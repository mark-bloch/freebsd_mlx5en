/*-
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "en.h"
#include <machine/in_cksum.h>

static inline int
mlx5e_alloc_rx_wqe(struct mlx5e_rq *rq,
    struct mlx5e_rx_wqe *wqe, u16 ix)
{
	bus_dma_segment_t segs[1];
	struct mbuf *mb;
	int nsegs;
	int err;

	mb = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, rq->wqe_sz);
	if (unlikely(!mb))
		return (-ENOMEM);

	/* set initial mbuf length */
	mb->m_pkthdr.len = mb->m_len = rq->wqe_sz;

	/* get IP header aligned */
	m_adj(mb, MLX5E_NET_IP_ALIGN);

	err = -bus_dmamap_load_mbuf_sg(rq->dma_tag, rq->mbuf[ix].dma_map,
	    mb, segs, &nsegs, BUS_DMA_NOWAIT);
	if (err != 0)
		goto err_free_mbuf;
	if (nsegs != 1) {
		err = -ENOMEM;
		goto err_free_mbuf;
	}
	wqe->data.addr = cpu_to_be64(segs[0].ds_addr);

	rq->mbuf[ix].mbuf = mb;

	bus_dmamap_sync(rq->dma_tag, rq->mbuf[ix].dma_map,
	    BUS_DMASYNC_PREREAD);
	return (0);

err_free_mbuf:
	m_freem(mb);
	return (err);
}

static void
mlx5e_post_rx_wqes(struct mlx5e_rq *rq)
{
	if (unlikely(rq->enabled == 0))
		return;

	while (!mlx5_wq_ll_is_full(&rq->wq)) {
		struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(&rq->wq, rq->wq.head);

		if (unlikely(mlx5e_alloc_rx_wqe(rq, wqe, rq->wq.head)))
			break;

		mlx5_wq_ll_push(&rq->wq, be16_to_cpu(wqe->next.next_wqe_index));
	}

	/* ensure wqes are visible to device before updating doorbell record */
	wmb();

	mlx5_wq_ll_update_db_record(&rq->wq);
}

static void
mlx5e_lro_update_hdr(struct mbuf* mb, struct mlx5_cqe64 *cqe)
{
	/* TODO: consider vlans, ip options, ... */
	struct ether_header *eh;
	uint16_t eh_type;

	struct ip6_hdr *ip6 = NULL;
	struct ip *ip4 = NULL;
	struct tcphdr *th;


	eh = mtod(mb, struct ether_header *);
	eh_type = ntohs(eh->ether_type);

	u8 l4_hdr_type = get_cqe_l4_hdr_type(cqe);
	int tcp_ack = ((CQE_L4_HDR_TYPE_TCP_ACK_NO_DATA  == l4_hdr_type) ||
			(CQE_L4_HDR_TYPE_TCP_ACK_AND_DATA == l4_hdr_type));

	/* TODO: consider vlan */
	u16 tot_len = be32_to_cpu(cqe->byte_cnt) - ETH_HLEN;

	switch (eh_type) {
	case ETHERTYPE_IP:
		ip4 = (struct ip *)(eh + 1);
		th = (struct tcphdr *)(ip4 + 1);
		break;
	case ETHERTYPE_IPV6:
		ip6 = (struct ip6_hdr *)(eh + 1);
		th = (struct tcphdr *)(ip6 + 1);
		break;
	default:
		return;
	}


	/* TODO: handle timestamp */

	if (get_cqe_lro_tcppsh(cqe))
		th->th_flags           |= TH_PUSH;

	if (tcp_ack) {
		th->th_flags           |= TH_ACK;
		th->th_ack             = cqe->lro_ack_seq_num;
		th->th_win             = cqe->lro_tcp_win;
	}

	if (ip4) {
		ip4->ip_ttl            = cqe->lro_min_ttl;
		ip4->ip_len            = cpu_to_be16(tot_len);
		ip4->ip_sum            = 0;
		ip4->ip_sum            = in_cksum(mb, ip4->ip_hl << 2);
	} else {
		ip6->ip6_hlim          = cqe->lro_min_ttl;
		ip6->ip6_plen	       = cpu_to_be16(tot_len -
				sizeof(struct ip6_hdr));
	}
	/* TODO: handle tcp checksum */
}


static inline void
mlx5e_build_rx_mbuf(struct mlx5_cqe64 *cqe,
    struct mlx5e_rq *rq, struct mbuf *mb)
{
	struct ifnet *ifp = rq->ifp;
	u32 cqe_bcnt = be32_to_cpu(cqe->byte_cnt);
	int lro_num_seg; /* HW LRO session aggregated packets counter */

	lro_num_seg = be32_to_cpu(cqe->srqn) >> 24;
	if (lro_num_seg > 1) {
		mlx5e_lro_update_hdr(mb, cqe);
		rq->stats.lro_packets++;
		rq->stats.lro_bytes += cqe_bcnt;
	}

	mb->m_pkthdr.len = mb->m_len = cqe_bcnt;
	mb->m_pkthdr.flowid = rq->ix;
	M_HASHTYPE_SET(mb, M_HASHTYPE_OPAQUE);
	mb->m_pkthdr.rcvif = ifp;

	if (likely(ifp->if_capabilities & IFCAP_RXCSUM) &&
	    ((cqe->hds_ip_ext & (CQE_L2_OK | CQE_L3_OK | CQE_L4_OK)) ==
	    (CQE_L2_OK | CQE_L3_OK | CQE_L4_OK))) {
		mb->m_pkthdr.csum_flags =
		    CSUM_IP_CHECKED | CSUM_IP_VALID |
		    CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
		mb->m_pkthdr.csum_data = htons(0xffff);
	} else {
		rq->stats.csum_none++;
	}

	if (cqe_has_vlan(cqe)) {
		mb->m_pkthdr.ether_vtag = be16_to_cpu(cqe->vlan_info);
		mb->m_flags |= M_VLANTAG;
	}
}

static int
mlx5e_poll_rx_cq(struct mlx5e_rq *rq, int budget)
{
#ifndef HAVE_TURBO_LRO
	struct lro_entry *queued;
#endif
	int i;

	for (i = 0; i < budget; i++) {
		struct mlx5e_rx_wqe *wqe;
		struct mlx5_cqe64 *cqe;
		struct mbuf *mb;
		__be16 wqe_counter_be;
		u16 wqe_counter;

		cqe = mlx5e_get_cqe(&rq->cq);
		if (!cqe)
			break;

		wqe_counter_be = cqe->wqe_counter;
		wqe_counter = be16_to_cpu(wqe_counter_be);
		wqe = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
		mb = rq->mbuf[wqe_counter].mbuf;
		rq->mbuf[wqe_counter].mbuf = NULL;	/* safety clear */

		bus_dmamap_sync(rq->dma_tag, rq->mbuf[wqe_counter].dma_map,
		    BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(rq->dma_tag, rq->mbuf[wqe_counter].dma_map);

		if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
			rq->stats.wqe_err++;
			m_freem(mb);
			goto wq_ll_pop;
		}
		mlx5e_build_rx_mbuf(cqe, rq, mb);
		rq->stats.packets++;
#ifdef HAVE_TURBO_LRO
		if (mb->m_pkthdr.csum_flags == 0 ||
		    (rq->ifp->if_capenable & IFCAP_LRO) == 0 ||
		    rq->lro.mbuf == NULL) {
			/* normal input */
			rq->ifp->if_input(rq->ifp, mb);
		} else {
			tcp_tlro_rx(&rq->lro, mb);
		}
#else
		if (mb->m_pkthdr.csum_flags == 0 ||
		    (rq->ifp->if_capenable & IFCAP_LRO) == 0 ||
		    rq->lro.lro_cnt == 0 ||
		    tcp_lro_rx(&rq->lro, mb, 0) != 0) {
			rq->ifp->if_input(rq->ifp, mb);
		}
#endif
wq_ll_pop:
		mlx5_wq_ll_pop(&rq->wq, wqe_counter_be,
		    &wqe->next.next_wqe_index);
	}

	mlx5_cqwq_update_db_record(&rq->cq.wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();
#ifndef HAVE_TURBO_LRO
	while ((queued = SLIST_FIRST(&rq->lro.lro_active)) != NULL) {
		SLIST_REMOVE_HEAD(&rq->lro.lro_active, next);
		tcp_lro_flush(&rq->lro, queued);
	}
#endif
	return (i);
}

void
mlx5e_rx_cq_function(struct mlx5e_cq *cq)
{
	struct mlx5e_rq *rq = container_of(cq, struct mlx5e_rq, cq);
	int i = 0;
	mtx_lock(&rq->mtx);

	/*
	 * Polling the entire CQ without posting new WQEs results in
	 * lack of receive WQEs during heavy traffic scenarios.
	 */
	while (1) {
		if (mlx5e_poll_rx_cq(rq, MLX5E_RX_BUDGET_MAX) !=
		    MLX5E_RX_BUDGET_MAX)
			break;
		i += MLX5E_RX_BUDGET_MAX;
		if (i >= MLX5E_BUDGET_MAX)
			break;
		mlx5e_post_rx_wqes(rq);
	}
	mlx5e_post_rx_wqes(rq);

	mlx5e_cq_arm(cq);
#ifdef HAVE_TURBO_LRO
	tcp_tlro_flush(&rq->lro, 1);
#endif
	mtx_unlock(&rq->mtx);
}
