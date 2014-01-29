#ifndef MLX4_CORE_TESTS_H
#define MLX4_CORE_TESTS_H

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include "freebsd_vl.h"
#include <linux/mlx4/driver.h>

/* alloc.c */
int db_test(struct mlx4_dev *dev, char* log);
int alloc_hwq_res_test(struct mlx4_dev *dev, char* log);

/* pd.c */
int bf_test (struct mlx4_dev *dev, char *log);
int uar_test (struct mlx4_dev *dev, char *log);
int xrcd_test(struct mlx4_dev *dev, char *log);
int pd_test(struct mlx4_dev *dev, char *log);

/* cmd.c  */
int cmd_test (struct mlx4_dev *dev, char* log);

/* qp.c */
int qp_to_ready_test (struct mlx4_dev *dev, char* log);
int qp_modify_test (struct mlx4_dev *dev, char* log);

/* mr.c */
int mtt_without_pages_test (struct mlx4_dev *dev, char *log);
int mtt_with_pages_test (struct mlx4_dev *dev, char *log);
int mr_test (struct mlx4_dev *dev, char *log);
int fmr_test (struct mlx4_dev *dev, char* log);

/* srq.c */
int srq_test(struct mlx4_dev *dev, char* log);

/* fw.c */
int fw_test(struct mlx4_dev *dev, char* log);

/* port.c */
int mac_functionality_test(struct mlx4_dev *dev, char *log);
int vlan_functionality_test(struct mlx4_dev *dev, char *log);
int SET_PORT_general_test(struct mlx4_dev *dev, char *log);
int SET_PORT_qpn_calc_test(struct mlx4_dev *dev, char *log);
int SET_PORT_PRIO2TC_test(struct mlx4_dev *dev, char *log);
int SET_PORT_SCHEDULER_test(struct mlx4_dev *dev, char *log);
int SET_MCAST_FLTR_test(struct mlx4_dev *dev, char *log);
int SET_stats_bitmap_test(struct mlx4_dev *dev, char *log);

/* mcg */
int ipv6_over_ib_steering_mode_B0_multicast_test(struct mlx4_dev *dev, char *log);
int eth_steering_mode_BO_multicast_test(struct mlx4_dev *dev, char *log);
int ib_steering_mode_A0_multicast_test(struct mlx4_dev *dev, char *log);
int ipv6_ib_unicast_test(struct mlx4_dev *dev, char *log);
int eth_unicast_test(struct mlx4_dev *dev, char *log);

/* eq.c */
int eq_test(struct mlx4_dev *dev, char* log);

/* cq.c */
int cq_test(struct mlx4_dev *dev, char* log);

#endif /* MLX4_CORE_TESTS_H */

