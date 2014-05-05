#ifndef _MLX4_UTILS_H_
#define	_MLX4_UTILS_H_

/* Lagg flags */
#define	MLX4_F_HASHL2		0x00000001	/* hash layer 2 */
#define	MLX4_F_HASHL3		0x00000002	/* hash layer 3 */
#define	MLX4_F_HASHL4		0x00000004	/* hash layer 4 */
#define	MLX4_F_HASHMASK		0x00000007

uint32_t mlx4_en_hashmbuf(uint32_t flags, struct mbuf *m, uint32_t key);

#endif		/* _MLX4_UTILS_H_ */
