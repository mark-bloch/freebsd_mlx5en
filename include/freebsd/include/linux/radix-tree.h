#ifndef	_FBSD_RADIX_TREE_H_
#define	_FBSD_RADIX_TREE_H_

#include <linux/types.h>

#define	RADIX_TREE_MAP_SHIFT	6
#define	RADIX_TREE_MAP_SIZE	(1 << RADIX_TREE_MAP_SHIFT)
#define	RADIX_TREE_MAP_MASK	(RADIX_TREE_MAP_SIZE - 1)
#define	RADIX_TREE_MAX_HEIGHT						\
	    DIV_ROUND_UP((sizeof(long) * NBBY), RADIX_TREE_MAP_SHIFT)

struct radix_tree_node {
	void		*slots[RADIX_TREE_MAP_SIZE];
	int		count;
};

struct radix_tree_root {
	struct radix_tree_node	*rnode;
	gfp_t			gfp_mask;
	int			height;
};

#define	RADIX_TREE_INIT(mask)						\
	    { .rnode = NULL, .gfp_mask = mask, .height = 0 };
#define	INIT_RADIX_TREE(root, mask)					\
	    { (root)->rnode = NULL; (root)->gfp_mask = mask; (root)->height = 0; }
#define	RADIX_TREE(name, mask)						\
	    struct radix_tree_root name = RADIX_TREE_INIT(mask)

void	*radix_tree_lookup(struct radix_tree_root *, unsigned long);
void	*radix_tree_delete(struct radix_tree_root *, unsigned long);
int	 radix_tree_insert(struct radix_tree_root *, unsigned long, void *);

#endif	/* _FBSD_RADIX_TREE_H_ */
