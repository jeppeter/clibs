#include <rb_func.h>
#include <rb_priv.h>
#include <rb_tree.h>
#include <cmn_err.h>
#include <cmn_output_debug.h>

/***********************************************
 * all algorithm from  https://en.wikipedia.org/wiki/Red%E2%80%93black_tree
***********************************************/


/*
 * construction
 * return NULL if out of memory
 */
RB_TREE *init_rb_tree(rb_malloc_func_t mallocfunc, rb_free_func_t freefunc,rb_compare_func_t comparefunc,rb_destroy_func_t destroyfunc)
{
	RB_TREE *rbt=NULL;
	int ret;

	if(mallocfunc == NULL || freefunc == NULL || comparefunc == NULL || destroyfunc == NULL) {
		ret = -CMN_EINVAL;
		SETERRNO(ret);
		return NULL;
	}

	rbt = (RB_TREE *) mallocfunc(sizeof(*rbt));
	if (rbt == NULL){
		ret = -CMN_NOBUFS;
		SETERRNO(ret);
		return NULL; /* out of memory */
	}

	rbt->m_comparefunc = comparefunc;
	rbt->m_destroyfunc = destroyfunc;
	rbt->m_mallocfunc = mallocfunc;
	rbt->m_freefunc = freefunc;
	/* sentinel node root */
	rbt->m_root = NULL;

	
	return rbt;
}

/*
 * destroy node recursively
 */
void __destroy(RB_TREE *rbt, RB_NODE *n,int keep)
{
	if (n != NULL) {
		__destroy(rbt, n->m_left,keep);
		__destroy(rbt, n->m_right,keep);
		if (keep == 0) {
			rbt->m_destroyfunc(n->m_value);
		}
		rbt->m_freefunc(n);
	}
}

/*
 * destruction
 */
void destroy_rb_tree(RB_TREE **prbt,int keep)
{
	if (prbt != NULL && *prbt != NULL) {
		RB_TREE* rbt = *prbt;
		rb_free_func_t freefunc = rbt->m_freefunc;
		__destroy(rbt, rbt->m_root,keep);
		freefunc(rbt);
		*prbt = NULL;
	}
}


RB_NODE* rb_first(RB_TREE* ptree)
{
	RB_NODE* pcur;
	if (ptree->m_root == NULL) {
		return NULL;
	}
	pcur = ptree->m_root;

	while(1) {
		if (pcur->m_left == NULL) {
			return pcur;
		}
		pcur = pcur->m_left;
	}
	return NULL;
}
/*
 * look up
 * return NULL if not found
 */
RB_NODE *rb_find(RB_TREE *rbt, void *data)
{
	RB_NODE *p;

	p = rbt->m_root;

	while (p != NULL) {
		int cmp;
		cmp = rbt->m_comparefunc(data, p->m_value);
		if (cmp == 0)
			return p; /* found */
		p = cmp < 0 ? p->m_left : p->m_right;
	}

	return NULL; /* not found */
}

/*
 * next larger
 * return NULL if not found
 */
RB_NODE *rb_node_next(RB_NODE *node)
{
	RB_NODE *p,*curp;

	p = node->m_right;

	if (p != NULL) {
		/* move down until we find it */
		for ( ; p->m_left != NULL; p = p->m_left) ;
	} else {
		/* move up until we find it or hit the root */
		while(1) {
			curp = p->m_parent;
			if (curp == NULL) {
				return NULL;
			}

			if (p == curp->m_right) {
				p = curp;
			} else {
				return curp;
			}
		}
	}

	return p;
}


/*
 * rotate left about x
 */
void rb_rotate_left(RB_TREE *rbt, RB_NODE *x)
{
	RB_NODE *y;

	rbt = rbt;

	y = x->m_right; /* child */

	/* tree x */
	x->m_right = y->m_left;
	if (x->m_right != NULL)
		x->m_right->m_parent = x;

	/* tree y */
	y->m_parent = x->m_parent;
	if (x == x->m_parent->m_left)
		x->m_parent->m_left = y;
	else
		x->m_parent->m_right = y;

	/* assemble tree x and tree y */
	y->m_left = x;
	x->m_parent = y;
	return;
}

/*
 * rotate right about x
 */
void rb_rotate_right(RB_TREE *rbt, RB_NODE *x)
{
	RB_NODE *y;

	rbt = rbt;

	y = x->m_left; /* child */

	/* tree x */
	x->m_left = y->m_right;
	if (x->m_left != NULL)
		x->m_left->m_parent = x;

	/* tree y */
	y->m_parent = x->m_parent;
	if (x == x->m_parent->m_left)
		x->m_parent->m_left = y;
	else
		x->m_parent->m_right = y;

	/* assemble tree x and tree y */
	y->m_right = x;
	x->m_parent = y;
	return;
}

/*
 * rebalance after insertion
 * RB_ROOT(rbt) is always BLACK, thus never reach beyond RB_FIRST(rbt)
 * after insert_repair, RB_FIRST(rbt) might be RED
 */
void rb_insert_repair(RB_TREE *rbt, RB_NODE *current)
{
	RB_NODE *uncle;

	do {
		/* current node is RED and parent node is RED */

		if (current->m_parent == current->m_parent->m_parent->m_left) {
			uncle = current->m_parent->m_parent->m_right;
			if (uncle->m_color == RB_RED) {
				/* insertion into 4-children cluster */

				/* split */
				current->m_parent->m_color = RB_BLACK;
				uncle->m_color = RB_BLACK;

				/* send grandparent node up the tree */
				current = current->m_parent->m_parent; /* goto loop or break */
				current->m_color = RB_RED;
			} else {
				/* insertion into 3-children cluster */

				/* equivalent BST */
				if (current == current->m_parent->m_right) {
					current = current->m_parent;
					rb_rotate_left(rbt, current);
				}

				/* 3-children cluster has two representations */
				current->m_parent->m_color = RB_BLACK; /* thus goto break */
				current->m_parent->m_parent->m_color = RB_RED;
				rb_rotate_right(rbt, current->m_parent->m_parent);
			}
		} else {
			uncle = current->m_parent->m_parent->m_left;
			if (uncle->m_color == RB_RED) {
				/* insertion into 4-children cluster */

				/* split */
				current->m_parent->m_color = RB_BLACK;
				uncle->m_color = RB_BLACK;

				/* send grandparent node up the tree */
				current = current->m_parent->m_parent; /* goto loop or break */
				current->m_color = RB_RED;
			} else {
				/* insertion into 3-children cluster */

				/* equivalent BST */
				if (current == current->m_parent->m_left) {
					current = current->m_parent;
					rb_rotate_right(rbt, current);
				}

				/* 3-children cluster has two representations */
				current->m_parent->m_color = RB_BLACK; /* thus goto break */
				current->m_parent->m_parent->m_color = RB_RED;
				rb_rotate_left(rbt, current->m_parent->m_parent);
			}
		}
	} while (current->m_parent->m_color == RB_RED);
}


/*
 * insert (or update) data
 * return NULL if out of memory
 */
RB_NODE *rb_insert(RB_TREE *rbt, void *data)
{
	RB_NODE *current, *parent;
	RB_NODE *new_node;

	/* do a binary search to find where it should be */

	current = NULL;
	parent = rbt->m_root;
	if (parent != NULL) {
		current = parent->m_left;
	}

	while (current != NULL) {
		int cmp;
		cmp = rbt->m_comparefunc(data, current->m_value);
		if (cmp == 0) {
			return current; /* updated */
		}

		parent = current;
		current = cmp < 0 ? current->m_left : current->m_right;
	}

	/* replace the termination NIL pointer with the new node pointer */

	current = new_node = (RB_NODE *) rbt->m_mallocfunc(sizeof(*new_node));
	if (current == NULL)
		return NULL; /* out of memory */

	current->m_left = current->m_right = NULL;
	current->m_parent = parent;
	current->m_color = RB_RED;
	current->m_value = data;
	
	if (parent == rbt->m_root || rbt->m_comparefunc(data, parent->m_value) < 0)
		parent->m_left = current;
	else
		parent->m_right = current;

	
	/*
	 * insertion into a red-black tree:
	 *   0-children root cluster (parent node is BLACK) becomes 2-children root cluster (new root node)
	 *     paint root node BLACK, and done
	 *   2-children cluster (parent node is BLACK) becomes 3-children cluster
	 *     done
	 *   3-children cluster (parent node is BLACK) becomes 4-children cluster
	 *     done
	 *   3-children cluster (parent node is RED) becomes 4-children cluster
	 *     rotate, and done
	 *   4-children cluster (parent node is RED) splits into 2-children cluster and 3-children cluster
	 *     split, and insert grandparent node into parent cluster
	 */
	if (current->m_parent->m_color == RB_RED) {
		/* insertion into 3-children cluster (parent node is RED) */
		/* insertion into 4-children cluster (parent node is RED) */
		rb_insert_repair(rbt, current);
	} else {
		/* insertion into 0-children root cluster (parent node is BLACK) */
		/* insertion into 2-children cluster (parent node is BLACK) */
		/* insertion into 3-children cluster (parent node is BLACK) */
	}

	/*
	 * the root is always BLACK
	 * insertion into 0-children root cluster or insertion into 4-children root cluster require this recoloring
	 */
	if (rbt->m_root) {
		rbt->m_root->m_color = RB_BLACK;
	}
	
	return new_node;
}


/*
 * rebalance after deletion
 */
void rb_delete_repair(RB_TREE *rbt, RB_NODE *current)
{
	RB_NODE *sibling;
	do {
		if (current == current->m_parent->m_left) {
			sibling = current->m_parent->m_right;

			if (sibling->m_color == RB_RED) {
				/* perform an adjustment (3-children parent cluster has two representations) */
				sibling->m_color = RB_BLACK;
				current->m_parent->m_color = RB_RED;
				rb_rotate_left(rbt, current->m_parent);
				sibling = current->m_parent->m_right;
			}

			/* sibling node must be BLACK now */

			if (sibling->m_right->m_color == RB_BLACK && sibling->m_left->m_color == RB_BLACK) {
				/* 2-children sibling cluster, fuse by recoloring */
				sibling->m_color = RB_RED;
				if (current->m_parent->m_color == RB_RED) { /* 3/4-children parent cluster */
					current->m_parent->m_color = RB_BLACK;
					break; /* goto break */
				} else { /* 2-children parent cluster */
					current = current->m_parent; /* goto loop */
				}
			} else {
				/* 3/4-children sibling cluster */
				
				/* perform an adjustment (3-children sibling cluster has two representations) */
				if (sibling->m_right->m_color == RB_BLACK) {
					sibling->m_left->m_color = RB_BLACK;
					sibling->m_color = RB_RED;
					rb_rotate_right(rbt, sibling);
					sibling = current->m_parent->m_right;
				}

				/* transfer by rotation and recoloring */
				sibling->m_color = current->m_parent->m_color;
				current->m_parent->m_color = RB_BLACK;
				sibling->m_right->m_color = RB_BLACK;
				rb_rotate_left(rbt, current->m_parent);
				break; /* goto break */
			}
		} else {
			sibling = current->m_parent->m_left;

			if (sibling->m_color == RB_RED) {
				/* perform an adjustment (3-children parent cluster has two representations) */
				sibling->m_color = RB_BLACK;
				current->m_parent->m_color = RB_RED;
				rb_rotate_right(rbt, current->m_parent);
				sibling = current->m_parent->m_left;
			}

			/* sibling node must be BLACK now */

			if (sibling->m_right->m_color == RB_BLACK && sibling->m_left->m_color == RB_BLACK) {
				/* 2-children sibling cluster, fuse by recoloring */
				sibling->m_color = RB_RED;
				if (current->m_parent->m_color == RB_RED) { /* 3/4-children parent cluster */
					current->m_parent->m_color = RB_BLACK;
					break; /* goto break */
				} else { /* 2-children parent cluster */
					current = current->m_parent; /* goto loop */
				}
			} else {
				/* 3/4-children sibling cluster */

				/* perform an adjustment (3-children sibling cluster has two representations) */
				if (sibling->m_left->m_color == RB_BLACK) {
					sibling->m_right->m_color = RB_BLACK;
					sibling->m_color = RB_RED;
					rb_rotate_left(rbt, sibling);
					sibling = current->m_parent->m_left;
				}

				/* transfer by rotation and recoloring */
				sibling->m_color = current->m_parent->m_color;
				current->m_parent->m_color = RB_BLACK;
				sibling->m_left->m_color = RB_BLACK;
				rb_rotate_right(rbt, current->m_parent);
				break; /* goto break */
			}
		}
	} while (current != rbt->m_root);
}


/*
 * delete node
 * return NULL if keep is zero (already freed)
 */
void *rb_delete(RB_TREE *rbt, RB_NODE *node, int keep)
{
	RB_NODE *target, *child;
	void *data;
	
	data = node->m_value;

	/* choose node's in-order successor if it has two children */
	
	if (node->m_left == NULL || node->m_right == NULL) {
		target = node;

	} else {
		target = rb_node_next(node); /* node->right must not be NIL, thus move down */

		node->m_value = target->m_value; /* data swapped */

	}

	child = (target->m_left == NULL) ? target->m_right : target->m_left; /* child may be NIL */

	/*
	 * deletion from red-black tree
	 *   4-children cluster (RED target node) becomes 3-children cluster
	 *     done
	 *   3-children cluster (RED target node) becomes 2-children cluster
	 *     done
	 *   3-children cluster (BLACK target node, RED child node) becomes 2-children cluster
	 *     paint child node BLACK, and done
	 *
	 *	 2-children root cluster (BLACK target node, BLACK child node) becomes 0-children root cluster
	 *     done
	 *
	 *   2-children cluster (BLACK target node, 4-children sibling cluster) becomes 3-children cluster
	 *     transfer, and done
	 *   2-children cluster (BLACK target node, 3-children sibling cluster) becomes 2-children cluster
	 *     transfer, and done
	 *
	 *   2-children cluster (BLACK target node, 2-children sibling cluster, 3/4-children parent cluster) becomes 3-children cluster
	 *     fuse, paint parent node BLACK, and done
	 *   2-children cluster (BLACK target node, 2-children sibling cluster, 2-children parent cluster) becomes 3-children cluster
	 *     fuse, and delete parent node from parent cluster
	 */
	if (target->m_color == RB_BLACK) {
		if (child->m_color == RB_RED) {
			/* deletion from 3-children cluster (BLACK target node, RED child node) */
			child->m_color = RB_BLACK;
		} else if (target == rbt->m_root) {
			/* deletion from 2-children root cluster (BLACK target node, BLACK child node) */
		} else {
			/* deletion from 2-children cluster (BLACK target node, ...) */
			rb_delete_repair(rbt, target);
		}
	} else {
		/* deletion from 4-children cluster (RED target node) */
		/* deletion from 3-children cluster (RED target node) */
	}

	if (child != NULL)
		child->m_parent = target->m_parent;

	if (target == target->m_parent->m_left)
		target->m_parent->m_left = child;
	else
		target->m_parent->m_right = child;

	rbt->m_freefunc(target);
	
	/* keep or discard data */
	if (keep == 0) {
		rbt->m_destroyfunc(data);
		data = NULL;
	}

	return data;
}


void* rb_node_get(RB_NODE* node)
{
	if (node == NULL) {
		return NULL;
	}
	return node->m_value;
}
