#include <rb_func.h>
#include <rb_priv.h>
#include <rb_tree.h>
#include <cmn_err.h>
#include <cmn_output_debug.h>
#include <cmn_strop.h>
#include <stdlib.h>
#include <stdio.h>

/***********************************************
 * all algorithm from  https://en.wikipedia.org/wiki/Red%E2%80%93black_tree
***********************************************/


/*
 * construction
 * return NULL if out of memory
 */
RB_TREE *init_rb_tree(rb_malloc_func_t mallocfunc, rb_free_func_t freefunc,rb_compare_func_t comparefunc,rb_destroy_func_t destroyfunc,rb_print_func_t printfunc)
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
	rbt->m_printfunc = printfunc;
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

void* rb_node_get(RB_NODE* node)
{
	void* pret= NULL;
	if (node) {
		pret = node->m_value;
	}
	return pret;
}


RB_NODE* __rb_find_insert_pos(RB_TREE* rbt,void* data)
{
	RB_NODE* temp=NULL;
	int ret;

	temp = rbt->m_root;
	while(temp != NULL) {
		ret = rbt->m_comparefunc(data,temp->m_value);
		if (ret == 0) {
			return temp;
		} else if (ret < 0) {
			if (temp->m_left == NULL) {
				return temp;
			}
			temp = temp->m_left;
		} else if (ret > 0) {
			if (temp->m_right == NULL) {
				return temp;
			}
			temp = temp->m_right;
		}
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
		if (cmp == 0){
			return p; /* found */
		}
		DEBUG_INFO("data %p p->m_value %p cmp %d",data,p->m_value, cmp);
		p = cmp < 0 ? p->m_left : p->m_right;
	}

	return NULL; /* not found */
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

void __debug_node(RB_NODE* node,const char* file,int lineno,const char* fmt, ...)
{
	int *ival;
	char* fmtstr=NULL;
	int fmtlen=0;
	int ret;
	va_list ap;
	va_start(ap,fmt);

	if (node == NULL) {
		ret = vsnprintf_safe(&fmtstr,&fmtlen,fmt,ap);
		if (ret >= 0) {
			DEBUG_INFO("[%s:%d] %s NULL",file,lineno,fmtstr);
		}
		vsnprintf_safe(&fmtstr,&fmtlen,NULL,NULL);		
		return;
	}

	ival = (int*) node->m_value;
	ret = vsnprintf_safe(&fmtstr,&fmtlen,fmt,ap);
	if (ret >= 0) {
		DEBUG_INFO("[%s:%d] %s %p color %s m_value %d",file,lineno, fmtstr,node, node->m_color == RB_RED ? "red" : "black", ival ? *ival : -1);	
	}
	vsnprintf_safe(&fmtstr,&fmtlen,NULL,NULL);
	return;
}

int __is_on_left(RB_NODE* x)
{
	int ret =0;

	if (x && x->m_parent && x->m_parent->m_left == x) {
		ret = 1;
	}

	return ret;
}

RB_NODE* __get_uncle(RB_NODE* x)
{
	if (x == NULL || x->m_parent == NULL) {
		return NULL;
	}

	if (__is_on_left(x) != 0) {
		return x->m_parent->m_right;
	}
	return x->m_parent->m_left;
}

void __swap_colors(RB_NODE* x, RB_NODE* y)
{
	if (x != NULL && y != NULL) {
		int color;
		color = x->m_color;
		x->m_color = y->m_color;
		y->m_color = color;
	}
	return;
}

void __swap_values(RB_NODE* x, RB_NODE* y)
{
	if (x != NULL && y != NULL) {
		void* data;
		data = x->m_value;
		x->m_value = y->m_value;
		y->m_value = data;
	}
	return;
}

void __fixup_red_red(RB_TREE *rbt,RB_NODE* x)
{
	if (x == rbt->m_root) {
		x->m_color = RB_BLACK;
		return;
	}

	RB_NODE* parent = x->m_parent;
	RB_NODE* grandparent = parent->m_parent;
	RB_NODE* uncle = __get_uncle(x);

    if (parent->m_color != RB_BLACK) {
      if (uncle != NULL && uncle->m_color == RB_RED) {
        // uncle red, perform recoloring and recurse
        parent->m_color = RB_BLACK;
        uncle->m_color = RB_BLACK;
        grandparent->m_color = RB_RED;
        __fixup_red_red(rbt,grandparent);
      } else {
        // Else perform LR, LL, RL, RR
        if (__is_on_left(parent) != 0) {
          if (__is_on_left(x) != 0) {
            // for left right
            __swap_colors(parent, grandparent);
          } else {
          	rb_rotate_left(rbt,parent);
          	__swap_colors(x,grandparent);
          }
          // for left left and left right
          rb_rotate_right(rbt,grandparent);
        } else {
          if (__is_on_left(x) != 0) {
            // for right left
            rb_rotate_right(rbt,parent);
            __swap_colors(x,grandparent);
          } else {
          	__swap_colors(parent,grandparent);
          }

          // for right right and right left
          rb_rotate_left(rbt,grandparent);
        }
      }
    }
}

RB_NODE *rb_insert(RB_TREE *rbt, void *data)
{
	RB_NODE* node=NULL;
	int ret=0;
	RB_NODE* temp = NULL;

	temp = __rb_find_insert_pos(rbt,data);
	if (temp == NULL) {
		node = rbt->m_mallocfunc(sizeof(*node));
		if (node == NULL) {
			ret = -ENOBUFS;
			SETERRNO(ret);
			return NULL;
		}
		node->m_left = NULL;
		node->m_right = NULL;
		node->m_parent = NULL;
		node->m_value = data;

		rbt->m_root = node;
		node->m_color = RB_BLACK;
		return node;
	}

	ret = rbt->m_comparefunc(data,temp->m_value);
	if (ret == 0) {
		return temp;
	}

	node = rbt->m_mallocfunc(sizeof(*node));
	if (node == NULL) {
		ret = -ENOBUFS;
		SETERRNO(ret);
		return NULL;
	}
	node->m_left = NULL;
	node->m_right = NULL;
	node->m_parent = NULL;
	node->m_value = data;
	node->m_color = RB_RED;

	if (ret < 0) {
		temp->m_left = node;
	} else {
		temp->m_right = node;
	}


	__fixup_red_red(rbt,node);
	return node;
}





RB_NODE* __bst_replace(RB_TREE* rbt,RB_NODE* x)
{
	rbt = rbt;
	if (x == NULL) {
		return NULL;
	}

	if (x->m_left != NULL && x->m_right != NULL) {
		return rb_node_next(x);
	}

	if (x->m_left != NULL) {
		return x->m_left;
	}
	return x->m_right;
}

/*
 * delete node
 * return NULL if keep is zero (already freed)
 */
void *rb_delete(RB_TREE *rbt, RB_NODE *v, int keep)
{
	rbt = rbt;
	v = v;
	keep = keep;
	return NULL;
}

void rb_print_node(RB_TREE* ptree,RB_NODE* node,int tab)
{
	int i;
	for(i=0;i<tab;i++) {
		fprintf(stdout,"    ");
	}
	fprintf(stdout,"node %p .m_parent %p .m_left %p .m_right %p .m_color %s\n",node,node->m_parent,node->m_left,node->m_right,node->m_color == RB_RED ? "RED" : "BLACK");
	if (ptree->m_printfunc) {
		ptree->m_printfunc(node->m_value,tab);
	}
	if (node->m_left) {
		rb_print_node(ptree,node->m_left,tab+1);
	}
	if (node->m_right) {
		rb_print_node(ptree,node->m_right,tab+1);
	}
}

void rb_print_tree(RB_TREE* ptree)
{
	fprintf(stdout,"tree %p\n", ptree);
	if (ptree && ptree->m_printfunc) {
		RB_NODE* root = ptree->m_root;
		rb_print_node(ptree,root,1);
	}
}
