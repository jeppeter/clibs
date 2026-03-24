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

void __debug_node(RB_NODE* node,const char* file,int lineno,const char* fmt, ...);
int __is_on_left(RB_NODE* x);
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

	if (node == NULL) {
		return NULL;
	}

	p = node->m_right;

	if (p != NULL) {
		/* move down until we find it */
		for ( ; p->m_left != NULL; p = p->m_left) {}

	} else {
		/* move up until we find it or hit the root */
		p = node;
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


    __debug_node(x,__FILE__,__LINE__,"before leftRotate");
    if (x->m_parent != NULL) {
      __debug_node(x->m_parent,__FILE__,__LINE__,"parent value");
    }
    if (x->m_left != NULL) {
      __debug_node(x->m_left,__FILE__,__LINE__,"left value");
    }

    if (x->m_right != NULL) {
      __debug_node(x->m_right,__FILE__,__LINE__,"right value");
    }


	RB_NODE* nparent = x->m_right; /* child */

	if (x == rbt->m_root) {
		rbt->m_root = nparent;
	}

	if (x->m_parent != NULL) {
		if (__is_on_left(x) != 0) {
			x->m_parent->m_left = nparent;
		} else {
			x->m_parent->m_right = nparent;
		}
	}
	nparent->m_parent = x->m_parent;
	x->m_parent = nparent;

	/* tree x */
	x->m_right = nparent->m_left;
	if (nparent->m_left != NULL)
		nparent->m_left->m_parent = x;

	nparent->m_left = x;

    __debug_node(x,__FILE__,__LINE__,"after leftRotate");
    if (x->m_parent != NULL) {
      __debug_node(x->m_parent,__FILE__,__LINE__,"parent value");
    }
    if (x->m_left != NULL) {
      __debug_node(x->m_left,__FILE__,__LINE__,"left value");
    }

    if (x->m_right != NULL) {
      __debug_node(x->m_right,__FILE__,__LINE__,"right value");
    }

	return;
}

/*
 * rotate right about x
 */
void rb_rotate_right(RB_TREE *rbt, RB_NODE *x)
{
    __debug_node(x,__FILE__,__LINE__,"before rightRotate");
    if (x->m_parent != NULL) {
      __debug_node(x->m_parent,__FILE__,__LINE__,"parent value");
    }
    if (x->m_left != NULL) {
      __debug_node(x->m_left,__FILE__,__LINE__,"left value");
    }

    if (x->m_right != NULL) {
      __debug_node(x->m_right,__FILE__,__LINE__,"right value");
    }


	RB_NODE* nparent = x->m_left; /* child */

	if (x == rbt->m_root) {
		rbt->m_root = nparent;
	}

	if (x->m_parent != NULL) {
		if (__is_on_left(x) == 0) {
			x->m_parent->m_right = nparent;
		} else {
			x->m_parent->m_left = nparent;
		}
	}
	nparent->m_parent = x->m_parent;
	x->m_parent = nparent;

	/* tree x */
	x->m_left = nparent->m_right;
	if (nparent->m_right != NULL)
		nparent->m_right->m_parent = x;

	nparent->m_right = x;


    __debug_node(x,__FILE__,__LINE__,"after rightRotate");
    if (x->m_parent != NULL) {
      __debug_node(x->m_parent,__FILE__,__LINE__,"parent value");
    }
    if (x->m_left != NULL) {
      __debug_node(x->m_left,__FILE__,__LINE__,"left value");
    }

    if (x->m_right != NULL) {
      __debug_node(x->m_right,__FILE__,__LINE__,"right value");
    }
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
			DEBUG_INFO("[%s:%d] NULL DEBUG_NODE %s",file,lineno,fmtstr);
		}
		vsnprintf_safe(&fmtstr,&fmtlen,NULL,NULL);		
		return;
	}

	ival = (int*) node->m_value;
	ret = vsnprintf_safe(&fmtstr,&fmtlen,fmt,ap);
	if (ret >= 0) {
		DEBUG_INFO("[%s:%d] %p DEBUG_NODE  %s color %s m_value %d",file,lineno,node, fmtstr, node->m_color == RB_RED ? "RED" : "BLACK", ival ? *ival : -1);	
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
	if (x == NULL || x->m_parent == NULL || x->m_parent->m_parent == NULL) {
		return NULL;
	}

	if (__is_on_left(x->m_parent) != 0) {
		return x->m_parent->m_parent->m_right;
	}
	return x->m_parent->m_parent->m_left;
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
    	__debug_node(parent,__FILE__,__LINE__," parent color != BLACK");
    	__debug_node(uncle,__FILE__,__LINE__,"uncle check");
      if (uncle != NULL && uncle->m_color == RB_RED) {
        // uncle red, perform recoloring and recurse
        parent->m_color = RB_BLACK;
        uncle->m_color = RB_BLACK;
        grandparent->m_color = RB_RED;
        __debug_node(grandparent,__FILE__,__LINE__,"grandparent = RED");
        __fixup_red_red(rbt,grandparent);
      } else {
        // Else perform LR, LL, RL, RR
        if (__is_on_left(parent) != 0) {
        	__debug_node(parent,__FILE__,__LINE__," parent is on left");
          if (__is_on_left(x) != 0) {
            // for left right
            __debug_node(x,__FILE__,__LINE__," x is on left");
            __swap_colors(parent, grandparent);
            __debug_node(parent,__FILE__,__LINE__," parent new value");
            __debug_node(grandparent,__FILE__,__LINE__," grandparent new value");
          } else {
            __debug_node(parent,__FILE__,__LINE__," x is on right");
          	rb_rotate_left(rbt,parent);
          	__swap_colors(x,grandparent);
            __debug_node(x,__FILE__,__LINE__," x new value");
            __debug_node(grandparent,__FILE__,__LINE__," grandparent new value");            
          }
          // for left left and left right
          rb_rotate_right(rbt,grandparent);
        } else {
          if (__is_on_left(x) != 0) {
            // for right left
            __debug_node(x,__FILE__,__LINE__," x is on left");
            rb_rotate_right(rbt,parent);
            __swap_colors(x,grandparent);
            __debug_node(x,__FILE__,__LINE__," x new value");
            __debug_node(grandparent,__FILE__,__LINE__," grandparent new value");            
          } else {
          	__swap_colors(parent,grandparent);
            __debug_node(parent,__FILE__,__LINE__," parent new value");
            __debug_node(grandparent,__FILE__,__LINE__," grandparent new value");
          }

          // for right right and right left
          rb_rotate_left(rbt,grandparent);
          __debug_node(grandparent,__FILE__,__LINE__," grandparent after rotate left");
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
		__debug_node(node,__FILE__,__LINE__,"new root");
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
	node->m_parent = temp;
	node->m_value = data;
	node->m_color = RB_RED;

	__debug_node(node,__FILE__,__LINE__,"set parent");

	if (ret < 0) {
		temp->m_left = node;
		__debug_node(temp,__FILE__,__LINE__,"set left");
	} else {
		temp->m_right = node;
		__debug_node(temp,__FILE__,__LINE__,"set right");
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


RB_NODE* __get_sibling(RB_NODE* x)
{
	if (x == NULL || x->m_parent == NULL) {
		return NULL;
	}

	if (__is_on_left(x) != 0) {
		return x->m_parent->m_right;
	}
	return x->m_parent->m_left;
}

int __has_red_child(RB_NODE* x)
{
	int ret = 0;
	if (x != NULL) {
		if (x->m_left != NULL && x->m_left->m_color == RB_RED) {
			ret = 1;
		}

		if (x->m_right && x->m_right->m_color == RB_RED) {
			ret = 1;
		}
	}
	return ret;
}

void __fixup_double_black(RB_TREE* rbt,RB_NODE*x)
{
    if (x == rbt->m_root){
      // Reached root
      __debug_node(x,__FILE__,__LINE__,"x == root");
      return;    	
    }

    RB_NODE *sibling = __get_sibling(x);
    RB_NODE *parent = x->m_parent;
    if (sibling == NULL) {
      // No sibling, double black pushed up
      __debug_node(parent,__FILE__,__LINE__,"fixDoubleBlack parent");
      __fixup_double_black(rbt,parent);
    } else {
      if (sibling->m_color == RB_RED) {
        // Sibling red
        __debug_node(parent,__FILE__,__LINE__,"parent set color RED");
        parent->m_color = RB_RED;
        __debug_node(sibling,__FILE__,__LINE__,"sibling set color BLACK");
        sibling->m_color = RB_BLACK;
        if (__is_on_left(sibling) != 0) {
          // left case
          __debug_node(parent,__FILE__,__LINE__,"parent rightRotate");
          rb_rotate_right(rbt,parent);
        } else {
          // right case
          __debug_node(parent,__FILE__,__LINE__,"parent leftRotate");
          rb_rotate_left(rbt,parent);
        }
        __debug_node(x,__FILE__,__LINE__,"fixDoubleBlack x");
        __fixup_double_black(rbt,x);
      } else {
        // Sibling black
        if (__has_red_child(sibling) != 0) {
          // at least 1 red children
          __debug_node(sibling,__FILE__,__LINE__,"hasRedChild");
          if (sibling->m_left != NULL && sibling->m_left->m_color == RB_RED) {
            if (__is_on_left(sibling) != 0) {
              // left left
              __debug_node(sibling,__FILE__,__LINE__,"sibling color fixup");
              sibling->m_left->m_color = sibling->m_color;
              __debug_node(sibling,__FILE__,__LINE__,"sibling parent color set");
              sibling->m_color = parent->m_color;
              __debug_node(parent,__FILE__,__LINE__,"rightRotate parent");
              rb_rotate_right(rbt,parent);
            } else {
              // right left
              __debug_node(sibling,__FILE__,__LINE__,"sibling color fixup");
              sibling->m_left->m_color = parent->m_color;
              __debug_node(sibling,__FILE__,__LINE__,"rightRotate sibling");
              rb_rotate_right(rbt,sibling);
              __debug_node(parent,__FILE__,__LINE__,"leftRotate parent");
              rb_rotate_left(rbt,parent);
            }
          } else {
          	__debug_node(sibling,__FILE__,__LINE__,"check sibling isOnLeft");
            if (__is_on_left(sibling) != 0) {
              // left right
              __debug_node(sibling,__FILE__,__LINE__,"sibling right color set");
              sibling->m_right->m_color = parent->m_color;
              __debug_node(sibling,__FILE__,__LINE__,"leftRotate sibling");
              rb_rotate_left(rbt,sibling);
              __debug_node(parent,__FILE__,__LINE__,"rightRotate parent");
              rb_rotate_right(rbt,parent);
            } else {
              // right right
              __debug_node(sibling,__FILE__,__LINE__,"sibling right color set");
              sibling->m_right->m_color = sibling->m_color;
              __debug_node(sibling,__FILE__,__LINE__,"sibling color parent set");
              sibling->m_color = parent->m_color;
              __debug_node(parent,__FILE__,__LINE__,"leftRotate parent");
              rb_rotate_left(rbt,parent);
            }
          }
          __debug_node(parent,__FILE__,__LINE__,"parent color BLACK");
          parent->m_color = RB_BLACK;
        } else {
          // 2 black children
          __debug_node(sibling,__FILE__,__LINE__,"sibling color RED");
          sibling->m_color = RB_RED;
          if (parent->m_color == RB_BLACK){
          	__debug_node(parent,__FILE__,__LINE__,"fixDoubleBlack parent");
            __fixup_double_black(rbt,parent);
          }
          else{
          	__debug_node(parent,__FILE__,__LINE__,"parent color BLACK");
            parent->m_color = RB_BLACK;
          }
        }
      }
    }
}

/*
 * delete node
 * return NULL if keep is zero (already freed)
 */
void *rb_delete(RB_TREE *rbt, RB_NODE *v, int keep)
{
	void* pret=NULL;

	RB_NODE* u = __bst_replace(rbt,v);
	RB_NODE* parent;
	int uvblack = 0;

	if (v ) {
		pret = v->m_value;
	}


try_again:
	__debug_node(v,__FILE__,__LINE__,"v node");
	__debug_node(u,__FILE__,__LINE__,"u node");
	uvblack = 0;
	if ((u == NULL || u->m_color == RB_BLACK) && v->m_color == RB_BLACK) {
		uvblack = 1;
	}
	parent = v->m_parent;
	__debug_node(parent,__FILE__,__LINE__,"parent node");


	if (u == NULL) {
		if (v == rbt->m_root) {
			__debug_node(v,__FILE__,__LINE__,"root clear");
			rbt->m_root = NULL;
		} else {
			if (uvblack != 0) {
				__debug_node(v,__FILE__,__LINE__,"fixDoubleBlack");
				__fixup_double_black(rbt,v);
			} else {
				RB_NODE* sibling = __get_sibling(v);
				if (sibling != NULL) {
					__debug_node(sibling,__FILE__,__LINE__,"sibling color set");
					sibling->m_color = RB_RED;
				} 
			}

			if (__is_on_left(v) != 0) {
				__debug_node(v,__FILE__,__LINE__,"leftset");
				parent->m_left = NULL;
			} else {
				__debug_node(v,__FILE__,__LINE__,"rightset");
				parent->m_right = NULL;
			}

		}
		DEBUG_INFO(" ");
		rbt->m_freefunc(v);
		if (keep == 0) {
			rbt->m_destroyfunc(pret);
			pret = NULL;
		}
		DEBUG_INFO("pret %p", pret);
		return pret;
	}

	if (v->m_left == NULL || v->m_right == NULL) {
		if (v == rbt->m_root) {
			__debug_node(v,__FILE__,__LINE__,"v set right left clear");
			v->m_value = u->m_value;
			v->m_left = v->m_right = NULL;
			rbt->m_freefunc(u);
			if (keep == 0) {
				rbt->m_destroyfunc(pret);
				pret = NULL;
			}
		} else {
			if (__is_on_left(v) != 0) {
				__debug_node(u,__FILE__,__LINE__,"parent left = u");
				parent->m_left = u;
			} else {
				__debug_node(u,__FILE__,__LINE__,"parent right = u");
				parent->m_right = u;
			}

			rbt->m_freefunc(v);
			if (keep == 0) {
				rbt->m_destroyfunc(pret);
				pret = NULL;
			}
			__debug_node(u,__FILE__,__LINE__,"u set parent");
			u->m_parent = parent;
			if (uvblack != 0) {
				__debug_node(u,__FILE__,__LINE__,"fixDoubleBlack");
				__fixup_double_black(rbt,u);
			} else {
				__debug_node(u,__FILE__,__LINE__,"u set black");
				u->m_color = RB_BLACK;
			}
		}
		return pret;
	}

	__debug_node(u,__FILE__,__LINE__,"swapValues");
	__swap_values(u,v);
	__debug_node(u,__FILE__,__LINE__,"recursive");
	v= u;
	u = __bst_replace(rbt,v);
	goto try_again;

}

void rb_print_node(RB_TREE* ptree,FILE* fp,RB_NODE* node,int tab)
{
	int i;
	if (node == NULL) {
		return;
	}
	for(i=0;i<tab;i++) {
		fprintf(fp,"    ");
	}
	fprintf(fp,"node %p .m_parent %p .m_left %p .m_right %p DISPLAY_NODE .m_color %s ",node,node->m_parent,node->m_left,node->m_right,node->m_color == RB_RED ? "RED" : "BLACK");
	if (ptree->m_printfunc) {
		ptree->m_printfunc(node->m_value,fp,tab);
	}
	fprintf(fp,"\n");
	if (node->m_left) {
		rb_print_node(ptree,fp,node->m_left,tab+1);
	}
	if (node->m_right) {
		rb_print_node(ptree,fp,node->m_right,tab+1);
	}
}

void rb_print_tree(RB_TREE* ptree,FILE* fp)
{
	fprintf(fp,"tree %p\n", ptree);
	if (ptree && ptree->m_printfunc) {
		RB_NODE* root = ptree->m_root;
		rb_print_node(ptree,fp,root,1);
	}
}
