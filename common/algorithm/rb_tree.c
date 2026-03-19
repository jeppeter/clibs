#include <rb_func.h>
#include <rb_priv.h>
#include <rb_tree.h>
#include <cmn_err.h>



RB_TREE* init_rb_tree(rb_malloc_func_t mallocfunc, rb_free_func_t freefunc,rb_compare_func_t comparefunc,rb_destroy_func_t destroyfunc)
{
	int ret;
	struct rb_tree_st* pret= NULL;
	if (mallocfunc == NULL || freefunc == NULL || comparefunc == NULL || destroyfunc == NULL) {
		ret = -CMN_EINVAL;
		SETERRNO(ret);
		return NULL;
	}

	pret = mallocfunc(sizeof(*pret));
	if (pret == NULL) {
		ret = - CMN_NOBUFS;
		goto fail;
	}

	pret->m_mallocfunc = mallocfunc;
	pret->m_freefunc = freefunc;
	pret->m_comparefunc = comparefunc;
	pret->m_destroyfunc = destroyfunc;
	pret->m_root = NULL;

	return pret;
fail:
	if (pret != NULL) {
		freefunc(pret);
	}
	pret = NULL;
	SETERRNO(ret);
	return NULL;
}


RB_NODE* __rb_rotate_sub_left(RB_TREE* ptree,RB_NODE* psub)
{
	RB_NODE* sub_parent = psub->m_parent;
	RB_NODE* new_root = psub->m_right;
	RB_NODE* new_child = new_root->m_left;

	psub->m_right = new_child;
	if (new_child != NULL) {
		new_child->m_parent = psub;
	}

	new_root->m_left = psub;
	new_root->m_parent = sub_parent;
	psub->m_parent = new_root;
	if (sub_parent != NULL) {
		if (psub == sub_parent->m_right) {
			sub_parent->m_right = new_root;
		} else {
			sub_parent->m_left = new_root;
		}
	} else {
		ptree->m_root = new_root;
	}
	return new_root;
}


RB_NODE* __rb_rotate_sub_right(RB_TREE* ptree,RB_NODE* psub)
{
	RB_NODE* sub_parent = psub->m_parent;
	RB_NODE* new_root = psub->m_left;
	RB_NODE* new_child = new_root->m_right;

	psub->m_left = new_child;
	if (new_child != NULL) {
		new_child->m_parent = psub;
	}

	new_root->m_right = psub;
	new_root->m_parent = sub_parent;
	psub->m_parent = new_root;
	if (sub_parent != NULL) {
		if (psub == sub_parent->m_right) {
			sub_parent->m_right = new_root;
		} else {
			sub_parent->m_left = new_root;
		}
	} else {
		ptree->m_root = new_root;
	}
	return new_root;
}

void __rb_insert_inner(RB_TREE* ptree,RB_NODE* pnode,RB_NODE* pparent,int isright)
{
	RB_NODE* node = pnode;
	RB_NODE* parent = pparent;
	RB_NODE* grandparent;
	RB_NODE* uncle;
	int nowright;

	node->m_color = RB_RED;
	node->m_parent = parent;

	if (parent == NULL) {
		ptree->m_root = node;
		return;
	}

	if (isright) {
		parent->m_right = node;
	} else {
		parent->m_left = node;
	}

	do {
		if (parent->m_color == RB_BLACK) {
			return;
		}

		grandparent = parent->m_parent;
		if (grandparent == NULL) {
			parent->m_color = RB_BLACK;
			return;
		}

		if (grandparent->m_right == parent) {
			nowright = 1;
		} else {
			nowright = 0;
		}

		if (nowright) {
			uncle = grandparent->m_left;
		} else {
			uncle = grandparent->m_right;
		}

		if (uncle == NULL || uncle->m_color == RB_BLACK) {
			if ((nowright != 0 && parent->m_left == node) || (nowright == 0 && parent->m_right == node)) {
				if (nowright) {
					__rb_rotate_sub_right(ptree,parent);
				} else {
					__rb_rotate_sub_left(ptree,parent);
				}
				node = parent;
				if (nowright) {
					parent = grandparent->m_right;
				} else {
					parent = grandparent->m_left;
				}
			}

			if (nowright) {
				__rb_rotate_sub_left(ptree,parent);
			} else {
				__rb_rotate_sub_right(ptree,parent);
			}
			parent->m_color = RB_BLACK;
			grandparent->m_color = RB_RED;
			return;
		}

		parent->m_color = RB_BLACK;
		uncle->m_color = RB_BLACK;
		grandparent->m_color = RB_RED;
		node = grandparent;


	} while((parent = node->m_parent) != NULL);
	return;
}


RB_NODE* rb_insert(RB_TREE* ptree,void* arg)
{
	RB_NODE* node=NULL;
	RB_NODE* sparent=NULL;
	RB_NODE* parent = NULL;
	int isright = 0;

	/*now search for*/

	sparent = ptree->m_root;

	while(1) {
		if (sparent == NULL) {
			break;
		}

		ret = ptree->m_comparefunc(sparent->m_value, arg);
		if (ret == 0) {
			/*it is duplicated so free */
			ptree->m_destroyfunc(sparent->m_value);
			sparent->m_value = arg;
			return sparent;
		} else if (ret < 0) {
			parent = sparent;
			isright = 0;
			sparent = parent->m_left;
		} else if (ret > 0) {
			parent = sparent;
			isright = 1;
			sparent = parent->m_right;
		}		
	}

	node = ptree->m_mallocfunc(sizeof(*node));
	if (node == NULL) {
		ret = -CMN_NOBUFS;
		SETERRNO(ret);
		return NULL;
	}

	node->m_color = RB_RED;
	node->m_left = NULL;
	node->m_right = NULL;
	node->m_value = arg;

	__rb_insert_inner(ptree,node,parent,isright);
	return node;
}

void __rb_delete_inner(RB_TREE* ptree, RB_NODE* pnode,int keep)
{
	RB_NODE* parent = pnode->m_parent;
	RB_NODE* node = pnode;
	RB_NODE* sibling ;
	RB_NODE* close_nephew;
	RB_NODE* distant_nephew;

	int isright;
	if (node == parent->m_right) {
		isright = 1;
	} else {
		isright = 0;
	}

	if (isright) {
		parent->m_right = NULL;
	} else {
		parent->m_left = NULL;
	}

	goto start_balance;
	do{
		if (node == parent->m_right) {
			isright = 1;
		} else {
			isright = 0;
		}
	start_balance:
		if (isright) {
			sibling = parent->m_left;
		} else {
			sibling = parent->m_right;
		}

		if (isright) {
			distant_nephew = sibling->m_left;
			close_nephew = sibling->m_right;
		} else {
			distant_nephew = sibling->m_right;
			close_nephew = sibling->m_left;
		}

		if (sibling->m_color == RB_RED) {
			if (isright) {
				__rb_rotate_sub_right(ptree,parent);
			} else {
				__rb_rotate_sub_left(ptree,parent);
			}
			parent->m_color = RB_RED;
			sibling->m_color = RB_BLACK;
			sibling = close_nephew;

			if (isright) {
				distant_nephew = sibling->m_left;
			} else {
				distant_nephew = sibling->m_right;
			}

			if (distant_nephew != NULL && distant_nephew->m_color == RB_RED) {
				goto case_6;
			}

			if (isright) {
				close_nephew = sibling->m_right;
			} else {
				close_nephew = sibling->m_left;
			}

			if (close_nephew != NULL && close_nephew->m_color == RB_RED) {
				goto case_5;
			}

			sibling->m_color = RB_RED;
			parent->m_color = RB_BLACK;
			goto free_out;
		}

		if (distant_nephew != NULL && distant_nephew->m_color == RB_RED) {
			goto case_6;
		}

		if (close_nephew != NULL && close_nephew->m_color == RB_RED) {
			goto case_5;
		}

		if (parent == NULL) {
			goto free_out;
		}

		if (parent->m_color == RB_RED) {
			sibling->m_color = RB_RED;
			parent->m_color = RB_BLACK;
			goto free_out;
		}

		sibling->m_color = RB_RED;
		node = parent;
	} while((parent = node->m_parent) != NULL);

case_5:
	if (isright) {
		__rb_rotate_sub_left(ptree,sibling);
	} else {
		__rb_rotate_sub_right(ptree,sibling);
	}
	sibling->m_color = RB_RED;
	close_nephew->m_color = RB_BLACK;
	distant_nephew = sibling;
	sibling = close_nephew;

case_6:

	if (isright) {
		__rb_rotate_sub_right(ptree,parent);
	} else {
		__rb_rotate_sub_left(ptree,parent);
	}
	sibling->m_color = parent->m_color;
	parent->m_color = RB_BLACK;
	distant_nephew->m_color = RB_BLACK;
	goto free_out;


free_out:
	if (keep == 0) {
		ptree->m_destroyfunc(pnode->m_value);
	}
	ptree->m_freefunc(pnode);
	return;
}

int rb_delete(RB_TREE* ptree, void*arg, int keep)
{
	int ret;
	RB_NODE* pnode = ptree->m_root;

	while (1){
		if (pnode == NULL) {
			return 0;
		}

		ret = ptree->m_comparefunc(pnode->m_value, arg);
		if (ret == 0) {
			__rb_delete_inner(ptree,pnode,keep);
			return 1;
		} else if (ret > 0) {
			pnode = pnode->m_right;
		} else {
			pnode = pnode->m_left;
		}
	}
	return 0;
}

#define PUSH_NODE(pcur,isright)                                                                   \
do{                                                                                               \
	if (nodesize < (nodelen+1)) {                                                                 \
		if (nodesize == 0) {                                                                      \
			nodesize = 4;                                                                         \
		} else {                                                                                  \
			nodesize <<= 1;                                                                       \
		}                                                                                         \
		pparr = ptree->m_mallocfunc(sizeof(*pparr) * nodesize);                                   \
		ptmppath = ptree->m_mallocfunc(sizeof(*pparr) * nodesize);                                \
		if (pparr == NULL || ptmppath) {                                                          \
			ret = -ENOBUFS;                                                                       \
			goto fail;                                                                            \
		}                                                                                         \
		for(i=0;i<nodesize;i++) {                                                                 \
			pparr[i] = NULL;                                                                      \
			ptmppath[i] = 0;                                                                      \
		}                                                                                         \
		if (nodelen > 0) {                                                                        \
			for(i=0;i<nodelen;i++) {                                                              \
				pparr[i] = nodearr[i];                                                            \
				ptmppath[i] = pathright[i];                                                       \
			}                                                                                     \
		}                                                                                         \
		if(nodearr) {                                                                             \
			ptree->m_freefunc(nodearr);                                                           \
		}                                                                                         \
		nodearr = pparr;                                                                          \
		pparr = NULL;                                                                             \
		if (pathright) {                                                                          \
			ptree->m_freefunc(pathright);                                                         \
		}                                                                                         \
		pathright = ptmppath;                                                                     \
		ptmppath = NULL;                                                                          \
	}                                                                                             \
	pathright[nodelen] = isright;                                                                 \
	nodearr[nodelen] = pcur;                                                                      \
	nodelen += 1;                                                                                 \
}while(0)

#define POP_NODE(pcur,isright)                                                                    \
do{                                                                                               \
	if (nodelen > 0) {                                                                            \
		pcur = pparr[nodelen-1];                                                                  \
		isright = pathright[nodelen - 1];                                                         \
		nodelen -= 1;                                                                             \
	} else {                                                                                      \
		pcur = NULL;                                                                              \
		isright = 0;                                                                              \
	}                                                                                             \
}while(0)

void destroy_rb_tree(RB_TREE* ptree,int keep)
{
	if (ptree == NULL) {
		return;
	}

	RB_NODE** nodearr = NULL, **pparr=NULL;
	int* pathright = NULL, *ptmppath=NULL;
	rb_free_func_t freefunc = ptree->m_freefunc;
	rb_destroy_func_t destroyfunc = ptree->m_destroyfunc;
	int nodesize=4;
	int nodelen=0;
	RB_NODE* pchild=ptree->m_root;
	RB_NODE* pcur=NULL;
	int isright = 0;

	if (pchild == NULL) {
		goto free_out;
	}

	if (pchild->m_left != NULL) {
		isright = 0;
		pchild =  pchild->m_left;
	} else if (pchild->m_right != NULL) {
		isright = 1;
		pchild = pchild->m_right;
	} else {
		pchild = NULL;
		isright = 0;
	}

next_level:
	if (pchild == NULL) {
		POP_NODE(pchild,isright);
		if (pchild == NULL) {
			goto free_out;
		}
		/*now free the child*/
		if (keep == 0) {
			destroyfunc(pchild->m_value);
		}
		
		pcur = NULL;
		if (isright) {
			if (pchild->m_parent != NULL) {
				pchild->m_parent->m_right = NULL;	
			}
			freefunc(pchild);
			isright = 0;			
		} else {
			if (pchild->m_parent != NULL) {
				pchild->m_parent->m_left = NULL;
				pcur = pchild->m_parent->m_right;
				if (pcur != NULL) {
					isright = 1;
				}
			}
			freefunc(pchild);
		}		
		pchild = pcur;
		goto next_level;

	} else {
		PUSH_NODE(pchild,isright);
		if (pchild->m_left != NULL) {
			isright = 0;
			pchild = pchild->m_left;
		} else if (pchild->m_right != NULL) {
			isright = 1;
			pchild = pchild->m_right;
		} else {
			pchild = NULL;
			isright = 0;
		}
		goto next_level;
	}
free_out:
	if (ptree->m_root != NULL) {
		destroyfunc(ptree->m_root->m_value);
		freefunc(ptree->m_root);
		ptree->m_root = NULL;
	}

	if (pparr) {
		freefunc(pparr);
	}
	pparr = NULL;

	if (pathright) {
		freefunc(pathright);
	}
	pathright = NULL;
	freefunc(ptree);

	return;
}