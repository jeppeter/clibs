#include <rb_func.h>
#include <rb_priv.h>
#include <rb_tree.h>
#include <cmn_err.h>
#include <cmn_output_debug.h>

/***********************************************
 * all algorithm from  https://en.wikipedia.org/wiki/Red%E2%80%93black_tree
***********************************************/


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

void __replace_node(RB_TREE* ptree,RB_NODE* onode, RB_NODE* nnode)
{
	if (onode->m_parent == NULL) {
		ptree->m_root = nnode;
	} else {
		if (onode == onode->m_parent->m_left) {
			onode->m_parent->m_left = nnode;
		} else {
			onode->m_parent->m_right = nnode;
		}
	}

	if (nnode != NULL) {
		nnode->m_parent = onode->m_parent;
	}
	return;
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
	int ret;

	/*now search for*/

	sparent = ptree->m_root;

	while(1) {
		if (sparent == NULL) {
			break;
		}

		ret = ptree->m_comparefunc(sparent->m_value,arg);
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


void __rb_delete_repair(RB_TREE* ptree, RB_NODE* pnode)
{
	RB_NODE* parent = pnode->m_parent;
	RB_NODE* node = pnode;
	RB_NODE* sibling ;
	RB_NODE* close_nephew;
	RB_NODE* distant_nephew;

	DEBUG_INFO("parent %p node %p",parent, node);



	int isright = -1;
	if (node == parent->m_right) {
		isright = 1;
	} else {
		isright = 0;
	}
	DEBUG_INFO(" ");

	if (isright) {
		parent->m_right = NULL;
	} else {
		parent->m_left = NULL;
	}

	DEBUG_INFO(" ");
	goto start_balance;
	do{
		DEBUG_INFO(" ");
		if (node == parent->m_right) {
			isright = 1;
		} else {
			isright = 0;
		}
	start_balance:
		DEBUG_INFO(" ");
		if (isright) {
			sibling = parent->m_left;
		} else {
			sibling = parent->m_right;
		}

		DEBUG_INFO("sibling %p isright %d", sibling,isright);
		if (isright) {
			distant_nephew = sibling->m_left;
			close_nephew = sibling->m_right;
		} else {
			distant_nephew = sibling->m_right;
			close_nephew = sibling->m_left;
		}

		DEBUG_INFO(" ");
		if (sibling->m_color == RB_RED) {
			if (isright) {
				__rb_rotate_sub_right(ptree,parent);
			} else {
				__rb_rotate_sub_left(ptree,parent);
			}
			DEBUG_INFO(" ");
			parent->m_color = RB_RED;
			sibling->m_color = RB_BLACK;
			sibling = close_nephew;
			DEBUG_INFO(" ");

			if (isright) {
				distant_nephew = sibling->m_left;
			} else {
				distant_nephew = sibling->m_right;
			}
			DEBUG_INFO(" ");
			if (distant_nephew != NULL && distant_nephew->m_color == RB_RED) {
				DEBUG_INFO(" ");
				goto case_6;
			}
			DEBUG_INFO(" ");
			if (isright) {
				close_nephew = sibling->m_right;
			} else {
				close_nephew = sibling->m_left;
			}

			DEBUG_INFO(" ");
			if (close_nephew != NULL && close_nephew->m_color == RB_RED) {
				goto case_5;
			}

			DEBUG_INFO(" ");
			sibling->m_color = RB_RED;
			parent->m_color = RB_BLACK;
			goto free_out;
		}

		DEBUG_INFO(" ");
		if (distant_nephew != NULL && distant_nephew->m_color == RB_RED) {
			goto case_6;
		}

		DEBUG_INFO(" ");
		if (close_nephew != NULL && close_nephew->m_color == RB_RED) {
			goto case_5;
		}

		if (parent == NULL) {
			goto free_out;
		}

		DEBUG_INFO(" ");
		if (parent->m_color == RB_RED) {
			sibling->m_color = RB_RED;
			parent->m_color = RB_BLACK;
			goto free_out;
		}

		DEBUG_INFO(" ");
		sibling->m_color = RB_RED;
		node = parent;
		DEBUG_INFO(" ");
	} while((parent = node->m_parent) != NULL);

case_5:
	DEBUG_INFO(" ");
	if (isright) {
		__rb_rotate_sub_left(ptree,sibling);
	} else {
		__rb_rotate_sub_right(ptree,sibling);
	}
	sibling->m_color = RB_RED;
	close_nephew->m_color = RB_BLACK;
	distant_nephew = sibling;
	sibling = close_nephew;
	DEBUG_INFO(" ");

case_6:
	DEBUG_INFO(" ");
	if (isright) {
		__rb_rotate_sub_right(ptree,parent);
	} else {
		__rb_rotate_sub_left(ptree,parent);
	}
	sibling->m_color = parent->m_color;
	parent->m_color = RB_BLACK;
	distant_nephew->m_color = RB_BLACK;
	DEBUG_INFO(" ");
	goto free_out;


free_out:
	//if (keep == 0) {
	//	ptree->m_destroyfunc(pnode->m_value);
	//}
	//ptree->m_freefunc(pnode);
	return;
}

RB_NODE* rb_first(RB_TREE* ptree)
{
	RB_NODE* pleft = NULL;
	RB_NODE* pcur=NULL;
	if (ptree== NULL) {
		return NULL;
	}

	pcur = ptree->m_root;

	if (pcur == NULL) {
		return NULL;
	}
	pleft = pcur->m_left;

	while(1) {
		if (pleft == NULL) {
			return pcur;
		}
		pcur = pleft;
		pleft = pcur->m_left;
	}

	return NULL;
}

RB_NODE* rb_node_next(RB_NODE* pnode)
{
	RB_NODE* pcur;
	RB_NODE* pnext;
	if (pnode == NULL) {
		return NULL;
	}


	if (pnode->m_right != NULL) {
		
		pcur = pnode->m_right;
		pnext = pcur->m_left;
		while(1) {
			if (pnext == NULL) {
				return pcur;
			}
			pcur = pnext;			
			pnext = pcur->m_left;
		}
	}

	if (pnode->m_parent != NULL) {
		while(1) {
			if (pnode->m_parent == NULL) {
				return NULL;
			}
			if (pnode != pnode->m_parent->m_right) {
				/*we are on the right ,so we put next*/
				return pnode->m_parent;
			}
			pnode = pnode->m_parent;
		}
	}
	return NULL;
}

void* rb_node_get(RB_NODE* pnode)
{
	return pnode->m_value;
}

RB_NODE* __rb_bst_replace(RB_NODE* node)
{
	if (node == NULL) {
		return NULL;
	}

	if (node->m_left != NULL && node->m_right != NULL) {
		return rb_node_next(node);
	}
	if (node->m_left != NULL) {
		return node->m_left;
	}
	return node->m_right;
}

RB_NODE* __get_sibling(RB_NODE* node)
{
	if (node == NULL || node->m_parent == NULL) {
		return NULL;
	}
	if (node == node->m_parent->m_left ) {
		return node->m_parent->m_right;
	}
	return node->m_parent->m_left;
}

int __is_on_left(RB_NODE* node)
{
	if (node == node->m_parent->m_left) {
		return 1;
	}
	return 0;
}



void* __rb_delete(RB_TREE* ptree, RB_NODE* pnode,int keep,int recursive)
{
	void* pret=pnode->m_value;
	RB_NODE* v = pnode;
	RB_NODE* u = __rb_bst_replace(v);
	RB_NODE* sibling;

	int uvblack = 0;
	if ((u == NULL || u->m_color == RB_BLACK) && v->m_color == RB_BLACK ) {
		uvblack = 1;
	}

	if (u == NULL) {
		if (v== ptree->m_root) {
			ptree->m_root = NULL;
		} else {
			if (uvblack != 0) {
				fixup_double_black(ptree,v);
			} else {
				sibling = __get_sibling(v);
				if (sibling != NULL) {
					sibling->m_color = RB_RED;
				}
			}

			if (__is_on_left(v) != 0) {
				v->m_parent->m_left = NULL;
			} else {
				v->m_parent->m_right = NULL;
			}
		}

		if (keep == 0 || recursive != 0) {
			ptree->m_destroyfunc(pret);
			pret = NULL;
		}
		ptree->m_freefunc(v);
		return pret;
	}

}

void* rb_delete(RB_TREE* ptree, RB_NODE* pnode,int keep)
{
	return __rb_delete(ptree,pnode,keep,0);
}

void* rb_delete2(RB_TREE* ptree, RB_NODE* pnode,int keep)
{
	void* pret = NULL;
	RB_NODE* target = NULL;
	RB_NODE* child=NULL;
	pret = pnode->m_value;

	DEBUG_INFO("delete pnode %d", pnode);
	if (pnode->m_left == NULL || pnode->m_right == NULL ) {
		target = pnode;
	} else {
		target = rb_node_next(pnode);
		/*swap the data*/
		pnode->m_value = target->m_value;
		target->m_value = NULL;
	}

	if (target->m_left == NULL) {
		child = target->m_right;
	} else {
		child = target->m_left;
	}

	DEBUG_INFO(" ");

	if (target->m_color == RB_BLACK) {
		if (child->m_color == RB_RED) {
			child->m_color = RB_BLACK;
		} else if (target == rb_first(ptree)) {

		} else {
			DEBUG_INFO(" ");
			__rb_delete_repair(ptree,target);		
		}
	} else {
		/*no deletion*/
	}

	DEBUG_INFO(" ");
	if (child != NULL) {
		DEBUG_INFO(" ");
		child->m_parent = target->m_parent;
	}

	DEBUG_INFO(" ");
	if (target == target->m_parent->m_left) {
		DEBUG_INFO(" ");
		target->m_parent->m_left = child;
	} else {
		DEBUG_INFO(" ");
		target->m_parent->m_right = child;
	}

	if (keep == 0) {
		ptree->m_freefunc(pret);
		pret = NULL;
	}

	DEBUG_INFO(" ");
	ptree->m_freefunc(target);
	DEBUG_INFO(" ");
	
	return pret;
}

RB_NODE* rb_find(RB_TREE* ptree, void*arg)
{
	int ret;
	RB_NODE* pnode = ptree->m_root;

	while (1){
		if (pnode == NULL) {
			return NULL;
		}

		ret = ptree->m_comparefunc(pnode->m_value, arg);
		if (ret == 0) {			
			return pnode;
		} else if (ret > 0) {
			pnode = pnode->m_right;
		} else {
			pnode = pnode->m_left;
		}
	}
	return NULL;
}

RB_NODE* _get_leaf(RB_NODE* pnode)
{
	if (pnode == NULL) {
		return NULL;
	}


	while(1) {
		if (pnode->m_left != NULL) {
			pnode = pnode->m_left;
		} else if (pnode->m_right != NULL) {
			pnode = pnode->m_right;
		} else {
			return pnode;
		}
	}
}


void destroy_rb_tree(RB_TREE** pptree,int keep)
{
	if (pptree == NULL || *pptree == NULL) {
		return;
	}

	RB_TREE* ptree = *pptree;
	rb_free_func_t freefunc = ptree->m_freefunc;
	rb_destroy_func_t destroyfunc = ptree->m_destroyfunc;
	RB_NODE* pcur;
	RB_NODE* parent;
	int isright;

	pcur = _get_leaf(ptree->m_root);

	while(1) {
		if (pcur == NULL) {
			break;
		}
		if (keep == 0) {
			destroyfunc(pcur->m_value);
		}
		pcur->m_value = NULL;
		parent = pcur->m_parent;
		isright = 0;
		if (parent != NULL && parent->m_right == pcur) {
			isright = 1;
			parent->m_right = NULL;
		} else if (parent != NULL && parent->m_left == pcur) {
			parent->m_left = NULL;
		}	
		freefunc(pcur);
		pcur = _get_leaf(parent);
	}


	freefunc(ptree);
	*pptree = NULL;
	return;
}