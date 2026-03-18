#include <rb_func.h>
#include <rb_priv.h>
#include <rb_tree.h>
#include <cmn_err.h>




void __rb_memset(void* ptr, unsigned char ch, size_t sz)
{
	unsigned char* pptr = (unsigned char*) ptr;
	size_t i;
	for(i=0;i<sz;i++) {
		pptr[i] = ch;
	}
	return;
}

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

RB_NODE* __rb_find_parent(RB_TREE*ptree, void* arg)
{
	RB_NODE* pcurnode= ptree->m_root;
	RB_NODE* parentnode = ptree->m_root;
	int ret;
	while(1) {
		if (pcurnode == NULL) {
			break;
		}
		ret = ptree->m_comparefunc(arg,pcurnode->m_value);
		if (ret == 0) {
			return pcurnode;
		} else if (ret < 0) {
			parentnode = pcurnode;
			pcurnode = parentnode->m_right;
		} else if (ret > 0) {
			parentnode = pcurnode;
			pcurnode = parentnode->m_left;
		}
	}

	return parentnode;
}

RB_NODE* __new_node(RB_TREE* ptree, void* arg)
{
	RB_NODE* pnode=NULL;
	int ret;

	pnode = ptree->m_mallocfunc(sizeof(*pnode));
	if (pnode == NULL) {
		ret = - CMN_NOBUFS;
		goto fail;
	}

	pnode->m_left = NULL;
	pnode->m_right = NULL;
	pnode->m_parent = NULL;
	pnode->m_value = arg;
	pnode->m_color = RB_RED;

	return pnode;
fail:
	SETERRNO(ret);
	return NULL;
}

RB_NODE* rb_insert(RB_TREE* ptree,void* arg)
{
	RB_NODE* pinsertnode=NULL;
	RB_NODE* parent=NULL;
	int ret;
	/*it is one the root*/
	if (ptree->m_root == NULL) {
		pinsertnode = ptree->m_mallocfunc(sizeof(*pinsertnode));
		if (pinsertnode == NULL) {
			ret = - CMN_NOBUFS;
			goto fail;
		}

		pinsertnode = __new_node(ptree,arg);
		if (pinsertnode != NULL) {
			ptree->m_root = pinsertnode;	
		}		
		return pinsertnode;
	}

	/*now we should check the value */
	nearnode = __rb_find_parent(ptree,arg);
	if (nearnode == NULL)


	return pinsertnode;
fail:
	if (pinsertnode) {
		ptree->m_freefunc(pinsertnode);
	}
	pinsertnode = NULL;
	SETERRNO(ret);
	return NULL;
}