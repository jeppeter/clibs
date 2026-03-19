
int HANDLE_share(int num)
{
	std::shared_ptr<HANDLE> phds(new HANDLE[(size_t)num]);
	HANDLE* phd;
	int i;

	phd = phds.get();
	for(i=0;i<num;i++) {
		phd[i] = (HANDLE)(addr_t)i;
	}
	DEBUG_BUFFER_FMT(phd,sizeof(*phd)*num,"num %d cnt %d",num,phds.use_count());
	return 0;
}

int get_HANDLE_share(int num, std::shared_ptr<HANDLE>& v)
{
	std::shared_ptr<HANDLE> phds(new HANDLE[(size_t)num]);
	HANDLE* phd;
	int i;

	phd = phds.get();
	for(i=0;i<num;i++) {
		phd[i] = (HANDLE)(addr_t)(i*2);
	}
	DEBUG_INFO("phd %p",phd);
	v.swap(phds);
	return 0;
}


int cppcon_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	pargs_options_t pargs = (pargs_options_t)popt;
	std::shared_ptr<HANDLE> nv;
	HANDLE* pcc;
	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(parsestate);
	init_log_level(pargs);
	HANDLE_share(10);
	get_HANDLE_share(10,nv);
	pcc = nv.get();
	DEBUG_BUFFER_FMT(pcc,sizeof(*pcc)*10,"new swap");

	ret = 0;
	SETERRNO(ret);
	return ret;
}

typedef struct rbval {
	int m_val;
} RBVAL_t,*PRBVAL_t;

void* malloc_func(size_t size)
{
	return malloc(size);
}

void free_func(void* ptr)
{
	free(ptr);
	return;
}

int compare_func(void* a,void* b)
{
	PRBVAL_t pa=(PRBVAL_t)a;
	PRBVAL_t pb =(PRBVAL_t)b;
	uint64_t aaddr,baddr;

	if (pa->m_val > pb->m_val) {
		return -1;
	} else if (pa->m_val < pb->m_val) {
		return 1;
	} else {
		if (pa == pb) {
			return 0;
		}

		aaddr = (uint64_t) pa;
		baddr = (uint64_t) pb;
		if (aaddr > baddr) {
			return -1;
		} else {
			return 1;
		}
	}
}

PRBVAL_t alloc_val(int a)
{
	PRBVAL_t pret= (PRBVAL_t)malloc(sizeof(*pret));
	if (pret != NULL) {
		pret->m_val = a;
	}
	return pret;
}

void destroy_val(void* p)
{
	if (p) {
		free(p);
	}
	return;
}

int rbtest_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	RB_TREE* ptree=NULL;
	PRBVAL_t pval=NULL;
	PRBVAL_t pcur=NULL;
	RB_NODE* pnode;
	int i;
	pargs_options_t pargs = (pargs_options_t) popt;

	init_log_level(pargs);
	ptree = init_rb_tree(malloc_func,free_func,compare_func,destroy_val);
	if (ptree == NULL) {
		GETERRNO(ret);
		goto out;
	}

	for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
		DEBUG_INFO("insert %s", parsestate->leftargs[i]);
		pval = alloc_val(atoi(parsestate->leftargs[i]));
		if (pval == NULL) {
			GETERRNO(ret);
			goto out;
		}

		pnode = rb_insert(ptree,pval);
		if (pnode == NULL) {
			GETERRNO(ret);
			goto out;
		}
		pval = NULL;
	}

	pnode = rb_first(ptree);
	while(1) {
		if (pnode == NULL) {
			break;
		}
		pcur = (PRBVAL_t) rb_node_get(pnode);
		fprintf(stdout,"value [%d:%p]\n",pcur->m_val,pcur);
		pnode = rb_node_next(pnode);
	}

	ret = 0;
out:
	if (pval) {
		destroy_val(pval);
	}
	pval = NULL;	
	destroy_rb_tree(&ptree,0);
	SETERRNO(ret);
	return ret;



}