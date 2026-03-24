
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

	if (pa->m_val < pb->m_val) {
		return -1;
	} else if (pa->m_val > pb->m_val) {
		return 1;
	} else {
		if (pa == pb) {
			return 0;
		}

		aaddr = (uint64_t) pa;
		baddr = (uint64_t) pb;
		if (aaddr < baddr) {
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

void print_val(void* p,FILE* fp,int tab)
{
	PRBVAL_t pval = (PRBVAL_t) p;
	tab = tab;
	fprintf(fp," .m_val %d\n", pval->m_val);
	return;

	
}

int rbtest_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	RB_TREE* ptree=NULL;
	PRBVAL_t pval=NULL;
	PRBVAL_t pret;
	RB_NODE* pnode;
	int curval;
	int i;
	pargs_options_t pargs = (pargs_options_t) popt;
	int af6 = 0;
	std::map<int,PRBVAL_t> mapvals;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);
	ptree = init_rb_tree(malloc_func,free_func,compare_func,destroy_val,print_val);
	if (ptree == NULL) {
		GETERRNO(ret);
		goto out;
	}

	if (pargs->m_af6) {
		af6 = 1;
	}

	for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
		DEBUG_INFO("insert %s", parsestate->leftargs[i]);
		curval = atoi(parsestate->leftargs[i]);
		if (curval < 0) {
			continue;
		}
		pval = alloc_val(curval);
		if (pval == NULL) {
			GETERRNO(ret);
			goto out;
		}

		pnode = rb_insert(ptree,pval);
		if (pnode == NULL) {
			GETERRNO(ret);
			goto out;
		}

		rb_print_tree(ptree,stderr);

		//fprintf(stdout,"pnode %p\n",pnode);
		mapvals.insert({curval,pval});
		pval = NULL;
	}

	for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
		curval = atoi(parsestate->leftargs[i]);
		if (curval > 0) {
			continue;
		}
		auto iter = mapvals.find(-curval);
		if (iter == mapvals.end()) {
			ret = - ERROR_INVALID_PARAMETER;
			fprintf(stderr,"can not find %d value\n",-curval);
			goto out;
		}
		pval = iter->second;
		ERROR_INFO("pval %p",pval);
		pnode = rb_find(ptree,pval);
		if (pnode != NULL) {
			ret = - ERROR_INVALID_PARAMETER;
			fprintf(stderr,"can not find %d\n", -curval);
			goto out;
		}
		if (af6) {
			pret = (PRBVAL_t)rb_delete(ptree,pnode,1);	
		} else {
			pret = (PRBVAL_t)rb_delete(ptree,pnode,0);
		}
			
		if (pret != pval && af6 != 0) {
			ret = - ERROR_INVALID_PARAMETER;
			fprintf(stderr,"can not get value %d:%p\n",pval->m_val,pval);
			goto out;
		}
		rb_print_tree(ptree,stderr);
		pval = NULL;
	}


	ret = 0;
out:
	if (pval) {
		destroy_val(pval);
	}
	pval = NULL;
	DEBUG_INFO("ptree %p",ptree);
	if (af6) {
		destroy_rb_tree(&ptree,1);	
	} else {
		destroy_rb_tree(&ptree,0);
	}

	while(mapvals.size() > 0) {
		auto iter = mapvals.begin();
		pval = iter->second;
		mapvals.erase(iter);
		if (af6) {
			free_func(pval);
		}
		pval = NULL;
	}
	
	SETERRNO(ret);
	return ret;
}


int rbrand_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	RB_TREE* ptree=NULL;
	PRBVAL_t pval=NULL;
	PRBVAL_t pret;
	RB_NODE* pnode,*pprev;
	int i,curval,cpos;
	pargs_options_t pargs = (pargs_options_t) popt;
	int af6 = 0;
	std::vector<int> vvals;
	std::map<int,PRBVAL_t> mapvals;
	int maxnum=100;
	int times=10;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);
	ptree = init_rb_tree(malloc_func,free_func,compare_func,destroy_val,print_val);
	if (ptree == NULL) {
		GETERRNO(ret);
		goto out;
	}

	if (pargs->m_af6) {
		af6 = 1;
	}

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		maxnum = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs && parsestate->leftargs[1]) {
			times = atoi(parsestate->leftargs[1]);
		}
	}

	if(maxnum < (times*2)) {
		fprintf(stderr,"times %d * 2 > maxnum %d\n", times,maxnum);
		ret = - ERROR_INVALID_PARAMETER;
		goto out;
	}

	/*to init rand seed*/
	srand((unsigned int)time(NULL));

	while ((int)vvals.size() < times) {
		curval = (((int)((double)rand() * RAND_MAX)) % maxnum);
		auto positer = mapvals.find(curval);
		if (positer != mapvals.end() || curval == 0) {
			continue;
		}

		fprintf(stderr,"insert [%d]\n", curval);
		pval = alloc_val(curval);
		if (pval == NULL) {
			GETERRNO(ret);
			goto out;
		}

		mapvals.insert({curval,pval});

		pnode = rb_insert(ptree,pval);
		if (pnode == NULL) {
			GETERRNO(ret);
			goto out;
		}

		vvals.push_back(curval);
		pval = NULL;
	}

	while(vvals.size() != 0) {
		cpos = (((int)((double)rand() * RAND_MAX)) % (int)vvals.size());
		curval = vvals.at((uint64_t)cpos);
		fprintf(stderr,"delete [%d]\n",curval);
		auto citer = mapvals.find(curval);
		if (citer == mapvals.end()) {
			ret = - ERROR_INVALID_PARAMETER;
			fprintf(stderr,"can not find %d\n",curval);
			goto out;
		}
		pval = citer->second;
		pnode = rb_find(ptree,pval);
		if (pnode == NULL) {
			ret = - ERROR_INVALID_PARAMETER;
			fprintf(stderr,"can not find [%d] for node\n",curval);
			goto out;
		}
		if (af6) {
			pret =(PRBVAL_t) rb_delete(ptree,pnode,1);	
		} else {
			pret = (PRBVAL_t)rb_delete(ptree,pnode,0);
		}
		pnode = NULL;
		
		if (af6 != 0 && (pret != pval)) {
			ret =  - ERROR_INVALID_PARAMETER;
			fprintf(stderr,"can not match pret %p pval %p\n",pret,pval);
			pval = NULL;
			goto out;
		}

		mapvals.erase(citer);
		vvals.erase(vvals.begin() + cpos);

		if (af6) {
			free_func(pval);
		}
		pval = NULL;

		fprintf(stderr,"check [%d]\n",curval);
		if (vvals.size() > 0) {
			i = 0;
			pnode = rb_first(ptree);
			while((i+1)< (int)vvals.size()) {
				PRBVAL_t aval,bval;
				if (pnode == NULL) {
					ret = - ERROR_INVALID_PARAMETER;
					fprintf(stderr,"cannot find %d size",i);
					goto out;
				}

				pprev = pnode;
				pnode = rb_node_next(pprev);
				if (pnode == NULL) {
					ret = - ERROR_INVALID_PARAMETER;
					fprintf(stderr,"can not get pnode\n");
					goto out;
				}

				aval = (PRBVAL_t)rb_node_get(pprev);
				bval = (PRBVAL_t) rb_node_get(pnode);

				ret = compare_func(aval, bval);
				if (ret >= 0) {
					ret = - ERROR_INVALID_PARAMETER;
					fprintf(stderr,"%d:%p >= %d:%p\n", aval->m_val,aval,bval->m_val,bval);
					goto out;
				}

				i += 1;
			}
		}
	}



	ret = 0;
out:
	if (pval) {
		destroy_val(pval);
	}
	pval = NULL;
	DEBUG_INFO("ptree %p",ptree);
	if (af6) {
		destroy_rb_tree(&ptree,1);	
	} else {
		destroy_rb_tree(&ptree,0);
	}

	while(vvals.size() > 0) {
		vvals.erase(vvals.begin());
	}

	while(mapvals.size() > 0) {
		auto iter = mapvals.begin();
		PRBVAL_t pcc = iter->second;
		mapvals.erase(iter);
		if (af6) {
			free_func(pcc);
		}
		pcc = NULL;
	}
	
	SETERRNO(ret);
	return ret;
}