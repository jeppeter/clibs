
int listuser_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	HANDLE exithd=NULL;
	pargs_options_t pargs = (pargs_options_t)popt;
	puser_info_t puserinfo=NULL;
	int usersize = 0;
	int userlen = 0;
	int i;
	int ret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(parsestate);

	init_log_level(pargs);
	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret = get_user_info(0,exithd,&puserinfo,&usersize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "get user info error [%d]\n", ret);
		goto out;
	}

	userlen = ret;
	for(i=0;i<userlen;i++) {
		fprintf(stdout,"[%d].name[%s].sid[%s]\n",i,puserinfo[i].m_name,puserinfo[i].m_sid);
	}
	ret = 0;
out:	
	get_user_info(1,NULL,&puserinfo,&usersize);
	close_ctrlc_handle();
	SETERRNO(ret);
	return ret;

}

int getprocmem_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t)popt;
	int i;
	int pid;
	uint64_t memsize;
	int ret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(parsestate);

	init_log_level(pargs);

	for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
		pid = atoi(parsestate->leftargs[i]);
		ret = get_proc_memory(pid,&memsize);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "get [%d] error[%d]\n", pid, ret);
			goto out;
		}
		fprintf(stdout,"[%d] memory [%lld:0x%llx]\n",pid,memsize,memsize);
	}

	ret = 0;
out:	
	SETERRNO(ret);
	return ret;

}