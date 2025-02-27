
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
out:
	SETERRNO(ret);
	return ret;
}