

int sigfd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	sigset_t sigmaskv;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;

    init_log_verbose(pargs);
    sigemptyset(&sigmaskv);
    for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
    	sigaddset(&sigmaskv,atoi(parsestate->leftargs[i]));
    }



    ret = 0;
out:
	SETERRNO(ret);
	return ret;
}