
int enumdisplay_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	pdisplay_name_t pnames=NULL;
	int namesize=0;
	int ret;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
	init_log_level(pargs);

    ret = enum_display_devices(0,&pnames,&namesize);
    if (ret < 0) {
    	GETERRNO(ret);
    	fprintf(stderr,"enum device error[%d]\n",ret);
    	goto out;
    }

    ret = 0;
out:
	enum_display_devices(1,&pnames,&namesize);
	SETERRNO(ret);
	return ret;
}