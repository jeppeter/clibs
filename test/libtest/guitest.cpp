
int enumdisplay_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	pdisplay_name_t pnames=NULL;
	int namesize=0;
	int namelen = 0;
	int ret;
	pdisplay_mode_t pmode=NULL;
	int modesize=0;
	int modelen = 0;
	int i,j;

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
    namelen = ret;
    for (i=0;i<namelen;i++) {
    	ret = enum_display_mode(pnames[i].m_name, &pmode,&modesize);
    	if (ret < 0) {
    		fprintf(stdout,"[%s] has mode[0]\n", pnames[i].m_name);
    	} else {
    		modelen = ret;
    		fprintf(stdout,"[%s] has mode[%d]\n", pnames[i].m_name, modelen);
    		for (j=0;j<modelen;j++) {
    			fprintf(stdout, "    width=%d;height=%d;freq=%d\n", pmode[j].m_width, pmode[j].m_height,pmode[j].m_refresh);
    		}
    	}
    }

    ret = 0;
out:
	enum_display_mode(NULL,&pmode,&modesize);
	enum_display_devices(1,&pnames,&namesize);
	SETERRNO(ret);
	return ret;
}