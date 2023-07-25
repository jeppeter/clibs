
int enumdisplay_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	pdisplay_name_t pnames = NULL;
	int namesize = 0;
	int namelen = 0;
	int ret;
	pdisplay_mode_t pmode = NULL;
	int modesize = 0;
	int modelen = 0;
	int i, j;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(parsestate);
	init_log_level(pargs);

	ret = enum_display_devices(0, &pnames, &namesize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "enum device error[%d]\n", ret);
		goto out;
	}
	namelen = ret;
	for (i = 0; i < namelen; i++) {
		ret = enum_display_mode(pnames[i].m_name, &pmode, &modesize);
		if (ret < 0) {
			fprintf(stdout, "[%s] has mode[0]\n", pnames[i].m_name);
		} else {
			modelen = ret;
			fprintf(stdout, "[%s] has mode[%d]\n", pnames[i].m_name, modelen);
			for (j = 0; j < modelen; j++) {
				fprintf(stdout, "    width=%d;height=%d;freq=%d;devname=%s\n", pmode[j].m_width, pmode[j].m_height, pmode[j].m_refresh, pmode[i].m_devname);
			}
		}
	}

	ret = 0;
out:
	enum_display_mode(NULL, &pmode, &modesize);
	enum_display_devices(1, &pnames, &namesize);
	SETERRNO(ret);
	return ret;
}

int setdisplay_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	pdisplay_mode_t pmode = NULL;
	int idx;
	int cnt = 0;
	DWORD flags = 0;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx]; idx++) {
		cnt ++;
	}

	if (cnt < 4) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "need devname width height freq\n");
		goto out;
	}

	pmode =(pdisplay_mode_t) malloc(sizeof(*pmode));
	if (pmode == NULL) {
		GETERRNO(ret);
		goto out;
	}
	memset(pmode, 0, sizeof(*pmode));
	strncpy_s(pmode->m_devname, sizeof(pmode->m_devname), parsestate->leftargs[0], sizeof(pmode->m_devname));
	pmode->m_width = atoi(parsestate->leftargs[1]);
	pmode->m_height = atoi(parsestate->leftargs[2]);
	pmode->m_refresh = atoi(parsestate->leftargs[3]);
	if (cnt > 4) {
		flags = (DWORD)atoi(parsestate->leftargs[4]);
	}


	ret = set_display_mode(pmode, flags);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "[%s].width[%d].height[%d].freq[%d] flags[0x%lx] error[%d]\n", pmode->m_devname, pmode->m_width, pmode->m_height, pmode->m_refresh, flags, ret);
		goto out;
	}

	fprintf(stdout, "[%s].width[%d].height[%d].freq[%d] flags[0x%lx] succ\n", pmode->m_devname, pmode->m_width, pmode->m_height, pmode->m_refresh, flags);

	ret = 0;
out:
	if (pmode) {
		free(pmode);
	}
	pmode = NULL;
	SETERRNO(ret);
	return ret;
}

int displayinfo_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	int dispsize=0,displen = 0;
	int i;
	pdisplay_info_t pinfo = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	uint32_t scaleinfo = 0;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(parsestate);

	init_log_level(pargs);

	ret = get_display_info(0,&pinfo,&dispsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not list display error [%d]\n", ret);
		goto out;
	}

	displen = ret;
	for (i=0;i<displen;i++) {
		fprintf(stdout,"[%d] [%s] path [%s] source [%d] target [%d] LUID [0x%lx.0x%lx]\n",
			i,pinfo[i].m_devname,pinfo[i].m_devpath,pinfo[i].m_sourceid, pinfo[i].m_targetid,pinfo[i].m_targetluid.HighPart,pinfo[i].m_targetluid.LowPart);

		ret = get_display_rescale(&(pinfo[i]),&scaleinfo,NULL,NULL);
		if (ret >= 0) {
			fprintf(stdout, "[%d] scale [%d]\n", i,scaleinfo);
		} else {
			fprintf(stdout, "[%d] can not get scale\n",i);
		}
	}

	ret = 0;
out:
	get_display_info(1,&pinfo,&dispsize);
	SETERRNO(ret);
	return ret;
}

static const int DpiVals[] = { 100,125,150,175,200,225,250,300,350, 400, 450, 500 };

/*Get default DPI scaling percentage.
The OS recommented value.
*/
int GetRecommendedDPIScaling()
{
    int dpi = 0;
    BOOL retval = SystemParametersInfo(SPI_GETLOGICALDPIOVERRIDE, 0, (LPVOID)&dpi, 1);

    if (retval != 0)
    {
    	fprintf(stdout,"dpi %d\n",dpi);
        int currDPI = DpiVals[dpi * -1];
        return currDPI;
    }
    fprintf(stdout,"retval %d\n",retval);

    return -1;
}


int getdpi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	uint32_t dpival;
	uint32_t *availscales=NULL;
	int availlen=0,availsize=0;
	pdisplay_info_t pinfos = NULL;
	int infosize=0,infolen=0;
	int ret;
	int i;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(parsestate);

	init_log_level(pargs);

	ret = get_display_info(0,&pinfos,&infosize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not get display info\n");
		goto out;
	}

	infolen = ret;
	if (infolen < 1) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "infolen %d not valid\n", infolen);
		goto out;
	}

	ret = get_display_rescale(&pinfos[0],&dpival,&availscales,&availsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "set %d error[%d]\n",dpival,ret );
		goto out;
	}

	fprintf(stdout, "dpival %d \n", dpival);
	availlen = ret;
	for(i=0;i<availlen ;i++) {
		if ((i%5) == 0) {
			fprintf(stdout,"   ");
		}
		fprintf(stdout," %05d", availscales[i]);
	}
	fprintf(stdout, "\n");
	ret = 0;
out:
	get_display_rescale(NULL,NULL,&availscales,&availsize);
	get_display_info(1,&pinfos,&infosize);
	SETERRNO(ret);
	return ret;
}


int setdpi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	int dpival = 100;
	pdisplay_info_t pinfos = NULL;
	int infosize=0,infolen=0;
	int ret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		dpival = atoi(parsestate->leftargs[0]);
	}

	ret = get_display_info(0,&pinfos,&infosize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not get display info\n");
		goto out;
	}

	infolen = ret;
	if (infolen < 1) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "infolen %d not valid\n", infolen);
		goto out;
	}

	ret = set_display_rescale(&pinfos[0],(uint32_t)dpival);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "set %d error[%d]\n",dpival,ret );
		goto out;
	}

	fprintf(stdout, "set %d succ\n", dpival);
	ret = 0;
out:
	get_display_info(1,&pinfos,&infosize);
	SETERRNO(ret);
	return ret;
}