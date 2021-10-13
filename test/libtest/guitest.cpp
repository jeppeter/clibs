
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