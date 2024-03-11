
int findwin_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int idx,jdx;
	char* pidstr = NULL;
	int pid;
	HWND* phds=NULL;
	int hdsize=0;
	int hdlen=0;
	char* ptext=NULL;
	int textsize=0;
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	for(idx=0;parsestate->leftargs != NULL && parsestate->leftargs[idx] != NULL;idx++) {
		pidstr = parsestate->leftargs[idx];
		pid = atoi(pidstr);

		ret = get_window_from_pid(pid,&phds,&hdsize);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "get [%d] window error [%d]\n", pid,ret);
			goto out;
		}

		hdlen = ret;
		for(jdx = 0; jdx < hdlen; jdx ++) {
			ret = get_window_text(phds[jdx],&ptext,&textsize);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "get [%s].[%d] [0x%p] error[%d]\n", pidstr,jdx, phds[jdx], ret);
				goto out;
			}
			fprintf(stdout,"[%s].[%d] [0x%p] [%s]\n", pidstr, jdx, phds[jdx], ptext);
		}
	}

	ret = 0;
	out:
	get_window_from_pid(0,&phds,&hdsize);
	hdlen = 0;
	get_window_text(NULL,&ptext,&textsize);
	SETERRNO(ret);
	return ret;
}

int setwinpos_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	uint64_t tmpval = 0;
	int tmpi = -1;
	HWND winhd=NULL;
	HWND afterhd = (HWND)HWND_TOPMOST;
	int x = 0;
	int y = 0;
	int cx = 10;
	int cy = 10;
	UINT uflags = SWP_SHOWWINDOW;
	int idx=0;
	BOOL bret;
	pargs_options_t pargs = (pargs_options_t) popt;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		GET_OPT_NUM64(tmpval, "winhd");
		winhd = (HWND) tmpval;
		if (parsestate->leftargs[1]) {
			GET_OPT_INT(tmpi,"afterhd");
			afterhd = (HWND)(uint64_t)tmpi;
			if (parsestate->leftargs[2]) {
				GET_OPT_INT(x,"x");
				if (parsestate->leftargs[3]) {
					GET_OPT_INT(y, "y");
					if (parsestate->leftargs[4]) {
						GET_OPT_INT(cx,"cx");
						if (parsestate->leftargs[5]) {
							GET_OPT_INT(cy, "cy");
							if (parsestate->leftargs[6]) {
								GET_OPT_NUM64(tmpval, "uflags");
								uflags = (UINT)tmpval;
							}
						}
					}
				}
			}			
		}
	}

	if (winhd == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "must set winhd\n");
		goto out;
	}

	bret= SetWindowPos(winhd,afterhd,x,y,cx,cy,uflags);
	if (!bret) {
		GETERRNO(ret);
		fprintf(stderr, "set 0x%p after 0x%p x %d y %d cx %d cy %d uflags 0x%x error[%d]\n", winhd,afterhd,x,y,cx,cy, uflags, ret);
		goto out;
	}
	fprintf(stdout, "set 0x%p after 0x%p x %d y %d cx %d cy %d uflags 0x%x succ\n", winhd,afterhd,x,y,cx,cy, uflags);
	ret = 0;
out:
	SETERRNO(ret);
	return ret;
}