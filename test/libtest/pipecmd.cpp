
int pipesvrtimeout_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int timeout = 500;
	char* pipename = NULL;
	void* pnp = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	int argcnt = 0;
	DWORD dret;
	HANDLE evt;
	int cnt;
	int ret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);

	for (; parsestate->leftargs && parsestate->leftargs[argcnt] != NULL;) {
		argcnt ++;
	}

	if (argcnt == 0) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "must specified pipename\n");
		goto out;
	}

	pipename = parsestate->leftargs[0];
	if (argcnt > 1) {
		timeout = atoi(parsestate->leftargs[1]);
	}


	pnp = bind_namedpipe(pipename);
	if (pnp == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret = get_namedpipe_connstate(pnp);
	if (ret == 0) {
		fprintf(stdout, "[%s] connected\n", pipename);
	} else {
		for(cnt = 0; cnt >= 0;cnt ++) {
			evt = get_namedpipe_connevt(pnp);
			dret = WaitForSingleObject(evt, (DWORD)timeout);
			if (dret == WAIT_OBJECT_0) {
				ret = complete_namedpipe_connpending(pnp);
				if (ret > 0) {
					fprintf(stdout, "[%s] connected\n", pipename);
					break;
				} else if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO("[%s] wait connect error [%d]\n", pipename,ret);
					goto out;
				}
			} else if (dret == WAIT_TIMEOUT) {
				DEBUG_INFO("wait [%s] on [%d] time [%d]",pipename,timeout,cnt);
			} else {
				GETERRNO(ret);
				ERROR_INFO("wait [%s] connect error [%d] [%d]", pipename, dret, ret);
				goto out;
			}
		}
	}

	ret  = 0;
out:
	close_namedpipe(&pnp);
	SETERRNO(ret);
	return ret;
}