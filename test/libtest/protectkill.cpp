

int protectkill_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	int cntargc = 0;
	void* pmon = NULL;
	char* mycmd = NULL;
	int mysize = 0;
	char* peercmd = NULL;
	int peersize = 0;
	int mode = PROC_APP_MODE;
	int waitmills = 3000;
	int interval = 50;
	BOOL bret;
	int peerpid = 0;
	char* verbosestr = NULL;
	int verbosesize = 0;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);

	bret = SetConsoleCtrlHandler(HandlerConsoleRunOk, TRUE);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
		goto out;
	}

	ret = snprintf_safe(&verbosestr, &verbosesize, "");
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	cntargc = 0;
	while (cntargc < pargs->m_verbose) {
		if (cntargc == 0) {
			ret = append_snprintf_safe(&verbosestr, &verbosesize, "-");
			if (ret < 0) {
				GETERRNO(ret);
				goto out;
			}
		}
		ret = append_snprintf_safe(&verbosestr, &verbosesize, "v");
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
		cntargc ++;
	}

	cntargc = 0;
	while (parsestate->leftargs && parsestate->leftargs[cntargc]) {
		cntargc ++;
	}

	if (pargs->m_timeout > 0) {
		waitmills = pargs->m_timeout;
	}

	if (cntargc == 0) {
		ret = snprintf_safe(&mycmd, &mysize, "protectkill %s --timeout %d app",verbosestr, waitmills);
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
		ret =  snprintf_safe(&peercmd, &peersize, "protectkill %s --timeout %d monitor",verbosestr, waitmills);
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
		mode = PROC_APP_MODE;
		peerpid = 0;
	} else if (str_nocase_cmp(parsestate->leftargs[0], "monitor") == 0) {
		ret = snprintf_safe(&mycmd, &mysize, "protectkill %s --timeout %d monitor",verbosestr, waitmills);
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
		ret =  snprintf_safe(&peercmd, &peersize, "protectkill %s --timeout %d app",verbosestr, waitmills);
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
		mode = PROC_MONITOR_MODE;
		peerpid = atoi(parsestate->leftargs[1]);
	}  else if (str_nocase_cmp(parsestate->leftargs[0], "app") == 0) {
		ret = snprintf_safe(&mycmd, &mysize, "protectkill %s --timeout %d app", verbosestr, waitmills);
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
		ret =  snprintf_safe(&peercmd, &peersize, "protectkill %s --timeout %d monitor",verbosestr, waitmills);
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}
		mode = PROC_APP_MODE;
		peerpid = atoi(parsestate->leftargs[1]);
	}	

	pmon = start_protect_monitor(mycmd, peercmd, peerpid, mode, waitmills, interval);
	if (pmon == NULL) {
		GETERRNO(ret);
		goto out;
	}

	while (st_run) {
		SleepEx(500, FALSE);
	}
	fprintf(stdout, "exit [%ld]\n", GetCurrentProcessId());

	ret = 0;
out:
	stop_protect_monitor(&pmon);
	snprintf_safe(&mycmd, &mysize, NULL);
	snprintf_safe(&peercmd, &peersize, NULL);
	SETERRNO(ret);
	return ret;
}

int openmux_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	char* muxname = NULL;
	HANDLE mux = NULL;
	BOOL bret;
	int cnt = 0;
	int created = 0;

	init_log_level(pargs);
	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	bret = SetConsoleCtrlHandler(HandlerConsoleRunOk, TRUE);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
		goto out;
	}

	muxname = parsestate->leftargs[0];
	if (parsestate->leftargs && parsestate->leftargs[1]) {
		created = 1;
	}
	while (st_run) {
		mux = open_mutex(muxname, created);
		if (mux != NULL) {
			fprintf(stdout, "%s [%s] succ\n", created ? "create" : "open", muxname);
			break;
		}
		GETERRNO(ret);
		fprintf(stdout, "%s [%s] error[%d]\n", created ? "create" : "open", muxname, ret);
		SleepEx(1000, TRUE);
	}

	cnt = 0;
	while (st_run) {
		fprintf(stdout, "[%s] hold on [%d]\n", muxname, cnt);
		SleepEx(1000, TRUE);
		cnt ++;
	}

	ret = 0;
out:
	if (mux != NULL) {
		CloseHandle(mux);
	}
	mux = NULL;
	SETERRNO(ret);
	return ret;
}

int waitevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* evtname = NULL;
	int ret;
	HANDLE evt = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	BOOL bret;
	int cnt = 0, waitcnt = 0;
	DWORD dret;

	init_log_level(pargs);

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	bret = SetConsoleCtrlHandler(HandlerConsoleRunOk, TRUE);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
		goto out;
	}

	evtname = parsestate->leftargs[0];
	evt = open_event(evtname, 1);
	if (evt == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "create [%s] error[%d]\n", evtname, ret );
		goto out;
	}

	cnt = 0;
	waitcnt = 0;
	while (st_run) {
		dret = WaitForSingleObject(evt, 1000);
		if (dret == WAIT_OBJECT_0) {
			cnt ++;
			ResetEvent(evt);
			fprintf(stdout, "[%s] signaled [%d]\n", evtname, cnt);
			continue;
		}
		fprintf(stdout, "[%s] not signaled [%d]\n", evtname, waitcnt);
		waitcnt ++;
	}

	ret = 0;
out:
	if (evt != NULL) {
		CloseHandle(evt);
	}
	evt = NULL;
	SETERRNO(ret);
	return ret;
}

int setevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* evtname = NULL;
	int ret;
	HANDLE evt = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	BOOL bret;

	init_log_level(pargs);

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	bret = SetConsoleCtrlHandler(HandlerConsoleRunOk, TRUE);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
		goto out;
	}

	evtname = parsestate->leftargs[0];
	evt = open_event(evtname, 0);
	if (evt == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "open [%s] error[%d]\n", evtname, ret);
		goto out;
	}

	bret = SetEvent(evt);
	if (!bret) {
		GETERRNO(ret);
		goto out;
	}

	fprintf(stdout, "set [%s] succ\n", evtname);


	ret = 0;
out:
	if (evt != NULL) {
		CloseHandle(evt);
	}
	evt = NULL;
	SETERRNO(ret);
	return ret;
}