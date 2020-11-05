
#define  APP_MODE           1
#define  MONITOR_MODE       2


typedef struct __protect_monitor {
	HANDLE m_thr;
	HANDLE m_exitevt;
	HANDLE m_exitnotifyevt;
	char* m_curcmdline;
	char* m_peercmdline;
	DWORD m_peerpid;
	int m_exited;
	int m_exitcode;
	int m_dummy;
} protect_monitor_t, *pprotect_monitor_t;


void __free_protect_monitor(pprotect_monitor_t *ppmon)
{
	if (ppmon && *ppmon) {
		pprotect_monitor_t pmon = (*ppmon);
		int cnt = 0;
		while (pmon->m_exited == 0) {
			SetEvent(pmon->m_exitevt);
			SleepEx(10, TRUE);
			cnt ++;
			if (cnt > 20) {
				ERROR_INFO("wait [%p] [%d]", pmon->m_thr, cnt);
			}
		}

		if (pmon->m_exitevt != NULL) {
			CloseHandle(pmon->m_exitevt);
		}
		pmon->m_exitevt = NULL;

		if (pmon->m_exitnotifyevt != NULL) {
			CloseHandle(pmon->m_exitnotifyevt);
		}
		pmon->m_exitnotifyevt = NULL;

		if (pmon->m_thr != NULL) {
			CloseHandle(pmon->m_thr);
		}
		pmon->m_thr = NULL;

		if (pmon->m_curcmdline) {
			free(pmon->m_curcmdline);
		}
		pmon->m_curcmdline = NULL;

		if (pmon->m_peercmdline) {
			free(pmon->m_peercmdline);
		}
		pmon->m_peercmdline = NULL;
		pmon->m_peerpid = 0;
		free(pmon);
		*ppmon = NULL;
	}
	return;
}

void protect_error_exit(int exitcode,const char* fmt,...)
{
	va_list ap;
	char* str=NULL;
	int strsize=0;
	int ret;
	if (fmt != NULL) {
		va_start(ap,fmt);
		ret = vsnprintf_safe(&str,&strsize,fmt,ap);
		if (ret >= 0) {
			ERROR_INFO("%s",str);
		}
		vsnprintf_safe(&str,&strsize,NULL,ap);
	}
	exit(exitcode);
	return;
}

void normalize_name(char* str)
{
	char* pcurptr = str;

	while(*pcurptr != '\0') {
		if (*pcurptr >= '0' && 
			*pcurptr <= '9') {
			pcurptr ++;
		} else if (*pcurptr >= 'a' &&
			*pcurptr <= 'z') {
			pcurptr ++;
		} else if (*pcurptr >= 'A' &&
			*pcurptr <= 'Z') {
			/*to lower case*/
			*pcurptr -= 'A';
			*pcurptr += 'a';
			pcurptr ++;
		} else {
			*pcurptr = '_';
			pcurptr ++;
		}
	}
	return;
}

int __start_peer(char* exepath,char* cmdline)
{
	char* runprog = NULL;
	int runsize=0;
	int ret;
	int pid=0;

	ret= snprintf_safe(&runprog,&runsize,"\"%s\" %s %d",exepath, cmdline,GetCurrentProcessPid());
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = start_cmd_single_detach(0,runprog);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	pid = ret;

	snprintf_safe(&runprog,&runsize,NULL);
	return pid;
fail:
	snprintf_safe(&runprog,&runsize,NULL);
	SETERRNO(ret);
	return ret;

}

int protect_doing(HANDLE exitevt,char* curcmdline,char* peercmdline,DWORD peerpid,int waitmills,int interval)
{
	char* exepath=NULL;
	int exesize=0;
	int ret;
	char* myevtname=NULL;
	int myevtsize=0;
	char* peerevtname = NULL;
	int peerevtsize=0;
	char* mymuxname= NULL;
	int mymuxsize=0;
	char* peermuxname=  NULL;
	int peermuxsize=0;
	HANDLE peerevt=NULL;
	char* runprog = NULL;
	int runsize=0;
	HANDLE mymux = NULL;
	HANDLE peermux = NULL;
	HANDLE myevt = NULL;
	int running = 1;
	HANDLE waithd[2];
	DWORD waitnum=0;


	REFERENCE_ARG(peerpid);
	REFERENCE_ARG(exitevt);

	ret = get_executable_wholepath(0,&exepath,&exesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = snprintf_safe(&myevtname,&myevtsize,"%s%s_evt",exepath,curcmdline);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	normalize_name(myevtname);

	ret = snprintf_safe(&peerevtname,&peerevtsize,"%s%s_evt",exepath,peercmdline);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	normalize_name(peerevtname);

	ret = snprintf_safe(&mymuxname,&mymuxsize,"%s%s_mux",exepath,curcmdline);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	normalize_name(mymuxname);

	ret = snprintf_safe(&peermuxname,&peermuxsize,"%s%s_mux",exepath,peercmdline);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	normalize_name(peermuxname);


	/*now to get the my mux created*/
	mymux = open_mutex(mymuxname,1);
	if (mymux == NULL) {
		GETERRNO(ret);
		ERROR_INFO("create [%s] error[%d]",mymuxname,ret);
		goto fail;
	}

	myevt = open_event(myevtname,1);
	if (myevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("create [%s] error[%d]",myevtname,ret);
		goto fail;
	}

	if (peerpid != 0) {
		/*yes this means that we have the peer ,so we should set event notify*/
		peerevt = open_event(peerevtname,0);
		if (peerevt != NULL) {
			bret = SetEvent(peerevt);
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("can not set event for [%s] error[%d]", peerevtname,ret);
			}
			/*we close this*/
			CloseHandle(peerevt);
			peerevt = NULL;
		}
	}

	while(running) {
		waitnum = 0;
		if (exitevt != NULL) {
			waithd[waitnum] = exitevt;
			waitnum ++;
		}

		peermux = open_mutex(peermuxname,1);
		if (peermux != NULL) {
			CloseHandle(peermux);
			peermux = NULL;
			/*this means the peer exit ,so we should create this function*/
			ret = __start_peer(exepath,peercmdline);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			/*now wait for the event*/
			waithd[waitnum] = myevt;
			waitnum ++;
			dret = WaitForMultipleObjects(waitnum,waithd,FALSE,waitmills);
			if (dret >= WAIT_OBJECT_0 && dret < (WAIT_OBJECT_0 + waitnum)) {
				hd = waithd[(dret - WAIT_OBJECT_0)];
				if (hd == exitevt) {
					running = 0;
					ERROR_INFO("exit notify");
					continue;
				} else if (hd == myevt) {
					/*ok we should give the notify*/
					ResetEvent(myevt);
					continue;
				} else {
					ASSERT_IF(0!=0);
				}
			} else if (dret == WAIT_TIMEOUT) {
				/*that means we should make another try*/
				continue;
			} else {
				GETERRNO(ret);
				ERROR_INFO("wait error[%ld] [%d]", dret,ret);
				goto fail;
			}
		}

		if (waitnum > 0) {
			dret = WaitForMultipleObjects(waitnum,waithd,FALSE,interval);
			if (dret == WAIT_OBJECT_0 )  {
				running = 0;
				continue;
			} else if (dret == WAIT_TIMEOUT) {
				continue;
			} else {
				GETERRNO(ret);
				ERROR_INFO("wait error[%ld] [%d]", dret,ret);
				goto fail;				
			}
		} else {
			SleepEx(interval,TRUE);
		}
	}

	ret = 0;
fail:
	if (mymux != NULL) {
		CloseHandle(mymux);
	}
	mymux = NULL;

	if (myevt != NULL) {
		CloseHandle(myevt);
	}
	myevt = NULL;

	if (peermux != NULL) {
		CloseHandle(peermux);
	}
	peermux = NULL;

	if (peerevt != NULL) {
		CloseHandle(peerevt);
	}
	peerevt = NULL;

	snprintf_safe(&peerevtname,&peerevtsize,NULL);
	snprintf_safe(&peermuxname,&peermuxsize,NULL);
	snprintf_safe(&myevtname,&myevtsize,NULL)
	snprintf_safe(&mymuxname,&mymuxsize,NULL);
	get_executable_wholepath(1,&exepath,&exesize);
	SETERRNO(ret);
	return ret;
}

DWORD CALLBACK monitor_thread(LPVOID lparam)
{
	int ret = 0;
	pprotect_monitor_t pmon = (pprotect_monitor_t) lparam;

	if (pmon) {
		goto fail;
	}
	ret = 0;
//out:
	pmon->m_exitcode = ret;
	SetEvent(pmon->m_exitnotifyevt);
	pmon->m_exited = 1;
	return (DWORD)ret;
fail:
	protect_error_exit(ret,"error on protect [%d]", ret);
	pmon->m_exitcode = ret;
	SetEvent(pmon->m_exitnotifyevt);
	pmon->m_exited = 1;
	return (DWORD)ret;
}

pprotect_monitor_t __alloc_protect_monitor(char* curcmdline, char* peercmdline, DWORD peerpid)
{
	pprotect_monitor_t pmon = NULL;
	int ret;
	DWORD thrid = 0;

	pmon = (pprotect_monitor_t) malloc(sizeof(*pmon));
	if (pmon == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pmon, 0, sizeof(*pmon));
	pmon->m_exited = 1;

	/*now to prepare the parameters*/
	pmon->m_curcmdline = _strdup(curcmdline);
	if (pmon->m_curcmdline == NULL)  {
		GETERRNO(ret);
		goto fail;
	}

	pmon->m_peercmdline = _strdup(peercmdline);
	if (pmon->m_peercmdline == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	pmon->m_peerpid = peerpid;

	pmon->m_exitevt = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (pmon->m_exitevt == NULL ||
	        pmon->m_exitevt == INVALID_HANDLE_VALUE)   {
		GETERRNO(ret);
		pmon->m_exitevt = NULL;
		goto fail;
	}

	pmon->m_exitnotifyevt = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (pmon->m_exitnotifyevt == NULL ||
	        pmon->m_exitnotifyevt == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		pmon->m_exitnotifyevt = NULL;
		goto fail;
	}

	/*pretend running*/
	pmon->m_exited = 0;
	pmon->m_thr = CreateThread(NULL, 0, monitor_thread, pmon, 0, &thrid);
	if (pmon->m_thr == NULL ||
	        pmon->m_thr == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		pmon->m_exited = 1;
		ERROR_INFO("can not create monitor_thread [%d]", ret);
		goto fail;
	}

	return pmon;
fail:
	__free_protect_monitor(&pmon);
	SETERRNO(ret);
	return NULL;
}




void* start_protect_monitor(char* curcmdline, char* peercmdline, DWORD peerpid, int mode)
{
	pprotect_monitor_t pmon=NULL;

	if (mode == MONITOR_MODE) {
		if (peerpid == 0) {
			exit(4);
		}


	} else {
		pmon = __alloc_protect_monitor(curcmdline,peercmdline,peerpid);
	}
	return pmon;
}


int protectkill_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	int cntargc = 0;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);

	while (parsestate->leftargs && parsestate->leftargs[cntargc]) {
		cntargc ++;
	}

	if (cntargc == 0) {
		ret = 1;		
	}

	ret = 0;
//out:
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
	while(st_run) {
		mux = open_mutex(muxname,created);
		if (mux != NULL) {
			fprintf(stdout,"%s [%s] succ\n", created ? "create" : "open", muxname);
			break;
		}
		GETERRNO(ret);
		fprintf(stdout,"%s [%s] error[%d]\n",created ? "create" : "open",muxname,ret);
		SleepEx(1000,TRUE);
	}

	cnt = 0;
	while(st_run) {
		fprintf(stdout,"[%s] hold on [%d]\n",muxname,cnt);
		SleepEx(1000,TRUE);
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
	char* evtname =NULL;
	int ret;
	HANDLE evt=NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	BOOL bret;
	int cnt=0,waitcnt=0;
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
	evt = open_event(evtname,1);
	if (evt == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "create [%s] error[%d]\n",evtname, ret );
		goto out;
	}

	cnt = 0;
	waitcnt = 0;
	while (st_run) {
		dret = WaitForSingleObject(evt,1000);
		if (dret == WAIT_OBJECT_0) {
			cnt ++;
			ResetEvent(evt);
			fprintf(stdout,"[%s] signaled [%d]\n",evtname,cnt);
			continue;
		}
		fprintf(stdout, "[%s] not signaled [%d]\n",evtname, waitcnt);
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
	char* evtname =NULL;
	int ret;
	HANDLE evt=NULL;
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
	evt = open_event(evtname,0);
	if (evt == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "open [%s] error[%d]\n", evtname, ret);
		goto out;
	}

	bret= SetEvent(evt);
	if (!bret) {
		GETERRNO(ret);
		goto out;
	}

	fprintf(stdout,"set [%s] succ\n",evtname);


	ret = 0;
out:
	if (evt != NULL) {
		CloseHandle(evt);
	}
	evt = NULL;
	SETERRNO(ret);
	return ret;
}