
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

DWORD CALLBACK monitor_thread(LPVOID lparam)
{
	int ret = 0;
	pprotect_monitor_t pmon = (pprotect_monitor_t) lparam;


	ret = 0;
out:
	pmon->m_exitcode = ret;
	SetEvent(pmon->m_exitnotifyevt);
	pmon->m_exited = 1;
	return ret;
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
		
	} else {
		pmon = __alloc_protect_monitor(curcmdline,peercmdline,peerpid);
	}
	return pmon;
}


int protectkill_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	int idx
	int cntargc = 0;

	init_log_level(pargs);

	while (parsestate->leftargs && parsestate->leftargs[cntargc]) {
		cntargc ++;
	}

	if (cntargc == 0) {

	}



	ret = 0;
out:
	SETERRNO(ret);
	return ret;
}