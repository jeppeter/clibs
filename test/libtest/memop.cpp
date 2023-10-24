
int memscan_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	HANDLE hproc=NULL;
	DWORD pid = GetCurrentProcessId();
	int ipid=-1;
	int idx=0;

	while(1) {
		if (parsestate->leftargs && parsestate->leftargs[idx]) {
			ipid = atoi(parsestate->leftargs[idx]);
			pid = (DWORD)ipid;
		}

		if (hproc != NULL) {
			CloseHandle(hproc);
		}
		hproc = NULL;
		hproc = OpenProcess(pid,)
	}
	

	ret = 0;
out:
	if (hproc != NULL && hproc != INVALID_HANDLE_VALUE)  {
		CloseHandle(hproc);
	}
	hproc = NULL;
	SETERRNO(ret);
	return ret;
}