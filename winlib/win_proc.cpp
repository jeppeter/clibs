#include <win_proc.h>
#include <win_fileop.h>
#include <win_err.h>
#include <win_uniansi.h>
#include <win_strop.h>
#include <tchar.h>

#pragma comment(lib,"Shell32.lib")
#pragma warning(disable:4996)

#define pid_wmic_cmd_fmt "WMIC /OUTPUT:%s process where \"ProcessId=%d\" get CommandLine,ProcessId"

int get_pid_argv(int pid,char*** pppargv,int *pargvsize)
{
	char* tempfile=NULL;
	int tempsize=0;
	int ret = 0;
	int retsize=0;
	char** ppretargv=NULL;
	int namelen = 0;
	int filllen = 0;
	int cmdlen=0;
	char* pcmd=NULL;
	char* pfilecont=NULL;
	int filelen=0;
	char* pcurptr=NULL;
	char* ppassptr=NULL;
	wchar_t* pucmdline=NULL;
	int ucmdlinesize=0;
	char* pcmdline=NULL;
	int cmdlinesize=0;
	wchar_t** pargv=NULL;
	int argvnum=0;
	char* argv0=NULL;
	int argv0size=0;
	int i;
	int curlen;

	if (pid < 0) {
		if (pppargv && *pppargv != NULL) {
			free(*pppargv);
		}
		if (pppargv) {
			*pppargv = NULL;
		}
		if (pargvsize) {
			*pargvsize = 0;
		}
		return 0;
	}

	if (pppargv == NULL || pargvsize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		return ret;
	}
	ppretargv = *pppargv;
	retsize = *pargvsize;



	ret = mktempfile_safe("pidfile",&tempfile,&tempsize);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not mktemp error[%d]",ret);
		goto fail;
	}

	cmdlen = tempsize + (int)strlen(pid_wmic_cmd_fmt) + 10;
	pcmd = (char*)malloc((size_t)cmdlen);
	if (pcmd == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not malloc %d error[%d]",cmdlen,ret);
		goto fail;
	}

	memset(pcmd,0,(size_t)cmdlen);
	ret = _snprintf(pcmd,(size_t)cmdlen,pid_wmic_cmd_fmt,tempfile,pid);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not snprintf error[%d]",ret);
		goto fail;
	}

	ret = system(pcmd);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not run [%s] error[%d]",pcmd,ret);
		goto fail;
	}

	/*now get the file information*/
	ret=  read_file_encoded(tempfile,&pfilecont,&filelen);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pfilecont == NULL) {
		ret = -ERROR_BAD_FILE_TYPE;
		ERROR_INFO("[%s] bad format",pfilecont);
		goto fail;
	}


	/**/
	pcurptr = strchr(pfilecont,'\n');
	if (pcurptr == NULL) {
		ret = -ERROR_BAD_FILE_TYPE;
		ERROR_INFO("[%s] bad format",pfilecont);
		goto fail;
	}
	ppassptr = pcurptr;
	ppassptr += 1;

	pcurptr = strchr(ppassptr,'\n');
	if (pcurptr == NULL) {
		ret = -ERROR_BAD_FILE_TYPE;
		ERROR_INFO("[%s] bad format",pfilecont);
		goto fail;		
	}

	pcurptr -= 1;

	while (1) {
		if (pcurptr <= ppassptr) {
			ret = -ERROR_BAD_FILE_TYPE;
			ERROR_INFO("[%s] bad format",pfilecont);
			goto fail;
		}
		if (*pcurptr == '\r' || 
			*pcurptr == ' ' ||
			*pcurptr == '\t') {
			pcurptr -= 1;
			continue;
		} else if (isdigit(*pcurptr)) {
			break;
		}
		ret = -ERROR_BAD_FILE_TYPE;
		ERROR_INFO("[%s] bad format",pfilecont);
		goto fail;		
	}

	while(1) {
		if (pcurptr <= ppassptr) {
			ret = -ERROR_BAD_FILE_TYPE;
			ERROR_INFO("[%s] bad format",pfilecont);
			goto fail;
		}
		if (isdigit(*pcurptr)) {
			pcurptr -= 1;
			continue;
		} else if (*pcurptr == ' ' || *pcurptr == '\t') {
			break;
		}
		ret = -ERROR_BAD_FILE_TYPE;
		ERROR_INFO("[%s] bad format",pfilecont);
		goto fail;		
	}

	/*now we should copy the line we add pcurptr*/
	cmdlinesize = (int)((pcurptr + 1) - ppassptr);
	pcmdline = (char*)malloc((size_t)(cmdlinesize + 10));
	if (pcmdline == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not malloc[%d] error[%d]",cmdlinesize+10,ret);
		goto fail;
	}
	memset(pcmdline,0,(size_t)(cmdlinesize+10));
	memcpy(pcmdline,ppassptr,(size_t)cmdlinesize);

	ret = AnsiToUnicode(pcmdline,&pucmdline,&ucmdlinesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	pargv = (wchar_t**)CommandLineToArgvW(pucmdline,&argvnum);
	if (pargv == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not pass [%s] to argv error[%d]",pcmdline,ret);
		goto fail;
	} else if (argvnum < 1) {
		ret = -ERROR_INVALID_FIELD_IN_PARAMETER_LIST;
		ERROR_INFO("[%s] param %d",pcmdline,argvnum);
		goto fail;
	}

try_again:
	namelen = 0;
	pcurptr = (char*)ppretargv;
	if (pcurptr == NULL || retsize < (int)(sizeof(char*)*argvnum + 1024) ) {
		if (retsize < (int)((sizeof(char*) * argvnum)+1024)) {
			retsize = 1024 + (int)(sizeof(char*) * argvnum);
		}
		if (ppretargv && ppretargv != *pppargv) {
			free(ppretargv);
		}
		ppretargv = NULL;
		ppretargv = (char**) malloc((size_t)retsize);
		if (ppretargv == NULL) {
			GETERRNO(ret);
			ERROR_INFO("can not malloc [%d] error[%d]",retsize,ret);
			goto fail;
		}
	}
	memset(ppretargv,0,(size_t)retsize);
	pcurptr = (char*)ppretargv;
	/*to skip*/
	pcurptr += argvnum * sizeof(char*);
	filllen = retsize - (int)(argvnum * sizeof(char*));
	for (i=0;i<argvnum;i++) {
		ret = UnicodeToAnsi(pargv[i],&argv0,&argv0size);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		curlen = (int)strlen(argv0) + 1;
		if ((namelen + curlen) > filllen) {
			retsize <<= 1;
			if (ppretargv && ppretargv != *pppargv) {
				free(ppretargv);
			}
			ppretargv = NULL;
			goto try_again;
		}
		strncpy(pcurptr,argv0,(size_t)(filllen - namelen));
		ppretargv[i] = pcurptr;
		pcurptr += curlen;
		namelen += curlen;
	}

	UnicodeToAnsi(NULL,&argv0,&argv0size);
	if (pargv) {
		LocalFree(pargv);
	}
	pargv=NULL;
	AnsiToUnicode(NULL,&pucmdline,&ucmdlinesize);
	if (pcmdline) {
		free(pcmdline);
	}
	pcmdline = NULL;
	cmdlinesize = 0;
	read_file_encoded(NULL,&pfilecont,&filelen);
	if (pcmd) {
		free(pcmd);
	}
	pcmd = NULL;
	if (tempfile != NULL) {
		delete_file(tempfile);
	}
	mktempfile_safe(NULL,&tempfile,&tempsize);

	if (*pppargv && *pppargv != ppretargv) {
		free(*pppargv);
	}
	*pppargv = ppretargv;
	*pargvsize = retsize;
	return argvnum;
fail:
	UnicodeToAnsi(NULL,&argv0,&argv0size);
	if (pargv) {
		LocalFree(pargv);
	}
	pargv=NULL;
	argvnum = 0;
	AnsiToUnicode(NULL,&pucmdline,&ucmdlinesize);
	if (pcmdline) {
		free(pcmdline);
	}
	pcmdline = NULL;
	cmdlinesize = 0;
	read_file_encoded(NULL,&pfilecont,&filelen);
	if (pcmd) {
		free(pcmd);
	}
	pcmd = NULL;
	if (tempfile != NULL) {
		delete_file(tempfile);
	}
	mktempfile_safe(NULL,&tempfile,&tempsize);
	if (ppretargv && ppretargv != *pppargv) {
		free(ppretargv);
	}
	ppretargv = NULL;
	SETERRNO(-ret);
	return ret;
}

#define PROC_MAGIC        0x33898221

#ifdef __PROC_DEBUG__
#define CHECK_PROC_MAGIC(proc) ((proc) && (proc)->m_magic == PROC_MAGIC)
#define SET_PROC_MAGIC(proc)  do { if ((proc) != NULL) { (proc)->m_magic = PROC_MAGIC;}} while(0)
#else
#define CHECK_PROC_MAGIC(proc) ((proc) && 1)
#define SET_PROC_MAGIC(proc)
#endif

typedef struct __proc_handle {
#ifdef __PROC_DEBUG__
	uint32_t m_magic;
#endif
	HANDLE m_stdinhd;
	HANDLE m_stdouthd;
	HANDLE m_stderrhd;	
	HANDLE m_prochd;

	/*for child hd*/
	HANDLE m_chldstdin;
	HANDLE m_chldstdout;
	HANDLE m_chldstderr;
	int m_exited;
	int m_exitcode;
} proc_handle_t,*pproc_handle_t;

void __close_handle_note(HANDLE *phd,const char* fmt,...)
{
	va_list ap;
	BOOL bret;
	char* errstr=NULL;
	int errsize=0;
	int ret;
	int res;
	if (phd && *phd != INVALID_HANDLE_VALUE && *phd != NULL) {
		bret = CloseHandle(*phd);
		if (!bret && fmt != NULL) {
			GETERRNO(ret);
			va_start(ap,fmt);
			res = vsnprintf_safe(&errstr,&errsize,fmt,ap);
			if (res >= 0) {
				ERROR_INFO("%s error[%d]", errstr, ret);
			}
			vsnprintf_safe(&errstr,&errsize,NULL,ap);
		}
		*phd = INVALID_HANDLE_VALUE;
	}
	return;
}

void __free_proc_handle(pproc_handle_t* ppproc)
{
	pproc_handle_t pproc = NULL;
	BOOL bret;
	int i;
	int maxcnt=5;
	if (ppproc != NULL) {
		pproc = *ppproc;
		ASSERT_IF(CHECK_PROC_MAGIC(pproc));
		__close_handle_note(&(pproc->m_stdinhd), "close stdin");
		__close_handle_note(&(pproc->m_stdouthd), "close stdout");
		__close_handle_note(&(pproc->m_stderrhd), "close stderr");
		__close_handle_note(&(pproc->m_chldstdin), "close child stdin");
		__close_handle_note(&(pproc->m_chldstdout), "close child stdout");
		__close_handle_note(&(pproc->m_chldstderr), "close child stderr");
		if (pproc->m_prochd != INVALID_HANDLE_VALUE && 
			pproc->m_prochd != NULL && pproc->m_exited == 0) {
			for (i=0;i<maxcnt;i++) {
				bret = GetExitCodeProcess(pproc->m_prochd,(DWORD*)&(pproc->m_exitcode));
				if (bret) {
					break;
				}
				TerminateProcess(pproc->m_prochd, 5);
			}
			if (i == maxcnt) {
				ERROR_INFO("can not terminate process");
			}
			pproc->m_exited = 1;
		}
		__close_handle_note(&(pproc->m_prochd), "proc handle");

		free(pproc);
		*ppproc = NULL;
	}
	return;
}

pproc_handle_t __alloc_proc_handle(void)
{
	pproc_handle_t pproc= NULL;
	int ret;
	pproc = (pproc_handle_t) malloc(sizeof(*pproc));
	if (pproc == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc [%d] error[%d]", sizeof(*pproc), ret);
		goto fail;
	}
	memset(pproc, 0 , sizeof(*pproc));
	SET_PROC_MAGIC(pproc);
	pproc->m_stdinhd = INVALID_HANDLE_VALUE;
	pproc->m_stdouthd = INVALID_HANDLE_VALUE;
	pproc->m_stderrhd = INVALID_HANDLE_VALUE;
	pproc->m_chldstdin = INVALID_HANDLE_VALUE;
	pproc->m_chldstdout = INVALID_HANDLE_VALUE;
	pproc->m_chldstderr = INVALID_HANDLE_VALUE;
	pproc->m_prochd = INVALID_HANDLE_VALUE;
	pproc->m_exited = 1;
	pproc->m_exitcode = 1;

	return pproc;
fail:
	__free_proc_handle(&pproc);
	SETERRNO(ret);
	return NULL;
}

int __create_pipe(HANDLE *whd, HANDLE *rhd, int bufsize, const char* fmt,...)
{
	SECURITY_ATTRIBUTES  sa;
	BOOL bret;
	int ret;
	va_list ap;
	char* errstr = NULL;
	int errsize=0;
	int res;
	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor  = NULL;

	bret = CreatePipe(rhd,whd,&sa,(DWORD)bufsize);
	if (!bret) {
		GETERRNO(ret);
		if (fmt != NULL) {
			va_start(ap, fmt);
			res = vsnprintf_safe(&errstr, &errsize,fmt,ap);
			if (res >= 0) {
				ERROR_INFO("%s error[%d]", errstr, ret);
			}
			vsnprintf_safe(&errstr,&errsize,NULL,ap);
		}
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int __create_nul(HANDLE* rfd, HANDLE *wfd, const char* fmt, ...)
{
	HANDLE hd=INVALID_HANDLE_VALUE;
	DWORD acsflag = 0;
	char* errstr=NULL;
	va_list ap;
	int errsize=0;
	int ret,res;
	if (rfd) {
		acsflag = GENERIC_READ;
	} else if (wfd) {
		acsflag = GENERIC_WRITE;
	}
	if (acsflag != 0) {
		hd = CreateFile(_T("nul:"), acsflag,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
		if (hd == INVALID_HANDLE_VALUE) {
			GETERRNO(ret);
			if (fmt !=NULL) {
				va_start(ap,fmt);
				res = vsnprintf_safe(&errstr,&errsize,fmt,ap);
				if (res >= 0) {
					ERROR_INFO("%s error[%d]", errstr,ret);
				}
				vsnprintf_safe(&errstr,&errsize,NULL,ap);
			}
			goto fail;
		}

		if (rfd) {
			*rfd = hd;
		} else if (wfd) {
			*wfd = hd;
		}
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int __create_flags(pproc_handle_t pproc, int flags)
{
	int ret;
	if (flags & PROC_PIPE_STDIN) {
		ret = __create_pipe(&(pproc->m_stdinhd), &(pproc->m_chldstdin),0, "stdin pipe");
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (flags & PROC_STDIN_NULL) {
		ret = __create_nul(&(pproc->m_chldstdin),NULL,"null child stdin");
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (flags & PROC_PIPE_STDOUT) {
		ret = __create_pipe(&(pproc->m_chldstdout), &(pproc->m_stdouthd),0, "stdout pipe");
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (flags & PROC_STDOUT_NULL) {
		ret = __create_nul(NULL,&(pproc->m_chldstdout), "null child stdout");
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (flags & PROC_PIPE_STDERR) {
		ret = __create_pipe(&(pproc->m_chldstderr), &(pproc->m_stderrhd),0,"stderr pipe");
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else if (flags & PROC_STDERR_NULL) {
		ret = __create_nul(NULL, &(pproc->m_chldstderr),"null child stderr");
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

void* start_cmdv(int createflag,char* prog[])
{
	pproc_handle_t pproc = NULL;
	int ret;
	char* cmdline=NULL;
	int cmdlinesize=0;
	char* qstr=NULL;
	int qsize=0;
	PROCESS_INFORMATION  *pinfo=NULL;
	STARTUPINFOW *pstartinfo=NULL;
	int usehd = 0;
	DWORD dwflag = 0;
	BOOL bret;
	wchar_t *wcmdline=NULL;
	int wcmdsize=0;
	int i,res;

	if (prog == NULL || prog[0] == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	pproc = __alloc_proc_handle();
	if (pproc == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	ret = __create_flags(pproc,createflag);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	for (i=0;prog[i] != NULL;i++) {
		if (i > 0) {
			ret = append_snprintf_safe(&cmdline,&cmdlinesize," ");
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}

		ret = quote_string(&qstr,&qsize,"%s",prog[i]);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = append_snprintf_safe(&cmdline,&cmdlinesize,"%s", qstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	/*now we should make this handle*/
	pinfo= (PROCESS_INFORMATION*) malloc(sizeof(*pinfo));
	if (pinfo == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc [%d] error[%d]", sizeof(*pinfo), ret);
		goto fail;
	}
	memset(pinfo, 0 , sizeof(*pinfo));

	pstartinfo = (STARTUPINFOW*) malloc(sizeof(*pstartinfo));
	if (pstartinfo == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc [%d] error[%d]", sizeof(*pstartinfo), ret);
		goto fail;
	}
	memset(pstartinfo, 0 , sizeof(*pstartinfo));

	pstartinfo->cb = sizeof(*pstartinfo);
	if (pproc->m_chldstdin != INVALID_HANDLE_VALUE) {
		pstartinfo->hStdInput  = pproc->m_chldstdin;
		usehd ++;
	}

	if (pproc->m_chldstdout != INVALID_HANDLE_VALUE) {
		pstartinfo->hStdOutput = pproc->m_chldstdout;
		usehd ++;
	}

	if (pproc->m_chldstderr != INVALID_HANDLE_VALUE) {
		pstartinfo->hStdError = pproc->m_chldstderr;
		usehd ++;
	}

	if (usehd > 0) {
		pstartinfo->dwFlags  |= STARTF_USESTDHANDLES;
	}

	if (createflag & PROC_NO_WINDOW) {
		dwflag |= CREATE_NO_WINDOW;
	}

	ret = AnsiToUnicode(cmdline,&wcmdline,&wcmdsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	bret = CreateProcessW(NULL,wcmdline,
						NULL,NULL,
						TRUE,dwflag,
						NULL,NULL,
						pstartinfo,pinfo);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("create [%s] error[%d]", cmdline, ret);
		goto fail;
	}

	/*now started*/
	pproc->m_exited = 0;
	pproc->m_prochd = pinfo->hProcess;

	if (pinfo->hThread != NULL) {
		bret = CloseHandle(pinfo->hThread);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("close thread handle [%p] error[%d]", pinfo->hThread, ret);
			goto fail;
		}
		pinfo->hThread = NULL;
	}

	AnsiToUnicode(NULL,&wcmdline,&wcmdsize);
	if (pinfo) {
		free(pinfo);
	}
	pinfo = NULL;
	if (pstartinfo) {
		free(pstartinfo);
	}
	pstartinfo = NULL;
	quote_string(&qstr,&qsize,NULL);
	append_snprintf_safe(&cmdline,&cmdlinesize,NULL);

	return (void*) pproc;
fail:
	AnsiToUnicode(NULL,&wcmdline,&wcmdsize);
	if (pinfo) {
		if (pinfo->hThread != NULL && pinfo->hThread != INVALID_HANDLE_VALUE) {
			bret = CloseHandle(pinfo->hThread);
			if (!bret) {
				GETERRNO(res);
				ERROR_INFO("close thread [%p] error[%d]", pinfo->hThread, res);
			}
		}
		pinfo->hThread = NULL;

		free(pinfo);
	}
	pinfo = NULL;
	if (pstartinfo) {
		free(pstartinfo);
	}
	pstartinfo = NULL;
	quote_string(&qstr,&qsize,NULL);
	append_snprintf_safe(&cmdline,&cmdlinesize,NULL);
	__free_proc_handle(&pproc);
	SETERRNO(ret);
	return NULL;
}

void* start_cmd(int createflag, const char* prog,...)
{
	char** argv=NULL;
	int argc = 0;
	void* pproc=NULL;
	char* curarg;
	int ret;
	int i;
	va_list ap,oldap;
	va_start(ap,prog);
	va_copy(oldap, ap);
	argc = 4;
try_again:
	va_copy(ap, oldap);
	if (argv != NULL) {
		free(argv);
	}
	argv = NULL;
	argv = (char**) malloc(sizeof(*argv)*argc);
	if (argv == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc %d error[%d]", sizeof(*argv)*argc, ret);
		goto fail;
	}
	memset(argv, 0 ,sizeof(*argv) * argc);
	argv[0] = (char*)prog;
	i = 1;
	for(i=1;i < argc;i++) {
		curarg = va_arg(ap,char*);
		if (curarg == NULL) {
			break;
		}
		argv[i] = curarg;
	}

	if (i== argc ) {
		/*filled so we should expand*/
		argc <<= 1;
		goto try_again;
	}

	pproc = start_cmdv(createflag, argv);
	if (pproc == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	if (argv != NULL) {
		free(argv);
	}
	argv = NULL;
	return pproc;
fail:	
	if (argv != NULL) {
		free(argv);
	}
	argv = NULL;
	if (pproc) {
		__free_proc_handle((pproc_handle_t*)&pproc);
	}
	SETERRNO(ret);
	return NULL;
}

HANDLE proc_get_stdin(void* proc)
{
	pproc_handle_t pproc = (pproc_handle_t) proc;
	if (CHECK_PROC_MAGIC(pproc)) {
		return pproc->m_stdinhd;
	}
	return INVALID_HANDLE_VALUE;
}

HANDLE proc_get_stdout(void* proc)
{
	pproc_handle_t pproc = (pproc_handle_t) proc;
	if (CHECK_PROC_MAGIC(pproc)) {
		return pproc->m_stdouthd;
	}
	return INVALID_HANDLE_VALUE;
}

HANDLE proc_get_stderr(void* proc)
{
	pproc_handle_t pproc = (pproc_handle_t) proc;
	if (CHECK_PROC_MAGIC(pproc)) {
		return pproc->m_stderrhd;
	}
	return INVALID_HANDLE_VALUE;
}

int kill_proc(void* proc, int *exitcode)
{
	BOOL bret;
	int i;
	int maxcnt = 5;
	int ret;
	pproc_handle_t pproc = (pproc_handle_t)proc;
	if (!CHECK_PROC_MAGIC(pproc)) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (pproc->m_exited == 0) {
		for (i=0;i<maxcnt;i++) {
			bret = GetExitCodeProcess((pproc->m_prochd), (DWORD*)&(pproc->m_exitcode));
			if (bret) {
				pproc->m_exited = 1;
				break;
			}
			TerminateProcess(pproc->m_prochd, 5);
		}

		if (pproc->m_exited == 0) {
			ret = -ERROR_PROC_NOT_FOUND;
			SETERRNO(ret);
			return ret; 
		}
	}

	if (exitcode) {
		*exitcode = pproc->m_exitcode;
	}

	return 0;
}
