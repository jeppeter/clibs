#include <win_proc.h>
#include <win_fileop.h>
#include <win_err.h>
#include <win_uniansi.h>
#include <win_strop.h>

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
	if (ppproc != NULL) {
		pproc = *ppproc;
		ASSERT_IF(CHECK_PROC_MAGIC(pproc));
		__close_handle_note(&(pproc->m_stdinhd), "close stdin");
		__close_handle_note(&(pproc->m_stdouthd), "close stdout");
		__close_handle_note(&(pproc->m_stderrhd), "close stderr");
		__close_handle_note(&(pproc->m_chldstdin), "close child stdin");
		__close_handle_note(&(pproc->m_chldstdout), "close child stdout");
		__close_handle_note(&(pproc->m_chldstderr), "close child stderr");
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

int __create_flags(pproc_handle_t pproc, int flags)
{
	int ret;
	if (flags & PROC_PIPE_STDIN) {
		ret = __create_pipe(&(pproc->m_stdinhd), &(pproc->m_chldstdin),0, "stdin pipe");
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
	}

	if (flags & PROC_PIPE_STDERR) {
		ret = __create_pipe(&(pproc->m_chldstderr), &(pproc->m_stderrhd),0,"stderr pipe");
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
	pproc = __alloc_proc_handle();
	if (pproc == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	prog = prog;
	createflag = createflag;

	return (void*) pproc;
fail:
	__free_proc_handle(&pproc);
	SETERRNO(ret);
	return NULL;
}