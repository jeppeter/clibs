#include <win_proc.h>
#include <win_fileop.h>
#include <win_err.h>
#include <win_uniansi.h>

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

