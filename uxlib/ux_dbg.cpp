#include <ux_dbg.h>
#include <ux_fileop.h>
#include <ux_strop.h>
#include <ux_regex.h>
#include <ux_output_debug.h>
#include <ux_args.h>

#include <stdlib.h>
#include <execinfo.h>
#include <string.h>


int backtrace_safe(int idx, void*** pppbacks, int *psize)
{
	int ret;
	void** ppnewbacks= NULL;
	int newsize=0;
	void** ppretbacks = NULL;
	int retsize = 0;
	int retlen = 0;
	int i,j;
	if (idx < 0) {
		if (pppbacks && *pppbacks) {
			free(*pppbacks);
			*pppbacks = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (pppbacks == NULL || psize == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	ppretbacks= *pppbacks;
	retsize = *psize;

	newsize = 4;
try_again:
	if (ppnewbacks) {
		free(ppnewbacks);
	}
	ppnewbacks = NULL;

	ppnewbacks = (void**)malloc(sizeof(*ppnewbacks)* newsize);
	if (ppnewbacks == NULL) {
		GETERRNO(ret);
		goto fail;
	}

 	ret = backtrace(ppnewbacks,newsize);
 	if (ret < 0) {
 		GETERRNO(ret);
 		goto fail;
 	} else if (ret == newsize) {
 		newsize <<= 1;
 		goto try_again;
 	}
 	retlen = ret - idx - 1;
 	if (retlen < 0) {
 		retlen = 0;
 	}

 	if (retlen > 0) {
	 	if (retlen >= retsize || ppretbacks == NULL) {
	 		if (retlen >= retsize) {
	 			retsize = retlen + 1;
	 		}

	 		ppretbacks = (void**)malloc(sizeof(*ppretbacks) * retsize);
	 		if (ppretbacks == NULL) {
	 			GETERRNO(ret);
	 			goto fail;
	 		}
	 	}
	 	memset(ppretbacks, 0, sizeof(*ppretbacks) * retsize);
	 	for(i=idx+1,j=0;j < retlen;j++,i++) {
	 		ppretbacks[j] = ppnewbacks[i];
	 	}
 	}


	if (ppnewbacks) {
		free(ppnewbacks);
	}
	ppnewbacks = NULL;

	if (*pppbacks && *pppbacks != ppretbacks) {
		free(*pppbacks);
	}
	*pppbacks = ppretbacks;
	*psize = retsize;


	return retlen;
fail:
	if (ppnewbacks) {
		free(ppnewbacks);
	}
	ppnewbacks = NULL;

	if (ppretbacks && ppretbacks != *pppbacks) {
		free(ppretbacks);
	}
	ppretbacks = NULL;
	SETERRNO(ret);
	return ret;
}

int get_proc_mem_info(int pid,pproc_mem_info_t *ppmem,int *psize)
{
	int ret;
	char* pfile=NULL;
	int filesize=0;
	char* pconbuf=NULL;
	int consize=0;
	char** pplines=NULL;
	int linesize=0;
	int linelen=0;
	pproc_mem_info_t pretmem = NULL;
	int retlen=0;
	int retsize=0;
	pproc_mem_info_t ptmp = NULL;
	char* curline=NULL;
	char* regstr = NULL;
	int regsize =0;
	void* pmatchreg = NULL;
	int *pstartpos=NULL,*pendpos=NULL;
	int possize=0;
	int poslen=0;
	char* pcpystr = NULL;
	int cpysize=0;
	int cpylen = 0;
	char* parsestr=NULL;
	int parsesize=0;
	char* pendptr = NULL;
	int i;


	if (pid < -1) {
		if (ppmem && *ppmem) {
			free(*ppmem);
			*ppmem = NULL;
		}

		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppmem == NULL || psize == NULL) {
		ret=  -EINVAL;
		SETERRNO(ret);
		return ret;
	}
	pretmem = *ppmem;
	retsize = *psize;

	if (pid < 0) {
		ret = snprintf_safe(&pfile,&filesize,"/proc/self/maps");
	} else {
		ret = snprintf_safe(&pfile,&filesize,"/proc/%d/maps",pid);
	}
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pretmem != NULL && retsize > 0) {
		memset(pretmem, 0, retsize);
	}

	ret = read_file_whole(pfile,&pconbuf,&consize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = split_lines(pconbuf,&pplines,&linesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	linelen = ret;

	ret = snprintf_safe(&regstr,&regsize,"^([0-9a-fA-F]+)\\-([0-9a-fA-F]+)\\s+([^ ]+)\\s+([0-9a-fA-F]+)\\s+([0-9:]+)\\s+([0-9]+)(\\s+(.*))?");
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = regex_compile(regstr,0,&pmatchreg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	for(i=0;i<linelen;i++) {
		curline = pplines[i];
		if (strlen(curline) == 0) {
			continue;
		}

		ret = regex_exec(pmatchreg,curline,&pstartpos,&pendpos,&possize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("[%d][%s] not match",i,curline);
			continue;
		}
		poslen = ret;
		if (poslen > 6) {
			/*now we get the value*/
			/*first to get the start address*/
			if (retlen >= (retsize-3)) {
				if (retsize == 0) {
					retsize = 4;
				} else {
					retsize += 4;
				}
				ptmp = (pproc_mem_info_t)malloc(sizeof(*ptmp) * retsize);
				if (ptmp == NULL) {
					GETERRNO(ret);
					goto fail;
				}
				memset(ptmp, 0, sizeof(*ptmp) * retsize);
				if (retlen > 0) {
					memcpy(ptmp, pretmem, sizeof(*ptmp) * retlen);
				}
				if (pretmem && pretmem != *ppmem) {
					free(pretmem);
				}
				pretmem = ptmp;
				ptmp = NULL;
			}

			cpylen = pendpos[1] - pstartpos[1];
			if (cpylen >= cpysize) {
				cpysize = cpylen + 1;
				if (pcpystr) {
					free(pcpystr);
				}
				pcpystr = NULL;
				pcpystr = (char*)malloc(cpysize);
				if (pcpystr == NULL) {
					GETERRNO(ret);
					goto fail;
				}
			}
			memset(pcpystr,0, cpysize);
			memcpy(pcpystr,&curline[pstartpos[1]],cpylen);
			ret = snprintf_safe(&parsestr,&parsesize,"0x%s",pcpystr);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			ret = parse_number(parsestr,&(pretmem[retlen].m_startaddr),&pendptr);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			cpylen = pendpos[2] - pstartpos[2];
			if (cpylen >= cpysize) {
				cpysize = cpylen + 1;
				if (pcpystr) {
					free(pcpystr);
				}
				pcpystr = NULL;
				pcpystr = (char*)malloc(cpysize);
				if (pcpystr == NULL) {
					GETERRNO(ret);
					goto fail;
				}
			}
			memset(pcpystr,0, cpysize);
			memcpy(pcpystr,&curline[pstartpos[2]],cpylen);
			ret = snprintf_safe(&parsestr,&parsesize,"0x%s",pcpystr);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			ret = parse_number(parsestr,&(pretmem[retlen].m_endaddr),&pendptr);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			/*we should give next address*/
			pretmem[retlen].m_endaddr -= 1;

			if (poslen >= 9) {
				cpylen = pendpos[8] - pstartpos[8];
				if (cpylen >= (int)sizeof(pretmem[retlen].m_file)) {
					cpylen = sizeof(pretmem[retlen].m_file) - 1;
				}
				if (curline[pstartpos[8]] == '/') {
					memcpy(&(pretmem[retlen].m_file), &(curline[pstartpos[8]]),cpylen);
				}				
			}

			retlen += 1;
		}
	}

	if (pcpystr) {
		free(pcpystr);
	}
	pcpystr = NULL;
	snprintf_safe(&parsestr,&parsesize,NULL);
	regex_exec(NULL,NULL,&pstartpos,&pendpos,&possize);
	regex_compile(NULL,0,&pmatchreg);
	snprintf_safe(&regstr,&regsize,NULL);
	split_lines(NULL,&pplines,&linesize);
	read_file_whole(NULL,&pconbuf,&consize);
	snprintf_safe(&pfile,&filesize,NULL);

	if (*ppmem && *ppmem != pretmem) {
		free(*ppmem);
	}
	*ppmem = pretmem;
	*psize = retsize;

	return retlen;
fail:
	if (pcpystr) {
		free(pcpystr);
	}
	pcpystr = NULL;
	snprintf_safe(&parsestr,&parsesize,NULL);
	regex_exec(NULL,NULL,&pstartpos,&pendpos,&possize);
	regex_compile(NULL,0,&pmatchreg);
	snprintf_safe(&regstr,&regsize,NULL);
	split_lines(NULL,&pplines,&linesize);
	read_file_whole(NULL,&pconbuf,&consize);
	snprintf_safe(&pfile,&filesize,NULL);
	if (pretmem && pretmem != *ppmem) {
		free(pretmem);
	}
	pretmem = NULL;
	SETERRNO(ret);
	return ret;
}