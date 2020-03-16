#include <win_prn.h>
#include <win_proc.h>
#include <win_strop.h>
#include <win_err.h>

#if _MSC_VER >= 1910
#pragma warning(push)
/*disable Spectre warnings*/
#pragma warning(disable:5045)
#endif


int get_printer_list(int freed,HANDLE hexitevt,pprinter_list_t* ppret, int *psize)
{
	char* poutlines=NULL;
	int outsize=0;
	char** pplines=NULL;
	int linesize=0;
	int linelen=0;
	int ret;
	int exitcode=0;
	pprinter_list_t pretlist=NULL;
	pprinter_list_t ptmplist=NULL;
	int retsize=0;
	int retlen=0;
	int i;
	int startline=0;
	char* pcurname=NULL;
	char* pcurserver=NULL;
	char* pcurshare=NULL;
	char* pcurlocal=NULL;
	const char* pwmiccmd = "wmic.exe printer list full";

	if (freed) {
		if (ppret && *ppret) {
			free(*ppret);
			*ppret = NULL;
		}
		if (psize) {
			*psize=0;
		}
		return 0;
	}

	if (ppret == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}
	pretlist = *ppret;
	retsize = *psize;

	ret = run_cmd_event_output_single(hexitevt,NULL,0,&poutlines,&outsize,NULL,0,&exitcode,0,(char*)pwmiccmd);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not run [%s] error[%d]", pwmiccmd,ret);
		goto fail;
	}

	if (exitcode != 0) {
		ret = -exitcode;
		if (ret > 0) {
			ret = -ret;
		}
		ERROR_INFO("run [%s] exitcode[%d]", pwmiccmd,exitcode);
		goto fail;
	}

	ret = split_lines(poutlines,&pplines,&linesize);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("split [%s] error[%d]",poutlines,ret);
		goto fail;
	}

	linelen = ret;
	for (i=0;i<linelen;i++) {
		if (startline) {
			if (strcmp(pplines[i],"") == 0) {
				if (pcurname && pcurserver && pcurlocal && pcurshare) {
					DEBUG_INFO("curname [%s]",pcurname);
					DEBUG_INFO("curserver [%s]",pcurserver);
					DEBUG_INFO("curshare [%s]",pcurshare);
					DEBUG_INFO("curlocal [%s]", pcurlocal);
					if (pretlist == NULL||retlen < retsize) {
						if (retsize == 0) {
							retsize = 4;
						} else {
							retsize <<= 1;
						}
						ptmplist = (pprinter_list_t)malloc(sizeof(*ptmplist) * retsize);
						if (ptmplist == NULL) {
							GETERRNO(ret);
							goto fail;
						}
						memset(ptmplist,0,sizeof(*ptmplist)*retsize);
						if (retlen > 0) {
							memcpy(ptmplist,pretlist,retlen * sizeof(*ptmplist));
						}
						if (pretlist && pretlist != *ppret) {
							free(pretlist);
						}
						pretlist = ptmplist;
						ptmplist = NULL;
					}
					strncpy_s(pretlist[retlen].m_sharename,sizeof(pretlist[retlen].m_sharename),pcurshare,sizeof(pretlist[retlen].m_sharename));
					strncpy_s(pretlist[retlen].m_name, sizeof(pretlist[retlen].m_name), pcurname, sizeof(pretlist[retlen].m_name));
					if (_strnicmp(pcurlocal,"true",4) == 0) {
						strncpy_s(pretlist[retlen].m_type,sizeof(pretlist[retlen].m_type),"local",sizeof(pretlist[retlen].m_type));
					} else {
						strncpy_s(pretlist[retlen].m_type,sizeof(pretlist[retlen].m_type),"network",sizeof(pretlist[retlen].m_type));
					}

					if (strcmp(pretlist[retlen].m_type,"network") == 0) {
						/*skip the first \\ characters*/
						strncpy_s(pretlist[retlen].m_ip, sizeof(pretlist[retlen].m_ip),(pcurserver + 2),sizeof(pretlist[retlen].m_ip));
					}
					retlen ++;
				}
				pcurname = NULL;
				pcurserver = NULL;
				pcurshare = NULL;
				pcurlocal = NULL;
			}
		} else {
			if (strcmp(pplines[i],"") != 0) {
				startline = 1;
			}
		}
		if (_strnicmp(pplines[i],"name=",5) == 0) {
			pcurname = (pplines[i] + 5);
		} else if (_strnicmp(pplines[i],"sharename=",10)==0) {
			pcurshare=(pplines[i] + 10);
		} else if (_strnicmp(pplines[i],"servername=",11)==0) {
			pcurserver = (pplines[i] + 11);
		} else if (_strnicmp(pplines[i],"local=",6) == 0) {
			pcurlocal=(pplines[i] + 6);
		}
	}

	if (*ppret && *ppret != pretlist) {
		free(*ppret);
	}
	*ppret = pretlist;
	pretlist = NULL;

	split_lines(NULL,&pplines,&linesize);
	linelen = 0;
	run_cmd_event_output_single(NULL,NULL,0,&poutlines,&outsize,NULL,0,&exitcode,0,NULL);

	return retlen;
fail:
	if (ptmplist) {
		free(ptmplist);
	}
	ptmplist = NULL;
	if (pretlist && pretlist != *ppret) {
		free(pretlist);
	}
	pretlist = NULL;
	retsize = 0;
	retlen = 0;
	split_lines(NULL,&pplines,&linesize);
	linelen = 0;
	run_cmd_event_output_single(NULL,NULL,0,&poutlines,&outsize,NULL,0,&exitcode,0,NULL);
	SETERRNO(ret);
	return ret;
}

#if _MSC_VER >= 1910
#pragma warning(pop)
#endif