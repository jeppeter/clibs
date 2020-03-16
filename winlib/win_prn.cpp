#include <win_prn.h>
#include <win_proc.h>
#include <win_strop.h>
#include <win_err.h>
#include <win_fileop.h>
#include <win_strop.h>

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


int add_share_printer(HANDLE hexitevt,char* name,char* remoteip,char* user,char* password)
{
	int ret;
	char* filetemplate=NULL;
	int templatesize=0;
	char* tempfile=NULL;
	int tempsize=0;
	int added=1;
	char* batscript=NULL;
	int batsize=0;
	int batlen=0;
	char* cmpname=NULL;
	int cmpsize=0;
	pprinter_list_t pplist=NULL;
	int prnsize=0,prnlen=0;
	int fidx=0;
	int i;
	int exitcode=0;

	ret = snprintf_safe(&cmpname,&cmpsize,"\\\\%s\\%s",remoteip,name);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	ret = get_printer_list(0,hexitevt,&pplist,&prnsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	prnlen = ret;


	fidx= -1;
	for (i=0;i<prnlen;i++) {
		if (_stricmp(cmpname,pplist[i].m_name) ==0) {
			added=0;
			DEBUG_INFO("already added [%s]",cmpname);
			goto succ;
		}
	}

	ret = snprintf_safe(&batscript,&batsize,"REM to connect use \nnet use \"\\\\%s\\ipc$\" /user:\"%s\" \"%s\"\nrundll32.exe printui.dll,PrintUIEntry /in /q /n \"\\\\%s\\%s\"",
		remoteip,user ? user : "guest", password ? password : "",remoteip,name);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	batlen = ret;

	ret = mktempfile_safe("addshareXXXXXX",&filetemplate,&templatesize);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("mktempfile error[%d]",ret);
		goto fail;
	}

	ret = snprintf_safe(&tempfile,&tempsize,"%s.bat",filetemplate);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = write_file_whole(tempfile,batscript,batlen);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("write [%s] error[%d]", tempfile,ret);
		goto fail;
	}

	run_cmd_event_output_single(hexitevt,NULL,0,NULL,0,NULL,0,&exitcode,0,tempfile);

	/*we do not check for the return value or */
	ret = get_printer_list(0,hexitevt,&pplist,&prnsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	prnlen = 0;
	fidx = -1;
	for (i= 0;i<prnlen;i++) {
		if (_stricmp(pplist[i].m_name,cmpname) == 0) {
			fidx = i;
			break;
		}
	}

	if (fidx < 0) {
		ret = -ERROR_CANNOT_MAKE;
		ERROR_INFO("can not make \\\\%s\\%s on user[%s] password[%s]", remoteip,name,user,password);
		goto fail;
	}

succ:
	get_printer_list(1,NULL,&pplist,&prnsize);
	snprintf_safe(&cmpname,&cmpsize,NULL);
	if (tempfile) {
		delete_file(tempfile);
	}
	snprintf_safe(&tempfile,&tempsize,NULL);
	mktempfile_safe(NULL,&filetemplate,&templatesize);
	snprintf_safe(&batscript,&batsize,NULL);
	return added;
fail:
	get_printer_list(1,NULL,&pplist,&prnsize);
	snprintf_safe(&cmpname,&cmpsize,NULL);
	if (tempfile) {
		delete_file(tempfile);
	}
	snprintf_safe(&tempfile,&tempsize,NULL);
	mktempfile_safe(NULL,&filetemplate,&templatesize);
	snprintf_safe(&batscript,&batsize,NULL);
	SETERRNO(ret);
	return ret;
}

#if _MSC_VER >= 1910
#pragma warning(pop)
#endif 