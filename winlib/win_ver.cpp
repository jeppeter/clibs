#include <win_ver.h>
#include <win_err.h>
#include <win_output_debug.h>


int get_osversion(int freed,OSVERSIONINFOEXW **ppver,int *psize)
{
	BOOL bret;
	OSVERSIONINFOEXW* pretver=NULL;
	int retsize=0;
	int retlen=0;
	int ret;
	if (freed) {
		if (ppver && *ppver) {
			free(*ppver);
			*ppver = NULL;
		}
		if (*psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppver == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pretver = *ppver;
	retsize = *psize;
	if (pretver == NULL || retsize < sizeof(*pretver)) {
		if (retsize < sizeof(*pretver)) {
			retsize = sizeof(*pretver);
		}
		pretver = (OSVERSIONINFOEXW*)malloc(retsize);
		if (pretver == NULL) {
			GETERRNO(ret);
			ERROR_INFO("alloc %d error[%d]", retsize, ret);
			goto fail;
		}
	}
	memset(pretver, 0 ,retsize);
	pretver->dwOSVersionInfoSize = retsize;

	bret = GetVersionExW((OSVERSIONINFOW*)pretver);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("can not get version error[%d]", ret);
		goto fail;
	}

	retlen = retsize;

	if (*ppver && *ppver != pretver) {
		free(*ppver);
	}
	*ppver = pretver;
	*psize = retsize;
	return retlen;
fail:
	if (pretver && pretver != *ppver) {
		free(pretver);
	}
	pretver =NULL;
	SETERRNO(ret);
	return ret;
}


int is_win7()
{
	OSVERSIONINFOEXW* posw=NULL;
	int size=0;
	int ret;
	int isvalid = 0;

	ret=  get_osversion(0, &posw,&size);
	if (ret < 0) {
		goto fail;
	}
	if (posw->dwMajorVersion == 6 && 
		posw->dwMinorVersion == 1 && 
		posw->wProductType  == VER_NT_WORKSTATION) {
		isvalid = 1;
	}

	get_osversion(1,&posw,&size);
	return isvalid;
fail:
	get_osversion(1,&posw,&size);
	return 0;
}

int is_win10()
{
	OSVERSIONINFOEXW* posw=NULL;
	int size=0;
	int ret;
	int isvalid = 0;

	ret=  get_osversion(0, &posw,&size);
	if (ret < 0) {
		goto fail;
	}
	DEBUG_INFO("major %d minor %d type %ld buildnumber %d", posw->dwMajorVersion,posw->dwMinorVersion,posw->wProductType, posw->dwBuildNumber);
	if (posw->dwMajorVersion == 10 && 
		posw->dwMinorVersion == 0 && 
		posw->wProductType  == VER_NT_WORKSTATION) {
		isvalid = 1;
	} else if (posw->dwMajorVersion == 6 && 
		posw->dwMinorVersion == 2 && 
		posw->wProductType == VER_NT_WORKSTATION && 
		posw->dwBuildNumber >= 9200) {
		isvalid = 1;
	}

	get_osversion(1,&posw,&size);
	return isvalid;
fail:
	get_osversion(1,&posw,&size);
	return 0;	
}
