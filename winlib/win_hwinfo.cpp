#include <win_hwinfo.h>
#include <win_output_debug.h>
#include <win_err.h>
#include <win_uniansi.h>

#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4514)
#include <cfgmgr32.h>
#pragma warning(disable:4668)
#include <setupapi.h>
#pragma warning(pop)

#include <initguid.h>

#pragma comment(lib,"Cfgmgr32.lib")
#pragma comment(lib,"SetupAPI.lib")


int get_guid_str(LPGUID pguid, char** ppstr, int *psize)
{
	wchar_t* puni = NULL;
	int ccmax = 256;
	int ret;
	int retlen = 0;

	if (pguid == NULL) {
		return UnicodeToAnsi(NULL, ppstr, psize);
	}

	puni = (wchar_t*) malloc(ccmax * sizeof(wchar_t));
	if (puni == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = StringFromGUID2((*pguid), puni, ccmax);
	if (ret == 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = UnicodeToAnsi(puni, ppstr, psize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	retlen = ret;
	if (puni) {
		free(puni);
	}
	puni = NULL;

	return retlen;
fail:
	if (puni) {
		free(puni);
	}
	puni = NULL;
	SETERRNO(ret);
	return ret;
}

void __free_hw_prop(phw_prop_t* ppprop)
{
	if (ppprop && *ppprop) {
		phw_prop_t pprop = *ppprop;
		UnicodeToUtf8(NULL, &(pprop->m_propguid), &(pprop->m_propguidsize));
		if (pprop->m_propbuf) {
			free(pprop->m_propbuf);
			pprop->m_propbuf = NULL;
		}
		pprop->m_propbuflen = 0;
		pprop->m_propbufsize = 0;
		free(pprop);
		*ppprop = NULL;
	}
}

void __free_hw_info(phw_info_t* ppinfo)
{
	if (ppinfo && *ppinfo) {
		phw_info_t pinfo = *ppinfo;
		if (pinfo->m_proparr != NULL) {
			int i;
			for (i = 0; i < pinfo->m_propsize; i++) {
				__free_hw_prop(&(pinfo->m_proparr[i]));
			}
			free(pinfo->m_proparr);
			pinfo->m_proparr = NULL;
		}
		pinfo->m_propsize = 0;
		pinfo->m_proplen = 0;
		free(pinfo);
		*ppinfo = NULL;
	}
	return;
}

phw_info_t __alloc_hw_info()
{
	phw_info_t pinfo = NULL;
	int ret;
	pinfo = (phw_info_t)malloc(sizeof(*pinfo));
	if (pinfo == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pinfo, 0 , sizeof(*pinfo));
	return pinfo;
fail:
	__free_hw_info(&pinfo);
	SETERRNO(ret);
	return NULL;
}

void __free_hw_infos(phw_info_t** pppinfos, int *psize)
{
	phw_info_t* ppinfos = NULL;
	int i;
	int retsize;
	if (pppinfos && *pppinfos) {
		ppinfos = *pppinfos;
		if (psize) {
			retsize = *psize;
			for (i = 0; i < retsize; i++) {
				__free_hw_info(&(ppinfos[i]));
			}
		}
		if (ppinfos) {
			free(ppinfos);
		}
		*pppinfos = NULL;
	}
	if (psize) {
		*psize = 0;
	}
	return;
}

int __append_hw_infos(phw_info_t** pppinfos, int *psize, phw_info_t* ppinfo)
{
	int findidx = -1;
	int i;
	int retsize = 0;
	int retlen = 0;
	int ret;
	phw_info_t* ppinfos;
	phw_info_t* pptmp = NULL;
	ASSERT_IF(pppinfos != NULL);
	ASSERT_IF(psize != NULL);
	retsize = *psize;
	ppinfos = *pppinfos;
	for (i = 0; i < retsize; i++) {
		if (ppinfos[i] == NULL) {
			findidx = i;
			break;
		}
	}

	if (findidx < 0) {
		retlen = retsize;
		if (retsize == 0) {
			retsize = 4;
		}  else {
			retsize <<= 1;
		}
		pptmp = (phw_info_t*) malloc(sizeof(*pptmp) * retsize);
		if (pptmp == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(pptmp, 0, sizeof(*pptmp) * retsize);
		if (retlen > 0) {
			memcpy(pptmp, ppinfos, sizeof(*pptmp) * retlen);
		}
		if (ppinfos != NULL) {
			free(ppinfos);
		}
		ppinfos = pptmp;
		pptmp = NULL;
		*pppinfos = ppinfos;
		*psize = retsize;
	} else {
		retlen = findidx;
	}
	ppinfos[retlen] = *ppinfo;
	*ppinfo = NULL;
	retlen ++;
	return retlen;
fail:
	if (pptmp) {
		free(pptmp);
	}
	pptmp = NULL;
	SETERRNO(ret);
	return ret;
}

int get_hw_infos(LPGUID pguid, DWORD flags, phw_info_t** pppinfos, int *psize)
{
	int retlen = 0;
	int retsize = 0;
	int ret;
	phw_info_t* ppinfos = NULL;
	phw_info_t pcurinfo = NULL;
	HDEVINFO hinfo = INVALID_HANDLE_VALUE;

	if (pguid == NULL) {
		__free_hw_infos(pppinfos, psize);
		return 0;
	}

	if (pppinfos == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	/*we free used to reset*/
	__free_hw_infos(pppinfos, psize);


	hinfo = SetupDiGetClassDevsW(pguid, NULL, NULL, flags);
	if (hinfo == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		ERROR_INFO("can not get flags [0x%x]", flags);
		goto fail;
	}





	ASSERT_IF(pcurinfo == NULL);
	*pppinfos = ppinfos;
	*psize = retsize;
	ppinfos = NULL;
	retsize = 0;

	if (hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = INVALID_HANDLE_VALUE;

	return retlen;
fail:
	__free_hw_info(&pcurinfo);
	__free_hw_infos(&ppinfos, &retsize);
	if (hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = INVALID_HANDLE_VALUE;
	SETERRNO(ret);
	return ret;
}

