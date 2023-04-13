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

int guid_from_str2(LPGUID pguid, char* pstr)
{
	wchar_t* pwstr = NULL;
	int wlen = 0;
	int ret;
	HRESULT hr;

	if (pguid == NULL || pstr == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	ret = AnsiToUnicode(pstr,&pwstr,&wlen);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	hr = CLSIDFromString((LPCOLESTR)pwstr,(LPCLSID)pguid);
	if (hr != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("convert [%s] error[%d]", pstr,ret);
		goto fail;
	}

	AnsiToUnicode(NULL,&pwstr,&wlen);
	return 0;
fail:
	AnsiToUnicode(NULL,&pwstr,&wlen);
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
		pprop->m_propguididx = -1;
		free(pprop);
		*ppprop = NULL;
	}
}

phw_prop_t __alloc_hw_prop()
{
	phw_prop_t pprop = NULL;
	int ret;

	pprop = (phw_prop_t) malloc(sizeof(*pprop));
	if (pprop == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pprop,0,sizeof(*pprop));
	pprop->m_propguid = NULL;
	pprop->m_propbuf = NULL;
	pprop->m_propbuflen = 0;
	pprop->m_propbufsize = 0;
	pprop->m_propguidsize = 0;
	pprop->m_propguididx = -1;

	return pprop;
fail:
	__free_hw_prop(&pprop);
	SETERRNO(ret);
	return NULL;
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

int __append_hw_info_prop(phw_info_t pinfo,phw_prop_t *ppprop)
{
	phw_prop_t* pptmp = NULL;
	int ret;
	if (pinfo->m_proplen >= pinfo->m_propsize) {
		if (pinfo->m_propsize == 0) {
			pinfo->m_propsize = 4;
		} else {
			pinfo->m_propsize <<= 1;
		}

		pptmp = (phw_prop_t*) malloc(sizeof(*pptmp) * pinfo->m_propsize);
		if (pptmp == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(pptmp, 0, sizeof(*pptmp) * pinfo->m_propsize);
		if (pinfo->m_proplen > 0) {
			memcpy(pptmp, pinfo->m_proparr, sizeof(*pptmp) * pinfo->m_proplen);
		}
		if (pinfo->m_proparr) {
			free(pinfo->m_proparr);
		}
		pinfo->m_proparr = pptmp;
		pptmp = NULL;
	}

	pinfo->m_proparr[pinfo->m_proplen] = *ppprop;
	pinfo->m_proplen ++;
	*ppprop = NULL;

	return pinfo->m_proplen;
fail:
	if (pptmp) {
		free(pptmp);
	}
	pptmp = NULL;
	SETERRNO(ret);
	return ret;
}

int __get_hw_info_props(phw_info_t pinfo, HDEVINFO hinfo, SP_DEVINFO_DATA* pndata)
{
	DEVPROPKEY* propkeys = NULL;
	DWORD propkeysize = 0;
	DWORD requiresize = 0;
	DWORD propkeylen = 0;
	BOOL bret;
	int ret;
	DWORD i;
	CONFIGRET cfgret;
	DEVPROPTYPE  proptype;
	phw_prop_t pcurprop = NULL;


	requiresize = 0;
	bret = SetupDiGetDevicePropertyKeys(hinfo, pndata, NULL, 0, &requiresize, 0);
	if (!bret) {
		GETERRNO(ret);
		if (ret != -ERROR_INSUFFICIENT_BUFFER) {
			ERROR_INFO("get property keys error[%d]", ret);
			goto fail;
		}
	}

	if (requiresize > propkeysize) {
		propkeysize = requiresize;
		if (propkeys) {
			free(propkeys);
		}
		propkeys = NULL;
		propkeys = (DEVPROPKEY*) malloc(sizeof(*propkeys) * propkeysize);
		if (propkeys == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	memset(propkeys, 0 , sizeof(*propkeys) * propkeysize);
	propkeylen = 0;
	bret = SetupDiGetDevicePropertyKeys(hinfo, pndata, propkeys, propkeysize, &propkeylen, 0);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("get prop keys error[%d]", ret);
		goto fail;
	}

	for (i = 0; i < propkeylen; i++) {
		ASSERT_IF(pcurprop == NULL);
		pcurprop = __alloc_hw_prop();
		if (pcurprop == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		ret = get_guid_str(&propkeys[i].fmtid, &(pcurprop->m_propguid),&(pcurprop->m_propguidsize));
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		pcurprop->m_propguididx = (int)propkeys[i].pid;
try_2:
		if (pcurprop->m_propbuf) {
			memset(pcurprop->m_propbuf, 0, (size_t)pcurprop->m_propbufsize);
		}
		pcurprop->m_propbuflen = pcurprop->m_propbufsize;
		proptype = 0;
		cfgret = CM_Get_DevNode_PropertyW(pndata->DevInst, &(propkeys[i]), &proptype, pcurprop->m_propbuf, &(pcurprop->m_propbuflen), 0);
		if (cfgret == CR_SUCCESS) {
			ret = __append_hw_info_prop(pinfo,&pcurprop);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		} else {
			if (cfgret == CR_BUFFER_SMALL) {
				pcurprop->m_propbufsize = pcurprop->m_propbuflen;
				if (pcurprop->m_propbuf) {
					free(pcurprop->m_propbuf);
				}
				pcurprop->m_propbuf = NULL;
				pcurprop->m_propbuf = (uint8_t*) malloc(pcurprop->m_propbufsize);
				if (pcurprop->m_propbuf == NULL) {
					GETERRNO(ret);
					goto fail;
				}
				goto try_2;
			}
			GETERRNO(ret);
			ERROR_INFO("[%ld] prop [%s].[0x%x] error[%d]", i, pcurprop->m_propguid, pcurprop->m_propguididx, cfgret);
			/*to free property*/
			__free_hw_prop(&pcurprop);
		}
	}


	ASSERT_IF(pcurprop == NULL);
	if (propkeys) {
		free(propkeys);
	}
	propkeys = NULL;

	return (int)propkeylen;
fail:
	__free_hw_prop(&pcurprop);
	if (propkeys) {
		free(propkeys);
	}
	propkeys = NULL;
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
	SP_DEVINFO_DATA* pndata = NULL;
	DWORD nindex = 0;
	BOOL bret;
	LPGUID psetguid = pguid;

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

	if (psetguid == GUID_NULL_PTR) {
		psetguid = NULL;
	} else {
		DEBUG_BUFFER_FMT(psetguid,sizeof(*psetguid),"set guid");
	}


	DEBUG_INFO("psetguid [%p] flags 0x%lx", psetguid, flags);
	hinfo = SetupDiGetClassDevsW(psetguid, NULL, NULL, flags);
	if (hinfo == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		ERROR_INFO("can not get flags [0x%x]", flags);
		goto fail;
	}

	pndata = (SP_DEVINFO_DATA*)malloc(sizeof(*pndata));
	if (pndata == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	while (1) {
		memset(pndata, 0, sizeof(*pndata));
		pndata->cbSize = sizeof(*pndata);

		bret = SetupDiEnumDeviceInfo(hinfo, nindex, pndata);
		if (!bret) {
			GETERRNO(ret);
			if (ret != -ERROR_NO_MORE_ITEMS) {
				ERROR_INFO("can not get on [%ld] device error[%d]", nindex , ret);
				goto fail;
			}
			/*all is gotten*/
			break;
		}

		ASSERT_IF(pcurinfo == NULL);
		pcurinfo = __alloc_hw_info();
		if (pcurinfo == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		ret = __get_hw_info_props(pcurinfo, hinfo, pndata);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = __append_hw_infos(&ppinfos, &retsize, &pcurinfo);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		retlen = ret;
		nindex += 1;
	}




	if (pndata) {
		free(pndata);
	}
	pndata = NULL;


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
	if (pndata) {
		free(pndata);
	}
	pndata = NULL;


	__free_hw_info(&pcurinfo);
	__free_hw_infos(&ppinfos, &retsize);
	if (hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = INVALID_HANDLE_VALUE;
	SETERRNO(ret);
	return ret;
}

int get_hw_prop(phw_info_t pinfo, char* propguid, int propidx, uint8_t** ppbuf, int *psize)
{
	int ret;
	int retlen = 0;
	uint8_t* pretbuf = NULL;
	int retsize = 0;
	int i;
	int fidx = -1;
	phw_prop_t pcurprop=NULL;

	if (pinfo == NULL) {
		if (ppbuf && *ppbuf) {
			free(*ppbuf);
			*ppbuf = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}
	if (propguid == NULL || ppbuf == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pretbuf = *ppbuf;
	retsize = *psize;

	for(i=0;i < pinfo->m_propsize;i++) {
		pcurprop = pinfo->m_proparr[i];
		if (pcurprop != NULL) {
			if (pcurprop->m_propguid && _stricmp(pcurprop->m_propguid, propguid) == 0 && pcurprop->m_propguididx == propidx) {
				fidx = i;
				break;
			}
		}
	}

	if (fidx < 0) {
		ret = -ERROR_NOT_FOUND;
		ERROR_INFO("not found [%s].[%d]",propguid, propidx);
		goto fail;
	}

	if ((int)pcurprop->m_propbuflen > retsize || pretbuf == NULL) {
		retsize = (int)pcurprop->m_propbuflen;
		pretbuf = (uint8_t*) malloc(pcurprop->m_propbuflen);
		if (pretbuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}
	memset(pretbuf, 0, (size_t)retsize);
	retlen = (int)pcurprop->m_propbuflen;
	if (retlen > 0) {
		memcpy(pretbuf, pcurprop->m_propbuf, pcurprop->m_propbuflen);	
	}

	if (*ppbuf && *ppbuf != pretbuf) {
		free(*ppbuf);
	}
	*ppbuf = pretbuf;
	*psize = retsize;

	return retlen;
fail:
	if (pretbuf && pretbuf != *ppbuf) {
		free(pretbuf);
	}
	pretbuf = NULL;
	retsize = 0;
	SETERRNO(ret);
	return ret;
}