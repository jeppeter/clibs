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


void __free_hw_prop(phw_prop_t* ppprop)
{
	if (ppprop && *ppprop) {
		phw_prop_t pprop = *ppprop;
		UnicodeToUtf8(NULL,&(pprop->m_propguid),&(pprop->m_propguidsize));
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
			for(i=0;i<pinfo->m_propsize;i++) {
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
	memset(pinfo, 0 ,sizeof(*pinfo));
	return pinfo;
fail:
	__free_hw_info(&pinfo);
	SETERRNO(ret);
	return NULL;
}

int get_hw_infos(LPGUID pguid, DWORD flags,phw_info_t** pppinfos, int *psize)
{
	int retlen=0;
	int retsize = 0;
	int i;
	int ret;
	phw_info_t* ppinfos= NULL;
	HDEVINFO hinfo = INVALID_HANDLE_VALUE;

	if (pguid == NULL) {
		if (pppinfos && *pppinfos) {
			ppinfos = *pppinfos;
			if (psize) {
				retsize = *psize;
				for (i=0;i<retsize;i++) {
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
		return 0;
	}

	hinfo = SetupDiGetClassDevsW(pguid, NULL, NULL, flags);
	if (hinfo == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		ERROR_INFO("can not get flags [0x%x]",flags);
		goto fail;
	}


	if (hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = INVALID_HANDLE_VALUE;

	return retlen;
fail:
	if (hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = INVALID_HANDLE_VALUE;
	SETERRNO(ret);
	return ret;
}

