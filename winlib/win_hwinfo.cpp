#include <win_hwinfo.h>
#include <win_output_debug.h>
#include <win_err.h>
#include <win_uniansi.h>


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

int get_hw_infos(LPGUID pguid, DWORD flags,phw_info_t* ppinfos, int *psize)
{
	int retlen=0;
	return retlen;
}

