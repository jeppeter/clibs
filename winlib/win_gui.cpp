
#include <win_gui.h>
#include <win_err.h>
#include <win_uniansi.h>


int enum_display_devices(int freed, pdisplay_name_t* ppdevices, int *psize)
{
	pdisplay_name_t pdevs = NULL;
	pdisplay_name_t ptmps = NULL;
	int retsize = 0;
	int retlen = 0;
	int ret;
	BOOL bret;
	PDISPLAY_DEVICEA pdisp = NULL;
	if (freed) {
		if (ppdevices && *ppdevices) {
			free(*ppdevices);
			*ppdevices = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppdevices == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}
	retsize = *psize;
	pdevs = *ppdevices;

	pdisp = (PDISPLAY_DEVICEA)malloc(sizeof(*pdisp));
	if (pdisp == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	for (;;) {
		memset(pdisp, 0, sizeof(*pdisp));
		pdisp->cb = sizeof(*pdisp);
		SETERRNO(0);
		bret = EnumDisplayDevicesA(NULL, (DWORD)retlen, pdisp, EDD_GET_DEVICE_INTERFACE_NAME);
		if (!bret) {
			GETERRNO_DIRECT(ret);
			if (ret == 0) {
				break;
			}
			ERROR_INFO("can not get [%d] error[%d]", retlen, ret);
			goto fail;
		}

		if (retlen == retsize || pdevs == NULL) {
			if (retsize == 0) {
				retsize = 4;
			} else {
				retsize <<= 1;
			}

			ptmps = (pdisplay_name_t) malloc(retsize * sizeof(*ptmps));
			if (ptmps == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			memset(ptmps, 0, sizeof(*ptmps) * retsize);
			if (retlen > 0) {
				memcpy(ptmps, pdevs, retlen * sizeof(*ptmps));
			}

			if (pdevs != NULL && pdevs != *ppdevices) {
				free(pdevs);
			}
			pdevs = ptmps;
			ptmps = NULL;
		}

		DEBUG_INFO("[%d].DeviceName =[%s]", retlen, pdisp->DeviceName);
		DEBUG_INFO("[%d].DeviceString =[%s]", retlen, pdisp->DeviceString);
		DEBUG_INFO("[%d].DeviceID =[%s]", retlen, pdisp->DeviceID);
		DEBUG_INFO("[%d].DeviceKey =[%s]", retlen, pdisp->DeviceKey);
		DEBUG_INFO("[%d].StateFlags =[0x%x]", retlen, pdisp->StateFlags);
		strncpy_s(pdevs[retlen].m_name, sizeof(pdisp->DeviceName), pdisp->DeviceName, sizeof(pdisp->DeviceName));
		strncpy_s(pdevs[retlen].m_id, sizeof(pdisp->DeviceID), pdisp->DeviceID, sizeof(pdisp->DeviceID));
		strncpy_s(pdevs[retlen].m_key, sizeof(pdisp->DeviceKey), pdisp->DeviceKey, sizeof(pdisp->DeviceKey));
		strncpy_s(pdevs[retlen].m_devstr, sizeof(pdisp->DeviceString), pdisp->DeviceString, sizeof(pdisp->DeviceString));
		pdevs[retlen].m_state = (int)pdisp->StateFlags;
		retlen ++;
	}

	if (pdisp) {
		free(pdisp);
	}
	pdisp = NULL;

	if (*ppdevices && *ppdevices != pdevs) {
		free(*ppdevices);
	}
	*ppdevices = pdevs;
	*psize = retsize;

	return retlen;
fail:
	if (pdisp) {
		free(pdisp);
	}
	pdisp = NULL;


	if (pdevs != NULL && pdevs != *ppdevices) {
		free(pdevs);
	}
	pdevs = NULL;
	SETERRNO(ret);
	return ret;
}

int enum_display_mode(char* devname, pdisplay_mode_t* ppmode, int *psize)
{
	int ret;
	PDEVMODEA pmode = NULL;
	pdisplay_mode_t pretmode = NULL;
	pdisplay_mode_t ptmps = NULL;
	int retsize = 0;
	int retlen = 0;
	BOOL bret;
	if (devname == NULL) {
		if (ppmode && *ppmode) {
			free(*ppmode);
			*ppmode = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppmode == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pretmode = *ppmode;
	retsize = *psize;

	pmode = (PDEVMODEA) malloc(sizeof(*pmode));
	if (pmode == NULL) {
		GETERRNO(ret);
		goto fail;
	}


	for (;;) {
		memset(pmode, 0, sizeof(*pmode));
		pmode->dmSize = sizeof(*pmode);
		SETERRNO(0);
		bret = EnumDisplaySettingsExA(devname, (DWORD)retlen, pmode, 0);
		if (!bret) {
			GETERRNO_DIRECT(ret);
			if (ret == 0) {
				break;
			}
			ERROR_INFO("[%s].[%d] error[%d]", devname, retlen, ret);
			goto fail;
		}

		if (retlen == retsize || pretmode == NULL) {
			if (retsize == 0) {
				retsize = 4;
			} else {
				retsize <<= 1;
			}

			ptmps = (pdisplay_mode_t) malloc(retsize * sizeof(*ptmps));
			if (ptmps == NULL) {
				GETERRNO(ret);
				goto fail;
			}

			memset(ptmps, 0, retsize * sizeof(*ptmps));
			if (retlen > 0) {
				memcpy(ptmps, pretmode, retlen * sizeof(*ptmps));
			}
			if (pretmode && pretmode != *ppmode) {
				free(pretmode);
			}
			pretmode = ptmps;
			ptmps = NULL;
		}

		// DEBUG_INFO("[%s].[%d].dmDeviceName=[%s]", devname,retlen, pmode->dmDeviceName);
		// DEBUG_INFO("[%s].[%d].dmFormName=[%s]", devname,retlen, pmode->dmFormName);
		// DEBUG_INFO("[%s].[%d].dmSpecVersion=[0x%x]", devname,retlen, pmode->dmSpecVersion);
		// DEBUG_INFO("[%s].[%d].dmDriverVersion=[0x%x]", devname,retlen, pmode->dmDriverVersion);
		// DEBUG_INFO("[%s].[%d].dmSize=[0x%x]", devname,retlen, pmode->dmSize);
		// DEBUG_INFO("[%s].[%d].dmDriverExtra=[0x%x]", devname,retlen, pmode->dmDriverExtra);
		// DEBUG_INFO("[%s].[%d].dmFields=[0x%x]", devname,retlen, pmode->dmFields);
		// DEBUG_INFO("[%s].[%d].dmDisplayFrequency=[0x%x]", devname,retlen, pmode->dmDisplayFrequency);
		// DEBUG_INFO("[%s].[%d].dmPelsWidth=[0x%x]", devname,retlen, pmode->dmPelsWidth);
		// DEBUG_INFO("[%s].[%d].dmPelsHeight=[0x%x]", devname,retlen, pmode->dmPelsHeight);
		// DEBUG_INFO("[%s].[%d].dmBitsPerPel=[0x%x]", devname,retlen, pmode->dmBitsPerPel);
		// DEBUG_INFO("[%s].[%d].dmLogPixels=[0x%x]", devname,retlen, pmode->dmLogPixels);

		pretmode[retlen].m_width = (int)pmode->dmPelsWidth;
		pretmode[retlen].m_height = (int)pmode->dmPelsHeight;
		pretmode[retlen].m_refresh = (int)pmode->dmDisplayFrequency;
		// DEBUG_BUFFER_FMT(pmode->dmDeviceName,sizeof(pmode->dmDeviceName),"[%s].[%d].dmDeviceName", devname,retlen);
		DEBUG_BUFFER_FMT(pmode, sizeof(*pmode), "[%d] mode", retlen);
		strncpy_s(pretmode[retlen].m_name, sizeof(pretmode[retlen].m_name) - 1, devname, sizeof(pretmode[retlen].m_name));
		strncpy_s(pretmode[retlen].m_devname, sizeof(pretmode[retlen].m_devname), (char*)pmode->dmDeviceName, sizeof(pretmode[retlen].m_devname));
		retlen ++;
	}

	if (pmode) {
		free(pmode);
	}
	pmode = NULL;

	if (*ppmode && *ppmode != pretmode) {
		free(*ppmode);
	}
	*ppmode = pretmode;
	*psize = retsize;

	return retlen;
fail:
	if (pmode) {
		free(pmode);
	}
	pmode = NULL;
	if (pretmode && pretmode != *ppmode) {
		free(pretmode);
	}
	pretmode = NULL;
	SETERRNO(ret);
	return ret;
}

int set_display_mode(pdisplay_mode_t pmode, DWORD flags)
{
	PDEVMODEA pdevmode = NULL;
	LONG lret;
	int ret;

	pdevmode = (PDEVMODEA) malloc(sizeof(*pdevmode));
	if (pdevmode == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pdevmode, 0, sizeof(*pdevmode));
	pdevmode->dmSize = sizeof(*pdevmode);
	strncpy_s((char*)pdevmode->dmDeviceName, sizeof(pdevmode->dmDeviceName), pmode->m_devname, sizeof(pdevmode->dmDeviceName));
	pdevmode->dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY;
	pdevmode->dmPelsWidth = (DWORD) pmode->m_width;
	pdevmode->dmPelsHeight = (DWORD) pmode->m_height;
	pdevmode->dmDisplayFrequency = (DWORD) pmode->m_refresh;

	lret = ChangeDisplaySettingsA(pdevmode, flags);
	if (lret != DISP_CHANGE_SUCCESSFUL) {
		GETERRNO(ret);
		ERROR_INFO("DISP_CHANGE_BADDUALVIEW [%d]", DISP_CHANGE_BADDUALVIEW);
		ERROR_INFO("DISP_CHANGE_SUCCESSFUL [%d]", DISP_CHANGE_SUCCESSFUL);
		ERROR_INFO("DISP_CHANGE_BADFLAGS [%d]", DISP_CHANGE_BADFLAGS);
		ERROR_INFO("DISP_CHANGE_BADMODE [%d]", DISP_CHANGE_BADMODE);
		ERROR_INFO("DISP_CHANGE_BADPARAM [%d]", DISP_CHANGE_BADPARAM);
		ERROR_INFO("DISP_CHANGE_FAILED [%d]", DISP_CHANGE_FAILED);
		ERROR_INFO("DISP_CHANGE_NOTUPDATED [%d]", DISP_CHANGE_NOTUPDATED);
		ERROR_INFO("DISP_CHANGE_RESTART [%d]", DISP_CHANGE_RESTART);
		ERROR_INFO("can not set [%s] flags[0x%x] error[%d] lret[%d]", pmode->m_name, flags, ret, lret);
		goto fail;
	}


	if (pdevmode) {
		free(pdevmode);
	}
	pdevmode = NULL;
	return 0;
fail:
	if (pdevmode) {
		free(pdevmode);
	}
	pdevmode = NULL;
	SETERRNO(ret);
	return ret;
}

int get_display_info(int freed, pdisplay_info_t *ppinfo, int *psize)
{
	pdisplay_info_t pretinfo = NULL;
	int retsize = 0;
	int retlen = 0;
	int ret;
	UINT32 flags = QDC_ALL_PATHS;
	UINT32 numpath = 0, numinfo = 0;
	LONG lret;
	DISPLAYCONFIG_PATH_INFO * ppathinfo = NULL;
	DISPLAYCONFIG_MODE_INFO * pmodeinfo = NULL;
	DISPLAYCONFIG_TARGET_DEVICE_NAME * ptargetname = NULL;
	DISPLAYCONFIG_ADAPTER_NAME *padaptername = NULL;
	DISPLAYCONFIG_TARGET_BASE_TYPE* pbasetype = NULL;
	DISPLAYCONFIG_SOURCE_DEVICE_NAME* psourcename =  NULL;
	char* pansiname = NULL;
	int ansisize = 0, ansilen;
	UINT32 i;
	if (freed) {
		if (ppinfo && *ppinfo) {
			free(*ppinfo);
			*ppinfo = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppinfo == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pretinfo = *ppinfo;
	retsize = *psize;


	lret = GetDisplayConfigBufferSizes(flags, &numpath, &numinfo);
	if (lret != ERROR_SUCCESS) {
		GETERRNO(ret);
		ERROR_INFO("GetDisplayConfigBufferSizes error [%ld] [%d]", lret, ret);
		goto fail;
	}

	if (numpath > 0) {
		ppathinfo = (DISPLAYCONFIG_PATH_INFO*)malloc(numpath * sizeof(*ppathinfo));
		if (ppathinfo == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(ppathinfo, 0, numpath * sizeof(*ppathinfo));
	}

	if (numinfo > 0) {
		pmodeinfo = (DISPLAYCONFIG_MODE_INFO*)malloc(numinfo * sizeof(*pmodeinfo));
		if (pmodeinfo == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(pmodeinfo, 0, numinfo * sizeof(*pmodeinfo));
	}

	lret = QueryDisplayConfig(flags, &numpath, ppathinfo, &numinfo, pmodeinfo, NULL);
	if (lret != ERROR_SUCCESS) {
		GETERRNO(ret);
		ERROR_INFO("QueryDisplayConfig error [%ld] [%d]", lret, ret);
		goto fail;
	}

	if (retsize < (int)numpath) {
		retsize = (int)numpath;
		pretinfo = (pdisplay_info_t)malloc(sizeof(*pretinfo) * retsize);
		if (pretinfo == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}
	retlen = (int)numpath;
	if (retsize > 0) {
		memset(pretinfo, 0, sizeof(*pretinfo) * retsize);
	}

	ptargetname = (DISPLAYCONFIG_TARGET_DEVICE_NAME*)malloc(sizeof(*ptargetname));
	if (ptargetname == NULL)  {
		GETERRNO(ret);
		goto fail;
	}

	padaptername = (DISPLAYCONFIG_ADAPTER_NAME*)malloc(sizeof(*padaptername));
	if (padaptername == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	pbasetype = (DISPLAYCONFIG_TARGET_BASE_TYPE*)malloc(sizeof(*pbasetype));
	if (pbasetype == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psourcename = (DISPLAYCONFIG_SOURCE_DEVICE_NAME*)malloc(sizeof(*psourcename));
	if (psourcename == NULL) {
		GETERRNO(ret);
		goto fail;
	}


	for (i = 0; i < numpath; i++) {
		pretinfo[i].m_targetid = ppathinfo[i].targetInfo.id;
		pretinfo[i].m_sourceid = ppathinfo[i].sourceInfo.id;
		memset(ptargetname, 0 , sizeof(*ptargetname));
		ptargetname->header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
		ptargetname->header.size = sizeof(*ptargetname);
		ptargetname->header.id = ppathinfo[i].targetInfo.id;
		ptargetname->header.adapterId = ppathinfo[i].targetInfo.adapterId;
		lret = DisplayConfigGetDeviceInfo(&(ptargetname->header));
		if (lret != ERROR_SUCCESS) {
			GETERRNO(ret);
			ERROR_INFO("[%d]DisplayConfigGetDeviceInfo DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME error [%ld] [%d]", i, lret, ret);
		} else {
			ret = UnicodeToAnsi(ptargetname->monitorFriendlyDeviceName, &pansiname, &ansisize);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			ansilen = ret;
			if (ansilen >= sizeof(pretinfo[i].m_targetname)) {
				memcpy(pretinfo[i].m_targetname, pansiname, sizeof(pretinfo[i].m_targetname) - 1);
			} else {
				memcpy(pretinfo[i].m_targetname, pansiname, (size_t) ansilen);
			}
			DEBUG_INFO("[%d].m_targetname [%s]", i, pretinfo[i].m_targetname);
		}


		memset(psourcename, 0 , sizeof(*psourcename));
		psourcename->header.type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
		psourcename->header.size = sizeof(*psourcename);
		psourcename->header.id = ppathinfo[i].targetInfo.id;
		psourcename->header.adapterId = ppathinfo[i].targetInfo.adapterId;
		lret = DisplayConfigGetDeviceInfo(&(psourcename->header));
		if (lret == ERROR_SUCCESS) {
			ret =  UnicodeToAnsi(psourcename->viewGdiDeviceName, &pansiname, &ansisize);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			ansilen = ret;
			if (ansilen >= sizeof(pretinfo[i].m_sourcename)) {
				memcpy(pretinfo[i].m_sourcename, pansiname, sizeof(pretinfo[i].m_sourcename) - 1);
			} else {
				memcpy(pretinfo[i].m_sourcename, pansiname, (size_t) ansilen);
			}
			DEBUG_INFO("[%d].m_sourcename [%s]", i, pretinfo[i].m_sourcename);
		} else {
			GETERRNO(ret);
			ERROR_INFO("[%d]DisplayConfigGetDeviceInfo DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME error [%ld] [%d]", i, lret, ret);
		}


		memset(padaptername, 0, sizeof(*padaptername));
		padaptername->header.type = DISPLAYCONFIG_DEVICE_INFO_GET_ADAPTER_NAME;
		padaptername->header.size = sizeof(*padaptername);
		padaptername->header.id = ppathinfo[i].targetInfo.id;
		padaptername->header.adapterId = ppathinfo[i].targetInfo.adapterId;
		lret = DisplayConfigGetDeviceInfo(&(padaptername->header));
		if (lret != ERROR_SUCCESS) {
			GETERRNO(ret);
			ERROR_INFO("[%d]DisplayConfigGetDeviceInfo DISPLAYCONFIG_DEVICE_INFO_GET_ADAPTER_NAME error [%ld] [%d]", i, lret, ret);
		} else {
			ret =  UnicodeToAnsi(padaptername->adapterDevicePath, &pansiname, &ansisize);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			ansilen = ret;
			if (ansilen >= sizeof(pretinfo[i].m_adaptername)) {
				memcpy(pretinfo[i].m_adaptername, pansiname, sizeof(pretinfo[i].m_adaptername) - 1);
			} else {
				memcpy(pretinfo[i].m_adaptername, pansiname, (size_t) ansilen);
			}
			DEBUG_INFO("[%d].m_adaptername [%s]", i,pretinfo[i].m_adaptername);
		}


		memset(pbasetype, 0, sizeof(*pbasetype));
		pbasetype->header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_BASE_TYPE;
		pbasetype->header.size = sizeof(*pbasetype);
		pbasetype->header.id = ppathinfo[i].targetInfo.id;
		pbasetype->header.adapterId = ppathinfo[i].targetInfo.adapterId;
		lret = DisplayConfigGetDeviceInfo(&(pbasetype->header));
		if (lret != ERROR_SUCCESS) {
			GETERRNO(ret);
			ERROR_INFO("[%d]DisplayConfigGetDeviceInfo DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_BASE_TYPE error [%ld] [%d]", i, lret, ret);
		} else {
			pretinfo[i].m_basetype = pbasetype->baseOutputTechnology;
			DEBUG_INFO("")
		}	

	}

	UnicodeToAnsi(NULL, &pansiname, &ansisize);

	if (ptargetname) {
		free(ptargetname);
	}
	ptargetname = NULL;

	if (padaptername) {
		free(padaptername);
	}
	padaptername = NULL;

	if (pbasetype) {
		free(pbasetype);
	}
	pbasetype = NULL;

	if (psourcename) {
		free(psourcename);
	}
	psourcename = NULL;


	if (ppathinfo) {
		free(ppathinfo);
	}
	ppathinfo = NULL;
	if (pmodeinfo) {
		free(pmodeinfo);
	}
	pmodeinfo = NULL;


	if (*ppinfo && *ppinfo != pretinfo) {
		free(*ppinfo);
	}
	*ppinfo = pretinfo;
	*psize = retsize;
	return retlen;

fail:
	UnicodeToAnsi(NULL, &pansiname, &ansisize);

	if (ptargetname) {
		free(ptargetname);
	}
	ptargetname = NULL;

	if (padaptername) {
		free(padaptername);
	}
	padaptername = NULL;

	if (pbasetype) {
		free(pbasetype);
	}
	pbasetype = NULL;

	if (psourcename) {
		free(psourcename);
	}
	psourcename = NULL;


	if (ppathinfo) {
		free(ppathinfo);
	}
	ppathinfo = NULL;
	if (pmodeinfo) {
		free(pmodeinfo);
	}
	pmodeinfo = NULL;

	if (pretinfo && pretinfo != *ppinfo) {
		free(pretinfo);
	}
	pretinfo = NULL;
	retsize = 0;
	SETERRNO(ret);
	return ret;
}