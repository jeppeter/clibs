
#include <win_gui.h>
#include <win_err.h>


int enum_display_devices(int freed,pdisplay_name_t* ppdevices, int *psize)
{
	pdisplay_name_t pdevs=NULL;
	pdisplay_name_t ptmps=NULL;
	int retsize=0;
	int retlen=0;
	int ret;
	BOOL bret;
	PDISPLAY_DEVICEA pdisp=NULL;
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
		memset(pdisp,0,sizeof(*pdisp));
		pdisp->cb = sizeof(*pdisp);
		SETERRNO(0);
		bret = EnumDisplayDevicesA(NULL,(DWORD)retlen,pdisp,EDD_GET_DEVICE_INTERFACE_NAME);
		if (!bret) {
			GETERRNO_DIRECT(ret);
			if (ret == 0) {
				break;
			}
			ERROR_INFO("can not get [%d] error[%d]",retlen, ret);
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
		strncpy_s(pdevs[retlen].m_id, sizeof(pdisp->DeviceID),pdisp->DeviceID, sizeof(pdisp->DeviceID));
		strncpy_s(pdevs[retlen].m_key, sizeof(pdisp->DeviceKey), pdisp->DeviceKey,sizeof(pdisp->DeviceKey));
		strncpy_s(pdevs[retlen].m_devstr,sizeof(pdisp->DeviceString),pdisp->DeviceString,sizeof(pdisp->DeviceString));
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
	PDEVMODEA pmode=NULL;
	pdisplay_mode_t pretmode=NULL;
	pdisplay_mode_t ptmps=NULL;
	int retsize=0;
	int retlen=0;
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


	for(;;) {
		memset(pmode,0,sizeof(*pmode));
		pmode->dmSize = sizeof(*pmode);
		SETERRNO(0);
		bret = EnumDisplaySettingsExA(devname,(DWORD)retlen,pmode,0);
		if (!bret) {
			GETERRNO_DIRECT(ret);
			if (ret == 0) {
				break;
			}
			ERROR_INFO("[%s].[%d] error[%d]", devname,retlen, ret);
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

			memset(ptmps,0,retsize * sizeof(*ptmps));
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
		strncpy_s(pretmode[retlen].m_name, sizeof(pretmode[retlen].m_name) - 1, devname, sizeof(pretmode[retlen].m_name));
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