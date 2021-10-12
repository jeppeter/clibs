
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
		bret = EnumDisplayDevicesA(NULL,(DWORD)retlen,pdisp,EDD_GET_DEVICE_INTERFACE_NAME);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("can not get [%d] error[%d]",retlen, ret);
			break;
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