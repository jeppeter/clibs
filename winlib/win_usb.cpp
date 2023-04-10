#include <win_usb.h>
#include <win_err.h>

#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4514)
#include <cfgmgr32.h>
#pragma warning(disable:4668)
#include <setupapi.h>
#pragma warning(pop)

#include <initguid.h>

// This is the GUID for the USB device class
DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE,
			0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);
// (A5DCBF10-6530-11D2-901F-00C04FB951ED)


#pragma comment(lib,"Cfgmgr32.lib")
#pragma comment(lib,"SetupAPI.lib")

int __get_guid_dev(LPGUID pguid,const char* guidstr,pusb_dev_t* ppdata, int *psize)
{
	HDEVINFO hinfo = NULL;
	int ret;
	int retlen = 0;
	SP_DEVINFO_DATA* pndata=NULL;
	DWORD nindex=  0;
	pusb_dev_t pretdata = NULL;
	pusb_dev_t ptmpdata= NULL;
	int retsize=0;
	DEVPROPKEY* propkey = NULL;
	DWORD propkeysize=0;
	DWORD propkeylen = 0;
	DWORD requiresize=0;
	DWORD i;
	uint8_t* ppropbuf=NULL;
	ULONG propbufsize=0;
	CONFIGRET cfgret;
	DEVPROPTYPE proptype;
	BOOL bret;
	if (pguid == NULL) {
		if (ppdata && *ppdata) {
			free(*ppdata);
			*ppdata = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (guidstr == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	pretdata = (pusb_dev_t)(*ppdata);
	retsize = *psize;



	hinfo = SetupDiGetClassDevs(pguid,NULL,NULL,DIGCF_ALLCLASSES);
	if (hinfo == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		ERROR_INFO("get guid [%s] error[%d]", guidstr,ret);
		goto fail;
	}

	pndata = (SP_DEVINFO_DATA*)malloc(sizeof(*pndata));
	if (pndata == NULL) {
		GETERRNO(ret);
		goto fail;
	}


	while(1) {
		memset(pndata,0,sizeof(*pndata));
		pndata->cbSize = sizeof(*pndata);

		bret = SetupDiEnumDeviceInfo(hinfo,nindex,pndata);
		if (!bret) {
			GETERRNO(ret);
			if (ret != ERROR_NO_MORE_ITEMS) {
				ERROR_INFO("get [%s] enum error[%d]", guidstr,ret);
				goto fail;
			}
			break;
		}

		if (retsize <= retlen || pretdata == NULL) {
			if (retsize == 0) {
				retsize = 4;
			} else {
				retsize <<= 1;
			}
			ASSERT_IF(ptmpdata == NULL);
			ptmpdata = (pusb_dev_t)malloc(sizeof(*ptmpdata) * retsize);
			if (ptmpdata == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			memset(ptmpdata,0, sizeof(*ptmpdata) * retsize);
			if (retlen > 0) {
				memcpy(ptmpdata,pretdata, sizeof(*ptmpdata) * retlen);
			}

			if (pretdata && pretdata != *ppdata) {
				free(pretdata);
			}
			pretdata = ptmpdata;
			ptmpdata = NULL;
		}


		/*now to get */
		bret = SetupDiGetDevicePropertyKeys(hinfo,pndata,NULL,0,&requiresize,0);
		if (!bret) {
			GETERRNO(ret);
			if (ret != -ERROR_INSUFFICIENT_BUFFER) {
				ERROR_INFO("get property keys error[%d]",ret);
				goto fail;				
			}

			if (requiresize > propkeysize) {
				propkeysize = requiresize;
				if (propkey != NULL) {
					free(propkey);
				}
				propkey = NULL;
				propkey = (DEVPROPKEY*)malloc(sizeof(*propkey) * propkeysize);
				if (propkey == NULL) {
					GETERRNO(ret);
					goto fail;
				}
			}
		}

		if (propkeysize > 0) {
			memset(propkey, 0, sizeof(*propkey) * propkeysize);
		}

		bret = SetupDiGetDevicePropertyKeys(hinfo,pndata,propkey,propkeysize,&requiresize,0);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("get property keys error[%d]", ret);
			goto fail;
		}
		propkeylen = requiresize;
		for(i=0;i<propkeylen;i++) {
			propkeylen = propkeysize;
			cfgret = CM_Get_DevNode_Property(pndata->DevInst,&(propkey[i]),&proptype,ppropbuf,&propkeylen,0);
			if (cfgret == CR_SUCCESS) {
				DEBUG_BUFFER_FMT(ppropbuf,propbufsize,"prop [%d]", i);
			} else {
				ERROR_INFO("[%ld] return [%ld]", i,cfgret);
			}
		}


	}


	if (ppropbuf) {
		free(ppropbuf);
	}
	ppropbuf = NULL;
	propbufsize = 0;

	if (propkey) {
		free(propkey);
	}
	propkey = NULL;


	if (pndata) {
		free(pndata);
	}
	pndata = NULL;

	if (hinfo != NULL && hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = NULL;


	return retlen;
fail:

	if (ppropbuf) {
		free(ppropbuf);
	}
	ppropbuf = NULL;
	propbufsize = 0;

	if (propkey) {
		free(propkey);
	}
	propkey = NULL;

	if (pndata) {
		free(pndata);
	}
	pndata = NULL;

	if (hinfo != NULL && hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = NULL;

	SETERRNO(ret);
	return ret;
}

int list_usb_roots(int freed, pusb_dev_t* ppur, int *psize)
{
	int retlen = 0;
	char* guidstr = NULL;
	int ccmax = 256;
	int ret;
	if (freed) {
		if (ppur && *ppur) {
			free(*ppur);
			*ppur = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	guidstr = (char*)malloc((size_t)ccmax);
	if (guidstr == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = StringFromGUID2(GUID_DEVINTERFACE_USB_DEVICE,(LPOLESTR)guidstr,ccmax);
	if (ret == 0) {
		GETERRNO(ret);
		goto fail;
	}


	ret = __get_guid_dev((LPGUID)&GUID_DEVINTERFACE_USB_DEVICE,guidstr,ppur,psize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	retlen = ret;
	if (guidstr) {
		free(guidstr);
	}
	guidstr = NULL;

	return retlen;
fail:
	if (guidstr) {
		free(guidstr);
	}
	guidstr = NULL;
	SETERRNO(ret);
	return ret;
}