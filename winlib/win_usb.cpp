#include <win_usb.h>
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

// This is the GUID for the USB device class
DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE,
            0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);
// (A5DCBF10-6530-11D2-901F-00C04FB951ED)


// This is the GUID for the USB hub class
DEFINE_GUID(GUID_DEVINTERFACE_USB_HUB,
            0xF18A0E88L, 0xC30C, 0x11D0, 0x88, 0x15, 0x00, 0xA0, 0xC9, 0x06, 0xBE, 0xD8);
// ({F18A0E88-C30C-11D0-8815-00A0C906BED8})


#define  HWID_PROPERTY_GUID     "{A45C254E-DF1C-4EFD-8020-67D146A850E0}"
#define  HWID_PROPERTY_PID      0x3

#define  INSTID_PROPERTY_GUID   "{78C34FC8-104A-4ACA-9EA4-524D52996E57}"
#define  INSTID_PROPERTY_PID    0x100

#pragma comment(lib,"Cfgmgr32.lib")
#pragma comment(lib,"SetupAPI.lib")

int __get_guid_str(LPGUID pguid, char** ppstr, int *psize)
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

int __get_guid_dev(LPGUID pguid, const char* guidstr, pusb_dev_t* ppdata, int *psize)
{
	HDEVINFO hinfo = NULL;
	int ret;
	int retlen = 0;
	SP_DEVINFO_DATA* pndata = NULL;
	DWORD nindex =  0;
	pusb_dev_t pretdata = NULL;
	pusb_dev_t ptmpdata = NULL;
	int retsize = 0;
	DEVPROPKEY* propkey = NULL;
	DWORD propkeysize = 0;
	DWORD propkeylen = 0;
	DWORD requiresize = 0;
	DWORD i;
	uint8_t* ppropbuf = NULL;
	ULONG propbufsize = 0;
	ULONG propbuflen = 0;
	CONFIGRET cfgret;
	DEVPROPTYPE proptype;
	BOOL bret;
	char* fmtid = NULL;
	int fmtmax = 0;
	char* propansi = NULL;
	int propansisize = 0;
	wchar_t* pwptr = NULL;
	int matchid = -1;
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


	hinfo = SetupDiGetClassDevs(pguid, NULL, NULL, DIGCF_ALLCLASSES);
	if (hinfo == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		ERROR_INFO("get guid [%s] error[%d]", guidstr, ret);
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

		DEBUG_INFO("nindex [0x%x] pndata [%p]", nindex, pndata);
		bret = SetupDiEnumDeviceInfo(hinfo, nindex, pndata);
		DEBUG_INFO("nindex [0x%x] pndata [%p] return", nindex, pndata);
		if (!bret) {
			GETERRNO(ret);
			if (ret != ERROR_NO_MORE_ITEMS) {
				ERROR_INFO("get [%s] enum error[%d]", guidstr, ret);
				goto fail;
			}
			DEBUG_INFO("nindex [0x%x]", nindex);
			break;
		}
		DEBUG_INFO("nindex [0x%x] pndata [%p] get", nindex, pndata);

		/*now to get */
		bret = SetupDiGetDevicePropertyKeys(hinfo, pndata, NULL, 0, &requiresize, 0);
		DEBUG_INFO("requiresize [%ld]", requiresize);
		if (!bret) {
			GETERRNO(ret);
			if (ret != -ERROR_INSUFFICIENT_BUFFER) {
				ERROR_INFO("get property keys error[%d]", ret);
				goto fail;
			}

			if (requiresize > propkeysize) {
				DEBUG_INFO("requiresize [0x%x]" ,requiresize);
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

		DEBUG_INFO("requiresize [%ld]", requiresize);
		bret = SetupDiGetDevicePropertyKeys(hinfo, pndata, propkey, propkeysize, &requiresize, 0);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("get property keys error[%d]", ret);
			goto fail;
		}
		propkeylen = requiresize;
		DEBUG_INFO("propkeylen [%ld]", propkeylen);
		if (ppropbuf == NULL) {
			propbufsize = 4;
			ppropbuf = (uint8_t*) malloc(propbufsize);
			if (ppropbuf == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}

		matchid = -1;
		for (i = 0; i < propkeylen; i++) {

			if (propkey[i].pid == HWID_PROPERTY_PID || propkey[i].pid == INSTID_PROPERTY_PID) {
				ret = __get_guid_str(&(propkey[i].fmtid), &fmtid, &fmtmax);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				if (_stricmp(fmtid, HWID_PROPERTY_GUID) == 0 && propkey[i].pid == HWID_PROPERTY_PID) {
					matchid = (int)i;
				} else if (_stricmp(fmtid, INSTID_PROPERTY_GUID) == 0 && propkey[i].pid == INSTID_PROPERTY_PID) {
					matchid = (int) i;
				}
			}

			if (matchid >= 0) {
				if (retlen >= retsize || pretdata == NULL) {
					if (retsize == 0) {
						retsize = 0;
					} else {
						retsize <<= 1;
					}
					ptmpdata = (pusb_dev_t) malloc(sizeof(*ptmpdata) * retsize);
					if (ptmpdata == NULL) {
						GETERRNO(ret);
						goto fail;
					}
					memset(ptmpdata, 0, sizeof(*ptmpdata) * retsize);
					if (retlen > 0) {
						memcpy(ptmpdata, pretdata, sizeof(*ptmpdata) * retlen);
					}
					if (pretdata && pretdata != *ppdata) {
						free(pretdata);
					}
					pretdata = ptmpdata;
					ptmpdata = NULL;
				}

try_again:
				propbuflen = propbufsize;
				memset(ppropbuf, 0, propbufsize);
				cfgret = CM_Get_DevNode_PropertyW(pndata->DevInst, &(propkey[i]), &proptype, ppropbuf, &propbuflen, 0);
				if (cfgret == CR_SUCCESS) {
					char* ppcptr ;
					int setpid = -1;
					int setvid = -1;
					pwptr = (wchar_t*)ppropbuf;
					DEBUG_BUFFER_FMT(ppropbuf, propbuflen, "[%ld].[%d]prop [%s] pid[%ld:0x%lx]", nindex, i, fmtid, propkey[i].pid, propkey[i].pid);
					ret = UnicodeToAnsi(pwptr, &propansi, &propansisize);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
					ppcptr = propansi;
					DEBUG_INFO("[%ld].[%s].[%d] prop[%s]", nindex, fmtid, i, propansi);
					if (propkey[i].pid == HWID_PROPERTY_PID) {
						while (*ppcptr != '\0') {
							if (setpid < 0) {
								if (_strnicmp(ppcptr, "pid_", 4) == 0) {
									setpid = 0;
									ppcptr += 4;
									while (*ppcptr != '\0' && *ppcptr != '&') {
										if (*ppcptr >= '0' && *ppcptr <= '9') {
											setpid <<= 4;
											setpid += *ppcptr - '0';
										} else if (*ppcptr >= 'a' && *ppcptr <= 'f') {
											setpid <<= 4;
											setpid += *ppcptr - 'a' + 10;
										} else if (*ppcptr >= 'A' && *ppcptr <= 'F') {
											setpid <<= 4;
											setpid += *ppcptr - 'A' + 10;
										} else {
											ret = -ERROR_INVALID_PARAMETER;
											ERROR_INFO("not valid [%s]", propansi);
											goto fail;
										}
										ppcptr ++;
									}
									pretdata[retlen].m_prodid = (uint32_t) setpid;
								}
							}
							if (setvid < 0 ) {
								if (_strnicmp(ppcptr, "vid_", 4) == 0) {
									setvid = 0;
									ppcptr += 4;
									while (*ppcptr != '\0' && *ppcptr != '&') {
										if (*ppcptr >= '0' && *ppcptr <= '9') {
											setvid <<= 4;
											setvid += *ppcptr - '0';
										} else if (*ppcptr >= 'a' && *ppcptr <= 'f') {
											setvid <<= 4;
											setvid += *ppcptr - 'a' + 10;
										} else if (*ppcptr >= 'A' && *ppcptr <= 'F') {
											setvid <<= 4;
											setvid += *ppcptr - 'A' + 10;
										} else {
											ret = -ERROR_INVALID_PARAMETER;
											ERROR_INFO("not valid [%s]", propansi);
											goto fail;
										}
										ppcptr ++;
									}
									pretdata[retlen].m_vendorid = (uint32_t) setvid;
								}
							}

							if (setvid >= 0 && setpid >= 0) {
								DEBUG_INFO("setvid [0x%x] setpid [0x%x]",setvid,setpid);
								break;
							}
							ppcptr ++;
						}

						if (setvid < 0 || setpid < 0) {
							ret = -ERROR_INVALID_PARAMETER;
							ERROR_INFO("no pid or vid in [%s]", propansi);
							goto fail;
						}

						strncpy_s((char*)pretdata[retlen].m_path, sizeof(pretdata[retlen].m_path) - 1, propansi, sizeof(pretdata[retlen].m_path) - 1);
					} else if (propkey[i].pid == INSTID_PROPERTY_PID) {
						while (*ppcptr != '\0') {
							if (setpid < 0) {
								if (_strnicmp(ppcptr, "pid_", 4) == 0) {
									setpid = 0;
									ppcptr += 4;
									while (*ppcptr != '\0' && *ppcptr != '&') {
										if (*ppcptr >= '0' && *ppcptr <= '9') {
											setpid <<= 4;
											setpid += *ppcptr - '0';
										} else if (*ppcptr >= 'a' && *ppcptr <= 'f') {
											setpid <<= 4;
											setpid += *ppcptr - 'a' + 10;
										} else if (*ppcptr >= 'A' && *ppcptr <= 'F') {
											setpid <<= 4;
											setpid += *ppcptr - 'A' + 10;
										} else {
											ret = -ERROR_INVALID_PARAMETER;
											ERROR_INFO("not valid [%s]", propansi);
											goto fail;
										}
										ppcptr ++;
									}
									pretdata[retlen].m_prodid = (uint32_t) setpid;
								}
							}
							if (setvid < 0 ) {
								if (_strnicmp(ppcptr, "vid_", 4) == 0) {
									setvid = 0;
									ppcptr += 4;
									while (*ppcptr != '\0' && *ppcptr != '&') {
										if (*ppcptr >= '0' && *ppcptr <= '9') {
											setvid <<= 4;
											setvid += *ppcptr - '0';
										} else if (*ppcptr >= 'a' && *ppcptr <= 'f') {
											setvid <<= 4;
											setvid += *ppcptr - 'a' + 10;
										} else if (*ppcptr >= 'A' && *ppcptr <= 'F') {
											setvid <<= 4;
											setvid += *ppcptr - 'A' + 10;
										} else {
											ret = -ERROR_INVALID_PARAMETER;
											ERROR_INFO("not valid [%s]", propansi);
											goto fail;
										}
										ppcptr ++;
									}
									pretdata[retlen].m_vendorid = (uint32_t) setvid;
								}
							}

							if (setvid >= 0 && setpid >= 0) {
								DEBUG_INFO("setvid [0x%x] setpid [0x%x]",setvid,setpid);
								break;
							}
							ppcptr ++;
						}

						if (setvid < 0 || setpid < 0) {
							ret = -ERROR_INVALID_PARAMETER;
							ERROR_INFO("no pid or vid in [%s]", propansi);
							goto fail;
						}

						strncpy_s((char*)pretdata[retlen].m_path, sizeof(pretdata[retlen].m_path) - 1, propansi, sizeof(pretdata[retlen].m_path) - 1);
					}
					retlen ++;
					DEBUG_INFO("retlen [%d]", retlen);
				} else {
					if (cfgret == CR_BUFFER_SMALL) {
						propbufsize <<= 1;
						if (ppropbuf) {
							free(ppropbuf);
						}
						ppropbuf = (uint8_t*)malloc(propbufsize);
						if (ppropbuf == NULL) {
							GETERRNO(ret);
							goto fail;
						}
						goto try_again;
					} else {
						ERROR_INFO("[%ld][%ld] return [%ld]", nindex, i, cfgret);
					}
				}
			}
			if (matchid >= 0) {
				break;
			}
		}
		DEBUG_INFO("nindex [0x%x]", nindex);

		nindex ++;
	}

	UnicodeToUtf8(NULL, &propansi, &propansisize);

	__get_guid_str(NULL, &fmtid, &fmtmax);

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


	if (*ppdata && *ppdata != pretdata) {
		free(*ppdata);
	}
	*ppdata = pretdata;
	*psize = retsize;

	return retlen;
fail:
	UnicodeToUtf8(NULL, &propansi, &propansisize);

	__get_guid_str(NULL, &fmtid, &fmtmax);

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

	if (pretdata != *ppdata && pretdata != NULL) {
		free(pretdata);
	}
	pretdata = NULL;

	SETERRNO(ret);
	return ret;
}

int list_usb_devices(int freed, pusb_dev_t* ppur, int *psize)
{
	int retlen = 0;
	char* guidstr = NULL;
	int ccmax = 0;
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

	ret = __get_guid_str((LPGUID)&GUID_DEVINTERFACE_USB_DEVICE, &guidstr, &ccmax);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	ret = __get_guid_dev((LPGUID)&GUID_DEVINTERFACE_USB_DEVICE, guidstr, ppur, psize);
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
	__get_guid_str(NULL, &guidstr, &ccmax);
	SETERRNO(ret);
	return ret;
}