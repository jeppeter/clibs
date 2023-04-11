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
	int retlen = 0;
	int ret;
	HDEVINFO hinfo = INVALID_HANDLE_VALUE;
	pusb_dev_t pretdata = NULL;
	int retsize = 0;
	SP_DEVINFO_DATA* pndata = NULL;
	DWORD nindex;
	BOOL bret;
	DEVPROPKEY* propkeys = NULL;
	DWORD propkeysize = 0;
	DWORD requiresize = 0;
	DWORD propkeylen = 0;
	DWORD i;
	char* fmtid = NULL;
	int ccmax = 0;
	int matchid ;
	uint8_t* propbuf = NULL;
	ULONG propbufsize = 0;
	ULONG propbuflen = 0;
	ULONG wi = 0;
	wchar_t* pwptr = NULL;
	char* propansi = NULL;
	int ansisize = 0;
	char* ppcptr = NULL;
	DEVPROPTYPE  proptype;
	pusb_dev_t ptmp = NULL;
	CONFIGRET cfgret;
	int setvid = -1;
	int setpid = -1;

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

	if (guidstr == NULL || ppdata == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pretdata = *ppdata;
	retsize = *psize;

	hinfo = SetupDiGetClassDevsW(pguid, NULL, NULL, DIGCF_ALLCLASSES);
	if (hinfo == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		ERROR_INFO("can not get class dev [%s] error[%d]", guidstr, ret);
		goto fail;
	}

	pndata = (SP_DEVINFO_DATA*)malloc(sizeof(*pndata));
	if (pndata == NULL) {
		GETERRNO(ret);
		goto fail;
	}


	nindex = 0;
	while (1) {
		memset(pndata, 0, sizeof(*pndata));
		pndata->cbSize = sizeof(*pndata);

		bret = SetupDiEnumDeviceInfo(hinfo, nindex, pndata);
		if (!bret) {
			GETERRNO(ret);
			if (ret != -ERROR_NO_MORE_ITEMS) {
				ERROR_INFO("can not get [%s] on [%ld] device error[%d]", guidstr, nindex, ret);
				goto fail;
			}
			/*all is gotten*/
			break;
		}

		requiresize = 0;
		bret = SetupDiGetDevicePropertyKeys(hinfo, pndata, NULL, 0, &requiresize, 0);
		if (!bret) {
			GETERRNO(ret);
			if (ret != -ERROR_INSUFFICIENT_BUFFER) {
				ERROR_INFO("[%s].[%ld] get property keys error[%d]", guidstr, nindex, ret);
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
			ERROR_INFO("[%s].[%ld] get prop keys error[%d]", guidstr, nindex, ret);
			goto fail;
		}
		//DEBUG_INFO("[%s].[%ld] get prop keys [%ld]", guidstr, nindex, propkeylen);

		for (i = 0; i < propkeylen ; i ++) {
			ret = __get_guid_str(&propkeys[i].fmtid, &fmtid, &ccmax);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
try_2:
			//proptype = 0;
			if (propbuf) {
				memset(propbuf, 0, propbufsize);
			}
			propbuflen = propbufsize;
			cfgret = CM_Get_DevNode_PropertyW(pndata->DevInst, &(propkeys[i]), &proptype, propbuf, &propbuflen, 0);
			if (cfgret == CR_SUCCESS) {
				pwptr = (wchar_t*) propbuf;
				wi = 0;
				DEBUG_BUFFER_FMT(propbuf,propbuflen,"[%ld].[%ld] [%s].[0x%lx] property", nindex,i,fmtid,propkeys[i].pid);
				while (wi < propbuflen) {
					while (wi < propbuflen && *pwptr == 0) {
						pwptr += 1;
						wi += 2;
					}

					if (wi < propbuflen) {
						ret = UnicodeToUtf8(pwptr, &propansi,&ansisize)	;
						if (ret < 0) {
							GETERRNO(ret);
							goto fail;
						}
						DEBUG_INFO("    [%s]", propansi);
					}

					while(wi < propbuflen && *pwptr != 0) {
						pwptr += 1;
						wi += 2;
					}
				}
			} else {
				if (cfgret == CR_BUFFER_SMALL) {
					propbufsize = propbuflen;
					if (propbuf) {
						free(propbuf);
					}
					propbuf = NULL;
					propbuf = (uint8_t*) malloc(propbufsize);
					if (propbuf == NULL) {
						GETERRNO(ret);
						goto fail;
					}
					goto try_2;
				}
				GETERRNO(ret);
				ERROR_INFO("[%s].[%ld].[%ld] prop [%s].[0x%lx] error[%d]", guidstr, nindex, i, fmtid,propkeys[i].pid, cfgret);
			}

		}


		matchid = -1;
		for (i = 0; i < propkeylen; i++) {
			if (propkeys[i].pid == HWID_PROPERTY_PID || propkeys[i].pid == INSTID_PROPERTY_PID) {
				ret = __get_guid_str(&(propkeys[i].fmtid), &fmtid, &ccmax);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				if (_stricmp(fmtid, HWID_PROPERTY_GUID) == 0 && propkeys[i].pid == HWID_PROPERTY_PID) {
					matchid = (int) i;
				} else if (_stricmp(fmtid, INSTID_PROPERTY_GUID) == 0 && propkeys[i].pid == INSTID_PROPERTY_PID) {
					matchid = (int) i;
				}
			}

			if (matchid >= 0) {
				if (retlen >= retsize) {
					if (retsize == 0) {
						retsize = 4;
					} else {
						retsize <<= 1;
					}
					ASSERT_IF(ptmp == NULL);
					ptmp = (pusb_dev_t) malloc(sizeof(*ptmp) * retsize);
					if (ptmp == NULL) {
						GETERRNO(ret);
						goto fail;
					}

					memset(ptmp, 0, sizeof(*ptmp) * retsize);
					if (retlen > 0) {
						memcpy(ptmp, pretdata, sizeof(*ptmp) * retlen);
					}

					if (pretdata && pretdata != *ppdata) {
						free(pretdata);
					}
					pretdata = NULL;
					pretdata = ptmp;
					ptmp = NULL;
				}

try_again:

				proptype = 0;
				if (propbuf != NULL) {
					memset(propbuf, 0, propbufsize);
				}
				setvid = -1;
				setpid = -1;
				propbuflen = propbufsize;
				cfgret = CM_Get_DevNode_PropertyW(pndata->DevInst, &(propkeys[i]), &proptype, propbuf, &propbuflen, 0);
				if (cfgret == CR_SUCCESS) {
					memset(&pretdata[retlen], 0 , sizeof(pretdata[retlen]));
					if (propkeys[i].pid == HWID_PROPERTY_PID || propkeys[i].pid == INSTID_PROPERTY_PID) {
						pwptr = (wchar_t*) propbuf;
						ret = UnicodeToUtf8(pwptr, &propansi, &ansisize);
						if (ret < 0) {
							GETERRNO(ret);
							goto fail;
						}
						//DEBUG_INFO("[%s].[%ld].[%ld] [%s].[0x%lx] prop [%s] setvid [%d] setpid [%d]", guidstr, nindex, i, fmtid, propkeys[i].pid, propansi,setvid,setpid);
						ppcptr = propansi;
						while (*ppcptr != '\0') {
							if (setvid < 0) {
								if (_strnicmp(ppcptr, "vid_", 4) == 0) {
									setvid = 0;
									ppcptr += 4;
									while (*ppcptr != '\0' && *ppcptr != '&' && *ppcptr != '\\') {
										if (*ppcptr >= '0' && *ppcptr <= '9') {
											setvid <<= 4;
											setvid += *ppcptr - '0';
										} else if (*ppcptr >= 'a' && *ppcptr <= 'f') {
											setvid <<= 4;
											setvid += (*ppcptr - 'a' + 10);
										} else if (*ppcptr >= 'A' && *ppcptr <= 'F') {
											setvid <<= 4;
											setvid += (*ppcptr - 'A' + 10);
										} else {
											setvid = -1;
											ERROR_INFO("[%ld].[%ld] prop [%s] not valid vid", nindex, i, propansi);
											break;
										}
										ppcptr ++;
									}
									pretdata[retlen].m_vendorid = (uint32_t)setvid;
									DEBUG_INFO("set vid [0x%x]", setvid);
								}
							}

							if (setpid < 0) {
								if (_strnicmp(ppcptr, "pid_", 4) == 0) {
									setpid = 0;
									ppcptr += 4;
									while (*ppcptr != '\0' && *ppcptr != '&' && *ppcptr != '\\') {
										if (*ppcptr >= '0' && *ppcptr <= '9') {
											setpid <<= 4;
											setpid += *ppcptr - '0';
										} else if (*ppcptr >= 'a' && *ppcptr <= 'f') {
											setpid <<= 4;
											setpid += (*ppcptr - 'a' + 10);
										} else if (*ppcptr >= 'A' && *ppcptr <= 'F') {
											setpid <<= 4;
											setpid += (*ppcptr - 'A' + 10);
										} else {
											setpid = -1;
											ERROR_INFO("[%ld].[%ld] prop [%s] not valid pid", nindex, i, propansi);
											break;
										}
										ppcptr ++;
									}
									pretdata[retlen].m_prodid = (uint32_t)setpid;
									DEBUG_INFO("set pid [0x%x]", setpid);
								}
							}

							if (setpid >= 0 && setvid >= 0) {
								break;
							}
							ppcptr ++;
						}

						if (setvid < 0 || setpid < 0) {
							ERROR_INFO("[%s].[%ld].[%ld] prop [%s] not valid", guidstr, nindex, i, propansi);
							matchid = -1;
						}

						if (matchid >= 0) {
							int clen = (int) strlen(propansi);
							if (clen >= sizeof(pretdata[retlen].m_path)) {
								clen = sizeof(pretdata[retlen].m_path) - 1;
							}
							memcpy(pretdata[retlen].m_path, propansi, (size_t)clen);
							retlen ++ ;
						}
					}
				} else {
					if (cfgret == CR_BUFFER_SMALL) {
						propbufsize = propbuflen;
						if (propbuf) {
							free(propbuf);
						}
						propbuf = NULL;
						propbuf = (uint8_t*) malloc(propbufsize);
						if (propbuf == NULL) {
							GETERRNO(ret);
							goto fail;
						}
						goto try_again;
					}
					GETERRNO(ret);
					ERROR_INFO("[%s].[%ld].[%ld] prop [%s] error[%d]", guidstr, nindex, i, fmtid, cfgret);
					goto fail;
				}
			}

			if (matchid >= 0) {
				break;
			}
		}

		nindex ++;
	}

	DEBUG_INFO("nindex [%ld]", nindex);

	UnicodeToUtf8(NULL, &propansi, &ansisize);

	if (propbuf) {
		free(propbuf);
	}
	propbuf = NULL;
	propbufsize = 0;
	propbuflen = 0;

	__get_guid_str(NULL, &fmtid, &ccmax);

	if (propkeys) {
		free(propkeys);
	}
	propkeys = NULL;
	propkeysize = 0;


	if (pndata) {
		free(pndata);
	}
	pndata = NULL;


	if (hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = INVALID_HANDLE_VALUE;




	if (*ppdata && *ppdata != pretdata) {
		free(*ppdata);
	}
	*ppdata = pretdata;
	*psize = retsize;


	return retlen;
fail:
	UnicodeToUtf8(NULL, &propansi, &ansisize);
	if (propbuf) {
		free(propbuf);
	}
	propbuf = NULL;
	propbufsize = 0;
	propbuflen = 0;


	if (ptmp) {
		free(ptmp);
	}
	ptmp = NULL;

	__get_guid_str(NULL, &fmtid, &ccmax);

	if (propkeys) {
		free(propkeys);
	}
	propkeys = NULL;
	propkeysize = 0;


	if (pndata) {
		free(pndata);
	}
	pndata = NULL;

	if (hinfo != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hinfo);
	}
	hinfo = INVALID_HANDLE_VALUE;

	if (pretdata && pretdata != *ppdata) {
		free(pretdata);
	}
	pretdata = NULL;
	retsize = 0;

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