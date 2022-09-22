#include <win_types.h>
#include <win_serial.h>
#include <win_output_debug.h>
#include <win_uniansi.h>


#define  SERIAL_DATA_MAGIC   0x710129d3


typedef struct __win_serial_priv {
	uint32_t m_magic;
	uint32_t m_reserv1;
	char* m_name;
	HANDLE m_hfile;
	HANDLE m_hrdevt;
	HANDLE m_hwrevt;
	uint8_t* m_prdptr;
	int m_rdleft;
	int m_reserv2;
	uint8_t* m_pwrptr;
	int m_wrleft;
	int m_reserv3;
	OVERLAPPED m_rdov;
	OVERLAPPED m_wrov;
	int m_inrd;
	int m_inwr;
	uint64_t m_rdtotal;
	uint64_t m_wrtotal;
	DCB m_dcb;
	DCB m_cacheddcb;
	int m_cached;
	int m_reserv4;
} win_serial_priv_t, *pwin_serial_priv_t;

void __free_serial(pwin_serial_priv_t* ppcom)
{
	BOOL bret;
	int ret;
	if (ppcom && *ppcom) {
		pwin_serial_priv_t pcom = *ppcom;
		if (pcom->m_magic != SERIAL_DATA_MAGIC) {
			ERROR_INFO("not magic com");
		}

		if (pcom->m_inrd > 0) {
			ASSERT_IF(pcom->m_hfile != NULL && pcom->m_hfile != INVALID_HANDLE_VALUE);
			bret = CancelIoEx(pcom->m_hfile, &(pcom->m_rdov));
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("cancel [%s] read event error[%d]", pcom->m_name, ret);
			}
		}
		pcom->m_inrd = 0;
		memset(&(pcom->m_rdov), 0 , sizeof(pcom->m_rdov));

		if (pcom->m_inwr > 0) {
			ASSERT_IF(pcom->m_hfile != NULL && pcom->m_hfile != INVALID_HANDLE_VALUE);
			bret = CancelIoEx(pcom->m_hfile, &(pcom->m_wrov));
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("cancel [%s] write event error[%d]", pcom->m_name, ret);
			}
		}
		pcom->m_inwr = 0;
		memset(&(pcom->m_wrov), 0, sizeof(pcom->m_wrov));

		if (pcom->m_hrdevt != NULL) {
			CloseHandle(pcom->m_hrdevt);
		}
		pcom->m_hrdevt = NULL;

		if (pcom->m_hwrevt != NULL) {
			CloseHandle(pcom->m_hwrevt);
		}
		pcom->m_hwrevt = NULL;

		if (pcom->m_hfile != NULL && pcom->m_hfile != INVALID_HANDLE_VALUE) {
			CloseHandle(pcom->m_hfile);
		}
		pcom->m_hfile = NULL;

		if (pcom->m_name != NULL) {
			free(pcom->m_name);
		}
		pcom->m_name = NULL;

		pcom->m_pwrptr = NULL;
		pcom->m_wrleft = 0;
		pcom->m_prdptr = NULL;
		pcom->m_rdleft = 0;

		pcom->m_rdtotal = 0;
		pcom->m_wrtotal = 0;

		memset(&(pcom->m_dcb), 0, sizeof(pcom->m_dcb));
		memset(&(pcom->m_cacheddcb), 0, sizeof(pcom->m_cacheddcb));
		pcom->m_cached = 0;

		free(pcom);
		*ppcom = NULL;
	}
}

void close_serial(void** ppcom)
{
	__free_serial((pwin_serial_priv_t*)ppcom);
}


void* open_serial(const char* name)
{
	pwin_serial_priv_t pcom = NULL;
	int ret;
	TCHAR* ptname = NULL;
	int tnamesize = 0;
	BOOL bret;

	if (name == NULL) {
		ret =  -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	pcom = (pwin_serial_priv_t)malloc(sizeof(*pcom));
	if (pcom == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pcom, 0, sizeof(*pcom));
	pcom->m_magic = SERIAL_DATA_MAGIC;
	pcom->m_name = NULL;
	pcom->m_hfile = NULL;
	pcom->m_hrdevt = NULL;
	pcom->m_hwrevt = NULL;

	pcom->m_prdptr = NULL;
	pcom->m_rdleft = 0;
	pcom->m_pwrptr = NULL;
	pcom->m_wrleft = 0;

	memset(&(pcom->m_rdov), 0, sizeof(pcom->m_rdov));
	memset(&(pcom->m_wrov), 0, sizeof(pcom->m_wrov));

	pcom->m_inrd = 0;
	pcom->m_inwr = 0;

	memset(&(pcom->m_dcb), 0, sizeof(pcom->m_dcb));
	memset(&(pcom->m_cacheddcb), 0, sizeof(pcom->m_cacheddcb));
	pcom->m_cached = 0;


	/*now to open file*/
	pcom->m_name = _strdup(name);
	if (pcom->m_name == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = AnsiToTchar(name, &ptname, &tnamesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	pcom->m_hfile = CreateFile(ptname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (pcom->m_hfile == NULL || pcom->m_hfile == INVALID_HANDLE_VALUE) {
		pcom->m_hfile = NULL;
		GETERRNO(ret);
		ERROR_INFO("open [%s] error[%d]", pcom->m_name, ret);
		goto fail;
	}

	/*now to make event ok*/
	pcom->m_hrdevt = CreateEvent(NULL, TRUE, TRUE, NULL);
	if (pcom->m_hrdevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("create [%s] rdevt error[%d]", pcom->m_name, ret);
		goto fail;
	}
	pcom->m_rdov.hEvent = pcom->m_hrdevt;

	pcom->m_hwrevt = CreateEvent(NULL, TRUE, TRUE, NULL);
	if (pcom->m_hwrevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("create [%s] wrevt error[%d]", pcom->m_name, ret);
		goto fail;
	}
	pcom->m_wrov.hEvent = pcom->m_hwrevt;

	memset(&(pcom->m_dcb),0,sizeof(pcom->m_dcb));
	pcom->m_dcb.DCBlength = sizeof(pcom->m_dcb.DCBlength);


	bret = GetCommState(pcom->m_hfile, &(pcom->m_dcb));
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("can not GetCommState [%s] error[%d]", pcom->m_name, ret);
		goto fail;
	}


	DEBUG_INFO("open [%s] succ", pcom->m_name);
	AnsiToTchar(NULL, &ptname, &tnamesize);
	return pcom;
fail:
	AnsiToTchar(NULL, &ptname, &tnamesize);
	__free_serial(&pcom);
	SETERRNO(ret);
	return NULL;
}

int __inner_read_serial(pwin_serial_priv_t pcom)
{
	int completed = 0;
	int ret;
	DWORD cbret;
	BOOL bret;

	while (pcom->m_rdleft > 0) {
		bret = ReadFile(pcom->m_hfile, pcom->m_prdptr, (DWORD) pcom->m_rdleft, &cbret, &(pcom->m_rdov));
		if (!bret) {
			GETERRNO(ret);
			if (ret == -ERROR_IO_PENDING ) {
				DEBUG_INFO("read pending on [%d] rdleft", pcom->m_rdleft);
				return 0;
			} else if (ret == -ERROR_MORE_DATA) {
				pcom->m_rdleft -= cbret;
				pcom->m_prdptr += cbret;
				pcom->m_rdtotal += cbret;
				if (pcom->m_rdleft == 0) {
					pcom->m_prdptr = NULL;
					completed = 1;
					pcom->m_inrd = 0;
				}
				return completed;
			}
			ERROR_INFO("can not read [%s] on [%d] error[%d]", pcom->m_name, pcom->m_rdleft, ret);
			SETERRNO(ret);
			return ret;
		}

		DEBUG_INFO("cbret [%d]", cbret);
		pcom->m_rdleft -= cbret;
		pcom->m_prdptr += cbret;
		pcom->m_rdtotal += cbret;
	}

	if (pcom->m_rdleft == 0) {
		completed = 1;
		pcom->m_prdptr = NULL;
		pcom->m_inrd = 0;
	}
	return completed;
}

int read_serial(void* pcom1, void* pbuf, int bufsize)
{
	pwin_serial_priv_t pcom = (pwin_serial_priv_t) pcom1;
	int completed = 0;
	int ret;
	if (pcom == NULL || pcom->m_magic != SERIAL_DATA_MAGIC ||
	        pcom->m_inrd > 0) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pcom->m_prdptr = (uint8_t*)pbuf;
	pcom->m_rdleft = bufsize;
	pcom->m_inrd = 1;
	ret = __inner_read_serial(pcom);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	if (pcom->m_inrd == 0) {
		completed = 1;
	}
	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int __inner_write_serial(pwin_serial_priv_t pcom)
{
	int completed = 0;
	int ret;
	DWORD cbret;
	BOOL bret;

	while (pcom->m_wrleft > 0) {
		bret = ReadFile(pcom->m_hfile, pcom->m_pwrptr, (DWORD) pcom->m_wrleft, &cbret, &(pcom->m_wrov));
		if (!bret) {
			GETERRNO(ret);
			if (ret == -ERROR_IO_PENDING ) {
				DEBUG_INFO("write pending on [%d] rdleft", pcom->m_rdleft);
				return 0;
			} else if (ret == -ERROR_MORE_DATA) {
				pcom->m_wrleft -= cbret;
				pcom->m_pwrptr += cbret;
				pcom->m_wrtotal += cbret;
				if (pcom->m_wrleft == 0) {
					pcom->m_pwrptr = NULL;
					completed = 1;
					pcom->m_inwr = 0;
				}
				return completed;
			}
			ERROR_INFO("can not write [%s] on [%d] error[%d]", pcom->m_name, pcom->m_wrleft, ret);
			SETERRNO(ret);
			return ret;
		}

		DEBUG_INFO("cbret [%d]", cbret);
		pcom->m_wrleft -= cbret;
		pcom->m_pwrptr += cbret;
		pcom->m_wrtotal += cbret;
	}

	if (pcom->m_wrleft == 0) {
		completed = 1;
		pcom->m_pwrptr = NULL;
		pcom->m_inwr = 0;
	}
	return completed;
}


int write_serial(void* pcom1, void* pbuf, int bufsize)
{
	pwin_serial_priv_t pcom = (pwin_serial_priv_t) pcom1;
	int completed = 0;
	int ret;
	if (pcom == NULL || pcom->m_magic != SERIAL_DATA_MAGIC ||
	        pcom->m_inwr > 0) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pcom->m_pwrptr = (uint8_t*)pbuf;
	pcom->m_wrleft = bufsize;
	pcom->m_inwr = 1;
	ret = __inner_write_serial(pcom);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	if (pcom->m_inwr == 0) {
		completed = 1;
	}
	return completed;
fail:
	SETERRNO(ret);
	return ret;
}