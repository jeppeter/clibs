#include <win_dns.h>


#define WSA_GETERRNO(ret) do { ret = WSAGetLastError(); if (ret > 0) {ret = -ret;} if (ret == 0) {ret = -1;} } while(0)


#define  DNS_QUERY_HDR_MAGIC   0x77929ac

typedef struct __dns_query {
	uint32_t m_magic;
	int m_aftype;
	char* m_qryip;
	char* m_qryport;
	char** m_iparr;
	int m_iplen;
	int m_ipsize;
	int m_inprog;
	uint64_t m_startticks;
	PADDRINFOEX  m_infores;
	ADDRINFOEX m_hints;
	WSAOVERLAPPED m_ov;
	HANDLE m_compevt;
	HANDLE m_cancelevt;
} DNS_QUERY_t,*PDNS_QUERY_t;


void __free_dns_query(PDNS_QUERY_t* ppdnsqry)
{
	if (ppdnsqry && *ppdnsqry) {
		int ret;
		int i;
		PDNS_QUERY_t pdnsqry = *ppdnsqry;
		if (pdnsqry->m_magic != DNS_QUERY_HDR_MAGIC) {
			ERROR_INFO("not valid DNS_QUERY_HDR_MAGIC 0x%x", pdnsqry->m_magic);
		}

		if (pdnsqry->m_inprog != 0) {
			ret = GetAddrInfoExCancel(pdnsqry->m_cancelevt);
			if (ret != NO_ERROR) {
				ERROR_INFO("GetAddrInfoExCancel error %d ",ret);
			}
			pdnsqry->m_inprog = 0;
		}

		if (pdnsqry->m_infores) {
			FreeAddrInfoEx(pdnsqry->m_infores);
		}
		pdnsqry->m_infores = NULL;

		memset(&pdnsqry->m_ov,0,sizeof(pdnsqry->m_ov));
		if (pdnsqry->m_compevt != NULL) {
			CloseHandle(pdnsqry->m_compevt);
		}
		pdnsqry->m_compevt = NULL;

		if (pdnsqry->m_cancelevt != NULL) {
			CloseHandle(pdnsqry->m_cancelevt);
		}
		pdnsqry->m_cancelevt = NULL;

		if (pdnsqry->m_iparr) {
			for(i=0;pdnsqry->m_iparr[i]!=NULL;i++) {
				free(pdnsqry->m_iparr[i]);
				pdnsqry->m_iparr[i] = NULL;
			}

			free(pdnsqry->m_iparr);
			pdnsqry->m_iparr = NULL;
		}

		pdnsqry->m_iplen = 0;
		pdnsqry->m_ipsize = 0;

		if (pdnsqry->m_qryip) {
			free(pdnsqry->m_qryip);
		}
		pdnsqry->m_qryip= NULL;

		if (pdnsqry->m_qryport) {
			free(pdnsqry->m_qryport);
		}
		pdnsqry->m_qryport = NULL;

		free(pdnsqry);
		*ppdnsqry = NULL;
	}
	return;
}

PDNS_QUERY_t __alloc_dns_query(int type,const char* name,const char* portstr)
{
	PDNS_QUERY_t pdnsqry = NULL;
	int ret;

	pdnsqry = malloc(sizeof(*pdnsqry));
	if (pdnsqry == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pdnsqry,0,sizeof(*pdnsqry));
	pdnsqry->m_magic = DNS_QUERY_HDR_MAGIC;
	pdnsqry->m_aftype = type;
	pdnsqry->m_qryip = _strdup(name);
	pdnsqry->m_qryport = _strdup(portstr);
	if (pdnsqry->m_qryip == NULL || pdnsqry->m_qryport == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	pdnsqry->m_compevt = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (pdnsqry->m_compevt == NULL)	 {
		GETERRNO(ret);
		ERROR_INFO("CreateEvent m_compevt error %d", ret);
		goto fail;
	}

	pdnsqry->m_cancelevt = CreateEvent(NULL,TRUE,FALSE,NULL);
	if (pdnsqry->m_cancelevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("CreateEvent m_cancelevt error %d", ret);
		goto fail;
	}

	return pdnsqry;
fail:
	__free_dns_query(&pdnsqry);
	SETERRNO(ret);
	return NULL;
}

int __fill_dns_result(PDNS_QUERY_t pdnsqry)
{
	int ret;
	int retlen = 0;
	PADDRINFOEX    pcurinfo=NULL;
	char* pstr = NULL;
	int size = 256;

	if (pstr) {
		free(pstr);
	}
	pstr = NULL;
	pstr = malloc(size);
	if (pstr == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	/*now we should give */
	pcurinfo = pdnsqry->m_infores;
	while(pcurinfo != NULL) {
		if (pcurinfo->ai_family == pdnsqry->m_aftype) {

		}
	}

	if (pstr) {
		free(pstr);
	}
	pstr = NULL;

	return retlen;
fail:
	if (pstr) {
		free(pstr);
	}
	pstr = NULL;

	SETERRNO(ret);
	return ret;
}



int __start_query_dns(PDNS_QUERY_t pdnsqry)
{
	wchar_t* pwip=NULL,*pwport=NULL;
	int wipsize=0,wportsize=0;
	int ret;
	int completed = 0;
	DWORD dret;

	if (pdnsqry->m_qryip == NULL || pdnsqry->m_inprog != 0) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	ret = AnsiToUnicode(pdnsqry->m_qryip,&pwip,&wipsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (pdnsqry->m_qryport != NULL) {
		ret = AnsiToUnicode(pdnsqry->m_qryport,&pwport,&wportsize);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	memset(&pdnsqry->m_hints,0,sizeof(pdnsqry->m_hints));
	pdnsqry->m_hints.ai_family  = pdnsqry->m_aftype;
	pdnsqry->m_hints.ai_socktype  = SOCK_STREAM;
	pdnsqry->m_hints.ai_protocol  = IPPROTO_TCP;

	pdnsqry->m_startticks = get_current_ticks();
	dret = GetAddrInfoExW(pwip,pwport,NS_DNS,NULL,&pdnsqry->m_hints,&pdnsqry->m_infores,NULL,
			&pdnsqry->m_ov,dns_query_callback,&pdnsqry->m_cancelevt);
	if (dret == 0) {
		ret = __fill_dns_result(pdnsqry);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else {
		if (dret != WSA_IO_PENDING) {
			WSA_GETERRNO(ret);
			goto fail;
		}
	}



	AnsiToUnicode(NULL,&pwport,&wportsize);
	AnsiToUnicode(NULL,&pwip,&wipsize);

	return completed;
fail:
	AnsiToUnicode(NULL,&pwport,&wportsize);
	AnsiToUnicode(NULL,&pwip,&wipsize);
	SETERRNO(ret);
	return ret;
}