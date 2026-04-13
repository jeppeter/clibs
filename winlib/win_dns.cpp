#pragma warning(push)

#pragma warning(disable:4005)
#pragma warning(disable:4668)
#pragma warning(disable:4820)


#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mswsock.h>

#pragma warning(pop)


#include <win_dns.h>
#include <win_uniansi.h>
#include <win_time.h>
#include <win_sock.h>
#include <win_output_debug.h>
#include <stdlib.h>


#pragma warning(push)
#if defined(_MSC_VER)
#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif
#endif


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
	int m_error;
	int m_exited;
	int m_reserv1;
	uint64_t m_startticks;
	PADDRINFOEXW  m_infores;
	ADDRINFOEXW m_hints;
	WSAOVERLAPPED m_ov;
	HANDLE m_compevt;
	HANDLE m_cancelevt;
	HANDLE m_errevt;
} DNS_QUERY_t,*PDNS_QUERY_t;


void __free_dns_query_iparr(PDNS_QUERY_t pdnsqry)
{
	int i;

	for(i=0;pdnsqry->m_iparr != NULL && pdnsqry->m_iparr[i]!=NULL;i++) {
		free(pdnsqry->m_iparr[i]);
		pdnsqry->m_iparr[i] = NULL;
	}
	if (pdnsqry->m_iparr) {
		free(pdnsqry->m_iparr);
	}
	pdnsqry->m_iparr = NULL;
	pdnsqry->m_ipsize = 0;
	pdnsqry->m_iplen = 0;
	return ;
}

void __free_dns_query(PDNS_QUERY_t* ppdnsqry)
{
	if (ppdnsqry && *ppdnsqry) {
		int ret;
		PDNS_QUERY_t pdnsqry = *ppdnsqry;
		if (pdnsqry->m_magic != DNS_QUERY_HDR_MAGIC) {
			ERROR_INFO("not valid DNS_QUERY_HDR_MAGIC 0x%x", pdnsqry->m_magic);
		}

		if (pdnsqry->m_inprog != 0) {
			ret = GetAddrInfoExCancel(&pdnsqry->m_cancelevt);
			if (ret != NO_ERROR) {
				ERROR_INFO("GetAddrInfoExCancel error %d ",ret);
			}
			pdnsqry->m_inprog = 0;
		}

		if (pdnsqry->m_infores) {
			FreeAddrInfoExW(pdnsqry->m_infores);
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

		if (pdnsqry->m_errevt != NULL) {
			CloseHandle(pdnsqry->m_errevt);
		}
		pdnsqry->m_errevt = NULL;

		__free_dns_query_iparr(pdnsqry);
		if (pdnsqry->m_qryip) {
			free(pdnsqry->m_qryip);
		}
		pdnsqry->m_qryip= NULL;

		if (pdnsqry->m_qryport) {
			free(pdnsqry->m_qryport);
		}
		pdnsqry->m_qryport = NULL;

		pdnsqry->m_exited = 0;

		free(pdnsqry);
		*ppdnsqry = NULL;
	}
	return;
}

PDNS_QUERY_t __alloc_dns_query(int type,const char* name,const char* portstr)
{
	PDNS_QUERY_t pdnsqry = NULL;
	int ret;

	pdnsqry =(PDNS_QUERY_t) malloc(sizeof(*pdnsqry));
	if (pdnsqry == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	memset(pdnsqry,0,sizeof(*pdnsqry));
	pdnsqry->m_magic = DNS_QUERY_HDR_MAGIC;
	pdnsqry->m_aftype = type;
	pdnsqry->m_qryip = _strdup(name);
	if (portstr != NULL) {
		pdnsqry->m_qryport = _strdup(portstr);	
	} else {
		pdnsqry->m_qryport = _strdup("0");	
	}
	
	if (pdnsqry->m_qryip == NULL || pdnsqry->m_qryport == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
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

	pdnsqry->m_errevt = CreateEvent(NULL,TRUE,FALSE,NULL);
	if (pdnsqry->m_errevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("CreateEvent m_errevt error %d", ret);
		goto fail;
	}

	return pdnsqry;
fail:
	__free_dns_query(&pdnsqry);
	SETERRNO(ret);
	return NULL;
}

int __append_dns_value(PDNS_QUERY_t pdnsqry,char* pval)
{
	char** pptmp = NULL;
	int ret;
	if (pdnsqry->m_iparr == NULL || (pdnsqry->m_iplen+1) >= pdnsqry->m_ipsize ) {
		if (pdnsqry->m_ipsize == 0) {
			pdnsqry->m_ipsize = 4;
		} else {
			pdnsqry->m_ipsize <<= 1;
		}

		pptmp = (char**)malloc(sizeof(*pptmp) * pdnsqry->m_ipsize);
		if (pptmp == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(pptmp, 0, sizeof(*pptmp) * pdnsqry->m_ipsize);
		if (pdnsqry->m_iplen > 0) {
			memcpy(pptmp, pdnsqry->m_iparr, sizeof(*pptmp) * pdnsqry->m_iplen);
		}

		if (pdnsqry->m_iparr) {
			free(pdnsqry->m_iparr);
		}
		pdnsqry->m_iparr = pptmp;
		pptmp = NULL;
	}

	pdnsqry->m_iparr[pdnsqry->m_iplen] = _strdup(pval);
	if (pdnsqry->m_iparr[pdnsqry->m_iplen] == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	pdnsqry->m_iplen += 1;

	return pdnsqry->m_iplen;
fail:
	if (pptmp) {
		free(pptmp);
	}
	pptmp = NULL;
	SETERRNO(ret);
	return ret;
}

int __fill_dns_result(PDNS_QUERY_t pdnsqry)
{
	int ret;
	PADDRINFOEXW    pcurinfo=NULL;
	char* pstr = NULL;
	int size = 0;
	wchar_t* pwstr=NULL;
	int wsize=256;

	__free_dns_query_iparr(pdnsqry);

	if (pwstr) {
		free(pwstr);
	}
	pwstr = NULL;
	pwstr =(wchar_t*) malloc((size_t)wsize * sizeof(*pwstr));
	if (pwstr == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	/*now we should give */
	pcurinfo = pdnsqry->m_infores;
	while(pcurinfo != NULL) {
		if (pcurinfo->ai_family == pdnsqry->m_aftype) {
			memset(pwstr,0,(size_t)wsize * sizeof(*pwstr));
			DWORD dsize=(DWORD) wsize;
			ret = WSAAddressToStringW(pcurinfo->ai_addr,(DWORD) pcurinfo->ai_addrlen,NULL,pwstr,&dsize);
			if (ret == 0) {
				DEBUG_BUFFER_FMT(pwstr,dsize*sizeof(*pwstr),"pwstr get");
				ret = UnicodeToAnsi(pwstr,&pstr,&size);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO("ret %d",ret);
					goto fail;
				}

				ret = __append_dns_value(pdnsqry,pstr);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				DEBUG_INFO("m_iplen %d", pdnsqry->m_iplen);
			} else {
				ERROR_INFO("ret %d", ret);
				WSA_GETERRNO(ret);
				ERROR_INFO("ret %d", ret);
				if (ret == -WSAENOBUFS) {
					wsize <<= 1;
					if (pwstr) {
						free(pwstr);
					}
					pwstr = NULL;
					pwstr = (wchar_t*)malloc((size_t)wsize * sizeof(*pwstr));
					if (pwstr == NULL) {
						GETERRNO(ret);
						ERROR_INFO(" ");
						goto fail;
					}
					continue;
				}
				ERROR_INFO("WSAAddressToStringW error %d", ret);
				goto fail;
			}
		}

		pcurinfo = pcurinfo->ai_next;
	}

	UnicodeToAnsi(NULL,&pstr,&size);

	if (pwstr) {
		free(pwstr);
	}
	pwstr = NULL;
	wsize = 0;

	return pdnsqry->m_iplen;
fail:
	UnicodeToAnsi(NULL,&pstr,&size);

	if (pwstr) {
		free(pwstr);
	}
	pwstr = NULL;
	wsize = 0;

	SETERRNO(ret);
	return ret;
}


void WINAPI dns_query_callback(DWORD error,DWORD bytes,LPOVERLAPPED ov)
{
	PDNS_QUERY_t pdnsqry = NULL;
	int ret;

	bytes = bytes;
	pdnsqry = CONTAINING_RECORD(ov,DNS_QUERY_t,m_ov);
	if (error != ERROR_SUCCESS) {
		ERROR_INFO("error code %d", error);
		pdnsqry->m_inprog = 0;
		pdnsqry->m_error = 1;
		pdnsqry->m_exited = 1;
		SetEvent(pdnsqry->m_errevt);
		return;
	}

	DEBUG_INFO("dns_query_callback");

	ret = __fill_dns_result(pdnsqry);
	if (ret < 0) {
		GETERRNO(ret);
		pdnsqry->m_error = 1;
		pdnsqry->m_inprog = 0;
		pdnsqry->m_exited = 1;
		ERROR_INFO("__fill_dns_result error %d", ret);
		SetEvent(pdnsqry->m_errevt);
		SETERRNO(ret);
		return;
	}

	/*all is ok*/
	pdnsqry->m_inprog = 0;
	pdnsqry->m_error = 0;
	pdnsqry->m_exited = 1;
	SetEvent(pdnsqry->m_compevt);
	return;
}


int __start_query_dns(PDNS_QUERY_t pdnsqry)
{
	wchar_t* pwip=NULL,*pwport=NULL;
	int wipsize=0,wportsize=0;
	int ret,cret;
	int completed = 0;

	if (pdnsqry->m_qryip == NULL || pdnsqry->m_inprog != 0) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO(" ");
		SETERRNO(ret);
		return ret;
	}

	ret = AnsiToUnicode(pdnsqry->m_qryip,&pwip,&wipsize);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	if (pdnsqry->m_qryport != NULL) {
		ret = AnsiToUnicode(pdnsqry->m_qryport,&pwport,&wportsize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
	}

	memset(&pdnsqry->m_hints,0,sizeof(pdnsqry->m_hints));
	pdnsqry->m_hints.ai_family  = pdnsqry->m_aftype;
	pdnsqry->m_hints.ai_socktype  = SOCK_STREAM;
	pdnsqry->m_hints.ai_protocol  = IPPROTO_TCP;
	pdnsqry->m_exited = 0;

	pdnsqry->m_startticks = get_current_ticks();
	//cret = GetAddrInfoExW(pwip,pwport,NS_ALL,NULL,&pdnsqry->m_hints,&pdnsqry->m_infores,NULL,
	cret = GetAddrInfoExW(pwip,NULL,NS_ALL,NULL,&pdnsqry->m_hints,&pdnsqry->m_infores,NULL,
			&pdnsqry->m_ov,dns_query_callback,&pdnsqry->m_cancelevt);
	if (cret == 0) {
		DEBUG_INFO("call direct filled");
		ret = __fill_dns_result(pdnsqry);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
		pdnsqry->m_exited = 1;
	} else {
		if (cret != WSA_IO_PENDING && cret != ERROR_IO_PENDING) {
			WSA_GETERRNO(ret);
			ERROR_INFO("cret %d ret %d",cret,ret);
			goto fail;				
		} else {
			pdnsqry->m_inprog = 1;	
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

void* start_dns_query(int type,const char* name,const char* portstr)
{
	PDNS_QUERY_t pdnsqry=NULL;
	int ret;
	if (type != AF_INET && type != AF_INET6) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO(" ");
		SETERRNO(ret);
		return NULL;
	}

	if (name == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO(" ");
		SETERRNO(ret);
		return NULL;
	}

	pdnsqry = __alloc_dns_query(type,name,portstr);
	if (pdnsqry == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		SETERRNO(ret);
		return NULL;
	}


	ret = __start_query_dns(pdnsqry);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	return pdnsqry;
fail:
	__free_dns_query(&pdnsqry);
	SETERRNO(ret);
	return NULL;
}

void free_dns_query(void** ppdnsqry1)
{
	PDNS_QUERY_t* ppdnsqry = (PDNS_QUERY_t*) ppdnsqry1;
	__free_dns_query(ppdnsqry);
	return;
}

int dns_query_time_left(void* pdnsqry1,int timeout)
{
	PDNS_QUERY_t pdnsqry = (PDNS_QUERY_t) pdnsqry1;
	int ret = -1;
	uint64_t cticks = 0;

	if (pdnsqry->m_magic != DNS_QUERY_HDR_MAGIC) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (pdnsqry->m_inprog == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	cticks = get_current_ticks();
	DEBUG_INFO("m_startticks 0x%llx cticks 0x%llx timeout %d", pdnsqry->m_startticks,cticks, timeout);
	return need_wait_times(pdnsqry->m_startticks,cticks,timeout);
}

HANDLE dns_query_get_error_evt(void* pdnsqry1)
{
	HANDLE hret = NULL;
	PDNS_QUERY_t pdnsqry = (PDNS_QUERY_t) pdnsqry1;

	if (pdnsqry->m_magic == DNS_QUERY_HDR_MAGIC) {
		hret = pdnsqry->m_errevt;
	}
	return hret;
}

HANDLE dns_query_get_complete_evt(void* pdnsqry1)
{
	HANDLE hret = NULL;
	PDNS_QUERY_t pdnsqry = (PDNS_QUERY_t) pdnsqry1;

	if (pdnsqry->m_magic == DNS_QUERY_HDR_MAGIC) {
		hret = pdnsqry->m_compevt;
	}
	return hret;
}


int dns_query_get_result(void* pdnsqry1,int idx,char** ppstr, int *psize)
{
	PDNS_QUERY_t pdnsqry = (PDNS_QUERY_t) pdnsqry1;
	int ret;
	int slen;
	char* pretstr = NULL;
	int retsize=0;


	if (pdnsqry == NULL || idx < 0) {
		if (ppstr && *ppstr) {
			free((void*)(*ppstr));
			*ppstr = NULL;
		}

		if (psize) {
			*psize = 0;
		}
		return 0;
	}


	if (pdnsqry->m_magic != DNS_QUERY_HDR_MAGIC) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (pdnsqry->m_exited == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	if (ppstr == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pretstr = *ppstr;
	retsize = *psize;


	if (idx >= pdnsqry->m_iplen) {
		return 0;
	}

	slen = (int)strlen(pdnsqry->m_iparr[idx]);
	if (slen >= retsize) {
		retsize = slen + 1;
		pretstr = (char*)malloc((size_t)retsize);
		if (pretstr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	memset(pretstr, 0, (size_t)retsize);
	memcpy(pretstr, pdnsqry->m_iparr[idx], (size_t)slen);

	if (*ppstr && *ppstr != pretstr) {
		free(*ppstr);
	}
	*ppstr = pretstr;
	*psize = retsize;

	return slen;
fail:
	if (pretstr && pretstr != *ppstr) {
		free(pretstr);
	}
	pretstr = NULL;
	SETERRNO(ret);
	return ret;
}


int is_dns_query_completed(void* pdnsqry1)
{
	PDNS_QUERY_t pdnsqry = (PDNS_QUERY_t) pdnsqry1;
	int ret = 0;
	if (pdnsqry == NULL || pdnsqry->m_magic != DNS_QUERY_HDR_MAGIC) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (pdnsqry->m_exited == 0) {
		return 0;
	}

	return 1;
}

int is_dns_query_error(void* pdnsqry1)
{
	PDNS_QUERY_t pdnsqry = (PDNS_QUERY_t) pdnsqry1;
	int ret =0;
	if (pdnsqry != NULL && pdnsqry->m_magic == DNS_QUERY_HDR_MAGIC) {
		if (pdnsqry->m_error != 0) {
			ret = 1;
		}
	}
	return ret;
}

#pragma warning(pop)