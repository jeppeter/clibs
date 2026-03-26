#include <ux_dns.h>

#define  UX_DNS_QUERY_MAGIC   0xace0782a

typedef struct __dns_query {
	uint32_t m_magic;
	int m_evtfd;
	int m_aftype;
	struct gaicb* m_gai;
	char* m_name;
	int m_exited;
	int m_errorcode;
} DNS_QUERY_t,*PDNS_QUERY_t;


void __free_dns_query(PDNS_QUERY_t* ppqry)
{
	if (ppqry && *ppqry) {
		int ret;
		int cnt=0;
		PDNS_QUERY_t pqry = *ppqry;
		if (ppqry->m_exited == 0) {
			cnt = 0;
			while(1) {
				ret = gai_cancel(pqry->m_gai);
				if (ret == EAI_ALLDONE || ret == EAI_CANCELLED)	 {
					break;
				}
				sched_out(1);
				cnt ++;
				if ((cnt % 20) == 0) {
					ERROR_INFO("cancel [%s] error %d", pqry->m_name, ret);
				}
			}
			pqry->m_exited = 1;			
		}

		if (pqry->m_gai != NULL) {
			if (pqry->m_gai->ar_result) {
				freeaddrinfo(pqry->m_gai->ar_result);
			}
			pqry->m_gai->ar_result = NULL;

			if (pqry->m_gai->ar_request) {
				free(pqry->m_gai->ar_request);
			}
			pqry->m_gai->ar_request = NULL;

			if (pqry->m_gai->ar_name) {
				free(pqry->m_gai->ar_name);
			}
			pqry->m_gai->ar_name = NULL;

			if (pqry->m_gai->ar_service) {
				free(pqry->m_gai->ar_service);
			}
			pqry->m_gai->ar_service = NULL;

			free(pqry->m_gai);
		}
		pqry->m_gai = NULL;

		if (pqry->m_name) {
			free(pqry->m_name);
		}
		pqry->m_name = NULL;

		if (pqry->m_evtfd >= 0) {
			close(pqry->m_evtfd);
		}
		pqry->m_evtfd = -1;

		pqry->m_magic = 0;
		pqry->m_errorcode = 0;

		free(pqry);
		*ppqry = NULL;
	}
	return;
}

PDNS_QUERY_t __alloc_dns_query(int aftype)
{
	PDNS_QUERY_t pqry = NULL;

	pqry = (PDNS_QUERY_t) malloc(sizeof(*pqry));
	if (pqry == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pqry,0,sizeof(*pqry));
	pqry->m_exited = 1;
	pqry->m_magic = UX_DNS_QUERY_MAGIC;
	

	return pqry;
fail:
	__free_dns_query(&pqry);
	SETERRNO(ret);
	return NULL;
}