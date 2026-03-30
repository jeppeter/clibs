//#define _GNU_SOURCE

#include <ux_dns.h>
#include <ux_output_debug.h>
#include <ux_err.h>
#include <ux_time_op.h>
#include <ux_strop.h>

#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/eventfd.h>

#define  UX_DNS_QUERY_MAGIC   0xace0782a

typedef struct __dns_query {
	uint32_t m_magic;
	int m_evtfd;
	int m_aftype;
	struct gaicb* m_gai;
	struct sigevent* m_sigev;
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
		if (pqry->m_exited == 0) {
			cnt = 0;
			while(1) {
				ret = gai_cancel(pqry->m_gai);
				if (ret == EAI_ALLDONE || ret == EAI_CANCELED)	 {
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
				free((void*)pqry->m_gai->ar_request);
			}
			pqry->m_gai->ar_request = NULL;

			if (pqry->m_gai->ar_name) {
				free((void*)pqry->m_gai->ar_name);
			}
			pqry->m_gai->ar_name = NULL;

			if (pqry->m_gai->ar_service) {
				free((void*)pqry->m_gai->ar_service);
			}
			pqry->m_gai->ar_service = NULL;

			free(pqry->m_gai);
		}
		pqry->m_gai = NULL;

		if (pqry->m_sigev) {
			free(pqry->m_sigev);
		}
		pqry->m_sigev = NULL;

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
	int ret;

	pqry = (PDNS_QUERY_t) malloc(sizeof(*pqry));
	if (pqry == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pqry,0,sizeof(*pqry));
	pqry->m_exited = 1;
	pqry->m_errorcode = 0;
	pqry->m_magic = UX_DNS_QUERY_MAGIC;
	pqry->m_evtfd = -1;
	pqry->m_aftype = aftype;
	pqry->m_gai  = NULL;
	pqry->m_sigev = NULL;
	pqry->m_name = NULL;

	return pqry;
fail:
	__free_dns_query(&pqry);
	SETERRNO(ret);
	return NULL;
}

void __dns_query_callback(union sigval context)
{
	PDNS_QUERY_t pqry = (PDNS_QUERY_t)context.sival_ptr;
	int ret;
	if (pqry->m_magic != UX_DNS_QUERY_MAGIC) {
		ERROR_INFO("magic 0x%x != 0x%x", pqry->m_magic, UX_DNS_QUERY_MAGIC);
		return;
	}

	if (pqry->m_gai == NULL) {
		ERROR_INFO("no m_gai allocate");
		return;
	}

	ret = gai_error(pqry->m_gai);

	if (ret == EAI_INPROGRESS) {
		DEBUG_INFO("[%s] in progress",pqry->m_name);
		return;
	}

	if (ret != 0) {
		pqry->m_errorcode = ret;
	} else {
		pqry->m_errorcode = 0;
	}
	/*now we should give the code*/

	pqry->m_exited = 1;
	eventfd_write(pqry->m_evtfd,1);
	return;
}

void* start_dns_query(int aftype,const char* name, char* portstr)
{
	PDNS_QUERY_t pqry = NULL;
	int ret;
	char* pstr= NULL;
	int size = 0;
	int res=0;
	struct addrinfo* info=NULL;

	if (name == NULL || (
		aftype != AF_INET && aftype != AF_INET6)) {
		ret = -EINVAL;
		SETERRNO(ret);
		return NULL;
	}

	pqry = __alloc_dns_query(aftype);
	if (pqry == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	pqry->m_evtfd = eventfd(0,EFD_NONBLOCK | EFD_CLOEXEC);
	if (pqry->m_evtfd < 0) {
		GETERRNO(ret);
		ERROR_INFO("eventfd error %d", ret);
		goto fail;
	}

	if (portstr != NULL) {
		ret = snprintf_safe(&pstr,&size,"%s,%s", name, portstr);	
	} else {
		ret = snprintf_safe(&pstr,&size,"%s", name);
	}
	
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	pqry->m_name = strdup(pstr);
	if (pqry->m_name == NULL) {
			GETERRNO(ret);
			goto fail;
	}

	pqry->m_gai = (struct gaicb*)malloc(sizeof(*pqry->m_gai));
	if (pqry->m_gai == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pqry->m_gai, 0, sizeof(*pqry->m_gai));
	pqry->m_gai->ar_name = strdup(name);
	if (pqry->m_gai->ar_name == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	if (portstr != NULL) {
		pqry->m_gai->ar_service = strdup(portstr);
		if (pqry->m_gai->ar_service == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	info = (struct addrinfo*)malloc(sizeof(*info));
	if (info == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	pqry->m_gai->ar_request = info;

	/*result is NULL*/
	pqry->m_gai->ar_result = NULL;

	memset((void*)info, 0 ,sizeof(*info));
	info->ai_family = aftype;
	info->ai_protocol = IPPROTO_TCP;
	info->ai_socktype = SOCK_STREAM;

	pqry->m_sigev = (struct sigevent*) malloc(sizeof(*pqry->m_sigev));
	if (pqry->m_sigev == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pqry->m_sigev, 0, sizeof(*pqry->m_sigev));
	pqry->m_sigev->sigev_notify = SIGEV_THREAD;
	pqry->m_sigev->sigev_value.sival_ptr = pqry;
	pqry->m_sigev->sigev_notify_function = __dns_query_callback;

	pqry->m_exited = 0;
	res = getaddrinfo_a(GAI_NOWAIT,&pqry->m_gai,1,pqry->m_sigev);
	if (res != 0) {
		GETERRNO(ret);
		pqry->m_exited = 1;
		ERROR_INFO("getaddrinfo_a[%s] error %d:%d",pqry->m_name, res,ret);
		goto fail;
	}

	snprintf_safe(&pstr,&size,NULL);
	return pqry;
fail:
	snprintf_safe(&pstr,&size,NULL);
	__free_dns_query(&pqry);
	SETERRNO(ret);
	return NULL;
}

void free_dns_query(void** ppdnsqry)
{
	PDNS_QUERY_t pqry;
	if (ppdnsqry && *ppdnsqry) {
		pqry = (PDNS_QUERY_t)*ppdnsqry;
		if (pqry->m_magic != UX_DNS_QUERY_MAGIC) {
			ERROR_INFO("0x%x != 0x%x", pqry->m_magic, UX_DNS_QUERY_MAGIC);
		}
		__free_dns_query(&pqry);
		*ppdnsqry = NULL;
	}
	return;
}

int is_dns_query_completed(void* pdnsqry)
{
	PDNS_QUERY_t pqry = (PDNS_QUERY_t) pdnsqry;
	int ret = 0;
	if (pqry->m_magic == UX_DNS_QUERY_MAGIC) {
		if (pqry->m_exited != 0 && pqry->m_gai != NULL) {
			ret = 1;
		}
	}
	return ret;
}

int dns_query_get_complete_evt(void* pdnsqry)
{
	int fd = -1;
	PDNS_QUERY_t pqry = (PDNS_QUERY_t) pdnsqry;
	if (pqry->m_magic == UX_DNS_QUERY_MAGIC) {
		if (pqry->m_exited == 0) {
			fd = pqry->m_evtfd;
		}
	}
	return fd;
}

int dns_query_get_result(void* pdnsqry,int idx,char** ppstr, int *psize)
{
	int ret = 0;
	int res;
	int cnt = 0;
	PDNS_QUERY_t pqry = (PDNS_QUERY_t) pdnsqry;
	const char* pret = NULL;
	char* buffer= NULL;
	int bsize = 4;
	struct sockaddr_in* paddr= NULL;
	struct sockaddr_in6* paddr6 = NULL;

	if (pqry == NULL || idx < 0) {
		snprintf_safe(ppstr,psize,NULL);
		return 0;
	}


	if (pqry->m_magic == UX_DNS_QUERY_MAGIC && pqry->m_exited != 0) {
		struct addrinfo* curinfo;
		if (pqry->m_gai->ar_result != NULL) {
			curinfo = pqry->m_gai->ar_result;
			while(curinfo != NULL) {
				if (cnt == idx) {
					while(1) {
						if (buffer) {
							free(buffer);
						}
						buffer = NULL;
						buffer = (char*)malloc(bsize);
						if (buffer == NULL) {
							GETERRNO(ret);
							goto fail;
						}
						memset(buffer,0,bsize);
						if (curinfo->ai_addr->sa_family == pqry->m_aftype) {
							if (pqry->m_aftype == AF_INET) {
								paddr = (struct sockaddr_in*) curinfo->ai_addr;
								//DEBUG_BUFFER_FMT(paddr,sizeof(*paddr), "ai_addr AF_INET");
								pret = inet_ntop(pqry->m_aftype,&(paddr->sin_addr),buffer,bsize);
							} else {
								paddr6 = (struct sockaddr_in6*) curinfo->ai_addr;
								//DEBUG_BUFFER_FMT(paddr6,sizeof(*paddr6), "ai_addr AF_INET6");
								pret = inet_ntop(pqry->m_aftype,&(paddr6->sin6_addr),buffer,bsize);
							}
							if (pret != NULL) {
								//DEBUG_BUFFER_FMT(buffer,bsize,"to get size");
								res = snprintf_safe(ppstr,psize,"%s",pret);
								if (res < 0) {
									GETERRNO(ret);
									goto fail;
								}
								ret = 1;
								goto succ;
							}
							GETERRNO(res);
							if (res != -ENOSPC) {
								ret = res;
								ERROR_INFO("can not get buffer error %d", res);
								goto fail;
							}
							bsize <<= 1;
						} else {
							/*not matched ,so break;*/
							break;
						}						
					}					
				}

				curinfo = curinfo->ai_next;
				cnt += 1;
			}
		}
	}

succ:
	if (buffer) {
		free(buffer);
	}
	buffer = NULL;
	bsize = 0;
	SETERRNO(0);
	return ret;
fail:
	if (buffer) {
		free(buffer);
	}
	buffer = NULL;
	bsize = 0;
	SETERRNO(ret);
	return ret;
}

int dns_query_get_error_code(void* pdnsqry,int *perror)
{
	PDNS_QUERY_t pqry = (PDNS_QUERY_t) pdnsqry;
	int ret = 0;

	if (pqry != NULL && pqry->m_magic == UX_DNS_QUERY_MAGIC && perror != NULL && pqry->m_exited != 0) {
		*perror = pqry->m_errorcode;
		ret = 1;
	}
	return ret;

}