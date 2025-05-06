#include <icmp_inner.h>
#include <icmp_api.h>
#include <win_err.h>
#include <win_output_debug.h>

#define  ICMP_HDR_MAGIC   0x779292a

typedef struct __icmp_sock {
	uint32_t m_magic;
	int m_icmptype;	
	SOCKET m_sock;
	WSAOVERLAPPED m_ov;
	uint64_t m_ticks;
} ICMP_SOCK_t,*PICMP_SOCK_t;

void __free_icmp_sock(PICMP_SOCK_t* ppsock)
{
	if (ppsock && *ppsock) {
		PICMP_SOCK_t psock = *ppsock;

		if (psock->m_magic != ICMP_HDR_MAGIC) {
			ERROR_INFO("not magic 0x%x != 0x%x",psock->m_magic,ICMP_HDR_MAGIC);
		}

		if (psock->m_sock != INVALID_SOCKET) {
			closesocket(psock->m_sock);
		}
		psock->m_sock = INVALID_SOCKET;

		free(psock);
		*ppsock = NULL;
	}
}


PICMP_SOCK_t __alloc_sock(int type)
{
	PICMP_SOCK_t psock = NULL;
	int proto = IPPROTO_ICMP;

	psock= malloc(sizeof(*psock));
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(psock, 0, sizeof(*psock));
	psock->m_magic = ICMP_HDR_MAGIC;
	psock->m_sock = INVALID_SOCKET;
	psock->m_icmptype = type;

	if (type == AF_INET) {
		proto = IPPROTO_ICMP;
	} else if (type == AF_INET6) {
		proto = IPPROTO_ICMP6;
	} else {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	psock->m_sock = socket(type , SOCK_RAW, proto);
	if (psock->m_sock == INVALID_SOCKET) {
		GETERRNO(ret);
		ERROR_INFO("proto [%d] error %d", proto, ret);
		goto fail;
	}

	return psock;
fail:
	__free_icmp_sock(&psock);
	SETERRNO(ret);
	return NULL;
}

int __bind_icmp_sock(PICMP_SOCK_t psock)
{
	struct addrinfo *pres=NULL;
	struct addrinfo hints;
	int ret;

	memset(&hints,0,sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = psock->m_icmptype;
	hints.ai_type = SOCK_RAW;
	hints.ai_protocol = 0;

	ret = getaddrinfo(NULL,"0",&hints,&pres);
	if (ret != 0) {
		if (ret > 0) {
			ret = -ret;	
		}
		ERROR_INFO("getaddrinfo error [%d]", ret);		
		goto fail;
	}

	if (pres == NULL) {
		ret = -WSAEINVAL;
		ERROR_INFO("getaddrinfo pres NULL");
		goto fail;
	}

	ret = bind(psock->m_sock,pres->ai_addr,(int)pres->ai_addrlen);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("bind  error [%d]", ret);
		goto fail;
	}

	if (pres != NULL) {
		freeaddrinfo(pres);
	}
	pres =  NULL;
	return 0;
fail:
	if (pres != NULL) {
		freeaddrinfo(pres);
	}
	pres =  NULL;
	SETERRNO(ret);
	return ret;
}

void* init_icmp_sock(int type)
{
	PICMP_SOCK_t psock = NULL;
	int ret;

	psock = __alloc_sock(type);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __bind_icmp_sock(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return psock;
fail:
	__free_icmp_sock(&psock);
	SETERRNO(ret);
	return NULL;
}


void free_icmp_sock(void** ppsock1)
{
	PICMP_SOCK_t* ppsock = (PICMP_SOCK_t*) ppsock1;
	__free_icmp_sock(ppsock);
	return;
}

int __format_icmp_request(PICMP_SOCK_t psock,uint64_t val,uint8_t* pbuf,int bufsize)
{
	PICMP_HDR picmphdr = (PICMP_HDR) pbuf;
	int maxsize = 0;
	if (psock->m_icmptype == AF_INET) {
		maxsize = sizeof(ICMP_HDR) + sizeof(uint64_t);
	} else if (psock->m_icmptype == AF_INET6) {
		maxsize = sizeof(ICMPV6_HDR) + sizeof(ICMPV6_ECHO_REQUEST) + sizeof(uint64_t);
	} else {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	if (bufsize < maxsize) {
		ret = -ERROR_INSUFFICIENT_BUFFER;
		goto fail;
	}

	if (psock->m_icmptype == AF_INET) {
		picmphdr = (PICMP_HDR) pbuf;
		picmphdr->
	} else if (psock->m_icmptype == AF_INET6) {
		picmp6hdr = (ICMPV6_HDR*) pbuf;
	}

}


int send_icmp_request(void* psock1,const char* ip,uint64_t val)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t)psock1;
	int ret;
	if (psock == NULL || psock->m_magic != ICMP_HDR_MAGIC) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}
}
