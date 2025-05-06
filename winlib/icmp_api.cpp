#include <icmp_inner.h>
#include <icmp_api.h>
#include <win_err.h>
#include <win_output_debug.h>

#define  ICMP_HDR_MAGIC   0x779292a

typedef struct __icmp_sock {
	uint32_t m_magic;
	int m_icmptype;	
	SOCKET m_sock;
	WSAOVERLAPPED m_sndov;
	WSAOVERLAPPED m_rcvov;
	int m_insnd;
	int m_inrcv;
	uint64_t m_ticks;
	int m_indent;
	int m_seq;
	uint8_t m_sndbuf[256];
	uint8_t m_rcvbuf[256];
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

		if (psock->m_sndov.hEvent != NULL) {
			CloseHandle(psock->m_sndov.hEvent);
		}
		psock->m_sndov.hEvent = NULL;

		if (psock->m_rcvov.hEvent != NULL) {
			CloseHandle(psock->m_rcvov.hEvent);
		}
		psock->m_rcvov.hEvent = NULL;

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
	psock->m_indent = 0;
	psock->m_seq = 0;
	psock->m_inrcv = 0;
	psock->m_insnd = 0;

	if (type == AF_INET) {
		proto = IPPROTO_ICMP;
	} else if (type == AF_INET6) {
		proto = IPPROTO_ICMP6;
	} else {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	psock->m_sock = WSASocket(type , SOCK_RAW, proto,NULL,0,WSA_FLAG_OVERLAPPED);
	if (psock->m_sock == INVALID_SOCKET) {
		GETERRNO(ret);
		ERROR_INFO("proto [%d] error %d", proto, ret);
		goto fail;
	}

	psock->m_sndov.hEvent = WSACreateEvent();
	if (psock->m_sndov.hEvent == WSA_INVALID_EVENT) {
		GETERRNO(ret);
		psock->m_sndov.hEvent = NULL;
		ERROR_INFO("cannot create snd sock event %d", ret);
		goto fail;
	}

	psock->m_rcvov.hEvent = WSACreateEvent();
	if (psock->m_rcvov.hEvent == WSA_INVALID_EVENT) {
		GETERRNO(ret);
		psock->m_rcvov.hEvent = NULL;
		ERROR_INFO("cannot create rcv sock event %d", ret);
		goto fail;		
	}

	return psock;
fail:
	__free_icmp_sock(&psock);
	SETERRNO(ret);
	return NULL;
}

int __get_sock_addr(const char* ip, const char* port,int sockfamily,struct sockaddr* paddr,addrlen_t addrlen)
{
	struct addrinfo hints;
	struct addrinfo* pres=NULL;
	int retlen=0;
	memset(&hints,0,sizeof(hints));
	hints.ai_flags = (ip == NULL ? AI_PASSIVE : 0);
	hints.ai_family = sockfamily;
	hints.ai_type = SOCK_RAW;
	hints.ai_protocol = 0;

	ret = getaddrinfo(ip,port,&hints,&pres);
	if (ret != 0) {
		if (ret > 0) {
			ret = -ret;	
		}
		ERROR_INFO("getaddrinfo error [%d]", ret);		
		goto fail;
	}

	if (pres == NULL) {
		ret = -WSAEINVAL;
		goto fail;
	}

	retlen = pres->ai_addrlen;

	if (retlen > addrlen) {
		ret = -ERROR_INSUFFICIENT_BUFFER;
		goto fail;
	}
	memcpy(sockaddr,pres->ai_addr,retlen);
	freeaddrinfo(pres);
	return retlen;
fail:
	if (pres) {
		freeaddrinfo(pres);
	}
	pres = NULL;
	SETERRNO(ret);
	return ret;
}

int __bind_icmp_sock(PICMP_SOCK_t psock)
{
	int ret;
	struct sockaddr saddr;
	addrlen_t addrlen;

	ret = __get_sock_addr(NULL,"0",psock->m_icmptype,&saddr,sizeof(saddr));
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	addrlen = ret;


	ret = bind(psock->m_sock,&saddr,addrlen);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("bind  error [%d]", ret);
		goto fail;
	}

	return 0;
fail:
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


unsigned short __icmp_checksum(uint8_t* pbuf, int bufsize)
{
	unsigned int chksum=0;
	unsigned int carray = 0;
	unsigned int curval;
	int leftsize =bufsize;
	uint8_t* pcur= (uint8_t*) pbuf;

	while(leftsize > 0) {
		if (leftsize == 1) {
			curval = *pcur;
			pcur ++;
			chksum += (curval << 8);
			leftsize -= 1;
			break;
		}

		curval = *pcur;
		curval <<= 8;
		pcur ++;
		curval += *pcur;
		pcur ++;
		chksum += curval;

		leftsize -= 2;
	}

	carray = chksum >> 16;
	while(carray != 0) {
		chksum = (chksum & 0xffff) + carray;
		carray = chksum >> 16;
	}

	chksum = ~chksum;


	return (chksum & 0xffff);
}

int __format_icmp_request(PICMP_SOCK_t psock,uint64_t val,int indent, int seq,uint8_t* pbuf,int bufsize)
{
	ICMP_HDR* picmphdr;
	ICMPV6_HDR* picmp6hdr;
	ICMPV6_ECHO_REQUEST* p6echo;
	uint8_t* pcur;

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
		picmphdr = (ICMP_HDR*) pbuf;
		picmphdr->icmp_type = ICMPV4_ECHO_REQUEST_TYPE;
		picmphdr->icmp_code = ICMPV4_ECHO_REQUEST_CODE;
		picmphdr->icmp_checksum = 0;
		picmphdr->icmp_id = htons(indent);
		picmphdr->icmp_sequence = seq;
		pcur = pbuf + sizeof(*picmphdr);
		memcpy(pcur,&val,sizeof(uint64_t));
		picmphdr->icmp_checksum = htons(__icmp_checksum(pbuf,maxsize));

	} else if (psock->m_icmptype == AF_INET6) {
		picmp6hdr = (ICMPV6_HDR*) pbuf;
		picmp6hdr->icmp6_type = ICMPV6_ECHO_REQUEST_TYPE;
		picmp6hdr->icmp6_code = ICMPV6_ECHO_REQUEST_CODE;
		picmp6hdr->icmp6_checksum = 0;
		p6echo = (ICMPV6_ECHO_REQUEST*) (pbuf + sizeof(*picmp6hdr));
		p6echo->icmp6_echo_id = htons(indent);
		p6echo->icmp6_echo_sequence = seq;
		pcur = pbuf + sizeof(*picmp6hdr) + sizeof(*p6echo);
		memcpy(pcur,&val,sizeof(uint64_t));
		picmp6hdr->icmp6_checksum = htons(__icmp_checksum(pbuf,maxsize));
	}

	return maxsize;
fail:
	SETERRNO(ret);
	return ret;
}


int send_icmp_request(void* psock1,const char* ip,uint64_t val)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t)psock1;
	int ret;
	WSABUF sndbuf;
	if (psock == NULL || psock->m_magic != ICMP_HDR_MAGIC) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_insnd != 0) {
		ret = -ERROR_BUSY;
		SETERRNO(ret);
		return ret;
	}

	psock->m_indent += 1;
	psock->m_seq += 1;
	ret = __format_icmp_request(psock,val,psock->m_indent, psock->m_seq,psock->m_sndbuf,sizeof(psock->m_sndbuf));
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	sndsize = ret;
	sndbuf.len = sndsize;
	sndbuf.buf = psock->m_sndbuf;
	ret = WSASendTo(psock->m_sock,&sndbuf,)


}
