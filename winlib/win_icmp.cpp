#include <icmp_inner.h>
#include <win_icmp.h>
#include <win_err.h>
#include <win_output_debug.h>
#include <win_time.h>

#pragma warning(push)
#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif


#define  ICMP_HDR_MAGIC   0x779292a

typedef struct __icmp_sock {
	uint32_t m_magic;
	int m_icmptype;	
	SOCKET m_sock;
	struct sockaddr m_sndaddr;
	int m_saddrlen;
	struct sockaddr m_rcvaddr;
	int m_raddrlen;
	uint64_t m_sndticks;
	WSAOVERLAPPED m_sndov;
	WSAOVERLAPPED m_rcvov;
	int m_insnd;
	int m_inrcv;
	int m_sndcnt;
	int m_rcvlen;
	int m_rcvcomplete;
	int m_sndlen;
	int m_sndsize;
	int m_indent;
	int m_seq;
	int m_reserve1;
	uint64_t m_ticks;
	uint8_t m_sndbuf[2048];
	uint8_t m_rcvbuf[2048];
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
	int ret;

	psock= (PICMP_SOCK_t)malloc(sizeof(*psock));
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

int __get_sock_addr(const char* ip, const char* port,int sockfamily,struct sockaddr* paddr,DWORD addrlen)
{
	struct addrinfo hints;
	struct addrinfo* pres=NULL;
	int retlen=0;
	int ret;

	memset(&hints,0,sizeof(hints));
	hints.ai_flags = (ip == NULL ? AI_PASSIVE : 0);
	hints.ai_family = sockfamily;
	hints.ai_socktype = SOCK_RAW;
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

	retlen = (int)pres->ai_addrlen;

	if (retlen > (int)addrlen) {
		ret = -ERROR_INSUFFICIENT_BUFFER;
		goto fail;
	}
	memcpy(paddr,pres->ai_addr,(size_t)retlen);
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
	int addrlen;

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
	int ret;

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
		picmphdr->icmp_id = htons((unsigned short)indent);
		picmphdr->icmp_sequence = (unsigned short)seq;
		pcur = pbuf + sizeof(*picmphdr);
		memcpy(pcur,&val,sizeof(uint64_t));
		picmphdr->icmp_checksum = htons(__icmp_checksum(pbuf,maxsize));

	} else if (psock->m_icmptype == AF_INET6) {
		picmp6hdr = (ICMPV6_HDR*) pbuf;
		picmp6hdr->icmp6_type = ICMPV6_ECHO_REQUEST_TYPE;
		picmp6hdr->icmp6_code = ICMPV6_ECHO_REQUEST_CODE;
		picmp6hdr->icmp6_checksum = 0;
		p6echo = (ICMPV6_ECHO_REQUEST*) (pbuf + sizeof(*picmp6hdr));
		p6echo->icmp6_echo_id = htons((unsigned short)indent);
		p6echo->icmp6_echo_sequence = (unsigned short)seq;
		pcur = pbuf + sizeof(*picmp6hdr) + sizeof(*p6echo);
		memcpy(pcur,&val,sizeof(uint64_t));
		picmp6hdr->icmp6_checksum = htons(__icmp_checksum(pbuf,maxsize));
	}

	return maxsize;
fail:
	SETERRNO(ret);
	return ret;
}


int send_icmp_request(void* psock1,const char* ip)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t)psock1;
	int ret;
	WSABUF sndbuf;
	DWORD bytessend;
	DWORD flags = 0;
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

	ret = __get_sock_addr(ip,"0",psock->m_icmptype,&(psock->m_sndaddr),sizeof(psock->m_sndaddr));
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	psock->m_saddrlen = ret;

	psock->m_indent += 1;
	psock->m_seq += 1;
	psock->m_sndticks = get_current_ticks();
	DEBUG_INFO("m_sndticks 0x%llx %lld",psock->m_sndticks, psock->m_sndticks);
	ret = __format_icmp_request(psock,psock->m_sndticks,psock->m_indent, psock->m_seq,psock->m_sndbuf,sizeof(psock->m_sndbuf));
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sndsize = ret;
	psock->m_sndlen = 0;
	sndbuf.len = (ULONG)psock->m_sndsize;
	sndbuf.buf = (CHAR*)psock->m_sndbuf;
	psock->m_rcvcomplete = 0;
	ret = WSASendTo(psock->m_sock,&sndbuf,1,&bytessend,flags,&(psock->m_sndaddr),psock->m_saddrlen,&(psock->m_sndov),NULL);
	if (ret == SOCKET_ERROR) {
		if (WSAGetLastError() != WSA_IO_PENDING ) {
			ret = WSAGetLastError();
			if (ret > 0) {
				ret = -ret;
			}
			ERROR_INFO("to send buffer error %d", ret);
			goto fail;
		}
		psock->m_insnd = 1;
		psock->m_sndlen += bytessend;
	} else {
		psock->m_sndlen += bytessend;
		psock->m_sndcnt += 1;
		DEBUG_BUFFER_FMT(psock->m_sndbuf,psock->m_sndlen,"sndbuf");
	}

	return psock->m_insnd ? 0 : 1;
fail:
	SETERRNO(ret);
	return ret;
}

int icmp_is_read_mode(void* psock1)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t) psock1;
	int ret= 0;
	if (psock && psock->m_magic == ICMP_HDR_MAGIC && psock->m_inrcv) {
		ret = 1;
	}
	return ret;
}


int icmp_is_write_mode(void* psock1)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t) psock1;
	int ret= 0;
	if (psock && psock->m_magic == ICMP_HDR_MAGIC && psock->m_insnd) {
		ret = 1;
	}
	return ret;
}


HANDLE get_icmp_read_evt(void* psock1)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t) psock1;
	HANDLE hret = NULL;
	if (psock && psock->m_magic == ICMP_HDR_MAGIC && psock->m_inrcv) {
		hret = psock->m_rcvov.hEvent;
	}
	return hret;
}

HANDLE get_icmp_write_evt(void* psock1)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t) psock1;
	HANDLE hret = NULL;
	if (psock && psock->m_magic == ICMP_HDR_MAGIC && psock->m_insnd) {
		hret = psock->m_sndov.hEvent;
	}
	return hret;
}

int icmp_complete_read(void* psock1)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t) psock1;
	int ret;
	BOOL bret;
	DWORD dret;
	DWORD flags=0;
	if (psock == NULL || psock->m_magic != ICMP_HDR_MAGIC) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_inrcv == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	dret = 0;
	flags = 0;
	bret = WSAGetOverlappedResult(psock->m_sock,&(psock->m_rcvov),&dret,FALSE,&flags);
	if (!bret) {
		GETERRNO(ret);
		if (ret != -WSA_IO_INCOMPLETE) {
			goto fail;
		}
		DEBUG_INFO("WSA_IO_INCOMPLETE dret %ld", dret);
		psock->m_rcvlen += dret;
	} else {
		psock->m_inrcv = 0;
		psock->m_rcvlen += dret;
		DEBUG_BUFFER_FMT(psock->m_rcvbuf,psock->m_rcvlen,"rcvbuf");
		psock->m_rcvcomplete = 1;
	}
	
	return psock->m_inrcv ? 0 : 1;
fail:
	SETERRNO(ret);
	return ret;
}

int icmp_complete_write(void* psock1)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t) psock1;
	int ret;
	BOOL bret;
	DWORD dret;
	DWORD flags=0;
	if (psock == NULL || psock->m_magic != ICMP_HDR_MAGIC) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_insnd == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	dret = 0;
	flags = 0;
	bret = WSAGetOverlappedResult(psock->m_sock,&(psock->m_sndov),&dret,FALSE,&flags);
	if (!bret) {
		GETERRNO(ret);
		if (ret != -WSA_IO_INCOMPLETE) {
			goto fail;
		}
		psock->m_sndlen += dret;
	} else {
		psock->m_insnd = 0;
		psock->m_sndlen += dret;	
		psock->m_sndcnt += 1;
		DEBUG_BUFFER_FMT(psock->m_sndbuf,psock->m_sndlen,"sndbuf");
	}
	
	return psock->m_insnd ? 0 : 1;
fail:
	SETERRNO(ret);
	return ret;
}

int __filter_icmp_header(PICMP_SOCK_t psock,uint64_t* pval)
{
	ICMP_HDR* picmphdr= NULL;
	uint64_t* pbuf;

	if (psock->m_icmptype == AF_INET) {
		if (psock->m_rcvlen < (sizeof(IPV4_HDR) + 16)) {
			return 0;
		}
		picmphdr = (ICMP_HDR*) (psock->m_rcvbuf + sizeof(IPV4_HDR));
		if (picmphdr->icmp_type == ICMPV4_ECHO_REPLY_TYPE && picmphdr->icmp_code == ICMPV4_ECHO_REPLY_CODE) {
			pbuf = (uint64_t*) (psock->m_rcvbuf + sizeof(IPV4_HDR) + sizeof(ICMP_HDR));
			if (*pbuf == psock->m_sndticks && psock->m_indent == ntohs(picmphdr->icmp_id) && psock->m_seq == picmphdr->icmp_sequence) {
				DEBUG_BUFFER_FMT(psock->m_rcvbuf,psock->m_rcvlen, "rcvlen");
				*pval = *pbuf;
				return 1;
			}
		}
	}
	DEBUG_BUFFER_FMT(psock->m_rcvbuf,psock->m_rcvlen,"not valid rcvlen");
	return 0;

}

int recv_icmp_response(void* psock1,uint64_t* pval)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t)psock1;
	int ret;
	int completed = 0;
	WSABUF data;
	DWORD bytercv=0;
	DWORD flags=0;
	uint64_t curticks;
	if (psock == NULL || psock->m_magic != ICMP_HDR_MAGIC || pval == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_inrcv != 0) {
		/*that not used one*/
		return 0;
	}

	if (psock->m_rcvcomplete != 0) {
	get_complete_read:		
		ret = __filter_icmp_header(psock,pval);
		if (ret == 0) {
			goto read_again;
		}
		curticks = get_current_ticks();
		DEBUG_INFO("curticks %lld 0x%llx retval %lld 0x%llx", curticks,curticks, psock->m_sndticks,psock->m_sndticks);
		*pval = curticks - psock->m_sndticks;
		psock->m_inrcv = 0;
		completed = 1;
	} else {
	read_again:
		memcpy(&(psock->m_rcvaddr),&(psock->m_sndaddr),(size_t)psock->m_saddrlen);
		psock->m_raddrlen = psock->m_saddrlen;
		data.len = sizeof(psock->m_rcvbuf);
		data.buf = (CHAR*)psock->m_rcvbuf;
		ret = WSARecvFrom(psock->m_sock,&data,1,&bytercv,&flags,&psock->m_rcvaddr,&psock->m_raddrlen,&psock->m_rcvov,NULL);
		if (ret == SOCKET_ERROR) {
			ret = WSAGetLastError();
			if (ret != WSA_IO_PENDING) {
				if (ret > 0) {
					ret = -ret;
				}
				ERROR_INFO("receive error %d", ret);
				goto fail;
			}
			psock->m_inrcv = 1;
			DEBUG_INFO("inrcv = 1");
		} else {
			psock->m_rcvlen = (int)bytercv;
			goto get_complete_read;
		}
	}

	return psock->m_inrcv ? 0 : 1;
fail:
	SETERRNO(ret);
	return ret;
}

int icmp_send_cnt(void* psock1)
{
	PICMP_SOCK_t psock = (PICMP_SOCK_t)psock1;
	int retcnt = -1;
	if (psock!=NULL && psock->m_magic == ICMP_HDR_MAGIC) {
		retcnt = psock->m_sndcnt;
	}
	return retcnt;

}

#pragma warning(pop)