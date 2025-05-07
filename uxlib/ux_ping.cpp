#include <ux_ping.h>
#include <ux_output_debug.h>
#include <ux_time_op.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#define  PING_HDR_MAGIC   0x779292a


typedef struct __ping_sock {
	uint32_t m_magic;
	int m_pingtype;	
	int m_sock;
	struct sockaddr *m_sndaddr;
	struct sockaddr *m_rcvaddr;
	int m_saddrlen;
	int m_raddrlen;
	uint64_t m_sndticks;
	char* m_ipname;
	int m_insnd;
	int m_inrcv;
	int m_sndcnt;
	int m_rcvlen;
	int m_rcvcomplete;
	int m_sndlen;
	int m_sndsize;
	int m_indent;
	int m_seq;
	uint8_t m_sndbuf[2048];
	uint8_t m_rcvbuf[2048];	
} ping_sock_t,*pping_sock_t;

void __free_ping_sock(pping_sock_t* ppsock)
{
	if (ppsock && *ppsock) {
		pping_sock_t psock = *ppsock;
		if (psock->m_sock >= 0) {
			close(psock->m_sock);
		}
		psock->m_sock = -1;
		if (psock->m_sndaddr) {
			free(psock->m_sndaddr);
		}
		psock->m_sndaddr = NULL;
		psock->m_saddrlen = 0;

		if (psock->m_rcvaddr) {
			free(psock->m_rcvaddr);
		}
		psock->m_rcvaddr = NULL;

		if (psock->m_ipname) {
			free(psock->m_ipname);
		}
		psock->m_ipname = NULL;

		psock->m_inrcv = 0;
		psock->m_insnd = 0;

		free(psock);
		*ppsock = NULL;
	}
	return;
}

void free_ping_sock(void** ppsock1)
{
	pping_sock_t *ppsock = (pping_sock_t*) ppsock1;
	if (ppsock && *ppsock && (*ppsock)->m_magic == PING_HDR_MAGIC) {
		__free_ping_sock(ppsock);
	}
	return;
}

pping_sock_t __alloc_ping_sock(int type)
{
	int ret;
	pping_sock_t psock = NULL;
	int proto = 0;
	int mode;
	psock = (pping_sock_t)malloc(sizeof(*psock));
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(psock, 0, sizeof(*psock));
	psock->m_magic = PING_HDR_MAGIC;
	psock->m_sock = -1;
	psock->m_pingtype = type;
	psock->m_indent = 0;
	psock->m_seq = 0;
	psock->m_inrcv = 0;
	psock->m_insnd = 0;

	if (type == AF_INET) {
		DEBUG_INFO("type AF_INET proto IPPROTO_ICMP");
		proto = IPPROTO_ICMP;
	} else if (type == AF_INET6) {
		DEBUG_INFO("type AF_INET6 proto IPPROTO_ICMPV6");
		proto = IPPROTO_ICMPV6;
	} else {
		ret = -EINVAL;
		goto fail;
	}

	psock->m_sock = socket(type,SOCK_RAW,proto);
	if (psock->m_sock < 0) {
		GETERRNO(ret);
		ERROR_INFO("socket %d error %d", type, ret);
		goto fail;
	}

	mode = fcntl(psock->m_sock,F_GETFL,0);
	ret = fcntl(psock->m_sock, F_SETFL, mode|O_NONBLOCK);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("O_NONBLOCK error %d", ret);
		goto fail;
	}


	return psock;
fail:
	__free_ping_sock(&psock);
	SETERRNO(ret);
	return NULL;
}

int __get_addr_info(const char* ip, const char* port,int sockfamily,struct sockaddr *saddr ,int addrlen)
{
	struct addrinfo hints;
	struct addrinfo* pres= NULL;
	int retlen;
	int ret;

	memset(&hints,0, sizeof(hints));
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
		ret = -EINVAL;
		goto fail;
	}

	retlen = (int)pres->ai_addrlen;
	if (retlen > addrlen) {
		ret = -ENOBUFS;
		goto fail;
	}

	memcpy(saddr,pres->ai_addr, retlen);

	if (pres) {
		freeaddrinfo(pres);
	}
	pres = NULL;

	return retlen;
fail:
	if (pres) {
		freeaddrinfo(pres);
	}
	pres = NULL;
	SETERRNO(ret);
	return ret;
}

int __bind_local_sock(pping_sock_t psock)
{
	int ret;
	struct sockaddr* saddr = NULL;
	int addrlen = 0;
	ASSERT_IF(psock->m_sock >= 0);
	addrlen = sizeof(*saddr);
get_again:
	if (saddr) {
		free(saddr);
	}
	saddr = NULL;
	saddr = (struct sockaddr*)malloc(addrlen);
	if (saddr == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret=  __get_addr_info(NULL,"0",psock->m_pingtype,saddr,addrlen);
	if (ret < 0) {
		GETERRNO(ret);
		if (ret == -ENOBUFS) {
			addrlen <<= 1;
			goto get_again;
		}
		goto fail;
	}
	addrlen = ret;

	ret = bind(psock->m_sock,saddr,addrlen);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("bind error %d", ret);
		goto fail;
	}

	if (saddr) {
		free(saddr);
	}
	saddr = NULL;

	return 0;
fail:
	if (saddr) {
		free(saddr);
	}
	saddr = NULL;
	SETERRNO(ret);
	return ret;
}

void* init_ping_sock(int type)
{
	pping_sock_t psock = NULL;
	int ret;

	psock = __alloc_ping_sock(type);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __bind_local_sock(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return psock;
fail:
	__free_ping_sock(&psock);
	SETERRNO(ret);
	return NULL;
}

unsigned short __ping_checksum(uint8_t* pbuf, int bufsize)
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

int __format_ping_request(pping_sock_t psock,uint64_t val,int indent, int seq,uint8_t* pbuf,int bufsize)
{
	struct icmphdr* picmphdr;
	struct icmp6_hdr* picmp6hdr;
	uint8_t* pcur;
	int ret;

	int maxsize = 0;
	if (psock->m_pingtype == AF_INET) {
		maxsize = sizeof(*picmphdr) + sizeof(uint64_t);
	} else if (psock->m_pingtype == AF_INET6) {
		maxsize = sizeof(*picmp6hdr) + sizeof(uint64_t);
	} else {
		ret = -EINVAL;
		goto fail;
	}

	if (bufsize < maxsize) {
		ret = -ENOBUFS;
		goto fail;
	}

	if (psock->m_pingtype == AF_INET) {
		picmphdr = (struct icmphdr*) pbuf;
		picmphdr->type = ICMP_ECHO;
		picmphdr->code = 0;
		picmphdr->checksum = 0;
		picmphdr->un.echo.id = htons((unsigned short)indent);
		picmphdr->un.echo.sequence = (unsigned short)seq;
		pcur = pbuf + sizeof(*picmphdr);
		memcpy(pcur,&val,sizeof(uint64_t));
		picmphdr->checksum = htons(__ping_checksum(pbuf,maxsize));

	} else if (psock->m_pingtype == AF_INET6) {
		picmp6hdr = (struct icmp6_hdr*) pbuf;
		picmp6hdr->icmp6_type = ICMP6_ECHO_REQUEST;
		picmp6hdr->icmp6_code = 0;
		picmp6hdr->icmp6_cksum = 0;
		picmp6hdr->icmp6_dataun.icmp6_un_data16[0] = htons((unsigned short)indent);
		picmp6hdr->icmp6_dataun.icmp6_un_data16[1] = (unsigned short)seq;
		pcur = pbuf + sizeof(*picmp6hdr);
		memcpy(pcur,&val,sizeof(uint64_t));
		picmp6hdr->icmp6_cksum = htons(__ping_checksum(pbuf,maxsize));
	}

	return maxsize;
fail:
	SETERRNO(ret);
	return ret;
}

char* __get_ip_name(pping_sock_t psock)
{
	if (psock == NULL || psock->m_ipname == NULL) {
		return (char*)"NULL";
	}
	return psock->m_ipname;
}


int send_ping_request(void* psock1,const char* ip)
{
	pping_sock_t psock = (pping_sock_t)psock1;
	int ret;
	if (psock == NULL || psock->m_magic != PING_HDR_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_insnd != 0) {
		ret = -EBUSY;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_ipname) {
		free(psock->m_ipname);
	}
	psock->m_ipname = NULL;
	psock->m_ipname = strdup(ip);
	if (psock->m_ipname == NULL) {
		GETERRNO(ret);
		goto fail;
	}


	if (psock->m_saddrlen == 0) {
		psock->m_saddrlen = sizeof(*psock->m_sndaddr);
	}

get_saddr_again:
	if (psock->m_sndaddr) {
		free(psock->m_sndaddr);
	}
	psock->m_sndaddr = NULL;
	psock->m_sndaddr = (struct sockaddr*) malloc(psock->m_saddrlen);
	if (psock->m_sndaddr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	ret = __get_addr_info(ip,"0",psock->m_pingtype,psock->m_sndaddr,psock->m_saddrlen);
	if (ret < 0) {
		GETERRNO(ret);
		if (ret == -ENOBUFS) {
			if (psock->m_saddrlen == 0) {
				psock->m_saddrlen = 4;
			} else {
				psock->m_saddrlen <<= 1;	
			}
			
			goto get_saddr_again;
		}
		goto fail;
	}
	psock->m_saddrlen = ret;

	psock->m_indent += 1;
	psock->m_seq += 1;
	psock->m_sndticks = get_cur_ticks();
	DEBUG_INFO("[%s]m_sndticks 0x%llx %lld",__get_ip_name(psock),psock->m_sndticks, psock->m_sndticks);
	ret = __format_ping_request(psock,psock->m_sndticks,psock->m_indent, psock->m_seq,psock->m_sndbuf,sizeof(psock->m_sndbuf));
	if (ret < 0) {
		GETERRNO(ret);
		DEBUG_INFO("ret %d", ret);
		goto fail;
	}

	psock->m_sndsize = ret;
	psock->m_sndlen = 0;
	psock->m_rcvcomplete = 0;
	ret = sendto(psock->m_sock,psock->m_sndbuf,psock->m_sndsize, MSG_DONTWAIT,psock->m_sndaddr,psock->m_saddrlen);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("[%s]send error %d",__get_ip_name(psock) ,ret);
		goto fail;
	} else {
		psock->m_insnd = 0;
		psock->m_sndlen += psock->m_sndsize;
		DEBUG_BUFFER_FMT(psock->m_sndbuf,psock->m_sndsize,"sndbuf");
	}

	return psock->m_insnd ? 0 : 1;
fail:
	SETERRNO(ret);
	return ret;
}

int ping_is_read_mode(void* psock1)
{
	pping_sock_t psock = (pping_sock_t) psock1;
	int ret= 0;
	if (psock && psock->m_magic == PING_HDR_MAGIC && psock->m_inrcv) {
		ret = 1;
	}
	return ret;
}


int ping_is_write_mode(void* psock1)
{
	pping_sock_t psock = (pping_sock_t) psock1;
	int ret= 0;
	if (psock && psock->m_magic == PING_HDR_MAGIC && psock->m_insnd) {
		ret = 1;
	}
	return ret;
}

int get_ping_evt(void* psock1)
{
	pping_sock_t psock = (pping_sock_t) psock1;
	int sock = -1;
	if (psock && psock->m_magic == PING_HDR_MAGIC && psock->m_sock >= 0 && (psock->m_inrcv != 0 || psock->m_insnd != 0)) {
		sock = psock->m_sock;
	}
	return sock;
}

int ping_complete_read(void* psock1)
{
	pping_sock_t psock = (pping_sock_t) psock1;
	socklen_t rcvaddrlen;
	struct sockaddr* naddr=NULL;
	int ret;
	if (psock == NULL || psock->m_magic != PING_HDR_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_inrcv == 0) {
		ret = -ENOENT;
		SETERRNO(ret);
		return ret;
	}

	rcvaddrlen = psock->m_saddrlen;
	naddr = (struct sockaddr*)malloc(rcvaddrlen);
	if (naddr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(naddr,0,sizeof(*naddr));
	ret = recvfrom(psock->m_sock,psock->m_rcvbuf,sizeof(psock->m_rcvbuf),MSG_DONTWAIT,naddr,&rcvaddrlen);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("[%s]recvfrom error %d", __get_ip_name(psock), ret);
		goto fail;
	} else {
		psock->m_rcvcomplete = 1;
		psock->m_inrcv = 0;
		psock->m_rcvlen = ret;
	}

	if (naddr) {
		free(naddr);
	}
	naddr = NULL;
	
	return psock->m_inrcv ? 0 : 1;
fail:
	if (naddr) {
		free(naddr);
	}
	naddr = NULL;
	SETERRNO(ret);
	return ret;
}

int ping_complete_write(void* psock1)
{
	pping_sock_t psock = (pping_sock_t) psock1;
	int ret;
	if (psock == NULL || psock->m_magic != PING_HDR_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_insnd == 0) {
		ret = -ENOENT;
		SETERRNO(ret);
		return ret;
	}

	ret = sendto(psock->m_sock,&(psock->m_sndbuf[psock->m_sndlen]), (psock->m_sndsize - psock->m_sndlen),MSG_DONTWAIT,psock->m_sndaddr,psock->m_saddrlen);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("[%s] send error [%d]",__get_ip_name(psock),ret);
		goto fail;
	} else {
		psock->m_sndlen += ret;
		if (psock->m_sndlen == psock->m_sndsize) {
			psock->m_insnd = 0;
		}
	}	
	return psock->m_insnd ? 0 : 1;
fail:
	SETERRNO(ret);
	return ret;
}


int __filter_ping_header(pping_sock_t psock,uint64_t* pval)
{
	struct icmphdr* picmphdr= NULL;
	struct iphdr* piphdr=NULL;
	struct icmp6_hdr* picmp6hdr = NULL;
	struct sockaddr_in* paddr;
	uint64_t* pbuf;

	if (psock->m_pingtype == AF_INET) {
		if (psock->m_rcvlen < (int)(sizeof(*piphdr) + 16)) {
			return 0;
		}
		picmphdr = (struct icmphdr*) (psock->m_rcvbuf + sizeof(*piphdr));
		piphdr = (struct iphdr*) (psock->m_rcvbuf);
		paddr = (struct sockaddr_in*) psock->m_sndaddr;
		if (piphdr->daddr != paddr->sin_addr.s_addr) {
			return 0;
		}

		if (picmphdr->type == ICMP_ECHOREPLY && picmphdr->code == 0) {
			pbuf = (uint64_t*) (psock->m_rcvbuf + sizeof(*piphdr) + sizeof(*picmphdr));
			if (*pbuf == psock->m_sndticks && psock->m_indent == ntohs(picmphdr->un.echo.id) && psock->m_seq == picmphdr->un.echo.sequence) {
				DEBUG_BUFFER_FMT(psock->m_rcvbuf,psock->m_rcvlen, "rcvlen");
				*pval = *pbuf;
				return 1;
			}
		}
	} else if (psock->m_pingtype == AF_INET6) {
		if (psock->m_rcvlen < (int)(sizeof(*picmp6hdr) + sizeof(uint64_t))) {
			return 0;
		}

		picmp6hdr = (struct icmp6_hdr*) (psock->m_rcvbuf);
		if (picmp6hdr->icmp6_type == ICMP6_ECHO_REPLY && picmp6hdr->icmp6_code == 0) {
			if (psock->m_indent == ntohs(picmp6hdr->icmp6_dataun.icmp6_un_data16[0]) && psock->m_seq == picmp6hdr->icmp6_dataun.icmp6_un_data16[1]) {
				pbuf = (uint64_t*)(psock->m_rcvbuf + sizeof(*picmp6hdr) );
				if ( *pbuf == psock->m_sndticks) {
					DEBUG_BUFFER_FMT(psock->m_rcvbuf,psock->m_rcvlen,"rcvlen");
					*pval = *pbuf;
					return 1;					
				}
			}
		}

	}
	DEBUG_BUFFER_FMT(psock->m_rcvbuf,psock->m_rcvlen,"not valid rcvlen");
	return 0;

}

int recv_ping_response(void* psock1,uint64_t* pval)
{
	pping_sock_t psock = (pping_sock_t)psock1;
	int ret;
	uint64_t curticks;
	struct sockaddr* naddr = NULL;
	socklen_t naddrlen = 0;
	if (psock == NULL || psock->m_magic != PING_HDR_MAGIC || pval == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_inrcv != 0) {
		/*that not used one*/
		DEBUG_INFO("inrcv != 0");
		return 0;
	}

	if (psock->m_rcvcomplete != 0) {
	get_complete_read:		
		ret = __filter_ping_header(psock,pval);
		if (ret == 0) {
			goto read_again;
		}
		curticks = get_cur_ticks();
		DEBUG_INFO("curticks %lld 0x%llx retval %lld 0x%llx", curticks,curticks, psock->m_sndticks,psock->m_sndticks);
		*pval = curticks - psock->m_sndticks;
		psock->m_inrcv = 0;
	} else {
	read_again:
		if (psock->m_rcvaddr == NULL || psock->m_raddrlen < psock->m_saddrlen) {
			if (psock->m_rcvaddr != NULL) {
				free(psock->m_rcvaddr);
			}
			psock->m_rcvaddr = NULL;
			psock->m_rcvaddr = (struct sockaddr*) malloc((size_t)psock->m_saddrlen);
			if (psock->m_rcvaddr == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}
		memcpy(psock->m_rcvaddr,psock->m_sndaddr,(size_t)psock->m_saddrlen);
		psock->m_raddrlen = psock->m_saddrlen;
		naddr = (struct sockaddr*)malloc(psock->m_saddrlen);
		if (naddr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memcpy(naddr,psock->m_sndaddr,psock->m_saddrlen);
		naddrlen = psock->m_saddrlen;
		ret = recvfrom(psock->m_sock,psock->m_rcvbuf,sizeof(psock->m_rcvbuf),MSG_DONTWAIT,naddr,&naddrlen);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("[%s] receive error %d", __get_ip_name(psock),ret);
			goto fail;
		} else {
			psock->m_inrcv = 0;
			psock->m_rcvlen = ret;
			psock->m_rcvcomplete = 1;
			goto get_complete_read;
		}
	}

	if (naddr) {
		free(naddr);
	}
	naddr = NULL;

	return psock->m_inrcv ? 0 : 1;
fail:
	if (naddr) {
		free(naddr);
	}
	naddr = NULL;
	SETERRNO(ret);
	return ret;
}
