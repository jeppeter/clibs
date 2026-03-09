#include <win_tcping.h>


#define  TCPING_HDR_MAGIC   0x7792939

typedef struct __tcping_sock {
	uint32_t m_magic;
	int m_tcpingtype;	
	SOCKET m_sock;
	int m_inconn;
	struct sockaddr m_connaddr;
	int m_connaddrlen;
	uint64_t m_startticks;
	uint64_t m_endticks;
	char* m_ipname;
	WSAOVERLAPPED m_connov;
} TCPING_SOCK_t,*PTCPING_SOCK_t;

void __close_tcping_sock(PTCPING_SOCK_t psock)
{
	if (psock->m_inconn != 0) {
		bret = CancelIoEx(psock->m_sock,&(psock->m_connov));
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("can not cancel ip %s", psock->m_ipname ? psock->m_ipname : "NULL");
		}
		psock->m_inconn = 0;
	}

	if (psock->m_sock != INVALID_SOCKET) {
		closesocket(psock->m_sock);
		psock->m_sock = INVALID_SOCKET;
	}

	if (psock->m_connov.hEvent != NULL) {
		CloseHandle(psock->m_connov.hEvent);
	}
	memset(&psock->m_connov,0,sizeof(psock->m_connov));
	return;
}

int __open_tcping_sock(PTCPING_SOCK_t psock)
{
	int ret;
	ASSERT_IF(psock->m_sock == INVALID_SOCKET);
	ASSERT_IF(psock->m_connaddr.hEvent == NULL);

	psock->m_sock = WSASocket(psock->m_tcpingtype , SOCK_STREAM, IPPROTO_TCP,NULL,0,WSA_FLAG_OVERLAPPED);
	if (psock->m_sock == INVALID_SOCKET) {
		GETERRNO(ret);
		ERROR_INFO("proto [%d] error %d", proto, ret);
		goto fail;
	}

	psock->m_connaddr.hEvent = WSACreateEvent();
	if (psock->m_connaddr.hEvent == WSA_INVALID_EVENT) {
		GETERRNO(ret);
		psock->m_connaddr.hEvent = NULL;
		ERROR_INFO("cannot create snd sock event %d", ret);
		goto fail;
	}
	return 0;
fail:
	__close_tcping_sock(psock);
	SETERRNO(ret);
	return ret;
}

void __free_tcping_sock(PTCPING_SOCK_t* ppsock)
{
	if (ppsock && *ppsock) {
		PTCPING_SOCK_t psock = *ppsock;

		if (psock->m_magic != TCPING_HDR_MAGIC) {
			ERROR_INFO("not magic 0x%x != 0x%x",psock->m_magic,TCPING_HDR_MAGIC);
		}

		__close_tcping_sock(psock);

		if (psock->m_sndaddr) {
			free(psock->m_sndaddr);
		}
		psock->m_sndaddr = NULL;
		psock->m_saddrlen = 0;


		if (psock->m_ipname) {
			free(psock->m_ipname);
		}
		psock->m_ipname = NULL;

		free(psock);
		*ppsock = NULL;
	}
}


PTCPING_SOCK_t __alloc_tcping_sock(int type)
{
	PTCPING_SOCK_t psock = NULL;
	int ret;

	psock= (PTCPING_SOCK_t)malloc(sizeof(*psock));
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(psock, 0, sizeof(*psock));
	psock->m_magic = TCPING_HDR_MAGIC;
	psock->m_sock = INVALID_SOCKET;
	psock->m_tcpingtype = type;

	if (type != AF_INET && type != AF_INET6) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	return psock;
fail:
	__free_tcping_sock(&psock);
	SETERRNO(ret);
	return NULL;
}

void free_tcping_sock(void** ppsock)
{
	if (ppsock && *ppsock) {
		PTCPING_SOCK_t psock = (PTCPING_SOCK_t)*ppsock;
		if (psock->m_magic == TCPING_HDR_MAGIC) {
			__free_tcping_sock(&psock);
		} else {
			ERROR_INFO("not valid magic 0x%x", psock->m_magic);
		}
		*ppsock = NULL;
	}
	return;
}

int __format_sock_addr(PTCPING_SOCK_t psock,const char* ip, int port)
{
	int ret;
	struct sockaddr_in* sinaddr=NULL;
	struct sockaddr_in6* sin6addr=NULL;

	ret = inet_ntop(psock->m_tcpingtype,ip,&(psock->m_connaddr));
	if (ret != 1) {
		ret = WSAGetLastError();
		if (ret == 0) {
			ret = -1;
		}

		if (ret > 0) {
			ret = -ret;
		}	
		ERROR_INFO("convert [%s] error %d", ip ? ip : "NULL", ret);
		goto fail;
	}

	if (psock->m_tcpingtype == AF_INET) {
		psock->m_connaddr.sa_family = psock->m_tcpingtype;
		psock->m_connaddrlen = sizeof(struct sockaddr_in);
		sinaddr= (struct sockaddr_in*)
	} else if (psock->m_tcpingtype == AF_INET6) {
		psock->m_connaddr.sa_family = psock->m_tcpingtype;
		psock->m_connaddrlen = sizeof(struct sockaddr_in6);
	} else {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}




	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


int send_tcping_request(void* psock1,const char* ip,int port)
{
	PTCPING_SOCK_t psock = (PTCPING_SOCK_t) psock1;
	int ret;
	int completed = 0;

	if (psock == NULL || psock->m_magic != TCPING_HDR_MAGIC) {
		return ret;
	}

	__close_tcping_sock(psock);

	ret = __open_tcping_sock(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	//

	return completed;
fail:
	__close_tcping_sock(psock);
	SETERRNO(ret);
	return ret;
}

