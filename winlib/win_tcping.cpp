#include <win_tcping.h>


#define  TCPING_HDR_MAGIC   0x7792939

typedef struct __tcping_sock {
	uint32_t m_magic;
	int m_tcpingtype;	
	SOCKET m_sock;
	int m_inconn;
	struct sockaddr *m_sndaddr;
	int m_saddrlen;
	uint64_t m_sndticks;
	char* m_ipname;
	WSAOVERLAPPED m_sndov;
} TCPING_SOCK_t,*PTCPING_SOCK_t;



void __free_tcping_sock(PTCPING_SOCK_t* ppsock)
{
	if (ppsock && *ppsock) {
		PTCPING_SOCK_t psock = *ppsock;

		if (psock->m_magic != TCPING_HDR_MAGIC) {
			ERROR_INFO("not magic 0x%x != 0x%x",psock->m_magic,TCPING_HDR_MAGIC);
		}


		if (psock->m_inconn != 0) {
			bret = CancelIoEx((HANDLE)psock->m_sock,&(psock->m_sndov));
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("can not cancel %s connect %d", psock->m_ipname,ret);
			}
			psock->m_inconn = 0;
		}

		if (psock->m_sock != INVALID_SOCKET) {
			closesocket(psock->m_sock);
		}
		psock->m_sock = INVALID_SOCKET;

		if (psock->m_sndov.hEvent != NULL) {
			CloseHandle(psock->m_sndov.hEvent);
		}
		psock->m_sndov.hEvent = NULL;


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

	psock->m_sock = WSASocket(type , SOCK_STREAM, IPPROTO_TCP,NULL,0,WSA_FLAG_OVERLAPPED);
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


	return psock;
fail:
	__free_tcping_sock(&psock);
	SETERRNO(ret);
	return NULL;
}


