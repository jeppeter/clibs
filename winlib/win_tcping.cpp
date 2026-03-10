#define WIN32_LEAN_AND_MEAN



#include <win_tcping.h>
#include <win_sock.h>
#include <win_output_debug.h>
#include <win_time.h>
#include <stdlib.h>

#pragma warning(push)

#pragma warning(disable:4820)
#pragma warning(disable:4514)

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mswsock.h>

#pragma warning(pop)


#pragma warning(push)

#if defined(_MSC_VER)
#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif
#endif


#define WSA_GETERRNO(ret) do { ret = WSAGetLastError(); if (ret > 0) {ret = -ret;} if (ret == 0) {ret = -1;} } while(0)
#define U64_TIME_PADDING  0xffffffffffffffffULL

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
	int m_port;
	int m_reserv1;
	WSAOVERLAPPED m_connov;
	LPFN_CONNECTEX  m_connexfunc;
} TCPING_SOCK_t,*PTCPING_SOCK_t;

void __close_tcping_sock(PTCPING_SOCK_t psock)
{
	BOOL bret;
	int ret;
	if (psock->m_inconn != 0) {
		bret = CancelIoEx((HANDLE)psock->m_sock,&(psock->m_connov));
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

	psock->m_connexfunc = NULL;

	if (psock->m_connov.hEvent != NULL) {
		CloseHandle(psock->m_connov.hEvent);
	}
	memset(&psock->m_connov,0,sizeof(psock->m_connov));
	return;
}

int __open_tcping_sock(PTCPING_SOCK_t psock)
{
	int ret;
	u_long block = 1;
	GUID guid = WSAID_CONNECTEX;
	DWORD dret;
	ASSERT_IF(psock->m_sock == INVALID_SOCKET);
	ASSERT_IF(psock->m_connov.hEvent == NULL);

	psock->m_sock = WSASocket(psock->m_tcpingtype , SOCK_STREAM, IPPROTO_TCP,NULL,0,WSA_FLAG_OVERLAPPED);
	if (psock->m_sock == INVALID_SOCKET) {
		GETERRNO(ret);
		ERROR_INFO("proto [%d] error %d", psock->m_tcpingtype, ret);
		goto fail;
	}

	block=1;
	ret = ioctlsocket(psock->m_sock, FIONBIO, &block);
	if (ret == SOCKET_ERROR) {
		WSA_GETERRNO(ret);
		ERROR_INFO("set socket non-block error[%d]", ret);
		goto fail;
	}

	psock->m_connov.hEvent = WSACreateEvent();
	if (psock->m_connov.hEvent == WSA_INVALID_EVENT) {
		GETERRNO(ret);
		psock->m_connov.hEvent = NULL;
		ERROR_INFO("cannot create snd sock event %d", ret);
		goto fail;
	}

	if (psock->m_connexfunc == NULL) {
		ret = WSAIoctl(psock->m_sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&guid, sizeof(guid), &(psock->m_connexfunc), sizeof(psock->m_connexfunc), &dret, NULL, NULL);
		if (ret != 0) {
			WSA_GETERRNO(ret);
			ERROR_INFO("get connection func error %d", ret);
			goto fail;
		}

		if (psock->m_connexfunc == NULL) {
			ret = -ERROR_INVALID_PARAMETER;
			ERROR_INFO("can not get m_connexfunc");
			goto fail;
		}
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

		memset(&psock->m_connaddr,0, sizeof(psock->m_connaddr));
		psock->m_connaddrlen = 0;


		if (psock->m_ipname) {
			free(psock->m_ipname);
		}
		psock->m_ipname = NULL;
		psock->m_port = 0;	

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
	int ret = 0;
	struct sockaddr_in* sinaddr=NULL;
	struct sockaddr_in6* sin6addr=NULL;


	if (psock->m_tcpingtype == AF_INET) {
		psock->m_connaddr.sa_family = (ADDRESS_FAMILY)psock->m_tcpingtype;
		psock->m_connaddrlen = sizeof(struct sockaddr_in);
		sinaddr= (struct sockaddr_in*)&psock->m_connaddr;
		sinaddr->sin_port = htons((unsigned short)port);
	} else if (psock->m_tcpingtype == AF_INET6) {
		psock->m_connaddr.sa_family = (ADDRESS_FAMILY)psock->m_tcpingtype;
		psock->m_connaddrlen = sizeof(struct sockaddr_in6);
		sin6addr = (struct sockaddr_in6*)&psock->m_connaddr;
		sin6addr->sin6_port = htons((unsigned short)port);
		ret = inet_pton(psock->m_tcpingtype,ip,&(sin6addr->sin6_addr));
	} else {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}
	if (ret != 1) {
		WSA_GETERRNO(ret);
		ERROR_INFO("convert [%s] error %d", ip ? ip : "NULL", ret);
		goto fail;
	}

	if (psock->m_ipname) {
		free(psock->m_ipname);
		psock->m_ipname = NULL;
	}

	psock->m_ipname = _strdup(ip);
	if (psock->m_ipname == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	psock->m_port = port;


	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int __connect_sock(PTCPING_SOCK_t psock)
{
	BOOL bret;
	DWORD dret;
	int ret;
	int completed = 0;
	ASSERT_IF(psock->m_connexfunc != NULL);
	psock->m_startticks = get_current_ticks();
	bret = psock->m_connexfunc(psock->m_sock, &psock->m_connaddr, psock->m_connaddrlen, NULL, 0, &dret, &(psock->m_connov));
	if (bret) {
		psock->m_endticks = get_current_ticks();
		completed = 1;
	} else {
		WSA_GETERRNO(ret);
		if (ret != ERROR_IO_PENDING) {
			ERROR_INFO("connect [%s:%d] error %d", psock->m_ipname, psock->m_port, ret);
			goto fail;
		}
		psock->m_inconn = 1;
	}
	return completed;
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
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	__close_tcping_sock(psock);

	ret = __open_tcping_sock(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	/*to get the port*/
	ret = __format_sock_addr(psock, ip, port);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __connect_sock(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	completed = ret;

	return completed;
fail:
	__close_tcping_sock(psock);
	SETERRNO(ret);
	return ret;
}

HANDLE get_tcping_evt(void* psock1)
{
	HANDLE hret=NULL;
	PTCPING_SOCK_t psock = (PTCPING_SOCK_t) psock1;
	if (psock->m_magic == TCPING_HDR_MAGIC && psock->m_inconn != 0) {
		hret = psock->m_connov.hEvent;
	}
	return hret;
}

int tcping_is_pending(void* psock1)
{
	int ret=0;
	PTCPING_SOCK_t psock = (PTCPING_SOCK_t) psock1;
	if (psock->m_magic == TCPING_HDR_MAGIC && psock->m_inconn != 0) {
		ret = 1;
	}
	return ret;
}

int tcping_complete(void* psock1)
{
	PTCPING_SOCK_t psock = (PTCPING_SOCK_t) psock1;
	int completed=0;
	BOOL bret;
	DWORD  dret;
	int ret;

	if (psock->m_inconn == 0) {
		return 1;
	}

	bret = GetOverlappedResult((HANDLE)psock->m_sock, &(psock->m_connov), &dret, FALSE);
	if (bret) {
		psock->m_inconn = 0;
		completed = 1;
		psock->m_endticks = get_current_ticks();
	} else {
		GETERRNO(ret);
		if (ret != -ERROR_IO_INCOMPLETE && ret != -ERROR_IO_PENDING) {
			ERROR_INFO("GetOverlappedResult error %d" , ret);
			goto fail;
		}
	}
	return completed;
fail:
	SETERRNO(ret);
	return ret;
}


int resend_tcping_request(void* psock1)
{
	PTCPING_SOCK_t psock = (PTCPING_SOCK_t) psock1;
	int ret;
	if (psock == NULL || psock->m_magic != TCPING_HDR_MAGIC || psock->m_connexfunc == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO("not valid state");
		SETERRNO(ret);
		return ret;
	}

	__close_tcping_sock(psock);

	ret = __open_tcping_sock(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	return ret;
fail:
	SETERRNO(ret);
	return ret;
}

int get_tcping_tick(void* psock1, uint64_t *pval)
{
	PTCPING_SOCK_t psock = (PTCPING_SOCK_t) psock1;
	int ret;
	if (psock == NULL || psock->m_magic != TCPING_HDR_MAGIC || pval == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_endticks == 0 ) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	if (psock->m_endticks >= psock->m_startticks) {
		*pval = psock->m_endticks - psock->m_startticks;
	} else {
		*pval = psock->m_startticks - psock->m_endticks + U64_TIME_PADDING;
	}
	return 0;

}

#pragma warning(pop)
