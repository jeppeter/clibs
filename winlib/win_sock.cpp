

#define WIN32_LEAN_AND_MEAN

#pragma warning(push)

#pragma warning(disable:4668)
#pragma warning(disable:4820)
#pragma warning(disable:4365)
#pragma warning(disable:4574)
#pragma warning(disable:4514)

#include <win_sock.h>
#include <win_output_debug.h>
#include <stdio.h>
#include <stdlib.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mswsock.h>

#pragma warning(pop)



// Need to link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#define WSA_GETERRNO(ret) do { ret = WSAGetLastError(); if (ret > 0) {ret = -ret;} if (ret == 0) {ret = -1;} } while(0)

#define  SOCKET_DATA_MAGIC   0x410129de
#define  SOCKET_CLIENT_TYPE  0x1
#define  SOCKET_SERVER_TYPE  0x2

typedef struct __sock_data_priv {
	uint32_t m_magic;
	int m_type;
	char* m_peeraddr;
	char* m_selfaddr;
	int m_peerport;
	int m_selfport;
	SOCKET m_sock;
	SOCKET m_accsock;

	/*these are connect functions*/
	LPFN_CONNECTEX  m_connexfunc;
	int m_inconn;
	uint32_t m_reserv1;
	HANDLE m_connevt;
	OVERLAPPED m_connov;

	/*these are bind functions*/
	uint8_t* m_paccbuf;
	LPFN_ACCEPTEX m_acceptexfunc;
	int m_inacc;
	uint32_t m_accbuflen;
	HANDLE m_accevt;
	OVERLAPPED m_accov;

	int m_inwr;
	uint32_t m_wrleft;
	HANDLE m_wrevt;
	OVERLAPPED m_wrov;
	uint8_t* m_pwrbuf;

	int m_inrd;
	uint32_t m_rdleft;
	HANDLE m_rdevt;
	OVERLAPPED m_rdov;
	uint8_t* m_prdbuf;
} sock_data_priv_t, *psock_data_priv_t;


int init_socket(void)
{
	WSADATA data;
	WORD wversion;
	int ret;
	wversion = MAKEWORD(2, 2);
	ret = WSAStartup(wversion, &data);
	if (ret != 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (LOBYTE(data.wVersion) != 2 || HIBYTE(data.wVersion) != 2) {
		ret = -ERROR_NOT_SUPPORTED;
		ERROR_INFO("init 2.2 return [%d.%d]", HIBYTE(data.wVersion), LOBYTE(data.wVersion));
		WSACleanup();
		goto fail;
	}

	return 0;
fail:

	SETERRNO(ret);
	return ret;
}

void fini_socket(void)
{
	WSACleanup();
}

void __free_socket(psock_data_priv_t* pptcp)
{
	psock_data_priv_t psock1 = NULL;
	BOOL bret;
	int ret;
	if (pptcp && *pptcp) {
		psock1 = *pptcp;
		if (psock1->m_type == SOCKET_CLIENT_TYPE) {
			if (psock1->m_inconn > 0) {
				/*now in connect ,so we should cancel*/
				bret = CancelIoEx((HANDLE)psock1->m_sock, &(psock1->m_connov));
				if (!bret) {
					GETERRNO(ret);
					if (ret != -ERROR_NOT_FOUND) {
						ERROR_INFO("can not cancel socket [%d] connect ov error[%d]", psock1->m_sock, ret);
					}
				}
			}
			psock1->m_inconn = 0;
			if (psock1->m_connevt != NULL) {
				CloseHandle(psock1->m_connevt);
			}
			psock1->m_connevt = NULL;
			memset(&(psock1->m_connov), 0, sizeof(psock1->m_connov));
			psock1->m_connexfunc = NULL;
		} else if (psock1->m_type == SOCKET_SERVER_TYPE) {
			if (psock1->m_inacc) {
				bret = CancelIoEx((HANDLE)psock1->m_sock, &(psock1->m_accov));
				if (!bret) {
					GETERRNO(ret);
					ERROR_INFO("can not cancel socket [%d] accpet ov error[%d]", psock1->m_sock, ret);
				}
			}
			psock1->m_inacc = 0;
			if (psock1->m_accevt != NULL) {
				CloseHandle(psock1->m_accevt);
			}
			psock1->m_accevt = NULL;
			memset(&(psock1->m_accov), 0, sizeof(psock1->m_accov));
			psock1->m_acceptexfunc = NULL;
		}

		if (psock1->m_inrd) {
			bret = CancelIoEx((HANDLE)psock1->m_sock, &(psock1->m_rdov));
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("can not cancel socket [%d] read ov error[%d]", psock1->m_sock, ret);
			}			
		}
		psock1->m_inrd = 0;
		if (psock1->m_rdevt != NULL) {
			CloseHandle(psock1->m_rdevt);
		}
		psock1->m_rdevt = NULL;
		memset(&(psock1->m_rdov), 0, sizeof(psock1->m_rdov));
		psock1->m_prdbuf = NULL;
		psock1->m_rdleft = 0;

		if (psock1->m_inwr) {
			bret = CancelIoEx((HANDLE)psock1->m_sock, &(psock1->m_wrov));
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("can not cancel socket [%d] write ov error[%d]", psock1->m_sock, ret);
			}
		}
		psock1->m_inwr = 0;
		if (psock1->m_wrevt != NULL) {
			CloseHandle(psock1->m_wrevt);
		}
		psock1->m_wrevt = NULL;
		memset(&(psock1->m_wrov), 0, sizeof(psock1->m_wrov));
		psock1->m_pwrbuf = NULL;
		psock1->m_wrleft = 0;

		if (psock1->m_accsock != INVALID_SOCKET) {
			closesocket(psock1->m_accsock);
		}
		psock1->m_accsock = INVALID_SOCKET;

		if (psock1->m_sock != INVALID_SOCKET) {
			closesocket(psock1->m_sock);
		}
		psock1->m_sock = INVALID_SOCKET;

		if (psock1->m_peeraddr != NULL) {
			free(psock1->m_peeraddr);
		}
		psock1->m_peeraddr = NULL;
		psock1->m_peerport = 0;

		if (psock1->m_selfaddr != NULL) {
			free(psock1->m_selfaddr);
		}
		psock1->m_selfaddr = NULL;
		psock1->m_selfport = 0;

		if (psock1->m_paccbuf != NULL) {
			free(psock1->m_paccbuf);
		}
		psock1->m_paccbuf = NULL;
		psock1->m_accbuflen = 0;



		free(psock1);
		*pptcp = NULL;
	}
	return;
}

void free_socket(void** pptcp)
{
	__free_socket((psock_data_priv_t*)pptcp);
	return ;
}


psock_data_priv_t __alloc_sock_priv(int typeval, char* ipaddr, int port)
{
	psock_data_priv_t psock = NULL;
	int ret;

	psock = (psock_data_priv_t)malloc(sizeof(*psock));
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(psock, 0, sizeof(*psock));
	psock->m_sock = INVALID_SOCKET;
	psock->m_accsock = INVALID_SOCKET;
	psock->m_type = typeval;
	psock->m_magic = SOCKET_DATA_MAGIC;
	if (typeval == SOCKET_CLIENT_TYPE) {
		psock->m_peeraddr = _strdup(ipaddr);
		if (psock->m_peeraddr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		psock->m_peerport = port;
	} else if (typeval == SOCKET_SERVER_TYPE) {
		psock->m_selfaddr = _strdup(ipaddr);
		if (psock->m_selfaddr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		psock->m_selfport = port;
	}

	return psock;
fail:
	__free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}

int __get_self_name(psock_data_priv_t psock)
{
	struct sockaddr nameaddr;
	struct sockaddr_in* name;
	int namelen = 0;
	int ret;
	int rc;
	namelen = sizeof(nameaddr);
	rc = getsockname(psock->m_sock, &nameaddr, &namelen);
	if (rc != 0) {
		GETERRNO(ret);
		ERROR_INFO("get socket name for connect [%s:%d] error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
		goto fail;
	}

	name = (struct sockaddr_in*)&nameaddr;

	if (name->sin_family != AF_INET) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO("socket name [%s:%d] not valid [%d]", psock->m_peeraddr, psock->m_peerport, name->sin_family);
		goto fail;
	}

	/**/
	if (psock->m_selfaddr != NULL) {
		free(psock->m_selfaddr);
	}
	psock->m_selfaddr = NULL;
	psock->m_selfaddr = (char*) malloc(INET_ADDRSTRLEN);
	if (psock->m_selfaddr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(psock->m_selfaddr, 0, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(name->sin_addr), psock->m_selfaddr, INET_ADDRSTRLEN);
	psock->m_selfport = ntohs(name->sin_port);

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int __get_peer_name(psock_data_priv_t psock)
{
	struct sockaddr nameaddr;
	struct sockaddr_in* name;
	int ret;
	int namelen;

	namelen = sizeof(nameaddr);
	ret = getpeername(psock->m_sock,&nameaddr,&namelen);
	if (ret != 0) {
		WSA_GETERRNO(ret);
		ERROR_INFO("get peername [%s:%d] error[%d]", psock->m_selfaddr,psock->m_selfport,ret);
		goto fail;
	}

	name = (struct sockaddr_in*) &nameaddr;
	if (name->sin_family != AF_INET) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO("socket name [%s:%d] not valid [%d]", psock->m_selfaddr, psock->m_selfport, name->sin_family);
		goto fail;
	}

	if (psock->m_peeraddr != NULL) {
		free(psock->m_peeraddr);
	}
	psock->m_peeraddr = NULL;
	psock->m_peeraddr = (char*) malloc(INET_ADDRSTRLEN);
	if (psock->m_peeraddr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(psock->m_peeraddr, 0, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(name->sin_addr), psock->m_peeraddr, INET_ADDRSTRLEN);
	psock->m_peerport = ntohs(name->sin_port);
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int __inner_make_read_write(psock_data_priv_t psock)
{
	int ret;

	if (psock->m_rdevt == NULL) {
		psock->m_rdevt = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (psock->m_rdevt == NULL) {
			GETERRNO(ret);
			ERROR_INFO("make read [%s:%d] error[%d]", psock->m_selfaddr,psock->m_selfport,ret);
			goto fail;
		}
		memset(&(psock->m_rdov),0,sizeof(psock->m_rdov));
		psock->m_rdov.hEvent = psock->m_rdevt;
		psock->m_inrd = 0;
	}

	if (psock->m_wrevt == NULL) {
		psock->m_wrevt = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (psock->m_wrevt == NULL) {
			GETERRNO(ret);
			ERROR_INFO("make write [%s:%d] error[%d]", psock->m_selfaddr,psock->m_selfport,ret);
			goto fail;
		}
		memset(&(psock->m_wrov),0,sizeof(psock->m_wrov));
		psock->m_wrov.hEvent = psock->m_wrevt;
		psock->m_wrov = 0;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


void* connect_tcp_socket(char* ipaddr, int port, char* bindip, int bindport, int connected)
{
	int ret;
	psock_data_priv_t psock = NULL;
	struct sockaddr_in name;
	int namelen = 0;
	u_long block = 1;
	GUID guid = WSAID_CONNECTEX;
	DWORD dret;
	BOOL bret;

	psock = __alloc_sock_priv(SOCKET_CLIENT_TYPE, ipaddr, port);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (psock->m_sock == INVALID_SOCKET) {
		WSA_GETERRNO(ret);
		goto fail;
	}


	block = 1;
	ret = ioctlsocket(psock->m_sock, FIONBIO, &block);
	if (ret == SOCKET_ERROR) {
		WSA_GETERRNO(ret);
		ERROR_INFO("set connect [%s:%d] non-block error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
		goto fail;
	}

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	if (bindip != NULL) {
		inet_pton(AF_INET, bindip, &(name.sin_addr));
	} else {
		name.sin_addr.s_addr = INADDR_ANY;
	}

	if (bindport != 0) {
		name.sin_port = htons((uint16_t)bindport);
	} else {
		name.sin_port = 0;
	}

	namelen = sizeof(name);
	ret = bind(psock->m_sock, (const struct sockaddr*)&name, namelen);
	if (ret != 0) {
		WSA_GETERRNO(ret);
		ERROR_INFO("bind address[%s:%d] error[%d]", bindip ? bindip : "INADDR_ANY", bindport, ret);
		goto fail;
	}


	psock->m_connevt = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (psock->m_connevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("create connevt for [%s:%d] error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
		goto fail;
	}

	memset(&(psock->m_connov), 0, sizeof(psock->m_connov));
	psock->m_connov.hEvent = psock->m_connevt;

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	inet_pton(AF_INET, ipaddr, &(name.sin_addr));
	name.sin_port = htons((uint16_t)port);


	ret = WSAIoctl(psock->m_sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
	               &guid, sizeof(guid), &(psock->m_connexfunc), sizeof(psock->m_connexfunc), &dret, NULL, NULL);
	if (ret != 0) {
		WSA_GETERRNO(ret);
		ERROR_INFO("get ConnectEx for [%s:%d] error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
		goto fail;
	}

	if (psock->m_connexfunc == NULL) {
		ret = -ERROR_INTERNAL_ERROR;
		ERROR_INFO("can not get ConnectEx [%d]", ret);
		goto fail;
	}

	namelen = sizeof(name);
	bret = psock->m_connexfunc(psock->m_sock, (const struct sockaddr*) &name, namelen, NULL, 0, &dret, &(psock->m_connov));
	if (bret) {
		ret = __get_self_name(psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		ret = __inner_make_read_write(psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		goto succ;
	} else {
		WSA_GETERRNO(ret);
		if (ret != -ERROR_IO_PENDING) {
			ERROR_INFO("call ConnectEx[%s:%d] error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
			goto fail;
		}
	}

	psock->m_inconn = 1;

	if (connected > 0) {
		/*now to wait for */
		dret = WaitForSingleObject(psock->m_connevt, INFINITE);
		if (dret == WAIT_OBJECT_0) {
			bret = GetOverlappedResult((HANDLE)psock->m_sock, &(psock->m_connov), &dret, FALSE);
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("get ConnectEx [%s:%d] result error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
				goto fail;
			}
			psock->m_inconn = 0;

			ret = __get_self_name(psock);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			ret = __inner_make_read_write(psock);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		} else {
			GETERRNO(ret);
			ERROR_INFO("Wait [%s:%d] ConnectEx error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
			goto fail;
		}
	}

succ:
	return psock;
fail:
	__free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}

HANDLE get_tcp_connect_handle(void* ptcp)
{
	HANDLE hret = NULL;
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	if (psock && psock->m_inconn > 0)  {
		hret = psock->m_connevt;
	}
	return hret;
}


int complete_tcp_connect(void* ptcp)
{
	int ret = 1;
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	DWORD dret;
	BOOL bret;
	if (psock && psock->m_inconn > 0)  {
		bret = GetOverlappedResult((HANDLE) psock->m_sock, &(psock->m_connov), &dret, NULL);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("get connect [%s:%d] result error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
			goto fail;
		}
		psock->m_inconn = 0;

		ret = __get_self_name(psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = __inner_make_read_write(psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		DEBUG_INFO(" local [%s:%d] connect [%s:%d]",  psock->m_selfaddr,psock->m_selfport,psock->m_peeraddr,psock->m_peerport);
	}
	return ret;

fail:
	SETERRNO(ret);
	return ret;
}

int __inner_accept(psock_data_priv_t psock)
{
	int ret;
	BOOL bret;
	struct sockaddr nameaddr;
	DWORD dret;

	if (psock->m_accsock != INVALID_SOCKET) {
		ret= -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	psock->m_accsock = socket(AF_INET, SOCK_STREAM, 0);
	if (psock->m_accsock == INVALID_SOCKET) {
		WSA_GETERRNO(ret);
		ERROR_INFO("make accept socket for [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
		goto fail;
	}

	psock->m_inacc = 0;
	memset(&nameaddr,0,sizeof(nameaddr));
	memset(psock->m_paccbuf,0, psock->m_accbuflen);
	//bret = psock->m_acceptexfunc(psock->m_sock, psock->m_accsock, NULL, 0, sizeof(nameaddr), sizeof(nameaddr), &dret, &(psock->m_accov));
	bret = psock->m_acceptexfunc(psock->m_sock, psock->m_accsock, psock->m_paccbuf, psock->m_accbuflen, sizeof(nameaddr)+16, sizeof(nameaddr)+16, &dret, &(psock->m_accov));
	if (!bret) {
		WSA_GETERRNO(ret);
		if (ret != -WSA_IO_PENDING) {
			ERROR_INFO("acceptex [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
			goto fail;			
		}
		psock->m_inacc = 1;
	} else {
		psock->m_inacc = 0;
	}

	return psock->m_inacc;
fail:
	SETERRNO(ret);
	return ret;
}

void* bind_tcp_socket(char* ipaddr, int port, int backlog)
{
	psock_data_priv_t psock = NULL;
	int ret;
	struct sockaddr_in* name;
	struct sockaddr nameaddr;
	int namelen;
	DWORD dret;
	GUID GuidAcceptEx = WSAID_ACCEPTEX;
	u_long block;

	psock = __alloc_sock_priv(SOCKET_SERVER_TYPE, ipaddr, port);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (psock->m_sock == INVALID_SOCKET) {
		WSA_GETERRNO(ret);
		ERROR_INFO("make socket for server [%s:%d] error[%d]", ipaddr, port, ret);
		goto fail;
	}

	block = 1;
	ret = ioctlsocket(psock->m_sock, FIONBIO, &block);
	if (ret == SOCKET_ERROR) {
		WSA_GETERRNO(ret);
		ERROR_INFO("set bind [%s:%d] non-block error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
		goto fail;
	}


	memset(&nameaddr, 0, sizeof(nameaddr));
	name = (struct sockaddr_in*) &nameaddr;
	name->sin_family = AF_INET;
	inet_pton(AF_INET, ipaddr, &(name->sin_addr));
	name->sin_port = htons((uint16_t)port);

	namelen = sizeof(nameaddr);
	ret = bind(psock->m_sock, &nameaddr, namelen);
	if (ret != 0) {
		WSA_GETERRNO(ret);
		ERROR_INFO("bind address[%s:%d] error[%d]", ipaddr, port, ret);
		goto fail;
	}

	ret = listen(psock->m_sock, backlog);
	if (ret != 0) {
		WSA_GETERRNO(ret);
		ERROR_INFO("listen on [%s:%d] with [%d] error[%d]", ipaddr, port, backlog, ret);
		goto fail;
	}

	ret = WSAIoctl(psock->m_sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
	               &GuidAcceptEx, sizeof(GuidAcceptEx), &(psock->m_acceptexfunc), sizeof(psock->m_acceptexfunc),
	               &dret, NULL, NULL);
	if (ret == SOCKET_ERROR) {
		WSA_GETERRNO(ret);
		ERROR_INFO("get acceptex function for [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
		goto fail;
	}

	/**/
	psock->m_accevt = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (psock->m_accevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("make accevt for [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
		goto fail;
	}

	memset(&(psock->m_accov), 0 , sizeof(psock->m_accov));
	psock->m_accov.hEvent = psock->m_accevt;

	psock->m_accbuflen = 1024;
	psock->m_paccbuf = (uint8_t*) malloc(psock->m_accbuflen);
	if (psock->m_paccbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __inner_accept(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return psock;
fail:
	__free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}

HANDLE get_tcp_accept_handle(void* ptcp)
{
	HANDLE hret = NULL;
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	if (psock && psock->m_inacc > 0) {
		hret = psock->m_accevt;
	}
	return hret;
}

int complete_tcp_accept(void* ptcp)
{
	int ret = 1;
	BOOL bret;
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	DWORD dret;

	if (psock && psock->m_inacc > 0) {
		dret = 0;
		bret = GetOverlappedResult((HANDLE)psock->m_sock, &(psock->m_accov),&dret,NULL);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("get accept [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
			goto fail;
		}
		DEBUG_INFO("accept dret [%ld]", dret);
		psock->m_inacc = 0;
	}

	return ret;
fail:
	SETERRNO(ret);
	return ret;
}

void* accept_tcp_socket(void* ptcp)
{
	psock_data_priv_t psvrsock = (psock_data_priv_t)ptcp;
	psock_data_priv_t psock = NULL;
	int ret;

	if (psvrsock == NULL || psvrsock->m_accsock == INVALID_SOCKET || psvrsock->m_inacc > 0) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	/*now we make the server socket*/
	psock = __alloc_sock_priv(SOCKET_SERVER_TYPE, psvrsock->m_selfaddr, psvrsock->m_selfport);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sock = psvrsock->m_accsock;
	psvrsock->m_accsock = INVALID_SOCKET;

	ret = setsockopt(psock->m_sock,SOL_SOCKET,SO_UPDATE_ACCEPT_CONTEXT,(char*)&(psvrsock->m_sock),sizeof(psvrsock->m_sock));
	if (ret != 0) {
		WSA_GETERRNO(ret);
		ERROR_INFO("can not get [%s:%d] update accept context error[%d]", psock->m_selfaddr,psock->m_selfport,ret);
		goto fail;
	}

	DEBUG_BUFFER_FMT(psvrsock->m_paccbuf,psvrsock->m_accbuflen,"accept buffer size");

	ret= __get_peer_name(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __inner_make_read_write(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __inner_accept(psvrsock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return psock;
fail:
	__free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}

HANDLE get_tcp_read_handle(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	HANDLE hret=NULL;

	if (psock && psock->m_inrd > 0) {
		hret = psock->m_rdevt;
	}
	return hret;
}

int __inner_start_read(psock_data_priv_t psock)
{
	DWORD dret;
	int ret;
	DWORD flags;
try_read_again:
	ret = WSARecv(psock->m_sock, psock->m_prdbuf, psock->m_rdleft,&(dret),&flags,&(psock->m_rdov),NULL);
	if (ret == 0) {
		psock->m_rdleft -= dret;
		psock->m_prdbuf += dret;
		if (psock->m_rdleft == 0) {
			psock->m_prdbuf = NULL;
			return 1;
		}
		goto try_read_again;
	} 
	WSA_GETERRNO(ret);
	ERROR_INFO("read [%s:%s] => [%s:%d] left [%d] error[%d]", psock->m_peeraddr,
			psock->m_peerport,psock->m_selfaddr,psock->m_selfport,psock->m_rdleft,ret);
	SETERRNO(ret);
	return ret;
}

int __inner_start_write(psock_data_priv_t psock)
{
	DWORD dret;
	int ret;
	DWORD flags;
try_write_again:
	flags = 0;
	ret = WSASend(psock->m_sock, psock->m_pwrbuf, psock->m_wrleft,&(dret),&flags,&(psock->m_wrov),NULL);
	if (ret == 0) {
		psock->m_wrleft -= dret;
		psock->m_pwrbuf += dret;
		if (psock->m_wrleft == 0) {
			psock->m_pwrbuf = NULL;
			return 1;
		}
		goto try_write_again;
	} 
	WSA_GETERRNO(ret);
	ERROR_INFO("write [%s:%s] => [%s:%d] left [%d] error[%d]", psock->m_selfaddr,
			psock->m_selfport,psock->m_peeraddr,psock->m_peerport,psock->m_wrleft,ret);
	SETERRNO(ret);
	return ret;
}

HANDLE get_tcp_write_handle(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	HANDLE hret=NULL;

	if (psock && psock->m_inwr > 0) {
		hret = psock->m_wrevt;
	}
	return hret;	
}

int complete_tcp_read(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	int ret = 1;
	BOOL bret;
	DWORD dret;
	if (psock && psock->m_inrd > 0) {
		bret = GetOverlappedResult((HANDLE) psock->m_sock,&(psock->m_rdov),&dret,NULL);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("read complete [%s:%d] => [%s:%d] left[%ld] error[%d]", psock->m_peeraddr,psock->m_peerport,
				psock->m_selfaddr,psock->m_selfport, psock->m_rdleft,ret);
			goto fail;
		}

		psock->m_rdleft -= dret;
		psock->m_prdbuf += dret;
		psock->m_inrd = 0;
		if (psock->m_rdleft == 0) {
			psock->m_rdleft = 0;
			psock->m_prdbuf = NULL;
		} else {
			ret = __inner_start_read(psock);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}

	}

	return ret;
fail:
	SETERRNO(ret);
	return ret;
}

int complete_tcp_write(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	int ret = 1;
	BOOL bret;
	DWORD dret;
	if (psock && psock->m_inwr > 0) {
		bret = GetOverlappedResult((HANDLE) psock->m_sock,&(psock->m_wrov),&dret,NULL);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("write complete [%s:%d] => [%s:%d] left [%ld] error[%d]", psock->m_selfaddr,psock->m_selfport,
				psock->m_peeraddr,psock->m_peerport, psock->m_wrleft,ret);
			goto fail;
		}

		psock->m_wrleft -= dret;
		psock->m_pwrbuf += dret;
		psock->m_inwr = 0;
		if (psock->m_wrleft == 0) {
			psock->m_wrleft = 0;
			psock->m_pwrbuf = NULL;
		} else {
			ret = __inner_start_write(psock);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}
	}

	return ret;
fail:
	SETERRNO(ret);
	return ret;
}

int read_tcp_socket(void* ptcp, uint8_t* pbuf,int bufsize)
{
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	if (psock == NULL || psock->m_inrd > 0 || psock->m_rdevt == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	psock->m_prdbuf = pbuf;
	psock->m_rdleft = bufsize;

	return __inner_start_read(psock);
}

int write_tcp_socket(void* ptcp, uint8_t* pbuf,int bufsize)
{
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	if (psock == NULL || psock->m_inwr > 0 || psock->m_wrevt == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	psock->m_pwrbuf = pbuf;
	psock->m_wrleft = bufsize;

	return __inner_start_write(psock);
}
