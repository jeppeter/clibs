

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
	char* m_ipaddr;
	int m_port;
	uint32_t m_reserv5;
	SOCKET m_sock;

	/*these are connect functions*/
	LPFN_CONNECTEX  m_connexfunc;
	int m_inconn;
	uint32_t m_reserv1;
	HANDLE m_connevt;
	OVERLAPPED m_connov;

	/*these are bind functions*/
	int m_inacc;
	uint32_t m_reserv2;
	HANDLE m_accevt;
	OVERLAPPED m_accov;

	int m_inwr;
	uint32_t m_reserv3;
	HANDLE m_wrevt;
	OVERLAPPED m_wrov;

	int m_inrd;
	uint32_t m_reserv4;
	HANDLE m_rdevt;
	OVERLAPPED m_rdov;
} sock_data_priv_t,*psock_data_priv_t;


int init_socket(void)
{
	WSADATA data;
	WORD wversion;
	int ret;
	wversion = MAKEWORD(2,2);
	ret = WSAStartup(wversion,&data);
	if (ret != 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (LOBYTE(data.wVersion) != 2 || HIBYTE(data.wVersion) != 2) {
		ret = -ERROR_NOT_SUPPORTED;
		ERROR_INFO("init 2.2 return [%d.%d]",HIBYTE(data.wVersion),LOBYTE(data.wVersion));
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
				bret = CancelIoEx((HANDLE)psock1->m_sock,&(psock1->m_connov));
				if (!bret) {
					GETERRNO(ret);
					if (ret != -ERROR_NOT_FOUND) {
						ERROR_INFO("can not cancel socket [%d] connect ov error[%d]", psock1->m_sock,ret);	
					}					
				}				
			}
			psock1->m_inconn = 0;
			if (psock1->m_connevt != NULL) {
				CloseHandle(psock1->m_connevt);
			}
			psock1->m_connevt = NULL;
			memset(&(psock1->m_connov),0, sizeof(psock1->m_connov));
			psock1->m_connexfunc = NULL;
		} else if (psock1->m_type == SOCKET_SERVER_TYPE) {
			if (psock1->m_inacc) {
				/*bret = CancelIoEx(psock1->m_sock,&(psock1->m_accov));
				if (!bret) {
					GETERRNO(ret);
					ERROR_INFO("can not cancel socket [%d] accpet ov error[%d]", psock1->m_sock, ret);
				}*/
			}
			psock1->m_inacc = 0;
			if (psock1->m_accevt != NULL) {
				CloseHandle(psock1->m_accevt);
			}
			psock1->m_accevt = NULL;
			memset(&(psock1->m_accov), 0, sizeof(psock1->m_accov));
		}

		if (psock1->m_inrd) {
			/*bret = CancelIoEx(psock1->m_sock, &(psock1->m_rdov));
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("can not cancel socket [%d] read ov error[%d]", psock1->m_sock, ret);
			}*/
		}
		psock1->m_inrd = 0;
		if (psock1->m_rdevt != NULL) {
			CloseHandle(psock1->m_rdevt);
		}
		psock1->m_rdevt = NULL;
		memset(&(psock1->m_rdov), 0, sizeof(psock1->m_rdov));

		if (psock1->m_inwr) {
			/*bret = CancelIoEx(psock1->m_sock, &(psock1->m_wrov));
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("can not cancel socket [%d] write ov error[%d]", psock1->m_sock, ret);
			}*/
		}
		psock1->m_inwr = 0;
		if (psock1->m_wrevt != NULL) {
			CloseHandle(psock1->m_wrevt);
		}
		psock1->m_wrevt = NULL;
		memset(&(psock1->m_wrov),0, sizeof(psock1->m_wrov));

		if (psock1->m_sock != INVALID_SOCKET) {
			closesocket(psock1->m_sock);
		}
		psock1->m_sock = INVALID_SOCKET;

		if (psock1->m_ipaddr != NULL) {
			free(psock1->m_ipaddr);
		}
		psock1->m_ipaddr = NULL;
		psock1->m_port = 0;

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


psock_data_priv_t __alloc_sock_priv(int typeval,char* ipaddr, int port)
{
	psock_data_priv_t psock = NULL;
	int ret;

	psock = (psock_data_priv_t)malloc(sizeof(*psock));
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(psock,0,sizeof(*psock));
	psock->m_sock = INVALID_SOCKET;
	psock->m_type = typeval;
	psock->m_magic = SOCKET_DATA_MAGIC;
	psock->m_ipaddr = _strdup(ipaddr);
	if (psock->m_ipaddr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	psock->m_port = port;

	return psock;
fail:
	__free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}

void* connect_tcp_socket(char* ipaddr,int port,char* bindip,int bindport,int connected)
{
	int ret;
	psock_data_priv_t psock = NULL;
	struct sockaddr_in name;
	int namelen = 0;
	u_long block=1;
	GUID guid = WSAID_CONNECTEX;
	DWORD dret;
	BOOL bret;

	psock = __alloc_sock_priv(SOCKET_CLIENT_TYPE,ipaddr, port);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sock = socket(AF_INET,SOCK_STREAM,0);
	if (psock->m_sock == INVALID_SOCKET) {
		WSA_GETERRNO(ret);
		goto fail;
	}


	block = 1;
	ret = ioctlsocket(psock->m_sock,FIONBIO,&block);
	if (ret == SOCKET_ERROR) {
		WSA_GETERRNO(ret);
		ERROR_INFO("set connect [%s:%d] non-block error[%d]", psock->m_ipaddr, psock->m_port,ret);
		goto fail;
	}

	memset(&name,0, sizeof(name));
	name.sin_family = AF_INET;
	if (bindip != NULL) {
		inet_pton(AF_INET,bindip,&(name.sin_addr));
	} else {
		name.sin_addr.s_addr = INADDR_ANY;		
	}

	if (bindport != 0) {
		name.sin_port = htons((uint16_t)bindport);
	} else {
		name.sin_port = 0;
	}

	namelen = sizeof(name);
	ret = bind(psock->m_sock, (const struct sockaddr*)&name,namelen);
	if (ret != 0) {
		WSA_GETERRNO(ret);
		ERROR_INFO("bind address[%s:%d] error[%d]",bindip ? bindip : "INADDR_ANY", bindport, ret);
		goto fail;
	}


	psock->m_connevt = CreateEvent(NULL,TRUE,FALSE,NULL);
	if (psock->m_connevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("create connevt for [%s:%d] error[%d]",psock->m_ipaddr, psock->m_port, ret);
		goto fail;
	}

	memset(&(psock->m_connov),0, sizeof(psock->m_connov));
	psock->m_connov.hEvent = psock->m_connevt;

	memset(&name,0, sizeof(name));
	name.sin_family = AF_INET;
	inet_pton(AF_INET,ipaddr,&(name.sin_addr));
	name.sin_port = htons((uint16_t)port);


	ret = WSAIoctl(psock->m_sock,SIO_GET_EXTENSION_FUNCTION_POINTER,
			&guid, sizeof(guid),&(psock->m_connexfunc),sizeof(psock->m_connexfunc),&dret,NULL,NULL);
	if (ret != 0) {
		WSA_GETERRNO(ret);
		ERROR_INFO("get ConnectEx for [%s:%d] error[%d]", psock->m_ipaddr,psock->m_port, ret);
		goto fail;
	}

	if (psock->m_connexfunc == NULL) {
		ret = -ERROR_INTERNAL_ERROR;
		ERROR_INFO("can not get ConnectEx [%d]", ret);
		goto fail;
	}

	namelen = sizeof(name);
	bret = psock->m_connexfunc(psock->m_sock, (const struct sockaddr*) &name,namelen,NULL,0,&dret,&(psock->m_connov));
	if (bret) {
		goto succ;
	} else {
		WSA_GETERRNO(ret);
		if (ret != -ERROR_IO_PENDING) {
			ERROR_INFO("call ConnectEx[%s:%d] error[%d]", psock->m_ipaddr, psock->m_port, ret);
			goto fail;
		}
	}

	psock->m_inconn = 1;

	if (connected > 0) {
		/*now to wait for */
		dret = WaitForSingleObject(psock->m_connevt,INFINITE);
		if (dret == WAIT_OBJECT_0) {
			bret = GetOverlappedResult((HANDLE)psock->m_sock,&(psock->m_connov),&dret,FALSE);
			if (!bret) {
				GETERRNO(ret);
				ERROR_INFO("get ConnectEx [%s:%d] result error[%d]", psock->m_ipaddr,psock->m_port, ret);
				goto fail;
			}
			psock->m_inconn = 0;
		} else {
			GETERRNO(ret);
			ERROR_INFO("Wait [%s:%d] ConnectEx error[%d]", psock->m_ipaddr,psock->m_port, ret);
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
	HANDLE hret= NULL;
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
		bret = GetOverlappedResult((HANDLE) psock->m_sock,&(psock->m_connov),&dret,NULL);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("get connect [%s:%d] result error[%d]", psock->m_ipaddr, psock->m_port, ret);
			goto fail;
		}
		psock->m_inconn = 0;
	}
	return ret;

fail:
	SETERRNO(ret);
	return ret;
}