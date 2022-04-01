#include <ux_sock.h>
#include <ux_output_debug.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>


#define  SOCKET_DATA_MAGIC   0x410129de
#define  SOCKET_CLIENT_TYPE  0x1
#define  SOCKET_SERVER_TYPE  0x2

#define  IPADDR_LENGTH       64


typedef struct __sock_data_priv {
	uint32_t m_magic;
	int m_type;
	char* m_peeraddr;
	char* m_selfaddr;
	int m_peerport;
	int m_selfport;

	int m_sock;
	int m_accsock;

	int m_inacc;
	int m_inconn;
	int m_inrd;
	int m_inwr;

	struct sockaddr m_accaddr;
	uint8_t* m_prdptr;
	int m_rdleft;
	uint8_t* m_pwrptr;
	int m_wrleft;
} sock_data_priv_t, *psock_data_priv_t;

int init_socket(void)
{
	return 0;
}

void fini_socket(void)
{
	return;
}

void __free_socket(psock_data_priv_t* pptcp)
{
	psock_data_priv_t psock = NULL;
	if (pptcp && *pptcp) {
		psock = (psock_data_priv_t) * pptcp;
		if (psock->m_magic != SOCKET_DATA_MAGIC) {
			ERROR_INFO("[%p].[0x%x] SOCKET_DATA_MAGIC [0x%x]", psock->m_magic, SOCKET_DATA_MAGIC);
		}
		if (psock->m_accsock >= 0) {
			close(psock->m_accsock);
		}
		psock->m_accsock = -1;

		if (psock->m_sock >= 0) {
			close(psock->m_sock);
		}
		psock->m_sock = -1;

		if (psock->m_selfaddr) {
			free(psock->m_selfaddr);
		}
		psock->m_selfaddr = NULL;

		if (psock->m_peeraddr) {
			free(psock->m_peeraddr);
		}
		psock->m_peeraddr = NULL;

		psock->m_prdptr = NULL;
		psock->m_pwrptr = NULL;
		psock->m_rdleft = 0;
		psock->m_wrleft = 0;

		psock->m_inconn = 0;
		psock->m_inacc = 0;
		psock->m_inrd = 0;
		psock->m_inwr = 0;

		free(psock);
		*pptcp = NULL;
	}	
}

void free_socket(void** pptcp)
{
	__free_socket((psock_data_priv_t*)pptcp);
	return;
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
	psock->m_sock = -1;
	psock->m_accsock = -1;
	psock->m_magic = SOCKET_DATA_MAGIC;
	psock->m_type = typeval;
	if (psock->m_type == SOCKET_SERVER_TYPE) {
		if (ipaddr != NULL) {
			psock->m_selfaddr = strdup(ipaddr);
			if (psock->m_selfaddr == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			psock->m_selfport = port;
		}
	} else if (psock->m_type == SOCKET_CLIENT_TYPE) {
		if (ipaddr != NULL) {
			psock->m_peeraddr = strdup(ipaddr);
			if (psock->m_peeraddr == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			psock->m_peerport = port;
		}
	} else {
		ret = -EINVAL;
		goto fail;
	}

	return psock;
fail:
	__free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}

int __get_sock_name(psock_data_priv_t psock)
{
	int ret;
	struct sockaddr saddr;
	struct sockaddr_in* paddr=NULL;
	socklen_t slen;
	const char* pret = NULL;
	slen = sizeof(saddr);
	ret = getsockname(psock->m_sock, &saddr, &slen);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("getsockname [%s:%d] error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
		goto fail;
	}

	paddr = (struct sockaddr_in*)&saddr;
	if (saddr.sa_family != AF_INET) {
		ret = -EINVAL;
		ERROR_INFO("getsockname [%s:%d] sin_family[%d] != AF_INET[%d]", psock->m_peeraddr, psock->m_peerport,
		           saddr.sa_family, AF_INET);
		goto fail;
	}

	if (psock->m_selfaddr == NULL) {
		psock->m_selfaddr = (char*)malloc(IPADDR_LENGTH);
		if (psock->m_selfaddr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}
	memset(psock->m_selfaddr, 0,IPADDR_LENGTH);
	pret = inet_ntop(AF_INET, &(paddr->sin_addr), psock->m_selfaddr, IPADDR_LENGTH-1);
	if (pret == NULL) {
		GETERRNO(ret);
		ERROR_INFO("inet_ntop [%s:%d] error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
		goto fail;
	}
	psock->m_selfport = ntohs(paddr->sin_port);


	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int __get_peer_name(psock_data_priv_t psock)
{
	int ret;
	struct sockaddr saddr;
	struct sockaddr_in* paddr;
	socklen_t slen;
	const char* pret = NULL;
	slen = sizeof(saddr);
	ret = getpeername(psock->m_sock, &saddr, &slen);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("getpeername [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
		goto fail;
	}

	paddr = (struct sockaddr_in*) &saddr;
	if (paddr->sin_family != AF_INET) {
		ret = -EINVAL;
		ERROR_INFO("getpeername [%s:%d] sin_family[%d] != AF_INET[%d]", psock->m_selfaddr, psock->m_selfport,
		           paddr->sin_family, AF_INET);
		goto fail;
	}

	if (psock->m_peeraddr == NULL) {
		psock->m_peeraddr = (char*)malloc(IPADDR_LENGTH);
		if (psock->m_peeraddr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}
	memset(psock->m_peeraddr, 0 , IPADDR_LENGTH);
	pret = inet_ntop(AF_INET, &(paddr->sin_addr), psock->m_peeraddr, IPADDR_LENGTH - 1);
	if (pret == NULL) {
		GETERRNO(ret);
		ERROR_INFO("inet_ntop [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
		goto fail;
	}
	psock->m_peerport = ntohs(paddr->sin_port);

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

void* connect_tcp_socket(char* ipaddr, int port, char* bindip, int bindport, int connected)
{
	psock_data_priv_t psock = NULL;
	int ret;
	int flags;
	struct sockaddr saddr;
	struct sockaddr_in *paddr;
	int error;
	socklen_t errlen;
	int inconn = 0;
	fd_set rfd;

	if (ipaddr == NULL || port < 1 || port >= ( 1 << 16)) {
		ret = -EINVAL;
		goto fail;
	}

	psock = __alloc_sock_priv(SOCKET_CLIENT_TYPE, ipaddr, port);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (psock->m_sock < 0) {
		GETERRNO(ret);
		ERROR_INFO("cannot socket error[%d]", ret);
		goto fail;
	}

	SETERRNO(0);
	flags = fcntl(psock->m_sock, F_GETFL);
	if (flags == -1) {
		GETERRNO_DIRECT(ret);
		if (ret != 0) {
			ERROR_INFO("get fcntl error[%d]", ret);
			goto fail;
		}
	}

	ret = fcntl(psock->m_sock, F_SETFL, O_NONBLOCK | flags);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set nonblock error[%d]", ret);
		goto fail;
	}

	if (bindip != NULL) {
		psock->m_selfaddr = strdup(bindip);
		if (psock->m_selfaddr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		psock->m_selfport = bindport;

		/*now bind address*/
		memset(&saddr, 0, sizeof(saddr));
		paddr = (struct sockaddr_in*)&saddr;
		paddr->sin_family = AF_INET;
		ret = inet_pton(AF_INET, bindip, &(paddr->sin_addr));
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("can not change [%s] to sin_addr [%d]", bindip, ret);
			goto fail;
		}
		paddr->sin_port = htons(bindport);

		ret = bind(psock->m_sock, &saddr, sizeof(*paddr));
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport , ret);
			goto fail;
		}
	}

	/*to connect*/
	error = 0;
	ret = setsockopt(psock->m_sock, SOL_SOCKET, SO_ERROR, &error, sizeof(error));
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("setsockopt [%s:%d] SO_ERROR error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
		goto fail;
	}

	memset(&saddr, 0, sizeof(saddr));
	paddr = (struct sockaddr_in*)&saddr;
	paddr->sin_family = AF_INET;
	ret = inet_pton(AF_INET, ipaddr, &(paddr->sin_addr));
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("can not change [%s] to bind addr [%d]", ipaddr, ret);
		goto fail;
	}
	paddr->sin_port = htons(port);
	inconn = 0;
	ret = connect(psock->m_sock, &saddr, sizeof(*paddr));
	if (ret < 0) {
		GETERRNO(ret);
		if (ret != -EINPROGRESS) {
			ERROR_INFO("connect [%s:%d] error[%d]", ipaddr, port, ret);
			goto fail;
		}
		inconn = 1;
	}

	if (connected && inconn > 0) {
		while (1) {
			FD_ZERO(&rfd);
			FD_SET(psock->m_sock , &rfd);
			ret = select(psock->m_sock + 1, &rfd, NULL, NULL, NULL);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			} else if (ret == 0) {
				ret = -ETIMEDOUT;
				ERROR_INFO("connect [%s:%d] timedout", psock->m_peeraddr, psock->m_peerport);
				goto fail;
			} else {
				errlen = sizeof(error);
				ret = getsockopt(psock->m_sock, SOL_SOCKET, SO_ERROR, &error, &errlen);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO("get connect result [%s:%d] error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
					goto fail;
				}
				if (error != 0) {
					ret = error;
					if (ret > 0) {
						ret = -ret;
					}
					ERROR_INFO("connect [%s:%d] result [%d]", psock->m_peeraddr, psock->m_peerport, error);
					goto fail;
				}
				inconn = 0;

				ret = __get_sock_name(psock);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
			}
		}
	}

	psock->m_inconn = inconn;
	return psock;
fail:
	__free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}

int get_tcp_connect_handle(void* ptcp)
{
	int conn = -1;
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	if (psock != NULL && psock->m_inconn > 0) {
		conn = psock->m_sock;
	}
	return conn;
}

int complete_tcp_connect(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	int ret = -EINVAL;
	int completed = 0;
	int error;
	socklen_t errlen;

	if (psock == NULL || psock->m_inconn == 0) {
		ret = -EINVAL;
		goto fail;
	}

	errlen = sizeof(error);
	ret = getsockopt(psock->m_sock, SOL_SOCKET, SO_ERROR, &error, &errlen);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (error != 0) {
		ret = error;
		if (ret > 0) {
			ret = -ret;
		}
		ERROR_INFO("connect [%s:%d] error[%d]", psock->m_peeraddr, psock->m_peerport, ret);
		goto fail;
	}

	ret = __get_sock_name(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	completed = 1;
	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int __accept_inner(psock_data_priv_t psock)
{
	int ret;
	socklen_t slen;
	ASSERT_IF(psock->m_accsock < 0);
	slen = sizeof(psock->m_accaddr);
	ret = accept(psock->m_sock, &(psock->m_accaddr), &slen);
	if (ret < 0) {
		GETERRNO(ret);
		if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
			ERROR_INFO("accept [%s:%d] error[%d]", psock->m_selfaddr, psock->m_selfport, ret);
			goto fail;
		}
		psock->m_inacc = 1;
	} else {
		psock->m_accsock = ret;
		psock->m_inacc = 0;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

void* bind_tcp_socket(char* ipaddr, int port, int backlog)
{
	psock_data_priv_t psock = NULL;
	int ret;
	int flags ;
	int opt;
	struct sockaddr saddr;
	struct sockaddr_in* paddr;

	if (ipaddr == NULL || port < 1 || port >= (1 << 16)) {
		ret = -EINVAL;
		goto fail;
	}


	psock = __alloc_sock_priv(SOCKET_SERVER_TYPE, ipaddr, port);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (psock->m_sock < 0) {
		GETERRNO(ret);
		ERROR_INFO("socket server[%s:%d] error[%d]", ipaddr, port, ret);
		goto fail;
	}

	SETERRNO(0);
	flags = fcntl(psock->m_sock, F_GETFL);
	if (flags == -1) {
		GETERRNO_DIRECT(ret);
		if (ret != 0) {
			ERROR_INFO("F_GETFL [%s:%d] error[%d]", ipaddr, port, ret);
			goto fail;
		}
	}

	ret =  fcntl(psock->m_sock, F_SETFL , flags | O_NONBLOCK);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("F_SETFL [%s:%d] error[%d]", ipaddr, port, ret);
		goto fail;
	}

	opt = 1;
	ret = setsockopt(psock->m_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("SO_REUSEADDR [%s:%d] error[%d]", ipaddr, port, ret);
		goto fail;
	}

	memset(&saddr, 0, sizeof(saddr));
	paddr = (struct sockaddr_in*)&saddr;
	paddr->sin_family = AF_INET;
	ret = inet_pton(AF_INET, ipaddr, &(paddr->sin_addr));
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("inet_pton [%s:%d] error[%d]", ipaddr, port, ret);
		goto fail;
	}
	paddr->sin_port = htons(port);

	ret = bind(psock->m_sock, &saddr, sizeof(*paddr));
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("bind [%s:%d] error[%d]", ipaddr, port, ret);
		goto fail;
	}

	ret = listen(psock->m_sock, backlog);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("listen [%s:%d] error[%d]", ipaddr, port, ret);
		goto fail;
	}

	ret = __accept_inner(psock);
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

void* accept_tcp_socket(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	psock_data_priv_t pretsock = NULL;
	int ret;

	if (psock == NULL || psock->m_type != SOCKET_SERVER_TYPE) {
		ret = -EINVAL;
		goto fail;
	}

	if (psock->m_inacc > 0) {
		ret = __accept_inner(psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		if (psock->m_accsock < 0) {
			ret = -EAGAIN;
			ERROR_INFO("no accsock for [%s:%d]", psock->m_selfaddr,psock->m_selfport);
			goto fail;
		}
	}

	ASSERT_IF(psock->m_accsock >= 0);
	pretsock = __alloc_sock_priv(SOCKET_SERVER_TYPE, psock->m_selfaddr, psock->m_selfport);
	if (pretsock == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	pretsock->m_sock = psock->m_accsock;
	psock->m_accsock = -1;

	/*now to get the address*/
	ret = __get_peer_name(pretsock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __accept_inner(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	return pretsock;
fail:
	__free_socket(&pretsock);
	SETERRNO(ret);
	return NULL;
}

int get_tcp_accept_handle(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;
	int retval = -1;
	if (psock != NULL && psock->m_type == SOCKET_SERVER_TYPE &&
	        psock->m_inacc > 0) {
		retval = psock->m_sock;
	}
	return retval;
}

int complete_tcp_accept(void* ptcp)
{
	int ret = 0;
	int completed = 0;
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	if (psock && psock->m_type == SOCKET_SERVER_TYPE ) {
		if (psock->m_inacc > 0) {
			ret = __accept_inner(psock);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}
		completed = psock->m_inacc > 0 ? 0 : 1;
	}

	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int __inner_read(psock_data_priv_t psock)
{
	int ret;

	psock->m_inrd = 0;
	while (psock->m_rdleft > 0) {
		ret = recv(psock->m_sock, psock->m_prdptr, psock->m_rdleft, MSG_DONTWAIT);
		if (ret < 0) {
			GETERRNO(ret);
			if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
				psock->m_inrd = 1;
				break;
			}
			ERROR_INFO("recv [%s:%d] => [%s:%d] on [%d] error[%d]",
			           psock->m_peeraddr, psock->m_peerport,
			           psock->m_selfaddr, psock->m_selfport, psock->m_rdleft,
			           ret);
			goto fail;
		} else if (ret == 0) {
			ret = -EPIPE;
			ERROR_INFO("recv [%s:%d] => [%s:%d] broken",
			           psock->m_peeraddr, psock->m_peerport,
			           psock->m_selfaddr, psock->m_selfport);
			goto fail;
		}

		psock->m_prdptr += ret;
		psock->m_rdleft -= ret;
	}

	if (psock->m_rdleft == 0) {
		/*all is over*/
		psock->m_prdptr = NULL;
	}

	return psock->m_inrd > 0 ? 0 : 1;
fail:
	SETERRNO(ret);
	return ret;
}


int read_tcp_socket(void* ptcp, uint8_t* pbuf, int bufsize)
{
	int ret;
	int completed = 1;
	psock_data_priv_t psock = (psock_data_priv_t)ptcp;

	if (psock == NULL || psock->m_sock < 0 || psock->m_inrd > 0 ) {
		ret = -EINVAL;
		goto fail;
	}

	psock->m_prdptr = pbuf;
	psock->m_rdleft = bufsize;

	ret = __inner_read(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	completed = psock->m_inrd > 0 ? 0 : 1;

	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int get_tcp_read_handle(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	int retval = -1;

	if (psock != NULL && psock->m_inrd > 0) {
		retval = psock->m_sock;
	}
	return retval;
}

int complete_tcp_read(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	int completed = 1;
	int ret;

	if (psock && psock->m_inrd > 0) {
		ret = __inner_read(psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		completed = psock->m_inrd > 0 ? 0 : 1;
	}

	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int __inner_write(psock_data_priv_t psock)
{
	int ret;
	psock->m_inwr = 0;
	while (psock->m_wrleft > 0) {
		ret = send(psock->m_sock, psock->m_pwrptr, psock->m_wrleft, MSG_DONTWAIT);
		if (ret < 0) {
			GETERRNO(ret);
			if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
				psock->m_inwr = 1;
				break;
			}
			ERROR_INFO("send [%s:%d] => [%s:%d] left [%d] error[%d]",
			           psock->m_selfaddr, psock->m_selfport,
			           psock->m_peeraddr, psock->m_peerport,
			           psock->m_wrleft, ret);
			goto fail;
		}
		psock->m_pwrptr += ret;
		psock->m_wrleft -= ret;
	}

	if (psock->m_wrleft == 0) {
		psock->m_pwrptr = NULL;
	}

	return psock->m_inwr > 0 ? 0 : 1;
fail:
	SETERRNO(ret);
	return ret;
}

int write_tcp_socket(void* ptcp, uint8_t* pbuf, int bufsize)
{
	int ret;
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	int completed = 0;

	if (psock == NULL || psock->m_sock < 0 || psock->m_inwr > 0) {
		ret = -EINVAL;
		goto fail;
	}

	psock->m_pwrptr = pbuf;
	psock->m_wrleft = bufsize;

	ret =  __inner_write(psock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	completed = psock->m_inwr > 0 ? 0 : 1;

	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int get_tcp_write_handle(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	int retval = -1;
	if (psock && psock->m_inwr > 0) {
		retval = psock->m_sock;
	}
	return retval;
}

int complete_tcp_write(void* ptcp)
{
	psock_data_priv_t psock = (psock_data_priv_t) ptcp;
	int ret ;
	int completed = 1;
	if (psock && psock->m_inwr > 0) {
		ret = __inner_write(psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		completed = psock->m_inwr > 0 ? 0 : 1;
	}

	return completed;
fail:
	SETERRNO(ret);
	return ret;
}