#include <ux_sock.h>


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

	int m_sock;

	int m_inacc;
	int m_inconn;
	int m_inrd;
	int m_inwr;

} sock_data_priv_t,*psock_data_priv_t;

int init_socket(void)
{
	return 0;
}

void fini_socket(void)
{
	return;
}

void free_socket(void** pptcp)
{
	psock_data_priv_t psock=NULL;
	if (pptcp && *pptcp) {
		psock = (psock_data_priv_t)*pptcp;
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

		psock->m_inconn = 0;
		psock->m_inacc = 0;
		psock->m_inrd = 0;
		psock->m_inwr = 0;

		free(psock);
		*pptcp = NULL;
	}
}

psock_data_priv_t __alloc_sock_priv(int typeval, char* ipaddr, int port)
{
	psock_data_priv_t psock = NULL;
	int ret;
	psock = malloc(sizeof(*psock));
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(psock, 0, sizeof(*psock));
	psock->m_sock = -1;
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
	free_socket(&psock);
	SETERRNO(ret);
	return NULL;	
}

void* connect_tcp_socket(char* ipaddr,int port,char* bindip,int bindport,int connected)
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

	psock = __alloc_sock_priv(SOCKET_CLIENT_TYPE,ipaddr,port);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sock = socket(AF_INET,SOCK_STREAM,0);
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
		memset(&saddr,0,sizeof(saddr));
		paddr = (struct sockaddr_in*)&saddr;
		paddr->sin_family = AF_INET;
		ret = inet_pton(AF_INET,bindip,&(paddr->sin_addr));
		if (ret <= 0) {
			GETERRNO(ret);
			ERROR_INFO("can not change [%s] to sin_addr [%d]", bindip,ret);
			goto fail;
		}
		paddr->sin_port = htons(bindport);

		ret = bind(psock->m_sock,&saddr,sizeof(*paddr));
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("bind [%s:%d] error[%d]", psock->m_selfaddr,psock->m_selfport ,ret);
			goto fail;
		}
	}

	/*to connect*/
	error = 0;
	ret = setsockopt(psock->m_sock,SOL_SOCKET,SO_ERROR,&error,sizeof(error));
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("setsockopt [%s:%d] SO_ERROR error[%d]", psock->m_peeraddr,psock->m_peerport, ret);
		goto fail;
	}

	memset(&saddr,0,sizeof(saddr));
	paddr = (struct sockaddr_in*)&saddr;
	paddr->sin_family = AF_INET;
	ret = inet_pton(AF_INET, ipaddr, &(paddr->sin_addr));
	if (ret <= 0) {
		GETERRNO(ret);
		ERROR_INFO("can not change [%s] to bind addr [%d]", ipaddr, ret);
		goto fail;
	}
	paddr->sin_port = htons(port);
	ret = connect(psock->m_sock, &saddr,sizeof(*paddr));
	if (ret < 0) {
		GETERRNO(ret);
		if (ret != -EINPROGRESS) {
			ERROR_INFO("connect [%s:%d] error[%d]", ipaddr,port, ret);
			goto fail;
		}
		inconn = 1;
	}

	if (connected && inconn > 0) {
		while(1) {
			FD_ZERO(&rfd);
			FD_SET(psock->m_sock , &rfd);
			ret = select(psock->m_sock + 1, &rfd,NULL,NULL,NULL);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			} else if (ret == 0) {
				ret = -ETIMEDOUT;
				ERROR_INFO("connect [%s:%d] timedout", psock->m_peeraddr, psock->m_peerport);
				goto fail;
			} else {
				errlen = sizeof(error);
				ret = getsockopt(psock->m_sock,SOL_SOCKET,SO_ERROR,&error,&errlen);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO("get connect result [%s:%d] error[%d]", psock->m_peeraddr,psock->m_peerport, ret);
					goto fail;
				}
				if (error != 0) {
					ret = error;
					if (ret > 0) {
						ret = -ret;
					}
					ERROR_INFO("connect [%s:%d] result [%d]", psock->m_peeraddr,psock->m_peerport, error);
					goto fail;
				}
				inconn = 0;
			}
		}		
	}

	psock->m_inconn = inconn;
	return psock;
fail:
	free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}

int get_tcp_connect_handle(void* ptcp)
{
	int conn=-1;
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
	struct sockaddr sockaddr;
	struct sockaddr_in* paddr;

	if (psock == NULL || psock->m_inconn ==0) {
		ret = -EINVAL;
		goto fail;
	}

	errlen = sizeof(error);
	ret = getsockopt(psock->m_sock, SOL_SOCKET, SO_ERROR, &error,&errlen);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (error != 0) {
		ret = error;
		if (ret > 0) {
			ret = -ret;
		}
		ERROR_INFO("connect [%s:%d] error[%d]", psock->m_peeraddr,psock->m_peerport, ret);
		goto fail;
	}

	if (psock->m_selfaddr == NULL) {
		memset(&sockaddr,0,sizeof(sockaddr));
		errlen = sizeof(sockaddr);
		ret = getsockname(psock->m_sock, &sockaddr,&errlen);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	completed = 1;


	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

void* bind_tcp_socket(char* ipaddr,int port,int backlog)
{
	psock_data_priv_t psock = NULL;
	int ret;
	int flags ;
	int opt;
	struct sockaddr saddr;
	struct sockaddr_in* paddr;


	psock = __alloc_sock_priv(SOCKET_SERVER_TYPE,ipaddr,port);
	if (psock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	psock->m_sock = socket(AF_INET,SOCK_STREAM,0);
	if (psock->m_sock < 0) {
		GETERRNO(ret);
		ERROR_INFO("socket server[%s:%d] error[%d]", ipaddr,port, ret);
		goto fail;
	}

	SETERRNO(0);
	flags = fcntl(psock->m_sock, F_GETFL);
	if (flags == -1) {
		GETERRNO_DIRECT(ret);
		if (ret != 0) {
			ERROR_INFO("F_GETFL [%s:%d] error[%d]", ipaddr, port,ret);
			goto fail;
		}
	}

	ret=  fcntl(psock->m_sock, F_SETFL , flags | O_NONBLOCK);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("F_SETFL [%s:%d] error[%d]", ipaddr, port,ret);
		goto fail;
	}

	opt = 1;
	ret = setsockopt(psock->m_sock, SOL_SOCKET, SO_REUSEADDR,&opt,sizeof(opt));
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("SO_REUSEADDR [%s:%d] error[%d]", ipaddr, port,ret);
		goto fail;
	}

	memset(&saddr,0,sizeof(saddr));
	paddr = (struct sockaddr_in*)&saddr;
	paddr->sin_family = AF_INET;





	return psock;
fail:
	free_socket(&psock);
	SETERRNO(ret);
	return NULL;
}