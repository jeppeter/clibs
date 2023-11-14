
int exit_fd_notify(void* pev, uint64_t fd, int event, void* arg)
{
	break_uxev(pev);
	return 0;
}

typedef struct __chatsvr_cli {
	int m_sock;
	int m_event;
	uint8_t* m_pwbuf;
	int m_wleft;
} chatsvr_cli_t, *pchatsvr_cli_t;

typedef struct __chat_svr {
	int m_bindsock;
	pchatsvr_cli_t* m_clis;
	int m_clinum;
} chat_svr_t, *pchat_svr_t;

void __free_chatsvr_cli(pchatsvr_cli_t* ppcli)
{
	if (ppcli && *ppcli) {
		pchatsvr_cli_t pcli = *ppcli;
		if (pcli->m_sock >= 0) {
			close(pcli->m_sock);
		}
		pcli->m_sock = -1;
		if (pcli->m_pwbuf) {
			free(pcli->m_pwbuf);
		}
		pcli->m_pwbuf = NULL;
		pcli->m_wleft = 0;
		free(pcli);
		*ppcli = NULL;
	}
}


pchatsvr_cli_t __alloc_chatsvr_cli(int sock)
{
	pchatsvr_cli_t pcli = NULL;
	int ret;

	pcli = (pchatsvr_cli_t) malloc(sizeof(*pcli));
	if (pcli == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pcli, 0, sizeof(*pcli));
	pcli->m_sock = sock;
	pcli->m_event = READ_EVENT;
	pcli->m_pwbuf = NULL;
	pcli->m_wleft = 0;

	return pcli;
fail:
	__free_chatsvr_cli(&pcli);
	SETERRNO(ret);
	return NULL;
}



int add_server_client_socket(pchat_svr_t psvr, int sock)
{
	pchatsvr_cli_t*parr = NULL;
	int nsize = 0;
	int ret;
	pchatsvr_cli_t pnewcli = NULL;
	nsize = psvr->m_clinum + 1;

	parr = (pchatsvr_cli_t*) malloc(sizeof(*parr) * nsize);
	if (parr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(parr, 0, sizeof(*parr) * nsize);
	if (psvr->m_clinum > 0) {
		memcpy(parr, psvr->m_clis, sizeof(*parr) * psvr->m_clinum);
	}
	pnewcli = __alloc_chatsvr_cli(sock);
	if (pnewcli == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	parr[psvr->m_clinum] = pnewcli;
	pnewcli = NULL;
	if (psvr->m_clis) {
		free(psvr->m_clis);
	}
	psvr->m_clis = parr;
	parr = NULL;
	psvr->m_clinum = nsize;
	return nsize;
fail:
	if (parr) {
		free(parr);
	}
	parr = NULL;
	__free_chatsvr_cli(&pnewcli);
	SETERRNO(ret);
	return ret;
}

pchatsvr_cli_t __find_server_client(pchat_svr_t psvr, int sock)
{
	int i;
	for (i = 0; i < psvr->m_clinum; i++) {
		if (psvr->m_clis[i]->m_sock == sock) {
			return psvr->m_clis[i];
		}
	}
	return NULL;
}

int remove_server_client_sock(pchat_svr_t psvr, int sock)
{
	int i;
	int nsize;
	pchatsvr_cli_t* parr = NULL;
	pchatsvr_cli_t poldcli = NULL;
	int finded = 0;
	int ret;
	poldcli = __find_server_client(psvr, sock);
	if (poldcli == NULL) {
		return 0;
	}

	nsize = psvr->m_clinum - 1;
	if (nsize > 0) {
		parr = (pchatsvr_cli_t*) malloc(sizeof(*parr) * nsize);
		if (parr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(parr, 0, sizeof(*parr) * nsize);
		for (i = 0; i < psvr->m_clinum; i++) {
			if (finded == 0) {
				if (psvr->m_clis[i] != poldcli) {
					parr[i] = psvr->m_clis[i];
				} else if (psvr->m_clis[i] == poldcli) {
					finded = 1;
				}
			} else  {
				if (i < nsize) {
					parr[i] = psvr->m_clis[i + 1];
				}
			}
		}
	}

	__free_chatsvr_cli(&poldcli);
	if (psvr->m_clis) {
		free(psvr->m_clis);
	}
	psvr->m_clis = parr;
	parr = NULL;
	psvr->m_clinum = nsize;
	return nsize;
fail:
	__free_chatsvr_cli(&poldcli);
	if (parr) {
		free(parr);
	}
	parr = NULL;
	SETERRNO(ret);
	return ret;
}

int __add_server_client_write_buffer(pchatsvr_cli_t pcli, uint8_t* pbuf, int len)
{
	uint8_t* pnewbuf = NULL;
	int nsize = 0;
	int ret;

	nsize = pcli->m_wleft + len;
	pnewbuf = (uint8_t*)malloc(sizeof(*pnewbuf) * nsize);
	if (pnewbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pnewbuf, 0, nsize);
	if (pcli->m_wleft > 0) {
		memcpy(pnewbuf, pcli->m_pwbuf, pcli->m_wleft);
	}
	memcpy(&pnewbuf[pcli->m_wleft], pbuf, len);
	if (pcli->m_pwbuf) {
		free(pcli->m_pwbuf);
	}
	pcli->m_pwbuf = pnewbuf;
	pnewbuf = NULL;
	pcli->m_wleft = nsize;
	return nsize;

fail:
	if (pnewbuf) {
		free(pnewbuf);
	}
	pnewbuf = NULL;
	SETERRNO(ret);
	return ret;
}

int __shrink_server_client_write_buffer(pchatsvr_cli_t pcli, int len)
{
	int nsize = pcli->m_wleft - len;
	uint8_t* pnewbuf = NULL;
	int ret ;
	if (nsize > 0) {
		pnewbuf = (uint8_t*) malloc(sizeof(*pnewbuf) * nsize);
		if (pnewbuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memcpy(pnewbuf, &pcli->m_pwbuf[len], nsize);
	}
	if (pcli->m_pwbuf) {
		free(pcli->m_pwbuf);
	}
	pcli->m_pwbuf = pnewbuf;
	pnewbuf = NULL;
	if (nsize > 0) {
		pcli->m_wleft = nsize;
	} else {
		pcli->m_wleft = 0;
	}
	return pcli->m_wleft;
fail:
	if (pnewbuf) {
		free(pnewbuf);
	}
	pnewbuf = NULL;
	SETERRNO(ret);
	return ret;
}

int add_chatsvr_cli_buffer(pchat_svr_t psvr, int sock, uint8_t* pbuf, int len)
{
	pchatsvr_cli_t poldcli = NULL;
	poldcli = __find_server_client(psvr, sock);
	if (poldcli == NULL) {
		return 0;
	}

	return __add_server_client_write_buffer(poldcli, pbuf, len);
}

int shrink_chatsvr_cli_buffer(pchat_svr_t psvr, int sock, int len)
{
	pchatsvr_cli_t poldcli = NULL;
	poldcli = __find_server_client(psvr, sock);
	if (poldcli == NULL) {
		return 0;
	}
	return __shrink_server_client_write_buffer(poldcli, len);
}

void __free_chatsvr(pchat_svr_t* ppsvr)
{
	if (ppsvr && *ppsvr) {
		pchat_svr_t psvr = *ppsvr;
		int i;
		for(i=0;i<psvr->m_clinum;i++) {
			__free_chatsvr_cli(&psvr->m_clis[i]);
		}
		free(psvr->m_clis);
		psvr->m_clis = NULL;
		psvr->m_clinum = 0;
		if (psvr->m_bindsock >= 0) {
			close(psvr->m_bindsock);
		}
		psvr->m_bindsock = -1;
		free(psvr);
		*ppsvr = NULL;
	}
}

int bind_chat_server(int port)
{
	int sock=-1;
	int ret;
	int reuse = 1;
	struct sockaddr_in sinaddr;

	sock = socket(AF_INET,SOCK_STREAM,0);
	if (sock < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = 	setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&reuse, sizeof(reuse));
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not set reuse error [%d]\n", ret);
		goto fail;
	}

	ret = ioctl(sock,FIONBIO,&reuse);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "set non-block error[%d]\n", ret);
		goto fail;
	}

	memset(&sinaddr,0,sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_addr.s_addr = inet_addr("0.0.0.0");
	sinaddr.sin_port = htons(port);
	ret = bind(sock,(struct sockaddr*)&sinaddr,sizeof(sinaddr));
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "bind [%d] error[%d]\n", port,ret);
		goto fail;
	}

	ret = listen(sock,5);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "listen on [%d] error[%d]\n", port, ret);
		goto fail;
	}

	return sock;
fail:
	if (sock >= 0) {
		close(sock);
	}
	sock = -1;
	SETERRNO(ret);
	return ret;
}


pchat_svr_t __alloc_chatsvr(int port)
{
	pchat_svr_t psvr = NULL;
	int ret;

	psvr = (pchat_svr_t)malloc(sizeof(*psvr));
	if (psvr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(psvr,0,sizeof(*psvr));
	psvr->m_bindsock = -1;
	psvr->m_clis = NULL;
	psvr->m_clinum = 0;

	psvr->m_bindsock = bind_chat_server(port);
	if (psvr->m_bindsock < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return psvr;
fail:
	__free_chatsvr(&psvr);
	SETERRNO(ret);
	return NULL;
}

int read_server_notify(void* pev, uint64_t sock, int event, void* arg);

int write_server_notify(void* pev, uint64_t sock, int event, void* arg)
{
	pchatsvr_cli_t poldcli = NULL;
	pchat_svr_t psvr = (pchat_svr_t)arg;
	int ret;
	int wlen;
	if ((event & WRITE_EVENT) != 0) {
		poldcli = __find_server_client(psvr, sock);
		if (poldcli != NULL) {
			if (poldcli->m_wleft > 0)
				ret = write(sock, poldcli->m_pwbuf, poldcli->m_wleft);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			wlen = ret;
			ret = __shrink_server_client_write_buffer(poldcli, wlen);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			if (ret == 0) {
				ret = delete_uxev_callback(pev, sock);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				ret = add_uxev_callback(pev, sock, READ_EVENT, read_server_notify, pev);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				poldcli->m_event = READ_EVENT;
			}
		}
	}

	ret = read_server_notify(pev, sock, event, arg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int read_server_notify(void* pev, uint64_t sock, int event, void* arg)
{
	char rbuf[1024];
	int rlen = 0;
	int clen ;
	pchatsvr_cli_t poldcli = NULL;
	pchat_svr_t psvr = (pchat_svr_t) arg;
	int ret;
	if ((event & READ_EVENT) != 0) {
		SETERRNO(0);
		poldcli = __find_server_client(psvr, sock);
		if (poldcli != NULL) {
			ret = read(sock, rbuf, sizeof(rbuf));
			if (ret < 0) {
				GETERRNO_DIRECT(ret);
				if (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == 0) {
					return 0;
				}
				fprintf(stderr, "read sock error[%d]\n", ret);
				goto fail;
			} else if (ret == 0) {
				ret = delete_uxev_callback(pev, sock);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				ret = remove_server_client_sock(psvr, sock);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
			} else {
				ret = __add_server_client_write_buffer(poldcli, (uint8_t*)rbuf, rlen);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				ret = write(sock, poldcli->m_pwbuf, poldcli->m_wleft);
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						if ((poldcli->m_event & WRITE_EVENT) == 0) {
							ret = delete_uxev_callback(pev, sock);
							if (ret < 0) {
								GETERRNO(ret);
								goto fail;
							}
							ret = add_uxev_callback(pev, sock, READ_EVENT | WRITE_EVENT, write_server_notify, arg);
							if (ret < 0) {
								GETERRNO(ret);
								goto fail;
							}
							poldcli->m_event = READ_EVENT | WRITE_EVENT;
						}
					}
				} else if (ret >= 0) {
					clen = __shrink_server_client_write_buffer(poldcli, ret);
					if (clen < 0) {
						GETERRNO(ret);
						goto fail;
					} else if (clen == 0) {
						if (poldcli->m_event != READ_EVENT) {
							ret = delete_uxev_callback(pev, sock);
							if (ret < 0) {
								GETERRNO(ret);
								goto fail;
							}
							ret = add_uxev_callback(pev, sock, READ_EVENT, read_server_notify, arg);
							if ( ret < 0 ) {
								GETERRNO(ret);
								goto fail;
							}
							poldcli->m_event = READ_EVENT;
						}

					} else if (clen > 0) {
						if (poldcli->m_event != (READ_EVENT | WRITE_EVENT)) {
							ret = delete_uxev_callback(pev, sock);
							if (ret < 0) {
								GETERRNO(ret);
								goto fail;
							}
							ret = add_uxev_callback(pev, sock, READ_EVENT, write_server_notify, arg);
							if ( ret < 0 ) {
								GETERRNO(ret);
								goto fail;
							}
							poldcli->m_event = READ_EVENT | WRITE_EVENT;
						}
					}
				}
			}
		}
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


int accept_server_notify(void* pev, uint64_t fd, int event, void* arg)
{
	struct sockaddr_in addr;
	socklen_t socklen;
	int connectfd = -1;
	int tmpfd = -1;
	int ret;
	int flags = 0;
	pchat_svr_t psvr = (pchat_svr_t) arg;
	socklen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	SETERRNO(0);
	connectfd = accept(fd, (struct sockaddr*)&addr, &socklen);
	if (connectfd < 0) {
		GETERRNO_DIRECT(ret);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -EINTR || ret == 0) {
			/*for next time*/
			return 0;
		}
		fprintf(stderr, "accept error [%d]\n", ret);
		goto fail;
	}

	flags = fcntl(connectfd,F_GETFD,0);
	ret = fcntl(connectfd,F_SETFD,flags | O_NONBLOCK);
	if (ret < 0) {
		close(connectfd);
		connectfd = -1;
		return 0;
	}

	ret = add_server_client_socket(psvr, connectfd);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	tmpfd = connectfd;
	connectfd = -1;

	ret = add_uxev_callback(pev, tmpfd, READ_EVENT, read_server_notify, arg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	if (connectfd >= 0) {
		close(connectfd);
	}
	connectfd = -1;
	SETERRNO(ret);
	return ret;
}



int evchatsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	int port = 3390;
	void* pev = NULL;
	int exitfd = -1;
	pchat_svr_t psvr=NULL;

	init_log_verbose(pargs);

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
	}

	exitfd = init_sighandler();
	if (exitfd < 0) {
		GETERRNO(ret);
		goto out;
	}

	pev = init_uxev(0);
	if (pev == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "init_uxev error[%d]\n", ret);
		goto out;
	}

	ret = add_uxev_callback(pev, exitfd, READ_EVENT, exit_fd_notify, NULL);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "add exit_fd_notify error[%d]\n", ret);
		goto out;
	}

	psvr = __alloc_chatsvr(port);
	if (psvr == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret = add_uxev_callback(pev,psvr->m_bindsock,READ_EVENT,accept_server_notify,psvr);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = loop_uxev(pev);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}
	ret = 0;
out:
	free_uxev(&pev);
	fini_sighandler();
	exitfd = -1;
	__free_chatsvr(&psvr);
	SETERRNO(ret);
	return ret;
}

typedef __chatcli {
	char* m_ip;
	int port;
	int m_sock;
	int m_fd;
	int m_connected;
	uint8_t* m_pwbuf;
	int m_wleft;
} chatcli_t,*pchatcli_t;

void __free_chatcli(pchatcli_t* ppcli)
{
	if (ppcli && *ppcli) {
		pchatcli_t pcli = *ppcli;
		if (pcli->m_ip) {
			free(pcli->m_ip);
		}
		pcli->m_ip = NULL;
		if (pcli->m_sock >= 0) {
			close(pcli->m_sock);
		}
		pcli->m_sock = -1;
		pcli->m_fd = -1;
		pcli->m_connected = 0;
		if (pcli->m_pwbuf) {
			free(pcli->m_pwbuf);
		}
		pcli->m_pwbuf = NULL;
		pcli->m_wleft = 0;
		free(pcli);
		*ppcli = NULL;
	}
}

pchatcli_t __alloc_chatcli(const char* ip,int port,int readfd)
{
	pchatcli_t pcli=NULL;
	int ret;
	struct sockaddr_in sinaddr;

	pcli = (pchatcli_t) malloc(sizeof(*pcli));
	if (pcli == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pcli,0,sizeof(*pcli));
	pcli->m_ip = NULL;
	pcli->m_port = 0;
	pcli->m_sock = -1;
	pcli->m_fd = readfd;
	pcli->m_connected = 0;
	pcli->m_pwbuf = NULL;
	pcli->m_wleft = 0;

	pcli->m_ip = strdup(ip);
	if (pcli->m_ip == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	pcli->m_port = port;

	pcli->m_sock = socket(AF_INET,SOCK_STREAM,0);
	if (pcli->m_sock < 0) {
		GETERRNO(ret);
		goto fail;
	}

	flags = fcntl(pcli->m_sock, F_GETFD,0);
	ret = fcntl(pcli->m_sock,F_SETFD,flags | O_NONBLOCK);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}



	return pcli;
fail:
	__free_chatcli(&pcli);
	SETERRNO(ret);
	return NULL;
}


int chat_cli_timeout(void* pev,uint64_t timeid, int event, void* arg)
{

}

int chat_cli_connect(void* pev,uint64_t sock, int event,void* arg)
{

}

int chat_cli_write(void* pev,uint64_t sock,int event,void* arg)
{

}

int chat_cli_read(void* pev,uint64_t sock,int event,void* arg)
{

}

int chat_cli_input(void* pev,uint64_t fd, int event,void* arg)
{

}
int evchatcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	char* ip= "127.0.0.1";
	int port = 3390;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;
	init_log_verbose(pargs);

	if (parsestate->leftargs) {
		if (parsestate->leftargs[0]) {
			ip = parsestate->leftargs[0];
			if (parsestate->leftargs[1]) {
				port = atoi(parsestate->leftargs[1]);
			}
		}
	}




	ret = 0;
out:
	SETERRNO(ret);
	return ret;
}