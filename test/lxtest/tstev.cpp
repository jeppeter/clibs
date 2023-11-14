
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
	pchatsvr_cli_t pnewcli = NULL;
	nsize = psvr->m_clinum + 1;

	parr = (pchatsvr_cli_t*) malloc(sizeof(*parr) * nsize);
	if (parr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(parr, 0, sizeof(*parr) * nsize);
	if (psvr->m_clinum > 0) {
		memcpy(parr, psvr->m_clisocks, sizeof(*parr) * psvr->m_clinum);
	}
	pnewcli = __alloc_chatsvr_cli(sock);
	if (pnewcli == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	parr[psvr->m_clinum] = pnewcli;
	pnewcli = NULL;
	if (psvr->m_clisocks) {
		free(psvr->m_clisocks);
	}
	psvr->m_clisocks = parr;
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
	int fidx = -1;
	int i;
	pchatsvr_cli_t poldcli = NULL;
	for (i = 0; i < psvr->m_clinum; i++) {
		if (psvr->m_clisocks[i]->m_sock == sock) {
			fidx = i;
			return psvr->m_clisocks[i];
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
				if (psvr->m_clisocks[i] != poldcli) {
					parr[i] = psvr->m_clisocks[i];
				} else if (psvr->m_clisocks[i] == poldcli) {
					finded = 1;
				}
			} else  {
				if (i < nsize) {
					parr[i] = psvr->m_clisocks[i + 1];
				}
			}
		}
	}

	__free_chatsvr_cli(&poldcli);
	if (psvr->m_clisocks) {
		free(psvr->m_clisocks);
	}
	psvr->m_clisocks = parr;
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

	return __add_server_client_write_buffer(poldcli, pbuf, int len);
}

int shrink_chatsvr_cli_buffer(pchatsvr_cli_t psvr, int sock, int len)
{
	pchatsvr_cli_t poldcli = NULL;
	poldcli = __find_server_client(psvr, sock);
	if (poldcli == NULL) {
		return 0;
	}
	return __shrink_server_client_write_buffer(poldcli, len);
}

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
				ret = delete_uxev_callback(pev, sock, poldcli->m_event);
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
				ret = delete_uxev_callback(pev, sock, poldcli->m_event);
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
				ret = __add_server_client_write_buffer(poldcli, rbuf, rlen);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				ret = write(sock, poldcli->m_pwbuf, poldcli->m_wleft);
				if (ret < 0) {
					if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
						if ((poldcli->m_event & WRITE_EVENT) == 0) {
							ret = delete_uxev_callback(pev, sock, poldcli->m_event);
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
					clen = __shrink_server_client_write_buffer(psvr, sock, ret);
					if (clen < 0) {
						GETERRNO(ret);
						goto fail;
					} else if (clen == 0) {
						if (poldcli->m_event != READ_EVENT) {
							ret = delete_uxev_callback(pev, sock, poldcli->m_event);
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
							ret = delete_uxev_callback(pev, sock, poldcli->m_event);
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


int accept_fd_notify(void* pev, uint64_t fd, int event, void* arg)
{
	struct sockaddr_in addr;
	socklen_t socklen;
	int connectfd = -1;
	int tmpfd = -1;
	int ret;
	pchat_svr_t psvr = (pchat_svr_t) arg;
	socklen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	SETERRNO(0);
	connectfd = accept(fd, &addr, &socklen);
	if (connectfd < 0) {
		GETERRNO_DIRECT(ret);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -EINTR || ret == 0) {
			/*for next time*/
			return 0;
		}
		fprintf(stderr, "accept error [%d]\n", ret);
		goto fail;
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

	init_log_verbose(pargs);

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
	}

	exitfd = init_sighandler();
	if (exitfd < 0) {
		GETERRNO(ret);
		goto fail;
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






	ret = 0;

out:
	free_uxev(&pev);
	fini_sighandler();
	exitfd = -1;
	SETERRNO(ret);
	return ret;
}