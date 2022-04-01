

int tstsockconn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	const char* ipaddr = NULL;
	int port = 0;
	const char* bindip = NULL;
	int bindport = 0;
	int connected = 0;
	int evfd = -1;
	int connectfd = -1;
	struct epoll_event evt;
	struct epoll_event getevt;

	init_log_verbose(pargs);

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not init_socket [%d]\n", ret);
		goto out;
	}

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		ipaddr = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			port = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				if (strcmp(parsestate->leftargs[2], "NULL") != 0) {
					bindip = parsestate->leftargs[2];
				}
				if (parsestate->leftargs[3]) {
					bindport = atoi(parsestate->leftargs[3]);
					if (parsestate->leftargs[4]) {
						connected = atoi(parsestate->leftargs[4]);
					}
				}
			}
		}
	}

	if (ipaddr == NULL) {
		fprintf(stderr, "must host specified\n");
		ret = -EINVAL;
		goto out;
	}

	psock = connect_tcp_socket(ipaddr, port, bindip, bindport, connected);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] bind [%s:%d] error[%d]\n",
		        ipaddr, port, bindip != NULL ? bindip : "NULL", bindport, ret);
		goto out;
	}

	evfd = epoll_create(1);
	if (evfd < 0) {
		GETERRNO(ret);
		fprintf(stderr, "epoll_create [%d]\n", ret);
		goto out;
	}

	connectfd = get_tcp_connect_handle(psock);
	if (connectfd >= 0) {
		memset(&evt, 0, sizeof(evt));
		evt.events = (EPOLLOUT | EPOLLET);
		evt.data.fd = connectfd;
		ret = epoll_ctl(evfd, EPOLL_CTL_ADD, connectfd, &evt);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not add connectfd [%d] error[%d]\n", connectfd, ret);
			goto out;
		}
		ret = epoll_wait(evfd, &getevt, 1, pargs->m_timeout);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "epoll_wait error[%d]\n", ret);
			goto out;
		} else if (ret == 0) {
			ret = -ETIMEDOUT;
			fprintf(stderr, "epoll_wait timeout\n");
			goto out;
		}

		if (getevt.data.fd != connectfd || getevt.events != EPOLLOUT) {
			ret = -EINVAL;
			fprintf(stderr, "getevt.data.fd [%d] != connectfd [%d] || getevt.events [%d] != EPOLLOUT [%d]\n", getevt.data.fd, connectfd,
			        getevt.events, EPOLLOUT);
			goto out;
		}
		ret = complete_tcp_connect(psock);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "complete [%s:%d] error[%d]\n", ipaddr, port, ret);
			goto out;
		} else if (ret == 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not complete [%s:%d]\n", ipaddr, port);
			goto out;
		}
	}

	fprintf(stdout, "connect [%s:%d] bind[%s:%d] connected[%d] succ\n", ipaddr, port,
	        bindip ? bindip : "NULL", bindport, connected);
	ret = 0;
out:
	if (evfd >= 0) {
		close(evfd);
	}
	evfd = -1;
	free_socket(&psock);
	fini_socket();
	SETERRNO(ret);
	return ret;
}

int tstsockacc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	const char* bindip = "0.0.0.0";
	int bindport = 0;
	int backlog = 5;
	int evfd = -1;
	int bindfd = -1;
	struct epoll_event evt;
	struct epoll_event getevt;
	void* paccsock = NULL;

	init_log_verbose(pargs);

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not init_socket [%d]\n", ret);
		goto out;
	}

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		bindport = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			bindip = parsestate->leftargs[1];
			if (parsestate->leftargs[2]) {
				backlog = atoi(parsestate->leftargs[2]);
			}
		}
	}


	psock = bind_tcp_socket(bindip, bindport, backlog);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "bind [%s:%d] error[%d]\n", bindip, bindport, ret);
		goto out;
	}



	evfd = epoll_create(1);
	if (evfd < 0) {
		GETERRNO(ret);
		fprintf(stderr, "epoll_create [%d]\n", ret);
		goto out;
	}

	bindfd = get_tcp_accept_handle(psock);
	if (bindfd >= 0) {
		memset(&evt, 0, sizeof(evt));
		evt.events = (EPOLLIN | EPOLLET);
		evt.data.fd = bindfd;
		ret = epoll_ctl(evfd, EPOLL_CTL_ADD, bindfd, &evt);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not add bindfd [%d] error[%d]\n", bindfd, ret);
			goto out;
		}
		ret = epoll_wait(evfd, &getevt, 1, pargs->m_timeout);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "epoll_wait error[%d]\n", ret);
			goto out;
		} else if (ret == 0) {
			ret = -ETIMEDOUT;
			fprintf(stderr, "epoll_wait timeout\n");
			goto out;
		}

		if (getevt.data.fd != bindfd || getevt.events != EPOLLIN) {
			ret = -EINVAL;
			fprintf(stderr, "getevt.data.fd [%d] != bindfd [%d] or getevt.events [%d] != EPOLLIN [%d]\n", getevt.data.fd, bindfd,
			        getevt.events, EPOLLIN);
			goto out;
		}
		DEBUG_INFO("getevt.events [%d]", getevt.events);
	}

	paccsock = accept_tcp_socket(psock);
	if (paccsock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not accept [%s:%d] error[%d]\n", bindip, bindport, ret);
		goto out;
	}

	fprintf(stdout, "bind [%s:%d] accept succ\n", bindip , bindport);
	ret = 0;
out:
	if (evfd >= 0) {
		close(evfd);
	}
	evfd = -1;
	free_socket(&paccsock);
	free_socket(&psock);
	fini_socket();
	SETERRNO(ret);
	return ret;
}

int tstclisockrd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	const char* ipaddr = NULL;
	int port = 0;
	int length = 1024;
	const char* bindip = NULL;
	int bindport = 0;
	int connected = 0;
	int evfd = -1;
	int connectfd = -1;
	int readfd = -1;
	int insertread = 0;
	struct epoll_event evt;
	struct epoll_event getevt;
	uint8_t* pbuf = NULL;
	int cnt = 0;

	init_log_verbose(pargs);

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not init_socket [%d]\n", ret);
		goto out;
	}

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		ipaddr = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			port = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				length = atoi(parsestate->leftargs[2]);
			}
		}
	}

	if (ipaddr == NULL) {
		fprintf(stderr, "must host specified\n");
		ret = -EINVAL;
		goto out;
	}

	psock = connect_tcp_socket(ipaddr, port, bindip, bindport, connected);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] bind [%s:%d] error[%d]\n",
		        ipaddr, port, bindip != NULL ? bindip : "NULL", bindport, ret);
		goto out;
	}

	evfd = epoll_create(1);
	if (evfd < 0) {
		GETERRNO(ret);
		fprintf(stderr, "epoll_create [%d]\n", ret);
		goto out;
	}

	connectfd = get_tcp_connect_handle(psock);
	if (connectfd >= 0) {
		memset(&evt, 0, sizeof(evt));
		evt.events = (EPOLLOUT | EPOLLET);
		evt.data.fd = connectfd;
		ret = epoll_ctl(evfd, EPOLL_CTL_ADD, connectfd, &evt);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not add connectfd [%d] error[%d]\n", connectfd, ret);
			goto out;
		}

		while (1) {
			ret = epoll_wait(evfd, &getevt, 1, pargs->m_timeout);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "epoll_wait error[%d]\n", ret);
				goto out;
			} else if (ret > 0) {
				break;
			}
			DEBUG_INFO("wait connect [%d]", cnt);
			cnt ++;
		}

		if (getevt.data.fd != connectfd || getevt.events != EPOLLOUT) {
			ret = -EINVAL;
			fprintf(stderr, "getevt.data.fd [%d] != connectfd [%d] || getevt.events [%d] != EPOLLOUT [%d]\n", getevt.data.fd, connectfd,
			        getevt.events, EPOLLOUT);
			goto out;
		}
		DEBUG_INFO("getevt.events [%d]", getevt.events);
		ret = complete_tcp_connect(psock);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "complete [%s:%d] error[%d]\n", ipaddr, port, ret);
			goto out;
		} else if (ret == 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not complete [%s:%d]\n", ipaddr, port);
			goto out;
		}

		memset(&evt, 0, sizeof(evt));
		evt.events = (EPOLLOUT | EPOLLET);
		evt.data.fd = connectfd;
		ret = epoll_ctl(evfd, EPOLL_CTL_DEL, connectfd, &evt);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "EPOLL_CTL_DEL error[%d]\n", ret);
			goto out;
		}

	}

	pbuf = (uint8_t*)malloc(length);
	if (pbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret = read_tcp_socket(psock, pbuf, length);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "read [%s:%d] length [%d] error[%d]\n", ipaddr, port, length, ret);
		goto out;
	}

	if (ret == 0) {
		while (1) {
			readfd = get_tcp_read_handle(psock);
			if (readfd < 0) {
				GETERRNO(ret);
				fprintf(stderr, "can not get read handle [%d]\n", ret);
				goto out;
			}

			if (insertread == 0) {
				memset(&evt, 0, sizeof(evt));
				evt.events = (EPOLLIN | EPOLLET);
				evt.data.fd = readfd;
				ret = epoll_ctl(evfd, EPOLL_CTL_ADD, readfd, &evt);
				if (ret < 0) {
					GETERRNO(ret);
					fprintf(stderr, "add readfd [%s:%d] error[%d]\n", ipaddr, port, ret);
					goto out;
				}
				insertread = 1;
			}

			ret = epoll_wait(evfd, &getevt, 1, pargs->m_timeout);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "epoll_wait [%s:%d] read error[%d]\n", ipaddr, port, ret);
				goto out;
			} else if (ret == 0) {
				ret = -ETIMEDOUT;
				fprintf(stderr, "epoll_wait [%s:%d] read timeout\n", ipaddr, port);
				goto out;
			}



			ret = complete_tcp_read(psock);
			DEBUG_INFO("complete read [%s:%d] [%d]", ipaddr, port, ret);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "complete read [%s:%d] error[%d]\n", ipaddr, port, ret);
				goto out;
			} else if (ret > 0) {
				break;
			}
		}

	}

	DEBUG_BUFFER_FMT(pbuf, length, "read [%s:%d] succ", ipaddr, port);

	ret = 0;
out:
	if (evfd >= 0) {
		close(evfd);
	}
	evfd = -1;
	free_socket(&psock);
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	fini_socket();
	SETERRNO(ret);
	return ret;
}

int tstsvrsockwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	const char* bindip = "0.0.0.0";
	int bindport = 0;
	int backlog = 5;
	int evfd = -1;
	int bindfd = -1;
	struct epoll_event evt;
	struct epoll_event getevt;
	void* paccsock = NULL;
	char* fname = NULL;
	char* pbuf = NULL;
	int bufsize = 0, buflen = 0;
	int wrlen = 0;
	int curlen = 0;
	int perlength = 1024;
	int wrinserted = 0;
	int wrfd = -1;
	int cnt = 0;

	init_log_verbose(pargs);

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not init_socket [%d]\n", ret);
		goto out;
	}

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		bindport = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			fname = parsestate->leftargs[1];
			if (parsestate->leftargs[2]) {
				perlength = atoi(parsestate->leftargs[2]);
				if (parsestate->leftargs[3]) {
					bindip = parsestate->leftargs[3];
					if (parsestate->leftargs[4]) {
						backlog = atoi(parsestate->leftargs[4]);
					}
				}
			}
		}
	}

	if (fname == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "need fname\n");
		goto out;
	}

	ret = read_file_whole(fname, &pbuf, &bufsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "read fname [%s] error[%d]\n", fname, ret);
		goto out;
	}
	buflen = ret;

	psock = bind_tcp_socket(bindip, bindport, backlog);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "bind [%s:%d] error[%d]\n", bindip, bindport, ret);
		goto out;
	}

	evfd = epoll_create(1);
	if (evfd < 0) {
		GETERRNO(ret);
		fprintf(stderr, "epoll_create [%d]\n", ret);
		goto out;
	}

	bindfd = get_tcp_accept_handle(psock);
	if (bindfd >= 0) {
		memset(&evt, 0, sizeof(evt));
		evt.events = (EPOLLIN | EPOLLET);
		evt.data.fd = bindfd;
		ret = epoll_ctl(evfd, EPOLL_CTL_ADD, bindfd, &evt);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not add bindfd [%d] error[%d]\n", bindfd, ret);
			goto out;
		}
		while (1) {
			ret = epoll_wait(evfd, &getevt, 1, pargs->m_timeout);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "epoll_wait error[%d]\n", ret);
				goto out;
			} else if (ret > 0) {
				break;
			}
			DEBUG_INFO("wait on [%d]", cnt);
			cnt ++;
		}

		if (getevt.data.fd != bindfd || getevt.events != EPOLLIN) {
			ret = -EINVAL;
			fprintf(stderr, "getevt.data.fd [%d] != bindfd [%d] or getevt.events [%d] != EPOLLIN [%d]\n", getevt.data.fd, bindfd,
			        getevt.events, EPOLLIN);
			goto out;
		}
		DEBUG_INFO("getevt.events [%d]", getevt.events);
		ret = epoll_ctl(evfd, EPOLL_CTL_DEL, bindfd, &evt);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "delete accept event error[%d]\n", ret);
			goto out;
		}
	}

	paccsock = accept_tcp_socket(psock);
	if (paccsock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not accept [%s:%d] error[%d]\n", bindip, bindport, ret);
		goto out;
	}

	while (wrlen < buflen) {
		curlen = perlength;
		if (curlen > (buflen - wrlen)) {
			curlen = buflen - wrlen;
		}

		ret = write_tcp_socket(paccsock, (uint8_t*) & (pbuf[wrlen]), curlen);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "write [%s] at [%d] error[%d]\n", fname, wrlen, ret);
			goto out;
		}

		if (ret > 0) {
			wrlen += curlen;
			continue;
		}

		wrfd = get_tcp_write_handle(paccsock);
		if (wrfd < 0) {
			GETERRNO(ret);
			fprintf(stderr, "get write handle error[%d]\n", ret);
			goto out;
		}

		if (wrinserted == 0) {
			memset(&evt, 0, sizeof(evt));
			evt.events = (EPOLLOUT | EPOLLET);
			evt.data.fd = wrfd;
			ret = epoll_ctl(evfd, EPOLL_CTL_ADD, wrfd, &evt);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "can not insert wrfd [%d]\n", ret);
				goto out;
			}
			wrinserted = 1;
		}

		while (1) {
			ret = epoll_wait(evfd, &getevt, 1, pargs->m_timeout);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "epoll_wait [%s:%d] error[%d]\n", bindip, bindport, ret );
				goto out;
			} else if (ret == 0) {
				ret = -ETIMEDOUT;
				fprintf(stderr, "epoll_wait [%s:%d] timeout\n", bindip, bindport);
				goto out;
			}

			ret = complete_tcp_write(paccsock);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "complete write [%d] wait error[%d]\n", wrlen, ret);
				goto out;
			} else if (ret > 0) {
				wrlen += curlen;
				break;
			}
		}
	}

	fprintf(stderr, "write [%s:%d] fname [%s] buflen [%d] succ\n", bindip, bindport, fname, buflen);

	ret = 0;
out:
	if (evfd >= 0) {
		close(evfd);
	}
	evfd = -1;
	free_socket(&paccsock);
	free_socket(&psock);
	read_file_whole(NULL, &pbuf, &bufsize);
	buflen = 0;
	fini_socket();
	SETERRNO(ret);
	return ret;
}

int tstclisockwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	const char* ipaddr = NULL;
	int port = 0;
	const char* bindip = NULL;
	int bindport = 0;
	int connected = 0;
	int evfd = -1;
	int connectfd = -1;
	struct epoll_event evt;
	struct epoll_event getevt;
	int cnt = 0;
	char* fname = NULL;
	char* pbuf = NULL;
	int bufsize = 0, buflen = 0;
	int perlength = 1024;
	int wrlen = 0;
	int curlen,wrinserted=0;
	int wrfd = -1;

	init_log_verbose(pargs);

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not init_socket [%d]\n", ret);
		goto out;
	}

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		ipaddr = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			port = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				fname = parsestate->leftargs[2];
				if (parsestate->leftargs[3]) {
					perlength = atoi(parsestate->leftargs[3]);
					if (parsestate->leftargs[4]) {
						bindip = parsestate->leftargs[4];
						if (parsestate->leftargs[5]) {
							bindport = atoi(parsestate->leftargs[5]);
							if (parsestate->leftargs[6]) {
								connected = atoi(parsestate->leftargs[6]);
							}
						}
					}
				}
			}
		}
	}

	if (ipaddr == NULL || fname == NULL) {
		fprintf(stderr, "must host or fname specified\n");
		ret = -EINVAL;
		goto out;
	}

	ret = read_file_whole(fname,&pbuf,&bufsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "read [%s] error[%d]\n", fname, ret);
		goto out;
	}
	buflen = ret;

	psock = connect_tcp_socket(ipaddr, port, bindip, bindport, connected);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] bind [%s:%d] error[%d]\n",
		        ipaddr, port, bindip != NULL ? bindip : "NULL", bindport, ret);
		goto out;
	}

	evfd = epoll_create(1);
	if (evfd < 0) {
		GETERRNO(ret);
		fprintf(stderr, "epoll_create [%d]\n", ret);
		goto out;
	}

	connectfd = get_tcp_connect_handle(psock);
	if (connectfd >= 0) {
		memset(&evt, 0, sizeof(evt));
		evt.events = (EPOLLOUT | EPOLLET);
		evt.data.fd = connectfd;
		ret = epoll_ctl(evfd, EPOLL_CTL_ADD, connectfd, &evt);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not add connectfd [%d] error[%d]\n", connectfd, ret);
			goto out;
		}

		while (1) {
			ret = epoll_wait(evfd, &getevt, 1, pargs->m_timeout);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "epoll_wait error[%d]\n", ret);
				goto out;
			} else if (ret > 0) {
				break;
			}
			DEBUG_INFO("wait connect [%d]", cnt);
			cnt ++;
		}

		if (getevt.data.fd != connectfd ) {
			ret = -EINVAL;
			fprintf(stderr, "getevt.data.fd [%d] != connectfd [%d] \n", getevt.data.fd, connectfd);
			goto out;
		}
		DEBUG_INFO("getevt.events [%d]", getevt.events);
		ret = complete_tcp_connect(psock);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "complete [%s:%d] error[%d]\n", ipaddr, port, ret);
			goto out;
		} else if (ret == 0) {
			GETERRNO(ret);
			fprintf(stderr, "can not complete [%s:%d]\n", ipaddr, port);
			goto out;
		}

		memset(&evt, 0, sizeof(evt));
		evt.events = (EPOLLOUT | EPOLLET);
		evt.data.fd = connectfd;
		ret = epoll_ctl(evfd, EPOLL_CTL_DEL, connectfd, &evt);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "EPOLL_CTL_DEL error[%d]\n", ret);
			goto out;
		}
	}

	while (wrlen < buflen) {
		curlen = perlength;
		if (curlen > (buflen - wrlen)) {
			curlen = buflen - wrlen;
		}

		ret = write_tcp_socket(psock, (uint8_t*) & (pbuf[wrlen]), curlen);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "write [%s] at [%d] error[%d]\n", fname, wrlen, ret);
			goto out;
		}

		if (ret > 0) {
			wrlen += curlen;
			continue;
		}

		wrfd = get_tcp_write_handle(psock);
		if (wrfd < 0) {
			GETERRNO(ret);
			fprintf(stderr, "get write handle error[%d]\n", ret);
			goto out;
		}

		if (wrinserted == 0) {
			memset(&evt, 0, sizeof(evt));
			evt.events = (EPOLLOUT | EPOLLET);
			evt.data.fd = wrfd;
			ret = epoll_ctl(evfd, EPOLL_CTL_ADD, wrfd, &evt);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "can not insert wrfd [%d]\n", ret);
				goto out;
			}
			wrinserted = 1;
		}

		while (1) {
			ret = epoll_wait(evfd, &getevt, 1, pargs->m_timeout);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "epoll_wait [%s:%d] error[%d]\n", ipaddr, port, ret );
				goto out;
			} else if (ret == 0) {
				ret = -ETIMEDOUT;
				fprintf(stderr, "epoll_wait [%s:%d] timeout\n", ipaddr, port);
				goto out;
			}

			if (getevt.data.fd != wrfd || getevt.events != EPOLLOUT) {
				ret = -EINVAL;
				fprintf(stderr, "getevt.data.fd [%d] != wrfd [%d] or getevt.events [%d] != EPOLLOUT [%d]\n", 
					getevt.data.fd,wrfd, getevt.events, EPOLLOUT);
				goto out;
			}

			ret = complete_tcp_write(psock);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "complete write [%d] wait error[%d]\n", wrlen, ret);
				goto out;
			} else if (ret > 0) {
				wrlen += curlen;
				break;
			}
		}
	}

	fprintf(stderr, "write [%s:%d] fname [%s] buflen [%d] succ\n", ipaddr, port, fname, buflen);
	ret = 0;
out:
	if (evfd >= 0) {
		close(evfd);
	}
	evfd = -1;
	free_socket(&psock);
	read_file_whole(NULL,&pbuf,&bufsize);
	buflen = 0;
	fini_socket();
	SETERRNO(ret);
	return ret;
}