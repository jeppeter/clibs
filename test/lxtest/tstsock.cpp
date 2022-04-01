

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
		evt.events = (EPOLLIN | EPOLLOUT | EPOLLET);
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

		if (getevt.data.fd != bindfd) {
			ret = -EINVAL;
			fprintf(stderr, "getevt.data.fd [%d] != bindfd [%d]\n", getevt.data.fd, bindfd);
			goto out;
		}
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
	int length = 1000;
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
		evt.events = (EPOLLIN | EPOLLOUT | EPOLLET);
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
			DEBUG_INFO("complete read [%s:%d] [%d]", ipaddr,port, ret);
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