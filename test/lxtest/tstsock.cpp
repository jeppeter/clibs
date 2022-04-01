

int tstsockconn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	const char* ipaddr=NULL;
	int port = 0;
	const char* bindip = NULL;
	int bindport = 0;
	int connected = 0;
	int evfd = -1;
	int connectfd = -1;

	init_log_level(pargs);

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
				if (strcmp(parsestate->leftargs[2],"NULL") != NULL) {
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

	psock = connect_tcp_socket(ipaddr,port,bindip,bindport, connected);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] bind [%s:%d] error[%d]\n", 
			ipaddr,port, bindip != NULL ? bindip : "NULL", bindport,ret);
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
		
	}





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