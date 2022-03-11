
int tstsockconn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	char* ip = NULL;
	int port = 0;
	DWORD dret;
	HANDLE hconn=NULL;
	pargs_options_t pargs = (pargs_options_t)popt;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		ip = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			port = atoi(parsestate->leftargs[1]);
		}
	}

	if (ip == NULL || port <= 0) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "can not accept ip port\n");
		goto out;
	}

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not init socket [%d]\n", ret);
		goto out;
	}

	psock = connect_tcp_socket(ip,port,NULL,0, 0);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] error[%d]\n", ip, port,ret );
		goto out;
	}

	hconn = get_tcp_connect_handle(psock);
	if (hconn != NULL) {
		dret = WaitForSingleObject(hconn,(DWORD)pargs->m_timeout);
		if (dret == WAIT_OBJECT_0) {
			ret = complete_tcp_connect(psock);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "connect [%s:%d] error[%d]\n",ip,port,ret );
				goto out;
			}
		} else {
			GETERRNO(ret);
			fprintf(stderr, "wait connect [%s:%d] error[%d]\n",ip,port, ret );
			goto out;
		}
	}

	fprintf(stdout, "connect [%s:%d] succ\n",ip,port);
	ret = 0;
out:
	free_socket(&psock);
	fini_socket();
	SETERRNO(ret);
	return ret;
}

int tstsockacc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	void* psock=NULL, *paccsock=NULL;
	int port = 0;
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	char* ip = "0.0.0.0";
	int backlog = 5;
	HANDLE hd;
	DWORD dret;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			backlog = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				ip = parsestate->leftargs[2];
			}
		}
	}

	if (port <= 0 || port >= (1 << 16)) {
		ret= -ERROR_INVALID_PARAMETER;
		fprintf(stderr,"[port] %d not valid\n",port);
		goto out;
	}

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "init socket error[%d]\n", ret);
		goto out;
	}

	psock = bind_tcp_socket(ip,port,backlog);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not bind [%s:%d] backlog[%d] error[%d]\n", ip,port, backlog,ret);
		goto out;
	}

	hd = get_tcp_accept_handle(psock);
	if (hd != NULL) {
		dret = WaitForSingleObject(hd,(DWORD)pargs->m_timeout);
		if (dret != WAIT_OBJECT_0) {
			GETERRNO(ret);
			fprintf(stderr, "wait [%s:%d] time [%d] error [%d] [%ld]\n",ip,port , pargs->m_timeout,ret,dret);
			goto out;
		}		
	}

	ret = complete_tcp_accept(psock);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "complete accept [%s:%d] error[%d]\n", ip,port ,ret);
		goto out;
	}

	paccsock = accept_tcp_socket(psock);
	if (paccsock == NULL) {
		GETERRNO(ret);
		fprintf(stderr,"can not accept [%s:%d] error[%d]", ip,port,ret);
		goto out;
	}

	fprintf(stdout,"accept [%s:%d] in [%d] succ\n",ip,port ,pargs->m_timeout);
	ret = 0;
out:
	free_socket(&paccsock);
	free_socket(&psock);
	fini_socket();
	SETERRNO(ret);
	return ret;
}