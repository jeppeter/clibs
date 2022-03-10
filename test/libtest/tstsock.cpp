
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