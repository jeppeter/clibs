
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

int tstclisockrd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	char* ip = NULL;
	int port = 0;
	DWORD dret;
	HANDLE hread=NULL;
	int numread = 1024;
	pargs_options_t pargs = (pargs_options_t)popt;
	uint8_t* pbuf=NULL;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		ip = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			port = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				numread = atoi(parsestate->leftargs[2]);
			}
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

	psock = connect_tcp_socket(ip,port,NULL,0, 1);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] error[%d]\n", ip, port,ret );
		goto out;
	}


	pbuf = (uint8_t*)malloc((size_t)numread);
	if (pbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}
	memset(pbuf,0,(size_t)numread);
	ret = read_tcp_socket(psock,pbuf,numread);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr,"read [%s:%d] error[%d]\n",ip,port,ret);
		goto out;
	}
	if (ret == 1) {
	debug_out:
		if (numread < 256) {
			DEBUG_BUFFER_FMT(pbuf,numread, "read buffer from [%s:%d]", ip,port);	
		} else {
			DEBUG_BUFFER_FMT(pbuf,128, "read buffer from [%s:%d] first 128", ip,port);
			DEBUG_BUFFER_FMT(pbuf+numread - 128, 128,"read buffer from [%s:%d] first 128", ip,port);
		}
		
	} else {
	wait_again:
		hread = get_tcp_read_handle(psock);
		if (hread == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not get read handle\n");
			goto out;
		}

		dret = WaitForSingleObject(hread,(DWORD)pargs->m_timeout);
		if (dret != WAIT_OBJECT_0) {
			GETERRNO(ret);
			fprintf(stderr, "wait [%s:%d] error[%d] [%ld]\n", ip,port,ret,dret);
			goto out;
		}

		ret = complete_tcp_read(psock);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "complete error[%d]\n", ret);
			goto out;
		}
		if (ret == 1) {
			goto debug_out;
		}
		goto wait_again;
	}

	ret = 0;
out:
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	free_socket(&psock);
	fini_socket();
	SETERRNO(ret);
	return ret;
}

int tstclisockwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	char* ip = NULL;
	int port = 0;
	DWORD dret;
	HANDLE hread=NULL;
	pargs_options_t pargs = (pargs_options_t)popt;
	char* pbuf=NULL;
	int bufsize=0;
	int buflen=0;
	char* fname=NULL;
	uint64_t cticks,sticks;
	int leftmills;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		ip = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			port = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				fname = parsestate->leftargs[2];
			}
		}
	}

	if (ip == NULL || port <= 0 || fname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "can not accept ip port or fname\n");
		goto out;
	}
	DEBUG_INFO("will read [%s]", fname);

	ret = read_file_whole(fname,&pbuf,&bufsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr,"can not read [%s] error[%d]\n",fname, ret);
		goto out;
	}
	buflen = ret;
	DEBUG_INFO("after read [%s] [%d]",fname,buflen);

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not init socket [%d]\n", ret);
		goto out;
	}

	psock = connect_tcp_socket(ip,port,NULL,0, 1);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] error[%d]\n", ip, port,ret );
		goto out;
	}

	DEBUG_INFO("write before [%s]",fname);
	ret = write_tcp_socket(psock,(uint8_t*)pbuf,buflen);
	DEBUG_INFO("write [%s] ret %d", fname,ret);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr,"read [%s:%d] error[%d]\n",ip,port,ret);
		goto out;
	}
	if (ret == 0) {
		sticks = get_current_ticks();		
	wait_again:

		hread = get_tcp_write_handle(psock);
		if (hread == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not get write handle [%d]\n", ret);
			goto out;
		}
		cticks = get_current_ticks();
		leftmills = need_wait_times(sticks,cticks,pargs->m_timeout);
		if (leftmills < 0) {
			GETERRNO(ret);
			fprintf(stderr, "wait time out [%d]\n", ret);
			goto out;
		}

		dret = WaitForSingleObject(hread,(DWORD)leftmills);
		if (dret != WAIT_OBJECT_0) {
			GETERRNO(ret);
			fprintf(stderr, "wait [%s:%d] write[%d] error[%d]\n",ip,port,buflen,ret );
			goto out;
		}

		ret = complete_tcp_write(psock);
		if (ret <0) {
			GETERRNO(ret);
			fprintf(stderr, "complete write error[%d]\n",ret );
			goto out;
		}
		if (ret == 0) {
			goto wait_again;
		}
	} 
	
	fprintf(stdout,"write [%s] succ\n",fname);
	ret = 0;
out:
	free_socket(&psock);
	fini_socket();
	read_file_whole(NULL,&pbuf,&bufsize);
	buflen = 0;
	SETERRNO(ret);
	return ret;
}

int tstsvrsockrd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	void* psock=NULL, *paccsock=NULL;
	int port = 0;
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	char* ip = "0.0.0.0";
	int backlog = 5;
	HANDLE hd;
	DWORD dret;
	int numread = 1024;
	uint8_t* pbuf=NULL;
	uint64_t sticks,cticks;
	int leftmills;
	HANDLE hread=NULL;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			numread = atoi(parsestate->leftargs[1]);
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
		dret = WaitForSingleObject(hd,INFINITE);
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

	pbuf = (uint8_t*)malloc((size_t)numread);
	if (pbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}
	memset(pbuf,0,(size_t)numread);

	ret = read_tcp_socket(paccsock,pbuf,numread);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "read [%d] error[%d]\n",port, ret );
		goto out;
	}

	hread = get_tcp_read_handle(paccsock);
	if (hread != NULL) {
		sticks = get_current_ticks();
		while(1){
			cticks = get_current_ticks();
			leftmills = need_wait_times(sticks,cticks,pargs->m_timeout);
			if (leftmills < 0) {
				ret = -ERROR_INVALID_PARAMETER;
				fprintf(stderr, "timed out\n" );
				goto out;
			}

			dret = WaitForSingleObject(hread, (DWORD)leftmills);
			if (dret != WAIT_OBJECT_0) {
				GETERRNO(ret);
				fprintf(stderr, "wait error[%d] [%ld]\n", ret,dret);
				goto out;
			}

			ret = complete_tcp_read(paccsock);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "read complete error[%d]\n",ret );
				goto out;
			}
			if (ret > 0) {
				break;
			}			
		}
	}



	fprintf(stdout,"read [%s:%d] in [%d] succ\n",ip,port ,pargs->m_timeout);
	ret = 0;
out:
	free_socket(&paccsock);
	free_socket(&psock);
	fini_socket();
	if (pbuf) {
		free(pbuf);
	}
	pbuf = NULL;
	SETERRNO(ret);
	return ret;	
}