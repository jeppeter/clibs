
int tstsockconn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	void* psock = NULL;
	char* ip = NULL;
	int port = 0;
	DWORD dret;
	HANDLE hconn = NULL;
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

	psock = connect_tcp_socket(ip, port, NULL, 0, 0);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] error[%d]\n", ip, port, ret );
		goto out;
	}

	hconn = get_tcp_connect_handle(psock);
	if (hconn != NULL) {
		dret = WaitForSingleObject(hconn, (DWORD)pargs->m_timeout);
		if (dret == WAIT_OBJECT_0) {
			ret = complete_tcp_connect(psock);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "connect [%s:%d] error[%d]\n", ip, port, ret );
				goto out;
			}
		} else {
			GETERRNO(ret);
			fprintf(stderr, "wait connect [%s:%d] error[%d]\n", ip, port, ret );
			goto out;
		}
	}


	fprintf(stdout, "connect [%s:%d] succ\n", ip, port);
	ret = 0;
out:
	free_socket(&psock);
	fini_socket();
	SETERRNO(ret);
	return ret;
}

int tstsockacc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	void* psock = NULL, *paccsock = NULL;
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
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "[port] %d not valid\n", port);
		goto out;
	}

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "init socket error[%d]\n", ret);
		goto out;
	}

	psock = bind_tcp_socket(ip, port, backlog);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not bind [%s:%d] backlog[%d] error[%d]\n", ip, port, backlog, ret);
		goto out;
	}

	hd = get_tcp_accept_handle(psock);
	if (hd != NULL) {
		dret = WaitForSingleObject(hd, (DWORD)pargs->m_timeout);
		if (dret != WAIT_OBJECT_0) {
			GETERRNO(ret);
			fprintf(stderr, "wait [%s:%d] time [%d] error [%d] [%ld]\n", ip, port , pargs->m_timeout, ret, dret);
			goto out;
		}
	}

	ret = complete_tcp_accept(psock);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "complete accept [%s:%d] error[%d]\n", ip, port , ret);
		goto out;
	}

	paccsock = accept_tcp_socket(psock);
	if (paccsock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not accept [%s:%d] error[%d]", ip, port, ret);
		goto out;
	}

	fprintf(stdout, "accept [%s:%d] in [%d] succ\n", ip, port , pargs->m_timeout);
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
	HANDLE hread = NULL;
	int numread = 1024;
	pargs_options_t pargs = (pargs_options_t)popt;
	uint8_t* pbuf = NULL;

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

	psock = connect_tcp_socket(ip, port, NULL, 0, 1);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] error[%d]\n", ip, port, ret );
		goto out;
	}

	DEBUG_INFO(" ");
	hread = get_tcp_connect_handle(psock);
	ASSERT_IF(hread == NULL);


	pbuf = (uint8_t*)malloc((size_t)numread);
	if (pbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}
	memset(pbuf, 0, (size_t)numread);
	ret = read_tcp_socket(psock, pbuf, numread);
	DEBUG_INFO("read [%d] return %d", numread, ret);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "read [%s:%d] error[%d]\n", ip, port, ret);
		goto out;
	}
	if (ret == 1) {
debug_out:
		if (numread < 256) {
			DEBUG_BUFFER_FMT(pbuf, numread, "read buffer from [%s:%d]", ip, port);
		} else {
			DEBUG_BUFFER_FMT(pbuf, 128, "read buffer from [%s:%d] first 128", ip, port);
			DEBUG_BUFFER_FMT(pbuf + numread - 128, 128, "read buffer from [%s:%d] first 128", ip, port);
		}

	} else {
wait_again:
		hread = get_tcp_read_handle(psock);
		if (hread == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "can not get read handle\n");
			goto out;
		}

		dret = WaitForSingleObject(hread, (DWORD)pargs->m_timeout);
		if (dret != WAIT_OBJECT_0) {
			GETERRNO(ret);
			ERROR_INFO("wait [%s:%d] error[%d] [%ld]", ip, port, ret, dret);
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
	HANDLE hread = NULL;
	pargs_options_t pargs = (pargs_options_t)popt;
	char* pbuf = NULL;
	int bufsize = 0;
	int buflen = 0;
	char* fname = NULL;
	uint64_t cticks, sticks;
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

	ret = read_file_whole(fname, &pbuf, &bufsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not read [%s] error[%d]\n", fname, ret);
		goto out;
	}
	buflen = ret;
	DEBUG_INFO("after read [%s] [%d]", fname, buflen);

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not init socket [%d]\n", ret);
		goto out;
	}

	psock = connect_tcp_socket(ip, port, NULL, 0, 1);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "connect [%s:%d] error[%d]\n", ip, port, ret );
		goto out;
	}

	DEBUG_INFO("write before [%s]", fname);
	ret = write_tcp_socket(psock, (uint8_t*)pbuf, buflen);
	DEBUG_INFO("write [%s] ret %d", fname, ret);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "read [%s:%d] error[%d]\n", ip, port, ret);
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
		leftmills = need_wait_times(sticks, cticks, pargs->m_timeout);
		if (leftmills < 0) {
			GETERRNO(ret);
			fprintf(stderr, "wait time out [%d]\n", ret);
			goto out;
		}

		dret = WaitForSingleObject(hread, (DWORD)leftmills);
		if (dret != WAIT_OBJECT_0) {
			GETERRNO(ret);
			fprintf(stderr, "wait [%s:%d] write[%d] error[%d]\n", ip, port, buflen, ret );
			goto out;
		}

		ret = complete_tcp_write(psock);
		if (ret < 0) {
			GETERRNO(ret);
			fprintf(stderr, "complete write error[%d]\n", ret );
			goto out;
		}
		if (ret == 0) {
			goto wait_again;
		}
	}

	fprintf(stdout, "write [%s] succ\n", fname);
	ret = 0;
out:
	free_socket(&psock);
	fini_socket();
	read_file_whole(NULL, &pbuf, &bufsize);
	buflen = 0;
	SETERRNO(ret);
	return ret;
}



int tstsvrsockrd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	void* psock = NULL, *paccsock = NULL;
	int port = 0;
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	char* ip = "0.0.0.0";
	int backlog = 5;
	HANDLE hd;
	DWORD dret;
	int numread = 1024;
	uint8_t* pbuf = NULL;
	uint64_t sticks, cticks;
	int leftmills;
	HANDLE hread = NULL;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			numread = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				ip = parsestate->leftargs[2];
			}
		}
	}

	if (port <= 0 || port >= (1 << 16)) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "[port] %d not valid\n", port);
		goto out;
	}

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "init socket error[%d]\n", ret);
		goto out;
	}

	psock = bind_tcp_socket(ip, port, backlog);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not bind [%s:%d] backlog[%d] error[%d]\n", ip, port, backlog, ret);
		goto out;
	}

	hd = get_tcp_accept_handle(psock);
	if (hd != NULL) {
		dret = WaitForSingleObject(hd, INFINITE);
		if (dret != WAIT_OBJECT_0) {
			GETERRNO(ret);
			fprintf(stderr, "wait [%s:%d] time [%d] error [%d] [%ld]\n", ip, port , pargs->m_timeout, ret, dret);
			goto out;
		}
	}

	ret = complete_tcp_accept(psock);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "complete accept [%s:%d] error[%d]\n", ip, port , ret);
		goto out;
	}

	paccsock = accept_tcp_socket(psock);
	if (paccsock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not accept [%s:%d] error[%d]", ip, port, ret);
		goto out;
	}

	pbuf = (uint8_t*)malloc((size_t)numread);
	if (pbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}
	memset(pbuf, 0, (size_t)numread);

	ret = read_tcp_socket(paccsock, pbuf, numread);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "read [%d] error[%d]\n", port, ret );
		goto out;
	}

	hread = get_tcp_read_handle(paccsock);
	if (hread != NULL) {
		sticks = get_current_ticks();
		while (1) {
			cticks = get_current_ticks();
			leftmills = need_wait_times(sticks, cticks, pargs->m_timeout);
			if (leftmills < 0) {
				ret = -ERROR_INVALID_PARAMETER;
				fprintf(stderr, "timed out\n" );
				goto out;
			}

			dret = WaitForSingleObject(hread, (DWORD)leftmills);
			if (dret != WAIT_OBJECT_0) {
				GETERRNO(ret);
				fprintf(stderr, "wait error[%d] [%ld]\n", ret, dret);
				goto out;
			}

			ret = complete_tcp_read(paccsock);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "read complete error[%d]\n", ret );
				goto out;
			}
			if (ret > 0) {
				break;
			}
		}
	}

	if (numread < 256) {
		DEBUG_BUFFER_FMT(pbuf, numread, "read buffer from [%s:%d]", ip, port);
	} else {
		DEBUG_BUFFER_FMT(pbuf, 128, "read buffer from [%s:%d] first 128", ip, port);
		DEBUG_BUFFER_FMT(pbuf + numread - 128, 128, "read buffer from [%s:%d] first 128", ip, port);
	}


	fprintf(stdout, "read [%s:%d] in [%d] succ\n", ip, port , pargs->m_timeout);
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


int tstsvrsockwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	void* psock = NULL, *paccsock = NULL;
	int port = 0;
	pargs_options_t pargs = (pargs_options_t) popt;
	int ret;
	char* ip = "0.0.0.0";
	int backlog = 5;
	HANDLE hd;
	DWORD dret;
	uint64_t sticks, cticks;
	int leftmills;
	HANDLE hwrite = NULL;
	char* pbuf = NULL;
	int bufsize = 0;
	int buflen = 0;
	char* fname = NULL;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			fname = parsestate->leftargs[1];
		}
	}

	if (port <= 0 || port >= (1 << 16) || fname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		fprintf(stderr, "[port] %d not valid\n", port);
		goto out;
	}

	ret = read_file_whole(fname, &pbuf, &bufsize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not read [%s] error[%d]\n", fname, ret);
		goto out;
	}
	buflen = ret;

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "init socket error[%d]\n", ret);
		goto out;
	}

	psock = bind_tcp_socket(ip, port, backlog);
	if (psock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not bind [%s:%d] backlog[%d] error[%d]\n", ip, port, backlog, ret);
		goto out;
	}

	hd = get_tcp_accept_handle(psock);
	if (hd != NULL) {
		DEBUG_INFO("listen on [%d]", port);
		dret = WaitForSingleObject(hd, INFINITE);
		DEBUG_INFO("dret %ld", dret);
		if (dret != WAIT_OBJECT_0) {
			GETERRNO(ret);
			fprintf(stderr, "wait [%s:%d] time [%d] error [%d] [%ld]\n", ip, port , pargs->m_timeout, ret, dret);
			goto out;
		}
	}

	ret = complete_tcp_accept(psock);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "complete accept [%s:%d] error[%d]\n", ip, port , ret);
		goto out;
	}
	DEBUG_INFO("complete tcp accept [%d]", port);

	paccsock = accept_tcp_socket(psock);
	if (paccsock == NULL) {
		GETERRNO(ret);
		fprintf(stderr, "can not accept [%s:%d] error[%d]", ip, port, ret);
		goto out;
	}

	DEBUG_INFO("accept socket write [%d]", buflen);


	ret = write_tcp_socket(paccsock, (uint8_t*)pbuf, buflen);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "write [%d] error[%d]\n", port, ret );
		goto out;
	}

	hwrite = get_tcp_write_handle(paccsock);
	if (hwrite != NULL) {
		sticks = get_current_ticks();
		while (1) {
			cticks = get_current_ticks();
			leftmills = need_wait_times(sticks, cticks, pargs->m_timeout);
			if (leftmills < 0) {
				ret = -ERROR_INVALID_PARAMETER;
				fprintf(stderr, "timed out\n" );
				goto out;
			}

			dret = WaitForSingleObject(hwrite, (DWORD)leftmills);
			if (dret != WAIT_OBJECT_0) {
				GETERRNO(ret);
				fprintf(stderr, "wait error[%d] [%ld]\n", ret, dret);
				goto out;
			}

			ret = complete_tcp_write(paccsock);
			if (ret < 0) {
				GETERRNO(ret);
				fprintf(stderr, "write complete error[%d]\n", ret );
				goto out;
			}
			if (ret > 0) {
				break;
			}
		}
	}

	fprintf(stdout, "write [%s:%d] in [%d] succ\n", ip, port , pargs->m_timeout);
	ret = 0;
out:
	free_socket(&paccsock);
	free_socket(&psock);
	fini_socket();
	read_file_whole(NULL, &pbuf, &bufsize);
	buflen = 0;
	SETERRNO(ret);
	return ret;
}


int tstsvrsockrdwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int lport = 0;
	char* fname = NULL;
	int ret;
	char* ipaddr = "0.0.0.0";
	int numread = 1024;
	int totalrd = 0;
	int totalwr = 0;
	int partwrite = 1024;
	pargs_options_t pargs = (pargs_options_t)popt;
	char* pcon = NULL;
	int consize = 0, conlen = 0;
	uint8_t* prbuf = NULL;
	void* paccsock = NULL;
	void* psvrsock = NULL;
	HANDLE waithds[4];
	DWORD waitnum;
	HANDLE hd;
	DWORD dret;
	int curwr = 0;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		lport = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			fname = parsestate->leftargs[1];
			if (parsestate->leftargs[2]) {
				numread = atoi(parsestate->leftargs[2]);
				if (parsestate->leftargs[3]) {
					ipaddr = parsestate->leftargs[3];
					if (parsestate->leftargs[4]) {
						partwrite = atoi(parsestate->leftargs[4]);
					}
				}
			}
		}
	}

	if (lport == 0 || lport >= (1 << 16) || fname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto out;
	}

	ret = read_file_whole(fname, &pcon, &consize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not read [%s] error[%d]\n", fname, ret);
		goto out;
	}
	conlen = ret;

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	psvrsock = bind_tcp_socket(ipaddr, lport, 5);
	if (psvrsock == NULL) {
		GETERRNO(ret);
		ERROR_INFO("cannot bind [%s:%d] error[%d]", ipaddr, lport, ret);
		goto out;
	}

	while (1) {
		hd = get_tcp_accept_handle(psvrsock);
		if (hd == NULL) {
			break;
		}
		dret = WaitForSingleObject(hd, INFINITE);
		if (dret == WAIT_OBJECT_0) {
			break;
		} else {
			GETERRNO(ret);
			ERROR_INFO("wait accept [%s:%d] error[%d]", ipaddr, lport, ret);
			goto out;
		}
	}

	ret = complete_tcp_accept(psvrsock);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	paccsock = accept_tcp_socket(psvrsock);
	if (paccsock == NULL) {
		GETERRNO(ret);
		ERROR_INFO("accept [%s:%d] error[%d]", ipaddr, lport, ret);
		goto out;
	}

	prbuf = (uint8_t*)malloc((size_t)numread);
	if (prbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}
	totalrd = 0;
	totalwr = 0;


	while (totalwr < conlen) {

		waitnum = 0;
try_read_again:
		hd = get_tcp_read_handle(paccsock);
		if (hd == NULL) {
			ret = read_tcp_socket(paccsock, prbuf, numread);
			if (ret < 0) {
				GETERRNO(ret);
				goto out;
			} else if (ret > 0) {
				totalrd += numread;
				if (numread < 16) {
					DEBUG_BUFFER_FMT(prbuf, numread, "read buffer [%d] [%d]", numread, totalrd);
				} else {
					DEBUG_BUFFER_FMT(prbuf, 16, "read buffer [%d] [%d]", numread, totalrd);
				}

			}
			goto try_read_again;

		}
		waithds[waitnum] = hd;
		waitnum ++;

		hd = get_tcp_write_handle(paccsock);
		if (hd == NULL) {
			curwr = partwrite;
			if (curwr > (conlen - totalwr)) {
				curwr = (conlen - totalwr);
			}
			ret = write_tcp_socket(paccsock, (uint8_t*) & (pcon[totalwr]), curwr);
			if (ret < 0) {
				GETERRNO(ret);
				goto out;
			} else if (ret > 0) {
				totalwr += curwr;
			}

			hd = get_tcp_write_handle(paccsock);
		}

		if (hd != NULL) {
			waithds[waitnum] = hd;
			waitnum ++;
		}

		dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)pargs->m_timeout, FALSE);
		if ( dret < (WAIT_OBJECT_0 + waitnum)) {
			hd = waithds[dret - WAIT_OBJECT_0];
			if (hd == get_tcp_write_handle(paccsock)) {
				ret = complete_tcp_write(paccsock);
				if (ret < 0) {
					GETERRNO(ret);
					goto out;
				} else if (ret > 0) {
					DEBUG_INFO("write [%d]", curwr);
					totalwr += curwr;
				}
			} else if (hd == get_tcp_read_handle(paccsock)) {
				ret = complete_tcp_read(paccsock);
				if (ret < 0) {
					GETERRNO(ret);
					goto out;
				} else if (ret > 0) {
					totalrd += numread;
					if (numread < 16) {
						DEBUG_BUFFER_FMT(prbuf, numread, "read buffer [%d] [%d]", numread, totalrd);
					} else {
						DEBUG_BUFFER_FMT(prbuf, 16, "read buffer [%d] [%d]", numread, totalrd);
					}
				}
			}
		} else {
			GETERRNO(ret);
			goto out;
		}
	}

	ret = 0;
	fprintf(stdout, "svrrdwr [%s:%d] succ\n", ipaddr, lport);
out:

	free_socket(&paccsock);
	free_socket(&psvrsock);

	if (prbuf) {
		free(prbuf);
	}
	prbuf = NULL;
	read_file_whole(NULL, &pcon, &consize);
	conlen = 0;
	fini_socket();
	SETERRNO(ret);
	return ret;
}
int tstclisockrdwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int port = 0;
	char* fname = NULL;
	int ret;
	char* ipaddr = NULL;
	int numread = 1024;
	int totalrd = 0;
	int totalwr = 0;
	int partwrite = 1024;
	pargs_options_t pargs = (pargs_options_t)popt;
	char* pcon = NULL;
	int consize = 0, conlen = 0;
	uint8_t* prbuf = NULL;
	void* psock = NULL;
	HANDLE waithds[4];
	DWORD waitnum;
	HANDLE hd;
	DWORD dret;
	int curwr = 0;

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		ipaddr = parsestate->leftargs[0];
		if (parsestate->leftargs[1]) {
			port = atoi(parsestate->leftargs[1]);
			if (parsestate->leftargs[2]) {
				fname = parsestate->leftargs[2];
				if (parsestate->leftargs[3]) {
					numread = atoi(parsestate->leftargs[3]);
					if (parsestate->leftargs[4]) {
						partwrite = atoi(parsestate->leftargs[4]);
					}
				}
			}
		}
	}

	if (port == 0 || port >= (1 << 16) || fname == NULL || ipaddr == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto out;
	}

	ret = read_file_whole(fname, &pcon, &consize);
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "can not read [%s] error[%d]\n", fname, ret);
		goto out;
	}
	conlen = ret;

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	psock = connect_tcp_socket(ipaddr, port, NULL, 0, 1);
	if (psock == NULL) {
		GETERRNO(ret);
		ERROR_INFO("cannot connect [%s:%d] error[%d]", ipaddr, port, ret);
		goto out;
	}

	prbuf = (uint8_t*)malloc((size_t)numread);
	if (prbuf == NULL) {
		GETERRNO(ret);
		goto out;
	}
	totalwr = 0;
	totalrd = 0;

	while (totalwr < conlen) {
		waitnum = 0;
try_read_again:
		hd = get_tcp_read_handle(psock);
		if (hd == NULL) {
			ret = read_tcp_socket(psock, prbuf, numread);
			if (ret < 0) {
				GETERRNO(ret);
				goto out;
			} else if (ret > 0) {
				totalrd += numread;
				DEBUG_BUFFER_FMT(prbuf, numread, "read buffer");
			}
			goto try_read_again;

		}
		waithds[waitnum] = hd;
		waitnum ++;

		hd = get_tcp_write_handle(psock);
		if (hd == NULL) {
			curwr = partwrite;
			if (curwr > (conlen - totalwr)) {
				curwr = (conlen - totalwr);
			}
			ret = write_tcp_socket(psock, (uint8_t*) & (pcon[totalwr]), curwr);
			if (ret < 0) {
				GETERRNO(ret);
				goto out;
			} else if (ret > 0) {
				totalwr += curwr;
				DEBUG_INFO("write [%d]", curwr);
			}

			hd = get_tcp_write_handle(psock);
		}

		if (hd != NULL) {
			waithds[waitnum] = hd;
			waitnum ++;
		}

		dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)pargs->m_timeout, FALSE);
		if ( dret < (WAIT_OBJECT_0 + waitnum)) {
			hd = waithds[dret - WAIT_OBJECT_0];
			if (hd == get_tcp_write_handle(psock)) {
				ret = complete_tcp_write(psock);
				if (ret < 0) {
					GETERRNO(ret);
					goto out;
				} else if (ret > 0) {
					DEBUG_INFO("write [%d]", curwr);
					totalwr += curwr;
				}
			} else if (hd == get_tcp_read_handle(psock)) {
				ret = complete_tcp_read(psock);
				if (ret < 0) {
					GETERRNO(ret);
					goto out;
				} else if (ret > 0) {
					DEBUG_BUFFER_FMT(prbuf, numread, "read complete");
					totalrd += numread;
				}
			}
		} else {
			GETERRNO(ret);
			goto out;
		}
	}

	ret = 0;
out:
	free_socket(&psock);
	fini_socket();
	if (prbuf) {
		free(prbuf);
	}
	prbuf = NULL;
	read_file_whole(NULL, &pcon, &consize);
	conlen = 0;
	SETERRNO(ret);
	return ret;
}


int sockacc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	void* psvr = NULL;
	int ret;
	int port = 7201;
	char* bindip = "0.0.0.0";
	pargs_options_t pargs = (pargs_options_t) popt;
	HANDLE exithd = NULL;
	HANDLE* phdl = NULL;
	DWORD hdlsize = 0;
	DWORD waitnum = 0;
	std::vector<void*>* conns = NULL;
	char rdbuf[256];
	unsigned int i;
	void* pcli=NULL;
	DWORD dret;
	HANDLE hd;

	REFERENCE_ARG(argv);
	REFERENCE_ARG(argc);

	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			bindip = parsestate->leftargs[1];
		}
	}

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	psvr = bind_tcp_socket(bindip, port, 5);
	if (psvr == NULL) {
		GETERRNO(ret);
		goto out;
	}
	hdlsize = 4;
	phdl = (HANDLE*)malloc(sizeof(*phdl) * hdlsize);
	if (phdl == NULL) {
		GETERRNO(ret);
		goto out;
	}

	DEBUG_INFO("wait for [%s:%d]",bindip,port);

	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		goto out;
	}
	conns = new std::vector<void*>();

	while (1) {
		waitnum = 0;
		phdl[waitnum] = exithd;
		waitnum ++;
		phdl[waitnum] = get_tcp_accept_handle(psvr);
		waitnum ++;
		if (conns->size() > 0) {
			for (i = 0; i < conns->size(); i++) {
				pcli = conns->at(i);
				if (get_tcp_read_handle(pcli) != NULL) {
					phdl[waitnum] = get_tcp_read_handle(pcli);
					waitnum ++;					
				}
			}
		}

		dret = WaitForMultipleObjectsEx(waitnum, phdl, FALSE, 30000, FALSE);
		if (dret < (WAIT_OBJECT_0 + waitnum)) {
			hd = phdl[(dret - WAIT_OBJECT_0)];
			if (hd == exithd) {
				break;
			} else if (hd == get_tcp_accept_handle(psvr)) {
				ret = complete_tcp_accept(psvr);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO("complete_tcp_accept error[%d]", ret);
					goto out;
				} else if (ret > 0) {
					pcli = accept_tcp_socket(psvr);
					if (pcli == NULL) {
						GETERRNO(ret);
						ERROR_INFO("accept_tcp_socket error[%d]", ret);
						goto out;
					}
					conns->push_back(pcli);
					while (1) {
						ret = read_tcp_socket(pcli, (uint8_t*)rdbuf, sizeof(rdbuf));
						if (ret < 0) {
							GETERRNO(ret);
							if (ret != -WSAESHUTDOWN) {
								ERROR_INFO("read_tcp_socket [%d] error[%d]", conns->size() - 1, ret);
								goto out;
							} else {
								DEBUG_INFO("shutdown socket");
								conns->pop_back();
								free_socket(&pcli);
							}
						} else if (ret > 0) {
							DEBUG_BUFFER_FMT(rdbuf, sizeof(rdbuf), "[%d] read buf", conns->size() - 1);
						} else {
							break;
						}
					}

					if (hdlsize <= (conns->size() + 2)) {
						hdlsize = (DWORD)(conns->size() + 2 + 1);
						if (phdl) {
							free(phdl);
						}
						phdl = NULL;
						phdl = (HANDLE*)malloc(sizeof(*phdl) * hdlsize);
						if (phdl == NULL) {
							GETERRNO(ret);
							goto out;
						}
					}
				}
			} else {
				for (i = 0; i < conns->size(); i++) {
					pcli = conns->at(i);
					if (hd == get_tcp_read_handle(pcli)) {
						ret = complete_tcp_read(pcli);
						if (ret < 0) {
							if (ret != -WSAESHUTDOWN) {
								ERROR_INFO("[%d]read error [%d]", i, ret);
								goto out;
							}
							DEBUG_INFO("[%d] closed",i);
							conns->erase(conns->begin() + i);
							free_socket(&pcli);
							break;
						} else if (ret > 0) {
							DEBUG_BUFFER_FMT(rdbuf, sizeof(rdbuf), "read [%d] conn", i);
							while (1) {
								ret = read_tcp_socket(pcli, (uint8_t*)rdbuf, sizeof(rdbuf));
								if (ret < 0) {
									GETERRNO(ret);
									if (ret != -WSAESHUTDOWN) {
										ERROR_INFO("read_tcp_socket [%d] error[%d]", i, ret);
										goto out;
									}
									DEBUG_INFO("[%d] closed", i);
									conns->erase(conns->begin()+i);
									free_socket(&pcli);
									goto next_cycle;
								} else if (ret > 0) {
									DEBUG_BUFFER_FMT(rdbuf, sizeof(rdbuf), "[%d] read buf", conns->size() - 1);
								} else {
									break;
								}
							}
						}
					}
				}
			}
		} else if (dret == WAIT_TIMEOUT) {
			continue;
		} else {
			GETERRNO(ret);
			ERROR_INFO("wait error [%ld] %d", dret, ret);
			goto out;
		}
	next_cycle:
		phdl = phdl;
	}
	ret = 0;
out:
	if (conns != NULL) {
		while (conns->size() > 0) {
			pcli = conns->at(0);
			conns->erase(conns->begin());
			free_socket(&pcli);
		}
		delete conns;
	}
	conns = NULL;
	free_socket(&psvr);
	fini_socket();
	close_ctrlc_handle();
	exithd = NULL;
	SETERRNO(ret);
	return ret;
}


int socksvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    sock_svr_comm* psvr = NULL;
    sock_comm* pcomm = NULL;
    sock_comm* ptmpcomm = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    char* ipaddr ="0.0.0.0";
    int port = 3391;
    jvalue* pj=NULL;
    char* pjstr =NULL;
    unsigned int jsize=0;
    int ret;
    DWORD dret;
    HANDLE curhd;
    HANDLE waithds[5];
    DWORD waitnum = 0;

    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);

    ret= init_socket();
    if (ret < 0) {
    	GETERRNO(ret);
    	goto out;
    }


    st_ExitEvt = set_ctrlc_handle();
    if (st_ExitEvt == NULL) {
        GETERRNO(ret);
        goto out;
    }
    if (parsestate->leftargs && parsestate->leftargs[0]) {
    	port = atoi(parsestate->leftargs[0]);
    	if (parsestate->leftargs[1]) {
    		ipaddr = parsestate->leftargs[1];
    	}
    }

init_again:
	if (pcomm) {
		delete pcomm;
	}
	pcomm = NULL;
	if (psvr) {
		delete psvr;
	}
	psvr = NULL;
	if (ptmpcomm) {
		delete ptmpcomm;
	}
	ptmpcomm = NULL;
    psvr = new sock_svr_comm(ipaddr,port);
    ret = psvr->init();
    if (ret < 0) {
    	GETERRNO(ret);
    	goto out;
    }

    DEBUG_INFO("listen on [%s:%d]",ipaddr, port);
    while(1) {
    	if (pj) {
    		jvalue_destroy(pj);
    	}
    	pj = NULL;
    	memset(waithds,0,sizeof(waithds));
    	waitnum = 0;
    	waithds[waitnum] = st_ExitEvt;
    	waitnum += 1;
    	waithds[waitnum] = psvr->get_accept_evt();
    	waitnum += 1;
    	if (pcomm) {
    	set_read:
    		ret = pcomm->is_read_mode();
    		if (ret > 0) {
    			waithds[waitnum] = pcomm->get_read_evt();
    			waitnum += 1;
    		} else {
    			ASSERT_IF(pj == NULL);
    			ret = pcomm->read_json(&pj);
    			if (ret < 0) {
    				delete pcomm;
    				pcomm = NULL;
   					continue;
   				} else if (ret > 0) {
   					pjstr = jvalue_write_pretty(pj,&jsize);
   					if (pjstr == NULL) {
    					GETERRNO(ret);
    					goto out;
    				}
    				DEBUG_INFO("read\n%s",pjstr);
    				free(pjstr);
    				pjstr = NULL;
   					jsize = 0;
   					ret = pcomm->write_json(pj);
  					if (ret < 0) {
    					delete pcomm;
    					pcomm = NULL;
    					continue;
    				}
    				jvalue_destroy(pj);
    				pj = NULL;
   				}
   				goto set_read;
   			}
   			if (pcomm->is_write_mode()) {
   				waithds[waitnum] = pcomm->get_write_evt();
   				waitnum += 1;
   			}
    	}

    	dret = WaitForMultipleObjectsEx(waitnum,waithds,FALSE,10000,TRUE);
    	if (dret < (WAIT_OBJECT_0 + waitnum)) {
    		curhd = waithds[(dret - WAIT_OBJECT_0)];
    		if (curhd == st_ExitEvt) {
    			DEBUG_INFO("break");
    			ret = 0;
    			break;
    		} else if (curhd == psvr->get_accept_evt()) {
    			ret= psvr->complete_accept();
    			if (ret < 0) {
    				goto init_again;
    			} else if (ret > 0) {
    				ASSERT_IF(ptmpcomm == NULL);
    				ptmpcomm = psvr->get_accept();
    				if (ptmpcomm == NULL) {
    					goto init_again;
    				}
    				if (pcomm != NULL) {
    					ERROR_INFO("already in client connect");
    					delete ptmpcomm;
    					ptmpcomm = NULL;
    				} else {
    					pcomm = ptmpcomm;
    					ptmpcomm = NULL;
    					ret = pcomm->init();
    					if (ret < 0) {
    						ERROR_INFO("init error");
    						delete pcomm;
    						pcomm = NULL;
    					}
    				}
    			}
    		} else if (pcomm) {
    			if (curhd == pcomm->get_read_evt()) {
    				ret = pcomm->complete_read();
    				if (ret < 0) {
    					delete pcomm;
    					pcomm = NULL;
    				}
    			} else if (curhd == pcomm->get_write_evt()) {
    				ret = pcomm->complete_write();
    				if (ret <0){
    					delete pcomm;
    					pcomm = NULL;
    				}
    			}
    		}
    	}
    }



    ret = 0;
out:
    if (pj) {
        jvalue_destroy(pj);
    }
    pj = NULL;
    if (pjstr) {
        free(pjstr);
    }
    pjstr = NULL;

    if (ptmpcomm) {
    	delete ptmpcomm;
    }
    ptmpcomm = NULL;
    if (pcomm) {
        delete pcomm;
    }
    pcomm = NULL;
    if (psvr) {
    	delete psvr;
    }
    psvr = NULL;
    SETERRNO(ret);
    return ret;
}
int sockcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    sock_cli_comm* pcli = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    char* ipaddr ="127.0.0.1";
    int port = 3391;
    jvalue* pj=NULL;
    char* pjstr =NULL;
    unsigned int jsize=0;
    int ret;
    DWORD dret;
    HANDLE curhd;
    HANDLE waithds[5];
    DWORD waitnum = 0;
    char** ppfnames = NULL;
    int fsize = 0;
    int i;
    int rdcnt = 0;
    int wrcnt =0;
    char* pbuf=NULL;
    int bufsize=0;
    int buflen=0;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);
    if (parsestate->leftargs && parsestate->leftargs[0]) {
    	port =atoi(parsestate->leftargs[0]);
    	fsize = 0;
    	for(i=1;parsestate->leftargs[i];i++) {
    		fsize += 1;
    	}
    	if (fsize > 0) {
    		ppfnames = &(parsestate->leftargs[1]);
    	}
    }

    if (ppfnames == NULL) {
    	ret = -ERROR_INVALID_PARAMETER;
    	fprintf(stderr, "need fnames\n");
    	goto out;
    }

    ret= init_socket();
    if (ret < 0) {
    	GETERRNO(ret);
    	goto out;
    }

    st_ExitEvt = set_ctrlc_handle();
    if (st_ExitEvt == NULL) {
    	GETERRNO(ret);
    	goto out;
    }

    pcli = new sock_cli_comm(ipaddr,port);
    ret = pcli->init();
    if (ret < 0) {
    	GETERRNO(ret);
    	goto out;
    }

    while(1) {
    	memset(waithds,0,sizeof(waithds));
    	waitnum = 0;
    	waithds[waitnum] = st_ExitEvt;

    	if (pcli->is_connect_mode()) {
    		waithds[waitnum] = pcli->get_connect_evt();
    		waitnum += 1;
    	} else {
    	set_read:
    		if(pcli->is_read_mode()) {
    			waithds[waitnum] = pcli->get_read_evt();
    			waitnum += 1;
    		} else {
    			ASSERT_IF(pj == NULL);
    			ret = pcli->read_json(&pj);
    			if (ret <0){
    				GETERRNO(ret);
    				ERROR_INFO(" ");
    				goto out;
    			} else if (ret > 0) {
    				ASSERT_IF(pjstr == NULL);
    				pjstr = jvalue_write_pretty(pj,&jsize);
    				if (pjstr == NULL) {
    					GETERRNO(ret);
    					goto out;
    				}
    				DEBUG_INFO("[%d]read\n%s",rdcnt,pjstr);
    				free(pjstr);
    				pjstr =NULL;
    				jvalue_destroy(pj);
    				pj = NULL;
    				rdcnt += 1;
    				if (rdcnt == fsize) {
    					ret = 0;
    					DEBUG_INFO("all over");
    					goto out;
    				}
    			}
    			goto set_read;
    		}
    		while(wrcnt < fsize) {
    			ret = read_file_whole(ppfnames[wrcnt],&pbuf,&bufsize);
    			if (ret < 0) {
    				GETERRNO(ret);
    				goto out;
    			}
    			buflen = ret;
    			if (buflen < bufsize) {
    				pbuf[buflen] = '\0';
    			}
    			ASSERT_IF(pj == NULL);
    			pj = jvalue_read(pbuf,&jsize);
    			if (pj == NULL) {
    				GETERRNO(ret);
    				ERROR_INFO("can not read [%d] [%s]",wrcnt,ppfnames[wrcnt]);
    				goto out;
    			}
    			ret = pcli->write_json(pj);
    			if (ret < 0) {
    				GETERRNO(ret);
    				goto out;
    			}
    			DEBUG_INFO("write[%d][%s] [%d]",wrcnt, ppfnames[wrcnt],ret);
    			jvalue_destroy(pj);
    			pj = NULL;
    			wrcnt += 1;
    		}

    		if (pcli->is_write_mode()) {
    			DEBUG_INFO("set write hd");
    			waithds[waitnum] = pcli->get_write_evt();
    			waitnum += 1;
    		}
    	}

    	dret = WaitForMultipleObjectsEx(waitnum,waithds,FALSE,10000,TRUE);
    	if (dret < (WAIT_OBJECT_0+waitnum)) {
    		curhd = waithds[(dret - WAIT_OBJECT_0)];
    		if (curhd == st_ExitEvt) {
    			ret = 0;
    			DEBUG_INFO("break");
    			goto out;
    		} else if (curhd == pcli->get_connect_evt()) {
    			ret = pcli->complete_connect();
    			if (ret < 0) {
    				GETERRNO(ret);
    				goto out;
    			}
    		} else if (curhd == pcli->get_read_evt()) {
    			ret = pcli->complete_read();
    			if (ret < 0) {
    				GETERRNO(ret);
    				goto out;
    			}
    		} else if (curhd == pcli->get_write_evt()) {
    			ret= pcli->complete_write();
    			if (ret < 0) {
    				GETERRNO(ret);
    				goto out;
    			}
    		}
    	} else if (dret != WAIT_TIMEOUT) {
    		GETERRNO(ret);
    		ERROR_INFO("dret %d",dret);
    		goto out;
    	}
    }

out:
	if (pj) {
		jvalue_destroy(pj);
	}
	pj= NULL;
	if(pjstr) {
		free(pjstr);
	}
	pjstr = NULL;
	if (pcli) {
		delete pcli;
	}
	pcli = NULL;
	read_file_whole(NULL,&pbuf,&bufsize);
	buflen = 0;
	SETERRNO(ret);
	return ret;
}
