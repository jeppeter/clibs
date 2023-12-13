


typedef struct __chatsvr_conn {
	void* m_psock;
	void* m_paccsock;
	void* m_pevmain;
	int m_insertrd;
	int m_insertwr;
	char m_rdbuf[256];
	HANDLE m_rdhd;
	HANDLE m_wrhd;
	int m_rdsize;
	int m_rdlen;
	int m_rdsidx;
	int m_rdeidx;
	char* m_pwrbuf;
	int m_wrsize;
	int m_wrlen;
	std::vector<char*> *m_ppwrbufs;
	std::vector<int> *m_pwrlens;
} chatsvr_conn_t, *pchatsvr_conn_t;


typedef struct __chatsvr_acc {
	void* m_psock;
	void* m_pevmain;
	char* m_ipaddr;
	int m_port;
	int m_inserted;
	HANDLE m_acchd;
	std::vector<pchatsvr_conn_t> *m_pconns;
} chatsvr_acc_t, *pchatsvr_acc_t;

int __find_conn(pchatsvr_acc_t pacc, pchatsvr_conn_t pconn)
{
	unsigned int i;
	int fidx = -1;
	pchatsvr_conn_t pcur;
	if (pacc->m_pconns->size() > 0) {
		if (pconn != NULL) {
			for (i = 0; i < pacc->m_pconns->size(); i++) {
				pcur = pacc->m_pconns->at(i);
				if (pcur == pconn) {
					fidx = (int)i;
					break;
				}
			}
		} else {
			fidx = 0;
		}
	}
	return fidx;
}

int remove_conn(void* pacc1, pchatsvr_conn_t pconn)
{
	pchatsvr_acc_t pacc = (pchatsvr_acc_t)pacc1;
	int fidx = -1;

	fidx = __find_conn(pacc, pconn);
	if (fidx < 0) {
		return 0;
	}

	pacc->m_pconns->erase(pacc->m_pconns->begin() + fidx);
	return 1;
}

void __stop_chatsvr_conn_event(pchatsvr_conn_t* ppconn)
{
	int ret;
	if (ppconn && *ppconn) {
		pchatsvr_conn_t pconn = *ppconn;
		if (pconn->m_insertrd > 0) {
			ASSERT_IF(pconn->m_rdhd != NULL);
			//DEBUG_INFO("remove %p",pconn->m_rdhd);
			ret = libev_remove_handle(pconn->m_pevmain, pconn->m_rdhd);
			ASSERT_IF(ret >= 0);
		}
		pconn->m_insertrd = 0;

		if (pconn->m_insertwr > 0) {
			ASSERT_IF(pconn->m_wrhd != NULL);
			//DEBUG_INFO("remove %p",pconn->m_wrhd);
			ret = libev_remove_handle(pconn->m_pevmain, pconn->m_wrhd);
			ASSERT_IF(ret >= 0);
		}
		pconn->m_insertwr = 0;
	}
}

void __free_chatsvr_conn(pchatsvr_conn_t* ppconn)
{
	__stop_chatsvr_conn_event(ppconn);
	if (ppconn && *ppconn) {
		pchatsvr_conn_t pconn = *ppconn;

		if (pconn->m_paccsock) {
			remove_conn(pconn->m_paccsock, pconn);
		}
		pconn->m_paccsock = NULL;


		free_socket(&pconn->m_psock);

		/*to free write buffers for it will CancelIoEx in free_socket*/
		if (pconn->m_pwrbuf) {
			free(pconn->m_pwrbuf);
		}
		pconn->m_pwrbuf = NULL;

		if (pconn->m_ppwrbufs && pconn->m_pwrlens) {
			while (pconn->m_ppwrbufs->size() > 0) {
				ASSERT_IF(pconn->m_ppwrbufs->size() == pconn->m_pwrlens->size());
				char* pwbuf = pconn->m_ppwrbufs->at(0);
				pconn->m_ppwrbufs->erase(pconn->m_ppwrbufs->begin());
				pconn->m_pwrlens->erase(pconn->m_pwrlens->begin());
				free(pwbuf);
				pwbuf = NULL;
			}
		}

		if (pconn->m_ppwrbufs) {
			delete pconn->m_ppwrbufs;
		}
		pconn->m_ppwrbufs = NULL;

		if (pconn->m_pwrlens) {
			delete pconn->m_pwrlens;
		}
		pconn->m_pwrlens = NULL;

		pconn->m_rdsize = 0;
		pconn->m_rdlen = 0;
		pconn->m_rdsidx = 0;
		pconn->m_rdeidx = 0;
		pconn->m_wrhd = NULL;
		pconn->m_rdhd = NULL;

		free(pconn);
		*ppconn = NULL;
	}
	return;
}

pchatsvr_conn_t __alloc_chatsvr_conn(void* psock, void* paccsock, void* pevmain)
{
	pchatsvr_conn_t pconn = NULL;
	int ret = -1;
	pconn = (pchatsvr_conn_t) malloc(sizeof(*pconn));
	if (pconn == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}
	memset(pconn, 0, sizeof(*pconn));
	pconn->m_psock = NULL;
	pconn->m_paccsock = paccsock;
	pconn->m_pevmain = pevmain;
	pconn->m_insertrd = 0;
	pconn->m_insertwr = 0;
	pconn->m_psock = psock;
	pconn->m_rdsize = sizeof(pconn->m_rdbuf);
	pconn->m_rdlen = 0;
	pconn->m_rdsidx = 0;
	pconn->m_rdeidx = 0;
	pconn->m_rdhd = NULL;
	pconn->m_wrhd = NULL;

	pconn->m_pwrbuf  = NULL;
	pconn->m_wrsize  = 0;
	pconn->m_ppwrbufs = NULL;
	pconn->m_pwrlens = NULL;
	pconn->m_ppwrbufs = new std::vector<char*>();
	pconn->m_pwrlens = new std::vector<int>();


	return pconn;
fail:
	__free_chatsvr_conn(&pconn);
	SETERRNO(ret);
	return NULL;
}



void __free_chatsvr_acc(pchatsvr_acc_t* ppacc)
{
	int ret;
	if (ppacc && *ppacc) {
		pchatsvr_acc_t pacc = *ppacc;
		if (pacc->m_inserted > 0) {
			DEBUG_INFO("remove %p",pacc->m_acchd);
			ret = libev_remove_handle(pacc->m_pevmain, pacc->m_acchd);
			ASSERT_IF(ret >= 0);
		}
		pacc->m_inserted = 0;
		pacc->m_acchd = NULL;

		if (pacc->m_pconns != NULL)	 {
			while (pacc->m_pconns->size() > 0) {
				pchatsvr_conn_t pconn = pacc->m_pconns->at(0);
				pacc->m_pconns->erase(pacc->m_pconns->begin());
				__free_chatsvr_conn(&pconn);
			}
			delete pacc->m_pconns;
		}
		pacc->m_pconns = NULL;

		if (pacc->m_ipaddr) {
			free(pacc->m_ipaddr);
		}
		pacc->m_ipaddr = NULL;
		pacc->m_port = -1;
		pacc->m_pevmain = NULL;
		free_socket(&pacc->m_psock);
		free(pacc);
		*ppacc = NULL;
	}
	return;
}

pchatsvr_acc_t __alloc_chatsvr_acc(const char* ipaddr, int port)
{
	pchatsvr_acc_t pacc = NULL;
	int ret;

	pacc = (pchatsvr_acc_t) malloc(sizeof(*pacc));
	if (pacc == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}
	memset(pacc, 0, sizeof(*pacc));
	pacc->m_psock = NULL;
	pacc->m_inserted = 0;
	pacc->m_pconns = NULL;
	pacc->m_ipaddr = NULL;
	pacc->m_port = -1;
	pacc->m_pevmain = NULL;
	pacc->m_acchd = NULL;

	pacc->m_ipaddr = _strdup(ipaddr);
	if (pacc->m_ipaddr == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	pacc->m_port = port;

	pacc->m_psock = bind_tcp_socket(pacc->m_ipaddr, pacc->m_port, 5);
	if (pacc->m_psock == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}
	pacc->m_pconns = new std::vector<pchatsvr_conn_t>();

	return pacc;
fail:
	__free_chatsvr_acc(&pacc);
	SETERRNO(ret);
	return NULL;
}

int exit_chatsvr(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	DEBUG_INFO(" ");
	REFERENCE_ARG(args);
	REFERENCE_ARG(event);
	REFERENCE_ARG(hd);
	libev_break_winev_loop(pevmain);
	return 0;
}

int write_chatsvr_conn_callback(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	pchatsvr_conn_t pconn = (pchatsvr_conn_t)args;
	int ret;
	DEBUG_INFO(" ");
	REFERENCE_ARG(pevmain);
	REFERENCE_ARG(hd);
	if (event == normal_event && pconn != NULL) {
		ret = complete_tcp_write(pconn->m_psock);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret > 0) {
			free(pconn->m_pwrbuf);
			pconn->m_pwrbuf = NULL;
			pconn->m_wrsize = 0;
			DEBUG_INFO("remove %p",pconn->m_wrhd);
			ret = libev_remove_handle(pconn->m_pevmain, pconn->m_wrhd);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail_really;
			}
			pconn->m_insertwr = 0;

			if (pconn->m_ppwrbufs->size() > 0) {
				while (pconn->m_ppwrbufs->size() > 0) {
					ASSERT_IF(pconn->m_ppwrbufs->size() == pconn->m_pwrlens->size());
					ASSERT_IF(pconn->m_pwrbuf == NULL);
					pconn->m_pwrbuf = pconn->m_ppwrbufs->at(0);
					pconn->m_wrsize = pconn->m_pwrlens->at(0);
					pconn->m_ppwrbufs->erase(pconn->m_ppwrbufs->begin());
					pconn->m_pwrlens->erase(pconn->m_pwrlens->begin());
					ret = write_tcp_socket(pconn->m_psock, (uint8_t*)pconn->m_pwrbuf, pconn->m_wrsize);
					if (ret < 0) {
						GETERRNO(ret);
						ERROR_INFO(" ");
						goto fail;
					} else if (ret == 0) {
						break;
					}
					/*completed*/
					free(pconn->m_pwrbuf);
					pconn->m_pwrbuf = NULL;
					pconn->m_wrsize = 0;
				}
			}

			if (pconn->m_pwrbuf != NULL && pconn->m_insertwr == 0) {
				DEBUG_INFO("insert wrhd %p",pconn->m_wrhd);
				ret = libev_insert_handle(pconn->m_pevmain, pconn->m_wrhd, write_chatsvr_conn_callback, pconn);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO(" ");
					goto fail_really;
				}
				pconn->m_insertwr = 1;
			}
		}

	}

	return 0;
fail:
	__free_chatsvr_conn(&pconn);
	SETERRNO(ret);
	return 0;
fail_really:
	SETERRNO(ret);
	return ret;
}

int write_chatsvr_conn(pchatsvr_conn_t pconn)
{
	char* pwrbuf = NULL;
	int wrsize = 0;
	int startwr = 0;
	int curidx;
	int ret;
	int i;

	wrsize = pconn->m_rdlen;
	pwrbuf = (char*)malloc((size_t)wrsize);
	if (pwrbuf == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	//DEBUG_INFO("pwrbuf %p wrsize %d",pwrbuf,wrsize);
	for (i = 0; i < pconn->m_rdlen; i++) {
		curidx = pconn->m_rdsidx + i;
		curidx %= pconn->m_rdsize;
		//DEBUG_INFO("[%d] => [%d]",curidx, i);
		pwrbuf[i] = pconn->m_rdbuf[curidx];
	}
	pconn->m_rdlen = 0;
	pconn->m_rdsidx = pconn->m_rdeidx;
	//DEBUG_INFO("m_rdsidx %d",pconn->m_rdsidx);

	if (pconn->m_pwrbuf == NULL) {
		DEBUG_BUFFER_FMT(pwrbuf,wrsize,"buffer");
		pconn->m_pwrbuf = pwrbuf;
		pwrbuf = NULL;
		pconn->m_wrsize = wrsize;
		ret = write_tcp_socket(pconn->m_psock, (uint8_t*)pconn->m_pwrbuf, pconn->m_wrsize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret > 0) {
			free(pconn->m_pwrbuf);
			pconn->m_pwrbuf = NULL;
			pconn->m_wrsize = 0;
		} else {
			/*not write ok*/
			ASSERT_IF(pconn->m_insertwr == 0);
			pconn->m_wrhd = get_tcp_write_handle(pconn->m_psock);
			//DEBUG_INFO("insert wrhd %p",pconn->m_wrhd);
			ret =  libev_insert_handle(pconn->m_pevmain, pconn->m_wrhd, write_chatsvr_conn_callback, pconn);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
			pconn->m_insertwr = 1;
		}
	} else {
		pconn->m_ppwrbufs->push_back(pwrbuf);
		pconn->m_pwrlens->push_back(wrsize);
		pwrbuf = NULL;
		wrsize = 0;
	}

	return startwr;
fail:
	if (startwr > 0) {
		__stop_chatsvr_conn_event(&pconn);
	}
	startwr = 0;
	if (pwrbuf) {
		free(pwrbuf);
	}
	pwrbuf = NULL;
	SETERRNO(ret);
	return ret;
}

int read_chatsvr_conn(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args);

int read_chatsvr_conn_inner(pchatsvr_conn_t pconn)
{
	int ret;
	while (1) {
		if (pconn->m_rdlen >= pconn->m_rdsize) {
			ret = write_chatsvr_conn(pconn);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
		}

		ret = read_tcp_socket(pconn->m_psock, (uint8_t*) & (pconn->m_rdbuf[pconn->m_rdeidx]), 1);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret == 0) {
			break;
		}
		pconn->m_rdlen ++;
		pconn->m_rdeidx ++;
		pconn->m_rdeidx %= pconn->m_rdsize;
	}
	if (pconn->m_rdlen > 0) {
		ret = write_chatsvr_conn(pconn);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
	}

	if (pconn->m_insertrd == 0) {
		pconn->m_rdhd = get_tcp_read_handle(pconn->m_psock);
		//DEBUG_INFO("insert rdhd %p",pconn->m_rdhd);
		ret =  libev_insert_handle(pconn->m_pevmain, pconn->m_rdhd, read_chatsvr_conn, pconn);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
		pconn->m_insertrd = 1;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int read_chatsvr_conn(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	pchatsvr_conn_t pconn = (pchatsvr_conn_t) args;
	int ret;
	REFERENCE_ARG(pevmain);
	REFERENCE_ARG(hd);
	if (event == normal_event && pconn != NULL) {
		ret = complete_tcp_read(pconn->m_psock);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret > 0) {
			pconn->m_rdeidx ++;
			pconn->m_rdeidx %= pconn->m_rdsize;
			pconn->m_rdlen ++;
			ret =  read_chatsvr_conn_inner(pconn);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
		}
	}

	return 0;
fail:
	__free_chatsvr_conn(&pconn);
	DEBUG_INFO("pconn remove");
	SETERRNO(ret);
	return 0;
}

int accept_chatsvr(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	pchatsvr_acc_t pacc = (pchatsvr_acc_t)args;
	pchatsvr_conn_t pconn = NULL;
	void* psock = NULL;
	int ret;
	//DEBUG_INFO(" ");
	REFERENCE_ARG(hd);
	if (event == normal_event) {
		ASSERT_IF(pacc->m_psock != NULL);
		while (1) {
			ret = complete_tcp_accept(pacc->m_psock);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			} else if (ret > 0) {
				psock = accept_tcp_socket(pacc->m_psock);
				if (psock == NULL) {
					GETERRNO(ret);
					ERROR_INFO(" ");
					goto fail;
				}

				pconn = __alloc_chatsvr_conn(psock, pacc, pevmain);
				if (pconn == NULL) {
					GETERRNO(ret);
					ERROR_INFO(" ");
					goto fail;
				}
				psock = NULL;

				ret = read_chatsvr_conn_inner(pconn);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO(" ");
					goto fail;
				}

				/*now to add */
				pacc->m_pconns->push_back(pconn);
			} else {
				break;
			}

		}
	}
	return 0;
fail:
	free_socket(&psock);
	__free_chatsvr_conn(&pconn);
	SETERRNO(ret);
	return ret;
}


int evchatsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret = 0;
	int port = 4099;
	const char* ipaddr = "0.0.0.0";
	void* pevmain = NULL;
	pchatsvr_acc_t psvr = NULL;
	pargs_options_t pargs = (pargs_options_t) popt;
	HANDLE exithd = NULL;
	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			ipaddr = parsestate->leftargs[1];
		}
	}

	pevmain = libev_init_winev();
	if (pevmain == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	ret = init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		fprintf(stderr, "cannot init_socket error[%d]\n", ret);
		goto out;
	}

	psvr = __alloc_chatsvr_acc(ipaddr, port);
	if (psvr == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}


	psvr->m_pevmain = pevmain;
	psvr->m_acchd= get_tcp_accept_handle(psvr->m_psock);
	//DEBUG_INFO("insert accept handle %p",psvr->m_acchd);
	ret = libev_insert_handle(pevmain, psvr->m_acchd, accept_chatsvr, psvr);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}
	psvr->m_inserted = 1;

	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	//DEBUG_INFO("insert exithd %p",exithd);
	ret =  libev_insert_handle(pevmain, exithd, exit_chatsvr, NULL);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	DEBUG_INFO("listen on [%s:%d]",ipaddr,port);

	ret = libev_winev_loop(pevmain);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	fprintf(stdout, "exit winev ok\n");
	ret = 0;
out:
	__free_chatsvr_acc(&psvr);
	libev_free_winev(&pevmain);
	fini_socket();
	SETERRNO(ret);
	return ret;
}

typedef struct __chatcli {
	void* m_psock;
	void* m_pevmain;
	char* m_connip;
	int m_port;
	int m_insertrd;
	int m_insertwr;
	int m_insertconn;
	int m_inserttimeout;
	int m_insertstdin;
	uint64_t m_timeoutguid;
	HANDLE m_connhd;
	HANDLE m_rdhd;
	HANDLE m_wrhd;
	HANDLE m_stdinhd;
	char* m_pwrbuf;
	int m_wrsize;
	int m_reserv1;
	std::vector<char*> *m_ppwrbufs;
	std::vector<int> *m_pwrlens;
	char m_rdbuf[256];
	int m_rdsidx;
	int m_rdeidx;
	int m_rdlen;
	char m_stdinrdbuf[256];
	int m_stdinrdlen;
	int m_stdinrdsidx;
	int m_stdinrdeidx;
} chatcli_t, *pchatcli_t;

void __stop_chatcli(pchatcli_t*ppcli)
{
	int ret;
	if (ppcli && *ppcli) {
		pchatcli_t pcli = *ppcli;
		if (pcli->m_inserttimeout > 0) {
			ret = libev_remove_timer(pcli->m_pevmain, pcli->m_timeoutguid);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_inserttimeout = 0;
		pcli->m_timeoutguid = 0;

		if (pcli->m_insertconn > 0) {
			DEBUG_INFO("remove %p",pcli->m_connhd);
			ret = libev_remove_handle(pcli->m_pevmain, pcli->m_connhd);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_insertconn  = 0;

		if (pcli->m_insertrd > 0) {
			DEBUG_INFO("remove %p",pcli->m_rdhd);
			ret = libev_remove_handle(pcli->m_pevmain, pcli->m_rdhd);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_insertrd = 0;

		if (pcli->m_insertwr > 0) {
			DEBUG_INFO("remove %p",pcli->m_wrhd);
			ret = libev_remove_handle(pcli->m_pevmain, pcli->m_wrhd);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_insertwr = 0;

		if (pcli->m_insertstdin > 0) {
			DEBUG_INFO("remove %p",pcli->m_stdinhd);
			ret = libev_remove_handle(pcli->m_pevmain, pcli->m_stdinhd);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_insertstdin = 0;

	}
}

void __free_chatcli(pchatcli_t*ppcli)
{

	__stop_chatcli(ppcli);
	if (ppcli && *ppcli) {
		pchatcli_t pcli = *ppcli;

		if (pcli->m_connip) {
			free(pcli->m_connip);
		}
		pcli->m_connip = NULL;
		pcli->m_port = -1;

		pcli->m_stdinhd = NULL;
		pcli->m_wrhd = NULL;
		pcli->m_rdhd = NULL;
		pcli->m_connhd = NULL;
		free_socket(&(pcli->m_psock));

		/*we put here to free the buffer ,because in free_socket will cancelio*/

		pcli->m_rdsidx = 0;
		pcli->m_rdlen = 0;
		pcli->m_rdeidx = 0;
		memset(pcli->m_rdbuf, 0, sizeof(pcli->m_rdbuf));

		pcli->m_stdinrdlen = 0;
		pcli->m_stdinrdsidx = 0;
		pcli->m_stdinrdeidx = 0;
		memset(pcli->m_stdinrdbuf, 0, sizeof(pcli->m_stdinrdbuf));

		if (pcli->m_pwrbuf) {
			free(pcli->m_pwrbuf);
		}
		pcli->m_pwrbuf = NULL;
		pcli->m_wrsize = 0;

		if (pcli->m_ppwrbufs && pcli->m_pwrlens) {
			while (pcli->m_ppwrbufs->size() > 0) {
				ASSERT_IF(pcli->m_ppwrbufs->size() == pcli->m_pwrlens->size());
				char* pwrbuf = pcli->m_ppwrbufs->at(0);
				pcli->m_ppwrbufs->erase(pcli->m_ppwrbufs->begin());
				pcli->m_pwrlens->erase(pcli->m_pwrlens->begin());
				free(pwrbuf);
				pwrbuf = NULL;
			}
		}

		if (pcli->m_ppwrbufs) {
			delete pcli->m_ppwrbufs;
		}
		pcli->m_ppwrbufs = NULL;

		if (pcli->m_pwrlens) {
			delete pcli->m_pwrlens;
		}
		pcli->m_pwrlens = NULL;


		free(pcli);
		*ppcli = NULL;
	}
}

pchatcli_t __alloc_chat_cli(char* connip, int port)
{
	pchatcli_t pcli = NULL;
	int ret;

	pcli = (pchatcli_t) malloc(sizeof(*pcli));
	if (pcli == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	memset(pcli, 0, sizeof(*pcli));
	pcli->m_psock = NULL;
	pcli->m_pevmain = NULL;
	pcli->m_connip = NULL;
	pcli->m_port = -1;

	pcli->m_insertrd = 0;
	pcli->m_insertwr = 0;
	pcli->m_insertconn = 0;
	pcli->m_inserttimeout = 0;
	pcli->m_insertstdin = 0;

	pcli->m_timeoutguid = 0;

	pcli->m_connhd = NULL;
	pcli->m_rdhd = NULL;
	pcli->m_wrhd = NULL;
	pcli->m_ppwrbufs = NULL;
	pcli->m_pwrlens = NULL;
	pcli->m_pwrbuf = NULL;
	pcli->m_wrsize = 0;

	pcli->m_stdinhd = GetStdHandle(STD_INPUT_HANDLE);
	if (pcli->m_stdinhd == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	pcli->m_psock = connect_tcp_socket(connip, port, NULL, 0, 0);
	if (pcli->m_psock == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	pcli->m_connip = _strdup(connip);
	if (pcli->m_connip == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}
	pcli->m_port = port;

	pcli->m_ppwrbufs = new std::vector<char*>();
	pcli->m_pwrlens = new std::vector<int>();

	return pcli;
fail:
	__free_chatcli(&pcli);
	SETERRNO(ret);
	return NULL;
}

int chatcli_pop_write_buffers(pchatcli_t pcli)
{
	int ret;
	while (pcli->m_ppwrbufs->size() > 0) {
		ASSERT_IF(pcli->m_pwrbuf == NULL);
		ASSERT_IF(pcli->m_ppwrbufs->size() == pcli->m_pwrlens->size());
		pcli->m_pwrbuf = pcli->m_ppwrbufs->at(0);
		pcli->m_wrsize = pcli->m_pwrlens->at(0);
		pcli->m_ppwrbufs->erase(pcli->m_ppwrbufs->begin());
		pcli->m_pwrlens->erase(pcli->m_pwrlens->begin());
		ret = write_tcp_socket(pcli->m_psock, (uint8_t*)pcli->m_pwrbuf, pcli->m_wrsize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret == 0) {
			break;
		}
		free(pcli->m_pwrbuf);
		pcli->m_pwrbuf = NULL;
		pcli->m_wrsize = 0;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int write_chatcli_conn_callback(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	int ret;
	pchatcli_t pcli = (pchatcli_t)args;
	DEBUG_INFO(" ");
	REFERENCE_ARG(pevmain);
	REFERENCE_ARG(hd);
	if (event == normal_event) {
		ret = complete_tcp_write(pcli->m_psock);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret > 0) {
			free(pcli->m_pwrbuf);
			pcli->m_pwrbuf = NULL;
			pcli->m_wrsize = 0;

			ret = chatcli_pop_write_buffers(pcli);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}

			if (pcli->m_pwrbuf == NULL && pcli->m_insertwr > 0) {
				DEBUG_INFO("remove %p",pcli->m_wrhd);
				ret = libev_remove_handle(pcli->m_pevmain, pcli->m_wrhd);
				if (ret < 0) {
					GETERRNO(ret);
					pcli->m_insertwr = 0;
					ERROR_INFO(" ");
					goto fail;
				}
				pcli->m_insertwr = 0;
			}
		}
	}

	return 0;

fail:
	SETERRNO(ret);
	return ret;
}

int write_chatcli_stdout(pchatcli_t pcli)
{
	char* pwrbuf = NULL;
	int wrsize = 0;
	int i;
	int ret;
	int curidx;

	wrsize = pcli->m_rdlen;
	pwrbuf = (char*) malloc((size_t)wrsize+1);
	if (pwrbuf == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	memset(pwrbuf,0,(size_t)wrsize + 1);
	for (i = 0; i < pcli->m_rdlen; i++) {
		curidx = pcli->m_rdsidx + i;
		curidx %= sizeof(pcli->m_rdbuf);
		pwrbuf[i] = pcli->m_rdbuf[curidx];
	}
	pcli->m_rdsidx = pcli->m_rdeidx;
	pcli->m_rdlen = 0;
	DEBUG_INFO("m_rdsidx %d m_rdlen %d",pcli->m_rdsidx,pcli->m_rdlen);
	fprintf(stdout,"%s",pwrbuf);
	fflush(stdout);
	free(pwrbuf);
	pwrbuf = NULL;
	return 0;
fail:
	if (pwrbuf) {
		free(pwrbuf);
	}
	pwrbuf = NULL;
	SETERRNO(ret);
	return ret;
}

int write_chatcli_stdout_conn(pchatcli_t pcli)
{
	char* pwrbuf = NULL;
	int wrsize = 0;
	int i;
	int ret;
	int curidx;

	wrsize = pcli->m_stdinrdlen;
	pwrbuf = (char*) malloc((size_t)wrsize);
	if (pwrbuf == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	if (pcli->m_stdinrdlen > 128) {
		ERROR_INFO("need write %d",pcli->m_stdinrdlen);
	}

	for (i = 0; i < pcli->m_stdinrdlen; i++) {
		curidx = pcli->m_stdinrdsidx + i;
		curidx %= sizeof(pcli->m_stdinrdbuf);
		pwrbuf[i] = pcli->m_stdinrdbuf[curidx];
	}
	pcli->m_stdinrdsidx = pcli->m_stdinrdeidx;
	pcli->m_stdinrdlen = 0;

	if (pcli->m_pwrbuf == NULL) {
		pcli->m_pwrbuf = pwrbuf;
		pcli->m_wrsize = wrsize;
		pwrbuf = NULL;
		wrsize = 0;
		ret =  write_tcp_socket(pcli->m_psock, (uint8_t*)pcli->m_pwrbuf, pcli->m_wrsize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret > 0) {
			free(pcli->m_pwrbuf);
			pcli->m_pwrbuf = NULL;
			pcli->m_wrsize = 0;
			if (pcli->m_insertwr > 0) {
				DEBUG_INFO("remove %p",pcli->m_wrhd);
				ret = libev_remove_handle(pcli->m_pevmain, pcli->m_wrhd);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO(" ");
					goto fail;
				}
				pcli->m_insertwr = 0;
			}
		}
	} else {
		pcli->m_ppwrbufs->push_back(pwrbuf);
		pcli->m_pwrlens->push_back(wrsize);
		pwrbuf = NULL;
		wrsize = 0;
	}

	if (pcli->m_pwrbuf == NULL) {
		ret =  chatcli_pop_write_buffers(pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
	}

	if (pcli->m_pwrbuf != NULL) {
		if (pcli->m_insertwr == 0) {
			pcli->m_wrhd = get_tcp_write_handle(pcli->m_psock);
			DEBUG_INFO("insert wrhd %p",pcli->m_wrhd);
			ret = libev_insert_handle(pcli->m_pevmain, pcli->m_wrhd, write_chatcli_conn_callback, pcli);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
			pcli->m_insertwr = 1;
		}
	}

	return 0;
fail:
	if (pwrbuf) {
		free(pwrbuf);
	}
	pwrbuf = NULL;
	wrsize = 0;
	SETERRNO(ret);
	return ret;
}

int write_chatcli_conn(pchatcli_t pcli)
{
	char* pwrbuf = NULL;
	int wrsize = 0;
	int i;
	int ret;
	int curidx;

	wrsize = pcli->m_rdlen + 1;
	pwrbuf = (char*) malloc((size_t)wrsize);
	if (pwrbuf == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	memset(pwrbuf, 0, (size_t)wrsize);
	for (i = 0; i < pcli->m_rdlen; i++) {
		curidx = pcli->m_rdsidx + i;
		curidx %= sizeof(pcli->m_rdbuf);
		pwrbuf[i] = pcli->m_rdbuf[curidx];
	}

	pcli->m_rdlen = 0;
	pcli->m_rdsidx = pcli->m_rdeidx;

	fprintf(stdout, "%s", pwrbuf);
	fflush(stdout);
	free(pwrbuf);
	pwrbuf = NULL;

	return 0;
fail:
	if (pwrbuf) {
		free(pwrbuf);
	}
	pwrbuf = NULL;
	wrsize = 0;
	SETERRNO(ret);
	return ret;
}

int read_chatcli_stdin(pchatcli_t pcli);

int read_chatcli_stdin_callback(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	int ret;
	pchatcli_t pcli = (pchatcli_t)args;
	REFERENCE_ARG(hd);
	REFERENCE_ARG(pevmain);
	if (event == normal_event) {
		ret = read_chatcli_stdin(pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
	}
	return 0;
fail:
	return ret;
}

int read_chatcli_conn(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args);
int read_chatcli_conn_inner(pchatcli_t pcli)
{
	int ret;
	/*connected*/
	while (1) {
		ret = read_tcp_socket(pcli->m_psock, (uint8_t*)&(pcli->m_rdbuf[pcli->m_rdeidx]), 1);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret == 0) {
			break;
		}
		pcli->m_rdlen ++;
		pcli->m_rdeidx ++;
		pcli->m_rdeidx %= sizeof(pcli->m_rdbuf);
		if (pcli->m_rdlen == sizeof(pcli->m_rdbuf)) {
			ret = write_chatcli_stdout(pcli);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
		}
	}

	if (pcli->m_rdlen != 0) {
		ret =  write_chatcli_stdout(pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
	}

	/*now to add */
	pcli->m_rdhd = get_tcp_read_handle(pcli->m_psock);
	if (pcli->m_insertrd == 0) {
		DEBUG_INFO("insert rdhd %p",pcli->m_rdhd);
		ret = libev_insert_handle(pcli->m_pevmain, pcli->m_rdhd, read_chatcli_conn, pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
		pcli->m_insertrd = 1;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;

}

int connect_chatcli_conn(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	pchatcli_t pcli = (pchatcli_t)args;
	int ret;
	REFERENCE_ARG(hd);
	REFERENCE_ARG(pevmain);
	if (event == normal_event) {
		ret = complete_tcp_connect(pcli->m_psock);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		} else if (ret > 0) {
			ASSERT_IF(pcli->m_insertconn > 0);
			DEBUG_INFO("remove %p",pcli->m_connhd);
			ret = libev_remove_handle(pcli->m_pevmain, pcli->m_connhd);
			ASSERT_IF(ret >= 0);
			pcli->m_insertconn = 0;
			ASSERT_IF(pcli->m_inserttimeout > 0);
			ret = libev_remove_timer(pcli->m_pevmain, pcli->m_timeoutguid);
			ASSERT_IF(ret >= 0);
			pcli->m_inserttimeout = 0;
			ret = read_chatcli_conn_inner(pcli);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
			DEBUG_INFO("read chatcli over");

			ret = read_chatcli_stdin(pcli);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
			DEBUG_INFO("read chatcli stdin over");
		}
	}
	DEBUG_INFO("connect_chatcli_conn return 0");
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int connect_chatcli_timeout(uint64_t guid,libev_enum_event_t event,void* pevmain,void* args)
{
	int ret;
	pchatcli_t pcli = (pchatcli_t)args;
	REFERENCE_ARG(pevmain);
	if (event == timer_event && pcli->m_timeoutguid == guid) {
		ret = -ETIMEDOUT;
		ERROR_INFO("connect [%s:%d] timedout", pcli->m_connip, pcli->m_port);
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;

}

int read_chatcli_conn(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	int ret;
	pchatcli_t pcli = (pchatcli_t)args;
	REFERENCE_ARG(hd);
	REFERENCE_ARG(pevmain);
	if (event == normal_event) {
		ret = complete_tcp_read(pcli->m_psock);
		if (ret > 0) {
			pcli->m_rdeidx ++;
			pcli->m_rdlen ++;
			pcli->m_rdeidx %= sizeof(pcli->m_rdbuf);
			if (pcli->m_rdlen == sizeof(pcli->m_rdbuf)) {
				ret = write_chatcli_stdout(pcli);
				if (ret < 0) {
					GETERRNO(ret);
					ERROR_INFO(" ");
					goto fail;
				}
			}

			ret = read_chatcli_conn_inner(pcli);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
		} else if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}

	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int read_chatcli_stdin(pchatcli_t pcli)
{
	int ret;
	INPUT_RECORD ir;
	DWORD retnum;
	int iscr = 0;
	BOOL bret;
	int maxcnt=1;
	int cnt=0;

	while (cnt < maxcnt) {
		cnt ++;
		DEBUG_INFO("before PeekConsoleInput");
		bret = PeekConsoleInput(pcli->m_stdinhd, &ir, 1, &retnum);
		DEBUG_INFO("after PeekConsoleInput %s",bret ? "TRUE" : "FALSE");
		if (!bret) {
			break;
		}
		bret = ReadConsoleInput(pcli->m_stdinhd, &ir, 1, &retnum);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}


		if (pcli->m_stdinrdlen >= (sizeof(pcli->m_stdinrdbuf) - 2)) {
			ret = write_chatcli_stdout_conn(pcli);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
		}

		if (ir.EventType == KEY_EVENT  && ir.Event.KeyEvent.bKeyDown) {
			//DEBUG_BUFFER_FMT(&(ir[i]),sizeof(ir[0]),"[%d] ir  0x%x",i,ir[i].Event.KeyEvent.uChar.AsciiChar);
			if (ir.Event.KeyEvent.uChar.AsciiChar != 0) {
				pcli->m_stdinrdbuf[pcli->m_stdinrdeidx] = ir.Event.KeyEvent.uChar.AsciiChar;
				if (ir.Event.KeyEvent.uChar.AsciiChar == '\r') {
					iscr = 1;
				}
				pcli->m_stdinrdeidx ++;
				pcli->m_stdinrdlen ++;
				pcli->m_stdinrdeidx %= sizeof(pcli->m_stdinrdbuf);
				if (iscr) {
					pcli->m_stdinrdbuf[pcli->m_stdinrdeidx] = '\n';
					pcli->m_stdinrdeidx ++;
					pcli->m_stdinrdlen ++;
					pcli->m_stdinrdeidx %= sizeof(pcli->m_stdinrdbuf);
				}
				iscr = 0;
			}
		}
	}

	if (pcli->m_stdinrdlen > 0) {
		ret = write_chatcli_stdout_conn(pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
	}

	if (pcli->m_insertstdin == 0) {
		DEBUG_INFO("insert stdinhd %p",pcli->m_stdinhd);
		ret = libev_insert_handle(pcli->m_pevmain, pcli->m_stdinhd, read_chatcli_stdin_callback, pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
		pcli->m_insertstdin = 1;
	}
	DEBUG_INFO("read_chatcli_stdin return 0");

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int exit_chatcli(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	REFERENCE_ARG(args);
	REFERENCE_ARG(event);
	REFERENCE_ARG(hd);
	DEBUG_INFO("exit_chatcli");
	libev_break_winev_loop(pevmain);
	return 0;
}


int evchatcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret = 0;
	char* connip = "127.0.0.1";
	int port = 4099;
	pargs_options_t pargs =  (pargs_options_t) popt;
	HANDLE exithd = NULL;
	pchatcli_t pcli = NULL;
	void* pevmain = NULL;
	HANDLE connhd = NULL;
	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			connip = parsestate->leftargs[1];
		}
	}

	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	ret =  init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	pevmain = libev_init_winev();
	if (pevmain == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	pcli = __alloc_chat_cli(connip, port);
	if (pcli == NULL) {
		GETERRNO(ret);	
		ERROR_INFO(" ");
		goto out;
	}

	pcli->m_pevmain = pevmain;

	connhd = get_tcp_connect_handle(pcli->m_psock);
	if (connhd == NULL) {
		ret = read_chatcli_conn_inner(pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto out;
		}
	} else {
		/*not connected*/
		pcli->m_connhd = get_tcp_connect_handle(pcli->m_psock);
		DEBUG_INFO("insert connhd %p",pcli->m_connhd);
		ret = libev_insert_handle(pcli->m_pevmain, pcli->m_connhd, connect_chatcli_conn, pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto out;
		}
		pcli->m_insertconn = 1;

		ret = libev_insert_timer(pcli->m_pevmain, &(pcli->m_timeoutguid), connect_chatcli_timeout, pcli, 5000, 0);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto out;
		}
		pcli->m_inserttimeout = 1;
	}

	DEBUG_INFO("insert exithd %p",exithd);
	ret = libev_insert_handle(pevmain, exithd, exit_chatcli, NULL);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("exithd error [%d]", ret);
		goto out;
	}


	if (pcli->m_insertconn == 0) {
		ret =  read_chatcli_stdin(pcli);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto out;
		}		
	}

	ret = libev_winev_loop(pevmain);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	ret =  0;
out:
	__free_chatcli(&pcli);
	libev_free_winev(&pevmain);
	close_ctrlc_handle();
	SETERRNO(ret);
	return ret;
}



int stdinev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret;
	HANDLE hstdin = NULL;
	HANDLE hrestdin = NULL;
	DWORD dret;
	pargs_options_t pargs = (pargs_options_t)popt;
	HANDLE exithd = NULL;
	HANDLE waithds[3];
	DWORD waitnum = 0;
	HANDLE hd;
	INPUT_RECORD ir[10];
	DWORD retnum;
	BOOL bret;
	DWORD mode;
	int isstdin = 1;
	char stdinbuf[256];
	OVERLAPPED stdinov = {0};
	DWORD i;
	int res;
	FILE_NAME_INFO* pnameinfo = NULL;
	DWORD namesize = sizeof(*pnameinfo);

	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	REFERENCE_ARG(parsestate);
	init_log_level(pargs);

	hstdin = GetStdHandle(STD_INPUT_HANDLE);

	if (hstdin == NULL || hstdin == INVALID_HANDLE_VALUE ) {
		ret = -ERROR_INVALID_PARAMETER;
		goto out;
	}

	bret = GetConsoleMode(hstdin, &mode);
	if (!bret) {
		isstdin = 0;
	}

	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto out;
	}

	if (isstdin == 0) {
		stdinov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (stdinov.hEvent == NULL) {
			GETERRNO(ret);
			fprintf(stderr, "stdinov event error[%d]\n", ret);
			goto out;
		}

		while (1) {

			if (pnameinfo) {
				free(pnameinfo);
			}
			pnameinfo = NULL;
			pnameinfo = (FILE_NAME_INFO*)malloc(namesize);
			if (pnameinfo == NULL) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto out;
			}
			memset(pnameinfo, 0, namesize);
			bret = GetFileInformationByHandleEx(hstdin, FileNameInfo, pnameinfo, namesize);
			if (bret) {
				break;
			}
			GETERRNO(ret);
			DEBUG_INFO("FileNameInfo error[%d]", ret);
			goto out;
		}
		DEBUG_BUFFER_FMT(pnameinfo, namesize, "name info");


		hrestdin = ReOpenFile(hstdin, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED);
		if (hrestdin == NULL || hrestdin == INVALID_HANDLE_VALUE) {
			hrestdin = NULL;
			GETERRNO(ret);
			ERROR_INFO("can not reopen hstdin [%d]", ret);
			goto out;
		}
#if 1
		memset(stdinbuf, 0, sizeof(stdinbuf));
		DEBUG_INFO("before ReadFile");
		bret = ReadFile(hrestdin, stdinbuf, sizeof(stdinbuf), &retnum, &stdinov);
		DEBUG_INFO("after ReadFile");
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("can not read stdin [%d]", ret);
			goto out;
		}
		//DEBUG_BUFFER_FMT(stdinbuf,retnum,"read stdin");
#endif
	}

	while (1) {
		waitnum = 0;
		waithds[waitnum] = exithd;
		waitnum ++;
		if (isstdin > 0) {
			waithds[waitnum] = hstdin;
			waitnum ++;
			DEBUG_INFO("hstdin set");
		} else {
			waithds[waitnum] = stdinov.hEvent;
			waitnum ++;
		}

		DEBUG_INFO("wait before");
		dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)300000, TRUE);
		DEBUG_INFO("wait after");
		if (dret < (WAIT_OBJECT_0 + waitnum)) {
			hd = waithds[(dret - WAIT_OBJECT_0)];
			if (hd == exithd) {
				ERROR_INFO("exithd notified");
				break;
			} else if (isstdin > 0 &&  hd == hstdin) {
#if 1
				bret = PeekConsoleInput(hstdin, ir, sizeof(ir) / sizeof(ir[0]), &retnum);
				if (bret) {
					bret = ReadConsoleInput(hstdin, ir, sizeof(ir) / sizeof(ir[0]), &retnum);
					if (!bret) {
						GETERRNO(ret);
						ERROR_INFO("can not read stdin error[%d]", ret);
						goto out;
					}
					for (i = 0; i < retnum; i++) {
						if (ir[i].EventType == KEY_EVENT  && ir[i].Event.KeyEvent.bKeyDown) {
							//DEBUG_BUFFER_FMT(&(ir[i]),sizeof(ir[0]),"[%d] ir  0x%x",i,ir[i].Event.KeyEvent.uChar.AsciiChar);
							if (ir[i].Event.KeyEvent.uChar.AsciiChar != 0) {
								fprintf(stdout, "%c", ir[i].Event.KeyEvent.uChar.AsciiChar);
								if (ir[i].Event.KeyEvent.uChar.AsciiChar == '\r') {
									fprintf(stdout, "\n");
								}
								fflush(stdout);
							}

						}
					}
				}
#endif
			} else if (isstdin == 0 && hd == stdinov.hEvent) {
				bret = GetOverlappedResult(hrestdin, &stdinov, &retnum, FALSE);
				if (!bret) {
					GETERRNO(ret);
					ERROR_INFO("GetOverlappedResult ret [%d]", ret);
					goto out;
				}
				stdinbuf[retnum] = '\0';
				fprintf(stdout, "%s", stdinbuf);
				fflush(stdout);
				memset(stdinbuf, 0, sizeof(stdinbuf));
				bret = ReadFile(hrestdin, stdinbuf, sizeof(stdinbuf), &retnum, &stdinov);
				if (!bret) {
					GETERRNO(ret);
					ERROR_INFO("ReadFile error[%d]", ret);
					goto out;
				}
			}
		} else if (dret == WAIT_TIMEOUT) {
			continue;
		} else if (dret == WAIT_IO_COMPLETION) {
			DEBUG_INFO("io completion");
			continue;
		} else {
			GETERRNO(ret);
			ERROR_INFO("wait error [%ld] %d", dret, ret);
			goto out;
		}
	}

	ret = 0;

out:
	if (isstdin == 0) {
		if (hrestdin != NULL) {
			bret = CancelIoEx(hrestdin, &stdinov);
			if (!bret) {
				GETERRNO(res);
				ERROR_INFO("cancel stdin error [%d]", res);
			}
		}
		if (stdinov.hEvent != NULL) {
			CloseHandle(stdinov.hEvent);
		}
		stdinov.hEvent = NULL;
	}
	if (hrestdin != NULL) {
		CloseHandle(hrestdin);
	}
	hrestdin = NULL;
	close_ctrlc_handle();
	hstdin = NULL;
	SETERRNO(ret);
	return ret;
}

int stdoutev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	REFERENCE_ARG(popt);
	REFERENCE_ARG(parsestate);
	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	return 0;
}