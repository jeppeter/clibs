


typedef struct __chatsvr_conn {
	void* m_psock;
	void* m_paccsock;
	void* m_pevmain;
	int m_insertrd;
	int m_insertwr;
	char m_rdbuf[256];
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
			ret = libev_remove_handle(pconn->m_pevmain, get_tcp_read_handle(pconn->m_psock));
			ASSERT_IF(ret >= 0);
		}
		pconn->m_insertrd = 0;

		if (pconn->m_insertwr > 0) {
			ret = libev_remove_handle(pconn->m_pevmain, get_tcp_write_handle(pconn->m_psock));
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
			ret = libev_remove_handle(pacc->m_pevmain, get_tcp_accept_handle(pacc->m_psock));
			ASSERT_IF(ret >= 0);
		}
		pacc->m_inserted = 0;

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
		goto fail;
	}
	memset(pacc, 0, sizeof(*pacc));
	pacc->m_psock = NULL;
	pacc->m_inserted = 0;
	pacc->m_pconns = NULL;
	pacc->m_ipaddr = NULL;
	pacc->m_port = -1;
	pacc->m_pevmain = NULL;

	pacc->m_ipaddr = _strdup(ipaddr);
	if (pacc->m_ipaddr == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	pacc->m_port = port;

	pacc->m_psock = bind_tcp_socket(pacc->m_ipaddr, pacc->m_port, 5);
	if (pacc->m_psock == NULL) {
		GETERRNO(ret);
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
	REFERENCE_ARG(pevmain);
	REFERENCE_ARG(hd);
	if (event == normal_event && pconn != NULL) {
		ret = complete_tcp_write(pconn->m_psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			free(pconn->m_pwrbuf);
			pconn->m_pwrbuf = NULL;
			pconn->m_wrsize = 0;
			ret = libev_remove_handle(pconn->m_pevmain, pconn->m_wrhd);
			if (ret < 0) {
				GETERRNO(ret);
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

			if (pconn->m_pwrbuf != NULL) {
				ret = libev_insert_handle(pconn->m_pevmain,pconn->m_wrhd,write_chatsvr_conn_callback,pconn);
				if (ret < 0) {
					GETERRNO(ret);
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
		goto fail;
	}

	for (i = 0; i < pconn->m_rdlen; i++) {
		curidx = pconn->m_rdsidx + i;
		curidx %= pconn->m_rdsize;
		pwrbuf[i] = pconn->m_rdbuf[curidx];
	}
	pconn->m_rdlen = 0;
	pconn->m_rdsidx = pconn->m_rdeidx;

	if (pconn->m_pwrbuf == NULL) {
		pconn->m_pwrbuf = pwrbuf;
		pwrbuf = NULL;
		pconn->m_wrsize = wrsize;
		ret = write_tcp_socket(pconn->m_psock, (uint8_t*)pconn->m_pwrbuf, pconn->m_wrsize);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			free(pconn->m_pwrbuf);
			pconn->m_pwrbuf = NULL;
			pconn->m_wrsize = 0;
		} else {
			/*not write ok*/
			ASSERT_IF(pconn->m_insertwr == 0);
			pconn->m_wrhd = get_tcp_write_handle(pconn->m_psock);
			ret =  libev_insert_handle(pconn->m_pevmain, get_tcp_write_handle(pconn->m_psock), write_chatsvr_conn_callback, pconn);
			if (ret < 0) {
				GETERRNO(ret);
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
			goto fail;
		} else if (ret > 0) {
			pconn->m_rdeidx ++;
			pconn->m_rdeidx %= pconn->m_rdsize;
			pconn->m_rdlen ++;
			while (1) {
				if (pconn->m_rdlen >= pconn->m_rdsize) {
					ret = write_chatsvr_conn(pconn);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
				}
				ret = read_tcp_socket(pconn->m_psock, (uint8_t*)&(pconn->m_rdbuf[pconn->m_rdeidx]), 1);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				} else if (ret == 0) {
					break;
				}
				pconn->m_rdlen ++;
				pconn->m_rdeidx ++;
				pconn->m_rdeidx %= pconn->m_rdsize;
			}
		}

		if (pconn->m_rdlen > 0) {
			ret = write_chatsvr_conn(pconn);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}
	}

	return 0;
fail:
	remove_conn(pconn->m_paccsock, pconn);
	__free_chatsvr_conn(&pconn);
	SETERRNO(ret);
	return 0;
}

int accept_chatsvr(HANDLE hd, libev_enum_event_t event, void* pevmain, void* args)
{
	pchatsvr_acc_t pacc = (pchatsvr_acc_t)args;
	pchatsvr_conn_t pconn = NULL;
	void* psock = NULL;
	int ret;
	REFERENCE_ARG(hd);
	if (event == normal_event) {
		ASSERT_IF(pacc->m_psock != NULL);
		while (1) {
			ret = complete_tcp_accept(pacc->m_psock);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			} else if (ret > 0) {
				psock = accept_tcp_socket(pacc->m_psock);
				if (psock == NULL) {
					GETERRNO(ret);
					goto fail;
				}

				pconn = __alloc_chatsvr_conn(psock, pacc, pevmain);
				if (pconn == NULL) {
					GETERRNO(ret);
					goto fail;
				}
				psock = NULL;

				while (1) {
					ret = read_tcp_socket(pconn->m_psock, (uint8_t*)&(pconn->m_rdbuf[pconn->m_rdeidx]), 1);
					if (ret == 0) {
						break;
					} else if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}

					pconn->m_rdeidx ++;
					pconn->m_rdeidx %= pconn->m_rdsize;
					pconn->m_rdlen ++;
					if (pconn->m_rdlen >= pconn->m_rdsize) {
						ret = write_chatsvr_conn(pconn);
						if (ret < 0) {
							GETERRNO(ret);
							goto fail;
						}
					}
				}

				if (pconn->m_rdlen > 0) {
					ret = write_chatsvr_conn(pconn);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
				}


				ret = libev_insert_handle(pconn->m_pevmain, get_tcp_read_handle(pconn->m_psock), read_chatsvr_conn, pconn);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				pconn->m_insertrd = 1;

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
	int port = 4012;
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
		goto out;
	}


	psvr->m_pevmain = pevmain;
	ret = libev_insert_handle(pevmain, get_tcp_accept_handle(psvr->m_psock), accept_chatsvr, psvr);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}
	psvr->m_inserted = 1;

	exithd = set_ctrlc_handle();
	if (exithd == NULL) {
		GETERRNO(ret);
		goto out;
	}

	ret =  libev_insert_handle(pevmain, exithd, exit_chatsvr, NULL);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	ret = libev_winev_loop(pevmain);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	fprintf(stdout, "exit winev ok\n");
	ret = 0;
out:
	libev_free_winev(&pevmain);
	__free_chatsvr_acc(&psvr);
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
	uint64_t m_timeoutguid;
	HANDLE m_connhd;
	HANDLE m_rdhd;
	HANDLE m_wrhd;
	HANDLE m_stdinhd;
} chatcli_t,*pchatcli_t;

void __stop_chatcli(pchatcli_t*ppcli)
{
	int ret;
	if (ppcli && *ppcli) {
		pchatcli_t pcli = *ppcli;
		if (pcli->m_inserttimeout > 0) {
			ret = libev_remove_timeout(pcli->m_pevmain,pcli->m_timeoutguid);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_inserttimeout = 0;
		pcli->m_timeoutguid = 0;

		if (pcli->m_insertconn > 0) {
			ret= libev_remove_handle(pcli->m_pevmain,pcli->m_connhd);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_insertconn  =0;

		if (pcli->m_insertrd > 0) {
			ret = libev_remove_handle(pcli->m_pevmain,pcli->m_rdhd);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_insertrd = 0;

		if (pcli->m_insertwr > 0) {
			ret = libev_remove_handle(pcli->m_pevmain,pcli->m_wrhd);
			ASSERT_IF(ret >= 0);
		}
		pcli->m_insertwr = 0;
	}
}

void __free_chatcli(pchatcli_t*ppcli)
{

	if (ppcli && *ppcli) {
		pchatcli_t pcli = *ppcli;


		pcli->m_rdhd = NULL;
		pcli->m_connhd = NULL;
		free_socket(&(pcli->m_psock));
		free(pcli);
		*ppcli = NULL;
	}
}

pchatcli_t __alloc_chat_cli(char* connip,int port)
{
	pchatcli_t pcli = NULL;
	int ret;

	return pcli;
fail:
	__free_chatcli(&pcli);
	SETERRNO(ret);
	return NULL;	
}

int evchatcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int ret = 0;
	char* connip = "127.0.0.1";
	int port = 4012;
	pargs_options_t pargs=  (pargs_options_t) popt;
	HANDLE exithd=NULL;
	void* pcli=NULL;
	void* pevmain = NULL;
	REFERENCE_ARG(argc);
	REFERENCE_ARG(argv);
	init_log_level(pargs);

	if (parsestate->leftargs && parsestate->leftargs[0]) {
		port = atoi(parsestate->leftargs[0]);
		if (parsestate->leftargs[1]) {
			connip = parsestate->leftargs[1];
		}
	}

	ret=  init_socket();
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}

	pevmain = libev_init_winev();
	if (pevmain == NULL) {
		GETERRNO(ret);
		goto out;
	}

	pcli = connect_tcp_socket(connip,port,NULL,0,0);
	if (pcli == NULL) {
		GETERRNO(ret);
		ERROR_INFO("connect [%s:%d] error[%d]",connip,port);
		goto out;
	}

	connhd = get_tcp_connect_handle(pcli);
	if (connhd == NULL) {
		/*connected*/
	} else {
		/*not connected*/
	}


	ret=  0;
out:
	libev_free_winev(&pevmain);
	free_socket(&pcli);
	fini_socket();
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