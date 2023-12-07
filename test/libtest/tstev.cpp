


typedef struct __chatsvr_conn {	
	void* m_psock;
    void* m_paccsock;
    void* m_pevmain;
    int m_insertrd;
    int m_insertwr;
} chatsvr_conn_t,*pchatsvr_conn_t;


typedef struct __chatsvr_acc {
	void* m_psock;
	void* m_pevmain;
	char* m_ipaddr;
	int m_port;
	int m_inserted;
	std::vector<pchatsvr_conn_t> *m_pconns;
} chatsvr_acc_t,*pchatsvr_acc_t;

int __find_conn(pchatsvr_acc_t pacc,pchatsvr_conn_t pconn)
{
	unsigned int i;
	int fidx=-1;
	pchatsvr_conn_t pcur;
	if (pacc->m_pconns->size() > 0) {
		if (pconn != NULL) {
			for(i=0;i<pacc->m_pconns->size();i++) {
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
	pchatsvr_acc_t pacc= (pchatsvr_acc_t)pacc1;
	int fidx = -1;

	fidx = __find_conn(pacc,pconn);
	if (fidx < 0) {
		return 0;
	}

	pacc->m_pconns->erase(pacc->m_pconns->begin()+fidx);
	return 1;	
}


void __free_chatsvr_conn(pchatsvr_conn_t* ppconn)
{
	int ret;
	if (ppconn && *ppconn) {
		pchatsvr_conn_t pconn = *ppconn;

		if (pconn->m_insertrd > 0) {
			ret = libev_remove_handle(pconn->m_pevmain,get_tcp_read_handle(pconn->m_psock));
			ASSERT_IF(ret >= 0);
		}
		pconn->m_insertrd = 0;

		if (pconn->m_insertwr > 0) {
			ret = libev_remove_handle(pconn->m_pevmain,get_tcp_write_handle(pconn->m_psock));
			ASSERT_IF(ret >= 0);
		}
		pconn->m_insertwr = 0;

		if (pconn->m_paccsock) {
			remove_conn(pconn->m_paccsock,pconn);
		}
		pconn->m_paccsock = NULL;
		free_socket(&pconn->m_psock);
		free(pconn);
		*ppconn = NULL;
	}
	return;
}

pchatsvr_conn_t __alloc_chatsvr_conn(void* psock,void* paccsock,void* pevmain)
{
	pchatsvr_conn_t pconn = NULL;
	int ret=-1;
	pconn = (pchatsvr_conn_t) malloc(sizeof(*pconn));
	if (pconn == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pconn,0,sizeof(*pconn));
	pconn->m_psock = NULL;
	pconn->m_paccsock = paccsock;
	pconn->m_pevmain = pevmain;
	pconn->m_insertrd = 0;
	pconn->m_insertwr = 0;
	pconn->m_psock = psock;

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
			ret = libev_remove_handle(pacc->m_pevmain,get_tcp_accept_handle(pacc->m_psock));
			ASSERT_IF(ret >= 0);
		}
		pacc->m_inserted = 0;

		if (pacc->m_pconns != NULL)	 {
			while(pacc->m_pconns->size() > 0) {
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

pchatsvr_acc_t __alloc_chatsvr_acc(const char* ipaddr,int port)
{
	pchatsvr_acc_t pacc=NULL;
	int ret;

	pacc= (pchatsvr_acc_t) malloc(sizeof(*pacc));
	if (pacc == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pacc,0,sizeof(*pacc));
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

	pacc->m_psock = bind_tcp_socket(pacc->m_ipaddr,pacc->m_port,5);
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

int exit_chatsvr(HANDLE hd,libev_enum_event_t event,void* pevmain,void* args)
{
	REFERENCE_ARG(args);
	REFERENCE_ARG(event);
	REFERENCE_ARG(hd);
	libev_break_winev_loop(pevmain);
	return 0;
}

int accept_chatsvr(HANDLE hd,libev_enum_event_t event,void* pevmain,void* args)
{
	pchatsvr_acc_t pacc = (pchatsvr_acc_t)args;
	pchatsvr_conn_t pconn = NULL;
	void* psock = NULL;
	int ret;
	REFERENCE_ARG(hd);
	if (event == normal_event) {
		ASSERT_IF(pacc->m_psock != NULL);
		ret = complete_tcp_accept(pacc->m_psock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		psock = accept_tcp_socket(pacc->m_psock);
		if (psock == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		pconn = __alloc_chatsvr_conn(psock,pacc,pevmain);
		if (pconn == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		psock = NULL;


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
    int ret =0;
    int port =4012;
    const char* ipaddr = "0.0.0.0";
    void* pevmain= NULL;
    pchatsvr_acc_t psvr= NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    HANDLE exithd=NULL;
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
    	fprintf(stderr,"cannot init_socket error[%d]\n",ret);
    	goto out;
    }

    psvr = __alloc_chatsvr_acc(ipaddr,port);
    if (psvr == NULL) {
    	GETERRNO(ret);
    	goto out;
    }

    psvr->m_pevmain = pevmain;
    ret = libev_insert_handle(pevmain,get_tcp_accept_handle(psvr->m_psock),accept_chatsvr,psvr);
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

    ret=  libev_insert_handle(pevmain,exithd,exit_chatsvr,NULL);
    if (ret < 0) {
    	GETERRNO(ret);
    	goto out;
    }

    ret = libev_winev_loop(pevmain);
    if (ret < 0) {
    	GETERRNO(ret);
    	goto out;
    }

    fprintf(stdout,"exit winev ok\n");
    ret = 0;
out:
	__free_chatsvr_acc(&psvr);
	libev_free_winev(&pevmain);
	fini_socket();
	SETERRNO(ret);
    return ret;
}

int evchatcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret =0;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(popt);
    return ret;
}