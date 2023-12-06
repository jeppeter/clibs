


typedef struct __chatsvr_conn {	
	void* m_psock;
    void* m_paccsock;
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
					fidx = i;
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

void __free_chatsvr_acc(pchatsvr_acc_t* ppacc)
{
	if (ppacc && *ppacc) {
		pchatsvr_acc_t pacc = *ppacc;
		if (pacc->m_inserted) {
			remove_
		}
	}
}

pchatsvr_acc_t __alloc_chatsvr_acc(const char* ipaddr,int port)
{
	pchatsvr_acc_t pacc=NULL;
}


int evchatsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret =0;
    int port =4012;
    const char* ipaddr = "0.0.0.0";
    int idx;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);
    if (parsestate->leftargs && parsestate->leftargs[0]) {
        port = atoi(parsestate->leftargs[0]);
        if (parsestate->leftargs[1]) {
            ipaddr = parsestate->leftargs[1];
        }
    }

out:
	SETERRNO(ret);
    return ret;
}

int evchatcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret =0;
    return ret;
}