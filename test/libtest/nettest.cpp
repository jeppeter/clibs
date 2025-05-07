
#define TYPE_PRINTF(type,stype)          \
do {                                     \
    if (pinfo->m_type & type) {          \
        if (typefp > 0) {                \
            fprintf(fp, "|");            \
        }                                \
        fprintf(fp, "%s", stype);        \
        typefp ++;                       \
    }                                    \
} while(0)

void debug_net_adapter(pnet_inter_info_t pinfo, FILE* fp, const char* fmt, ...)
{
    va_list ap;
    int typefp = 0;
    if (fmt != NULL) {
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        fprintf(fp, "\n");
    }

    fprintf(fp, "m_adaptername[%s]\n", pinfo->m_adaptername);
    fprintf(fp, "m_adapternickname[%s]\n", pinfo->m_adapternickname);
    fprintf(fp, "m_adapterip4[%s]\n", pinfo->m_adapterip4);
    fprintf(fp, "m_adapterip6[%s]\n", pinfo->m_adapterip6);
    fprintf(fp, "m_adaptermask4[%s]\n", pinfo->m_adaptermask4);
    fprintf(fp, "m_adaptermask6[%s]\n", pinfo->m_adaptermask6);
    fprintf(fp, "m_adaptergw[%s]\n", pinfo->m_adaptergw);
    fprintf(fp, "m_adapterdns[%s]\n", pinfo->m_adapterdns);
    fprintf(fp, "m_adaptermac[%s]\n", pinfo->m_adaptermac);
    fprintf(fp, "m_mtu[%d]\n", pinfo->m_mtu);

    fprintf(fp, "m_type ");
    TYPE_PRINTF(ETHER_NET, "ETHER_NET");
    TYPE_PRINTF(IP4_NET, "IP4_NET");
    TYPE_PRINTF(IP6_NET, "IP6_NET");
    if (typefp == 0) {
        fprintf(fp, "0");
    }
    fprintf(fp, "\n");
    DEBUG_BUFFER_FMT(pinfo->m_adapternickname,sizeof(pinfo->m_adapternickname),"adaptername [%s]",pinfo->m_adapternickname);
    return ;
}

int netinter_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pnet_inter_info_t pinfos = NULL;
    int infosize = 0;
    int i, j;
    int num;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);
    argc = argc;
    argv = argv;

    if (parsestate->leftargs == NULL) {
        ret = get_all_adapter_info(0, NULL, &pinfos, &infosize);
        if (ret < 0 ) {
            GETERRNO(ret);
            fprintf(stderr, "can not get adapter info error[%d]\n", ret);
            goto out;
        }
        num = ret;
        for (i = 0; i < num; i++) {
            debug_net_adapter(&(pinfos[i]), stdout, "[%d] adapter", i);
        }
    } else {
        for (i = 0; parsestate->leftargs[i] != NULL ; i ++) {
            ret = get_all_adapter_info(0, parsestate->leftargs[i], &pinfos, &infosize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "can not get adapter for [%s] error[%d]\n", parsestate->leftargs[i], ret);
                goto out;
            }
            num = ret;
            for (j = 0; j < num; j++) {
                debug_net_adapter(&(pinfos[j]), stdout, "[%d] adapter for [%s]", j, parsestate->leftargs[i]);
            }
        }
    }

    ret = 0;
out:
    get_all_adapter_info(1, NULL, &pinfos, &infosize);
    SETERRNO(ret);
    return ret;
}

int netservnames_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char** servnames = NULL;
    int servsize=0;
    int servlen=0;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
    init_log_level(pargs);

    ret = get_adapter_servicenames(0,&servnames,&servsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    servlen = ret;

    for(i=0;i < servlen;i++) {
        fprintf(stdout,"[%d]=%s\n",i,servnames[i]);
    }
    ret = 0;
out:
    get_adapter_servicenames(1,&servnames,&servsize);
    SETERRNO(ret);
    return ret;
}

int arpreq_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* srcip=NULL;
    char* dstip=NULL;
    int macsize=0;
    unsigned char* macaddr=NULL;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    dstip = parsestate->leftargs[0];
    if (parsestate->leftargs && parsestate->leftargs[1] != NULL) {
        srcip = parsestate->leftargs[1];
    }

    ret = get_arp_request(srcip,dstip,(void**)&macaddr);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"get [%s]:[%s] error[%d]\n",srcip,dstip,ret);
        goto out;
    }

    macsize = ret;    

    for(i=0;i<macsize;i++) {
        if (i > 0) {
            fprintf(stdout," ");
        }
        fprintf(stdout,"0x%02x",macaddr[i]);
    }
    fprintf(stdout,"\n");

    ret = 0;
out:
    get_arp_request(NULL,NULL,(void**)&macaddr);
    SETERRNO(ret);
    return ret;
}

int nslookup_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char** ppips = NULL;
    int retlen = 0;
    int retsize=0;
    int i,j;
    char* curdomain;
    pargs_options_t pargs = (pargs_options_t)popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    ret = init_socket();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "cannot init_socket [%d]\n", ret);
        goto out;
    }

    for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        curdomain = parsestate->leftargs[i];
        ret = get_domain_ipaddr(curdomain,&ppips,&retsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s] error[%d]\n", curdomain,ret);
            goto out;
        }
        retlen = ret;
        fprintf(stdout, "[%s] ips\n", curdomain);
        for(j=0;j<retlen;j++) {
            fprintf(stdout,"    [%d] [%s]\n",j,ppips[j]);
        }
    }

    ret = 0;
out:
    get_domain_ipaddr(NULL,&ppips,&retsize);
    fini_socket();
    SETERRNO(ret);
    return ret;
}

int icmpping_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;
    void** ipsocks = NULL;
    int socklen=0;
    int i;
    HANDLE *hdls=NULL;
    HANDLE exithd=NULL;
    int maxhdl=0;
    DWORD waitnum;
    int *ptimes=NULL;
    int timeout= pargs->m_timeout;
    HANDLE curhd;
    uint64_t curval;
    DWORD dret;
    int added;
    int *nextones=NULL;
    int curtimeout = 0;
    int waitnext=0;
    uint64_t* pexpires = NULL;
    uint64_t* pnextrestart = NULL;
    uint64_t cticks;


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    ret = init_socket();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "cannot init_socket [%d]\n", ret);
        goto out;
    }

    if (timeout == 0) {
        timeout = 5000;
    }

    for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        socklen += 1;
    }

    if (socklen == 0) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "at least one ip\n");
        goto out;
    }
    DEBUG_INFO("ips %d", socklen);

    exithd = set_ctrlc_handle();
    if (exithd == NULL) {
        GETERRNO(ret);
        ERROR_INFO(" ");
        goto out;
    }

    ipsocks = (void**)malloc(sizeof(*ipsocks) * socklen);
    if (ipsocks == NULL) {
        GETERRNO(ret);
        ERROR_INFO(" ");
        goto out;
    }
    memset(ipsocks, 0, sizeof(*ipsocks) * socklen);

    maxhdl = socklen * 2 + 1;
    hdls = (HANDLE*)malloc(sizeof(*hdls) * maxhdl);
    if(hdls == NULL) {
        GETERRNO(ret);
        ERROR_INFO(" ");
        goto out;
    }
    memset(hdls,0,sizeof(*hdls) *maxhdl);

    ptimes = (int*)malloc(sizeof(*ptimes) * socklen);
    if (ptimes == NULL) {
        GETERRNO(ret);
        ERROR_INFO(" ");
        goto out;
    }
    memset(ptimes, 0, sizeof(*ptimes) * socklen);

    nextones = (int*)malloc(sizeof(*nextones) * socklen);
    if (nextones == NULL) {
        GETERRNO(ret);
        ERROR_INFO(" ");
        goto out;
    }
    memset(nextones, 0, sizeof(*nextones) * socklen);

    pexpires = (uint64_t*) malloc(sizeof(*pexpires) * socklen);
    if (pexpires == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(pexpires, 0, sizeof(*pexpires) * socklen);

    pnextrestart = (uint64_t*) malloc(sizeof(*pnextrestart) * socklen);
    if (pnextrestart == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(pnextrestart, 0, sizeof(*pnextrestart) * socklen);



    for(i=0;i<socklen;i++) {
        ipsocks[i] = init_ping_sock(AF_INET);
        if (ipsocks[i] == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "init %d error %d\n",i, ret);
            goto out;
        }
        ret = send_ping_request(ipsocks[i], parsestate->leftargs[i]);
        pexpires[i] = get_current_ticks();
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "send [%s] error %d\n", parsestate->leftargs[i], ret);
            goto out;
        } else if (ret > 0) {
            ret = recv_ping_response(ipsocks[i],&curval);
            if (ret > 0) {
                pexpires[i] = 0;
                pnextrestart[i] = get_current_ticks();
                DEBUG_INFO("[%s] ttl %lld", parsestate->leftargs[i] ,curval);
                printf("[%s:%d] %s ttl %lld\n", __FILE__,__LINE__,parsestate->leftargs[i], curval);
            }
        }
        
    }

    while(1) {
        waitnum = 0;
        curtimeout = timeout;
        memset(nextones,0,sizeof(*nextones)*socklen);
        hdls[waitnum] = exithd;
        waitnum += 1;
        for(i=0;i<socklen;i++) {
            if (ptimes[i] < pargs->m_times || pargs->m_times ==0) {
                added = 0;
                cticks = get_current_ticks();
                if (pexpires[i] != 0) {
                    ret = need_wait_times(pexpires[i],cticks,timeout);
                    if (ret < 0) {
                        /**/
                        fprintf(stdout,"[%s:%d] [%s] timeout\n",__FILE__,__LINE__,parsestate->leftargs[i]);
                        DEBUG_INFO("[%s] timeout", parsestate->leftargs[i]);
                        ptimes[i] += 1;
                        free_ping_sock(&ipsocks[i]);
                        ipsocks[i] = init_ping_sock(AF_INET);
                        if (ipsocks[i] == NULL) {
                            GETERRNO(ret);
                            goto out;
                        }
                        ret = send_ping_request(ipsocks[i], parsestate->leftargs[i]);
                        pexpires[i] = get_current_ticks();
                        if (ret < 0) {
                            GETERRNO(ret);
                            goto out;
                        } else if (ret > 0) {
                            ret = recv_ping_response(ipsocks[i], &curval);
                            if (ret > 0) {
                                ptimes[i] += 1;
                                pexpires[i] = 0;
                                pnextrestart[i] = get_current_ticks();
                                DEBUG_INFO("[%s] ttl %lld", parsestate->leftargs[i] ,curval);
                                printf("[%s:%d] %s ttl %lld\n", __FILE__,__LINE__,parsestate->leftargs[i], curval);
                            }
                        }
                        
                    }                    
                } else {
                    ret = need_wait_times(pnextrestart[i],cticks,1000);
                    if (ret < 0) {
                        DEBUG_INFO("start [%s]",parsestate->leftargs[i]);
                        ret = send_ping_request(ipsocks[i],parsestate->leftargs[i]);
                        pexpires[i] = get_current_ticks();
                        if (ret < 0) {
                            GETERRNO(ret);
                            goto out;
                        } else if (ret > 0) {                            
                            ret = recv_ping_response(ipsocks[i], &curval);
                            if (ret > 0) {
                                ptimes[i] += 1;
                                pexpires[i] = 0;
                                pnextrestart[i] = get_current_ticks();
                                DEBUG_INFO("[%s] ttl %lld", parsestate->leftargs[i] ,curval);
                                printf("[%s:%d] %s ttl %lld\n", __FILE__,__LINE__,parsestate->leftargs[i], curval);
                            }
                        }                        
                    }
                }

                if (ping_is_write_mode(ipsocks[i]) != 0) {
                    hdls[waitnum] = get_ping_write_evt(ipsocks[i]);
                    waitnum += 1;
                }
                if (ping_is_read_mode(ipsocks[i]) != 0) {
                    hdls[waitnum] = get_ping_read_evt(ipsocks[i]);
                    waitnum += 1;
                }

                if (added == 0) {
                    nextones[i] = 1;
                }
            }
        }

        waitnext = 0;
        if (waitnum == 1) {
            /*this is over so break*/
            waitnext = 0;
            for(i=0;i<socklen;i++) {
                if (nextones[i]) {
                    waitnext = 1;
                }
            }
            if (waitnext == 0) {
                DEBUG_INFO("completed");
                break;                
            }
        }

        dret = WaitForMultipleObjectsEx(waitnum,hdls,FALSE,(DWORD)curtimeout,FALSE);
        if (dret < (WAIT_OBJECT_0 + waitnum)) {
            curhd = hdls[dret - WAIT_OBJECT_0];
            if (curhd == exithd) {
                break;
            } else {
                for(i=0;i<socklen;i++) {
                    if (ptimes[i] < pargs->m_times || pargs->m_times ==0) {
                        if (get_ping_write_evt(ipsocks[i]) == curhd) {
                            ret=  ping_complete_write(ipsocks[i]);
                            if (ret > 0) {
                            get_response:
                                ret = recv_ping_response(ipsocks[i],&curval);
                                if (ret < 0) {
                                    GETERRNO(ret);
                                    goto out;
                                } else if (ret > 0) {
                                    printf("[%s:%d] %s ttl %lld\n",__FILE__,__LINE__, parsestate->leftargs[i], curval);
                                    DEBUG_INFO("%s ttl %lld", parsestate->leftargs[i], curval);
                                    ptimes[i] += 1;
                                    pexpires[i] = 0;
                                    pnextrestart[i] = get_current_ticks();
                                }
                            }
                            break;
                        } else if (get_ping_read_evt(ipsocks[i]) == curhd) {
                            ret = ping_complete_read(ipsocks[i]);
                            if (ret < 0) {
                                GETERRNO(ret);
                                goto out;
                            } else if (ret > 0) {
                                goto get_response;
                            }
                            break;
                        }
                    }                    
                }
            }
        } else if (dret == WAIT_TIMEOUT) {
            continue;
        }
    }



    ret = 0;
out:
    if (socklen > 0) {
        for(i=0;i<socklen;i++) {
            free_ping_sock(&ipsocks[i]);
        }
    }
    if (ipsocks) {
        free(ipsocks);
    }
    ipsocks = NULL;

    if (hdls) {
        free(hdls);
    }
    hdls = NULL;
    if (ptimes) {
        free(ptimes);
    }
    ptimes = NULL;

    if (nextones) {
        free(nextones);
    }
    nextones = NULL;

    if (pexpires) {
        free(pexpires);
    }
    pexpires = NULL;

    if (pnextrestart) {
        free(pnextrestart);
    }
    pnextrestart = NULL;

    fini_socket();
    SETERRNO(ret);
    return ret;
}