
int icmpping_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    PingTotal* ptotal = NULL;
    int ret;
    int idx;
    pargs_options_t pargs = (pargs_options_t) popt;
    int timeout= pargs->m_timeout;
    int nexttime = pargs->m_nexttime;
    int times = pargs->m_times;
    char* ipstr =NULL;
    uint64_t cval = 0;
    int exithd= -1;
    double ratio = 0.0;

    //REFERENCE_ARG(argc);
    //REFERENCE_ARG(argv);

    init_log_verbose(pargs);
 
    ret = init_socket();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "cannot init_socket [%d]\n", ret);
        goto out;
    }

    if (timeout == 0) {
        timeout = 5000;
    }

    if (nexttime == 0) {
    	nexttime = 1000;
    }

    DEBUG_INFO(" ");

    exithd = init_sighandler();
    if (exithd < 0) {
        GETERRNO(ret);
        goto out;
    }


    ptotal = new PingTotal(timeout,nexttime,times,1);
    DEBUG_INFO(" ");

    for(idx=0;parsestate->leftargs && parsestate->leftargs[idx];idx++) {
        DEBUG_INFO("[%d] [%s]", idx,parsestate->leftargs[idx]);
        ret = ptotal->add_host(parsestate->leftargs[idx]);
        if (ret < 0) {
            GETERRNO(ret);
            DEBUG_INFO("ret %d", ret);
            goto out;
        }
    }

    ret=  ptotal->loop(exithd);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    idx = 0;
    while(1) {
        ret = ptotal->get_mean(idx,&ipstr,&cval);
        if (ret == 0) {
            break;
        }

        ratio = 0.0;
        ret = ptotal->get_succ_ratio(idx,&ipstr,&ratio);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
#if __SIZEOF_POINTER__ == 8
        printf("%s mean %ld %f\n",ipstr,cval, ratio);
#else
        printf("%s mean %lld %f\n",ipstr,cval, ratio);
#endif
        idx += 1;
    }
    ret = 0;
out:
    if (ptotal) {
        ptotal->get_mean(-1,&ipstr,&cval);
        delete ptotal;
    }
    ptotal = NULL;
    SETERRNO(ret);
    return ret;
}

int sockaddrsize_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    fprintf(stdout,"sizeof(struct sockaddr) %ld sizeof(struct sockaddr_in) %ld sizeof(struct sockaddr_in6) %ld\n",
        sizeof(struct sockaddr),
        sizeof(struct sockaddr_in), 
        sizeof(struct sockaddr_in6));

    SETERRNO(0);
    return 0;
}


int dnsqry_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    DnsTotal* total=NULL;
    int aftype = AF_INET;
    std::map<std::string,std::vector<std::string> > okres;
    std::vector<std::string> errs;
    int exithd = -1;
    void* pev = NULL;

    init_log_verbose(pargs);


    pev = init_uxev(0);
    if (pev == NULL) {
        GETERRNO(ret);
        fprintf(stderr,"can not libev_init_winev error %d\n", ret);
        goto out;
    }

    total = new DnsTotal(pev,5000);

    if (pargs->m_timeout != 0) {
        total->set_timeout(pargs->m_timeout);
    }

    exithd = init_sighandler();
    if (exithd < 0) {
        GETERRNO(ret);
        fprintf(stderr,"can not ctrlc handle\n");
        goto out;
    }

    ret = init_socket();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"not init sock error %d\n", ret);
        goto out;
    }


    if (pargs->m_af6) {
        aftype = AF_INET6;
    }


    for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        ret = total->start_dns(aftype,parsestate->leftargs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr,"can not start_dns [%s] error %d\n", parsestate->leftargs[i],ret);
            goto out;
        }
    }

    ret = total->get_dns_query();
    if (ret != 0) {
        ret = loop_uxev(pev);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr,"can not loop ok %d\n",ret);
            goto out;
        }
    }


    ret = total->get_result(okres);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"get_result error %d\n",ret);
        goto out;
    }


    for(std::map<std::string,std::vector<std::string> >::iterator iter = okres.begin();iter != okres.end(); ++ iter) {        
        fprintf(stdout,"%s:", iter->first.c_str());
        i = 0;
        for(i=0;i< (int)iter->second.size() ;i += 1) {
            if ((i%5) == 0) {
                fprintf(stdout,"\n    ");
            }
            fprintf(stdout," %s",iter->second.at((uint64_t)i).c_str());
        }
        fprintf(stdout,"\n");
    }

    ret = total->get_errors(errs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"get_error error %d\n",ret);
        goto out;
    }
    

    i = 0;
    fprintf(stdout,"errors:");
    for(std::vector<std::string>::iterator citer = errs.begin(); citer != errs.end(); ++ citer) {
        if ((i%5) == 0) {
            fprintf(stdout,"\n    ");
        }
        fprintf(stdout," %s",citer->c_str());
        i += 1;
    }
    fprintf(stdout,"\n");


    ret = 0;
out:
    if (total){
        delete total;
    }
    total = NULL;

    free_uxev(&pev);
    SETERRNO(ret);
    return ret;
}
