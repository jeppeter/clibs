
int exit_hd_notify(void* pev,uint64_t fd,int event,void* arg)
{
    DEBUG_INFO(" ");
    break_uxev(pev);
    return 0;
}


int icmpping_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    PingTotal* ptotal = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int timeout= pargs->m_timeout;
    int nexttime = pargs->m_nexttime;
    int times = pargs->m_times;
    int exithd=-1;
    std::map<std::string,double> meanres;
    std::map<std::string,double> failres;
    std::map<std::string,std::vector<std::string>> dnsres;
    void* pev = NULL;
    DnsTotal* pdns=NULL;
    int aftype = AF_INET;
    int i;


    init_log_verbose(pargs);
 
    ret = init_socket();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "cannot init_socket [%d]\n", ret);
        goto out;
    }

    if(timeout == 0) {
        timeout = 5000;
    }

    if (pargs->m_af6) {
        aftype = AF_INET6;
    }


    DEBUG_INFO(" ");

    exithd = init_sighandler();
    if (exithd < 0) {
        GETERRNO(ret);
        goto out;
    }

    pev = init_uxev(0);
    if (pev == NULL) {
        GETERRNO(ret);
        fprintf(stderr,"can not libev_init_winev %d", ret);
        goto out;
    }

    ret= add_uxev_callback(pev,exithd,READ_EVENT,exit_hd_notify,NULL);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    pdns = new DnsTotal(pev,timeout);

    for(i=0;parsestate->leftargs && parsestate->leftargs[i]; i++) {
        ret = pdns->start_dns(aftype,parsestate->leftargs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    if (pdns->get_dns_query() != 0) {
        ret = loop_uxev(pev);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }        
    }


    ret = pdns->get_result(dnsres);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    delete pdns;
    pdns = NULL;

    free_uxev(&pev);

    pev = init_uxev(0);
    if (pev == NULL) {
        GETERRNO(ret);
        fprintf(stderr,"can not init_uxev %d", ret);
        goto out;
    }

    ret= add_uxev_callback(pev,exithd,READ_EVENT,exit_hd_notify,NULL);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ptotal = new PingTotal(timeout, nexttime,times, pev);

    for(auto iter = dnsres.begin() ; iter != dnsres.end(); ++ iter) {
        auto vvec = iter->second;
        if (vvec.size() == 0) {
            ret = - EINVAL;
            fprintf(stderr,"[%s] dns 0",iter->first.c_str());
            goto out;
        }
        ret = ptotal->add_host(aftype,vvec[0].c_str());
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    if (ptotal->get_tasks() != 0) {
        ret = loop_uxev(pev);
        DEBUG_INFO("loop ret %d", ret);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    ret = ptotal->get_mean(meanres);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    fprintf(stdout,"%-20s %-10s\n","IP","AVERAGE");
    for(auto iter = meanres.begin() ; iter != meanres.end(); ++ iter) {
        fprintf(stdout,"%-20s %-05f\n", iter->first.c_str(),iter->second);
    }  

    fprintf(stdout,"\n");

    ret = ptotal->get_succ_ratio(failres);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    fprintf(stdout,"%-20s %-10s\n", "IP","SUCC RATIO");
    for(auto iter = failres.begin() ; iter != failres.end(); ++ iter) {
        fprintf(stdout,"%-20s %-05f\n", iter->first.c_str(),iter->second);
    }

    ret = 0;
out:

    if (pdns) {
        delete pdns;
    }
    pdns = NULL;
    if (ptotal) {
        delete ptotal;
    }
    ptotal = NULL;

    free_uxev(&pev);
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

int __split_time(const char* pname, std::string& name,std::string& ports)
{
    std::string ns = pname;
    size_t sidx;
    ports = "";
    name = "";

    sidx = ns.find(',');
    if (sidx == std::string::npos) {
        name = pname;
    } else {
        name = ns.substr(0,sidx);
        ports = ns.substr(sidx+1,ns.length() - sidx-1);
    }
    DEBUG_INFO("name %s ports %s",name.c_str(),ports.c_str());
    return 0;    
}


int tcping_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    int exithd=-1;
    TcpingTotal* ptotal = NULL;
    void* pev=NULL;
    int times;
    int nexttime = 5000;
    int timeout;
    int aftype = AF_INET;
    DnsTotal* pdns= NULL;
    std::string name;
    std::string ports;
    std::map<std::string,std::vector<std::string> > ipres;
    std::vector<std::string> iperrs;
    int i;


    init_log_verbose(pargs);

    times = pargs->m_times;
    timeout = pargs->m_timeout;
    if (timeout == 0) {
        timeout = 5000;
    }
    if (pargs->m_nexttime != 0) {
        nexttime = pargs->m_nexttime;    
    }
    

    if (pargs->m_af6) {
        aftype = AF_INET6;
    }

    ret = init_socket();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "cannot init_socket [%d]\n", ret);
        goto out;
    }


    pev = init_uxev(0);
    if (pev == NULL) {
        GETERRNO(ret);
        goto out;
    }

    exithd = init_sighandler();
    if (exithd < 0) {
        GETERRNO(ret);
        goto out;
    }

    /*now first to give the total*/
    pdns = new DnsTotal(pev,5000);

    for(i=0;parsestate->leftargs&& parsestate->leftargs[i];i+=1) {
        ret = pdns->start_dns(aftype,parsestate->leftargs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    ret =  add_uxev_callback(pev, exithd, READ_EVENT, exit_hd_notify, NULL);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO(" ");
        goto out;
    }


    if (pdns->get_dns_query() != 0) {
        ret = loop_uxev(pev);
        if (ret < 0) {
            GETERRNO(ret);
            DEBUG_INFO(" ");
            goto out;
        }
    }

    DEBUG_INFO(" ");

    ret = pdns->get_result(ipres);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    DEBUG_INFO(" ");

    ret = pdns->get_errors(iperrs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    DEBUG_INFO(" ");

    delete pdns;
    pdns = NULL;

    free_uxev(&pev);

    pev = init_uxev(0);
    if (pev == NULL) {
        GETERRNO(ret);
        goto out;
    }


    DEBUG_INFO("ipres size %lld", ipres.size());
    ptotal = new TcpingTotal(pev,times,timeout,nexttime);
    for(std::map<std::string,std::vector<std::string> >::iterator iter = ipres.begin(); iter != ipres.end(); ++ iter) {
        DEBUG_INFO(" ");
        if (iter->second.size() > 0) {
            std::string cstr = iter->second.at(0);
            size_t sidx = cstr.find(';',0);
            if (sidx != std::string::npos) {
                cstr = cstr.substr(0,sidx);
            }
            DEBUG_INFO("cstr [%s]", cstr.c_str());
            ret = __split_time(cstr.c_str(),name,ports);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            ret = ptotal->start_tcping(aftype,name.c_str(),(char*)ports.c_str());
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
        }
    }



    if (ptotal->get_tasks() != 0) {

        ret =  add_uxev_callback(pev, exithd, READ_EVENT, exit_hd_notify, NULL);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO(" ");
            goto out;
        }

        ret = loop_uxev(pev);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }
    ret = 0;
out:
    if (ptotal) {
        delete ptotal;
    }
    ptotal = NULL;

    if (pdns) {
        delete pdns;
    }
    pdns = NULL;

    free_uxev(&pev);

    SETERRNO(ret);
    return ret;
}