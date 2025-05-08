
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

        printf("%s mean %ld %f\n",ipstr,cval, ratio);
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