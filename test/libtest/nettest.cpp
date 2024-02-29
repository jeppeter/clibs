
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