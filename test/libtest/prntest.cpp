int getprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    pprinter_list_t pprn = NULL;
    int prnsize = 0, prnlen = 0;
    int i;
    size_t namelen = 0, sharelen = 0, iplen = 0, typelen = 0;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
    init_log_level(pargs);

    ret = get_printer_list(0, NULL, &pprn, &prnsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not get printer list [%d]", ret);
        goto out;
    }
    prnlen = ret;

    namelen = strlen("name") ;
    iplen = strlen("ip");
    typelen = strlen("type");
    sharelen = strlen("share");

    for (i = 0; i < prnlen; i++) {
        if (strlen(pprn[i].m_name) >= namelen) {
            namelen = strlen(pprn[i].m_name) + 1;
        }
        if (strlen(pprn[i].m_sharename) >= sharelen) {
            sharelen = strlen(pprn[i].m_sharename) + 1;
        }

        if (strlen(pprn[i].m_ip) >= iplen) {
            iplen = strlen(pprn[i].m_ip) + 1;
        }

        if (strlen(pprn[i].m_type) >= typelen) {
            typelen = strlen(pprn[i].m_type) + 1;
        }
    }

    fprintf(stdout, "items %-*s %-*s %-*s %-*s\n", (int)namelen, "name", (int)typelen, "type", (int)sharelen, "share", (int)iplen, "ip");
    for (i = 0; i < prnlen; i++) {
        fprintf(stdout, "%03d   %-*s %-*s %-*s %-*s\n", i, (int)namelen, pprn[i].m_name, (int)typelen, pprn[i].m_type,
                (int)sharelen, pprn[i].m_sharename, (int)iplen, pprn[i].m_ip);
    }
    ret = 0;
out:
    get_printer_list(1, NULL, &pprn, &prnsize);
    prnlen = 0;
    SETERRNO(ret);
    return ret;
}

int addprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* remoteip = NULL;
    char* name = NULL;
    char* user = NULL;
    char* password = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;
    int i = 0;
    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        if (i == 0) {
            remoteip = parsestate->leftargs[i];
        } else if (i == 1) {
            name = parsestate->leftargs[i];
        } else if (i == 2) {
            user = parsestate->leftargs[i];
        } else if (i == 3) {
            password = parsestate->leftargs[i];
        }
    }

    if (remoteip == NULL || name == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "need remoteip and name\n");
        goto out;
    }

    ret = add_share_printer(NULL, name, remoteip, user, password);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not add [\\\\%s\\%s] with user[%s] password[%s] error[%d]\n",
                remoteip, name, user ? user : "guest", password ? password : "", ret);
        goto out;
    }

    fprintf(stdout, "add [\\\\%s\\%s] succ\n", remoteip, name);

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int delprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* remoteip = NULL;
    char* name = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    remoteip = parsestate->leftargs[0];
    name = parsestate->leftargs[1];

    ret = del_share_printer(NULL, name, remoteip);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not delete printer [%s].[%s] error[%d]", remoteip, name, ret);
        goto out;
    }

    fprintf(stdout, "delete \\\\%s\\%s succ\n", remoteip, name);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;

}
int saveprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char*exportfile = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    exportfile = parsestate->leftargs[0];

    ret = save_printer_exportfile(NULL, exportfile);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("save printer configuration [%s] error[%d]", exportfile, ret);
        goto out;
    }

    fprintf(stdout, "save printer configuration [%s] succ\n", exportfile);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int restoreprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char*exportfile = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);
    exportfile = parsestate->leftargs[0];

    ret = restore_printer_exportfile(NULL, exportfile);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("restore printer configuration [%s] error[%d]", exportfile, ret);
        goto out;
    }

    fprintf(stdout, "restore printer configuration [%s] succ\n", exportfile);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svraddprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(ADDPRN_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrdelprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(DELPRN_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrsaveprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(SAVEPRN_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrrestoreprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(RESTOREPRN_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}
