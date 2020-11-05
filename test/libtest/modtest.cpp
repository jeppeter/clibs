int listmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int idx = 0;
    int lastidx = 0;
    int procid = 0;
    char* modname = NULL;
    int maxlen = 0;
    int i;
    pmod_info_t pinfo = NULL;
    int infosize = 0;
    int infolen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    GET_OPT_INT(procid, "procid");
    if (parsestate->leftargs && parsestate->leftargs[idx]) {
        lastidx = idx;
        for (; parsestate->leftargs && parsestate->leftargs[lastidx]; lastidx ++ ) {
            modname = parsestate->leftargs[lastidx];
            ret = get_module_info(procid, modname, &pinfo, &infosize);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not get [%d] mod[%s] error[%d]", procid, modname, ret);
                goto out;
            }
            infolen = (int)(ret / sizeof(*pinfo));
            for (i = 0; i < infolen; i++) {
                if ((int)strlen(pinfo[i].m_modfullname) > maxlen) {
                    maxlen = (int)strlen(pinfo[i].m_modfullname);
                }
            }
        }
        lastidx = idx;
        fprintf(stdout, "%-*s %-*s %-*s      \n", maxlen, "name", 16, "addr", 8, "size");
        for (; parsestate->leftargs && parsestate->leftargs[lastidx]; lastidx ++ ) {
            modname = parsestate->leftargs[lastidx];
            ret = get_module_info(procid, modname, &pinfo, &infosize);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not get [%d] mod[%s] error[%d]", procid, modname, ret);
                goto out;
            }
            infolen = (int)(ret / sizeof(*pinfo));
            for (i = 0; i < infolen; i++) {
                fprintf(stdout, "%-*s %p %d\n", maxlen, pinfo[i].m_modfullname, pinfo[i].m_pimgbase,
                        pinfo[i].m_modsize);
            }
        }
    } else {
        ret = get_module_info(procid, "", &pinfo, &infosize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not get [%d] mod[%s] error[%d]", procid, modname, ret);
            goto out;
        }
        infolen = (int)(ret / sizeof(*pinfo));
        DEBUG_INFO("infolen [%d]", infolen);
        for (i = 0; i < infolen; i++) {
            if ((int)strlen(pinfo[i].m_modfullname) > maxlen) {
                maxlen = (int)strlen(pinfo[i].m_modfullname);
            }
        }
        fprintf(stdout, "%-*s %-*s %-*s      \n", maxlen, "name", 16, "addr", 8, "size");
        ret = get_module_info(procid, "", &pinfo, &infosize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not get [%d] mod[%s] error[%d]", procid, modname, ret);
            goto out;
        }
        infolen = (int)(ret / sizeof(*pinfo));
        DEBUG_INFO("infolen [%d]", infolen);
        for (i = 0; i < infolen; i++) {
            fprintf(stdout, "%-*s %p %d\n", maxlen, pinfo[i].m_modfullname, pinfo[i].m_pimgbase,
                    pinfo[i].m_modsize);
        }
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}
