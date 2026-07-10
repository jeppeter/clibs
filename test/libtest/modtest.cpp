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


int findmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int idx = 0;
    int lastidx = 0;
    char* modname = NULL;
    int maxlen = 0;
    int *procpids = NULL;
    int pidsize=0;
    int pidlen=0;
    pmod_info_t pinfo = NULL;
    int infosize = 0;
    int infolen = 0;
    int jdx,kdx;
    pargs_options_t pargs = (pargs_options_t) popt;


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);

    DEBUG_INFO(" ");

    /*now first to get pids*/
    ret = list_proc("",&procpids,&pidsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"list_proc error %d\n",ret);
        goto out;
    }

    DEBUG_INFO(" ");

    pidlen = ret;

    /*now first to get */
    for(lastidx = 0 ; parsestate->leftargs && parsestate->leftargs[lastidx];lastidx += 1) {
    }

    if (lastidx > 0) {
        for(idx=0;parsestate->leftargs && parsestate->leftargs[idx];idx += 1) {
            modname = parsestate->leftargs[idx];
            for(jdx=0;jdx < pidlen;jdx += 1) {
                if (procpids[jdx] != 0) {
                    if (infosize > 0 && pinfo != NULL) {
                        memset(pinfo,0,(size_t)infosize);
                    }
                    ret = get_module_info(procpids[jdx],modname,&pinfo,&infosize);
                    if (ret < 0) {
                        GETERRNO(ret);
                        if (ret != -ERROR_ACCESS_DENIED) {
                            fprintf(stderr,"get_module_info [%d] modname %s error %d\n",procpids[jdx],modname,ret);
                            goto out;                            
                        }
                        continue;
                    }
                    infolen = ret / (int)sizeof(*pinfo);
                    for(kdx = 0; kdx < infolen;kdx += 1) {
                        if ((int)strlen(pinfo[kdx].m_modfullname) > maxlen) {
                            maxlen = (int)strlen(pinfo[kdx].m_modfullname);
                        }                    
                    }

                }
            }
        }
    } else {
        for(jdx=0;jdx < pidlen;jdx += 1) {
            if (procpids[jdx] != 0) {
                if (infosize > 0 && pinfo != NULL) {
                    memset(pinfo,0,(size_t)infosize);
                }
                ret = get_module_info(procpids[jdx],"",&pinfo,&infosize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret != - ERROR_ACCESS_DENIED) {
                        fprintf(stderr,"get_module_info [%d] error %d\n",procpids[jdx],ret);
                        goto out;                        
                    }
                    continue;
                }
                infolen = ret / (int)sizeof(*pinfo);
                for(kdx = 0; kdx < infolen;kdx += 1) {
                    if ((int)strlen(pinfo[kdx].m_modfullname) > maxlen) {
                        maxlen = (int)strlen(pinfo[kdx].m_modfullname);
                    }                    
                }
            }
        }
    }



    if (lastidx > 0) {
        for(idx=0;parsestate->leftargs && parsestate->leftargs[idx];idx += 1) {
            modname = parsestate->leftargs[idx];
            for(jdx=0;jdx < pidlen;jdx += 1) {
                if (procpids[jdx] != 0) {
                    if (infosize > 0 && pinfo != NULL) {
                        memset(pinfo,0,(size_t)infosize);
                    }
                    ret = get_module_info(procpids[jdx],modname,&pinfo,&infosize);
                    if (ret < 0) {
                        GETERRNO(ret);
                        if (ret != -ERROR_ACCESS_DENIED) {
                            fprintf(stderr,"get_module_info [%d] modname %s error %d\n",procpids[jdx],modname,ret);
                            goto out;                            
                        }
                        continue;
                    }
                    infolen = ret / (int)sizeof(*pinfo);
                    for(kdx = 0; kdx < infolen;kdx += 1) {
                        fprintf(stdout, "proc %05d %-*s %p %d\n",procpids[jdx], maxlen, pinfo[kdx].m_modfullname, pinfo[kdx].m_pimgbase,
                                pinfo[kdx].m_modsize);
                    }
                }
            }
        }
    } else {
        for(jdx=0;jdx < pidlen;jdx += 1) {
            if (procpids[jdx] != 0) {
                if (infosize > 0 && pinfo != NULL) {
                    memset(pinfo,0,(size_t)infosize);
                }
                ret = get_module_info(procpids[jdx],"",&pinfo,&infosize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret != - ERROR_ACCESS_DENIED) {
                        fprintf(stderr,"get_module_info [%d] error %d\n",procpids[jdx],ret);
                        goto out;                        
                    }
                    continue;
                }
                infolen = ret / (int)sizeof(*pinfo);
                for(kdx = 0; kdx < infolen;kdx += 1) {
                    fprintf(stdout, "proc %05d %-*s %p %d\n",procpids[jdx], maxlen, pinfo[kdx].m_modfullname, pinfo[kdx].m_pimgbase,
                            pinfo[kdx].m_modsize);
                }
            }
        }
    }

    ret = 0;

out:
    get_module_info(-1,NULL,&pinfo,&infosize);
    infolen = 0;
    list_proc(NULL,&procpids,&pidsize);
    pidlen = 0;
    return ret;
}