
int regexec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* preg = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int argcnt = 0;
    int i, j, retlen;
    int *pstartpos = NULL, *pendpos = NULL;
    int possize = 0;
    int ret;
    char* pcurstr = NULL;
    char* pmatchstr = NULL;
    size_t matchsize = 0;
    size_t matchlen = 0;
    int handled = 0;

    argc = argc;
    argv = argv;
    init_log_verbose(pargs);
    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2) {
        ret = -EINVAL;
        ERROR_INFO("arg must restr instr...");
        goto out;
    }

    ret = regex_compile(parsestate->leftargs[0], REGEX_NONE, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not compile [%s]", parsestate->leftargs[0]);
        goto out;
    }

    for (i = 1; i < argcnt; i++) {
        pcurstr = parsestate->leftargs[i];
        handled = 0;
try_again:
        ret = regex_exec(preg, pcurstr, &pstartpos, &pendpos, &possize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not exec [%s] for [%s] error[%d]", pcurstr, parsestate->leftargs[0], ret);
            goto out;
        }
        retlen = ret;
        if (retlen > 0) {
            fprintf(stdout, "[%s] find [%s]\n", parsestate->leftargs[0], pcurstr);
            for (j = 0; j < retlen; j++) {
                matchlen = (size_t)(pendpos[j] - pstartpos[j]);
                if (matchlen >= matchsize || pmatchstr == NULL) {
                    if (pmatchstr) {
                        free(pmatchstr);
                    }
                    pmatchstr = NULL;
                    matchsize = (matchlen + 3);
                    pmatchstr = (char*) malloc(matchsize);
                    if (pmatchstr == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc %d error[%d]", matchsize, ret);
                        goto out;
                    }
                }
                memset(pmatchstr, 0 , matchsize);
                memcpy(pmatchstr, &(pcurstr[pstartpos[j]]), matchlen);
                fprintf(stdout, "    [%03d] %s\n", j, pmatchstr);
            }
            /*we move to the next to find*/
            pcurstr = &(pcurstr[pendpos[0]]);
            fprintf(stdout, "    left[%s]\n", pcurstr);
            handled ++;
            goto try_again;
        } else {
            if (handled == 0) {
                fprintf(stdout, "[%s] not find in [%s]\n", parsestate->leftargs[0], pcurstr);
            }
        }
    }

    ret = 0;
out:
    if (pmatchstr != NULL) {
        free(pmatchstr);
    }
    pmatchstr = NULL;
    matchsize = 0;
    regex_exec(NULL, NULL, &pstartpos, &pendpos, &possize);
    regex_compile(NULL, REGEX_NONE, &preg);
    SETERRNO(ret);
    return ret;
}


int iregexec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* preg = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int argcnt = 0;
    int i, j, retlen;
    int *pstartpos = NULL, *pendpos = NULL;
    int possize = 0;
    int ret;
    char* pcurstr = NULL;
    char* pmatchstr = NULL;
    size_t matchsize = 0;
    size_t matchlen = 0;
    int handled = 0;
    char** pplines=NULL;
    int lsize=0,llen=0;

    argc = argc;
    argv = argv;
    init_log_verbose(pargs);
    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2 && pargs->m_input == NULL) {
        ret = -EINVAL;
        ERROR_INFO("arg must restr instr...");
        goto out;
    }

    ret = regex_compile(parsestate->leftargs[0], REGEX_IGNORE_CASE, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not compile [%s]", parsestate->leftargs[0]);
        goto out;
    }

    if (argcnt >= 2) {
        for (i = 1; i < argcnt; i++) {
            pcurstr = parsestate->leftargs[i];
            handled = 0;
try_again:
            ret = regex_exec(preg, pcurstr, &pstartpos, &pendpos, &possize);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not exec [%s] for [%s] error[%d]", pcurstr, parsestate->leftargs[0], ret);
                goto out;
            }
            retlen = ret;
            if (retlen > 0) {
                fprintf(stdout, "[%s] find [%s]\n", parsestate->leftargs[0], pcurstr);
                for (j = 0; j < retlen; j++) {
                    matchlen = (size_t)(pendpos[j] - pstartpos[j]);
                    if (matchlen >= matchsize || pmatchstr == NULL) {
                        if (pmatchstr) {
                            free(pmatchstr);
                        }
                        pmatchstr = NULL;
                        matchsize = (matchlen + 3);
                        pmatchstr = (char*) malloc(matchsize);
                        if (pmatchstr == NULL) {
                            GETERRNO(ret);
                            ERROR_INFO("alloc %d error[%d]", matchsize, ret);
                            goto out;
                        }
                    }
                    memset(pmatchstr, 0 , matchsize);
                    memcpy(pmatchstr, &(pcurstr[pstartpos[j]]), matchlen);
                    fprintf(stdout, "    [%03d] %s\n", j, pmatchstr);
                }
                /*we move to the next to find*/
                pcurstr = &(pcurstr[pendpos[0]]);
                fprintf(stdout, "    left[%s]\n", pcurstr);
                handled ++;
                goto try_again;
            } else {
                if (handled == 0) {
                    fprintf(stdout, "[%s] not find in [%s]\n", parsestate->leftargs[0], pcurstr);
                }
            }
        }
    } else {
        ret = read_file_lines(pargs->m_input, &pplines,&lsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        llen = ret;
        for (i=0;i<llen;i++) {
            pcurstr = pplines[i];
            handled = 0;
file_try_again:
            ret = regex_exec(preg, pcurstr, &pstartpos, &pendpos, &possize);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not exec [%s] for [%s] error[%d]", pcurstr, parsestate->leftargs[0], ret);
                goto out;
            }
            retlen = ret;
            if (retlen > 0) {
                fprintf(stdout, "[%s] find [%s]\n", parsestate->leftargs[0], pcurstr);
                for (j = 0; j < retlen; j++) {
                    matchlen = (size_t)(pendpos[j] - pstartpos[j]);
                    if (matchlen >= matchsize || pmatchstr == NULL) {
                        if (pmatchstr) {
                            free(pmatchstr);
                        }
                        pmatchstr = NULL;
                        matchsize = (matchlen + 3);
                        pmatchstr = (char*) malloc(matchsize);
                        if (pmatchstr == NULL) {
                            GETERRNO(ret);
                            ERROR_INFO("alloc %d error[%d]", matchsize, ret);
                            goto out;
                        }
                    }
                    memset(pmatchstr, 0 , matchsize);
                    memcpy(pmatchstr, &(pcurstr[pstartpos[j]]), matchlen);
                    fprintf(stdout, "    [%03d] %s\n", j, pmatchstr);
                }
                /*we move to the next to find*/
                pcurstr = &(pcurstr[pendpos[0]]);
                fprintf(stdout, "    left[%s]\n", pcurstr);
                handled ++;
                goto file_try_again;
            } else {
                if (handled == 0) {
                    fprintf(stdout, "[%s] not find in [%s]\n", parsestate->leftargs[0], pcurstr);
                }
            }

        }
    }

    ret = 0;
out:
    if (pmatchstr != NULL) {
        free(pmatchstr);
    }
    pmatchstr = NULL;
    matchsize = 0;
    read_file_lines(NULL,&pplines,&lsize);
    regex_exec(NULL, NULL, &pstartpos, &pendpos, &possize);
    regex_compile(NULL, REGEX_NONE, &preg);
    SETERRNO(ret);
    return ret;
}

