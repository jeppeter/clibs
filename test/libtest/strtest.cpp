
int quote_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char* qstr = NULL;
    int qsize = 0;
    int i;

    argc = argc;
    argv = argv;
    popt = popt;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        ret = quote_string(&qstr, &qsize, parsestate->leftargs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "[%d][%s] quoted [%s]\n", i, parsestate->leftargs[i], qstr);
    }
    ret = 0;
out:
    quote_string(&qstr, &qsize, NULL);
    SETERRNO(ret);
    return ret;
}

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
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2) {
        ret = -ERROR_INVALID_PARAMETER;
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

    argc = argc;
    argv = argv;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("arg must restr instr...");
        goto out;
    }

    ret = regex_compile(parsestate->leftargs[0], REGEX_IGNORE_CASE, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not compile [%s]", parsestate->leftargs[0]);
        goto out;
    }

    for (i = 1; i < argcnt; i++) {
        pcurstr = parsestate->leftargs[i];
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
        } else {
            fprintf(stdout, "[%s] not find in [%s]\n", parsestate->leftargs[0], pcurstr);
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


int __get_code(pextargs_state_t parsestate, char** ppcode, int* psize)
{
    int cnt = 0;
    int ret;
    char* pcode = NULL;
    int retsize = 0;
    int num = 0;
    int idx;
    int i;
    if (parsestate == NULL) {
        if (ppcode && *ppcode) {
            free(*ppcode);
            *ppcode = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (retsize <= cnt || pcode == NULL) {
        if (retsize <= cnt) {
            retsize = cnt + 1;
        }
        pcode = (char*)malloc((size_t)retsize);
        if (pcode == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "alloc %d error[%d]\n", retsize, ret);
            goto fail;
        }
    }
    memset(pcode, 0, (size_t)retsize);
    idx = 0;
    for (i = 0; i < cnt; i++) {
        GET_OPT_INT(num, "number");
        /*we change the idx*/
        pcode[i] = (char)num;
    }


    if (*ppcode && *ppcode != pcode) {
        free(*ppcode);
    }
    *ppcode = pcode;
    *psize = retsize;
    return cnt;
out:
fail:
    if (pcode && pcode != *ppcode) {
        free(pcode);
    }
    pcode = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}


int utf8toansi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* putf8 = NULL;
    int utf8size = 0;
    int utf8len = 0;
    char* pansi = NULL;
    int ansisize = 0, ansilen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    ret = __get_code(parsestate, &putf8, &utf8size);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    utf8len = ret;
    ret = Utf8ToAnsi(putf8, &pansi, &ansisize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not trans buffer [%d]\n", ret);
        goto out;
    }
    ansilen = ret;

    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    __debug_buf(stdout, putf8, utf8len);
    fprintf(stdout, "ansi buffer [%d]\n", ansilen);
    __debug_buf(stdout, pansi, ansilen);
    ret = 0;
out:
    Utf8ToAnsi(NULL, &pansi, &ansisize);
    __get_code(NULL, &putf8, &utf8size);
    SETERRNO(ret);
    return ret;
}

int ansitoutf8_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* putf8 = NULL;
    int utf8size = 0;
    int utf8len = 0;
    char* pansi = NULL;
    int ansisize = 0, ansilen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);
    ret = __get_code(parsestate, &pansi, &ansisize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    ansilen = ret;
    ret = AnsiToUtf8(pansi, &putf8, &utf8size);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not trans buffer [%d]\n", ret);
        goto out;
    }
    utf8len = ret;

    fprintf(stdout, "ansi buffer [%d]\n", ansilen);
    __debug_buf(stdout, pansi, ansilen);
    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    __debug_buf(stdout, putf8, utf8len);
    ret = 0;
out:
    AnsiToUtf8(NULL, &putf8, &utf8size);
    __get_code(NULL, &pansi, &ansisize);
    SETERRNO(ret);
    return ret;
}
