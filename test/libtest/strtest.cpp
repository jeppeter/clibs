
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

int regsplit_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
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

    ret = regex_compile(parsestate->leftargs[0], REGEX_NONE, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not compile [%s]", parsestate->leftargs[0]);
        goto out;
    }

    for (i = 1; i < argcnt; i++) {
        pcurstr = parsestate->leftargs[i];
        ret = regex_split(preg, pcurstr, &pstartpos, &pendpos, &possize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not exec [%s] for [%s] error[%d]", pcurstr, parsestate->leftargs[0], ret);
            goto out;
        }
        retlen = ret;
        if (retlen > 0) {
            fprintf(stdout, "[%s] split [%s]\n", parsestate->leftargs[0], pcurstr);
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
            fprintf(stdout, "[%s] can not split [%s]\n", parsestate->leftargs[0], pcurstr);
        }
    }

    ret = 0;
    out:
    if (pmatchstr != NULL) {
        free(pmatchstr);
    }
    pmatchstr = NULL;
    matchsize = 0;
    regex_split(NULL, NULL, &pstartpos, &pendpos, &possize);
    regex_compile(NULL, REGEX_NONE, &preg);
    SETERRNO(ret);
    return ret;    
}

int iregsplit_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
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

    ret = regex_compile(parsestate->leftargs[0], REGEX_NONE, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not compile [%s]", parsestate->leftargs[0]);
        goto out;
    }

    for (i = 1; i < argcnt; i++) {
        pcurstr = parsestate->leftargs[i];
        ret = regex_split(preg, pcurstr, &pstartpos, &pendpos, &possize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not exec [%s] for [%s] error[%d]", pcurstr, parsestate->leftargs[0], ret);
            goto out;
        }
        retlen = ret;
        if (retlen > 0) {
            fprintf(stdout, "[%s] split [%s]\n", parsestate->leftargs[0], pcurstr);
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
            fprintf(stdout, "[%s] can not split [%s]\n", parsestate->leftargs[0], pcurstr);
        }
    }

    ret = 0;
    out:
    if (pmatchstr != NULL) {
        free(pmatchstr);
    }
    pmatchstr = NULL;
    matchsize = 0;
    regex_split(NULL, NULL, &pstartpos, &pendpos, &possize);
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

    if (retsize <= (cnt + (int)sizeof(wchar_t)) || pcode == NULL) {
        retsize = cnt + (int) sizeof(wchar_t);
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
    debug_buffer(stdout, putf8, utf8len,NULL);
    fprintf(stdout, "ansi buffer [%d]\n", ansilen);
    debug_buffer(stdout, pansi, ansilen,NULL);
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
    debug_buffer(stdout, pansi, ansilen,NULL);
    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    debug_buffer(stdout, putf8, utf8len,NULL);
    ret = 0;
    out:
    AnsiToUtf8(NULL, &putf8, &utf8size);
    __get_code(NULL, &pansi, &ansisize);
    SETERRNO(ret);
    return ret;
}

int simpleansi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* cstr = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    for (i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        cstr = parsestate->leftargs[i];
        debug_buffer(stdout,cstr,(int)strlen(cstr) + 1,NULL);
    }
    return 0;
}

int encbase64_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    char* input = NULL;
    char* output = NULL;
    char* inbuf = NULL;
    int insize = 0, inlen = 0;
    char* outbuf = NULL;
    int outsize = 0;
    int outlen = 0;
    int ret;
    char* expandline = NULL;
    int expandsize = 0;
    int expandlen = 0;

    init_log_level(pargs);
    argc = argc;
    argv = argv;
    input = parsestate->leftargs[0];
    output = parsestate->leftargs[1];

    ret = read_file_whole(input, &inbuf, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read %s error%d\n", input, ret);
        goto out;
    }
    inlen = ret;

    outsize = 32;
try_again:
    if (outbuf) {
        free(outbuf);
    }
    outbuf = NULL;
    outbuf = (char*)malloc((size_t)outsize);
    if (outbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "alloc %d error%d\n", outsize, ret );
        goto out;
    }

    ret = encode_base64((unsigned char*)inbuf, inlen, outbuf, outsize);
    if (ret < 0) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            outsize <<= 1;
            goto try_again;
        }
        fprintf(stderr, "can not encode base\n");
        debug_buffer(stderr, inbuf, insize,NULL);
        fprintf(stderr, "error [%d]\n", ret);
        goto out;
    }

    outlen = ret;
    ret = base64_splite_line(outbuf, outlen, 76, &expandline, &expandsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "expand line error[%d]\n", ret);
        goto out;
    }

    expandlen = ret;

    //fprintf(stdout, "inlen [%d]outlen [%d]\n", inlen, expandlen);
    ret = write_file_whole(output, expandline, expandlen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] error[%d]\n", output, ret );
        goto out;
    }

    fprintf(stdout, "encode [%s] => [%s] succ\n", input, output );
    ret = 0;

out:
    base64_splite_line(NULL, 0, 0, &expandline, &expandsize);
    read_file_whole(NULL, &inbuf, &insize);
    if (outbuf) {
        free(outbuf);
    }
    outbuf = NULL;
    SETERRNO(ret);
    return ret;

}
int decbase64_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    char* input = NULL;
    char* output = NULL;
    char* inbuf = NULL;
    int insize = 0, inlen = 0;
    char* outbuf = NULL;
    int outsize = 0;
    int outlen = 0;
    int ret;
    char* compactbuf = NULL;
    int compactlen = 0, compactsize = 0;

    init_log_level(pargs);
    argc = argc;
    argv = argv;
    input = parsestate->leftargs[0];
    output = parsestate->leftargs[1];

    ret = read_file_whole(input, &inbuf, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read %s error%d\n", input, ret);
        goto out;
    }
    inlen = ret;


    ret = base64_compact_line(inbuf, inlen, &compactbuf, &compactsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "compact error[%d]\n", ret);
        goto out;
    }
    compactlen = ret;

    outsize = 32;
    try_again:
    if (outbuf) {
        free(outbuf);
    }
    outbuf = NULL;
    outbuf = (char*)malloc((size_t)outsize);
    if (outbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "alloc %d error%d\n", outsize, ret );
        goto out;
    }



    ret = decode_base64(compactbuf, compactlen, (unsigned char*)outbuf, outsize);
    if (ret < 0) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            outsize <<= 1;
            goto try_again;
        }
        fprintf(stderr, "can not decode base\n");
        debug_buffer(stderr, inbuf, insize,NULL);
        fprintf(stderr, "error [%d]\n", ret);
        goto out;
    }

    outlen = ret;
    fprintf(stdout, "inlen [%d]outlen [%d]\n", inlen, outlen);
    ret = write_file_whole(output, outbuf, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] error[%d]\n", output, ret );
        goto out;
    }

    fprintf(stdout, "decode [%s] => [%s] succ\n", input, output );
    ret = 0;

out:
    base64_compact_line(NULL, 0, &compactbuf, &compactsize);
    read_file_whole(NULL, &inbuf, &insize);
    if (outbuf) {
        free(outbuf);
    }
    outbuf = NULL;
    SETERRNO(ret);
    return ret;
}

static int format_pipe_data(jvalue* pj, char** ppsndbuf, int* psndsize)
{
    jentry** entries = NULL;
    jentry* pcurentry = NULL;
    unsigned int entriesizes = 0;
    int ret;
    int sndlen = 0;
    char* pstr = NULL;
    int strsize = 0;
    char* valstr = NULL;
    unsigned int valsize = 0;
    int retlen = 0;
    char* pretbuf = NULL;
    unsigned int i;


    if (psndsize == NULL || ppsndbuf == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    retlen = *psndsize;
    pretbuf = *ppsndbuf;

    entries = jobject_entries(pj, &entriesizes);
    if (entries == NULL) {
        ret = snprintf_safe(&pstr, &strsize, "");
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    } else {
        for (i = 0; i < entriesizes; i++) {
            pcurentry = entries[i];
            switch (pcurentry->value->type) {
                case JNONE:
                case JBOOL:
                case JNULL:
                case JINT:
                case JINT64:
                case JREAL:
                case JSTRING:
                case JARRAY:
                case JOBJECT:
                if (valstr) {
                    free(valstr);
                }
                valstr = NULL;
                valsize = 0;
                valstr = jvalue_write(pcurentry->value, &valsize);
                if (valstr == NULL) {
                    GETERRNO(ret);
                    goto fail;
                }
                ret = append_snprintf_safe(&pstr, &strsize, "%s=%s\n", pcurentry->key, valstr);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                break;
                default:
                ret = -ERROR_INVALID_PARAMETER;
                goto fail;
            }
        }
    }

    sndlen = (int)(strlen(pstr) + sizeof(uint32_t));
    if (retlen < sndlen || pretbuf == NULL) {
        if (retlen < sndlen) {
            retlen = sndlen;
        }
        pretbuf = (char*) malloc((size_t)retlen);
        if (pretbuf == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }
    memcpy(pretbuf, &sndlen, sizeof(uint32_t));
    if (sndlen > sizeof(uint32_t)) {
        memcpy(&(pretbuf[sizeof(uint32_t)]), pstr, (sndlen - sizeof(uint32_t)));
    }

    if (*ppsndbuf && *ppsndbuf != pretbuf) {
        free(*ppsndbuf);
    }
    *ppsndbuf = pretbuf;
    *psndsize = retlen;

    snprintf_safe(&pstr, &strsize, NULL);
    if (valstr) {
        free(valstr);
    }
    valstr = NULL;
    valsize = 0;
    jentries_destroy(&entries);

    return sndlen;
fail:
    if (pretbuf && pretbuf != *ppsndbuf) {
        free(pretbuf);
    }
    pretbuf = NULL;

    snprintf_safe(&pstr, &strsize, NULL);
    if (valstr) {
        free(valstr);
    }
    valstr = NULL;
    valsize = 0;
    jentries_destroy(&entries);
    SETERRNO(ret);
    return ret;
}

int pipedata_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* fname;
    jvalue* pj = NULL;
    char* filecon = NULL;
    int filesize = 0;
    int ret;
    unsigned int size;
    char* poutdata = NULL;
    int outsize = 0;
    int outlen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        fname = parsestate->leftargs[i];
        ret = read_file_whole(fname, &filecon, &filesize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("read [%s] error[%d]", fname, ret);
            goto out;
        }

        if (pj) {
            jvalue_destroy(pj);
        }
        pj = NULL;
        size = 0;
        pj = jvalue_read(filecon, &size);
        if (pj == NULL) {
            GETERRNO(ret);
            ERROR_INFO("[%s] not json file", fname);
            goto out;
        }

        ret = format_pipe_data(pj, &poutdata, &outsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("format pipe [%s] error[%d]", fname, ret);
            goto out;
        }
        outlen = ret;
        DEBUG_BUFFER_FMT(poutdata, outlen, "[%s] format data", fname);
    }

    ret = 0;
    out:
    if (pj) {
        jvalue_destroy(pj);
    }
    pj = NULL;
    read_file_whole(NULL, &filecon, &filesize);
    SETERRNO(ret);
    return ret;
}

int utf8touni_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* putf8 = NULL;
    int utf8size = 0;
    int utf8len = 0;
    wchar_t* puni = NULL;
    int unisize = 0, unilen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    ret = __get_code(parsestate, &putf8, &utf8size);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    utf8len = ret;
    ret = Utf8ToUnicode(putf8, &puni, &unisize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not trans buffer [%d]\n", ret);
        goto out;
    }
    unilen = ret;

    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    debug_buffer(stdout, putf8, utf8len,NULL);
    fprintf(stdout, "unicode buffer [%d]\n", unilen);
    debug_buffer(stdout, (char*)puni, unilen,NULL);
    ret = 0;
    out:
    Utf8ToUnicode(NULL, &puni, &unisize);
    __get_code(NULL, &putf8, &utf8size);
    SETERRNO(ret);
    return ret;
}


int unitoutf8_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    char* putf8 = NULL;
    int utf8size = 0;
    int utf8len = 0;
    wchar_t* puni = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    ret = __get_code(parsestate, &pbuf, &bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    buflen = ret;

    puni = (wchar_t*)pbuf;

    ret = UnicodeToUtf8(puni, &putf8, &utf8size);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not trans buffer [%d]\n", ret);
        goto out;
    }
    utf8len = ret;

    fprintf(stdout, "unicode buffer [%d]\n", buflen);
    debug_buffer(stdout, pbuf, buflen,NULL);
    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    debug_buffer(stdout, putf8, utf8len,NULL);
    ret = 0;
    out:
    UnicodeToUtf8(NULL, &putf8, &utf8size);
    __get_code(NULL, &pbuf, &bufsize);
    SETERRNO(ret);
    return ret;
}

int utf8json_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    jvalue* mainpj = NULL;
    jvalue* filepj = NULL;
    jentry** entries = NULL;
    jentry* curentry = NULL;
    const char* key = NULL;
    jvalue* value = NULL;
    jvalue* insertval = NULL;
    jvalue* replval = NULL;
    unsigned int entrysize = 0;
    char* filebuf = NULL;
    int filesize = 0;
    int filelen = 0;
    char* fname = NULL;
    unsigned int rdlen = 0;
    char* poutbuf = NULL;
    unsigned int outbufsize = 0;
    int i;
    unsigned int j;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);

    mainpj = jobject_create();
    if (mainpj == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create object error");
        goto out;
    }

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        fname = parsestate->leftargs[i];
        ret = read_file_whole(fname, &filebuf, &filesize);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }

        filelen = ret;
        rdlen = 0;
        filepj = jvalue_read(filebuf, &rdlen);
        if (filepj == NULL) {
            GETERRNO(ret);
            ERROR_INFO("parse [%s] error[%d]", fname, ret);
            goto out;
        }
        if ((int)rdlen > filelen) {
            ret = -ERROR_INVALID_PARAMETER;
            ERROR_INFO("[%s] overread", fname);
            goto out;
        }

        entries = jobject_entries(filepj, &entrysize);
        if (entries == NULL) {
            DEBUG_INFO("entries 0");
            goto next;
        }

        for (j = 0; j < entrysize; j++) {
            curentry = entries[j];
            key = curentry->key;
            value = curentry->value;

            insertval = jvalue_clone(value);
            if (insertval == NULL) {
                GETERRNO(ret);
                ERROR_INFO("clone[%s] value error[%d]", key, ret);
                goto out;
            }

            replval = jobject_put(mainpj, key, insertval, &ret);
            if (ret != 0) {
                GETERRNO(ret);
                ERROR_INFO("put value [%s] error[%d]", key, ret);
                goto out;
            }
            if (replval != NULL) {
                DEBUG_INFO("replace [%s]" , key);
                jvalue_destroy(replval);
                replval = NULL;
            }
            insertval = NULL;
        }

        next:
        jentries_destroy(&entries);
        if (filepj) {
            jvalue_destroy(filepj);
        }
        filepj = NULL;
        read_file_whole(NULL, &filebuf, &filesize);
        filelen  = 0;
    }

    /*now to jvalue_write_raw*/
    poutbuf = jvalue_write_raw(mainpj, &outbufsize);
    if (poutbuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not write mainpj [%d]", ret);
        goto out;
    }

    debug_buffer(stdout, poutbuf, (int)outbufsize,NULL);

    ret = 0;
    out:
    if (poutbuf) {
        free(poutbuf);
    }
    poutbuf = NULL;
    outbufsize = 0;
    if (insertval) {
        jvalue_destroy(insertval);
    }
    insertval = NULL;

    jentries_destroy(&entries);
    read_file_whole(NULL, &filebuf, &filesize);
    filelen = 0;
    if (filepj) {
        jvalue_destroy(filepj);
    }
    filepj = NULL;
    if (mainpj) {
        jvalue_destroy(mainpj);
    }
    mainpj = NULL;
    SETERRNO(ret);
    return ret;
}

int jsonget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* jsonfile=NULL;
    int jsonsize=0;
    unsigned int jsonlen=0;
    char* jsons = NULL;
    char* jsontype="string";
    int ret;
    jvalue* pj = NULL;
    jarray* parr = NULL;
    jvalue* pobj= NULL;
    char* keyname = NULL;
    unsigned int arrsize = 0;
    char* formjson=NULL;
    unsigned int formsize=0;
    int error = 0;
    unsigned int i;
    const jvalue* pcur=NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    if (parsestate->leftargs && parsestate->leftargs[0]) {
        jsonfile = parsestate->leftargs[0];
        if (parsestate->leftargs[1]) {
            keyname = parsestate->leftargs[1];
            if (parsestate->leftargs[2]) {
                jsontype = parsestate->leftargs[2];
            }
        }
    }

    if (jsonfile == NULL || keyname == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "no jsonfile or keyname set\n");
        goto out;
    }

    ret = read_file_whole(jsonfile,&jsons,&jsonsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    jsonlen = (unsigned int)jsonsize;
    pj = jvalue_read(jsons,&jsonlen);
    if (pj == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "not parse [%s]\n%s\n",jsonfile,jsons);
        goto out;
    }

    if (strcmp(jsontype,"array") == 0) {
        parr = jobject_get_array(pj,keyname,&error);
        if (parr == NULL) {
            GETERRNO(ret);
            fprintf(stderr,"can not get [%s]\n",keyname);
            goto out;
        }

        arrsize = jarray_size((const jvalue*)parr);
        fprintf(stdout,"[%s] array size [%d]\n",keyname,arrsize);
            /*now to get all */
        for(i=0;i<arrsize;i++) {
            pcur = jarray_get((const jvalue*)parr,i,&error);
            if (pcur == NULL) {
                GETERRNO(ret);
                goto out;
            }
            ASSERT_IF(formjson == NULL);
            formjson = jvalue_write(pcur,&formsize);
            if (formjson != NULL) {
                fprintf(stdout,"[%s].[%d]item\n%s\n",keyname,i,formjson);
                free(formjson);
            } else {
                fprintf(stdout,"[%s].[%d]item\nreally null\n",keyname,i);
            }
            formjson = NULL;
            formsize = 0;
        }
    } else if (strcmp(jsontype,"object") == 0) {
        pobj = jobject_get(pj,keyname);
        if (pobj == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s] error[%d]\n", keyname,ret);
            goto out;
        }
        jsons = jvalue_write(pobj,&formsize);
        if (jsons == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "write [%s] error [%d]\n", keyname,ret);
            goto out;
        }
        fprintf(stdout,"[%s]\n%s\n",keyname,jsons);
    } else if (strcmp(jsontype,"int") == 0) {
        error = 0;
        int retval = jobject_get_int(pj,keyname,&error);
        if (error != 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%s] get error[%d]\n", keyname,ret);
            goto out;
        }
        fprintf(stderr, "%s = %d\n", keyname,retval);
    } else if (strcmp(jsontype,"int64") == 0) {
        error = 0;
        long long int retval = jobject_get_int64(pj,keyname,&error);
        if (error != 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%s] get error[%d]\n", keyname,ret);
            goto out;
        }
        fprintf(stderr, "%s = %lld\n", keyname,retval);
    } else if (strcmp(jsontype,"bool") == 0) {
        error = 0;
        int retval = jobject_get_bool(pj,keyname,&error);
        if (error != 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%s] get error[%d]\n", keyname,ret);
            goto out;
        }
        fprintf(stderr, "%s = %s\n", keyname,retval ? "true": "false");
    } else if (strcmp(jsontype,"float") == 0 ) {
        error = 0;
        double retval = jobject_get_real(pj,keyname,&error);
        if (error != 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%s] get error[%d]\n", keyname,ret);
            goto out;
        }
        fprintf(stderr, "%s = %f\n", keyname,retval);
    } else if (strcmp(jsontype,"null") == 0 ) {
        error = 0;
        jobject_get_real(pj,keyname,&error);
        if (error != 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%s] get error[%d]\n", keyname,ret);
            goto out;
        }
        fprintf(stderr, "%s = null\n", keyname);
    } else if (strcmp(jsontype,"string") == 0 ) {
        error = 0;
        const char* retval = jobject_get_string(pj,keyname,&error);
        if (error != 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%s] get error[%d]\n", keyname,ret);
            goto out;
        }
        fprintf(stderr, "%s = %s\n", keyname,retval);
    } else {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "not support type [%s]\n", jsontype);
        goto out;
    }

    ret = 0;
    out:
    if (formjson) {
        free(formjson);
    }
    formjson = NULL;
    formsize = 0;
    if (pj) {
        jvalue_destroy(pj);
    }
    pj = NULL;
    read_file_whole(NULL,&jsons,&jsonsize);
    SETERRNO(ret);
    return ret;
}


int unitoansi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* ansistr=NULL;
    int ansisize=0;
    char* puni=NULL;
    int unisize=0;
    int unilen;


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);



    ret = __get_code(parsestate,&puni,&unisize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    unilen = ret;

    ret=  UnicodeToAnsi((wchar_t*)puni,&ansistr,&ansisize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    debug_buffer(stdout,puni,unilen,"unicode buffer");
    fprintf(stdout,"%s\n",ansistr);

    ret = 0;
out:
    UnicodeToAnsi(NULL,&ansistr,&ansisize);
    __get_code(NULL,&puni,&unisize);
    SETERRNO(ret);
    return ret;
}


int ansitouni_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* ansistr=NULL;
    wchar_t* puni=NULL;
    int unisize=0;
    int unilen=0;
    int i;


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);


    for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        ansistr = parsestate->leftargs[i];
        ret = AnsiToUnicode(ansistr,&puni,&unisize);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        unilen = ret;
        debug_buffer(stdout,(char*)puni,(int)sizeof(wchar_t)* unilen,"ansi [%s]",ansistr);
    }
    ret = 0;
out:
    AnsiToUnicode(NULL,&puni,&unisize);
    SETERRNO(ret);
    return ret;

}
