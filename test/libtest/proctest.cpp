
int pidargv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char** ppargv = NULL;
    int argvsize = 0;
    int pid = -1;
    int ret = 0;
    int totalret = 0;
    int i, j;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            pid = atoi(parsestate->leftargs[i]);
            ret = get_pid_argv(pid, &ppargv, &argvsize);
            if (ret < 0) {
                fprintf(stderr, "can not get [%d] error[%d]\n", pid, ret);
                totalret = ret;
                continue;
            }
            for (j = 0; j < ret; j++) {
                fprintf(stdout, "[%d][%d]=[%s]\n", pid, j, ppargv[j]);
            }
        }
    }
    get_pid_argv(-1, &ppargv, &argvsize);
    return totalret;
}


void __debug_buf(FILE* fp, char* ptr, int size)
{
    int i, lasti;
    unsigned char* pcur = (unsigned char*)ptr;
    unsigned char* plast = pcur;

    for (i = 0; i < size; i++) {
        if ((i % 16) == 0) {
            if (i > 0) {
                fprintf(fp, "    ");
                while (plast != pcur) {
                    if (isprint((char) *plast)) {
                        fprintf(fp, "%c", *plast);
                    } else {
                        fprintf(fp, ".");
                    }
                    plast ++;
                }
                fprintf(fp, "\n");
            }
            fprintf(fp, "0x%08x:", i);
        }
        fprintf(fp, " 0x%02x", *pcur);
        pcur ++;
    }

    if (plast != pcur) {
        lasti = i;
        /*now we should give out*/
        while ((lasti % 16)) {
            fprintf(fp, "     ");
            lasti ++;
        }
        fprintf(fp, "    ");
        while (plast != pcur) {
            if (isprint((char) *plast)) {
                fprintf(fp, "%c", *plast);
            } else {
                fprintf(fp, ".");
            }
            plast ++;
        }
        fprintf(fp, "\n");
    }
    fflush(fp);
    return;
}

int runv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int i;
    int ret;
    char** ppoutbuf = NULL;
    int *poutsize = NULL;
    char** pperrbuf = NULL;
    int *perrsize = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_whole(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        insize = ret;
    }

    if (pargs->m_output != NULL) {
        ppoutbuf = &outbuf;
        poutsize = &outsize;
    }

    if (pargs->m_errout != NULL) {
        pperrbuf = &errbuf;
        perrsize = &errsize;
    }

    ret = run_cmd_outputv(inbuf, insize, ppoutbuf, poutsize, pperrbuf, perrsize, &exitcode, pargs->m_timeout, parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run cmd [");
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", parsestate->leftargs[i]);
        }
        fprintf(stderr, "] error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "run cmd [");
    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        if (i > 0) {
            fprintf(stdout, ",");
        }
        fprintf(stdout, "%s", parsestate->leftargs[i]);
    }
    fprintf(stdout, "] succ\n");
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input --------------------\n");
        __debug_buf(stdout, inbuf, insize);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        __debug_buf(stdout, outbuf, outsize);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        __debug_buf(stdout, errbuf, errsize);
        fprintf(stdout, "errout ++++++++++++++++++++\n");
    }

    ret = 0;
out:
    run_cmd_outputv(NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_whole(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}

int runsingle_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int ret;
    char** ppoutbuf = NULL;
    int *poutsize = NULL;
    char** pperrbuf = NULL;
    int *perrsize = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_whole(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        insize = ret;
    }

    if (pargs->m_output != NULL) {
        ppoutbuf = &outbuf;
        poutsize = &outsize;
    }

    if (pargs->m_errout != NULL) {
        pperrbuf = &errbuf;
        perrsize = &errsize;
    }

    ret = run_cmd_output_single(inbuf, insize, ppoutbuf, poutsize, pperrbuf, perrsize, &exitcode, pargs->m_timeout, parsestate->leftargs[0]);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run single cmd [%s] error[%d]\n", parsestate->leftargs[0], ret);
        goto out;
    }

    fprintf(stdout, "run cmd [%s] succ\n", parsestate->leftargs[0]);
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input --------------------\n");
        __debug_buf(stdout, inbuf, insize);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        __debug_buf(stdout, outbuf, outsize);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        __debug_buf(stdout, errbuf, errsize);
        fprintf(stdout, "errout ++++++++++++++++++++\n");
    }

    ret = 0;
out:
    run_cmd_output_single(NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_whole(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}

int outc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    char* ptmpbuf = NULL;
    char* pinbuf = NULL;
    int insize = 0;
    int inlen = 0;
    char** ppllines = NULL;
    int lsize = 0;
    int llen = 0;
    argc = argc;
    argv = argv;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            fprintf(stderr, "stderr %s\n", parsestate->leftargs[i]);
            Sleep(1000);
            fprintf(stdout, "stdout %s\n", parsestate->leftargs[i]);
        }
    } else {

        insize = 1024;
        pinbuf = (char*) malloc((size_t)insize);
        if (pinbuf == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", insize, ret);
            goto out;
        }
        while (1) {
            ret = (int)fread(&(pinbuf[inlen]), 1, (size_t) (insize - inlen), stdin);
            if (ret < 0 ) {
                if (feof(stdin)) {
                    break;
                }
                GETERRNO(ret);
                ERROR_INFO("read [%d] error[%d]", inlen, ret);
                goto out;
            }

            inlen += ret;
            if (ret == 0) {
                break;
            }
            if (inlen >= insize) {
                insize <<= 1;
                ptmpbuf = (char*) malloc((size_t)insize);
                if (ptmpbuf == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", insize, ret);
                    goto out;
                }
                memset(ptmpbuf, 0, (size_t)insize);
                if (inlen > 0) {
                    memcpy(pinbuf, ptmpbuf, (size_t)inlen);
                }
                if (pinbuf) {
                    free(pinbuf);
                }
                pinbuf = ptmpbuf;
                ptmpbuf = NULL;
            }
        }

        ret = split_lines(pinbuf, &ppllines, &lsize);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        llen = ret;
        for (i = 0; i < llen; i++) {
            fprintf(stderr, "stderr %s\n", ppllines[i]);
            Sleep(1000);
            fprintf(stdout, "stdout %s\n", ppllines[i]);
        }
    }
    ret = 0;
out:
    split_lines(NULL, &ppllines, &lsize);
    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    if (pinbuf != NULL) {
        free(pinbuf);
    }
    pinbuf = NULL;
    insize = 0;
    inlen = 0;
    SETERRNO(ret);
    return ret;
}

int run_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pout = NULL;
    int outsize = 0;
    char* perr = NULL;
    int errsize = 0;
    int exitcode = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    parsestate = parsestate;
    init_log_level(pargs);


    ret = run_cmd_output(NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, "libtest.exe", "outc", "little", "big", NULL);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    if (exitcode != 0) {
        GETERRNO(ret);
        ERROR_INFO("exitcode %d", ret);
        goto out;
    }

    fprintf(stdout, "read stdout------------\n");
    fprintf(stdout, "%s", pout);
    fprintf(stdout, "++++++++++++++++++++++++++\n");
    fprintf(stdout, "read stderr------------\n");
    fprintf(stdout, "%s", perr);
    fprintf(stdout, "++++++++++++++++++++++++++\n");

    ret = 0;
out:
    run_cmd_output(NULL, 0, &pout, &outsize, &perr, &errsize, NULL, 0, NULL);
    SETERRNO(ret);
    return ret;
}

void __close_handle_note_2(HANDLE *phd, const char* fmt, ...)
{
    va_list ap;
    BOOL bret;
    char* errstr = NULL;
    int errsize = 0;
    int ret;
    int res;
    if (phd && *phd != INVALID_HANDLE_VALUE && *phd != NULL) {
        bret = CloseHandle(*phd);
        if (!bret && fmt != NULL) {
            GETERRNO(ret);
            va_start(ap, fmt);
            res = vsnprintf_safe(&errstr, &errsize, fmt, ap);
            if (res >= 0) {
                ERROR_INFO("%s error[%d]", errstr, ret);
            }
            vsnprintf_safe(&errstr, &errsize, NULL, ap);
        }
        *phd = INVALID_HANDLE_VALUE;
    }
    return;
}


#define MIN_BUF_SIZE    0x400

int __create_pipe_2(char* name , int wr, HANDLE *ppipe, OVERLAPPED* pov, HANDLE *pevt, int *pstate)
{
    int ret;
    int res;
    BOOL bret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    DWORD omode = 0;
    DWORD pmode = 0;
    if (name == NULL) {
        if ( ppipe != NULL && *ppipe != NULL &&
                *ppipe != INVALID_HANDLE_VALUE && pov != NULL) {
            if (pstate && (*pstate != PIPE_NONE && *pstate != PIPE_READY)) {
                bret = CancelIoEx(*ppipe, pov);
                if (!bret) {
                    GETERRNO(res);
                    ERROR_INFO("cancel io error[%d] at state [%d]", res, *pstate);
                }
            }
        }

        if (ppipe != NULL && *ppipe != NULL &&
                *ppipe != INVALID_HANDLE_VALUE &&
                pstate != NULL &&
                (*pstate == PIPE_WAIT_READ && *pstate == PIPE_WAIT_WRITE )) {
            bret = DisconnectNamedPipe(*ppipe);
            if (!bret) {
                GETERRNO(res);
                ERROR_INFO("disconnect error[%d]", res);
            }
        }
        __close_handle_note_2(pevt, "event close");
        __close_handle_note_2(ppipe, "pipe close");
        if (pov != NULL) {
            memset(pov, 0 , sizeof(*pov));
        }
        return 0;
    }

    if (ppipe == NULL || pevt == NULL || pov == NULL || pstate == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (*ppipe != NULL || *pevt != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    *pstate = PIPE_NONE;
    *pevt = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (*pevt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not create event for[%s] error[%d]", name, ret);
        goto fail;
    }

    memset(pov, 0 , sizeof(*pov));
    pov->hEvent = *pevt;

    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (wr) {
        omode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        pmode = PIPE_TYPE_MESSAGE | PIPE_WAIT;
    } else {
        omode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        pmode = PIPE_TYPE_MESSAGE  | PIPE_WAIT;
    }

    DEBUG_INFO("create %s [%s]", wr ? "write" : "read", name);

    *ppipe = CreateNamedPipe(ptname, omode, pmode, 1, MIN_BUF_SIZE * sizeof(TCHAR), MIN_BUF_SIZE * sizeof(TCHAR), 5000, NULL);
    if (*ppipe == NULL ||
            *ppipe == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("create [%s] for %s error[%d]", name, wr ? "write" : "read", ret);
        goto fail;
    }


    bret = ConnectNamedPipe(*ppipe, pov);
    if (!bret) {
        GETERRNO(ret);
        if (ret != -ERROR_IO_PENDING && ret != -ERROR_PIPE_CONNECTED) {
            ERROR_INFO("connect [%s] for %s error[%d]", name, wr ? "write" : "read", ret);
            goto fail;
        }
        if (ret == -ERROR_IO_PENDING) {
            DEBUG_INFO("[%s] connect pending" , name);
            *pstate = PIPE_WAIT_CONNECT;
        } else {
            *pstate = PIPE_READY;
        }
    } else {
        /*ok so we got ready*/
        *pstate = PIPE_READY;
    }


    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    AnsiToTchar(NULL, &ptname, &tnamesize);
    __close_handle_note_2(pevt, "%s event", name);
    __close_handle_note_2(ppipe, "%s server pipe", name);
    memset(pov, 0, sizeof(*pov));
    SETERRNO(ret);
    return ret;
}

#define LEAST_UNIQ_NUM    50

int __get_temp_pipe_name_2(char* prefix, char** pptmp, int *psize)
{
    TCHAR* tmpdirbuf = NULL;
    size_t tmpdirsize = 0, tmpdirlen;
    TCHAR* ptprefix = NULL;
    int prefixsize = 0;
    TCHAR* tmpfilebuf = NULL;
    size_t tmpfilesize = 0, tmpfilelen;

    int ret, nlen;
    DWORD dret;
    UINT uniq, uret;
    TCHAR* prealname = NULL;
    TCHAR* pcmpname = NULL;


    if (prefix == NULL) {
        if (pptmp && *pptmp && psize) {
            TcharToAnsi(NULL, pptmp, psize);
        }
        return 0;
    }

    ret = AnsiToTchar(prefix, &ptprefix, &prefixsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    tmpdirsize = 1024 * sizeof(TCHAR);
    tmpfilesize = 1024 * sizeof(TCHAR);
try_again:
    if (tmpdirbuf != NULL) {
        free(tmpdirbuf);
    }
    tmpdirbuf = NULL;
    tmpdirbuf = (TCHAR*) malloc(tmpdirsize);
    if (tmpdirbuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tmpdirsize, ret);
        goto fail;
    }
    memset(tmpdirbuf, 0 , tmpdirsize);
    dret = GetTempPath((DWORD)(tmpdirsize / sizeof(TCHAR)), tmpdirbuf);
    if (dret == 0) {
        GETERRNO(ret);
        ERROR_INFO("get temp path error[%d]", ret);
        goto fail;
    } else if (dret >= (tmpdirsize / sizeof(TCHAR))) {
        tmpdirsize <<= 1;
        goto try_again;
    }

    if (tmpfilebuf != NULL) {
        free(tmpfilebuf);
    }
    tmpfilebuf = NULL;
    tmpfilebuf = (TCHAR*) malloc(tmpfilesize);
    if (tmpfilebuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tmpfilesize , ret);
        goto fail;
    }
    tmpdirlen = _tcslen(tmpdirbuf);
    if (tmpfilesize < ((tmpdirlen + LEAST_UNIQ_NUM + strlen(prefix)) * sizeof(TCHAR))) {
        tmpfilesize = ((tmpdirlen + LEAST_UNIQ_NUM + strlen(prefix)) * sizeof(TCHAR));
        goto try_again;
    }
    memset(tmpfilebuf, 0 , tmpfilesize);
    //uniq = (UINT)(LEAST_UNIQ_NUM + strlen(prefix));
    uniq = 0;

    uret = GetTempFileName(tmpdirbuf, ptprefix, uniq, tmpfilebuf);
    if (uret == 0) {
        GETERRNO(ret);
        ERROR_INFO("get temp file name error[%s]", ret);
        goto fail;
    }

    prealname = tmpfilebuf;
    pcmpname = tmpdirbuf;
    while (*prealname == *pcmpname) {
        prealname ++;
        pcmpname ++;
    }

    while ( *prealname == __TEXT('\\')) {
        prealname ++;
    }

    tmpdirlen = _tcslen(tmpdirbuf);
    tmpfilelen = _tcslen(tmpfilebuf);
    DEBUG_BUFFER_FMT(tmpdirbuf, (int)((tmpdirlen + 1) * sizeof(TCHAR)), NULL);
    DEBUG_BUFFER_FMT(tmpfilebuf, (int)((tmpfilelen + 1) * sizeof(TCHAR)), NULL);

    DEBUG_INFO("tmpfilebuf %p prealname %p", tmpfilebuf, prealname);

    ret = TcharToAnsi(prealname, pptmp, psize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    nlen = ret;
    if (tmpdirbuf != NULL) {
        free(tmpdirbuf);
    }
    tmpdirbuf = NULL;
    tmpdirsize = 0;
    if (tmpfilebuf != NULL) {
        free(tmpfilebuf);
    }
    tmpfilebuf = NULL;
    tmpfilesize = 0;
    AnsiToTchar(NULL, &ptprefix, &prefixsize);
    return nlen;
fail:
    if (tmpdirbuf != NULL) {
        free(tmpdirbuf);
    }
    tmpdirbuf = NULL;
    tmpdirsize = 0;
    if (tmpfilebuf != NULL) {
        free(tmpfilebuf);
    }
    tmpfilebuf = NULL;
    tmpfilesize = 0;
    AnsiToTchar(NULL, &ptprefix, &prefixsize);
    SETERRNO(ret);
    return ret;
}


int svrlap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    HANDLE svrpipe = NULL;
    HANDLE evt = NULL;
    OVERLAPPED ov;
    int state = PIPE_NONE;
    int wr = 0;
    HANDLE waithds[1];
    DWORD waitnum;
    DWORD dret;
    char* poutbuf = NULL;
    size_t outsize = 0;
    size_t outlen = 0;
    char* pinbuf = NULL;
    size_t insize = 0;
    size_t inlen = 0;
    DWORD wtime;
    pargs_options_t pargs = (pargs_options_t) popt;
    uint64_t sticks = 0, cticks = 0;
    DWORD cbret;
    char* pipename = NULL;
    char* ptmpbuf = NULL;
    BOOL bret;
    char* pipebasename = NULL;
    int pipebasesize = 0;
    char* tmppipe = NULL;
    int tmppipesize = 0;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (pargs->m_input != NULL) {
        wr = 1;
        ret = read_file_whole(pargs->m_input, &poutbuf, (int*)&outsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
    }

    if (parsestate->leftargs != NULL && parsestate->leftargs[0] != NULL) {
        pipename = parsestate->leftargs[0];
    } else {
        ret = __get_temp_pipe_name_2("pipe", &pipebasename, &pipebasesize);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }

        ret = snprintf_safe(&tmppipe, &tmppipesize, "\\\\.\\pipe\\%s", pipebasename);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "create pipe %s\n", tmppipe);
        pipename = tmppipe;
    }


    ret = __create_pipe_2(pipename, wr, &svrpipe, &ov, &evt, &state);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "create %s error[%d]\n", pipename, ret);
        goto out;
    }

    if (pargs->m_timeout > 0) {
        sticks = get_current_ticks();
    }

    if (wr == 0) {
        insize = MIN_BUF_SIZE;
        pinbuf = (char*) malloc(insize);
        if (pinbuf == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "alloc %zu error[%d]\n", insize, ret);
            goto out;
        }
        memset(pinbuf, 0, insize);
    }

    while (1) {
        waitnum = 0;
        memset(waithds, 0 , sizeof(waithds));
        if (state == PIPE_WAIT_CONNECT) {
            waithds[0] = evt;
            waitnum ++;
        } else if (wr && state == PIPE_WAIT_WRITE) {
            waithds[0] = evt;
            waitnum ++;
        } else if (wr == 0 && state == PIPE_WAIT_READ) {
            waithds[0] = evt;
            waitnum ++;
        }

        if (waitnum > 0) {
            wtime = INFINITE;
            if (pargs->m_timeout > 0) {
                cticks = get_current_ticks();
                ret = need_wait_times(sticks, cticks, pargs->m_timeout);
                if (ret < 0) {
                    ret = -WAIT_TIMEOUT;
                    ERROR_INFO("wait [%s] timedout", pipename);
                    goto out;
                }
                wtime = (DWORD)ret;
            }
            dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, wtime, FALSE);
            if (dret != WAIT_OBJECT_0) {
                GETERRNO(ret);
                ERROR_INFO("wait [%s] ret[%ld] error[%d]", pipename, dret, ret);
                goto out;
            }
        }

        if (state == PIPE_WAIT_CONNECT) {
            DEBUG_INFO("%s connect", pipename);
            state = PIPE_READY;
        }

        if (state == PIPE_WAIT_READ) {
            /*ok this is for the */
            bret = GetOverlappedResult(svrpipe, &(ov), &cbret, FALSE);
            if (!bret) {
                GETERRNO(ret);
                if (ret != -ERROR_IO_PENDING && ret != -ERROR_MORE_DATA && ret != -ERROR_BROKEN_PIPE) {
                    ERROR_INFO("read [%s] at [%zu] error[%d]", pipename, inlen, ret);
                    goto out;
                }
                if (ret == -ERROR_BROKEN_PIPE) {
                    state = PIPE_READY;
                    break;
                }

                if (ret == -ERROR_MORE_DATA) {
                    inlen += cbret;
                    if (inlen > insize) {
                        ERROR_INFO("cbret [%d]", cbret);
                        inlen = insize;
                    }
                    DEBUG_INFO("inlen [%zu] insize[%zu]", inlen, insize);
                    if (inlen == insize) {
                        state = PIPE_READY;
                    }
                }
            } else {
                inlen += cbret;
                if (inlen > insize) {
                    ERROR_INFO("cbret [%d]", cbret);
                    inlen = insize;
                }
                DEBUG_INFO("inlen [%zu] insize[%zu] cbret[%d]", inlen, insize, cbret);
                if (inlen == insize) {
                    state = PIPE_READY;
                }
            }
        }

        if (state == PIPE_WAIT_WRITE) {
            bret = GetOverlappedResult(svrpipe, &(ov), &cbret, FALSE);
            if (!bret) {
                GETERRNO(ret);
                if (ret != -ERROR_IO_PENDING) {
                    ERROR_INFO("write [%s] [%zu] error[%d]", pipename, outlen, ret);
                    goto out;
                }
                outlen += cbret;
                if (outlen > outsize) {
                    ERROR_INFO("ret [%d] cbret [%d] outlen [%zu] outsize[%zu]", ret, cbret, outlen, outsize);
                    outlen = outsize;
                }
            } else {
                outlen += cbret;
                if (outlen > outsize) {
                    ERROR_INFO("cbret [%d] outlen [%zu] outsize[%zu]", cbret, outlen, outsize);
                    outlen = outsize;
                }
            }


            DEBUG_INFO("outlen [%zu] outsize [%zu]", outlen, outsize);
            if (outlen == outsize) {
                /*that is all ok so break*/
                break;
            }
        }

        if (state == PIPE_READY) {
            if (wr) {
                bret = WriteFile(svrpipe, &(poutbuf[outlen]), (DWORD)(outsize - outlen), &cbret, &(ov));
                if (!bret) {
                    GETERRNO(ret);
                    if (ret != -ERROR_IO_PENDING) {
                        ERROR_INFO("write [%s] [%zu] error[%d]", pipename, outlen, ret);
                        goto out;
                    }
                    state = PIPE_WAIT_WRITE;
                } else {
                    outlen += cbret;
                    if (outlen > outsize) {
                        ERROR_INFO("cbret [%d] outlen[%zu] outsize[%zu]", cbret, outlen, outsize);
                        outlen = outsize;
                    }
                }
                if (outlen == outsize) {
                    /*all writed ,so out*/
                    break;
                }
            } else {
                if (inlen == insize) {
                    insize <<= 1;
                    ptmpbuf = (char*) malloc(insize);
                    if (ptmpbuf == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc %zu error[%d]", insize, ret);
                        goto out;
                    }
                    memset(ptmpbuf, 0 , insize);
                    if (inlen > 0) {
                        memcpy(ptmpbuf, pinbuf, inlen);
                    }

                    if (pinbuf) {
                        free(pinbuf);
                    }
                    pinbuf = NULL;
                    pinbuf = ptmpbuf;
                    ptmpbuf = NULL;
                }

                bret = ReadFile(svrpipe, &(pinbuf[inlen]), (DWORD)(insize - inlen), &cbret, &(ov));
                if (!bret) {
                    GETERRNO(ret);
                    if (ret != -ERROR_IO_PENDING && ret != -ERROR_BROKEN_PIPE) {
                        ERROR_INFO("read [%s] [%zu] error[%d]", pipename, inlen, ret);
                        goto out;
                    }

                    if (ret == -ERROR_BROKEN_PIPE) {
                        state = PIPE_READY;
                        break;
                    }
                    state = PIPE_WAIT_READ;
                } else {
                    inlen += cbret;
                    if (inlen > insize) {
                        ERROR_INFO("cbret [%d] inlen[%zu] insize[%zu]", cbret, inlen, insize);
                        inlen = insize;
                    }
                }
            }
        }
    }

    if (wr == 0) {
        fprintf(stdout, "read [%s] --------------------\n", pipename);
        __debug_buf(stdout, pinbuf, (int)inlen);
        fprintf(stdout, "read [%s] ++++++++++++++++++++\n", pipename);
    }
    ret = 0;
out:

    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    if (pinbuf != NULL) {
        free(pinbuf);
    }
    pinbuf = NULL;
    insize = 0;

    read_file_whole(NULL, &poutbuf, (int*)&outsize);
    __create_pipe_2(NULL, 0, &svrpipe, &ov, &evt, &state);
    snprintf_safe(&tmppipe, &tmppipesize, NULL);
    __get_temp_pipe_name_2(NULL, &pipebasename, &pipebasesize);
    SETERRNO(ret);
    return ret;
}

int __connect_pipe_2(char* name, int wr, HANDLE* pcli)
{
    int ret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    HANDLE phd = NULL;
    BOOL bret;
    DWORD omode;

    if (name == NULL) {
        if (pcli) {
            if (*pcli != NULL &&
                    *pcli != INVALID_HANDLE_VALUE) {
                bret = CloseHandle(*pcli);
                if (!bret) {
                    GETERRNO(ret);
                    ERROR_INFO("close handle error[%d]", ret);
                }
            }
            *pcli = NULL;
        }
        return 0;
    }

    if (pcli == NULL || (*pcli != NULL && *pcli != INVALID_HANDLE_VALUE )) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (wr) {
        omode = GENERIC_WRITE;
    } else {
        omode = GENERIC_READ;
    }

    phd = CreateFile(ptname, omode, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (phd == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("open file [%s] error[%d]", name, ret);
        goto fail;
    }

    *pcli = phd;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    if (phd != NULL) {
        CloseHandle(phd);
    }
    phd = NULL;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return ret;
}

int clilap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* pipename = NULL;
    HANDLE hd = INVALID_HANDLE_VALUE;
    int wr = 0;
    DWORD cbret;
    char* poutbuf = NULL;
    int outsize = 0;
    int outlen = 0;
    char* pinbuf = NULL;
    char* ptmpbuf = NULL;
    int insize = 1024;
    int inlen = 0;
    BOOL bret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("no pipe name");
        goto out;
    }

    pipename = parsestate->leftargs[0];
    wr = 0;
    if (pargs->m_input != NULL) {
        wr = 1;
        ret = read_file_whole(pargs->m_input, &poutbuf, &outsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("read file [%s] error[%d]", pargs->m_input, ret);
            goto out;
        }
    }

    ret = __connect_pipe_2(pipename, wr, &(hd));
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("client [%s] for %s error[%d]", pipename, wr ? "write" : "read", ret);
        goto out;
    }

    if (wr) {
        while (outlen < outsize) {
            bret = WriteFile(hd, &(poutbuf[outlen]), (DWORD)(outsize - outlen), &cbret, NULL);
            if (!bret) {
                GETERRNO(ret);
                if (ret != -ERROR_IO_PENDING) {
                    ERROR_INFO("write [%s] [%d] error[%d]", pipename, outlen, ret);
                    goto out;
                }
                continue;
            }
            outlen += cbret;
        }
    } else {
        pinbuf = (char*) malloc((size_t)insize);
        if (pinbuf == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", insize, ret);
            goto out;
        }
        while (1) {
            bret = ReadFile(hd, &(pinbuf[inlen]), (DWORD)(insize - inlen), &cbret, NULL);
            if (!bret) {
                GETERRNO(ret);
                if (ret != -ERROR_IO_PENDING && ret != -ERROR_BROKEN_PIPE) {
                    ERROR_INFO("read [%s] [%d] error[%d]", pipename, inlen, ret);
                    goto out;
                }
                if (ret == -ERROR_BROKEN_PIPE) {
                    break;
                }
                continue;
            }
            inlen += cbret;
            if (inlen >= insize) {
                inlen = insize;
                insize <<= 2;
                ptmpbuf = (char*) malloc((size_t)insize);
                if (ptmpbuf == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", insize, ret);
                    goto out;
                }
                memset(ptmpbuf, 0, (size_t)insize);
                if (inlen > 0) {
                    memcpy(ptmpbuf, pinbuf, (size_t)inlen);
                }
                if (pinbuf) {
                    free(pinbuf);
                }
                pinbuf = ptmpbuf;
                ptmpbuf = NULL;
            }
        }

        fprintf(stdout, "read [%s] ------------------------\n", pipename);
        __debug_buf(stdout, pinbuf, inlen);
        fprintf(stdout, "read [%s] ++++++++++++++++++++++++\n", pipename);
    }

    ret = 0;
out:
    read_file_whole(NULL, &poutbuf, &outsize);
    if (pinbuf != NULL) {
        free(pinbuf);
    }
    pinbuf = NULL;
    insize = 0;
    inlen = 0;
    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    __connect_pipe_2(NULL, 0, &hd);
    SETERRNO(ret);
    return ret;
}

int runevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pout = NULL;
    int outsize = 0;
    char* perr = NULL;
    int errsize = 0;
    int exitcode = 0;
    BOOL bret;
    int res;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    parsestate = parsestate;
    init_log_level(pargs);

    st_ExitEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_ExitEvt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create exit event %d\n", ret);
        goto out;
    }
    bret = SetConsoleCtrlHandler(HandlerConsoleRoutine, TRUE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
        goto out;
    }


    ret = run_cmd_event_output(st_ExitEvt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, "libtest.exe", "outc", "little", "big", NULL);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    if (exitcode != 0) {
        GETERRNO(ret);
        ERROR_INFO("exitcode %d", ret);
        goto out;
    }

    fprintf(stdout, "read stdout------------\n");
    fprintf(stdout, "%s", pout);
    fprintf(stdout, "++++++++++++++++++++++++++\n");
    fprintf(stdout, "read stderr------------\n");
    fprintf(stdout, "%s", perr);
    fprintf(stdout, "++++++++++++++++++++++++++\n");

    ret = 0;
out:
    if (st_ExitEvt != NULL && st_ExitEvt != INVALID_HANDLE_VALUE) {
        bret = CloseHandle(st_ExitEvt);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("can not close[%p] error[%d]", st_ExitEvt, res);
        }
    }
    st_ExitEvt = NULL;
    run_cmd_event_output(st_ExitEvt, NULL, 0, &pout, &outsize, &perr, &errsize, NULL, 0, NULL);
    SETERRNO(ret);
    return ret;
}

int runvevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int i;
    int ret;
    char** ppoutbuf = NULL;
    int *poutsize = NULL;
    char** pperrbuf = NULL;
    int *perrsize = NULL;
    BOOL bret;
    int res;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    st_ExitEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_ExitEvt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create exit event %d\n", ret);
        goto out;
    }
    bret = SetConsoleCtrlHandler(HandlerConsoleRoutine, TRUE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
        goto out;
    }


    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_whole(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        insize = ret;
    }

    if (pargs->m_output != NULL) {
        ppoutbuf = &outbuf;
        poutsize = &outsize;
    }

    if (pargs->m_errout != NULL) {
        pperrbuf = &errbuf;
        perrsize = &errsize;
    }

    ret = run_cmd_event_outputv(st_ExitEvt, inbuf, insize, ppoutbuf, poutsize, pperrbuf, perrsize, &exitcode, pargs->m_timeout, parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run cmd [");
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", parsestate->leftargs[i]);
        }
        fprintf(stderr, "] error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "run cmd [");
    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        if (i > 0) {
            fprintf(stdout, ",");
        }
        fprintf(stdout, "%s", parsestate->leftargs[i]);
    }
    fprintf(stdout, "] succ\n");
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input --------------------\n");
        __debug_buf(stdout, inbuf, insize);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        __debug_buf(stdout, outbuf, outsize);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        __debug_buf(stdout, errbuf, errsize);
        fprintf(stdout, "errout ++++++++++++++++++++\n");
    }

    ret = 0;
out:
    if (st_ExitEvt != NULL && st_ExitEvt != INVALID_HANDLE_VALUE) {
        bret = CloseHandle(st_ExitEvt);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("can not close[%p] error[%d]", st_ExitEvt, res);
        }
    }
    st_ExitEvt = NULL;
    run_cmd_event_outputv(st_ExitEvt, NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_whole(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}

int runsevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int ret;
    char** ppoutbuf = NULL;
    int *poutsize = NULL;
    char** pperrbuf = NULL;
    int *perrsize = NULL;
    BOOL bret;
    int res;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    st_ExitEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_ExitEvt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create exit event %d\n", ret);
        goto out;
    }
    bret = SetConsoleCtrlHandler(HandlerConsoleRoutine, TRUE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
        goto out;
    }

    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_whole(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        insize = ret;
    }

    if (pargs->m_output != NULL) {
        ppoutbuf = &outbuf;
        poutsize = &outsize;
    }

    if (pargs->m_errout != NULL) {
        pperrbuf = &errbuf;
        perrsize = &errsize;
    }

    ret = run_cmd_event_output_single(st_ExitEvt, inbuf, insize, ppoutbuf, poutsize, pperrbuf, perrsize, &exitcode, pargs->m_timeout, parsestate->leftargs[0]);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run single cmd [%s] error[%d]\n", parsestate->leftargs[0], ret);
        goto out;
    }

    fprintf(stdout, "run cmd [%s] succ\n", parsestate->leftargs[0]);
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input --------------------\n");
        __debug_buf(stdout, inbuf, insize);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        __debug_buf(stdout, outbuf, outsize);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        __debug_buf(stdout, errbuf, errsize);
        fprintf(stdout, "errout ++++++++++++++++++++\n");
    }

    ret = 0;
out:
    if (st_ExitEvt != NULL && st_ExitEvt != INVALID_HANDLE_VALUE) {
        bret = CloseHandle(st_ExitEvt);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("can not close[%p] error[%d]", st_ExitEvt, res);
        }
    }
    st_ExitEvt = NULL;
    run_cmd_event_output_single(st_ExitEvt, NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_whole(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}
