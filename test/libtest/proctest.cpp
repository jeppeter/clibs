
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
    void* pstdout = NULL, *pstderr = NULL;
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

    pstdout = open_file(pargs->m_output, READ_MODE);
    pstderr = open_file(pargs->m_errout, READ_MODE);
    if (pstdout != NULL || pstderr != NULL) {
        if (pstdout != NULL) {
            close_file(&pstdout);
            pstdout = open_file(pargs->m_output, WRITE_MODE);
            if (pstdout == NULL) {
                GETERRNO(ret);
                goto out;
            }
            ret = write_file(pstdout, 0, outbuf, (uint32_t)outsize);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            close_file(&pstdout);
        }


        if (pstderr != NULL) {
            close_file(&pstderr);
            pstderr = open_file(pargs->m_errout, WRITE_MODE);
            if (pstderr == NULL) {
                GETERRNO(ret);
                goto out;
            }

            ret = write_file(pstderr, 0, errbuf, (uint32_t)errsize);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            close_file(&pstderr);
        }
    } else {
        fprintf(stdout, "run cmd [");
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            if (i > 0) {
                fprintf(stdout, ",");
            }
            fprintf(stdout, "%s", parsestate->leftargs[i]);
        }
        fprintf(stdout, "] succ [%d]\n", exitcode);
        if (pargs->m_input != NULL) {
            fprintf(stdout, "input --------------------\n");
            debug_buffer(stdout, inbuf, insize,NULL);
            fprintf(stdout, "input ++++++++++++++++++++\n");
        }

        if (pargs->m_output != NULL) {
            fprintf(stdout, "output --------------------\n");
            debug_buffer(stdout, outbuf, outsize,NULL);
            fprintf(stdout, "output ++++++++++++++++++++\n");
        }

        if (pargs->m_errout != NULL) {
            fprintf(stdout, "errout --------------------\n");
            debug_buffer(stdout, errbuf, errsize,NULL);
            fprintf(stdout, "errout ++++++++++++++++++++\n");
        }
    }

    ret = 0;
out:
    close_file(&pstdout);
    close_file(&pstderr);
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
        debug_buffer(stdout, inbuf, insize,NULL);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        debug_buffer(stdout, outbuf, outsize,NULL);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        debug_buffer(stdout, errbuf, errsize,NULL);
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
        debug_buffer(stdout, pinbuf, (int)inlen,NULL);
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
        debug_buffer(stdout, pinbuf, inlen,NULL);
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
        debug_buffer(stdout, inbuf, insize,NULL);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        debug_buffer(stdout, outbuf, outsize,NULL);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        debug_buffer(stdout, errbuf, errsize,NULL);
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
        debug_buffer(stdout, inbuf, insize,NULL);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        debug_buffer(stdout, outbuf, outsize,NULL);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        debug_buffer(stdout, errbuf, errsize,NULL);
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

int startdetach_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char** progv = NULL;
    int createflags = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    progv = parsestate->leftargs;
    ret = start_cmdv_detach(createflags, progv);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not start");
        if (parsestate->leftargs) {
            for (i = 0; parsestate->leftargs[i] != NULL; i++) {
                if (i > 0) {
                    fprintf(stderr, " ");
                }
                fprintf(stderr, "[%s]", parsestate->leftargs[i]);
            }
        }
        fprintf(stderr, " error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "start ");
    if (parsestate->leftargs) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            if (i > 0) {
                fprintf(stdout, " ");
            }
            fprintf(stdout, "[%s]", parsestate->leftargs[i]);
        }
    }
    fprintf(stdout, " pid[%d]\n", ret);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int getpidsname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    DWORD *ppids = NULL;
    int size = 0, cnt;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    char* procname;
    int j;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        procname = parsestate->leftargs[i];
        ret = get_pids_by_name(procname, &ppids, &size);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not get [%s] error[%d]\n", procname, ret);
            goto out;
        }
        cnt = ret;
        fprintf(stdout, "find [%s] count[%d]", procname, cnt);
        for (j = 0; j < cnt; j++) {
            if ((j % 5) == 0) {
                fprintf(stdout, "\n%d ", j);
            }
            fprintf(stdout, " %d", (int)ppids[j]);
        }
        fprintf(stdout, "\n");
    }

    ret = 0;
out:
    get_pids_by_name(NULL, &ppids, &size);
    SETERRNO(ret);
    return ret;
}

int sessrunv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int retpid = -1;
    int num;
    DWORD sessid = 0;
    int cnt = 0;
    char** progv = NULL;
    int i;
    int idx = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        cnt ++;
    }

    if (cnt < 2) {
        ret =  -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "need session progv...\n");
        goto out;
    }

    num = 0;
    GET_OPT_INT(num, "session id");
    sessid = (DWORD)num;
    progv = &(parsestate->leftargs[1]);

    ret = start_cmdv_session_detach(sessid, progv);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not start [");
        for (i = 1; i < cnt; i++) {
            if (i > 1) {
                fprintf(stderr, " ");
            }
            fprintf(stderr, "%s", parsestate->leftargs[i]);
        }
        fprintf(stderr, "] on session[%d] error[%d]\n", (int)sessid, ret);
        goto out;
    }
    retpid = ret;

    fprintf(stdout, "run [");
    for (i = 1; i < cnt; i++) {
        if (i > 1) {
            fprintf(stdout, " ");
        }
        fprintf(stdout, "%s", parsestate->leftargs[i]);
    }
    fprintf(stdout, "] on session[%d] [%d]succ\n", (int)sessid, retpid);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int __send_svr_pipe(uint32_t cmd, pextargs_state_t parsestate, pargs_options_t pargs)
{
    char* pipename = NULL;
    HANDLE hpipe = NULL;
    OVERLAPPED *prdov = NULL, *pwrov = NULL;
    size_t totallen = 0;
    pipe_hdr_t *phdr = NULL;
    int ret;
    BOOL bret;
    int i;
    char* pcurptr = NULL;
    size_t curlen;


    pipename = pargs->m_pipename;
    if (pipename == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "no pipename\n");
        goto out;
    }

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

    ret = connect_pipe(pipename, st_ExitEvt, &hpipe, &prdov, &pwrov);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not connect pipe [%s] error[%d]\n", pipename, ret);
        goto out;
    }

    /*now format the buffer*/
    totallen = 0;
    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i] != NULL ; i++) {
        totallen += (strlen(parsestate->leftargs[i]) + 1);
    }

    if (totallen > 0) {
        totallen ++;
        totallen += sizeof(*phdr);
    }

    if (totallen == 0) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "can not accept zero command\n");
        goto out;
    }

    phdr = (pipe_hdr_t*)malloc(totallen);
    if (phdr == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(phdr, 0, totallen);
    phdr->m_datalen = (uint32_t)totallen;
    phdr->m_cmd = cmd;

    pcurptr = (char*) phdr;
    pcurptr += sizeof(*phdr);

    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i]; i++) {
        curlen = strlen(parsestate->leftargs[i]);
        memcpy(pcurptr, parsestate->leftargs[i], curlen);
        pcurptr += (curlen + 1);
    }
    DEBUG_BUFFER_FMT(phdr, (int)totallen, "buffer write");

    ret = write_pipe_data(st_ExitEvt, hpipe, pwrov, pargs->m_timeout, (char*)phdr, (int)totallen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] with len [%zd] error[%d]\n", pipename, totallen, ret);
        goto out;
    }

    DEBUG_INFO("Sleep before");
    if (pargs->m_timeout != 0) {
        SleepEx((DWORD)pargs->m_timeout, TRUE);
    } else {
        SleepEx(1000, TRUE);
    }

    DEBUG_INFO("Sleep after");

    ret = 0;
out:
    if (st_ExitEvt) {
        CloseHandle(st_ExitEvt);
    }
    st_ExitEvt = NULL;

    if (phdr) {
        free(phdr);
    }
    phdr = NULL;
    connect_pipe(NULL, NULL, &hpipe, &prdov, &pwrov);
    SETERRNO(ret);
    return ret;
}

int svrcmd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(EXECUTE_COMMAND, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int svrnetmount_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(NETSHARE_MOUNT, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrcreatememmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(MAP_MEM_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrunmapmemmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(UNMAP_MEM_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}



int chgpass_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* user, *oldpass, *newpass;
    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    user = parsestate->leftargs[0];
    oldpass = parsestate->leftargs[1];
    newpass = parsestate->leftargs[2];
    ret = user_change_password(user, oldpass, newpass);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not change [%s] pass [%s] => [%s] error[%d]\n", user, oldpass, newpass, ret);
        goto out;
    }

    fprintf(stdout, "change [%s] pass[%s] => [%s] succ\n", user, oldpass, newpass);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int svrchgpass_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(CHG_USER_PASS, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

#define  MAX_WAIT_NUM   3

int npsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* pipename = NULL;
    pipe_svr_comm* pcomm = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    HANDLE waithds[MAX_WAIT_NUM];
    DWORD waitnum = 0;
    jvalue* pj=NULL;
    char* pjstr =NULL;
    unsigned int jsize=0;
    int ret;
    DWORD dret;
    HANDLE curhd;

    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);

    pipename = pargs->m_pipename;

    st_ExitEvt = set_ctrlc_handle();
    if (st_ExitEvt == NULL) {
        GETERRNO(ret);
        goto out;
    }

try_again:
    if (pcomm) {
        DEBUG_INFO("delete pcomm");
        delete pcomm;
    }
    pcomm = NULL;

    if (pjstr) {
        free(pjstr);
    }
    pjstr = NULL;
    jsize = 0;
    if (pj) {
        jvalue_destroy(pj);
    }
    pj = NULL;

    pcomm = new pipe_svr_comm(pipename);
    ret = pcomm->init();
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }


    DEBUG_INFO("bind [%s]", pipename);


    DEBUG_INFO("client connect[%s]", pipename);


    while(1) {
        waitnum = 0;
        waithds[waitnum] = st_ExitEvt;
        waitnum += 1;
        if (pcomm->is_accept_mode()) {
            waithds[waitnum] = pcomm->get_accept_evt();
            waitnum += 1;
        } else {
        set_read:
            if (pcomm->is_read_mode()) {
                waithds[waitnum] = pcomm->get_read_evt();
                waitnum += 1;
            } else {
            read_again:
                ASSERT_IF(pj == NULL);
                ret = pcomm->read_json(&pj);
                if (ret <0) {
                    GETERRNO(ret);
                    ERROR_INFO("read_json [%s] error[%d]",pipename,ret);
                    goto try_again;
                } else if (ret > 0) {
                    ASSERT_IF(pjstr == NULL);
                    pjstr = jvalue_write_pretty(pj,&jsize);
                    if (pjstr == NULL) {
                        GETERRNO(ret);
                        goto out;
                    }
                    DEBUG_INFO("read\n%s",pjstr);
                    free(pjstr);
                    pjstr = NULL;
                    jsize = 0;

                    ret = pcomm->write_json(pj);
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto try_again;
                    }
                    jvalue_destroy(pj);
                    pj = NULL;
                    goto read_again;
                }
                goto set_read;
            }

            if (pcomm->is_write_mode()) {
                waithds[waitnum] = pcomm->get_write_evt();
                waitnum += 1;
            }
        }

        dret = WaitForMultipleObjectsEx(waitnum,waithds,FALSE,10000,TRUE);
        if (dret < (WAIT_OBJECT_0 + waitnum)) {
            curhd = waithds[(dret - WAIT_OBJECT_0)];
            if (curhd == st_ExitEvt) {
                ERROR_INFO("break");
                break;
            } else if (curhd == pcomm->get_read_evt()) {
                ret = pcomm->complete_read();
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("complete_read error %d",ret);
                    goto try_again;
                }
            } else if (curhd == pcomm->get_accept_evt()) {
                ret = pcomm->complete_accept();
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("complete_accept error %d",ret);
                    goto try_again;
                } else if (ret > 0) {
                    DEBUG_INFO("accept [%s]", pipename);
                }
            } else if (curhd == pcomm->get_write_evt()) {
                ret = pcomm->complete_write();
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("complete_write error %d",ret);
                    goto try_again;
                }                
            }
        } else if (dret != WAIT_TIMEOUT) {
            ERROR_INFO("dret %d",dret);
            goto try_again;
        }
    }

    ret = 0;
out:
    if (pj) {
        jvalue_destroy(pj);
    }
    pj = NULL;

    if (pjstr) {
        free(pjstr);
    }
    pjstr = NULL;
    if (pcomm) {
        delete pcomm;
    }
    pcomm = NULL;
    SETERRNO(ret);
    return ret;
}

int npsvr2_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* pipename = NULL;
    int ret;
    int argcnt = 0;
    char** filecon = NULL;
    int* filelen = NULL;
    int i;
    char** fnames = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    BOOL bret;
    void* pnp = NULL;
    int curidx;
    uint32_t rcvlen = 0;
    uint32_t needlen = 0;
    uint32_t wholelen = 0;
    char* preadbuf = NULL;
    char* ptmpreadbuf = NULL;
    uint32_t rcvsize = 0;
    std::vector<char*> wbufs;
    std::vector<int> wlens;
    char* pwritebuf = NULL;
    int writelen = 0;
    char* pcurwrite = NULL;
    int curwritelen = 0;
    HANDLE curhd;
    HANDLE waithds[MAX_WAIT_NUM];
    DWORD dret;
    DWORD waitnum = 0;
    int filesize = 0;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);
    pipename = pargs->m_pipename;

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        argcnt ++;
    }


    if (argcnt > 0) {
        fnames = parsestate->leftargs;
        filecon = (char**) malloc(sizeof(*filecon) * argcnt);
        if (filecon == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not alloc [%zu] error[%d]", sizeof(*filecon) * argcnt, ret);
            goto out;
        }
        memset(filecon, 0, sizeof(*filecon) * argcnt);

        filelen = (int*) malloc(sizeof(*filelen) * argcnt);
        if (filelen == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not alloc [%zu] error[%d]", sizeof(*filelen) * argcnt, ret);
            goto out;
        }
        memset(filelen, 0, sizeof(*filelen) * argcnt);

        for (i = 0; i < argcnt; i++) {
            filesize = 0;
            ret = read_file_whole(fnames[i], &(filecon[i]), &filesize);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("[%d].[%s] read error[%d]", i, fnames[i], ret);
                goto out;
            }
            filelen[i] = ret;
        }
    }

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



try_again:
    close_namedpipe(&pnp);
    if (ptmpreadbuf) {
        free(ptmpreadbuf);
    }
    ptmpreadbuf = NULL;
    if (preadbuf) {
        free(preadbuf);
    }
    preadbuf = NULL;


    if (pcurwrite) {
        free(pcurwrite);
    }
    pcurwrite = NULL;
    curwritelen = 0;
    if (pwritebuf) {
        free(pwritebuf);
    }
    pwritebuf = NULL;
    writelen = 0;
    while (wbufs.size() > 0) {
        ASSERT_IF(wbufs.size() == wlens.size());
        pcurwrite = wbufs.at(0);
        wbufs.erase(wbufs.begin());
        if (pcurwrite) {
            free(pcurwrite);
        }
        pcurwrite = NULL;
        curwritelen = wlens.at(0);
        wlens.erase(wlens.begin());
    }

    pnp = bind_namedpipe(pipename);
    if (pnp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("bind [%s] error[%d]", pipename, ret);
        goto out;
    }

    DEBUG_INFO("bind [%s]", pipename);

    if (get_namedpipe_connstate(pnp) > 0) {
        while (1) {
            waitnum = 0;
            waithds[waitnum] = st_ExitEvt;
            waitnum ++;
            waithds[waitnum] = get_namedpipe_connevt(pnp);
            waitnum ++;

            dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, INFINITE, FALSE);
            if ((dret < (WAIT_OBJECT_0 + waitnum))) {
                curhd = waithds[(dret - WAIT_OBJECT_0)];
                if (curhd == st_ExitEvt) {
                    ret = 0;
                    goto out;
                } else if (curhd == get_namedpipe_connevt(pnp)) {
                    ret = complete_namedpipe_connpending(pnp);
                    if (ret < 0) {
                        GETERRNO(ret);
                        ERROR_INFO("wait connect[%s] error[%d]", pipename, ret);
                        goto try_again;
                    }
                    if (ret > 0) {
                        break;
                    }
                }
            } else {
                ERROR_INFO("wait connect[%s] error[%d]", pipename, dret);
                goto try_again;
            }
        }
    }

    DEBUG_INFO("client connect[%s]", pipename);

    curidx = 0;
    rcvlen = 0;
    needlen = sizeof(uint32_t);
    rcvsize = 256;
    preadbuf = (char*)malloc((size_t)rcvsize);
    if (preadbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not alloc [%d] error[%d]\n", rcvsize, ret );
        goto out;
    }

    while (1) {
        waitnum = 0;
        memset(waithds, 0, sizeof(waithds));
        ASSERT_IF(waitnum < MAX_WAIT_NUM);
        waithds[waitnum] = st_ExitEvt;
        waitnum ++;
        if (get_namedpipe_rdstate(pnp) == 0) {
read_again:
            ret = read_namedpipe(pnp, &(preadbuf[rcvlen]), (int)(needlen - rcvlen));
            if (ret < 0) {
                ERROR_INFO("read [%s] error[%d]", pipename, ret);
                goto try_again;
            } else if (ret > 0) {
                rcvlen = needlen;    
            }
            
            if (get_namedpipe_rdstate(pnp) == 0) {
                ASSERT_IF(rcvlen == needlen);
                if (needlen == sizeof(uint32_t)) {
                    memcpy(&wholelen, &(preadbuf[0]), sizeof(uint32_t));
                    needlen = wholelen;
                    if (needlen > rcvsize) {
                        rcvsize = needlen;
                        ptmpreadbuf = (char*)malloc(rcvsize);
                        if (ptmpreadbuf == NULL) {
                            GETERRNO(ret);
                            fprintf(stderr, "cannot alloc [%d] error[%d]\n", rcvsize , ret);
                            goto out;
                        }
                        if (rcvlen > 0) {
                            memcpy(ptmpreadbuf, preadbuf, rcvlen);
                        }
                        if (preadbuf) {
                            free(preadbuf);
                        }
                        preadbuf = ptmpreadbuf;
                        ptmpreadbuf = NULL;
                    }
                    if (needlen == sizeof(uint32_t)) {
                        goto reply_read;
                    }

                    ret = read_namedpipe(pnp, &(preadbuf[rcvlen]), (int)(needlen - rcvlen));
                    if (ret < 0) {
                        GETERRNO(ret);
                        ERROR_INFO("read [%s] error[%d]", pipename, ret);
                        goto try_again;
                    } else if (ret > 0) {
                        rcvlen = needlen;
                        goto reply_read;
                    }

                    ASSERT_IF(waitnum < MAX_WAIT_NUM);
                    waithds[waitnum] = get_namedpipe_rdevt(pnp);
                    waitnum ++;
                } else if (needlen > sizeof(uint32_t)) {
                    rcvlen = needlen;
reply_read:
                    DEBUG_BUFFER_FMT(preadbuf,
                                     (int)needlen,
                                     "read packet [%d]",
                                     curidx);
                    if (curidx >= argcnt) {
                        curidx = 0;
                    }
                    if (curidx >= argcnt) {
                        writelen = (int)needlen;
                    } else {
                        writelen = (int)(sizeof(uint32_t) + filelen[curidx]);
                    }
                    pwritebuf = (char*)malloc((size_t)writelen);
                    if (pwritebuf == NULL) {
                        GETERRNO(ret);
                        fprintf(stderr, "alloc %d error[%d]\n", writelen, ret);
                        goto out;
                    }
                    if (curidx >= argcnt) {
                        memcpy(pwritebuf, preadbuf, needlen);
                    } else {
                        memcpy(pwritebuf, &writelen, sizeof(uint32_t));
                        memcpy(&(pwritebuf[sizeof(uint32_t)]),
                               filecon[curidx],
                               (size_t)filelen[curidx]);
                    }
                    if (pcurwrite == NULL) {
                        pcurwrite = pwritebuf;
                        curwritelen = writelen;
                        pwritebuf = NULL;
                        writelen = 0;
                        ret = write_namedpipe(pnp, pcurwrite, curwritelen);
                        if (ret < 0) {
                            fprintf(stderr, "can not write [%s] error[%d]\n", pipename, ret);
                            goto try_again;
                        } else if (ret > 0) {                            
                            free(pcurwrite);
                            pcurwrite = NULL;
                            curwritelen = 0;
                        }
                    } else {
                        wbufs.push_back(pwritebuf);
                        wlens.push_back(writelen);
                        pwritebuf = NULL;
                        writelen = 0;
                    }
                    curidx ++;
                    needlen = sizeof(uint32_t);
                    rcvlen = 0;
                    goto read_again;
                }
            } else {
                ASSERT_IF(waitnum < MAX_WAIT_NUM);
                waithds[waitnum] = get_namedpipe_rdevt(pnp);
                waitnum ++;
            }
        } else {
            ASSERT_IF(waitnum < MAX_WAIT_NUM);
            waithds[waitnum] = get_namedpipe_rdevt(pnp);
            waitnum ++;
        }

        if (get_namedpipe_wrstate(pnp) == 0) {
write_again:
            if (pcurwrite != NULL) {
                free(pcurwrite);
            }
            pcurwrite = NULL;
            curwritelen = 0;
            if (wbufs.size() > 0) {
                pcurwrite = wbufs.at(0);
                wbufs.erase(wbufs.begin());
                curwritelen = wlens.at(0);
                wlens.erase(wlens.begin());
                ret = write_namedpipe(pnp, pcurwrite, curwritelen);
                if (ret < 0) {
                    GETERRNO(ret);
                    fprintf(stderr, "write [%s] error[%d]\n", pipename, ret);
                    goto try_again;
                } else if (ret > 0) {
                    goto write_again;
                }
                ASSERT_IF(waitnum < MAX_WAIT_NUM);
                waithds[waitnum] = get_namedpipe_wrevt(pnp);
                waitnum ++;
            }
        } else {
            ASSERT_IF(waitnum < MAX_WAIT_NUM);
            waithds[waitnum] = get_namedpipe_wrevt(pnp);
            waitnum ++;
        }

        dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, INFINITE, FALSE);
        if (dret < (WAIT_OBJECT_0 + waitnum)) {
            curhd = waithds[(dret - WAIT_OBJECT_0)];
            if (curhd == st_ExitEvt) {
                break;
            } else if (curhd == get_namedpipe_rdevt(pnp)) {
                ret = complete_namedpipe_rdpending(pnp);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not complete [%s]", pipename);
                    goto try_again;
                } else if (ret > 0) {
                    if (needlen == sizeof(uint32_t)) {
                        rcvlen = needlen;
                        memcpy(&needlen, preadbuf, sizeof(uint32_t));
                        if (needlen > rcvsize) {
                            rcvsize = needlen;
                            ASSERT_IF(ptmpreadbuf == NULL);
                            ptmpreadbuf = (char*)malloc(rcvsize);
                            if (ptmpreadbuf == NULL) {
                                GETERRNO(ret);
                                ERROR_INFO("can not alloc [%d] error[%d]", rcvsize , ret);
                                goto out;
                            }
                            if (rcvlen > 0) {
                                memcpy(ptmpreadbuf, preadbuf, rcvlen);
                            }
                            if (preadbuf) {
                                free(preadbuf);
                            }
                            preadbuf = ptmpreadbuf;
                            ptmpreadbuf = NULL;
                        }

                        if (needlen == sizeof(uint32_t)) {
                            goto wait_write;
                        }
                    } else if (needlen > sizeof(uint32_t)) {
wait_write:
                        DEBUG_BUFFER_FMT(preadbuf, (int)needlen, "[%d] packet" , curidx);
                        if (curidx >= argcnt) {
                            curidx = 0;
                        }

                        if (curidx >= argcnt) {
                            writelen = (int)needlen;
                        } else {
                            writelen = (int)(sizeof(uint32_t) + filelen[curidx]);
                        }

                        pwritebuf = (char*) malloc((size_t)writelen);
                        if (pwritebuf == NULL) {
                            GETERRNO(ret);
                            ERROR_INFO("alloc [%d] error[%d]", writelen, ret);
                            goto out;
                        }

                        if (curidx >= argcnt) {
                            memcpy(pwritebuf, preadbuf, (size_t)writelen);
                        } else {
                            memcpy(pwritebuf, &writelen, sizeof(uint32_t));
                            memcpy(&(pwritebuf[sizeof(uint32_t)]), filecon[curidx], (size_t)filelen[curidx]);
                        }

                        if (pcurwrite == NULL) {
                            pcurwrite = pwritebuf;
                            curwritelen = writelen;
                            pwritebuf = NULL;
                            writelen = 0;
                            ret = write_namedpipe(pnp, pcurwrite, curwritelen);
                            if (ret < 0) {
                                GETERRNO(ret);
                                ERROR_INFO("write [%s] error[%d]", pipename, ret);
                                goto try_again;
                            }
                            if (get_namedpipe_wrstate(pnp) == 0) {
                                free(pcurwrite);
                                curwritelen = 0;
                            }
                        } else {
                            wbufs.push_back(pwritebuf);
                            wlens.push_back(writelen);
                            pwritebuf = NULL;
                            writelen = 0;
                        }
                        curidx ++;
                    }
                }
            } else if (curhd == get_namedpipe_wrevt(pnp)) {
                ret = complete_namedpipe_wrpending(pnp);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not complete [%s]", pipename);
                    goto try_again;
                }
            }
        } else if (dret == WAIT_TIMEOUT) {
            continue;
        } else {
            ERROR_INFO("dret [%ld] error", dret);
            goto try_again;
        }
    }

    ret = 0;
out:
    close_namedpipe(&pnp);
    if (ptmpreadbuf) {
        free(ptmpreadbuf);
    }
    ptmpreadbuf = NULL;
    if (preadbuf) {
        free(preadbuf);
    }
    preadbuf = NULL;


    if (pcurwrite) {
        free(pcurwrite);
    }
    pcurwrite = NULL;
    curwritelen = 0;
    if (pwritebuf) {
        free(pwritebuf);
    }
    pwritebuf = NULL;
    writelen = 0;
    while (wbufs.size() > 0) {
        ASSERT_IF(wbufs.size() == wlens.size());
        pcurwrite = wbufs.at(0);
        wbufs.erase(wbufs.begin());
        if (pcurwrite) {
            free(pcurwrite);
        }
        pcurwrite = NULL;
        curwritelen = wlens.at(0);
        wlens.erase(wlens.begin());
    }

    ASSERT_IF(wbufs.size() == 0);
    ASSERT_IF(wlens.size() == 0);

    if (filecon != NULL && filelen != NULL) {
        for (i = 0; i < argcnt ; i++) {
            read_file_whole(NULL, &(filecon[i]), &(filelen[i]));
        }
    }

    if (filecon) {
        free(filecon);
    }
    filecon = NULL;

    if (filelen) {
        free(filelen);
    }
    filelen = NULL;
    argcnt = 0;
    SETERRNO(ret);
    return ret;
}

int npcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pipe_cli_comm* pcomm = NULL;
    jvalue* pj=NULL;
    jvalue* inpj =NULL;
    char* pipename = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int curidx =0;
    int argcnt = 0;
    int readcnt = 0;
    HANDLE waithds[3];
    DWORD waitnum;
    char* fname;
    char* pbuf=NULL;
    int buflen=0,bufsize=0;
    int ret;
    char* pjstr=NULL;
    unsigned int jsize=0;
    DWORD dret;
    HANDLE curhd;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    pipename = pargs->m_pipename;

    while(1) {
        if (parsestate->leftargs == NULL || parsestate->leftargs[argcnt] == NULL) {
            break;
        }
        argcnt += 1;
    }

    pcomm = new pipe_cli_comm(pipename,0);
    ret=  pcomm->init();
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    st_ExitEvt = set_ctrlc_handle();
    if (st_ExitEvt == NULL) {
        GETERRNO(ret);
        goto out;
    }

    while(1) {
        waitnum = 0;
        waithds[waitnum] = st_ExitEvt;
        waitnum += 1;
    set_read:
        if (pcomm->is_read_mode()) {
            waithds[waitnum] = pcomm->get_read_evt();
            waitnum += 1;
        } else {
        read_again:
            ASSERT_IF(inpj == NULL);
            ret = pcomm->read_json(&inpj);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            } else if (ret > 0) {
                ASSERT_IF(pjstr == NULL);
                pjstr = jvalue_write_pretty(inpj,&jsize);
                if (pjstr == NULL) {
                    GETERRNO(ret);
                    goto out;
                }
                DEBUG_INFO("read\n%s",pjstr);
                free(pjstr);
                pjstr = NULL;
                jvalue_destroy(inpj);
                inpj = NULL;
                readcnt += 1;
                if (readcnt == argcnt) {
                    DEBUG_INFO("all over");
                    break;
                }
                goto read_again;
            }
            goto set_read;
        }

        if (pcomm->is_write_mode()) {
            waithds[waitnum] = pcomm->get_write_evt();
            waitnum += 1;
        } else {
            while (curidx < argcnt) {
                fname = parsestate->leftargs[curidx];
                ret = read_file_whole(fname,&pbuf,&bufsize);
                if (ret <0){
                    GETERRNO(ret);
                    goto out;
                }
                buflen = ret; 
                if (buflen < bufsize) {
                    pbuf[buflen] = '\0';
                }
                pj = jvalue_read(pbuf,&jsize);
                if (pj == NULL) {
                    GETERRNO(ret);
                    goto out;
                }

                ret = pcomm->write_json(pj);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto out;
                }
                jvalue_destroy(pj);
                pj = NULL;
                curidx += 1;
            }
        }

        dret = WaitForMultipleObjectsEx(waitnum,waithds,FALSE,10000,TRUE);
        if (dret < (WAIT_OBJECT_0 + waitnum)) {
            curhd = waithds[(dret - WAIT_OBJECT_0)];
            if (curhd == st_ExitEvt) {
                DEBUG_INFO("break");
                break;
            } else if (curhd == pcomm->get_read_evt()) {
                ret = pcomm->complete_read();
                if (ret < 0) {
                    GETERRNO(ret);
                    goto out;
                }
            } else if (curhd == pcomm->get_write_evt()) {
                ret = pcomm->complete_write();
                if (ret < 0) {
                    GETERRNO(ret);
                    goto out;
                }
            }
        } else if (dret != WAIT_TIMEOUT) {
            GETERRNO(ret);
            ERROR_INFO("dret %d",dret);
            goto out;
        }
    }



    ret = 0;
out:
    read_file_whole(NULL,&pbuf,&bufsize);
    buflen = 0;
    if(pj) {
        jvalue_destroy(pj);
    }
    pj = NULL;
    if (inpj) {
        jvalue_destroy(inpj);
    }
    inpj = NULL;
    if(pjstr){
        free(pjstr);
    }
    pjstr = NULL;
    if (pcomm) {
        delete pcomm;
        pcomm = NULL;
    }
    SETERRNO(ret);
    return ret;
}

int npcli2_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    void* pnp = NULL;
    char** filecon = NULL;
    int *filelen = NULL;
    int argcnt = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int curidx = 0;
    char** fnames = NULL;
    char* pipename = NULL;
    char* pwritebuf = NULL;
    int writelen = 0;
    uint32_t writesize = 0;
    char* preadbuf = NULL;
    int needlen = 0;
    int rcvlen = 0;
    int ridx = 0;
    HANDLE waithds[MAX_WAIT_NUM];
    DWORD waitnum;
    int i;
    BOOL bret;
    uint32_t rcvsize = 0;
    char* ptmpreadbuf = NULL;
    DWORD dret;
    HANDLE curhd;
    int filesize = 0;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    pipename = pargs->m_pipename;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        argcnt ++;
    }

    if (argcnt > 0) {
        fnames = parsestate->leftargs;
        filecon = (char**) malloc(sizeof(*filecon) * argcnt);
        if (filecon == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "can not alloc [%zu] error[%d]\n", sizeof(*filecon)* argcnt, ret);
            goto out;
        }
        memset(filecon, 0, sizeof(*filecon) * argcnt);

        filelen = (int*) malloc(sizeof(*filelen) * argcnt);
        if (filelen == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "can not alloc [%zu] error[%d]\n", sizeof(*filelen)* argcnt, ret);
            goto out;
        }
        memset(filelen, 0, sizeof(*filelen) * argcnt);

        for (i = 0; i < argcnt; i++) {
            filesize = 0;
            ret = read_file_whole(fnames[i], &(filecon[i]), &filesize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "[%d].[%s] read error[%d]\n", i, fnames[i], ret);
                goto out;
            }
            filelen[i] = ret;
        }
    }

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


    pnp = connect_namedpipe_timeout(pipename, pargs->m_timeout);
    if (pnp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not connect [%s] timeout[%d] error[%d]", pipename, pargs->m_timeout, ret);
        goto out;
    }

    DEBUG_INFO("connect [%s]", pipename);

    curidx = 0;
    ridx = 0;
    rcvlen = 0;
    needlen = sizeof(uint32_t);
    rcvsize = 256;
    preadbuf = (char*)malloc(rcvsize);
    if (preadbuf == NULL ) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc[%d] error[%d]", rcvsize, ret);
        goto out;
    }
    writesize = 0;
    while (curidx < argcnt || ridx < argcnt) {
        if (pargs->m_timeout != 0) {
            sleep_mill(pargs->m_timeout);
        }
        DEBUG_INFO("curidx [%d] ridx [%d] argcnt [%d]", curidx, ridx, argcnt);
        waitnum = 0;
        waithds[waitnum] = st_ExitEvt;
        waitnum ++;
        if (get_namedpipe_wrstate(pnp) == 0) {
write_again:
            if (curidx < argcnt) {
                if (writesize < (filelen[curidx] + sizeof(uint32_t))) {
                    writesize = (filelen[curidx] + sizeof(uint32_t));
                    if (pwritebuf) {
                        free(pwritebuf);
                    }
                    pwritebuf = NULL;
                    pwritebuf = (char*) malloc(writesize);
                    if (pwritebuf == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc [%d] error[%d]", writesize, ret);
                        goto out;
                    }
                }
                ASSERT_IF(pwritebuf != NULL);
                writelen = (int)(filelen[curidx] + sizeof(uint32_t));
                memcpy(&(pwritebuf[0]), &writelen, sizeof(uint32_t));
                memcpy(&(pwritebuf[sizeof(uint32_t)]), filecon[curidx], (size_t)filelen[curidx]);
                DEBUG_BUFFER_FMT(pwritebuf,writelen,"write [%d] file",curidx);
                ret = write_namedpipe(pnp, pwritebuf, writelen);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not write [%s].[%d] error[%d]", pipename, curidx, ret);
                    goto out;
                }
                if (get_namedpipe_wrstate(pnp) == 0) {
                    curidx ++;
                    goto write_again;
                }
                ASSERT_IF(waitnum < MAX_WAIT_NUM);
                waithds[waitnum] = get_namedpipe_wrevt(pnp);
                waitnum ++;
            }
        } else {
            ASSERT_IF(waitnum < MAX_WAIT_NUM);
            waithds[waitnum] = get_namedpipe_wrevt(pnp);
            waitnum ++;
        }
        if (get_namedpipe_rdstate(pnp) == 0) {
read_again:
            if (ridx < argcnt) {
                ret = read_namedpipe(pnp, &(preadbuf[rcvlen]), (needlen - rcvlen));
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not read [%s] error[%d]", pipename, ret);
                    goto out;
                }
                DEBUG_INFO("read [%d]", ret);
                if (get_namedpipe_rdstate(pnp) == 0) {
                    rcvlen = needlen;
                    if (needlen == sizeof(uint32_t)) {
                        memcpy(&needlen, preadbuf, sizeof(uint32_t));
                        if (needlen > (int)rcvsize) {
                            rcvsize = (uint32_t)needlen;
                            ptmpreadbuf = (char*)malloc(rcvsize);
                            if (ptmpreadbuf == NULL) {
                                GETERRNO(ret);
                                ERROR_INFO("can not alloc [%d] error[%d]", rcvsize , ret);
                                goto out;
                            }
                            if (rcvlen > 0) {
                                memcpy(ptmpreadbuf, preadbuf, (size_t)rcvlen);
                            }
                            if (preadbuf) {
                                free(preadbuf);
                            }
                            preadbuf = ptmpreadbuf;
                            ptmpreadbuf = NULL;
                        }

                        if (needlen > sizeof(uint32_t)) {
                            ret = read_namedpipe(pnp, &(preadbuf[rcvlen]), (needlen - rcvlen));
                            rcvlen += ret;
                            if (ret < 0) {
                                GETERRNO(ret);
                                ERROR_INFO("read [%s] error[%d]", pipename, ret);
                                goto out;
                            }
                        }

                        if (get_namedpipe_rdstate(pnp) == 0) {
                            rcvlen = needlen;
                            goto read_more;
                        }
                    } else if (needlen > sizeof(uint32_t)) {
                        rcvlen = needlen;
read_more:
                        DEBUG_BUFFER_FMT(preadbuf, needlen, "read [%d] packet", ridx);
                        ridx ++;
                        needlen = sizeof(uint32_t);
                        rcvlen = 0;
                        goto read_again;
                    }
                } else {
                    ASSERT_IF(waitnum < MAX_WAIT_NUM);
                    waithds[waitnum] = get_namedpipe_rdevt(pnp);
                    waitnum ++;
                }
            }
        } else {
            ASSERT_IF(waitnum < MAX_WAIT_NUM);
            waithds[waitnum] = get_namedpipe_rdevt(pnp);
            waitnum ++;
        }

        dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, 500, FALSE);
        if (dret < (WAIT_OBJECT_0 + waitnum)) {
            curhd = waithds[(dret - WAIT_OBJECT_0)];
            if (curhd == st_ExitEvt) {
                break;
            } else if (curhd == get_namedpipe_rdevt(pnp)) {
                DEBUG_INFO("rdevt");
                ret = complete_namedpipe_rdpending(pnp);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("complete [%s] read error[%d]", pipename, ret);
                    goto out;
                }

                if (ret > 0) {
                    DEBUG_INFO("needlen [%d]", needlen);
                    if (needlen > sizeof(uint32_t)) {
                        rcvlen = needlen;
dump_again:
                        DEBUG_BUFFER_FMT(preadbuf, needlen, "read [%d] packet", ridx);
                        needlen = sizeof(uint32_t);
                        rcvlen = 0;
                        ridx ++;
                    } else if (needlen == sizeof(uint32_t)) {
                        rcvlen = needlen;
                        memcpy(&needlen, preadbuf, sizeof(uint32_t));
                        DEBUG_INFO("more [%d]", needlen);
                        if (needlen == sizeof(uint32_t)) {
                            goto dump_again;
                        }

                        if (needlen > (int)rcvsize) {
                            rcvsize = (uint32_t)needlen;
                            ptmpreadbuf = (char*)malloc(rcvsize);
                            if (ptmpreadbuf == NULL) {
                                GETERRNO(ret);
                                ERROR_INFO("can not alloc [%d] error[%d]", rcvsize , ret);
                                goto out;
                            }
                            if (rcvlen > 0) {
                                memcpy(ptmpreadbuf, preadbuf, (size_t)rcvlen);
                            }
                            if (preadbuf) {
                                free(preadbuf);
                            }
                            preadbuf = ptmpreadbuf;
                            ptmpreadbuf = NULL;
                        }
                    }
                }
            } else if (curhd == get_namedpipe_wrevt(pnp)) {
                ret = complete_namedpipe_wrpending(pnp);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("complete [%s] write error[%d]", pipename, ret);
                    goto out;
                }

                if (ret > 0) {
                    curidx ++;
                }
            }
        } else if (dret == WAIT_TIMEOUT) {
            continue;
        } else {
            GETERRNO(ret);
            ERROR_INFO("wait error [%d] [%d]", dret, ret);
            goto out;
        }
    }


    ret = 0;
out:
    close_namedpipe(&pnp);
    if (filecon != NULL && filelen != NULL) {
        for (i = 0; i < argcnt; i++) {
            read_file_whole(NULL, &(filecon[i]), &(filelen[i]));
        }
    }

    if (pwritebuf) {
        free(pwritebuf);
    }
    pwritebuf = NULL;
    writelen = 0;
    writesize = 0;

    if (preadbuf) {
        free(preadbuf);
    }
    preadbuf = NULL;
    rcvlen = 0;
    needlen = 0;
    rcvsize = 0;

    if (ptmpreadbuf) {
        free(ptmpreadbuf);
    }
    ptmpreadbuf = NULL;

    if (filecon) {
        free(filecon);
    }
    filecon = NULL;

    if (filelen) {
        free(filelen);
    }
    filelen = NULL;
    argcnt = 0;
    SETERRNO(ret);
    return ret;
}


int wtsdetachrun_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(WTS_DETACH_RUN, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int startproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int createflags = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    int ret;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    if (pargs->m_hidewindow) {
        createflags |= PROC_NO_WINDOW;
    }

    ret = start_cmdv_detach(createflags, parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "start [");
        for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", parsestate->leftargs[i] );
        }
        fprintf(stderr, "] error[%d]\n", ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int checkproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int numproc = 0;
    int ret;
    char** ppnames = NULL;
    int i;
    int* pfinded = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        numproc ++;
    }

    ppnames = (char**) malloc(sizeof(ppnames[0]) * numproc);
    if (ppnames == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc [%d] error[%d]", sizeof(ppnames[0]) * numproc, ret);
        goto out;
    }

    pfinded = (int*) malloc(sizeof(pfinded[0]) * numproc);
    if (pfinded == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc [%d] error[%d]", sizeof(pfinded[0]) * numproc, ret);
        goto out;
    }

    memset(pfinded, 0, sizeof(pfinded[0]) * numproc);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        ppnames[i] = parsestate->leftargs[i];
    }

    ret = process_num(ppnames, numproc, pfinded);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "find proc [");
        for (i = 0; i < numproc; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", ppnames[i]);
        }
        fprintf(stderr, "] error [%d]\n", ret);
        goto out;
    }
    for (i = 0; i < numproc; i++) {
        fprintf(stdout, "[%s]        run [%d]", ppnames[i], pfinded[i]);
    }


    ret = 0;
out:
    if (ppnames) {
        free(ppnames);
    }
    ppnames = NULL;

    if (pfinded) {
        free(pfinded);
    }
    pfinded = NULL;

    SETERRNO(ret);
    return ret;
}

int svrcheckproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(PROCESS_NUM_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int iswts_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);

    init_log_level(pargs);

    fprintf(stdout, "wts [%s]\n", is_wts_enabled() > 0 ? "enabled" : "disabled");

    return 0;

}

int termproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int pid = -1;
    int idx;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx]; idx++) {
        pid = atoi(parsestate->leftargs[idx]);
        ret = kill_process(pid);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not kill [%d] error[%d]", pid, ret);
            goto out;
        }
        fprintf(stdout, "[%d]kill [%d] succ\n", idx, pid);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int listproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    const char* procname = NULL;
    int idx;
    int j;
    pargs_options_t pargs = (pargs_options_t) popt;
    int* pids = NULL;
    int retlen = 0;
    int retsize = 0;
    init_log_level(pargs);


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx]; idx++) {
        procname = parsestate->leftargs[idx];
        ret = list_proc(procname, &pids, &retsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not get [%s] error[%d]", procname, ret);
            goto out;
        }
        retlen = ret;
        fprintf(stdout, "get [%s] [%d]", procname, retlen);
        for (j = 0; j < retlen; j++) {
            if ((j % 5) == 0) {
                fprintf(stdout, "\n%05d:", j);
            }
            fprintf(stdout, " %08d", pids[j]);
        }
        fprintf(stdout, "\n");
    }

    ret = 0;
out:
    list_proc(NULL, &pids, &retsize);
    SETERRNO(ret);
    return ret;
}

int svrbackrun_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(BACK_CMD_RUN, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int procsecget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    int pid;


    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);
    init_log_level(pargs);

    ret = init_nt_envop_funcs();
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }


    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] != NULL ; i ++) {
        pid = atoi(parsestate->leftargs[i]);
        ret = dump_process_security(stdout, pid);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    ret = 0;
out:
    fini_nt_envop_funcs();
    SETERRNO(ret);
    return ret;
}

int procsecset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int pid;
    char* maskstr;
    char* modestr;
    char* inheritstr;
    char* username = NULL;


    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);
    init_log_level(pargs);

    ret = init_nt_envop_funcs();
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    pid = atoi(parsestate->leftargs[0]);
    maskstr = parsestate->leftargs[1];
    modestr = parsestate->leftargs[2];
    inheritstr = parsestate->leftargs[3];
    username = parsestate->leftargs[4];

    ret = proc_dacl_set(NULL, pid, maskstr, modestr, inheritstr, username);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    fprintf(stdout, "set [%s] mask [%s] mode[%s] inherit [%s] user[%s] succ\n",
            parsestate->leftargs[0], parsestate->leftargs[1], parsestate->leftargs[2], parsestate->leftargs[3],
            parsestate->leftargs[4]);
    ret = 0;
out:
    fini_nt_envop_funcs();
    SETERRNO(ret);
    return ret;
}

int getprocwin_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    HWND *phds = NULL;
    int hdsize = 0;
    int hdlen = 0;
    int i;
    int j;
    int pid;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        pid = atoi(parsestate->leftargs[i]);
        if (pid != 0) {
            ret = get_window_from_pid(pid, &phds, &hdsize);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            hdlen = ret;
            fprintf(stdout, "[%d] windows", pid);
            for (j = 0; j < hdlen; j++) {
                if ((j % 5) == 0) {
                    fprintf(stdout, "\n");
                }
                fprintf(stdout, " %p", phds[j]);
            }
            fprintf(stdout, "\n");
        }
    }

    ret =  0;
out:
    get_window_from_pid(0, &phds, &hdsize);
    hdlen = 0;
    SETERRNO(ret);
    return ret;
}

int existproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    int i;
    int pid;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        pid = atoi(parsestate->leftargs[i]);
        ret = process_exist(pid);
        fprintf(stdout, "[%d] %s\n", pid, ret > 0 ? "exist" : "not exist");
    }
    ret = 0;
    SETERRNO(ret);
    return ret;
}

int waitexit_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    int i;
    int *ppid = NULL;
    HANDLE *pproc = NULL;
    int argcnt = 0;
    DWORD dret;
    int d;
    BOOL bret;
    DWORD exitcode;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    for (argcnt = 0; parsestate->leftargs && parsestate->leftargs[argcnt]; argcnt ++) {

    }

    ppid = (int*) malloc(sizeof(ppid[0]) * argcnt);
    if (ppid == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(ppid, 0, sizeof(ppid[0]) * argcnt);
    pproc = (HANDLE*)malloc(sizeof(pproc[0]) * argcnt);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(pproc, 0, sizeof(pproc[0]) * argcnt);

    for (i = 0; i < argcnt; i++) {
        ppid[i] = atoi(parsestate->leftargs[i]);
        pproc[i] = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION , FALSE, (DWORD)ppid[i]);
        if (pproc[i] == NULL) {
            GETERRNO(ret);
            ERROR_INFO("open [%d] error[%d]", ppid[i], ret);
            goto out;
        }
        DEBUG_INFO("[%d]open [%d]", i , ppid[i]);
    }

    while (1) {
        dret = WaitForMultipleObjectsEx((DWORD)argcnt, pproc, FALSE, 1000, TRUE);
        if (dret < (WAIT_OBJECT_0 + argcnt)) {
            d = (int)(dret - WAIT_OBJECT_0);
            bret = GetExitCodeProcess(pproc[d], &exitcode);
            if (bret) {
                fprintf(stdout, "[%d] exit [%ld]\n", ppid[d], exitcode);
                break;
            } else {
                GETERRNO(ret);
                DEBUG_INFO("wait [%d] error[%d]", ppid[i], ret);
            }
        } else if (dret == WAIT_TIMEOUT) {
            DEBUG_INFO("no exit");
            continue;
        } else {
            GETERRNO(ret);
            ERROR_INFO("wait error [%ld] [%d]", dret, ret);
            goto out;
        }
    }
    ret =  0;
out:
    if (pproc) {
        for (i = 0; i < argcnt; i++) {
            if (pproc[i] != NULL) {
                CloseHandle(pproc[i]);
                pproc[i] = NULL;
            }
        }
        free(pproc);
        pproc = NULL;
    }

    if (ppid) {
        free(ppid);
        ppid = NULL;
    }
    SETERRNO(ret);
    return ret;
}

int sendctrlc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    int curpid = 0;
    int argcnt = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    BOOL bret;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    for (argcnt = 0; parsestate->leftargs && parsestate->leftargs[argcnt] ; argcnt ++) {

    }

    bret = SetConsoleCtrlHandler(HandlerConsoleRoutine, TRUE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
        goto out;
    }

    for (i = 0; i < argcnt; i++) {
        curpid = atoi(parsestate->leftargs[i]);
        ret = send_ctrlc(curpid);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("send_ctrlc [%d]", ret);
            goto out;
        }
        fprintf(stdout, "send_ctrlc [%d] succ\n", curpid);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int waitctrlc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(popt);
    return 0;
}

int dllproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    HMODULE hmod=NULL;
    char* dllname = NULL;
    char* procname = NULL;
    void* procfunc=NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    if (parsestate->leftargs && parsestate->leftargs[0]) {
        dllname = parsestate->leftargs[0];
    }

    if (parsestate->leftargs && parsestate->leftargs[1]) {
        procname = parsestate->leftargs[1];
    }

    if (dllname && procname) {
        hmod = LoadLibraryA(dllname);
        if (hmod == NULL ){
            GETERRNO(ret);
            fprintf(stderr,"can not load [%s] error[%d]\n",dllname,ret);
            goto out;
        }

        procfunc = GetProcAddress(hmod,procname);
        if (procfunc) {
            fprintf(stdout,"[%s].[%s] %p\n", dllname,procname,procfunc);
        } else {
            GETERRNO(ret);
            fprintf(stderr,"[%s].[%s] error[%d]\n",dllname,procname,ret);
            goto out;
        }
    }

    ret = 0;

out:
    if (hmod != NULL) {
        FreeLibrary(hmod);
    }
    hmod = NULL;
    SETERRNO(ret);
    return ret;
}

int handles_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    phandle_info_t phdls=NULL;
    int hdlsize=0;
    int hdllen=0;
    int i;

    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    ret = get_handle_infos(0,&phdls,&hdlsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get handles error[%d]\n", ret);
        goto out;
    }

    hdllen = ret;
    for(i=0;i<hdllen;i++) {
        fprintf(stdout,"[%d] proc[%d] handle[0x%p] type[%s] name[%s]\n",i,phdls[i].m_pid,phdls[i].m_hdl,phdls[i].m_typename,phdls[i].m_name);
    }
    ret = 0;
out:
    get_handle_infos(1,&phdls,&hdlsize);
    hdllen = 0;
    SETERRNO(ret);
    return ret;
}


int disabledebug_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int level;
    pargs_options_t pargs = (pargs_options_t)popt;

    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    DEBUG_INFO("BEFORE change");

    level = change_log_level(BASE_LOG_FATAL);
    if (level < 0) {
        GETERRNO(ret);
        ERROR_INFO("change_log_level error[%d]", ret);
        goto out;
    }

    DEBUG_INFO("should not see");

    ret = change_log_level(level);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("change_log_level error[%d]", ret);
        goto out;
    }

    DEBUG_INFO("after change");

    ret = 0;
out:    
    SETERRNO(ret);
    return ret;
}

DWORD exit_thread(void* arg)
{
    int num = (int) (addr_t)arg;
    int i;
    for(i=0;i<num;i++) {
        DEBUG_INFO("[%d] thread",i);
        sleep_mill(1000);
    }
    exit(0);
    //return 0;

}

int threxit_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int num = 10;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    HANDLE hthr=NULL;
    DWORD tid;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    if (parsestate->leftargs && parsestate->leftargs[0]) {
        num = atoi(parsestate->leftargs[0]);
    }

    hthr = CreateThread(NULL,0,exit_thread,(void*)(addr_t)num,0,&tid);
    if (hthr == NULL) {
        GETERRNO(ret);
        goto out;
    }

    i = 0;
    while(1) {
        sleep_mill(1000);
        DEBUG_INFO("[%d] main",i);
        i += 1;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}