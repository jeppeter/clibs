
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



int run_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char** ppout = NULL;
    char** pperr = NULL;
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    char* pout = NULL;
    int outsize = 0;
    char* perr = NULL;
    int errsize = 0;
    sighandler_t sighdl = SIG_ERR;
    int exitcode;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    if (pargs->m_input) {
        ret = read_file_whole(pargs->m_input, &pin, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        inlen = ret;
    }

    if (pargs->m_output != NULL) {
        ppout = &pout;
    }

    if (pargs->m_errout != NULL) {
        pperr = &perr;
    }

    if (pargs->m_withevt) {
        st_evtfd = eventfd(0, 0);
        if (st_evtfd < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not create event fd error[%d]\n", ret);
            goto out;
        }

        sighdl = signal(SIGINT, sig_handler);
        if (sighdl == SIG_ERR) {
            GETERRNO(ret);
            fprintf(stderr, "signal SIGINT error[%d]", ret);
            goto out;
        }
    }

    ret = run_cmd_event_outputv(st_evtfd, pin, inlen, ppout, &outsize, pperr, &errsize, &exitcode, pargs->m_timeout, parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run command error [%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "run command [");
    for (i = 0; parsestate->leftargs[i]; i++) {
        if (i > 0) {
            fprintf(stdout, ",");
        }
        fprintf(stdout, "%s", parsestate->leftargs[i]);
    }
    fprintf(stdout, "] exitcode [%d]\n", exitcode);
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input out\n");
        __debug_buf(stdout, pin, inlen);
    } else {
        fprintf(stdout, "input none\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output\n");
        __debug_buf(stdout, pout, outsize);
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout\n");
        __debug_buf(stdout, perr, errsize);
    }

    ret = 0;
out:
    run_cmd_event_outputv(-1, NULL, 0, &pout, &outsize, &perr, &errsize, NULL, 0, NULL);
    read_file_whole(NULL, &pin, &insize);
    if (st_evtfd >= 0) {
        close(st_evtfd);
    }
    st_evtfd = -1;
    SETERRNO(ret);
    return ret;
}

int backtrace_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int stkidx = 0;

    init_log_verbose(pargs);
    if (parsestate->leftargs && parsestate->leftargs[0]) {
        stkidx = atoi(parsestate->leftargs[0]);
    }

    BACKTRACE_FATAL(stkidx,"BACKTRACE_FATAL");
    BACKTRACE_ERROR(stkidx,"BACKTRACE_ERROR");
    BACKTRACE_WARN(stkidx,"BACKTRACE_WARN");
    BACKTRACE_INFO(stkidx,"BACKTRACE_INFO");
    BACKTRACE_DEBUG(stkidx,"BACKTRACE_DEBUG");
    BACKTRACE_TRACE(stkidx,"BACKTRACE_TRACE");

    return 0;
}