
int debug_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    ret = init_log_verbose(pargs);
    if (ret < 0) {
        GETERRNO(ret);
        return ret;
    }

    TRACE_INFO("hello world");
    DEBUG_INFO("hello world");
    INFO_INFO("hello world");
    WARN_INFO("hello world");
    ERROR_INFO("hello world");
    FATAL_INFO("hello world");

    TRACE_BUFFER(pargs, sizeof(*pargs));
    DEBUG_BUFFER(pargs, sizeof(*pargs));
    INFO_BUFFER(pargs, sizeof(*pargs));
    WARN_BUFFER(pargs, sizeof(*pargs));
    ERROR_BUFFER(pargs, sizeof(*pargs));
    FATAL_BUFFER(pargs, sizeof(*pargs));

    TRACE_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    DEBUG_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    INFO_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    WARN_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    ERROR_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    FATAL_BUFFER_FMT(pargs, sizeof(*pargs), "args for");

    return 0;
}

int sleep_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    int i;
    int curmills;
    int smills;
    uint64_t sticks;
    uint64_t cticks;
    pargs_options_t pargs = (pargs_options_t) popt;
    ret = init_log_verbose(pargs);
    if (ret < 0) {
        GETERRNO(ret);
        return ret;
    }


    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        curmills = atoi(parsestate->leftargs[i]);
        sticks = get_cur_ticks();
        smills = curmills;
        if ((i % 2) == 0) {
            if (smills > 50) {
                smills -= 10;
            }
        } else {
            if (smills > 50) {
                smills += 10;
            }
        }
        sched_out(smills);
        ret = time_left(sticks, curmills);
        cticks = get_cur_ticks();
        fprintf(stdout, "[%d] [%d] [%lld:0x%llx] [%lld:0x%llx] %s\n",
                i, curmills, (long long int)sticks, (long long unsigned int)sticks,
                (long long int) cticks, (long long unsigned int)cticks,
                (ret > 0 ? "not expired" : "expired"));
    }

    ret = 0;
    SETERRNO(ret);
    return ret;
}

static int st_evtfd = -1;

void sig_handler(int signo)
{
    uint64_t u;
    int ret;
    if (st_evtfd >= 0) {
        u = 1;
        ret = write(st_evtfd, &u, sizeof(u));
        if (ret != sizeof(u)) {
            GETERRNO(ret);
            fprintf(stderr, "int write error[%d]", ret);
        }
    }
    return;
}

