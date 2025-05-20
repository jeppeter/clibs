
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


int procmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int pid = -1;
    pproc_mem_info_t pmem=NULL;
    int memsize=0,memlen=0;
    int i;
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;


    init_log_verbose(pargs);
    if (parsestate->leftargs && parsestate->leftargs[0]) {
        pid = atoi(parsestate->leftargs[0]);
    }

    ret = get_proc_mem_info(pid,&pmem,&memsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "get [%d] proc mem map error %d\n", pid, ret);
        goto out;
    }

    memlen = ret;
    for(i=0;i<memlen;i++) {
        fprintf(stdout,"[0x%lx] - [0x%lx]           [%s]\n",pmem[i].m_startaddr, pmem[i].m_endaddr,pmem[i].m_file);
    }

    ret = 0;
out:
    get_proc_mem_info(-2,&pmem,&memsize);
    SETERRNO(ret);
    return ret;    
}

int call_func1(int idx)
{
    int ret;
    void** ppstack=NULL;
    int stacksize=0,stacklen=0;
    int i;
    ret = backtrace_safe(idx,&ppstack,&stacksize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    stacklen = ret;
    for(i=0;i<stacklen;i++) {
        fprintf(stdout,"[%d] %p\n",i,ppstack[i]);
    }

    backtrace_safe(-1,&ppstack,&stacksize);
    return 0;
fail:
    backtrace_safe(-1,&ppstack,&stacksize);
    SETERRNO(ret);
    return ret;
}

int call_func2(int idx)
{
    return call_func1(idx);
}

int call_func3(int idx)
{
    return call_func2(idx);
}

int backtrace2_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int idx=0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    pproc_mem_info_t pmem=NULL;
    int memsize=0,memlen=0;
    int i,j;
    char** searchfiles=NULL;

    init_log_verbose(pargs);
    if (parsestate->leftargs && parsestate->leftargs[0]) {
        idx = atoi(parsestate->leftargs[0]);
        if (parsestate->leftargs && parsestate->leftargs[1]) {
            searchfiles = &(parsestate->leftargs[1]);
        }
    }

    ret = call_func3(idx);

    ret = get_proc_mem_info(-1,&pmem,&memsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    memlen = ret;
    fprintf(stdout,"memlen %d\n", memlen);
    for(i=0;i<memlen;i++) {
        fprintf(stdout,"[0x%lx] - [0x%lx]  [0x%lx]         [%s]\n",pmem[i].m_startaddr, pmem[i].m_endaddr, pmem[i].m_endaddr - pmem[i].m_startaddr,pmem[i].m_file);
        if (searchfiles != NULL) {
            int matched = 0;
            for(j=0;searchfiles[j] != NULL;j++) {
                size_t slen = strlen(searchfiles[j]);
                size_t flen = strlen(pmem[i].m_file);
                char* pptr = pmem[i].m_file + flen - slen;
                if (strcmp(pptr,searchfiles[j]) == 0) {
                    matched = 1;
                    break;
                }
            }

            if (matched){
                //debug_buffer(stdout,(char*)pmem[i].m_startaddr, 0x20,"[%d][%s] 0x%llx", i,pmem[i].m_file, pmem[i].m_startaddr);
                //debug_buffer(stdout,(char*)(pmem[i].m_endaddr - 0x20), 0x20,"[%d][%s] 0x%llx", i,pmem[i].m_file,pmem[i].m_endaddr - 0x20);
                print_buffer(stdout,(unsigned char*)pmem[i].m_startaddr, (int)(pmem[i].m_endaddr - pmem[i].m_startaddr + 1), "[%d][%s] 0x%lx size 0x%x", i,pmem[i].m_file,pmem[i].m_startaddr, (int)(pmem[i].m_endaddr - pmem[i].m_startaddr + 1));
            }
        }
    }

    ret = 0;
out:
    get_proc_mem_info(-2,&pmem,&memsize);
    SETERRNO(ret);
    return ret;

}