#include <win_fileop.h>
#include <win_output_debug.h>
#include <win_args.h>
#include <win_strop.h>
#include <extargs.h>
#include <win_err.h>
#include <win_proc.h>
#include <win_window.h>
#include <win_verify.h>
#include <win_netinter.h>
#include <win_time.h>
#include <win_uniansi.h>

typedef struct __args_options {
    int m_verbose;
    char* m_classname;
    char* m_input;
    char* m_output;
    char* m_errout;
    int m_timeout;
} args_options_t, *pargs_options_t;

int mktemp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int readencode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pidargv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int findwindow_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int fullpath_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int winverify_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int netinter_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int quote_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int run_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrlap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int clilap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sendmsg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);

#include "args_options.cpp"

#define  GET_NUM64(num,name) 
do{

} while(0)

int init_log_level(pargs_options_t pargs)
{
    int loglvl = BASE_LOG_ERROR;
    if (pargs->m_verbose <= 0) {
        loglvl = BASE_LOG_ERROR;
    } else if (pargs->m_verbose == 1) {
        loglvl = BASE_LOG_WARN;
    } else if (pargs->m_verbose == 2) {
        loglvl = BASE_LOG_INFO;
    } else if (pargs->m_verbose == 3) {
        loglvl = BASE_LOG_DEBUG;
    } else {
        loglvl = BASE_LOG_TRACE;
    }
    fprintf(stdout, "verbose [%d]\n", pargs->m_verbose);
    return INIT_LOG(loglvl);
}

int mktemp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* templstr = NULL;
    int templsize = 0;
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL ; i++) {
            ret = mktempfile_safe(parsestate->leftargs[i], &templstr, &templsize);
            //ret = 0;
            if (ret < 0) {
                fprintf(stderr, "can not parse [%s] error(%d)\n", parsestate->leftargs[i], ret);
                goto out;
            }
            fprintf(stdout, "[%d]%s => %s\n", i, parsestate->leftargs[i], templstr);
        }
    }
out:
    mktempfile_safe(NULL, &templstr, &templsize);
    return ret;
}

int readencode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* templstr = NULL;
    int templsize = 0;
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            ret = read_file_encoded(parsestate->leftargs[i], &templstr, &templsize);
            if (ret < 0) {
                fprintf(stderr, "can not read [%s] error[%d]\n", parsestate->leftargs[i], ret);
                goto out;
            }
            fprintf(stdout, "%s\n----------------------\n%s\n+++++++++++++++++++++++++\n", parsestate->leftargs[i], templstr);
        }
    }
out:
    read_file_encoded(NULL, &templstr, &templsize);
    return ret;
}

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

int findwindow_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i, j;
    int pid = -1;
    int ret = 0;
    int totalret = 0;
    HWND* pwnd = NULL;
    pargs_options_t poption = (pargs_options_t) popt;
    argv = argv;
    argc = argc;
    int wndsize = 0;
    init_log_level(poption);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            pid = atoi(parsestate->leftargs[i]);
            ret = get_win_handle_by_classname(poption->m_classname, pid, &pwnd, &wndsize);
            if (ret < 0) {
                GETERRNO(ret);
                totalret = ret;
                fprintf(stderr, "can not get [%d] class[%s] error[%d]\n", pid, poption->m_classname, ret);
                continue;
            }
            fprintf(stdout, "get [%d] class [%s]:", pid, poption->m_classname);
            for (j = 0; j < ret; j++) {
                if ((j % 5) == 0) {
                    fprintf(stdout, "\n    ");
                }
                fprintf(stdout, " 0x%p", pwnd[j]);
            }
            fprintf(stdout, "\n");
        }

    } else {
        ret = get_win_handle_by_classname(poption->m_classname, -1, &pwnd, &wndsize);
        if (ret < 0) {
            GETERRNO(ret);
            totalret = ret;
            fprintf(stderr, "can not get [%s] on pid[%d] error[%d]\n", poption->m_classname, pid, ret);
            goto out;
        }
        fprintf(stdout, "get class [%s]:", poption->m_classname);
        for (j = 0; j < ret; j++) {
            if ((j % 5) == 0) {
                fprintf(stdout, "\n    ");
            }
            fprintf(stdout, " 0x%p", pwnd[j]);
        }
        fprintf(stdout, "\n");

    }

    ret = totalret;
out:
    get_win_handle_by_classname(NULL, -1, &pwnd, &wndsize);
    SETERRNO(-ret);
    return ret;
}

int fullpath_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pfullpath = NULL;
    int fullsize = 0;
    int i;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i ++) {
            ret = get_full_path(parsestate->leftargs[i], &pfullpath, &fullsize);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            fprintf(stdout, "[%d][%s] => [%s]\n", i, parsestate->leftargs[i], pfullpath);
        }
    }

    ret = 0;
out:
    get_full_path(NULL, &pfullpath, &fullsize);
    SETERRNO(-ret);
    return ret;
}

int winverify_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int totalret = 0;
    int ret;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs) {
        i = 0;
        while (parsestate->leftargs[i] != NULL) {
            ret = verify_windows_pe(parsestate->leftargs[i]);
            if (ret < 0) {
                GETERRNO(ret);
                totalret = ret;
                fprintf(stderr, "[%d] verify [%s] error[%d]\n", i, parsestate->leftargs[i], ret);
            } else {
                fprintf(stdout, "[%d]verify [%s] succ\n", i, parsestate->leftargs[i]);
            }
            i ++;
        }
    }

    SETERRNO(totalret);
    return totalret;
}

#define TYPE_PRINTF(type,stype)          \
do {                                     \
    if (pinfo->m_type & type) {          \
        if (typefp > 0) {                \
            fprintf(fp, "|");            \
        }                                \
        fprintf(fp, "%s", stype);        \
        typefp ++;                       \
    }                                    \
} while(0)

void debug_net_adapter(pnet_inter_info_t pinfo, FILE* fp, const char* fmt, ...)
{
    va_list ap;
    int typefp = 0;
    if (fmt != NULL) {
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        fprintf(fp, "\n");
    }

    fprintf(fp, "m_adaptername[%s]\n", pinfo->m_adaptername);
    fprintf(fp, "m_adapternickname[%s]\n", pinfo->m_adapternickname);
    fprintf(fp, "m_adapterip4[%s]\n", pinfo->m_adapterip4);
    fprintf(fp, "m_adapterip6[%s]\n", pinfo->m_adapterip6);
    fprintf(fp, "m_adaptermask4[%s]\n", pinfo->m_adaptermask4);
    fprintf(fp, "m_adaptermask6[%s]\n", pinfo->m_adaptermask6);
    fprintf(fp, "m_adaptergw[%s]\n", pinfo->m_adaptergw);
    fprintf(fp, "m_adapterdns[%s]\n", pinfo->m_adapterdns);
    fprintf(fp, "m_adaptermac[%s]\n", pinfo->m_adaptermac);
    fprintf(fp, "m_mtu[%d]\n", pinfo->m_mtu);

    fprintf(fp, "m_type ");
    TYPE_PRINTF(ETHER_NET, "ETHER_NET");
    TYPE_PRINTF(IP4_NET, "IP4_NET");
    TYPE_PRINTF(IP6_NET, "IP6_NET");
    if (typefp == 0) {
        fprintf(fp, "0");
    }
    fprintf(fp, "\n");
    return ;
}

int netinter_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pnet_inter_info_t pinfos = NULL;
    int infosize = 0;
    int i, j;
    int num;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);
    argc = argc;
    argv = argv;

    if (parsestate->leftargs == NULL) {
        ret = get_all_adapter_info(0, NULL, &pinfos, &infosize);
        if (ret < 0 ) {
            GETERRNO(ret);
            fprintf(stderr, "can not get adapter info error[%d]\n", ret);
            goto out;
        }
        num = ret;
        for (i = 0; i < num; i++) {
            debug_net_adapter(&(pinfos[i]), stdout, "[%d] adapter", i);
        }
    } else {
        for (i = 0; parsestate->leftargs[i] != NULL ; i ++) {
            ret = get_all_adapter_info(0, parsestate->leftargs[i], &pinfos, &infosize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "can not get adapter for [%s] error[%d]\n", parsestate->leftargs[i], ret);
                goto out;
            }
            num = ret;
            for (j = 0; j < num; j++) {
                debug_net_adapter(&(pinfos[j]), stdout, "[%d] adapter for [%s]", j, parsestate->leftargs[i]);
            }
        }
    }

    ret = 0;
out:
    get_all_adapter_info(1, NULL, &pinfos, &infosize);
    SETERRNO(ret);
    return ret;
}

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

void __debug_buf(FILE* fp, char* ptr, int size)
{
    int i;
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
        unsigned char* pcc = plast;
        /*now we should give out*/
        while (pcc != pcur) {
            fprintf(fp, "     ");
            pcc ++;
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
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int i;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_encoded(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
    }

    ret = run_cmd_outputv(inbuf, insize, &outbuf, &outsize, &errbuf, &errsize, &exitcode, pargs->m_timeout, parsestate->leftargs);
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
    fprintf(stdout, "output --------------------\n");
    __debug_buf(stdout, outbuf, outsize);
    fprintf(stdout, "output ++++++++++++++++++++\n");
    fprintf(stdout, "errout --------------------\n");
    __debug_buf(stdout, errbuf, errsize);
    fprintf(stdout, "errout ++++++++++++++++++++\n");

    ret = 0;
out:
    run_cmd_outputv(NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_encoded(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}

#define PIPE_NO_WAIT            0
#define PIPE_READ_WAIT          1
#define PIPE_WRITE_WAIT         2
#define PIPE_CONN_WAIT          3

typedef struct __pipe_st {
    HANDLE m_pipe;
    HANDLE m_evt;
    HANDLE m_nul;
    HANDLE m_chldpipe;
    OVERLAPPED m_ov;
    int m_state;
    char* m_pipename;
    int m_pipenamesize;
} pipe_st_t, *ppipe_st_t;

void __close_handle_note(HANDLE *phd, const char* fmt, ...)
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


void __close_pipe(ppipe_st_t p)
{
    char* curname = "no name";
    BOOL bret;
    int res;
    if (p->m_pipename) {
        curname = p->m_pipename;
    }
    if (p->m_state != PIPE_NO_WAIT) {
        bret = CancelIoEx(p->m_pipe, &(p->m_ov));
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("can not stop [%s] error[%d]", curname, res);
        }
        p->m_state = PIPE_NO_WAIT;
    }

    __close_handle_note(&(p->m_evt), "evt[%s]", curname);
    __close_handle_note(&(p->m_pipe), "server[%s]", curname);
    __close_handle_note(&(p->m_chldpipe), "client[%s]", curname);
    __close_handle_note(&(p->m_nul), "null[%s]", curname);
    snprintf_safe(&(p->m_pipename), &(p->m_pipenamesize), NULL);
    return;
}

void __free_pipe(ppipe_st_t *pp)
{
    if (pp != NULL && *pp != NULL) {
        ppipe_st_t p = *pp;
        __close_pipe(p);
        free(p);
        *pp = NULL;
    }
    return ;
}

ppipe_st_t __alloc_pipe()
{
    ppipe_st_t p = NULL;
    int ret;

    p = (ppipe_st_t) malloc(sizeof(*p));
    if (p == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*p));
        goto fail;
    }

    memset(p, 0 , sizeof(*p));
    p->m_state = PIPE_NO_WAIT;
    p->m_pipe = INVALID_HANDLE_VALUE;
    p->m_evt = INVALID_HANDLE_VALUE;
    p->m_chldpipe = INVALID_HANDLE_VALUE;
    p->m_nul = INVALID_HANDLE_VALUE;
    p->m_pipename = NULL;
    p->m_pipenamesize = 0;

    return p;
fail:
    __free_pipe(&p);
    SETERRNO(ret);
    return NULL;
}

int __connect_child(int wr, ppipe_st_t p)
{
    DWORD chldacs = 0;
    DWORD chldshmode = 0;
    int ret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;

    if (p->m_pipename == NULL ||
            p->m_pipenamesize == 0 ||
            p->m_pipe == INVALID_HANDLE_VALUE ||
            p->m_pipe == NULL ||
            (p->m_chldpipe != INVALID_HANDLE_VALUE && p->m_chldpipe != NULL)) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (wr) {
        chldacs = GENERIC_READ;
        chldshmode = FILE_SHARE_READ;
    } else {
        chldacs = GENERIC_WRITE;
        chldshmode = FILE_SHARE_WRITE;
    }

    ret = AnsiToTchar(p->m_pipename, &(ptname), &(tnamesize));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    p->m_chldpipe = CreateFile(ptname, chldacs, chldshmode, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (p->m_chldpipe == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("connect [%s] error[%d]", p->m_pipename, ret);
        goto fail;
    }

    AnsiToTchar(NULL, &(ptname), &(tnamesize));
    return 0;
fail:
    AnsiToTchar(NULL, &(ptname), &(tnamesize));
    SETERRNO(ret);
    return ret;
}

#define MIN_BUF_SIZE  0x400

int __create_pipe(int wr, ppipe_st_t p, char* name)
{
    BOOL bret;
    int ret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    DWORD chldacs;
    DWORD chldshmode;
    DWORD omode = FILE_FLAG_OVERLAPPED ;
    DWORD pmode = PIPE_TYPE_MESSAGE | PIPE_ACCEPT_REMOTE_CLIENTS | PIPE_NOWAIT | PIPE_READMODE_MESSAGE;

    if (name == NULL || p == NULL ||
            (p->m_pipe != INVALID_HANDLE_VALUE && p->m_pipe != NULL) ||
            (p->m_chldpipe != INVALID_HANDLE_VALUE && p->m_chldpipe != NULL) ||
            (p->m_evt != INVALID_HANDLE_VALUE && p->m_evt != NULL) ||
            (p->m_nul != INVALID_HANDLE_VALUE && p->m_nul != NULL) ||
            p->m_state != PIPE_NO_WAIT ||
            p->m_pipename != NULL || p->m_pipenamesize != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (wr) {
        omode |=  PIPE_ACCESS_OUTBOUND;
        chldacs = GENERIC_READ;
        chldshmode = FILE_SHARE_READ;
    } else {
        omode |= PIPE_ACCESS_INBOUND;
        chldacs = GENERIC_WRITE;
        chldshmode = FILE_SHARE_WRITE;
    }

    p->m_evt = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (p->m_evt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not create for [%s] error[%d]", name, ret);
        goto fail;
    }
    memset(&(p->m_ov), 0 , sizeof(p->m_ov));
    p->m_ov.hEvent = p->m_evt;

    ret = snprintf_safe(&(p->m_pipename), &(p->m_pipenamesize), "%s", name);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    p->m_pipe = CreateNamedPipe(ptname, omode, pmode, 1, MIN_BUF_SIZE, MIN_BUF_SIZE, NMPWAIT_USE_DEFAULT_WAIT, NULL);
    if (p->m_pipe == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("can not create [%s] pipe error[%d]", name, ret);
        goto fail;
    }

    bret = ConnectNamedPipe(p->m_pipe, &(p->m_ov));
    if (!bret) {
        GETERRNO(ret);
        if (ret != -ERROR_IO_PENDING && ret != -ERROR_PIPE_CONNECTED) {
            ERROR_INFO("connect [%s] error[%d]", name, ret);
            goto fail;
        }
        if (ret == -ERROR_IO_PENDING) {
            p->m_state = PIPE_CONN_WAIT;
        }
    }

    if (p->m_state != PIPE_CONN_WAIT) {
        /*now we should connect to the server*/
        ret = __connect_child(wr, p);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    __close_pipe(p);
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return ret;
}

int svrlap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    argc = argc;
    argv = argv;
    parsestate = parsestate;
    popt = popt;
    return 0;
}

int clilap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    argc = argc;
    argv = argv;
    parsestate = parsestate;
    popt = popt;
    return 0;
}


int sendmsg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int cnt = 0;
    int ret;
    int idx=0;
    HWND hwnd;
    UINT msg;
    WPARAM wparam;
    LPARAM lparam;

    if (parsestate->leftargs != NULL) {
        for (cnt = 0; parsestate->leftargs[cnt] != NULL; cnt ++) {

        }
    }

    if (cnt < 4) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "sendmsg hwnd msg wparam lparam\n");
        goto out;
    }

out:
    SETERRNO(ret);
    return ret;
}

int main(int argc, char* argv[])
{
    char** args = NULL;
    int ret = 0;
    args_options_t argsoption;
    pextargs_state_t pextstate = NULL;

    memset(&argsoption, 0, sizeof(argsoption));

    args = copy_args(argc, argv);
    if (args == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not copy args error[%d]\n", ret);
        goto out;
    }

    ret = EXTARGS_PARSE(argc, args, &argsoption, pextstate);
    //ret = parse_param_smart(argc, args, st_main_cmds, &argsoption, &pextstate, NULL, NULL);
    if (ret < 0) {
        fprintf(stderr, "could not parse error(%d)", ret);
        goto out;
    }

    ret = 0;
out:
    free_extargs_state(&pextstate);
    release_extargs_output(&argsoption);
    free_args(&args);
    extargs_deinit();
    return ret;
}