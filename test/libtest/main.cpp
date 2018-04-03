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

#pragma comment(lib,"user32.lib")

#ifdef __cplusplus
extern "C" {
#endif
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
int sendmsg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);

#ifdef __cplusplus
};
#endif

#include "args_options.cpp"

#define  GET_OPT_TYPE(num, desc, typeof)                                          \
do{                                                                               \
    char* __pendptr;                                                              \
    uint64_t __num;                                                               \
    if (parsestate->leftargs &&                                                   \
        parsestate->leftargs[idx] != NULL) {                                      \
        ret = parse_number(parsestate->leftargs[idx],&__num,&__pendptr);          \
        if (ret < 0) {                                                            \
            GETERRNO(ret);                                                        \
            fprintf(stderr,"%s error[%d]\n", desc, ret);                          \
            goto out;                                                             \
        }                                                                         \
        num = (typeof)__num;                                                      \
        idx ++;                                                                   \
    }                                                                             \
} while(0)

#define  GET_OPT_NUM64(num,desc)          GET_OPT_TYPE(num,desc, uint64_t)
#define  GET_OPT_INT(num, desc)           GET_OPT_TYPE(num,desc,int)

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

#define PIPE_NONE                0
#define PIPE_READY               1
#define PIPE_WAIT_READ           2
#define PIPE_WAIT_WRITE          3
#define PIPE_WAIT_CONNECT        4

#define MIN_BUF_SIZE    0x400

int __create_pipe(char* name , int wr, HANDLE *ppipe, OVERLAPPED* pov, HANDLE *pevt, int *pstate)
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
        __close_handle_note(pevt, "event close");
        __close_handle_note(ppipe, "pipe close");
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
    __close_handle_note(pevt, "%s event", name);
    __close_handle_note(ppipe, "%s server pipe", name);
    memset(pov, 0, sizeof(*pov));
    SETERRNO(ret);
    return ret;
}

#define LEAST_UNIQ_NUM    50

int __get_temp_pipe_name(char* prefix, char** pptmp, int *psize)
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
        ret = read_file_encoded(pargs->m_input, &poutbuf, (int*)&outsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
    }

    if (parsestate->leftargs != NULL && parsestate->leftargs[0] != NULL) {
        pipename = parsestate->leftargs[0];
    } else {
        ret = __get_temp_pipe_name("pipe", &pipebasename, &pipebasesize);
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


    ret = __create_pipe(pipename, wr, &svrpipe, &ov, &evt, &state);
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
                    ERROR_INFO("ret [%d] cbret [%d] outlen [%zu] outsize[%zu]", ret,cbret, outlen, outsize);
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

    read_file_encoded(NULL, &poutbuf, (int*)&outsize);
    __create_pipe(NULL, 0, &svrpipe, &ov, &evt, &state);
    snprintf_safe(&tmppipe, &tmppipesize, NULL);
    __get_temp_pipe_name(NULL, &pipebasename, &pipebasesize);
    SETERRNO(ret);
    return ret;
}


int sendmsg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    int cnt = 0;
    int idx = 0;
    HWND hwnd = NULL;
    UINT msg = 0;
    WPARAM wparam = 0;
    LPARAM lparam = 0;
    LRESULT lret;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (parsestate->leftargs != NULL) {
        for (cnt = 0; parsestate->leftargs[cnt] != NULL; cnt ++) {

        }
    }

    if (cnt < 4 || (cnt % 4) != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "sendmsg hwnd msg wparam lparam\n");
        goto out;
    }


    while (parsestate->leftargs[idx] != NULL) {
        GET_OPT_TYPE(hwnd, "get hwnd", HWND);
        GET_OPT_TYPE(msg, "get msg", UINT);
        GET_OPT_TYPE(wparam, "get wparam", WPARAM);
        GET_OPT_TYPE(lparam, "get lparam", LPARAM);

        lret = SendMessage(hwnd, msg, wparam, lparam);
        fprintf(stdout, "send [%p] msg[%d:0x%x] with wparam [%lld:0x%llx] lparam[%lld:0x%llx] ret[%lld]\n",
                hwnd, msg, msg,
                wparam, wparam,
                lparam, lparam, lret);
        if (pargs->m_timeout > 0) {
            SleepEx((DWORD)pargs->m_timeout, TRUE);
        }
    }
    ret = 0;
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