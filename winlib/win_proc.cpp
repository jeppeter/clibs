
#include <win_proc.h>
#include <win_fileop.h>
#include <win_err.h>
#include <win_uniansi.h>
#include <win_strop.h>
#include <win_time.h>
#include <win_priv.h>

#pragma warning(push)

#pragma warning(disable:4668)
#pragma warning(disable:4820)

#include <tchar.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <stdio.h>

#pragma warning(pop)

#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"Userenv.lib")
#pragma comment(lib,"Wtsapi32.lib")

#if _MSC_VER >= 1910
#pragma warning(push)
/*disable Spectre warnings*/
#pragma warning(disable:5045)
#endif


#define pid_wmic_cmd_fmt "WMIC /OUTPUT:%s process where \"ProcessId=%d\" get CommandLine,ProcessId"

#define MIN_BUF_SIZE    0x400

int get_pid_argv(int pid, char*** pppargv, int *pargvsize)
{
    char* tempfile = NULL;
    int tempsize = 0;
    int ret = 0;
    int retsize = 0;
    char** ppretargv = NULL;
    int namelen = 0;
    int filllen = 0;
    int cmdlen = 0;
    char* pcmd = NULL;
    char* pfilecont = NULL;
    int filelen = 0;
    char* pcurptr = NULL;
    char* ppassptr = NULL;
    wchar_t* pucmdline = NULL;
    int ucmdlinesize = 0;
    char* pcmdline = NULL;
    int cmdlinesize = 0;
    wchar_t** pargv = NULL;
    int argvnum = 0;
    char* argv0 = NULL;
    int argv0size = 0;
    int i;
    int curlen;

    if (pid < 0) {
        if (pppargv && *pppargv != NULL) {
            free(*pppargv);
        }
        if (pppargv) {
            *pppargv = NULL;
        }
        if (pargvsize) {
            *pargvsize = 0;
        }
        return 0;
    }

    if (pppargv == NULL || pargvsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        return ret;
    }
    ppretargv = *pppargv;
    retsize = *pargvsize;



    ret = mktempfile_safe("pidfile", &tempfile, &tempsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not mktemp error[%d]", ret);
        goto fail;
    }

    cmdlen = tempsize + (int)strlen(pid_wmic_cmd_fmt) + 10;
    pcmd = (char*)malloc((size_t)cmdlen);
    if (pcmd == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not malloc %d error[%d]", cmdlen, ret);
        goto fail;
    }

    memset(pcmd, 0, (size_t)cmdlen);
    ret = _snprintf_s(pcmd, (size_t)cmdlen, (size_t)cmdlen, pid_wmic_cmd_fmt, tempfile, pid);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not snprintf error[%d]", ret);
        goto fail;
    }

    ret = system(pcmd);
    if (ret != 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run [%s] error[%d]", pcmd, ret);
        goto fail;
    }

    /*now get the file information*/
    ret =  read_file_encoded(tempfile, &pfilecont, &filelen);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (pfilecont == NULL) {
        ret = -ERROR_BAD_FILE_TYPE;
        ERROR_INFO("[%s] bad format", pfilecont);
        goto fail;
    }


    /**/
    pcurptr = strchr(pfilecont, '\n');
    if (pcurptr == NULL) {
        ret = -ERROR_BAD_FILE_TYPE;
        ERROR_INFO("[%s] bad format", pfilecont);
        goto fail;
    }
    ppassptr = pcurptr;
    ppassptr += 1;

    pcurptr = strchr(ppassptr, '\n');
    if (pcurptr == NULL) {
        ret = -ERROR_BAD_FILE_TYPE;
        ERROR_INFO("[%s] bad format", pfilecont);
        goto fail;
    }

    pcurptr -= 1;

    while (1) {
        if (pcurptr <= ppassptr) {
            ret = -ERROR_BAD_FILE_TYPE;
            ERROR_INFO("[%s] bad format", pfilecont);
            goto fail;
        }
        if (*pcurptr == '\r' ||
                *pcurptr == ' ' ||
                *pcurptr == '\t') {
            pcurptr -= 1;
            continue;
        } else if (isdigit(*pcurptr)) {
            break;
        }
        ret = -ERROR_BAD_FILE_TYPE;
        ERROR_INFO("[%s] bad format", pfilecont);
        goto fail;
    }

    while (1) {
        if (pcurptr <= ppassptr) {
            ret = -ERROR_BAD_FILE_TYPE;
            ERROR_INFO("[%s] bad format", pfilecont);
            goto fail;
        }
        if (isdigit(*pcurptr)) {
            pcurptr -= 1;
            continue;
        } else if (*pcurptr == ' ' || *pcurptr == '\t') {
            break;
        }
        ret = -ERROR_BAD_FILE_TYPE;
        ERROR_INFO("[%s] bad format", pfilecont);
        goto fail;
    }

    /*now we should copy the line we add pcurptr*/
    cmdlinesize = (int)((pcurptr + 1) - ppassptr);
    pcmdline = (char*)malloc((size_t)(cmdlinesize + 10));
    if (pcmdline == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not malloc[%d] error[%d]", cmdlinesize + 10, ret);
        goto fail;
    }
    memset(pcmdline, 0, (size_t)(cmdlinesize + 10));
    memcpy(pcmdline, ppassptr, (size_t)cmdlinesize);

    ret = AnsiToUnicode(pcmdline, &pucmdline, &ucmdlinesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pargv = (wchar_t**)CommandLineToArgvW(pucmdline, &argvnum);
    if (pargv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not pass [%s] to argv error[%d]", pcmdline, ret);
        goto fail;
    } else if (argvnum < 1) {
        ret = -ERROR_INVALID_FIELD_IN_PARAMETER_LIST;
        ERROR_INFO("[%s] param %d", pcmdline, argvnum);
        goto fail;
    }

try_again:
    namelen = 0;
    pcurptr = (char*)ppretargv;
    if (pcurptr == NULL || retsize < (int)(sizeof(char*)*argvnum + 1024) ) {
        if (retsize < (int)((sizeof(char*) * argvnum) + 1024)) {
            retsize = 1024 + (int)(sizeof(char*) * argvnum);
        }
        if (ppretargv && ppretargv != *pppargv) {
            free(ppretargv);
        }
        ppretargv = NULL;
        ppretargv = (char**) malloc((size_t)retsize);
        if (ppretargv == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not malloc [%d] error[%d]", retsize, ret);
            goto fail;
        }
    }
    memset(ppretargv, 0, (size_t)retsize);
    pcurptr = (char*)ppretargv;
    /*to skip*/
    pcurptr += argvnum * sizeof(char*);
    filllen = retsize - (int)(argvnum * sizeof(char*));
    for (i = 0; i < argvnum; i++) {
        ret = UnicodeToAnsi(pargv[i], &argv0, &argv0size);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        curlen = (int)strlen(argv0) + 1;
        if ((namelen + curlen) > filllen) {
            retsize <<= 1;
            if (ppretargv && ppretargv != *pppargv) {
                free(ppretargv);
            }
            ppretargv = NULL;
            goto try_again;
        }
        strncpy_s(pcurptr, (size_t)(filllen - namelen), argv0, (size_t)(filllen - namelen));
        ppretargv[i] = pcurptr;
        pcurptr += curlen;
        namelen += curlen;
    }

    UnicodeToAnsi(NULL, &argv0, &argv0size);
    if (pargv) {
        LocalFree(pargv);
    }
    pargv = NULL;
    AnsiToUnicode(NULL, &pucmdline, &ucmdlinesize);
    if (pcmdline) {
        free(pcmdline);
    }
    pcmdline = NULL;
    cmdlinesize = 0;
    read_file_encoded(NULL, &pfilecont, &filelen);
    if (pcmd) {
        free(pcmd);
    }
    pcmd = NULL;
    if (tempfile != NULL) {
        delete_file(tempfile);
    }
    mktempfile_safe(NULL, &tempfile, &tempsize);

    if (*pppargv && *pppargv != ppretargv) {
        free(*pppargv);
    }
    *pppargv = ppretargv;
    *pargvsize = retsize;
    return argvnum;
fail:
    UnicodeToAnsi(NULL, &argv0, &argv0size);
    if (pargv) {
        LocalFree(pargv);
    }
    pargv = NULL;
    argvnum = 0;
    AnsiToUnicode(NULL, &pucmdline, &ucmdlinesize);
    if (pcmdline) {
        free(pcmdline);
    }
    pcmdline = NULL;
    cmdlinesize = 0;
    read_file_encoded(NULL, &pfilecont, &filelen);
    if (pcmd) {
        free(pcmd);
    }
    pcmd = NULL;
    if (tempfile != NULL) {
        delete_file(tempfile);
    }
    mktempfile_safe(NULL, &tempfile, &tempsize);
    if (ppretargv && ppretargv != *pppargv) {
        free(ppretargv);
    }
    ppretargv = NULL;
    SETERRNO(-ret);
    return ret;
}

#define PROC_MAGIC        0x33898221

#ifdef __PROC_DEBUG__
#define CHECK_PROC_MAGIC(proc) ((proc) && (proc)->m_magic == PROC_MAGIC)
#define SET_PROC_MAGIC(proc)  do { if ((proc) != NULL) { (proc)->m_magic = PROC_MAGIC;}} while(0)
#else
#define CHECK_PROC_MAGIC(proc) ((proc) && 1)
#define SET_PROC_MAGIC(proc)
#endif

#define PIPE_NONE                0
#define PIPE_READY               1
#define PIPE_WAIT_READ           2
#define PIPE_WAIT_WRITE          3
#define PIPE_WAIT_CONNECT        4




typedef struct __pipe_server {
    HANDLE m_pipesvr;
    HANDLE m_evt;
    HANDLE m_pipecli;
    char* m_pipename;
    OVERLAPPED m_ov;
    int m_pipesize;
    int m_wr;
    int m_state;
    int m_reserv1;
} pipe_server_t, *ppipe_server_t;


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

void __free_pipe_server(ppipe_server_t *ppsvr)
{
    char* pipename = NULL;
    BOOL bret;
    int ret;
    ppipe_server_t psvr;
    if (ppsvr && *ppsvr) {
        psvr = *ppsvr;
        if (psvr->m_pipename) {
            pipename = psvr->m_pipename;
        } else {
            pipename = "none";
        }

        if (psvr->m_state == PIPE_WAIT_CONNECT ||
                psvr->m_state == PIPE_WAIT_READ ||
                psvr->m_state == PIPE_WAIT_WRITE) {
            bret = CancelIoEx(psvr->m_pipesvr, &(psvr->m_ov));
            if (!bret) {
                GETERRNO(ret);
                ERROR_INFO("cancel [%s] [%d] error[%d]", pipename, psvr->m_state, ret);
            }
        }
        psvr->m_state = PIPE_NONE;
        __close_handle_note(&(psvr->m_evt), "%s evt", pipename);
        __close_handle_note(&(psvr->m_pipecli), "%s child", pipename);
        __close_handle_note(&(psvr->m_pipesvr), "%s parent", pipename);
        snprintf_safe(&(psvr->m_pipename), &(psvr->m_pipesize), NULL);
        memset(&(psvr->m_ov), 0, sizeof(psvr->m_ov));
        free(psvr);
        *ppsvr = NULL;
    }
}

int __connect_pipe(char* name, int wr, HANDLE* pcli)
{
    int ret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    HANDLE phd = NULL;
    BOOL bret;
    DWORD omode;
    SECURITY_ATTRIBUTES sa;

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

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    phd = CreateFile(ptname, omode, 0, &sa, OPEN_EXISTING, 0, NULL);
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
        //pmode = PIPE_TYPE_MESSAGE | PIPE_WAIT;
        pmode = PIPE_TYPE_MESSAGE ;
    } else {
        omode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        //pmode = PIPE_TYPE_MESSAGE  | PIPE_WAIT;
        pmode = PIPE_TYPE_MESSAGE;
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
        //ok so we got ready
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



ppipe_server_t __alloc_pipe_server(int wr, const char* fmt, ...)
{
    ppipe_server_t psvr = NULL;
    int ret;
    va_list ap;
    char* cliname = NULL;
    int clisize = 0;
    if (fmt == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    psvr = (ppipe_server_t) malloc(sizeof(*psvr));
    if (psvr == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*psvr), ret);
        goto fail;
    }
    memset(psvr, 0 , sizeof(*psvr));
    psvr->m_pipesvr = NULL;
    psvr->m_evt = NULL;
    psvr->m_pipecli = NULL;
    memset(&(psvr->m_ov), 0 , sizeof(psvr->m_ov));
    psvr->m_pipename = NULL;
    psvr->m_pipesize = 0;
    psvr->m_wr = wr;
    psvr->m_state = PIPE_NONE;

    va_start(ap, fmt);
    ret = vsnprintf_safe(&(psvr->m_pipename), &(psvr->m_pipesize), fmt, ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __create_pipe(psvr->m_pipename, wr, &(psvr->m_pipesvr), &(psvr->m_ov), &(psvr->m_evt), &(psvr->m_state));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    ret = __connect_pipe(psvr->m_pipename, wr ? 0 : 1, &(psvr->m_pipecli));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    snprintf_safe(&cliname, &clisize, NULL);
    return psvr;
fail:
    snprintf_safe(&cliname, &clisize, NULL);
    __free_pipe_server(&psvr);
    return NULL;
}


int __get_temp_pipe_name(char* prefix, char** pptmp, int *psize)
{
    char* pwholepath = 0;
    int wholesize = 0;
    char* pcurptr;
    int retlen = 0;
    char* prettmp = NULL;
    int retsize = 0;
    int ret;
    if (prefix == NULL) {
        if (pptmp && *pptmp) {
            free(*pptmp);
            *pptmp = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (pptmp == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    prettmp = *pptmp;
    retsize = *psize;

    ret = mktempfile_safe(prefix, &pwholepath, &wholesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pcurptr = pwholepath;
    pcurptr += strlen(pwholepath);
    pcurptr -- ;

    while (pcurptr != pwholepath) {
        if (*pcurptr == '\\') {
            pcurptr ++;
            break;
        }
        pcurptr --;
    }

    retlen = (int)strlen(pcurptr);
    if (prettmp == NULL || retsize < (retlen + 1)) {
        if (retsize < (retlen + 1)) {
            retsize = retlen + 1;
        }
        prettmp = (char*) malloc((size_t)retsize);
        if (prettmp == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }

    memcpy(prettmp, pcurptr, (size_t)(retlen + 1));
    if (*pptmp && *pptmp != prettmp) {
        free(*pptmp);
    }
    *pptmp = prettmp;
    *psize = retsize;
    mktempfile_safe(NULL, &pwholepath, &wholesize);
    return retlen;
fail:
    if (prettmp && prettmp != *pptmp) {
        free(prettmp);
    }
    prettmp = NULL;

    mktempfile_safe(NULL, &pwholepath, &wholesize);
    SETERRNO(ret);
    return ret;
}

int get_temp_pipe_name(char* prefix, char** pptmp, int *psize)
{
    return __get_temp_pipe_name(prefix, pptmp, psize);
}

typedef struct __proc_handle {
#ifdef __PROC_DEBUG__
    uint32_t m_magic;
    uint32_t m_reserv1;
#endif
    /*handle for event overlapped*/
    ppipe_server_t m_stdinpipe;
    ppipe_server_t m_stdoutpipe;
    ppipe_server_t m_stderrpipe;

    HANDLE m_stdinnull;
    HANDLE m_stdoutnull;
    HANDLE m_stderrnull;

    HANDLE m_prochd;
    char* m_cmdline;

    int m_exitcode;
    int m_cmdlinesize;
    int m_exited;
    int m_reserv2;
} proc_handle_t, *pproc_handle_t;


int __get_command_lines(char** ppcmdline, int *psize, char* prog[])
{
    int i;
    char* qstr = NULL;
    int qsize = 0;
    int ret;
    if (prog == NULL || prog[0] == NULL) {
        snprintf_safe(ppcmdline, psize, NULL);
        return 0;
    }

    ret = quote_string(&qstr, &qsize, "%s", prog[0]);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    ret = snprintf_safe(ppcmdline, psize, "%s", qstr);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    for (i = 1; prog[i] != NULL; i++) {
        ret = quote_string(&qstr, &qsize, "%s", prog[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        ret = append_snprintf_safe(ppcmdline, psize, " %s", qstr);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }
    DEBUG_INFO("cmdline [%s]", *ppcmdline);
    quote_string(&qstr, &qsize, NULL);
    return ret;

fail:
    quote_string(&qstr, &qsize, NULL);
    SETERRNO(ret);
    return ret;
}


void __free_proc_handle(pproc_handle_t* ppproc)
{
    pproc_handle_t pproc = NULL;
    BOOL bret;
    int i;
    int maxcnt = 5;
    if (ppproc != NULL && *ppproc != NULL) {
        pproc = *ppproc;
        ASSERT_IF(CHECK_PROC_MAGIC(pproc));
        __free_pipe_server(&(pproc->m_stdinpipe));
        __free_pipe_server(&(pproc->m_stdoutpipe));
        __free_pipe_server(&(pproc->m_stderrpipe));
        __close_handle_note(&(pproc->m_stdinnull), "stdin null");
        __close_handle_note(&(pproc->m_stdoutnull), "stdout null");
        __close_handle_note(&(pproc->m_stderrnull), "stderr null");
        if (pproc->m_prochd != INVALID_HANDLE_VALUE &&
                pproc->m_prochd != NULL && pproc->m_exited == 0) {
            for (i = 0; i < maxcnt; i++) {
                bret = GetExitCodeProcess(pproc->m_prochd, (DWORD*) & (pproc->m_exitcode));
                if (bret) {
                    break;
                }
                TerminateProcess(pproc->m_prochd, 5);
            }
            if (i == maxcnt) {
                ERROR_INFO("can not terminate process");
            }
            pproc->m_exited = 1;
        }
        __close_handle_note(&(pproc->m_prochd), "proc handle");
        snprintf_safe(&(pproc->m_cmdline), &(pproc->m_cmdlinesize), NULL);

        free(pproc);
        *ppproc = NULL;
    }
    return;
}

pproc_handle_t __alloc_proc_handle(void)
{
    pproc_handle_t pproc = NULL;
    int ret;
    pproc = (pproc_handle_t) malloc(sizeof(*pproc));
    if (pproc == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", sizeof(*pproc), ret);
        goto fail;
    }
    memset(pproc, 0 , sizeof(*pproc));
    SET_PROC_MAGIC(pproc);
    pproc->m_stdinpipe = NULL;
    pproc->m_stdoutpipe = NULL;
    pproc->m_stderrpipe = NULL;
    pproc->m_stdinnull = NULL;
    pproc->m_stdoutnull = NULL;
    pproc->m_stderrnull = NULL;
    pproc->m_prochd = INVALID_HANDLE_VALUE;
    pproc->m_exited = 1;
    pproc->m_exitcode = 1;

    pproc->m_cmdline = NULL;
    pproc->m_cmdlinesize = NULL;

    return pproc;
fail:
    __free_proc_handle(&pproc);
    SETERRNO(ret);
    return NULL;
}


int __create_nul(HANDLE* rfd, HANDLE *wfd, const char* fmt, ...)
{
    HANDLE hd = INVALID_HANDLE_VALUE;
    DWORD acsflag = 0;
    char* errstr = NULL;
    va_list ap;
    int errsize = 0;
    int ret, res;
    if (rfd) {
        acsflag = GENERIC_READ;
    } else if (wfd) {
        acsflag = GENERIC_WRITE;
    }
    if (acsflag != 0) {
        hd = CreateFile(_T("nul:"), acsflag, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hd == INVALID_HANDLE_VALUE) {
            GETERRNO(ret);
            if (fmt != NULL) {
                va_start(ap, fmt);
                res = vsnprintf_safe(&errstr, &errsize, fmt, ap);
                if (res >= 0) {
                    ERROR_INFO("%s error[%d]", errstr, ret);
                }
                vsnprintf_safe(&errstr, &errsize, NULL, ap);
            }
            goto fail;
        }

        if (rfd) {
            *rfd = hd;
        } else if (wfd) {
            *wfd = hd;
        }
    }

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __create_flags(pproc_handle_t pproc, int flags)
{
    int ret;
    char* pipename = NULL;
    int pipesize = 0;
    char* tempname = NULL;
    int tempsize = 0;

    ret = __get_temp_pipe_name("pipe", &tempname, &tempsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (flags & PROC_PIPE_STDIN) {
        if (pproc->m_stdinpipe != NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }

        ret = snprintf_safe(&pipename, &pipesize, "\\\\.\\pipe\\%s_stdin", tempname);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        pproc->m_stdinpipe = __alloc_pipe_server(1, pipename);
        if (pproc->m_stdinpipe == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    } else if (flags & PROC_STDIN_NULL) {
        ret = __create_nul(&(pproc->m_stdinnull), NULL, "null child stdin");
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    if (flags & PROC_PIPE_STDOUT) {
        if (pproc->m_stdoutpipe != NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }

        ret = snprintf_safe(&pipename, &pipesize, "\\\\.\\pipe\\%s_stdout", tempname);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        pproc->m_stdoutpipe = __alloc_pipe_server(0, pipename);
        if (pproc->m_stdoutpipe == NULL) {
            GETERRNO(ret);
            goto fail;
        }

    } else if (flags & PROC_STDOUT_NULL) {
        ret = __create_nul(NULL, &(pproc->m_stdoutnull), "null child stdout");
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    if (flags & PROC_PIPE_STDERR) {
        if (pproc->m_stderrpipe != NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }

        ret = snprintf_safe(&pipename, &pipesize, "\\\\.\\pipe\\%s_stderr", tempname);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        pproc->m_stderrpipe = __alloc_pipe_server(0, pipename);
        if (pproc->m_stderrpipe == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    } else if (flags & PROC_STDERR_NULL) {
        ret = __create_nul(NULL, &(pproc->m_stderrnull), "null child stderr");
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    snprintf_safe(&pipename, &pipesize, NULL);
    __get_temp_pipe_name(NULL, &tempname, &tempsize);
    return 0;
fail:
    snprintf_safe(&pipename, &pipesize, NULL);
    __get_temp_pipe_name(NULL, &tempname, &tempsize);
    SETERRNO(ret);
    return ret;
}

int __start_proc(pproc_handle_t pproc, int createflag, char* prog)
{
    PROCESS_INFORMATION  *pinfo = NULL;
    STARTUPINFOW *pstartinfo = NULL;
    int usehd = 0;
    DWORD dwflag = 0;
    BOOL bret;
    wchar_t *wcmdline = NULL;
    int wcmdsize = 0;
    int res;
    int ret;

    ret = snprintf_safe(&(pproc->m_cmdline), &(pproc->m_cmdlinesize), "%s", prog);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /*now we should make this handle*/
    pinfo = (PROCESS_INFORMATION*) malloc(sizeof(*pinfo));
    if (pinfo == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", sizeof(*pinfo), ret);
        goto fail;
    }
    memset(pinfo, 0 , sizeof(*pinfo));

    pstartinfo = (STARTUPINFOW*) malloc(sizeof(*pstartinfo));
    if (pstartinfo == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", sizeof(*pstartinfo), ret);
        goto fail;
    }
    memset(pstartinfo, 0 , sizeof(*pstartinfo));

    pstartinfo->cb = sizeof(*pstartinfo);
    if (pproc->m_stdinpipe != NULL) {
        pstartinfo->hStdInput  = pproc->m_stdinpipe->m_pipecli;
        usehd ++;
    } else if (pproc->m_stdinnull != NULL && pproc->m_stdinnull != INVALID_HANDLE_VALUE) {
        pstartinfo->hStdInput = pproc->m_stdinnull;
        usehd ++;
    }

    if (pproc->m_stdoutpipe != NULL) {
        pstartinfo->hStdOutput = pproc->m_stdoutpipe->m_pipecli;
        usehd ++;
    } else if (pproc->m_stdoutnull != NULL && pproc->m_stdoutnull != INVALID_HANDLE_VALUE) {
        pstartinfo->hStdOutput = pproc->m_stdoutnull;
        usehd ++;
    }

    if (pproc->m_stderrpipe != NULL) {
        pstartinfo->hStdError = pproc->m_stderrpipe->m_pipecli;
        usehd ++;
    } else if (pproc->m_stderrnull != NULL && pproc->m_stderrnull != INVALID_HANDLE_VALUE) {
        pstartinfo->hStdError = pproc->m_stderrnull;
        usehd ++;
    }

    if (usehd > 0) {
        pstartinfo->dwFlags  |= STARTF_USESTDHANDLES;
    }

    if (usehd > 0) {
        if (pstartinfo->hStdInput == NULL) {
            pstartinfo->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        }

        if (pstartinfo->hStdOutput == NULL) {
            pstartinfo->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        }

        if (pstartinfo->hStdError == NULL) {
            pstartinfo->hStdError = GetStdHandle(STD_ERROR_HANDLE);
        }
    }

    if (createflag & PROC_NO_WINDOW) {
        dwflag |= CREATE_NO_WINDOW;
        pstartinfo->dwFlags |= STARTF_USESHOWWINDOW;
        pstartinfo->wShowWindow = SW_HIDE;
    }

    ret = AnsiToUnicode(pproc->m_cmdline, &wcmdline, &wcmdsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    DEBUG_INFO("run cmd [%s]", pproc->m_cmdline);
    bret = CreateProcessW(NULL, wcmdline,
                          NULL, NULL,
                          TRUE, dwflag,
                          NULL, NULL,
                          pstartinfo, pinfo);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("create [%s] error[%d]", pproc->m_cmdline
                   , ret);
        goto fail;
    }

    /*now started*/
    pproc->m_exited = 0;
    pproc->m_prochd = pinfo->hProcess;

    if (pinfo->hThread != NULL) {
        bret = CloseHandle(pinfo->hThread);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("close thread handle [%p] error[%d]", pinfo->hThread, ret);
            goto fail;
        }
        pinfo->hThread = NULL;
    }

    DEBUG_INFO("start [%s] ok", pproc->m_cmdline);

    AnsiToUnicode(NULL, &wcmdline, &wcmdsize);
    if (pinfo) {
        free(pinfo);
    }
    pinfo = NULL;
    if (pstartinfo) {
        free(pstartinfo);
    }
    pstartinfo = NULL;

    return 0;
fail:
    AnsiToUnicode(NULL, &wcmdline, &wcmdsize);
    if (pinfo) {
        if (pinfo->hThread != NULL && pinfo->hThread != INVALID_HANDLE_VALUE) {
            bret = CloseHandle(pinfo->hThread);
            if (!bret) {
                GETERRNO(res);
                ERROR_INFO("close thread [%p] error[%d]", pinfo->hThread, res);
            }
        }
        pinfo->hThread = NULL;

        free(pinfo);
    }
    pinfo = NULL;
    if (pstartinfo) {
        free(pstartinfo);
    }
    pstartinfo = NULL;
    SETERRNO(ret);
    return ret;
}


void __free_wts_token(HANDLE *phtok)
{
    if (phtok && *phtok)  {
        CloseHandle(*phtok);
        *phtok = NULL;
    }
    return ;
}


int __get_wts_token(HANDLE* phtok)
{
    HANDLE curtok = NULL;
    HANDLE copytok = NULL;
    int ret;
    PWTS_SESSION_INFO psessinfo = NULL;
    PWTS_SESSION_INFO cursess = NULL;
    DWORD cnt = 0;
    BOOL bret;
    DWORD i;
    int sessid = -1;
    int enabled = 0;

    if (phtok == NULL || *phtok != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    bret = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &psessinfo, &cnt);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not enum session error[%d]", ret);
        goto fail;
    }

    for (i = 0; i < cnt; i++) {
        cursess = &(psessinfo[i]);
        if (cursess->State == WTSActive) {
            sessid = (int)cursess->SessionId;
            break;
        }
    }

    if (sessid < 0) {
        ret = -ERROR_NOT_FOUND;
        ERROR_INFO("can not find active session");
        goto fail;
    }

    DEBUG_INFO("active session %d", sessid);

    ret = enable_tcb_priv();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    enabled = 1;

    bret = WTSQueryUserToken((ULONG)sessid, &curtok);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not query [%d] tok error[%d]", sessid, ret);
        goto fail;
    }

    bret = DuplicateTokenEx(curtok, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS | MAXIMUM_ALLOWED
                            , 0, SecurityImpersonation, TokenPrimary, &copytok);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("dup [%d] sess tok [0x%x] error[%d]", sessid, curtok, copytok);
        goto fail;
    }

    *phtok = copytok;

    if (curtok) {
        CloseHandle(curtok);
    }
    curtok = NULL;

    WTSFreeMemory(psessinfo);
    psessinfo = NULL;
    cnt = 0;
    if (enabled) {
        disable_tcb_priv();
    }
    enabled = 0;

    return 0;
fail:
    if (copytok) {
        CloseHandle(copytok);
    }
    copytok = NULL;

    if (curtok) {
        CloseHandle(curtok);
    }
    curtok = NULL;

    if (psessinfo) {
        WTSFreeMemory(psessinfo);
    }
    psessinfo = NULL;
    cnt = 0;

    if (enabled) {
        disable_tcb_priv();
    }
    enabled = 0;
    SETERRNO(ret);
    return ret;
}



int __start_proc_wts(pproc_handle_t pproc, int createflag, char* prog)
{
    PROCESS_INFORMATION  *pinfo = NULL;
    STARTUPINFOW *pstartinfo = NULL;
    int usehd = 0;
    DWORD dwflag = 0;
    BOOL bret;
    wchar_t *wcmdline = NULL;
    int wcmdsize = 0;
    int res;
    int ret;
    HANDLE husertok = NULL;
    void* penvblock = NULL;

    ret = __get_wts_token(&husertok);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    DEBUG_INFO("husertok 0x%x", husertok);

    bret = CreateEnvironmentBlock(&penvblock, husertok, FALSE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("create environment block error[%d]", ret);
        goto fail;
    }


    ret = snprintf_safe(&(pproc->m_cmdline), &(pproc->m_cmdlinesize), "%s", prog);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /*now we should make this handle*/
    pinfo = (PROCESS_INFORMATION*) malloc(sizeof(*pinfo));
    if (pinfo == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", sizeof(*pinfo), ret);
        goto fail;
    }
    memset(pinfo, 0 , sizeof(*pinfo));

    pstartinfo = (STARTUPINFOW*) malloc(sizeof(*pstartinfo));
    if (pstartinfo == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", sizeof(*pstartinfo), ret);
        goto fail;
    }
    memset(pstartinfo, 0 , sizeof(*pstartinfo));

    pstartinfo->cb = sizeof(*pstartinfo);
    if (pproc->m_stdinpipe != NULL) {
        pstartinfo->hStdInput  = pproc->m_stdinpipe->m_pipecli;
        usehd ++;
    } else if (pproc->m_stdinnull != NULL && pproc->m_stdinnull != INVALID_HANDLE_VALUE) {
        pstartinfo->hStdInput = pproc->m_stdinnull;
        usehd ++;
    }

    if (pproc->m_stdoutpipe != NULL) {
        pstartinfo->hStdOutput = pproc->m_stdoutpipe->m_pipecli;
        usehd ++;
    } else if (pproc->m_stdoutnull != NULL && pproc->m_stdoutnull != INVALID_HANDLE_VALUE) {
        pstartinfo->hStdOutput = pproc->m_stdoutnull;
        usehd ++;
    }

    if (pproc->m_stderrpipe != NULL) {
        pstartinfo->hStdError = pproc->m_stderrpipe->m_pipecli;
        usehd ++;
    } else if (pproc->m_stderrnull != NULL && pproc->m_stderrnull != INVALID_HANDLE_VALUE) {
        pstartinfo->hStdError = pproc->m_stderrnull;
        usehd ++;
    }

    //pstartinfo->lpDesktop = L"winsta0\\default";

    if (usehd > 0) {
        pstartinfo->dwFlags  |= STARTF_USESTDHANDLES;
    }

    if (usehd > 0) {
        if (pstartinfo->hStdInput == NULL) {
            pstartinfo->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        }

        if (pstartinfo->hStdOutput == NULL) {
            pstartinfo->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        }

        if (pstartinfo->hStdError == NULL) {
            pstartinfo->hStdError = GetStdHandle(STD_ERROR_HANDLE);
        }
    }

    if (createflag & PROC_NO_WINDOW) {
        dwflag |= CREATE_NO_WINDOW;
    }

    dwflag |= CREATE_UNICODE_ENVIRONMENT;

    ret = AnsiToUnicode(pproc->m_cmdline, &wcmdline, &wcmdsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    DEBUG_INFO("run cmd [%s]", pproc->m_cmdline);
    bret = CreateProcessAsUserW(husertok,
                                NULL,
                                wcmdline,
                                /*process security attr*/
                                NULL,
                                /*thread security attr*/
                                NULL,
                                /*inheritable*/
                                FALSE,
                                /*create flag*/
                                dwflag,
                                penvblock,
                                NULL,
                                pstartinfo, pinfo);
#if   0
    bret = CreateProcessW(NULL, wcmdline,
                          NULL, NULL,
                          TRUE, dwflag,
                          NULL, NULL,
                          pstartinfo, pinfo);
#endif
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("create [%s] error[%d]", pproc->m_cmdline
                   , ret);
        goto fail;
    }

    /*now started*/
    pproc->m_exited = 0;
    pproc->m_prochd = pinfo->hProcess;

    if (pinfo->hThread != NULL) {
        bret = CloseHandle(pinfo->hThread);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("close thread handle [%p] error[%d]", pinfo->hThread, ret);
            goto fail;
        }
        pinfo->hThread = NULL;
    }

    DEBUG_INFO("start [%s] ok", pproc->m_cmdline);

    AnsiToUnicode(NULL, &wcmdline, &wcmdsize);
    if (pinfo) {
        free(pinfo);
    }
    pinfo = NULL;
    if (pstartinfo) {
        free(pstartinfo);
    }
    pstartinfo = NULL;

    if (penvblock) {
        DestroyEnvironmentBlock(penvblock);
    }
    penvblock = NULL;
    __free_wts_token(&husertok);

    return 0;
fail:
    AnsiToUnicode(NULL, &wcmdline, &wcmdsize);
    if (pinfo) {
        if (pinfo->hThread != NULL && pinfo->hThread != INVALID_HANDLE_VALUE) {
            bret = CloseHandle(pinfo->hThread);
            if (!bret) {
                GETERRNO(res);
                ERROR_INFO("close thread [%p] error[%d]", pinfo->hThread, res);
            }
        }
        pinfo->hThread = NULL;

        free(pinfo);
    }
    pinfo = NULL;
    if (pstartinfo) {
        free(pstartinfo);
    }
    pstartinfo = NULL;

    if (penvblock) {
        DestroyEnvironmentBlock(penvblock);
    }
    penvblock = NULL;

    __free_wts_token(&husertok);
    SETERRNO(ret);
    return ret;
}


void* start_cmd_single(int createflag, char* prog)
{
    pproc_handle_t pproc = NULL;
    int ret;

    if (prog == NULL || prog[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    pproc = __alloc_proc_handle();
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    ret = __create_flags(pproc, createflag);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __start_proc(pproc, createflag, prog);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return (void*) pproc;
fail:
    __free_proc_handle(&pproc);
    SETERRNO(ret);
    return NULL;
}


void* start_cmdv(int createflag, char* prog[])
{
    pproc_handle_t pproc = NULL;
    int ret;
    char* pcmdline = NULL;
    int cmdlinesize = 0;

    if (prog == NULL || prog[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret = __get_command_lines(&pcmdline, &cmdlinesize, prog);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pproc = (pproc_handle_t) start_cmd_single(createflag, pcmdline);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    __get_command_lines(&pcmdline, &cmdlinesize, NULL);
    return (void*) pproc;
fail:
    __free_proc_handle(&pproc);
    __get_command_lines(&pcmdline, &cmdlinesize, NULL);
    SETERRNO(ret);
    return NULL;
}



void* start_cmd(int createflag, const char* prog, ...)
{
    char** argv = NULL;
    int argc = 0;
    void* pproc = NULL;
    char* curarg;
    int ret;
    int i;
    va_list ap, oldap;
    va_start(ap, prog);
    va_copy(oldap, ap);
    argc = 4;
try_again:
    va_copy(ap, oldap);
    if (argv != NULL) {
        free(argv);
    }
    argv = NULL;
    argv = (char**) malloc(sizeof(*argv) * argc);
    if (argv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*argv)*argc, ret);
        goto fail;
    }
    memset(argv, 0 , sizeof(*argv) * argc);
    argv[0] = (char*)prog;
    i = 1;
    for (i = 1; i < argc; i++) {
        curarg = va_arg(ap, char*);
        if (curarg == NULL) {
            break;
        }
        argv[i] = curarg;
    }

    if (i == argc ) {
        /*filled so we should expand*/
        argc <<= 1;
        goto try_again;
    }

    pproc = start_cmdv(createflag, argv);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    if (argv != NULL) {
        free(argv);
    }
    argv = NULL;
    return pproc;
fail:
    if (argv != NULL) {
        free(argv);
    }
    argv = NULL;
    if (pproc) {
        __free_proc_handle((pproc_handle_t*)&pproc);
    }
    SETERRNO(ret);
    return NULL;
}


/********************************************
wts mode
********************************************/

void* wts_start_cmd_single(int createflag, char* prog)
{
    pproc_handle_t pproc = NULL;
    int ret;

    if (prog == NULL || prog[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    pproc = __alloc_proc_handle();
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    ret = __create_flags(pproc, createflag);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __start_proc_wts(pproc, createflag, prog);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return (void*) pproc;
fail:
    __free_proc_handle(&pproc);
    SETERRNO(ret);
    return NULL;
}


void* wts_start_cmdv(int createflag, char* prog[])
{
    pproc_handle_t pproc = NULL;
    int ret;
    char* pcmdline = NULL;
    int cmdlinesize = 0;

    if (prog == NULL || prog[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret = __get_command_lines(&pcmdline, &cmdlinesize, prog);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pproc = (pproc_handle_t) wts_start_cmd_single(createflag, pcmdline);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    __get_command_lines(&pcmdline, &cmdlinesize, NULL);
    return (void*) pproc;
fail:
    __free_proc_handle(&pproc);
    __get_command_lines(&pcmdline, &cmdlinesize, NULL);
    SETERRNO(ret);
    return NULL;
}

void* wts_start_cmd(int createflag, const char* prog, ...)
{
    char** argv = NULL;
    int argc = 0;
    void* pproc = NULL;
    char* curarg;
    int ret;
    int i;
    va_list ap, oldap;
    va_start(ap, prog);
    va_copy(oldap, ap);
    argc = 4;
try_again:
    va_copy(ap, oldap);
    if (argv != NULL) {
        free(argv);
    }
    argv = NULL;
    argv = (char**) malloc(sizeof(*argv) * argc);
    if (argv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*argv)*argc, ret);
        goto fail;
    }
    memset(argv, 0 , sizeof(*argv) * argc);
    argv[0] = (char*)prog;
    i = 1;
    for (i = 1; i < argc; i++) {
        curarg = va_arg(ap, char*);
        if (curarg == NULL) {
            break;
        }
        argv[i] = curarg;
    }

    if (i == argc ) {
        /*filled so we should expand*/
        argc <<= 1;
        goto try_again;
    }

    pproc = wts_start_cmdv(createflag, argv);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    if (argv != NULL) {
        free(argv);
    }
    argv = NULL;
    return pproc;
fail:
    if (argv != NULL) {
        free(argv);
    }
    argv = NULL;
    if (pproc) {
        __free_proc_handle((pproc_handle_t*)&pproc);
    }
    SETERRNO(ret);
    return NULL;
}


int kill_proc(void* proc, int *exitcode)
{
    BOOL bret;
    int i;
    int maxcnt = 5;
    int ret;
    pproc_handle_t pproc = (pproc_handle_t)proc;
    if (!CHECK_PROC_MAGIC(pproc)) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pproc->m_exited == 0) {
        for (i = 0; i < maxcnt; i++) {
            bret = GetExitCodeProcess((pproc->m_prochd), (DWORD*) & (pproc->m_exitcode));
            if (bret) {
                pproc->m_exited = 1;
                break;
            }
            TerminateProcess(pproc->m_prochd, 5);
        }

        if (pproc->m_exited == 0) {
            ret = -ERROR_PROC_NOT_FOUND;
            SETERRNO(ret);
            return ret;
        }
    }

    if (exitcode) {
        *exitcode = pproc->m_exitcode;
    }

    return 0;
}

int get_proc_exit(void* proc, int *exitcode)
{
    pproc_handle_t pproc = (pproc_handle_t) proc;
    int ret;
    BOOL bret;
    DWORD exitret;
    if (!CHECK_PROC_MAGIC(pproc)) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pproc->m_exited == 0) {
        SETERRNO(0);
        bret = GetExitCodeProcess(pproc->m_prochd, &exitret);
        if (bret) {
            if (exitret != STILL_ACTIVE) {
                pproc->m_exited = 1;
                pproc->m_exitcode = (int)exitret;
                DEBUG_INFO("exit code %d", exitret);
                if (exitcode) {
                    *exitcode = (int)exitret;
                }
                return 0;
            }
        }
        GETERRNO_DIRECT(ret);
        if (ret != 0) {
            ERROR_INFO("get exit code error[%d]", ret);
        }
        ret = -ERROR_ALREADY_EXISTS;
        SETERRNO(ret);
        return ret;
    }
    if (exitcode) {
        *exitcode = pproc->m_exitcode;
    }
    return 0;
}

int __write_file_sync(HANDLE hd, OVERLAPPED *pov, char* ptr, int size, int *pending)
{
    char* pcur = ptr;
    int writelen = 0;
    int ret;
    BOOL bret;
    DWORD rsize = 0;
    DWORD wsize = (DWORD)size;

    while (writelen < size) {
        bret = WriteFile(hd, pcur, wsize, &rsize, pov);
        if (!bret) {
            GETERRNO(ret);
            if (ret == -ERROR_IO_PENDING) {
                if (pending) {
                    *pending = 1;
                }
                DEBUG_INFO("writelen[%d]", writelen);
                return writelen;
            }
            ERROR_INFO("write ret [%d]", ret);
            goto fail;
        }
        DEBUG_INFO("rsize [%d]", rsize);
        pcur += rsize;
        wsize -= rsize;
        writelen += rsize;
    }

    DEBUG_INFO("outbuf [%d]", rsize);
    bret = FlushFileBuffers(hd);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("flush buffer error[%d]", ret);
        goto fail;
    }

    if (pending) {
        *pending = 0;
    }

    return writelen;
fail:
    SETERRNO(ret);
    return ret;
}

int __read_file_sync(HANDLE hd, OVERLAPPED* pov, char* pinbuf, int size, int *pending)
{
    BOOL bret;
    int ret;
    DWORD rsize = 0;

    bret = ReadFile(hd, pinbuf, (DWORD)size, &rsize, pov);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_IO_PENDING) {
            if (pending) {
                *pending = 1;
            }
            return 0;
        } else if (ret != -ERROR_BROKEN_PIPE) {
            ERROR_INFO("read file error[%d]", ret);
            goto fail;
        }
        if (pending) {
            *pending = 2;
        }
        return 0;
    }

    if (pending) {
        *pending = 0;
    }

    return (int)rsize;
fail:
    SETERRNO(ret);
    return ret;
}

int __get_overlapped(HANDLE hd, OVERLAPPED* pov, int *addlen, const char* fmt, ...)
{
    BOOL bret;
    DWORD rsize;
    int ret;
    va_list ap;
    int res;
    char* errstr = NULL;
    int errsize = 0;
    bret = GetOverlappedResult(hd, pov, &rsize, FALSE);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_IO_PENDING) {
            DEBUG_INFO("hd [%d] pending", hd);
            return 1;
        }

        if (fmt != NULL) {
            va_start(ap, fmt);
            res = vsnprintf_safe(&errstr, &errsize, fmt, ap);
            if (res >= 0) {
                ERROR_INFO("%s error [%d]", errstr, ret);
            }
            vsnprintf_safe(&errstr, &errsize, NULL, ap);
        }
        goto fail;
    }

    if (addlen) {
        *addlen += rsize;
    }

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __left_pipe_bytes(HANDLE hd)
{
    BOOL bret;
    DWORD totalbytes;
    int ret;
    bret = PeekNamedPipe(hd, NULL, 0, NULL, &totalbytes, NULL);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not peek error[%d]", ret);
        goto fail;
    }

    return (int)totalbytes;
fail:
    SETERRNO(ret);
    return ret;
}

#define   WRITE_WAIT(vpipename,ptrmem,memlen,memsize)                                             \
    do {                                                                                          \
        if (pproc->vpipename != NULL) {                                                           \
            if (pproc->vpipename->m_state == PIPE_WAIT_CONNECT ||                                 \
                pproc->vpipename->m_state == PIPE_WAIT_WRITE) {                                   \
                waithds[waitnum] = pproc->vpipename->m_evt;                                       \
                waitnum ++;                                                                       \
                DEBUG_INFO("add %s", #vpipename);                                                 \
            } else if (pproc->vpipename->m_state == PIPE_READY) {                                 \
                pending = 0;                                                                      \
                ret = __write_file_sync(pproc->vpipename->m_pipesvr,&(pproc->vpipename->m_ov),    \
                        &(ptrmem[memlen]), (memsize - memlen), &pending);                         \
                if (ret < 0) {                                                                    \
                    GETERRNO(ret);                                                                \
                    goto fail;                                                                    \
                }                                                                                 \
                DEBUG_INFO("ret [%d] write [%d]", ret, (memsize - memlen));                       \
                memlen += ret;                                                                    \
                if (memlen > memsize) {                                                           \
                    ERROR_INFO("write [%s] inlen [%d] insize[%d]",                                \
                        pproc->vpipename->m_pipename, memlen, memsize);                           \
                    memlen = memsize;                                                             \
                }                                                                                 \
                if (memlen == memsize) {                                                          \
                    DEBUG_INFO("close %s", #vpipename);                                           \
                    __close_handle_note(&(pproc->vpipename->m_pipesvr),                           \
                        "close %s",pproc->vpipename->m_pipename);                                 \
                    pproc->vpipename->m_state = PIPE_NONE;                                        \
                } else if (pending) {                                                             \
                    DEBUG_INFO("add %s", #vpipename);                                             \
                    pproc->vpipename->m_state = PIPE_WAIT_WRITE;                                  \
                    waithds[waitnum] = pproc->vpipename->m_evt;                                   \
                    waitnum ++;                                                                   \
                }                                                                                 \
            }                                                                                     \
        }                                                                                         \
    } while(0)

#define  STDIN_WRITE_WAIT()        \
    WRITE_WAIT(m_stdinpipe,pin, inlen, insize)


#define  READ_EXPAND(vpipename,ptrmem, ppmemptr, memlen,memsize,gotolabel)                        \
    do{                                                                                           \
        if (pproc->vpipename != NULL) {                                                           \
            if (pproc->vpipename->m_state == PIPE_WAIT_CONNECT ||                                 \
                pproc->vpipename->m_state == PIPE_WAIT_READ) {                                    \
                waithds[waitnum] = pproc->vpipename->m_evt;                                       \
                waitnum ++;                                                                       \
                DEBUG_INFO("add %s", #vpipename);                                                 \
            } else if (pproc->vpipename->m_state == PIPE_READY) {                                 \
        gotolabel:                                                                                \
                if (ptrmem == NULL || memsize == memlen) {                                        \
                    if (memsize < MIN_BUF_SIZE) {                                                 \
                        memsize = MIN_BUF_SIZE;                                                   \
                    } else {                                                                      \
                        memsize <<= 1;                                                            \
                    }                                                                             \
                    ASSERT_IF(ptmpbuf == NULL);                                                   \
                    ptmpbuf = (char*)malloc((size_t)(memsize));                                   \
                    if (ptmpbuf == NULL) {                                                        \
                        GETERRNO(ret);                                                            \
                        ERROR_INFO("alloc %d error[%d]", memsize, ret);                           \
                        goto fail;                                                                \
                    }                                                                             \
                    memset(ptmpbuf, 0, (size_t)(memsize));                                        \
                    if (memlen > 0) {                                                             \
                        memcpy(ptmpbuf, ptrmem, (size_t)(memlen));                                \
                    }                                                                             \
                    if (ptrmem != NULL && ptrmem != *ppmemptr) {                                  \
                        free(ptrmem);                                                             \
                    }                                                                             \
                    ptrmem = ptmpbuf;                                                             \
                    ptmpbuf = NULL;                                                               \
                }                                                                                 \
                pending = 0;                                                                      \
                ret = __read_file_sync(pproc->vpipename->m_pipesvr,&(pproc->vpipename->m_ov),     \
                        &(ptrmem[memlen]), (memsize- memlen), &pending);                          \
                if (ret < 0) {                                                                    \
                    GETERRNO(ret);                                                                \
                    goto fail;                                                                    \
                }                                                                                 \
                if (ret > 0) {                                                                    \
                    DEBUG_BUFFER_FMT(&(ptrmem[memlen]),ret,"read %s pending %d",                  \
                            #vpipename,pending);                                                  \
                }                                                                                 \
                memlen += ret;                                                                    \
                if (memlen > memsize) {                                                           \
                    ERROR_INFO("read [%s] %s len[%d] %s size [%d]",                               \
                        pproc->vpipename->m_pipename, #vpipename ,memlen,                         \
                        #vpipename, memsize);                                                     \
                    memlen = memsize;                                                             \
                }                                                                                 \
                if (pending == 0) {                                                               \
                    goto gotolabel;                                                               \
                } else if (pending == 2) {                                                        \
                    __close_handle_note(&(pproc->vpipename->m_pipesvr),"%s",                      \
                        pproc->vpipename->m_pipename);                                            \
                    pproc->vpipename->m_state = PIPE_NONE;                                        \
                    DEBUG_INFO("close %s", #vpipename);                                           \
                } else {                                                                          \
                    waithds[waitnum] = pproc->vpipename->m_evt;                                   \
                    waitnum ++;                                                                   \
                    pproc->vpipename->m_state = PIPE_WAIT_READ;                                   \
                    DEBUG_INFO("add %s",#vpipename);                                              \
                }                                                                                 \
            }                                                                                     \
        }                                                                                         \
    }while(0)

#define   STDOUT_READ_EXPAND(gotolabel)                                                           \
    READ_EXPAND(m_stdoutpipe,pretout, ppout,outlen, outsize,gotolabel)

#define   STDERR_READ_EXPAND(gotolabel)                                                           \
    READ_EXPAND(m_stderrpipe,preterr, pperr,errlen, errsize,gotolabel)


#define  WAIT_HANDLE(vpipename,ptrmem,memlen,memsize,waitflag,waitstate)                          \
    do{                                                                                           \
        if (pproc->vpipename != NULL &&                                                           \
            (pproc->vpipename->m_state == PIPE_WAIT_CONNECT ||                                    \
            pproc->vpipename->m_state == waitstate) &&                                            \
            hd == pproc->vpipename->m_evt) {                                                      \
            int lastlen= (memlen);                                                                \
            DEBUG_INFO("handle %s", #vpipename);                                                  \
            ret= __get_overlapped(pproc->vpipename->m_pipesvr,&(pproc->vpipename->m_ov),          \
                    &(memlen),#vpipename" result");                                               \
            if (ret < 0) {                                                                        \
                GETERRNO(ret);                                                                    \
                ERROR_INFO("%s get result error",#vpipename);                                     \
                goto fail;                                                                        \
            }                                                                                     \
            if (waitstate == PIPE_WAIT_READ && lastlen != (memlen)) {                             \
                DEBUG_BUFFER_FMT(&(ptrmem[lastlen]), (memlen - lastlen), "%s read",#vpipename);   \
            }                                                                                     \
            waitflag = ret;                                                                       \
            if (waitflag == 0) {                                                                  \
                if (pproc->vpipename->m_state == PIPE_WAIT_CONNECT ||                             \
                    pproc->vpipename->m_state == waitstate) {                                     \
                    pproc->vpipename->m_state = PIPE_READY;                                       \
                }                                                                                 \
                DEBUG_INFO("%s len[%d]", #vpipename, memlen);                                     \
                if (memlen == memsize && waitstate == PIPE_WAIT_WRITE) {                          \
                    __close_handle_note(&(pproc->vpipename->m_pipesvr),                           \
                        "%s", pproc->vpipename->m_pipename);                                      \
                    pproc->vpipename->m_state = PIPE_NONE;                                        \
                }                                                                                 \
            }                                                                                     \
        }                                                                                         \
    }while(0)

#define   STDIN_WAIT_HANDLE()                                                                     \
    WAIT_HANDLE(m_stdinpipe,pin,inlen,insize,inwait,PIPE_WAIT_WRITE)


#define   STDOUT_WAIT_HANDLE()                                                                    \
    WAIT_HANDLE(m_stdoutpipe,pretout,outlen,outsize,outwait,PIPE_WAIT_READ)

#define   STDERR_WAIT_HANDLE()                                                                    \
    WAIT_HANDLE(m_stderrpipe,preterr,errlen,errsize,errwait,PIPE_WAIT_READ)


#define   READ_LEFT(vpipename,ptrmem, ppmemptr,memlen,memsize)                                    \
    do{                                                                                           \
        if (pproc->vpipename != NULL) {                                                           \
            DEBUG_INFO("%s state %s", #vpipename,                                                 \
                pproc->vpipename->m_state == PIPE_READY ? "READY" : "WAIT");                      \
            ret = __left_pipe_bytes(pproc->vpipename->m_pipesvr);                                 \
            if (ret < 0) {                                                                        \
                GETERRNO(ret);                                                                    \
                ERROR_INFO("get %s left bytes error[%d]", #vpipename,ret);                        \
                goto fail;                                                                        \
            }                                                                                     \
            curlen = ret;                                                                         \
            if (curlen > 0) {                                                                     \
                if ((memsize - memlen) < curlen) {                                                \
                    memsize = memsize - memlen + curlen;                                          \
                    ptmpbuf = (char*)malloc((size_t)(memsize));                                   \
                    if (ptmpbuf == NULL) {                                                        \
                        GETERRNO(ret);                                                            \
                        ERROR_INFO("alloc %d error[%d]", memsize,ret);                            \
                        goto fail;                                                                \
                    }                                                                             \
                    memset(ptmpbuf,0, (size_t)(memsize));                                         \
                    if (memlen > 0) {                                                             \
                        memcpy(ptmpbuf, ptrmem, (size_t)(memlen));                                \
                    }                                                                             \
                    if (ptrmem != NULL && ptrmem != *ppmemptr) {                                  \
                        free(ptrmem);                                                             \
                    }                                                                             \
                    ptrmem = ptmpbuf;                                                             \
                    ptmpbuf = NULL;                                                               \
                }                                                                                 \
                ret = __read_file_sync(pproc->vpipename->m_pipesvr,&(pproc->vpipename->m_ov),     \
                    &(ptrmem[memlen]), curlen, &pending);                                         \
                if (ret < 0) {                                                                    \
                    GETERRNO(ret);                                                                \
                    goto fail;                                                                    \
                }                                                                                 \
                if (ret != curlen) {                                                              \
                    ret = -ERROR_INTERNAL_ERROR;                                                  \
                    ERROR_INFO("read %s left error[%d]", #vpipename,ret);                         \
                    goto fail;                                                                    \
                }                                                                                 \
                DEBUG_BUFFER_FMT(&(ptrmem[memlen]), curlen, "new %s", #vpipename);                \
                memlen += ret;                                                                    \
            }                                                                                     \
        }                                                                                         \
    }while(0)


#define  STDOUT_READ_LEFT()                                                                       \
    READ_LEFT(m_stdoutpipe,pretout, ppout,outlen,outsize)

#define  STDERR_READ_LEFT()                                                                       \
    READ_LEFT(m_stderrpipe,preterr, pperr,errlen,errsize)

#if 1
int __inner_run(pproc_handle_t pproc, HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout)
{
    int inlen = 0;
    char* pretout = NULL;
    int outsize = 0, outlen = 0;
    char* preterr = NULL;
    int errsize = 0, errlen = 0;
    char* ptmpbuf = NULL;
    HANDLE waithds[4];
    int waitnum = 0;
    DWORD dret = 0;
    uint64_t sticks = 0, cticks = 0;
    DWORD waittime;
    HANDLE hd;
    int pending;
    int inwait = 0, outwait = 0, errwait = 0;
    int ret;
    int curlen;

    if (ppout != NULL) {
        pretout = *ppout;
        outsize = *poutsize;
    }

    if (pperr != NULL) {
        preterr = *pperr;
        errsize = *perrsize;
    }

    if (timeout > 0) {
        sticks = get_current_ticks();
    }

    while (1) {
        ret = get_proc_exit(pproc, NULL);
        if (ret >= 0) {
            DEBUG_INFO("proc exited");
            break;
        }

        /*now we should make waithds*/
        memset(waithds, 0 , sizeof(waithds));
        waitnum = 0;

        STDIN_WRITE_WAIT();
        STDOUT_READ_EXPAND(out_again);
        STDERR_READ_EXPAND(err_again);

        if (hevt != NULL && hevt != INVALID_HANDLE_VALUE) {
            waithds[waitnum] = hevt;
            waitnum ++;
        }

        waittime = INFINITE;
        if (timeout > 0) {
            cticks = get_current_ticks();
            ret = need_wait_times(sticks, cticks, timeout);
            if (ret < 0) {
                ret = -WAIT_TIMEOUT;
                ERROR_INFO("wait time out");
                goto fail;
            }
            waittime = (DWORD)ret;
        }

        if (waittime == INFINITE || waittime > 1000) {
            waittime = 1000;
        }

        if (waitnum > 0 ) {
            dret = WaitForMultipleObjectsEx((DWORD)waitnum, waithds, FALSE, waittime, FALSE);
            DEBUG_INFO("dret [%d]", dret);
            if ((dret < (WAIT_OBJECT_0 + waitnum))) {
                hd = waithds[(dret - WAIT_OBJECT_0)];
#pragma warning(disable:4127)
                STDIN_WAIT_HANDLE();
#pragma warning(default:4127)
                STDOUT_WAIT_HANDLE();
                STDERR_WAIT_HANDLE();

                if (hevt != NULL && hevt != INVALID_HANDLE_VALUE && hd == hevt) {
                    ret = -WSAEINTR;
                    ERROR_INFO("interrupted");
                    goto fail;
                }
            } else  if (dret == WAIT_TIMEOUT) {
                continue;
            } else {
                GETERRNO(ret);
                ERROR_INFO("run cmd [%s] [%ld] error [%d]", pproc->m_cmdline, dret, ret);
                goto fail;
            }
        } else {
            /*nothing to wait ,so we should wait for the handle of proc*/
            if (waittime != INFINITE && waittime < 100) {
                SleepEx(waittime, TRUE);
            } else {
                SleepEx(100, TRUE);
            }
            DEBUG_INFO("prochd time");
        }
    }

    STDOUT_READ_LEFT();
    STDERR_READ_LEFT();

    if (exitcode) {
        *exitcode = pproc->m_exitcode;
    }
    if (ppout != NULL) {
        if (*ppout != NULL && *ppout != pretout) {
            free(*ppout);
        }
        *ppout = pretout;
    }

    if (pperr != NULL) {
        if (*pperr != NULL && *pperr != preterr) {
            free(*pperr);
        }
        *pperr = preterr;
    }

    if (perrsize) {
        *perrsize = errlen;
    }

    if (poutsize) {
        *poutsize = outlen;
    }
    return 0;
fail:
    if (ptmpbuf) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    if (pretout && (ppout == NULL || pretout != *ppout)) {
        free(pretout);
    }
    pretout = NULL;
    if (preterr && (pperr == NULL || preterr != *pperr)) {
        free(preterr);
    }
    preterr = NULL;
    SETERRNO(ret);
    return ret;
}


int __wts_inner_run(pproc_handle_t pproc, HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout)
{
    char* pretout = NULL;
    int outsize = 0, outlen = 0;
    char* preterr = NULL;
    int errsize = 0, errlen = 0;
    char* ptmpbuf = NULL;
    HANDLE waithds[4];
    int waitnum = 0;
    DWORD dret = 0;
    uint64_t sticks = 0, cticks = 0;
    DWORD waittime;
    HANDLE hd;
    int ret;
    insize = insize;
    if (pin) {
        pin = pin;
    }

    if (ppout != NULL) {
        pretout = *ppout;
        outsize = *poutsize;
    }

    if (pperr != NULL) {
        preterr = *pperr;
        errsize = *perrsize;
    }

    if (timeout > 0) {
        sticks = get_current_ticks();
    }

    while (1) {
        ret = get_proc_exit(pproc, NULL);
        if (ret >= 0) {
            DEBUG_INFO("proc exited");
            break;
        }

        /*now we should make waithds*/
        memset(waithds, 0 , sizeof(waithds));
        waitnum = 0;


        if (hevt != NULL && hevt != INVALID_HANDLE_VALUE) {
            waithds[waitnum] = hevt;
            waitnum ++;
        }

        waittime = INFINITE;
        if (timeout > 0) {
            cticks = get_current_ticks();
            ret = need_wait_times(sticks, cticks, timeout);
            if (ret < 0) {
                ret = -WAIT_TIMEOUT;
                ERROR_INFO("wait time out");
                goto fail;
            }
            waittime = (DWORD)ret;
        }

        if (waittime == INFINITE || waittime > 1000) {
            waittime = 1000;
        }

        if (waitnum > 0 ) {
            dret = WaitForMultipleObjectsEx((DWORD)waitnum, waithds, FALSE, waittime, FALSE);
            DEBUG_INFO("dret [%d]", dret);
            if ((dret < (WAIT_OBJECT_0 + waitnum))) {
                hd = waithds[(dret - WAIT_OBJECT_0)];

                if (hevt != NULL && hevt != INVALID_HANDLE_VALUE && hd == hevt) {
                    ret = -WSAEINTR;
                    ERROR_INFO("interrupted");
                    goto fail;
                }
            } else  if (dret == WAIT_TIMEOUT) {
                continue;
            } else {
                GETERRNO(ret);
                ERROR_INFO("run cmd [%s] [%ld] error [%d]", pproc->m_cmdline, dret, ret);
                goto fail;
            }
        } else {
            /*nothing to wait ,so we should wait for the handle of proc*/
            if (waittime != INFINITE && waittime < 100) {
                SleepEx(waittime, TRUE);
            } else {
                SleepEx(100, TRUE);
            }
            DEBUG_INFO("prochd time");
        }
    }

    if (exitcode) {
        *exitcode = pproc->m_exitcode;
    }
    if (ppout != NULL) {
        if (*ppout != NULL && *ppout != pretout) {
            free(*ppout);
        }
        *ppout = pretout;
    }

    if (pperr != NULL) {
        if (*pperr != NULL && *pperr != preterr) {
            free(*pperr);
        }
        *pperr = preterr;
    }

    if (perrsize) {
        *perrsize = errlen;
    }

    if (poutsize) {
        *poutsize = outlen;
    }
    return 0;
fail:
    if (ptmpbuf) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    if (pretout && (ppout == NULL || pretout != *ppout)) {
        free(pretout);
    }
    pretout = NULL;
    if (preterr && (pperr == NULL || preterr != *pperr)) {
        free(preterr);
    }
    preterr = NULL;
    SETERRNO(ret);
    return ret;
}


#else

#endif

int run_cmd_event_output_single(HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog)
{
    pproc_handle_t pproc = NULL;
    int ret;
    int createflag = 0;

    DEBUG_INFO(" ");
    if (prog == NULL) {
        if (ppout != NULL) {
            if (*ppout != NULL) {
                free(*ppout);
            }
            *ppout = NULL;
        }
        if (poutsize) {
            *poutsize = 0;
        }

        if (pperr != NULL) {
            if (*pperr != NULL) {
                free(*pperr);
            }
            *pperr = NULL;
        }
        if (perrsize) {
            *perrsize = 0;
        }
        return 0;
    }

    if (pin != NULL) {
        createflag |= PROC_PIPE_STDIN;
    } else {
        createflag |= PROC_STDIN_NULL;
    }

    if (ppout != NULL) {
        if (poutsize == NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
        createflag |= PROC_PIPE_STDOUT;
    } else {
        //createflag |= PROC_STDOUT_NULL;
    }

    if (pperr != NULL) {
        if (perrsize == NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
        createflag |= PROC_PIPE_STDERR;
    } else {
        //createflag |= PROC_STDERR_NULL;
    }
    createflag |= PROC_NO_WINDOW;

    DEBUG_INFO(" ");

    pproc = (pproc_handle_t)start_cmd_single(createflag, prog);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __inner_run(pproc, hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /*now exited we will give the output*/
    __free_proc_handle(&pproc);
    return 0;
fail:
    __free_proc_handle(&pproc);
    SETERRNO(ret);
    return ret;
}

int run_cmd_output_single(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog)
{
    return run_cmd_event_output_single(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog);
}

int run_cmd_event_outputv(HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog[])
{
    pproc_handle_t pproc = NULL;
    int ret;
    int createflag = 0;

    DEBUG_INFO("prog [%p]", prog);
    if (prog == NULL) {
        if (ppout != NULL) {
            if (*ppout != NULL) {
                free(*ppout);
            }
            *ppout = NULL;
        }
        if (poutsize) {
            *poutsize = 0;
        }

        if (pperr != NULL) {
            if (*pperr != NULL) {
                free(*pperr);
            }
            *pperr = NULL;
        }
        if (perrsize) {
            *perrsize = 0;
        }
        DEBUG_INFO(" ");
        return 0;
    }

    if (pin != NULL) {
        createflag |= PROC_PIPE_STDIN;
    } else {
        createflag |= PROC_STDIN_NULL;
    }

    if (ppout != NULL) {
        if (poutsize == NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
        createflag |= PROC_PIPE_STDOUT;
    } else {
        //createflag |= PROC_STDOUT_NULL;
    }

    if (pperr != NULL) {
        if (perrsize == NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
        createflag |= PROC_PIPE_STDERR;
    } else {
        //createflag |= PROC_STDERR_NULL;
    }
    createflag |= PROC_NO_WINDOW;


    pproc = (pproc_handle_t)start_cmdv(createflag, prog);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __inner_run(pproc, hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    __free_proc_handle(&pproc);
    return 0;
fail:
    __free_proc_handle(&pproc);
    SETERRNO(ret);
    return ret;
}

int run_cmd_outputv(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog[])
{
    return run_cmd_event_outputv(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog);
}

int run_cmd_event_outputa(HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, va_list ap)
{
    va_list oldap;
    char** progv = NULL;
    int i;
    int retlen;
    int ret;
    char* curarg;
    int cnt = 0;

    if (prog == NULL) {
        return run_cmd_event_outputv(hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, NULL);
    }

    cnt = 1;
    va_copy(oldap, ap);
    while (1) {
        curarg = va_arg(ap, char*);
        if (curarg == NULL) {
            break;
        }
        cnt ++;
    }

    progv = (char**) malloc(sizeof(*progv ) * (cnt + 1));
    if (progv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*progv) * (cnt + 1), ret);
        goto fail;
    }

    memset(progv, 0 , sizeof(*progv) * (cnt + 1));
    va_copy(ap, oldap);
    progv[0] = (char*)prog;
    for (i = 1; i < cnt ; i++) {
        curarg = va_arg(ap, char*);
        ASSERT_IF(curarg != NULL);
        progv[i] = curarg;
    }

    curarg = va_arg(ap, char*);
    ASSERT_IF(curarg == NULL);

    ret = run_cmd_event_outputv(hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, progv);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    retlen = ret;
    free(progv);

    return retlen;

fail:
    if (progv != NULL) {
        free(progv);
    }
    progv = NULL;
    SETERRNO(ret);
    return ret;
}

int run_cmd_outputa(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, va_list ap)
{
    return run_cmd_event_outputa(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog, ap);
}

int run_cmd_event_output(HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...)
{
    va_list ap = NULL;
    if (prog == NULL) {
        return run_cmd_event_outputa(hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, NULL, ap);
    }
    va_start(ap, prog);
    return run_cmd_event_outputa(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog, ap);
}

int run_cmd_output(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...)
{
    va_list ap = NULL;
    if (prog == NULL) {
        return run_cmd_event_outputa(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, NULL, ap);
    }
    va_start(ap, prog);
    return run_cmd_event_outputa(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog, ap);
}


/****************************************************
 wts mode
****************************************************/
int wts_run_cmd_event_output_single(HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog)
{
    pproc_handle_t pproc = NULL;
    int ret;
    int createflag = 0;

    DEBUG_INFO(" ");
    if (prog == NULL) {
        if (ppout != NULL) {
            if (*ppout != NULL) {
                free(*ppout);
            }
            *ppout = NULL;
        }
        if (poutsize) {
            *poutsize = 0;
        }

        if (pperr != NULL) {
            if (*pperr != NULL) {
                free(*pperr);
            }
            *pperr = NULL;
        }
        if (perrsize) {
            *perrsize = 0;
        }
        return 0;
    }

    if (pin != NULL) {
        createflag |= PROC_PIPE_STDIN;
    } else {
        createflag |= PROC_STDIN_NULL;
    }

    if (ppout != NULL) {
        if (poutsize == NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
        createflag |= PROC_PIPE_STDOUT;
    } else {
        //createflag |= PROC_STDOUT_NULL;
    }

    if (pperr != NULL) {
        if (perrsize == NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
        createflag |= PROC_PIPE_STDERR;
    } else {
        //createflag |= PROC_STDERR_NULL;
    }
    createflag |= PROC_NO_WINDOW;

    DEBUG_INFO(" ");

    pproc = (pproc_handle_t)wts_start_cmd_single(createflag, prog);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __wts_inner_run(pproc, hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /*now exited we will give the output*/
    __free_proc_handle(&pproc);
    return 0;
fail:
    __free_proc_handle(&pproc);
    SETERRNO(ret);
    return ret;
}

int wts_run_cmd_output_single(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog)
{
    return wts_run_cmd_event_output_single(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog);
}

int wts_run_cmd_event_outputv(HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog[])
{
    pproc_handle_t pproc = NULL;
    int ret;
    int createflag = 0;

    DEBUG_INFO("prog [%p]", prog);
    if (prog == NULL) {
        if (ppout != NULL) {
            if (*ppout != NULL) {
                free(*ppout);
            }
            *ppout = NULL;
        }
        if (poutsize) {
            *poutsize = 0;
        }

        if (pperr != NULL) {
            if (*pperr != NULL) {
                free(*pperr);
            }
            *pperr = NULL;
        }
        if (perrsize) {
            *perrsize = 0;
        }
        DEBUG_INFO(" ");
        return 0;
    }

    if (pin != NULL) {
        createflag |= PROC_PIPE_STDIN;
    } else {
        createflag |= PROC_STDIN_NULL;
    }

    if (ppout != NULL) {
        if (poutsize == NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
        createflag |= PROC_PIPE_STDOUT;
    } else {
        //createflag |= PROC_STDOUT_NULL;
    }

    if (pperr != NULL) {
        if (perrsize == NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }
        createflag |= PROC_PIPE_STDERR;
    } else {
        //createflag |= PROC_STDERR_NULL;
    }
    createflag |= PROC_NO_WINDOW;


    pproc = (pproc_handle_t)wts_start_cmdv(createflag, prog);
    if (pproc == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __wts_inner_run(pproc, hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    __free_proc_handle(&pproc);
    return 0;
fail:
    __free_proc_handle(&pproc);
    SETERRNO(ret);
    return ret;
}

int wts_run_cmd_outputv(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog[])
{
    return wts_run_cmd_event_outputv(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog);
}

int wts_run_cmd_event_outputa(HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, va_list ap)
{
    va_list oldap;
    char** progv = NULL;
    int i;
    int retlen;
    int ret;
    char* curarg;
    int cnt = 0;

    if (prog == NULL) {
        return wts_run_cmd_event_outputv(hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, NULL);
    }

    cnt = 1;
    va_copy(oldap, ap);
    while (1) {
        curarg = va_arg(ap, char*);
        if (curarg == NULL) {
            break;
        }
        cnt ++;
    }

    progv = (char**) malloc(sizeof(*progv ) * (cnt + 1));
    if (progv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*progv) * (cnt + 1), ret);
        goto fail;
    }

    memset(progv, 0 , sizeof(*progv) * (cnt + 1));
    va_copy(ap, oldap);
    progv[0] = (char*)prog;
    for (i = 1; i < cnt ; i++) {
        curarg = va_arg(ap, char*);
        ASSERT_IF(curarg != NULL);
        progv[i] = curarg;
    }

    curarg = va_arg(ap, char*);
    ASSERT_IF(curarg == NULL);

    ret = wts_run_cmd_event_outputv(hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, progv);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    retlen = ret;
    free(progv);

    return retlen;

fail:
    if (progv != NULL) {
        free(progv);
    }
    progv = NULL;
    SETERRNO(ret);
    return ret;
}

int wts_run_cmd_outputa(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, va_list ap)
{
    return wts_run_cmd_event_outputa(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog, ap);
}

int wts_run_cmd_event_output(HANDLE hevt, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...)
{
    va_list ap = NULL;
    if (prog == NULL) {
        return wts_run_cmd_event_outputa(hevt, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, NULL, ap);
    }
    va_start(ap, prog);
    return wts_run_cmd_event_outputa(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog, ap);
}

int wts_run_cmd_output(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...)
{
    va_list ap = NULL;
    if (prog == NULL) {
        return wts_run_cmd_event_outputa(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, NULL, ap);
    }
    va_start(ap, prog);
    return wts_run_cmd_event_outputa(NULL, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog, ap);
}


int start_cmdv_detach(int createflag, char* progv[])
{
    int retpid = 0;
    pproc_handle_t ppinfo = NULL;
    int ret;
    ppinfo = (pproc_handle_t)start_cmdv(createflag, progv);
    if (ppinfo == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    retpid = (int)GetProcessId(ppinfo->m_prochd);
    /*now to close handle*/
    CloseHandle(ppinfo->m_prochd);
    ppinfo->m_prochd = NULL;
    /*exited*/
    ppinfo->m_exited = 1;
    __free_proc_handle(&ppinfo);
    return retpid;
fail:
    __free_proc_handle(&ppinfo);
    SETERRNO(ret);
    return ret;
}

int start_cmd_single_detach(int createflag, const char* prog)
{
    int retpid = 0;
    pproc_handle_t ppinfo = NULL;
    int ret;
    ppinfo = (pproc_handle_t)start_cmd_single(createflag, (char*)prog);
    if (ppinfo == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    retpid = (int)GetProcessId(ppinfo->m_prochd);
    /*now to close handle*/
    CloseHandle(ppinfo->m_prochd);
    ppinfo->m_prochd = NULL;
    /*exited*/
    ppinfo->m_exited = 1;
    __free_proc_handle(&ppinfo);
    return retpid;
fail:
    __free_proc_handle(&ppinfo);
    SETERRNO(ret);
    return ret;
}


int start_cmd_detach(int createflag, const char* prog, ...)
{
    va_list oldap;
    char** progv = NULL;
    int cnt;
    int retpid = 0;
    va_list ap;
    char* curarg = NULL;
    int ret;
    int i;

    va_start(ap, prog);

    cnt = 1;
    va_copy(oldap, ap);
    while (1) {
        curarg = va_arg(ap, char*);
        if (curarg == NULL) {
            break;
        }
        cnt ++;
    }

    progv = (char**) malloc(sizeof(*progv ) * (cnt + 1));
    if (progv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*progv) * (cnt + 1), ret);
        goto fail;
    }

    memset(progv, 0 , sizeof(*progv) * (cnt + 1));
    va_copy(ap, oldap);
    progv[0] = (char*)prog;
    for (i = 1; i < cnt ; i++) {
        curarg = va_arg(ap, char*);
        ASSERT_IF(curarg != NULL);
        progv[i] = curarg;
    }

    ret = start_cmdv_detach(createflag, progv);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retpid = ret;

    if (progv) {
        free(progv);
    }
    progv = NULL;

    return retpid;
fail:
    if (progv) {
        free(progv);
    }
    progv = NULL;
    SETERRNO(ret);
    return ret;
}


int wts_start_cmdv_detach(int createflag, char* progv[])
{
    int retpid = 0;
    pproc_handle_t ppinfo = NULL;
    int ret;
    ppinfo = (pproc_handle_t)wts_start_cmdv(createflag, progv);
    if (ppinfo == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    retpid = (int)GetProcessId(ppinfo->m_prochd);
    /*now to close handle*/
    CloseHandle(ppinfo->m_prochd);
    ppinfo->m_prochd = NULL;
    /*exited*/
    ppinfo->m_exited = 1;
    __free_proc_handle(&ppinfo);
    return retpid;
fail:
    __free_proc_handle(&ppinfo);
    SETERRNO(ret);
    return ret;

}


int wts_start_cmd_detach(int createflag, const char* prog, ...)
{
    va_list oldap;
    char** progv = NULL;
    int cnt;
    int retpid = 0;
    va_list ap;
    char* curarg = NULL;
    int ret;
    int i;

    va_start(ap, prog);

    cnt = 1;
    va_copy(oldap, ap);
    while (1) {
        curarg = va_arg(ap, char*);
        if (curarg == NULL) {
            break;
        }
        cnt ++;
    }

    progv = (char**) malloc(sizeof(*progv ) * (cnt + 1));
    if (progv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*progv) * (cnt + 1), ret);
        goto fail;
    }

    memset(progv, 0 , sizeof(*progv) * (cnt + 1));
    va_copy(ap, oldap);
    progv[0] = (char*)prog;
    for (i = 1; i < cnt ; i++) {
        curarg = va_arg(ap, char*);
        ASSERT_IF(curarg != NULL);
        progv[i] = curarg;
    }

    ret = wts_start_cmdv_detach(createflag, progv);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retpid = ret;

    if (progv) {
        free(progv);
    }
    progv = NULL;

    return retpid;
fail:
    if (progv) {
        free(progv);
    }
    progv = NULL;
    SETERRNO(ret);
    return ret;
}

int wts_start_cmd_single_detach(int createflag, const char* prog)
{
    int retpid = 0;
    pproc_handle_t ppinfo = NULL;
    int ret;
    ppinfo = (pproc_handle_t)wts_start_cmd_single(createflag, (char*)prog);
    if (ppinfo == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    retpid = (int)GetProcessId(ppinfo->m_prochd);
    /*now to close handle*/
    CloseHandle(ppinfo->m_prochd);
    ppinfo->m_prochd = NULL;
    /*exited*/
    ppinfo->m_exited = 1;
    __free_proc_handle(&ppinfo);
    return retpid;
fail:
    __free_proc_handle(&ppinfo);
    SETERRNO(ret);
    return ret;
}


int get_pids_by_name(const char* name, DWORD** ppids, int *psize)
{
    PROCESSENTRY32* procentry = NULL;
    HANDLE hsnap = INVALID_HANDLE_VALUE;
    int ret;
    int cnt = 0;
    DWORD* pretpids = NULL;
    DWORD* ptmppids = NULL;
    int retsize = 0;
    BOOL bret;
    TCHAR* ptname = NULL;
    int namesize = 0;
    if (name == NULL) {
        if (ppids && *ppids) {
            free(*ppids);
            *ppids = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppids == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return  ret;
    }

    pretpids = *ppids;
    retsize = *psize;


    hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnap == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("create snapshot error [%d]", ret);
        goto fail;
    }

    procentry = (PROCESSENTRY32*)malloc(sizeof(*procentry));
    if (procentry == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(procentry , 0 , sizeof(*procentry));
    procentry->dwSize = sizeof(*procentry);

    bret = Process32First(hsnap, procentry);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_NO_MORE_FILES) {
            goto succ;
        }
        ERROR_INFO("first process error [%d]", ret);
        goto fail;
    }

    ret = AnsiToTchar(name, &ptname, &namesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    do {
        if (_tcscmp(procentry->szExeFile, ptname) == 0) {
            if (cnt >= retsize || pretpids == NULL) {
                if (cnt >= retsize) {
                    if (retsize == 0) {
                        retsize = 4;
                    } else {
                        retsize <<= 1;
                    }
                }
                ptmppids = (DWORD*)malloc(sizeof(*ptmppids) * retsize);
                if (ptmppids == NULL) {
                    GETERRNO(ret);
                    goto fail;
                }
                memset(ptmppids, 0, sizeof(*ptmppids) * retsize);
                if (cnt > 0) {
                    memcpy(ptmppids, pretpids, cnt * sizeof(*pretpids));
                }
                if (pretpids && pretpids != *ppids) {
                    free(pretpids);
                }
                pretpids = ptmppids;
                ptmppids = NULL;
            }
            pretpids[cnt] = procentry->th32ProcessID;
            cnt ++;
        }

        bret = Process32Next(hsnap, procentry);
        if (!bret) {
            GETERRNO(ret);
            if (ret == -ERROR_NO_MORE_FILES) {
                break;
            }
            ERROR_INFO("can not next error[%d]", ret);
            goto fail;
        }
    } while (1);

succ:

    AnsiToTchar(NULL, &ptname, &namesize);

    if (procentry != NULL) {
        free(procentry);
    }
    procentry = NULL;

    if (hsnap != INVALID_HANDLE_VALUE && hsnap != NULL) {
        CloseHandle(hsnap);
    }
    hsnap = INVALID_HANDLE_VALUE;

    if (*ppids && *ppids != pretpids) {
        free(*ppids);
    }
    *ppids = pretpids;
    *psize = retsize;

    return cnt;
fail:
    AnsiToTchar(NULL, &ptname, &namesize);
    if (procentry != NULL) {
        free(procentry);
    }
    procentry = NULL;

    if (hsnap != INVALID_HANDLE_VALUE && hsnap != NULL) {
        CloseHandle(hsnap);
    }
    hsnap = INVALID_HANDLE_VALUE;

    if (ptmppids) {
        free(ptmppids);
    }
    ptmppids = NULL;

    if (pretpids && pretpids != *ppids) {
        free(pretpids);
    }
    pretpids = NULL;
    retsize = 0;

    SETERRNO(ret);
    return ret;
}

int __start_cmdv_session_detach(DWORD session, DWORD winlogonpid, char* cmdline)
{
    int retpid = -1;
    int ret, res;
    STARTUPINFO* pstartinfo = NULL;
    PROCESS_INFORMATION* procinfo = NULL;
    TCHAR* ptdesktop = NULL;
    int tdesksize = 0;
    HANDLE hproc = INVALID_HANDLE_VALUE;
    HANDLE htoken = INVALID_HANDLE_VALUE;
    HANDLE husertoken = INVALID_HANDLE_VALUE;
    BOOL bret;
    DWORD getsessid;
    PVOID penv = NULL;
    TCHAR* ptcmdline = NULL;
    int cmdsize = 0;
    DWORD createflag = 0;
    SECURITY_ATTRIBUTES      sa;

    bret = ProcessIdToSessionId(winlogonpid, &getsessid);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not get sessionid from [%d] error[%d]", (int) winlogonpid, ret);
        SETERRNO(ret);
        return ret;
    }

    if (getsessid != session) {
        ret = -ERROR_SERVER_SID_MISMATCH;
        ERROR_INFO("mismatch sessionid [%d] != [%d]", (int) getsessid, (int) session);
        SETERRNO(ret);
        return ret;
    }


    pstartinfo = (STARTUPINFO*)malloc(sizeof(*pstartinfo));
    if (pstartinfo == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    memset(pstartinfo, 0, sizeof(*pstartinfo));

    ret = AnsiToTchar("winsta0\\default", &ptdesktop, &tdesksize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pstartinfo->cb = sizeof(*pstartinfo);
    pstartinfo->lpDesktop = ptdesktop;

    createflag |= NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;


    procinfo = (PROCESS_INFORMATION*)malloc(sizeof(*procinfo));
    if (procinfo == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(procinfo, 0, sizeof(*procinfo));

    hproc = OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonpid);
    if (hproc == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open [%d] error [%d]", (int) winlogonpid, ret);
        goto fail;
    }

    bret = OpenProcessToken(hproc,
                            //TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE,
                            //TOKEN_QUERY | TOKEN_DUPLICATE |  TOKEN_READ | TOKEN_ADJUST_PRIVILEGES,
                            TOKEN_DUPLICATE,
                            &htoken);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not get token for [%d] error[%d]", (int) winlogonpid, ret);
        goto fail;
    }

    memset(&sa, 0 , sizeof(sa));
    sa.nLength = sizeof(sa);

    //bret = DuplicateTokenEx(htoken,MAXIMUM_ALLOWED,NULL,SecurityIdentification,TokenPrimary,&husertoken);
    bret = DuplicateTokenEx(htoken, MAXIMUM_ALLOWED, &sa, SecurityIdentification, TokenPrimary, &husertoken);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not duplicate token error [%d]", ret);
        goto fail;
    }

    ret = enable_token_debug_priv(husertoken);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = disable_token_tcb_priv(husertoken);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = SetTokenInformation(husertoken, TokenSessionId, (void*)(&session), sizeof(DWORD));
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("set session id for duplicate token error[%d]", ret);
        goto fail;
    }


    bret = CreateEnvironmentBlock(&penv, husertoken, TRUE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("create environment block error[%d]", ret);
        goto fail;
    }

    createflag |= CREATE_UNICODE_ENVIRONMENT;

    ret = AnsiToTchar(cmdline, &ptcmdline, &cmdsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = CreateProcessAsUser(husertoken, NULL, ptcmdline,
                               NULL, NULL, FALSE, createflag, penv, NULL, pstartinfo, procinfo);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("create [%s] session [%d] error[%d]", cmdline, session, ret);
        goto fail;
    }

    if (procinfo->hThread) {
        CloseHandle(procinfo->hThread);
    }

    if (procinfo->hProcess) {
        CloseHandle(procinfo->hProcess);
    }

    retpid = (int)procinfo->dwProcessId;


    AnsiToTchar(NULL, &ptcmdline, &cmdsize);

    if (penv) {
        bret = DestroyEnvironmentBlock(penv);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("destroy environment block error[%d]", res);
        }
    }
    penv = NULL;


    if (husertoken != NULL && husertoken != INVALID_HANDLE_VALUE) {
        CloseHandle(husertoken);
    }
    husertoken = INVALID_HANDLE_VALUE;

    if (htoken != NULL && htoken != INVALID_HANDLE_VALUE) {
        CloseHandle(htoken);
    }
    htoken = INVALID_HANDLE_VALUE;

    if (hproc != NULL && hproc != INVALID_HANDLE_VALUE) {
        CloseHandle(hproc);
    }
    hproc = INVALID_HANDLE_VALUE;

    AnsiToTchar(NULL, &ptdesktop, &tdesksize);

    if (pstartinfo) {
        free(pstartinfo);
    }
    pstartinfo = NULL;
    if (procinfo) {
        free(procinfo);
    }
    procinfo = NULL;


    return retpid;
fail:
    AnsiToTchar(NULL, &ptcmdline, &cmdsize);

    if (penv) {
        bret = DestroyEnvironmentBlock(penv);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("destroy environment block error[%d]", res);
        }
    }
    penv = NULL;


    if (husertoken != NULL && husertoken != INVALID_HANDLE_VALUE) {
        CloseHandle(husertoken);
    }
    husertoken = INVALID_HANDLE_VALUE;

    if (htoken != NULL && htoken != INVALID_HANDLE_VALUE) {
        CloseHandle(htoken);
    }
    htoken = INVALID_HANDLE_VALUE;

    if (hproc != NULL && hproc != INVALID_HANDLE_VALUE) {
        CloseHandle(hproc);
    }
    hproc = INVALID_HANDLE_VALUE;

    AnsiToTchar(NULL, &ptdesktop, &tdesksize);

    if (pstartinfo) {
        free(pstartinfo);
    }
    pstartinfo = NULL;
    if (procinfo) {
        free(procinfo);
    }
    procinfo = NULL;
    SETERRNO(ret);
    return ret;
}


int start_cmdv_session_detach(DWORD session, char* prog[])
{
    int ret;
    int cnt = 0;
    int size = 0;
    DWORD* ppids = NULL;
    int i;
    int retpid = -1;
    char* cmdlines = NULL;
    int cmdsize = 0;

    /*to find the winlogon and get the session id*/
    ret = get_pids_by_name("winlogon.exe", &ppids, &size);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    cnt = ret;
    if (cnt == 0) {
        ret = -ERROR_NO_SUCH_LOGON_SESSION;
        ERROR_INFO("no such [%d] session", (int)session);
        goto fail;
    }

    ret = __get_command_lines(&cmdlines, &cmdsize, prog);

    /*now we find the session*/
    for (i = 0; i < cnt; i++) {
        ret = __start_cmdv_session_detach(session, ppids[i], cmdlines);
        if (ret >= 0) {
            retpid = ret;
            break;
        }
    }

    if (retpid < 0) {
        ret = -ERROR_BAD_LOGON_SESSION_STATE;
        ERROR_INFO("can not run [%s] for sessions", cmdlines);
        goto fail;
    }

    __get_command_lines(&cmdlines, &cmdsize, NULL);
    get_pids_by_name(NULL, &ppids, &size);

    return retpid;

fail:
    __get_command_lines(&cmdlines, &cmdsize, NULL);
    get_pids_by_name(NULL, &ppids, &size);
    SETERRNO(ret);
    return ret;
}


int start_cmd_session_detach(DWORD session, const char* prog, ...)
{
    va_list oldap;
    char** progv = NULL;
    int cnt;
    int retpid = 0;
    va_list ap;
    char* curarg = NULL;
    int ret;
    int i;

    va_start(ap, prog);

    cnt = 1;
    va_copy(oldap, ap);
    while (1) {
        curarg = va_arg(ap, char*);
        if (curarg == NULL) {
            break;
        }
        cnt ++;
    }

    progv = (char**) malloc(sizeof(*progv ) * (cnt + 1));
    if (progv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*progv) * (cnt + 1), ret);
        goto fail;
    }

    memset(progv, 0 , sizeof(*progv) * (cnt + 1));
    va_copy(ap, oldap);
    progv[0] = (char*)prog;
    for (i = 1; i < cnt ; i++) {
        curarg = va_arg(ap, char*);
        ASSERT_IF(curarg != NULL);
        progv[i] = curarg;
    }

    ret = start_cmdv_session_detach(session, progv);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retpid = ret;

    if (progv) {
        free(progv);
    }
    progv = NULL;

    return retpid;
fail:
    if (progv) {
        free(progv);
    }
    progv = NULL;
    SETERRNO(ret);
    return ret;
}

int is_wts_enabled(void)
{
    HANDLE hd = NULL;
    int ret;

    ret =  __get_wts_token(&hd);
    if (ret < 0) {
        goto fail;
    }

    __free_wts_token(&hd);
    return 1;
fail:
    __free_wts_token(&hd);
    return 0;
}


#define CHECK_PROC_RUN()                                                                          \
do{                                                                                               \
    int _curlen=0;                                                                                \
    char* _ptr=NULL;                                                                              \
    char* _cptr=NULL;                                                                             \
    int _plen = 0;                                                                                \
    int __i=0;                                                                                    \
    char* _ansiname=NULL;                                                                         \
    int _ansisize=0;                                                                              \
    int _ret;                                                                                     \
    int _matched;                                                                                 \
    ret = TcharToAnsi(pproc->szExeFile,&_ansiname,&_ansisize);                                    \
    if (ret < 0) {                                                                                \
        GETERRNO(ret);                                                                            \
        goto fail;                                                                                \
    }                                                                                             \
    _ptr = _ansiname;                                                                             \
    _plen = (int)strlen(_ansiname);                                                               \
    for (__i=0;__i<numproc;__i++) {                                                               \
        _matched = 1;                                                                             \
        _curlen=(int) strlen(ppnames[__i]);                                                       \
        if (_plen >= _curlen) {                                                                   \
            if (_plen > _curlen)  {                                                               \
                /*check if the previous character is \\*/                                         \
                _cptr = _ptr + (_plen - _curlen);                                                 \
                _cptr --;                                                                         \
                if (*_cptr != '\\') {                                                             \
                    _matched = 0;                                                                 \
                }                                                                                 \
            }                                                                                     \
            _cptr = _ptr + (_plen - _curlen);                                                     \
            if (_matched){                                                                        \
                _ret = _stricmp(_cptr,ppnames[__i]);                                              \
                if (_ret != 0) {                                                                  \
                    _matched = 0;                                                                 \
                }                                                                                 \
            }                                                                                     \
        } else {                                                                                  \
            _matched = 0;                                                                         \
        }                                                                                         \
        if (_matched){                                                                            \
            DEBUG_INFO("[%d] [%s] matched [%s]", numhdl, _ansiname, ppnames[__i]);                \
            pfinded[__i] ++;                                                                      \
        }                                                                                         \
    }                                                                                             \
    TcharToAnsi(NULL,&_ansiname,&_ansisize);                                                      \
}while(0)



int process_num(char** ppnames, int numproc, int* pfinded)
{
    HANDLE hd = NULL;
    int ret;
    LPPROCESSENTRY32 pproc = NULL;
    BOOL bret;
    int numhdl = 0;

    if (ppnames == NULL || pfinded == NULL || numproc == 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }


    hd = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hd == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("can not create process snapshot error[%d]", ret);
        goto fail;
    }

    pproc = (LPPROCESSENTRY32) malloc(sizeof(*pproc));
    if (pproc == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", sizeof(*pproc) , ret);
        goto fail;
    }
    memset(pproc, 0, sizeof(*pproc));
    pproc->dwSize = sizeof(*pproc);
    memset(pfinded, 0 , sizeof(pfinded[0]) * numproc);

    bret = Process32First(hd, pproc);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_NO_MORE_FILES ) {
            goto succ;
        }
        ERROR_INFO("get first process snapshot error[%d]", ret);
        goto fail;
    }

    CHECK_PROC_RUN();
    numhdl ++;
    while (1) {
        memset(pproc, 0, sizeof(*pproc));
        pproc->dwSize = sizeof(*pproc);
        bret = Process32Next(hd, pproc);
        if (!bret) {
            GETERRNO(ret);
            if (ret == -ERROR_NO_MORE_FILES) {
                break;
            }
            ERROR_INFO("can not get proc snapshot at [%d] error[%d]", numhdl, ret);
            goto fail;
        }

        CHECK_PROC_RUN();
        numhdl ++;
    }
succ:
    if (pproc) {
        free(pproc);
    }
    pproc = NULL;

    if (hd != NULL && hd != INVALID_HANDLE_VALUE) {
        CloseHandle(hd);
    }
    hd = NULL;


    return numhdl;
fail:
    if (pproc) {
        free(pproc);
    }
    pproc = NULL;

    if (hd != NULL && hd != INVALID_HANDLE_VALUE) {
        CloseHandle(hd);
    }
    hd = NULL;

    SETERRNO(ret);
    return ret;
}

#define   MOD_INFO_HANDLE()                                                                       \
do{                                                                                               \
    ret = TcharToAnsi(pmod->szModule, &pmodname, &modsize);                                       \
    if (ret < 0) {                                                                                \
        GETERRNO(ret);                                                                            \
        goto fail;                                                                                \
    }                                                                                             \
    DEBUG_INFO("[%d]modname [%s] base [%p] modsize[0x%x]", numhdl, pmodname,                      \
               pmod->modBaseAddr, pmod->modBaseSize);                                             \
    pcur = strrchr(pmodname, '\\');                                                               \
    if (pcur) {                                                                                   \
        pcur ++;                                                                                  \
    } else {                                                                                      \
        pcur = pmodname;                                                                          \
    }                                                                                             \
    DEBUG_INFO("name [%s] pcur [%s]", name, pcur);                                                \
    if ( (int)strlen(name) == 0 || _stricmp(pcur, name) == 0) {                                   \
        if (pretinfo == NULL || retsize < (int)((retlen + 1) * sizeof(*pretinfo))) {              \
            if (retsize < (int)((retlen + 1) * sizeof(*pretinfo))) {                              \
                retsize = (int)(((retlen + 1) << 1) * sizeof(*pretinfo));                         \
            }                                                                                     \
            ptmpinfo = (pmod_info_t) malloc((size_t)retsize);                                     \
            if (ptmpinfo == NULL) {                                                               \
                GETERRNO(ret);                                                                    \
                goto fail;                                                                        \
            }                                                                                     \
            memset(ptmpinfo, 0, (size_t)retsize);                                                 \
            if (retlen > 0) {                                                                     \
                memcpy(ptmpinfo, pretinfo, (retlen * sizeof(*pretinfo)));                         \
            }                                                                                     \
            if (pretinfo && pretinfo != *ppinfo) {                                                \
                free(pretinfo);                                                                   \
            }                                                                                     \
            pretinfo = ptmpinfo;                                                                  \
            ptmpinfo = NULL;                                                                      \
        }                                                                                         \
        strncpy_s(pretinfo[retlen].m_modfullname, sizeof(pretinfo[retlen].m_modfullname),         \
                  pmodname, sizeof(pretinfo[retlen].m_modfullname));                              \
        pretinfo[retlen].m_pimgbase =  pmod->modBaseAddr;                                         \
        pretinfo[retlen].m_modsize = pmod->modBaseSize;                                           \
        retlen ++;                                                                                \
        DEBUG_INFO("insert [%d]", retlen);                                                        \
    }                                                                                             \
    numhdl ++;                                                                                    \
}while(0)

int get_module_info(int procid, const char* name, pmod_info_t *ppinfo, int *psize)
{
    HANDLE hd = NULL;
    int ret;
    LPMODULEENTRY32  pmod = NULL;
    char* pmodname = NULL;
    int modsize = 0;
    BOOL bret;
    char* pcur;
    int numhdl = 0;
    pmod_info_t pretinfo = NULL, ptmpinfo = NULL;
    int retsize = 0;
    int retlen = 0;

    if (name == NULL) {
        if (ppinfo && *ppinfo) {
            free(*ppinfo);
            *ppinfo = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppinfo == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretinfo = *ppinfo;
    retsize = *psize;

    hd = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)procid);
    if (hd == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("can not create process snapshot error[%d]", ret);
        goto fail;
    }

    pmod = (LPMODULEENTRY32) malloc(sizeof(*pmod));
    if (pmod == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", sizeof(*pmod) , ret);
        goto fail;
    }
    memset(pmod, 0, sizeof(*pmod));
    pmod->dwSize = sizeof(*pmod);

    bret = Module32First(hd, pmod);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_NO_MORE_FILES ) {
            goto succ;
        }
        ERROR_INFO("get first module snapshot error[%d]", ret);
        goto fail;
    }

    MOD_INFO_HANDLE();

    while (1) {
        memset(pmod, 0, sizeof(*pmod));
        pmod->dwSize = sizeof(*pmod);
        bret = Module32Next(hd, pmod);
        if (!bret) {
            GETERRNO(ret);
            if (ret == -ERROR_NO_MORE_FILES) {
                break;
            }
            ERROR_INFO("can not get proc snapshot at [%d] error[%d]", numhdl, ret);
            goto fail;
        }
        MOD_INFO_HANDLE();
    }
succ:
    if (ptmpinfo) {
        free(ptmpinfo);
    }
    ptmpinfo = NULL;

    TcharToAnsi(NULL, &pmodname, &modsize);
    if (pmod) {
        free(pmod);
    }
    pmod = NULL;

    if (hd != NULL && hd != INVALID_HANDLE_VALUE) {
        CloseHandle(hd);
    }
    hd = NULL;
    if (*ppinfo && *ppinfo != pretinfo) {
        free(*ppinfo);
    }
    *ppinfo = pretinfo;
    *psize = retsize;

    return (int)(retlen * sizeof(*pretinfo));
fail:
    if (ptmpinfo) {
        free(ptmpinfo);
    }
    ptmpinfo = NULL;

    if (pretinfo && pretinfo != *ppinfo) {
        free(pretinfo);
    }
    pretinfo = NULL;

    TcharToAnsi(NULL, &pmodname, &modsize);
    if (pmod) {
        free(pmod);
    }
    pmod = NULL;
    if (hd != NULL && hd != INVALID_HANDLE_VALUE) {
        CloseHandle(hd);
    }
    hd = NULL;

    SETERRNO(ret);
    return ret;
}


#if _MSC_VER >= 1910
#pragma warning(pop)
#endif