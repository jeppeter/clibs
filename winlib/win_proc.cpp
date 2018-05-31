#include <tchar.h>
#include <win_proc.h>
#include <win_fileop.h>
#include <win_err.h>
#include <win_uniansi.h>
#include <win_strop.h>
#include <win_time.h>

#pragma comment(lib,"Shell32.lib")
#pragma warning(disable:4996)

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
    ret = _snprintf(pcmd, (size_t)cmdlen, pid_wmic_cmd_fmt, tempfile, pid);
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
        strncpy(pcurptr, argv0, (size_t)(filllen - namelen));
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


#define __OLD_USE__   0


typedef struct __pipe_server {
    HANDLE m_pipesvr;
    HANDLE m_evt;
    HANDLE m_pipecli;
    OVERLAPPED m_ov;
    char* m_pipename;
    int m_pipesize;
    int m_wr;
    int m_state;
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

#if __OLD_USE__

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
#else /* __OLD_USE__ */

int __create_pipe(char* name, int wr, HANDLE* pparent, HANDLE *pcli, OVERLAPPED* pov, HANDLE *pevt, int* pstate)
{
    int ret;
    BOOL bret;
    SECURITY_ATTRIBUTES attr;

    if (name == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pparent == NULL || (*pparent != NULL && *pparent != INVALID_HANDLE_VALUE)) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pcli == NULL || (*pcli != NULL && *pcli != INVALID_HANDLE_VALUE)) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pevt == NULL || (*pevt != NULL && *pevt != INVALID_HANDLE_VALUE )) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pstate == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;        
    }

    memset(pov, 0 , sizeof(*pov));
    *pevt = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (*pevt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not create event for[%s] error[%d]", name, ret);
        goto fail;
    }
    pov->hEvent = *pevt;


    memset(&attr, 0, sizeof(attr));
    attr.nLength = sizeof(attr);
    attr.bInheritHandle = TRUE;
    attr.lpSecurityDescriptor = NULL;

    *pstate= PIPE_NONE;


    if (wr) {
        bret = CreatePipe(pcli, pparent, &attr, 0);
    } else {
        bret = CreatePipe(pparent, pcli, &attr, 0);
    }
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("create [%s] [%s] pipe error[%d]", name, wr ? "write" : "read", ret);
        goto fail;
    }

    bret = SetHandleInformation(*pparent, HANDLE_FLAG_INHERIT, 0);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not set handle information for [%p] error[%d]", *pparent, ret);
        goto fail;
    }

    *pstate = PIPE_READY;

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

ppipe_server_t __alloc_pipe_server(int wr, const char* fmt, ...)
{
    ppipe_server_t psvr = NULL;
    int ret;
    va_list ap;
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

    ret = __create_pipe(psvr->m_pipename, wr, &(psvr->m_pipesvr), &(psvr->m_pipecli), &(psvr->m_ov), &(psvr->m_evt), &(psvr->m_state));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return psvr;
fail:
    __free_pipe_server(&psvr);
    return NULL;
}


#endif /* __OLD_USE__ */

typedef struct __proc_handle {
#ifdef __PROC_DEBUG__
    uint32_t m_magic;
#endif
    /*handle for event overlapped*/
    ppipe_server_t m_stdinpipe;
    ppipe_server_t m_stdoutpipe;
    ppipe_server_t m_stderrpipe;

    HANDLE m_stdinnull;
    HANDLE m_stdoutnull;
    HANDLE m_stderrnull;

    HANDLE m_prochd;

    int m_exited;
    int m_exitcode;

    char* m_cmdline;
    int m_cmdlinesize;
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
    if (ppproc != NULL) {
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

#if __OLD_USE__
    char* tempname = NULL;
    int tempsize = 0;
    ret = __get_temp_pipe_name("pipe", &tempname, &tempsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
#endif /*__OLD_USE__*/

    if (flags & PROC_PIPE_STDIN) {
        if (pproc->m_stdinpipe != NULL) {
            ret = -ERROR_INVALID_PARAMETER;
            goto fail;
        }

#if __OLD_USE__
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
#else /*__OLD_USE__*/
        pproc->m_stdinpipe = __alloc_pipe_server(1, "stdin");
        if (pproc->m_stdinpipe == NULL) {
            GETERRNO(ret);
            goto fail;
        }
#endif /*__OLD_USE__*/
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

#if __OLD_USE__
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
#else  /*__OLD_USE__*/
        pproc->m_stdoutpipe = __alloc_pipe_server(0, "stdout");
        if (pproc->m_stdoutpipe == NULL) {
            GETERRNO(ret);
            goto fail;
        }
#endif /*__OLD_USE__*/

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

#if __OLD_USE__
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
#else /*__OLD_USE__*/
        pproc->m_stderrpipe = __alloc_pipe_server(0, "stderr");
        if (pproc->m_stderrpipe == NULL) {
            GETERRNO(ret);
            goto fail;
        }
#endif /*__OLD_USE__*/
    } else if (flags & PROC_STDERR_NULL) {
        ret = __create_nul(NULL, &(pproc->m_stderrnull), "null child stderr");
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    snprintf_safe(&pipename, &pipesize, NULL);
#if __OLD_USE__    
    __get_temp_pipe_name(NULL, &tempname, &tempsize);
#endif /*__OLD_USE__*/
    return 0;
fail:
    snprintf_safe(&pipename, &pipesize, NULL);
#if __OLD_USE__
    __get_temp_pipe_name(NULL, &tempname, &tempsize);
#endif /*__OLD_USE__*/
    SETERRNO(ret);
    return ret;
}


void* start_cmd_single(int createflag, char* prog)
{
    pproc_handle_t pproc = NULL;
    int ret;
    PROCESS_INFORMATION  *pinfo = NULL;
    STARTUPINFOW *pstartinfo = NULL;
    int usehd = 0;
    DWORD dwflag = 0;
    BOOL bret;
    wchar_t *wcmdline = NULL;
    int wcmdsize = 0;
    int res;

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
    }

    ret = AnsiToUnicode(pproc->m_cmdline, &wcmdline, &wcmdsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


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

    return (void*) pproc;
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
    __free_proc_handle(&pproc);
    SETERRNO(ret);
    return NULL;
}

void* start_cmdv(int createflag, char* prog[])
{
    pproc_handle_t pproc = NULL;
    int ret;
    PROCESS_INFORMATION  *pinfo = NULL;
    STARTUPINFOW *pstartinfo = NULL;
    int usehd = 0;
    DWORD dwflag = 0;
    BOOL bret;
    wchar_t *wcmdline = NULL;
    int wcmdsize = 0;
    int res;

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

    ret = __get_command_lines(&(pproc->m_cmdline), &(pproc->m_cmdlinesize), prog);
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
    }

    ret = AnsiToUnicode(pproc->m_cmdline, &wcmdline, &wcmdsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


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

    return (void*) pproc;
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
    __free_proc_handle(&pproc);
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
        bret = GetExitCodeProcess(pproc->m_prochd, &exitret);
        if (bret) {
            if (exitret != STILL_ACTIVE) {
                pproc->m_exited = 1;
                pproc->m_exitcode = (int)exitret;
                if (exitcode) {
                    *exitcode = (int)exitret;
                }
                return 0;
            }
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

    return totalbytes;
fail:
    SETERRNO(ret);
    return ret;
}

int __inner_run(pproc_handle_t pproc, char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout)
{
    int inlen = 0;
    char* pretout = NULL;
    int outsize = 0, outlen = 0;
    char* preterr = NULL;
    int errsize = 0, errlen = 0;
    char* ptmpbuf = NULL;
    HANDLE waithds[3];
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

        if (pproc->m_stdinpipe != NULL) {
            if (pproc->m_stdinpipe->m_state == PIPE_WAIT_CONNECT ||
                    pproc->m_stdinpipe->m_state == PIPE_WAIT_WRITE) {
                waithds[waitnum] = pproc->m_stdinpipe->m_evt;
                waitnum ++;
                DEBUG_INFO("add stdin");
            } else if (pproc->m_stdinpipe->m_state == PIPE_READY) {
                pending = 0;
                ret = __write_file_sync(pproc->m_stdinpipe->m_pipesvr, &(pproc->m_stdinpipe->m_ov), &(pin[inlen]), (insize - inlen), &pending);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }

                DEBUG_INFO("ret [%d] write[%d]", ret, (insize - inlen));

                inlen += ret;
                if (inlen > insize) {
                    ERROR_INFO("write [%s] inlen [%d] insize[%d]", pproc->m_stdinpipe->m_pipename, inlen, insize);
                    inlen = insize;
                }

                if (inlen == insize) {
                    /*now we should close the handle*/
                    DEBUG_INFO("close stdin");
                    __close_handle_note(&(pproc->m_stdinpipe->m_pipesvr), "%s close", pproc->m_stdinpipe->m_pipename);
                    pproc->m_stdinpipe->m_state = PIPE_NONE;
                } else if (pending) {
                    DEBUG_INFO("add stdin");
                    pproc->m_stdinpipe->m_state = PIPE_WAIT_WRITE;
                    waithds[waitnum] = pproc->m_stdinpipe->m_evt;
                    waitnum ++;
                }
            }
        }

        if (pproc->m_stdoutpipe != NULL) {
            if (pproc->m_stdoutpipe->m_state == PIPE_WAIT_CONNECT ||
                    pproc->m_stdoutpipe->m_state == PIPE_WAIT_READ) {
                waithds[waitnum] = pproc->m_stdoutpipe->m_evt;
                waitnum ++;
                DEBUG_INFO("add stdout");
            } else if (pproc->m_stdoutpipe->m_state == PIPE_READY) {
out_again:
                if (pretout == NULL || outsize == outlen) {
                    if (outsize < MIN_BUF_SIZE) {
                        outsize = MIN_BUF_SIZE;
                    } else if (outsize == outlen) {
                        outsize <<= 1;
                    }
                    ptmpbuf = (char*) malloc((size_t)outsize);
                    if (ptmpbuf == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc %d error[%d]", outsize, ret);
                        goto fail;
                    }
                    memset(ptmpbuf, 0 , (size_t)outsize);
                    if (outlen > 0) {
                        memcpy(ptmpbuf, pretout, (size_t)outlen);
                    }
                    if (pretout != NULL && pretout != *ppout) {
                        free(pretout);
                    }
                    pretout = ptmpbuf;
                    ptmpbuf = NULL;
                }

                pending = 0;
                ret = __read_file_sync(pproc->m_stdoutpipe->m_pipesvr, &(pproc->m_stdoutpipe->m_ov), &(pretout[outlen]), (outsize - outlen), &pending);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                if (ret > 0) {
                    DEBUG_BUFFER_FMT(&(pretout[outlen]), ret, "stdout new in");
                }
                outlen += ret;
                if (outlen > outsize) {
                    ERROR_INFO("read [%s] outlen[%d] outsize [%d]", pproc->m_stdoutpipe->m_pipename, outlen, outsize);
                    outlen = outsize;
                }

                if (pending == 0) {
                    if (outlen == outsize) {
                        goto out_again;
                    }
                    /*because we only read some bytes , so let it ok next try*/
                } else if (pending == 2) {
                    /*now close the file*/
                    __close_handle_note(&(pproc->m_stdoutpipe->m_pipesvr), "%s", pproc->m_stdoutpipe->m_pipename);
                    pproc->m_stdoutpipe->m_state = PIPE_NONE;
                    DEBUG_INFO("close stdout");
                } else {
                    waithds[waitnum] = pproc->m_stdoutpipe->m_evt;
                    waitnum ++;
                    pproc->m_stdoutpipe->m_state = PIPE_WAIT_READ;
                    DEBUG_INFO("add stdout");
                }
            }
        }

        if (pproc->m_stderrpipe != NULL) {
            if (pproc->m_stderrpipe->m_state == PIPE_WAIT_CONNECT ||
                    pproc->m_stderrpipe->m_state == PIPE_WAIT_READ) {
                waithds[waitnum] = pproc->m_stderrpipe->m_evt;
                waitnum ++;
                DEBUG_INFO("add stderr");
            } else if (pproc->m_stderrpipe->m_state == PIPE_READY) {
err_again:
                if (preterr == NULL || errsize == errlen) {
                    if (errsize < MIN_BUF_SIZE) {
                        errsize = MIN_BUF_SIZE;
                    } else if (errsize == errlen) {
                        errsize <<= 1;
                    }
                    ptmpbuf = (char*) malloc((size_t)errsize);
                    if (ptmpbuf == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc %d error[%d]", errsize, ret);
                        goto fail;
                    }
                    memset(ptmpbuf, 0 , (size_t)errsize);
                    if (errlen > 0) {
                        memcpy(ptmpbuf, preterr, (size_t)errlen);
                    }
                    if (preterr != NULL && preterr != *pperr) {
                        free(preterr);
                    }
                    preterr = ptmpbuf;
                    ptmpbuf = NULL;
                }
                pending = 0;
                ret = __read_file_sync(pproc->m_stderrpipe->m_pipesvr , &(pproc->m_stderrpipe->m_ov), &(preterr[errlen]), (errsize - errlen), &pending);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }

                if (ret > 0) {
                    DEBUG_BUFFER_FMT(&(preterr[errlen]), ret, "stderr new in");
                }
                errlen += ret;
                if (errlen > errsize) {
                    ERROR_INFO("read [%s] errlen[%d] errsize[%d]", pproc->m_stderrpipe->m_pipename, errlen, errsize);
                    errlen = errsize;
                }

                if (pending == 0) {
                    if (errlen == errsize) {
                        goto err_again;
                    }
                    /*we only read this ,so just next try*/
                } else if (pending == 2) {
                    __close_handle_note(&(pproc->m_stderrpipe->m_pipesvr), "%s", pproc->m_stderrpipe->m_pipename);
                    pproc->m_stderrpipe->m_state = PIPE_NONE;
                    DEBUG_INFO("close stderr");
                } else {
                    waithds[waitnum] = pproc->m_stderrpipe->m_evt;
                    waitnum ++;
                    pproc->m_stderrpipe->m_state = PIPE_WAIT_READ;
                    DEBUG_INFO("add stderr");
                }
            }
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
            if ((dret >= WAIT_OBJECT_0) && (dret < (WAIT_OBJECT_0 + waitnum))) {
                hd = waithds[(dret - WAIT_OBJECT_0)];
                if (pproc->m_stdinpipe
                        && (pproc->m_stdinpipe->m_state == PIPE_WAIT_CONNECT  || pproc->m_stdinpipe->m_state == PIPE_WAIT_WRITE)
                        && hd == pproc->m_stdinpipe->m_evt) {
                    DEBUG_INFO("stdin write");
                    ret = __get_overlapped(pproc->m_stdinpipe->m_pipesvr, &(pproc->m_stdinpipe->m_ov), &inlen, "stdin result");
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto fail;
                    }
                    /*inwait over*/
                    inwait = ret;
                    if (inwait == 0) {
                        if (pproc->m_stdinpipe->m_state == PIPE_WAIT_CONNECT) {
                            pproc->m_stdinpipe->m_state = PIPE_READY;
                        } else if (pproc->m_stdinpipe->m_state == PIPE_WAIT_WRITE) {
                            pproc->m_stdinpipe->m_state = PIPE_READY;
                        }
                        DEBUG_INFO("stdin write inlen[%d]", inlen);
                        /*already */
                        if (inlen == insize) {
                            __close_handle_note(&(pproc->m_stdinpipe->m_pipesvr), "%s", pproc->m_stdinpipe->m_pipename);
                            pproc->m_stdinpipe->m_state = PIPE_NONE;
                            DEBUG_INFO("close stdin");
                        }
                    }
                } else if (pproc->m_stdoutpipe != NULL &&
                           (pproc->m_stdoutpipe->m_state == PIPE_WAIT_READ || pproc->m_stdoutpipe->m_state == PIPE_WAIT_CONNECT)
                           && hd == pproc->m_stdoutpipe->m_evt) {
                    DEBUG_INFO("stdout read");
                    outwait = outlen;
                    ret = __get_overlapped(pproc->m_stdoutpipe->m_pipesvr, &(pproc->m_stdoutpipe->m_ov), &outlen, "get stdout result");
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto fail;
                    }
                    if (outlen != outwait) {
                        DEBUG_BUFFER_FMT(&pretout[outwait], (outlen - outwait), "stdout ov");
                    }

                    outwait = ret;
                    if (outwait == 0) {
                        if (pproc->m_stdoutpipe->m_state == PIPE_WAIT_CONNECT) {
                            pproc->m_stdoutpipe->m_state = PIPE_READY;
                        } else if (pproc->m_stdoutpipe->m_state == PIPE_WAIT_READ) {
                            pproc->m_stdoutpipe->m_state = PIPE_READY;
                        }
                        DEBUG_INFO("ready stdout outlen[%d]", outlen);
                    }

                } else if (pproc->m_stderrpipe && (pproc->m_stderrpipe->m_state == PIPE_WAIT_CONNECT || pproc->m_stderrpipe->m_state == PIPE_WAIT_READ)
                           && hd == pproc->m_stderrpipe->m_evt) {
                    DEBUG_INFO("stderr read");
                    errwait = errlen;
                    ret = __get_overlapped(pproc->m_stderrpipe->m_pipesvr, &(pproc->m_stderrpipe->m_ov), &errlen, "get stdout result");
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto fail;
                    }
                    if (errwait != errlen) {
                        DEBUG_BUFFER_FMT(&preterr[errwait], (errlen - errwait), "stderr ov");
                    }
                    errwait = ret;
                    if (errwait == 0) {
                        if (pproc->m_stderrpipe->m_state == PIPE_WAIT_CONNECT) {
                            pproc->m_stderrpipe->m_state = PIPE_READY;
                        } else if (pproc->m_stderrpipe->m_state == PIPE_WAIT_READ) {
                            pproc->m_stderrpipe->m_state = PIPE_READY;
                        }
                        DEBUG_INFO("ready stderr errlen[%d]", errlen);
                    }
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

    /*now exited we will give the output so we may have some data in the pipe*/
    if (pproc->m_stdoutpipe != NULL ) {
        DEBUG_INFO("stdout [%s]", pproc->m_stdoutpipe->m_state == PIPE_READY ? "READY" : "WAIT");
        ret = __left_pipe_bytes(pproc->m_stdoutpipe->m_pipesvr);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        curlen = ret;
        if (curlen > 0) {
            if ((outsize - outlen) < curlen) {
                outsize = (outsize - outlen +  curlen);
                ptmpbuf = (char*) malloc(outsize);
                if (ptmpbuf == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", outsize, ret);
                    goto fail;
                }
                memset(ptmpbuf, 0, outsize);
                if (outlen > 0) {
                    memcpy(ptmpbuf, pretout, outlen);
                }
                if (pretout && pretout != *ppout) {
                    free(pretout);
                }
                pretout = ptmpbuf;
                ptmpbuf = NULL;
            }
            ret = __read_file_sync(pproc->m_stdoutpipe->m_pipesvr, &(pproc->m_stdoutpipe->m_ov), &(pretout[outlen]), curlen, &pending);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }


            if (ret != curlen) {
                ret = -ERROR_INTERNAL_ERROR;
                ERROR_INFO("read stdout left error[%d]", ret);
                goto fail;
            }
            DEBUG_BUFFER_FMT(&(pretout[outlen]), curlen, "new stdout");
            outlen += ret;
        }
    }

    if (pproc->m_stderrpipe != NULL ) {
        DEBUG_INFO("stdout [%s]", pproc->m_stderrpipe->m_state == PIPE_READY ? "READY" : "WAIT");
        ret = __left_pipe_bytes(pproc->m_stderrpipe->m_pipesvr);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        curlen = ret;
        if (curlen > 0) {
            if ((errsize - errlen) < curlen) {
                errsize = (errsize - errlen +  curlen);
                ptmpbuf = (char*) malloc(errsize);
                if (ptmpbuf == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", errsize, ret);
                    goto fail;
                }
                memset(ptmpbuf, 0, errsize);
                if (errlen > 0) {
                    memcpy(ptmpbuf, preterr, errlen);
                }
                if (preterr && preterr != *pperr) {
                    free(preterr);
                }
                preterr = ptmpbuf;
                ptmpbuf = NULL;
            }
            ret = __read_file_sync(pproc->m_stderrpipe->m_pipesvr, &(pproc->m_stderrpipe->m_ov), &(preterr[errlen]), curlen, &pending);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }

            if (ret != curlen) {
                ret = -ERROR_INTERNAL_ERROR;
                ERROR_INFO("read stderr left error[%d]", ret);
                goto fail;
            }
            DEBUG_BUFFER_FMT(&(preterr[errlen]), curlen, "new stderr");
            errlen += ret;
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


int run_cmd_output_single(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog)
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

    ret = __inner_run(pproc, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout);
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

int run_cmd_outputv(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, char* prog[])
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

    ret = __inner_run(pproc, pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout);
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

int run_cmd_outputa(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, va_list ap)
{
    va_list oldap;
    char** progv = NULL;
    int i;
    int retlen;
    int ret;
    char* curarg;
    int cnt = 0;

    if (prog == NULL) {
        return run_cmd_outputv(pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, NULL);
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

    ret = run_cmd_outputv(pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, progv);
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

int run_cmd_output(char* pin, int insize, char** ppout, int *poutsize, char** pperr, int *perrsize, int *exitcode, int timeout, const char* prog, ...)
{
    va_list ap = NULL;
    if (prog == NULL) {
        return run_cmd_outputa(pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, NULL, ap);
    }
    va_start(ap, prog);
    return run_cmd_outputa(pin, insize, ppout, poutsize, pperr, perrsize, exitcode, timeout, prog, ap);
}