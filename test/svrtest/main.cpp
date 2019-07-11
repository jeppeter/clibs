#include <extargs.h>
#include <win_svc.h>
#include <win_time.h>
#include <win_strop.h>
#include <win_uniansi.h>
#include <tchar.h>


#define  TSTSVR_PIPE "\\\\.\\pipe\\tstsvr_pipe"
#define  SVCNAME     "tstsvr"
#define  PIPE_BUFSIZE  4096
#define  PIPE_TIMEOUT  5000

#pragma comment(lib,"Advapi32.lib")

typedef struct __args_options {
    int m_verbose;
} args_options_t,*pargs_options_t;


#include "args_options.cpp"

int handle_cmds(int argc, char* argv[])
{
    int ret = 0;
    args_options_t argsoption;
    pextargs_state_t pextstate = NULL;

    memset(&argsoption, 0, sizeof(argsoption));


    ret = EXTARGS_PARSE(argc, argv, &argsoption, pextstate);
    //ret = parse_param_smart(argc, args, st_main_cmds, &argsoption, &pextstate, NULL, NULL);
    if (ret < 0) {
        fprintf(stderr, "could not parse error(%d)", ret);
        goto out;
    }

    ret = 0;
out:
    free_extargs_state(&pextstate);
    release_extargs_output(&argsoption);
    extargs_deinit();
    return ret;
}




typedef struct __pipe_hdr_t {
    uint32_t m_datalen;
    uint32_t m_cmd;
} pipe_hdr_t, *ppipe_hdr_t;

int read_file_overlapped(HANDLE hd, OVERLAPPED* ov, HANDLE evt, void* pbuf, int size)
{
    BOOL bret;
    unsigned char* pcurptr = (unsigned char*)pbuf;
    int retlen = 0;
    DWORD cbret;
    int ret;

    ov->hEvent = evt;
    while (retlen < size) {
        bret = ReadFile(hd,  &(pcurptr[retlen]), (DWORD)(size - retlen), &cbret, ov);
        if (!bret) {
            GETERRNO(ret);
            if (ret != -ERROR_IO_PENDING) {
                ERROR_INFO("can not read [%d] error[%d]", retlen, ret);
                goto fail;
            }
            break;
        }

        if (cbret == 0) {
            GETERRNO(ret);
            ERROR_INFO("read 0 size");
            goto fail;
        }
        retlen += cbret;
    }
    DEBUG_INFO("retlen [%d]", retlen);
    return retlen;
fail:
    SETERRNO(ret);
    return ret;
}

int get_overlapped_res(HANDLE hd , OVERLAPPED* ov, HANDLE evt, int wr)
{
    BOOL bret;
    DWORD cbret;
    int retlen = 0;
    int ret;
    ov->hEvent = evt;
    bret = GetOverlappedResult(hd, ov, &cbret, FALSE);
    if (!bret) {
        GETERRNO(ret);
        if (ret != -ERROR_IO_PENDING && wr) {
            ERROR_INFO("overlapped result [%d]", ret);
            goto fail;
        } else if (ret != -ERROR_IO_PENDING && ret != -ERROR_MORE_DATA && wr == 0) {
            ERROR_INFO("overlapped result [%d]", ret);
            goto fail;
        }
        DEBUG_INFO("ret [%d]", ret);
        if (ret == -ERROR_MORE_DATA && wr == 0) {
            DEBUG_INFO("cbret [%d]", cbret);
            retlen += cbret;
        }
    } else {
        if (cbret == 0 && wr == 0) {
            GETERRNO(ret);
            ERROR_INFO("read cbret [0]");
            goto fail;
        }
        DEBUG_INFO("cbret [%d]", cbret);
        retlen += cbret;
    }

    return retlen;
fail:
    SETERRNO(ret);
    return ret;
}

int write_file_overlap(HANDLE hd, OVERLAPPED *ov, HANDLE evt, void* pbuf, int size)
{
    BOOL bret;
    unsigned char* pcurptr = (unsigned char*)pbuf;
    int retlen = 0;
    DWORD cbret;
    int ret;

    ov->hEvent = evt;
    while (retlen < size) {
        //DEBUG_INFO("before [%d]", retlen);
        bret = WriteFile(hd, &(pcurptr[retlen]), (DWORD)(size - retlen), &cbret, ov);
        //DEBUG_INFO("after [%d] cbret %d", retlen, cbret);
        if (!bret) {
            GETERRNO(ret);
            if (ret != -ERROR_IO_PENDING) {
                ERROR_INFO("can not write [%d] error[%d]", retlen, ret);
                goto fail;
            }
            break;
        }
        retlen += cbret;
    }
    FlushFileBuffers(hd);
    return retlen;
fail:
    SETERRNO(ret);
    return ret;
}



int write_pipe_data(HANDLE exitevt, HANDLE hpipe, OVERLAPPED* ov, int maxmills, char* pdata, int datalen)
{
    int retlen = 0;
    int ret;
    uint64_t sticks, curticks = 0;
    int timeoutmills;
    HANDLE waithds[2];
    DWORD waitnum = 0;
    DWORD dret;

    sticks = get_current_ticks();

    ret = write_file_overlap(hpipe, ov, ov->hEvent, pdata, datalen);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    retlen += ret;
    while (retlen < datalen) {
        waitnum = 0;
        waithds[waitnum] = exitevt;
        waitnum ++;
        waithds[waitnum] = ov->hEvent;
        waitnum ++;
        curticks = get_current_ticks();
        timeoutmills = need_wait_times(sticks, curticks, maxmills);
        if (timeoutmills < 0) {
            ret = -WAIT_TIMEOUT;
            ERROR_INFO("timeout write");
            goto fail;
        }

        dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)timeoutmills, TRUE);
        if (dret == WAIT_OBJECT_0) {
            ret = -ERROR_CONTROL_C_EXIT;
            goto fail;
        } else if (dret == (WAIT_OBJECT_0 + 1)) {
            ret = get_overlapped_res(hpipe, ov, ov->hEvent, 1);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            retlen += ret;
        } else {
            ret = (int)dret;
            if (ret > 0) {
                ret = -ret;
            }
            if (ret == 0) {
                ret = -WAIT_TIMEOUT;
            }
            ERROR_INFO("wait error [%d] %d", ret, dret);
            goto fail;
        }
    }

    return retlen;
fail:
    SETERRNO(ret);
    return ret;
}


int read_pipe_data(HANDLE exitevt, HANDLE hpipe, OVERLAPPED* ov, int maxmills, char** ppdata, int *datasize)
{
    char* pretdata = NULL;
    size_t retsize = 0;
    char* ptmpdata = NULL;
    int retlen = 0;
    HANDLE waithds[2];
    DWORD waitnum = 0;
    int ret;
    DWORD dret;
    uint64_t sticks = 0, curticks;
    int timeoutmills;
    int curmaxmills = 0;
    ppipe_hdr_t phdr = NULL;
    if (exitevt == NULL ||
            hpipe == NULL) {
        if (ppdata && *ppdata) {
            free(*ppdata);
        }
        *ppdata = NULL;
        if (datasize) {
            *datasize = 0;
        }
        return 0;
    }

    if (ppdata == NULL || datasize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    retsize = (size_t)*datasize;
    pretdata = *ppdata;

    if (retsize == 0 || pretdata == NULL) {
        if (retsize <= 0) {
            retsize = 16;
        }
        pretdata = (char*)malloc((size_t)retsize);
        if (pretdata == NULL) {
            GETERRNO(ret);
            ERROR_INFO("malloc %d error [%d]", retsize, ret);
            goto fail;
        }
    }

    memset(pretdata, 0, (size_t)retsize);

    ret = read_file_overlapped(hpipe, ov, ov->hEvent, &(pretdata[retlen]), sizeof(pipe_hdr_t));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    retlen += ret;
    if (retlen == sizeof(pipe_hdr_t)) {
        goto next_read_more;
    }


try_headers:
    waitnum = 0;
    waithds[waitnum] = exitevt;
    waitnum ++;
    waithds[waitnum] = ov->hEvent;
    waitnum ++;
    curmaxmills = 15000;

    timeoutmills = curmaxmills;
    dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)timeoutmills, TRUE);
    if (dret == WAIT_OBJECT_0) {
        ret = -ERROR_CONTROL_C_EXIT;
        goto fail;
    } else if (dret == (WAIT_OBJECT_0 + 1)) {
        ret = get_overlapped_res(hpipe, ov, ov->hEvent, 0);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        retlen += ret;
    } else {
        if (dret == WAIT_TIMEOUT) {
            /*we first to get the header ,so we should */
            goto try_headers;
        }

        ret = (int)dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -WAIT_TIMEOUT;
        }
        ERROR_INFO("wait error [%d] %d", ret, dret);
        goto fail;
    }

    if (retlen < sizeof(pipe_hdr_t)) {
        goto try_headers;
    }


next_read_more:
    sticks = get_current_ticks();
    phdr = (ppipe_hdr_t) pretdata;
    if (phdr->m_datalen == sizeof(pipe_hdr_t)) {
        goto read_all;
    }
    if (retsize < phdr->m_datalen) {
        retsize = phdr->m_datalen;
        ptmpdata = (char*)malloc(retsize);
        if (ptmpdata == NULL) {
            GETERRNO(ret);
            ERROR_INFO("malloc %d error[%d]", retsize, ret);
            goto fail;
        }
        memset(ptmpdata, 0, retsize);
        if (retlen > 0) {
            memcpy(ptmpdata, pretdata, (size_t)retlen);
        }
        if (pretdata && pretdata != *ppdata) {
            free(pretdata);
        }
        pretdata = ptmpdata;
        ptmpdata = NULL;
    } else  if ((int)phdr->m_datalen <= retlen) {
        goto read_all;
    }

    ret = read_file_overlapped(hpipe, ov, ov->hEvent, &(pretdata[retlen]), (int)(phdr->m_datalen - retlen));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    retlen += ret;
    if (retlen == (int)phdr->m_datalen) {
        goto read_all;
    }

try_read_more:
    waitnum = 0;
    waithds[waitnum] = exitevt;
    waitnum ++;
    waithds[waitnum] = ov->hEvent;
    waitnum ++;
    curticks = get_current_ticks();
    timeoutmills = need_wait_times(sticks, curticks, maxmills);
    if (timeoutmills < 0) {
        ret = -WAIT_TIMEOUT;
        ERROR_INFO("timeout");
        goto fail;
    }

    dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)timeoutmills, TRUE);
    if (dret == WAIT_OBJECT_0) {
        ret = -ERROR_CONTROL_C_EXIT;
        goto fail;
    } else if (dret == (WAIT_OBJECT_0 + 1)) {
        ret = get_overlapped_res(hpipe, ov, ov->hEvent, 0);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        retlen += ret;
    } else {
        ret = (int)dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -WAIT_TIMEOUT;
        }
        ERROR_INFO("wait error [%d] %d", ret, dret);
        goto fail;
    }

    if (retlen < (int)phdr->m_datalen) {
        goto try_read_more;
    }

read_all:
    if (*ppdata && pretdata != *ppdata) {
        free(*ppdata);
        *ppdata = NULL;
    }
    *ppdata = pretdata;
    *datasize = (int)retsize;

    return retlen;

fail:
    if (ptmpdata) {
        free(ptmpdata);
    }
    ptmpdata = NULL;

    if (pretdata && pretdata != *ppdata) {
        free(pretdata);
    }
    pretdata = NULL;
    SETERRNO(ret);
    return ret;
}

void free_overlap(OVERLAPPED** ppov)
{
    OVERLAPPED* pov = NULL;
    if (ppov && *ppov) {
        pov = *ppov;
        if (pov->hEvent != NULL) {
            CloseHandle(pov->hEvent);
            pov->hEvent = NULL;
        }
        free(pov);
        *ppov = NULL;
    }
    return ;
}

OVERLAPPED* alloc_overlap(const char* fmt, ...)
{
    OVERLAPPED* pov = NULL;
    va_list ap;
    char* errstr = NULL;
    int errsize = 0;
    int ret;
    int res;



    pov = (OVERLAPPED*)malloc(sizeof(*pov));
    if (pov == NULL) {
        GETERRNO(ret);
        va_start(ap, fmt);
        res = vsnprintf_safe(&errstr, &errsize, fmt, ap);
        if (res > 0) {
            ERROR_INFO("alloc %s size [%d] error[%d]\n", errstr, sizeof(*pov), ret);
        }
        goto fail;
    }

    memset(pov, 0, sizeof(*pov));
    pov->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (pov->hEvent == NULL) {
        GETERRNO(ret);
        va_start(ap, fmt);
        res = vsnprintf_safe(&errstr, &errsize, fmt, ap);
        if (res > 0) {
            ERROR_INFO("create %s event error[%d]\n", errstr, ret);
        }
    }

    return pov;
fail:
    free_overlap(&pov);
    SETERRNO(ret);
    return NULL;
}


int connect_pipe(char* pipename, HANDLE exitevt, HANDLE* phd, OVERLAPPED** pprdov, OVERLAPPED** ppwrov)
{
    HANDLE hpipe = NULL;
    OVERLAPPED *pwrov = NULL, *prdov = NULL, *pconnov = NULL;
    TCHAR *ptname = NULL;
    int tnamesize = 0;
    int ret;
    BOOL bret;
    DWORD cbret;
    DWORD waitnum=0;
    HANDLE waithds[2];
    DWORD dret;
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    /*we set the security for everyone*/
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, (PACL) NULL, FALSE);
    sa.nLength = (DWORD) sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = (LPVOID) &sd;
    sa.bInheritHandle = TRUE;


    if (pipename == NULL) {
        free_overlap(pprdov);
        free_overlap(ppwrov);
        if (phd && *phd != NULL) {
            CloseHandle(*phd);
            *phd = NULL;
        }
        return 0;
    }

    if (phd == NULL || *phd != NULL ||
            pprdov == NULL || *pprdov != NULL ||
            ppwrov == NULL || *ppwrov != NULL ||
            exitevt == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    DEBUG_INFO("connect [%s]", pipename);
    ret = AnsiToTchar(pipename, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pconnov = alloc_overlap("%s connect event",pipename);
    if (pconnov == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    hpipe = CreateNamedPipe(
                ptname,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1, /*we only accept 1 instance*/
                PIPE_BUFSIZE * sizeof(TCHAR),
                PIPE_BUFSIZE * sizeof(TCHAR),
                PIPE_TIMEOUT,
                //NULL
                &sa
            );
    if (hpipe == NULL || hpipe == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        hpipe = NULL;
        ERROR_INFO("can not open pipe [%s] error[%d]", pipename, ret);
        goto fail;
    }

    bret = ConnectNamedPipe(hpipe, pconnov);
    if (!bret) {
        GETERRNO(ret);
        if (ret != -ERROR_PIPE_CONNECTED &&
                ret != -ERROR_IO_PENDING) {
            ERROR_INFO("connect [%s] error [%d]", pipename, ret);
            goto fail;
        }

        if (ret == -ERROR_IO_PENDING) {
            waitnum = 0;
            waithds[waitnum] = exitevt;
            waitnum ++;
            waithds[waitnum] = pconnov->hEvent;
            waitnum ++;

            /*wait for connecting*/
            dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, 5000, FALSE);
            if (dret == WAIT_OBJECT_0) {
                ret = -ERROR_CONTROL_C_EXIT;
                goto fail;
            } else if (dret == (WAIT_OBJECT_0 + 1)) {
                bret = GetOverlappedResult(hpipe, pconnov, &cbret, FALSE);
                if (!bret) {
                    GETERRNO(ret);
                    ERROR_INFO("get [%s] connect overlap error[%d]", pipename, ret);
                    goto fail;
                }
            } else {
                GETERRNO(ret);
                ERROR_INFO("wait connect error [%d] dret[%d]", ret, dret);
                goto fail;
            }
        }
    }

    prdov = alloc_overlap("%s read event", pipename);
    if (prdov == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    pwrov = alloc_overlap("%s write event", pipename);
    if (pwrov == NULL) {
        GETERRNO(ret);
        goto fail;
    }


    *ppwrov = pwrov;
    *pprdov = prdov;
    *phd = hpipe;

    free_overlap(&pconnov);
    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    AnsiToTchar(NULL, &ptname, &tnamesize);
    free_overlap(&pconnov);
    free_overlap(&prdov);
    free_overlap(&pwrov);
    if (hpipe != NULL) {
        CloseHandle(hpipe);
    }
    hpipe = NULL;
    SETERRNO(ret);
    return ret;
}

int main_loop(HANDLE exitevt, char* pipename, int maxmills)
{
    char* pindata = NULL;
    int indatasize = 0, indatalen = 0;
    int ret;
    HANDLE hpipe=NULL;
    OVERLAPPED *prdov=NULL,*pwrov=NULL;
    HANDLE waithds[2];
    DWORD waitnum = 0;
    DWORD dret;


bind_pipe_again:
    connect_pipe(NULL, exitevt, &hpipe, &prdov, &pwrov);
    ret = connect_pipe(pipename, exitevt, &hpipe, &prdov, &pwrov);
    if (ret < 0) {
        GETERRNO(ret);
        if (ret == -ERROR_CONTROL_C_EXIT) {
            goto fail;
        }
        waitnum = 0;
        waithds[waitnum] = exitevt;
        waitnum ++;
        /*a 1000 ms to retry*/
        dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, 1000, FALSE);
        if (dret == WAIT_OBJECT_0) {
            ret = -ERROR_CONTROL_C_EXIT;
            goto fail;
        }
        goto bind_pipe_again;
    }



    while (1) {
        ret = read_pipe_data(exitevt, hpipe, prdov, maxmills, &pindata, &indatasize);
        if (ret < 0) {
            if (ret == -ERROR_CONTROL_C_EXIT) {
                break;
            }
            ERROR_INFO("will build pipe again");
            goto bind_pipe_again;
        }

        indatalen = ret;
        DEBUG_BUFFER_FMT(pindata, ret, "indatalen [%d]", indatalen);
    }


    connect_pipe(NULL,exitevt,&hpipe,&prdov,&pwrov);
    read_pipe_data(NULL, NULL, NULL, 0, &pindata, &indatasize);
    return 0;

fail:
    connect_pipe(NULL,exitevt,&hpipe,&prdov,&pwrov);
    read_pipe_data(NULL, NULL, NULL, 0, &pindata, &indatasize);
    SETERRNO(ret);
    return ret;
}


static HANDLE st_hEvent = NULL;


VOID WINAPI svc_ctrl_handler( DWORD dwCtrl )
{
    int ret;
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        ret = svc_report_mode(SERVICE_STOP_PENDING, 500);
        if (ret < 0) {
            ERROR_INFO("ctrl handle stop pending error %d\n", ret);
        }
        // Signal the service to stop.
        SetEvent(st_hEvent);
        return;

    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    }
    return ;
}


int svc_main_loop()
{
    int ret, res;

    st_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_hEvent == NULL) {
        GETERRNO(ret);
        ERROR_INFO("could not create event %d\n", ret);
        goto fail;
    }

    ret = svc_report_mode(SERVICE_RUNNING, 0);
    if (ret < 0) {
        ERROR_INFO("report running error %d\n", ret);
        goto fail;
    }


    ret = main_loop(st_hEvent, TSTSVR_PIPE, 1000);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run main loop error %d", ret);
        goto fail;
    }



    res = svc_report_mode(SERVICE_STOPPED, 0);
    if (res < 0) {
        ERROR_INFO("report svc stopped error %d\n", res);
        ret = res;
        goto fail;
    }
    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;

    return ret;
fail:
    res = svc_report_mode(SERVICE_STOPPED, 0);
    if (res < 0) {
        ERROR_INFO("report svc stopped error %d\n", res);
    }
    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;
    return ret;
}

VOID WINAPI svc_main( DWORD dwArgc, LPSTR *lpszArgv )
{
    int ret;
    dwArgc = dwArgc;
    lpszArgv = lpszArgv;
    DEBUG_INFO("in main\n ");
    ret = svc_init_mode(SVCNAME, svc_ctrl_handler);
    if (ret < 0) {
        ERROR_INFO("can not init svc\n");
        return ;
    }
    svc_main_loop();

    svc_close_mode();
    return ;
}

int _tmain(int argc, _TCHAR* argv[])
{
    DEBUG_INFO("start simplsvc\n");
    argc = argc;
    argv = argv;
    return svc_start(SVCNAME, svc_main);
}
