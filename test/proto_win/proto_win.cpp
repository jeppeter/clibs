#include <proto_win.h>
#include <proto_api.h>
#include <win_uniansi.h>
#include <win_err.h>
#include <win_time.h>
#include <win_strop.h>


#define  PIPE_BUFSIZE  4096
#define  PIPE_TIMEOUT  5000

#pragma comment(lib,"Advapi32.lib")


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


    va_start(ap, fmt);
    pov = (OVERLAPPED*)malloc(sizeof(*pov));
    if (pov == NULL) {
        GETERRNO(ret);
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
        res = vsnprintf_safe(&errstr, &errsize, fmt, ap);
        if (res > 0) {
            ERROR_INFO("create %s event error[%d]\n", errstr, ret);
        }
    }

    vsnprintf_safe(&errstr, &errsize, NULL, ap);
    return pov;
fail:
    free_overlap(&pov);
    vsnprintf_safe(&errstr, &errsize, NULL, ap);
    SETERRNO(ret);
    return NULL;
}


int bind_pipe(char* pipename, HANDLE exitevt, HANDLE* phd, OVERLAPPED** pprdov, OVERLAPPED** ppwrov)
{
    HANDLE hpipe = NULL;
    OVERLAPPED *pwrov = NULL, *prdov = NULL, *pconnov = NULL;
    TCHAR *ptname = NULL;
    int tnamesize = 0;
    int ret;
    BOOL bret;
    DWORD cbret;
    DWORD waitnum = 0;
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

    pconnov = alloc_overlap("%s connect event", pipename);
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


int connect_pipe(char* pipename, HANDLE exitevt, HANDLE *phd, OVERLAPPED** pprdov, OVERLAPPED** ppwrov)
{
    TCHAR* ptpipename = NULL;
    int tpipesize = 0;
    HANDLE hpipe = NULL;
    OVERLAPPED *prdov = NULL, *pwrov = NULL;
    int ret;

    if (pipename == NULL) {
        free_overlap(pprdov);
        free_overlap(ppwrov);
        if (phd && *phd) {
            CloseHandle(*phd);
            *phd = NULL;
        }
        return 0;
    }

    if (exitevt == NULL ||
            phd == NULL || *phd != NULL ||
            pprdov == NULL || *pprdov != NULL ||
            ppwrov == NULL || *ppwrov != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    ret = AnsiToTchar(pipename, &ptpipename, &tpipesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    hpipe = CreateFile(ptpipename,
                       GENERIC_READ | GENERIC_WRITE,
                       0,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_OVERLAPPED,
                       NULL);
   	if (hpipe == NULL || hpipe == INVALID_HANDLE_VALUE) {
   		GETERRNO(ret);
   		hpipe = NULL;
   		ERROR_INFO("connect [%s] pipe error [%d]", pipename, ret);
   		goto fail;
   	}

   	prdov = alloc_overlap("%s rd evt", pipename);
   	if (prdov == NULL) {
   		GETERRNO(ret);
   		goto fail;
   	}


   	pwrov = alloc_overlap("%s wr evt", pipename);
   	if (pwrov == NULL) {
   		GETERRNO(ret);
   		goto fail;
   	}

    AnsiToTchar(NULL, &ptpipename, &tpipesize);
    *phd = hpipe;
    *pprdov = prdov;
    *ppwrov = pwrov;
    return 0;
fail:
    AnsiToTchar(NULL, &ptpipename, &tpipesize);
    free_overlap(&prdov);
    free_overlap(&pwrov);
    if (hpipe != NULL) {
        CloseHandle(hpipe);
    }
    hpipe = NULL;
    SETERRNO(ret);
    return ret;
}