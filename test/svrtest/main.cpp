#include <extargs.h>
#include <win_svc.h>


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
        bret = ReadFile(hd,  &(pcurptr[retlen]), (size - retlen), &cbret, ov);
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
        bret = WriteFile(hd, &(pcurptr[retlen]), (size - retlen), &cbret, ov);
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
    int waitnum = 0;

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

        dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, timeoutmills, TRUE);
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
            ret = dret;
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
    int retsize = 0;
    char* ptmpdata = NULL;
    int retlen = 0;
    int waithds[2];
    int waitnum = 0;
    int ret;
    int readlen = 0;
    DWORD dret;
    uint64_t sticks = 0, curticks;
    int timeoutmills;
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

    retsize = *datasize;
    pretdata = *ppdata;

    if (retsize == 0 || pretdata == NULL) {
        if (retsize < 0) {
            retsize = 16;
        }
        pretdata = malloc(retsize);
        if (pretdata == NULL) {
            GETERRNO(ret);
            ERROR_INFO("malloc %d error [%d]", retsize, ret);
            goto fail;
        }
    }

    memset(pretdata, 0, retsize);
    sticks = get_current_ticks();

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

    timeoutmills = need_wait_times(sticks, curticks, maxmills);
    if (timeoutmills < 0) {
        ret = -WAIT_TIMEOUT;
        ERROR_INFO("timeout");
        goto fail;
    }


    dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, timeoutmills, TRUE);
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
        ret = dret;
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
    phdr = (ppipe_hdr_t) pretdata;
    if (phdr->m_datalen == sizeof(pipe_hdr_t)) {
        goto read_all;
    }
    if (retsize < phdr->m_datalen) {
        retsize = phdr->m_datalen;
        ptmpdata = malloc(retsize);
        if (ptmpdata == NULL) {
            GETERRNO(ret);
            ERROR_INFO("malloc %d error[%d]", retsize, ret);
            goto fail;
        }
        memset(ptmpdata, 0, retsize);
        if (retlen > 0) {
            memcpy(ptmpdata, pretdata, retlen);
        }
        if (pretdata && pretdata != *ppdata) {
            free(pretdata);
        }
        pretdata = ptmpdata;
        ptmpdata = NULL;
    } else 	if (phdr->m_datalen <= retlen) {
        goto read_all;
    }

    ret = read_file_overlapped(hpipe, ov, ov->hEvent, &(pretdata[retlen]), (phdr->m_datalen - retlen));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    retlen += ret;
    if (retlen == phdr->m_datalen) {
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

    dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, timeoutmills, TRUE);
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
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -WAIT_TIMEOUT;
        }
        ERROR_INFO("wait error [%d] %d", ret, dret);
        goto fail;
    }

    if (retlen < phdr->m_datalen) {
        goto try_read_more;
    }

read_all:
    if (*ppdata && pretdata != *ppdata) {
        free(*ppdata);
        *ppdata = NULL;
    }
    *ppdata = pretdata;
    *datasize = retsize;

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


int main_loop(HANDLE exitevt, char* pipename, int maxmills)
{
    HANDLE hpipe = NULL;


    if (hpipe != NULL) {

    }

    return 0;

fail:
    if (hpipe != NULL) {
        CloseHandle(hpipe);
    }
    hpipe = NULL;
    return ret;
}


static HANDLE st_hEvent = NULL;


VOID WINAPI svc_ctrl_handler( DWORD dwCtrl )
{
    int ret;
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        ret = report_svc_mode(SERVICE_STOP_PENDING, 500);
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
    int mask;

    st_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_hEvent == NULL) {
        GETERRNO(ret);
        ERROR_INFO("could not create event %d\n", ret);
        goto fail;
    }

    ret = report_svc_mode(SERVICE_RUNNING, 0);
    if (ret < 0) {
        ERROR_INFO("report running error %d\n", ret);
        goto fail;
    }


    ret = main_loop(st_hEvent, TSTSVR_PIPE, 10000);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run main loop error %d", ret);
        goto fail;
    }



    res = report_svc_mode(SERVICE_STOPPED, 0);
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
    res = report_svc_mode(SERVICE_STOPPED, 0);
    if (res < 0) {
        ERROR_INFO("report svc stopped error %d\n", res);
    }
    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;
    return ret;
}

VOID WINAPI svc_main( DWORD dwArgc, LPTSTR *lpszArgv )
{
    int ret;
    DEBUG_INFO("in main\n ");
    ret = init_svc_mode(SVCNAME, svc_ctrl_handler);
    if (ret < 0) {
        ERROR_INFO("can not init svc\n");
        return ;
    }
    svc_main_loop();

    close_svc_mode();
    return ;
}

int _tmain(int argc, _TCHAR* argv[])
{
    DEBUG_INFO("start simplsvc\n");
    return start_svc(SVCNAME, (LPSERVICE_MAIN_FUNCTION)svc_main);
}
