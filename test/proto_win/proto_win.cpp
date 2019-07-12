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
            if (ret != -ERROR_IO_PENDING && ret != -ERROR_MORE_DATA) {
                ERROR_INFO("can not read [%d] size [%d] error[%d]", retlen, size, ret);
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
        DEBUG_INFO("free [%p]", pov);
        free(pov);
        *ppov = NULL;
    }
    return ;
}

OVERLAPPED* alloc_overlap(const char* fmt, ...)
{
    OVERLAPPED* pov = NULL;
    int ret;

    DEBUG_INFO("alloc size %zd", sizeof(*pov));
    pov = (OVERLAPPED*)malloc(sizeof(*pov));
    if (pov == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc size [%d] error[%d]\n", sizeof(*pov), ret);
        goto fail;
    }

    DEBUG_INFO(" ");
    memset(pov, 0, sizeof(*pov));
    pov->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (pov->hEvent == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create event error[%d]\n", ret);
        goto fail;
    }

    DEBUG_INFO("alloc %p", pov);
    return pov;
fail:
    free_overlap(&pov);
    SETERRNO(ret);
    return NULL;
}


int bind_pipe(char* pipename, HANDLE exitevt, HANDLE* phd, OVERLAPPED** pprdov, OVERLAPPED** ppwrov)
{
	HANDLE hpipe=NULL;
	OVERLAPPED *prdov=NULL,*pwrov=NULL;
	int ret;
	TCHAR* ptpipename=NULL;
	int tpipesize = 0;
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    BOOL bret;
    DWORD dret;
    DWORD waitnum;
    HANDLE waithds[2];
    DWORD cbret;
	OVERLAPPED *pconnov=NULL;
    /*we set the security for everyone*/
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, (PACL) NULL, FALSE);
    sa.nLength = (DWORD) sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = (LPVOID) &sd;
    sa.bInheritHandle = TRUE;

	if (pipename == NULL) {
		/**/
		if (phd && *phd != NULL) {
			CloseHandle(*phd);
			*phd = NULL;
		}
		free_overlap(pprdov);
		free_overlap(ppwrov);
		return 0;
	}

	if (phd == NULL ||
		*phd != NULL || 
		pprdov == NULL || 
		*pprdov != NULL ||
		ppwrov == NULL ||
		*ppwrov != NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	ret= AnsiToTchar(pipename,&ptpipename,&tpipesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


    hpipe = CreateNamedPipe(
                        ptpipename,
                        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                        1, /*we only accept 1 instance*/
                        PIPE_BUFSIZE * sizeof(TCHAR),
                        PIPE_BUFSIZE * sizeof(TCHAR),
                        PIPE_TIMEOUT,
                        //NULL
                        &sa
                    );
   	if (hpipe ==NULL || hpipe == INVALID_HANDLE_VALUE) {
   		GETERRNO(ret);
   		ERROR_INFO("can not create %s error[%d]", pipename, ret);
   		hpipe = NULL;
   		goto fail;
   	}

	pconnov = alloc_overlap("%s conn evt", pipename);
	if (pconnov == NULL) {
		GETERRNO(ret);
		goto fail;
	}   	

   	bret = ConnectNamedPipe(hpipe,pconnov);
   	if (!bret) {
        GETERRNO(ret);
        DEBUG_INFO("ret %d", ret);
        if (ret != -ERROR_IO_PENDING && ret != -ERROR_PIPE_CONNECTED) {
            ERROR_INFO("connect (%s) error %d\n",pipename,ret);
            goto fail;
        }
        if (ret == -ERROR_IO_PENDING) {
        	waitnum = 0;
        	waithds[waitnum] = exitevt;
        	waitnum ++;
        	waithds[waitnum] = pconnov->hEvent;
        	waitnum ++;
        	dret = WaitForMultipleObjectsEx(waitnum,waithds,FALSE,5000,TRUE);
        	DEBUG_INFO("[%d]dret %d", waitnum, dret);
        	if (dret == WAIT_OBJECT_0) {
        		ret= -ERROR_CONTROL_C_EXIT;
        		goto fail;
        	} else if (dret == (WAIT_OBJECT_0 + 1)) {
        		bret = GetOverlappedResult(hpipe,pconnov,&cbret,FALSE);
        		if (!bret) {
        			GETERRNO(ret);
        			ERROR_INFO("connect %s result %d", pipename,ret);
        			goto fail;
        		}
        	} else {
        		GETERRNO(ret);
        		if (ret == -ERROR_CONTROL_C_EXIT) {
        			ret = -WAIT_TIMEOUT;
        		}
        		ERROR_INFO("wait connect [%s] error[%d] dret[%d]", pipename, ret, dret);
        		goto fail;
        	}
        }
   	}

   	prdov = alloc_overlap("%s rd ov", pipename);
   	if (prdov == NULL) {
   		GETERRNO(ret);
   		goto fail;
   	}

   	pwrov = alloc_overlap("%s wr ov", pipename);
   	if (pwrov == NULL) {
   		GETERRNO(ret);
   		goto fail;
   	}


	*phd = hpipe;
	*pprdov = prdov;
	*ppwrov = pwrov;

	free_overlap(&pconnov);
	AnsiToTchar(NULL,&ptpipename,&tpipesize);
	return 0;
fail:
	/*
		we close the pipe first ,it will give no 
		over
	*/
	if (hpipe != NULL) {
		CloseHandle(hpipe);
	}
	hpipe = NULL;
	free_overlap(&pconnov);
	free_overlap(&prdov);
	free_overlap(&pwrov);
	AnsiToTchar(NULL,&ptpipename,&tpipesize);
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