#include <apipe.h>


void __free_async_evt(pasync_evt_t* ppevt)
{
    BOOL bret;
    int res;
    if (ppevt != NULL && *ppevt != NULL) {
        pasync_evt_t pevt = *ppevt;
        if (pevt->m_evt != NULL) {
            bret = CloseHandle(pevt->m_evt);
            if (!bret) {
                GETERRNO(res);
                ERROR_INFO("close handle [%p] error[%d]", pevt->m_evt, res);
            }
            pevt->m_evt = NULL;
        }
        pevt->m_cbret = 0;
        pevt->m_errorcode = 0;
        free(pevt);
        *ppevt = NULL;
    }
    return;
}

pasync_evt_t __alloc_async_evt()
{
    pasync_evt_t pevt = NULL;
    int ret;

    pevt = (pasync_evt_t)malloc(sizeof(*pevt));
    if (pevt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*pevt), ret);
        goto fail;
    }

    memset(pevt, 0, sizeof(*pevt));
    pevt->m_evt = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (pevt->m_evt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not create event error[%d]", ret);
        goto fail;
    }

    return pevt;
fail:
    __free_async_evt(&pevt);
    return NULL;
}


int __create_pipe_async(char* name , int wr, HANDLE *ppipe, OVERLAPPED* pov, int bufsize)
{
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    BOOL bret;
    int res;
    int ret;
    if (name == NULL ||  ppipe == NULL || *ppipe != NULL || pov == NULL
            || pov->hEvent == NULL || pov->hEvent == INVALID_HANDLE_VALUE) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pov->hEvent != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    /*now we should make the */
    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    *ppipe = CreateNamedPipe(ptname, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_WAIT, 1, bufsize, bufsize, PIPE_TIMEOUT, NULL);
    if (*ppipe == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not create [%s] error[%d]", name, ret);
        goto fail;
    }

    bret = ConnectNamedPipe(*ppipe, pov);
    if (!bret) {
        GETERRNO(ret);
        if (ret != -ERROR_IO_PENDING && ret != -ERROR_PIPE_CONNECTED) {
            ERROR_INFO("can not connect [%s] error[%d]", name, ret);
            goto fail;
        }

        if (ret == -ERROR_IO_PENDING) {
            ret = PIPE_WAIT_CONNECT;
        } else if (ret == -ERROR_PIPE_CONNECTED) {
            bret = SetEvent(pov->hEvet);
            if (!bret) {
                GETERRNO(ret);
                ERROR_INFO("can not set connected pipe[%s] error[%d]", name, ret);
                goto fail;
            }
            ret = PIPE_READY;
        }
    } else {
        ret = PIPE_READY;
    }

    AnsiToTchar(NULL, &ptname, &tnamesize);
    return ret;
fail:
    AnsiToTchar(NULL, &ptname, &tnamesize);
    if (*ppipe != NULL && *ppipe != INVALID_HANDLE_VALUE) {
        bret = CloseHandle(*ppipe);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("close [%s] error[%d]", name, res);
        }
    }
    *ppipe = NULL;
    SETERRNO(ret);
    return ret;
}

int __connect_pipe_async(char* name, int wr, HANDLE *pcli)
{
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    int ret;
    int res;

    if (name == NULL || pcli == NULL || (*pcli != NULL && *pcli != INVALID_HANDLE_VALUE)) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    *pcli = CreateFile(ptname, GENERIC_READ | GENERIC_WRITE , 0,
                       NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (*pcli == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("create pipe [%s] error[%d]", name, ret);
        goto fail;
    }

    return 0;
fail:
    if (*pcli != NULL && *pcli != INVALID_HANDLE_VALUE) {
        bret = CloseHandle(*pcli);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("close [%s] error[%d]", name, res);
        }
    }
    *pcli = NULL;
    SETERRNO(ret);
    return ret;
}
