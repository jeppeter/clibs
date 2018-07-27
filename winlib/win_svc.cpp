#include <win_svc.h>
#include <win_err.h>
#include <win_uniansi.h>
#include <win_types.h>
#include <win_time.h>

#pragma comment(lib,"Advapi32.lib")

void __close_scm(SC_HANDLE* pschd)
{
    BOOL bret;
    int ret;
    if (pschd != NULL && *pschd != NULL) {
        bret = CloseServiceHandle(*pschd);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("close %p error[%d]", *pschd, ret);
        }
        *pschd = NULL;
    }
}

void __close_svc(SC_HANDLE* pshsv)
{
    __close_scm(pshsv);
}

SC_HANDLE __open_scm(const char* name, DWORD accmode)
{
    SC_HANDLE schd = NULL;
    int ret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;

    if (name != NULL) {
        ret = AnsiToTchar(name, &ptname, &tnamesize);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    schd = OpenSCManager(ptname, NULL, accmode);
    if (schd == NULL) {
        GETERRNO(ret);
        ERROR_INFO("open %s scm err[%d]", name != NULL ? name : "local", ret);
        goto fail;
    }

    AnsiToTchar(NULL, &ptname, &tnamesize);

    return schd;
fail:
    __close_scm(&schd);
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return NULL;
}

SC_HANDLE __open_svc(SC_HANDLE schd, const char* name, DWORD accmode)
{
    SC_HANDLE shsv = NULL;
    int ret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    if (schd == NULL || name == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    shsv = OpenService(schd, ptname, accmode);
    if (shsv == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open [%s] error[%d]", name, ret);
        goto fail;
    }

    AnsiToTchar(NULL, &ptname, &tnamesize);
    return shsv;
fail:
    __close_svc(&shsv);
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return NULL;
}

int is_service_exist(const char* name)
{
    SC_HANDLE schd = NULL;
    SC_HANDLE shsv = NULL;
    int exist = 0;
    int ret;

    schd = __open_scm(NULL, GENERIC_READ);
    if (schd == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    shsv = __open_svc(schd, name, GENERIC_READ);
    if (shsv == NULL) {
        GETERRNO(ret);
        if (ret != -ERROR_SERVICE_DOES_NOT_EXIST) {
            goto fail;
        }
        exist = 0;
    } else {
        exist = 1;
    }

    __close_svc(&shsv);
    __close_scm(&schd);

    return exist;
fail:
    __close_svc(&shsv);
    __close_scm(&schd);
    SETERRNO(ret);
    return ret;
}

int __open_handle(const char* name, SC_HANDLE *pschd , SC_HANDLE *pshsv, DWORD scmmode, DWORD svcmode)
{
    int ret;
    if (name == NULL) {
        __close_svc(pshsv);
        __close_scm(pschd);
        return 0;
    }

    if (pschd == NULL || pshsv == NULL ||
            *pschd != NULL || *pshsv != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    *pschd = __open_scm(NULL, scmmode);
    if (*pschd == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    *pshsv = __open_svc(*pschd, name, svcmode);
    if (*pshsv == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    return 0;
fail:
    __close_svc(pshsv);
    __close_scm(pschd);
    SETERRNO(ret);
    return ret;
}

int __inner_get_state(SC_HANDLE shsv, SERVICE_STATUS_PROCESS* pssp)
{
    BOOL bret;
    DWORD needed = 0;
    int ret;

    bret = QueryServiceStatusEx(shsv, SC_STATUS_PROCESS_INFO, (LPBYTE)pssp, sizeof(*pssp), &needed);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("query error[%d]", ret);
        SETERRNO(ret);
        return ret;
    }
    return 0;
}

int __get_service_current_state(const char* name)
{
    SC_HANDLE schd = NULL;
    SC_HANDLE shsv = NULL;
    int state;
    int ret;
    SERVICE_STATUS_PROCESS ssp;

    ret = __open_handle(name, &schd, &shsv, GENERIC_READ, GENERIC_READ);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    memset(&ssp, 0 , sizeof(ssp));
    ret = __inner_get_state(shsv, &ssp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    state = ssp.dwCurrentState;

    __open_handle(NULL, &schd, &shsv, GENERIC_READ, GENERIC_READ);
    return state;
fail:
    __open_handle(NULL, &schd, &shsv, GENERIC_READ, GENERIC_READ);
    SETERRNO(ret);
    return ret;
}

int is_service_running(const char* name)
{
    int state = 0;
    int ret;

    state = __get_service_current_state(name);
    if (state < 0) {
        GETERRNO(ret);
        SETERRNO(ret);
        return ret;
    }

    if (state == SERVICE_RUNNING) {
        return 1;
    }
    return 0;
}

int is_service_stopped(const char* name)
{
    int state = 0;
    int ret;

    state = __get_service_current_state(name);
    if (state < 0) {
        GETERRNO(ret);
        SETERRNO(ret);
        return ret;
    }

    if (state == SERVICE_STOPPED) {
        return 1;
    }
    return 0;
}

int service_running_mode(const char* name)
{
    int state ;
    int ret = SVC_STATE_UNKNOWN;

    state = __get_service_current_state(name);
    if (state < 0) {
        GETERRNO(ret);
        SETERRNO(ret);
        return ret;
    }

    switch (state) {
    case SERVICE_STOPPED:
        ret = SVC_STATE_STOPPED;
        break;
    case SERVICE_START_PENDING:
        ret = SVC_STATE_START_PENDING;
        break;
    case SERVICE_STOP_PENDING:
        ret = SVC_STATE_STOP_PENDING;
        break;
    case SERVICE_RUNNING:
        ret = SVC_STATE_RUNNING;
        break;
    case SERVICE_PAUSED:
        ret = SVC_STATE_PAUSED;
        break;
    case SERVICE_PAUSE_PENDING:
        ret = SVC_STATE_PAUSE_PENDING;
        break;
    case SERVICE_CONTINUE_PENDING:
        ret = SVC_STATE_CONTINUE_PENDING;
        break;
    default:
        ret = SVC_STATE_UNKNOWN;
        break;
    }
    return ret;
}

int __inner_get_config(SC_HANDLE shsv , QUERY_SERVICE_CONFIGW** ppconfigw, int *psize)
{
    int ret;
    BOOL bret;
    DWORD needed = 0;
    QUERY_SERVICE_CONFIGW* pretconfig = NULL;
    int retsize = 0;
    if (shsv == NULL) {
        if (ppconfigw && *ppconfigw != NULL) {
            free(*ppconfigw);
            *ppconfigw = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppconfigw == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretconfig = *ppconfigw;
    retsize = *psize;

try_again:
    bret = QueryServiceConfigW(shsv, pretconfig, retsize, &needed);
    if (!bret) {
        GETERRNO(ret);
        if (ret != -ERROR_INSUFFICIENT_BUFFER) {
            ERROR_INFO("query config error[%d]", ret);
            goto fail;
        }

        if (pretconfig != *ppconfigw && pretconfig != NULL)  {
            free(pretconfig);
        }
        pretconfig = NULL;
        if (retsize < (int)needed) {
            retsize = needed ;
        } else {
            retsize <<= 1;
        }
        pretconfig = (QUERY_SERVICE_CONFIGW*) malloc(retsize);
        if (pretconfig == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", retsize, ret);
            goto fail;
        }
        goto try_again;
    }

    if (*ppconfigw != NULL && pretconfig != *ppconfigw) {
        free(*ppconfigw);
    }

    *ppconfigw = pretconfig;
    *psize = retsize;
    return 0;
fail:
    if (pretconfig != NULL && pretconfig != *ppconfigw) {
        free(pretconfig);
    }
    pretconfig = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

int __inner_set_configw(SC_HANDLE shsv , QUERY_SERVICE_CONFIGW* pconfigw, int size)
{
    BOOL bret;
    int ret;

    size = size;
    bret = ChangeServiceConfigW(shsv, pconfigw->dwServiceType ,
                                pconfigw->dwStartType, pconfigw->dwErrorControl ,
                                pconfigw->lpBinaryPathName, pconfigw->lpLoadOrderGroup,
                                &(pconfigw->dwTagId), pconfigw->lpDependencies,
                                pconfigw->lpServiceStartName, NULL, pconfigw->lpDisplayName);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not change config error[%d]", ret);
        goto fail;
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __get_service_start_mode(const char* name)
{
    SC_HANDLE schd = NULL;
    SC_HANDLE shsv = NULL;
    int ret;
    int state;
    QUERY_SERVICE_CONFIGW* pconfigw = NULL;
    int size = 0;

    ret = __open_handle(name, &schd, &shsv, GENERIC_READ, GENERIC_READ);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __inner_get_config(shsv, &pconfigw, &size);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    state = pconfigw->dwStartType;

    __inner_get_config(NULL, &pconfigw, &size);
    __open_handle(NULL, &schd, &shsv, GENERIC_READ, GENERIC_READ);
    return state;
fail:
    __inner_get_config(NULL, &pconfigw, &size);
    __open_handle(NULL, &schd, &shsv, GENERIC_READ, GENERIC_READ);
    SETERRNO(ret);
    return ret;

}

int service_start_mode(const char* name)
{
    int state = 0;
    int ret;

    state = __get_service_start_mode(name);
    if (state < 0) {
        GETERRNO(ret);
        SETERRNO(ret);
        return ret;
    }
    switch (state) {
    case SERVICE_BOOT_START:
        ret = SVC_START_ON_BOOT;
        break;
    case SERVICE_SYSTEM_START:
        ret = SVC_START_ON_SYSTEM;
        break;
    case SERVICE_AUTO_START:
        ret = SVC_START_ON_AUTO;
        break;
    case SERVICE_DEMAND_START:
        ret = SVC_START_ON_DEMAND;
        break;
    case SERVICE_DISABLED:
        ret = SVC_START_ON_DISABLED;
        break;
    default:
        ret = SVC_START_ON_UNKNOWN;
        break;
    }

    return ret;
}

int config_service_start(const char* name, int startmode)
{
    int mode;
    int ret;
    SC_HANDLE shsv = NULL;
    SC_HANDLE schd = NULL;
    QUERY_SERVICE_CONFIGW* pconfigw = NULL;
    int configsize = 0;

    switch (startmode) {
    case SVC_START_ON_BOOT:
        mode = SERVICE_BOOT_START;
        break;
    case SVC_START_ON_SYSTEM:
        mode = SERVICE_SYSTEM_START;
        break;
    case SVC_START_ON_AUTO:
        mode = SERVICE_AUTO_START;
        break;
    case SVC_START_ON_DEMAND:
        mode = SERVICE_DEMAND_START;
        break;
    case SVC_START_ON_DISABLED:
        mode = SERVICE_DISABLED;
        break;
    default:
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    ret = __open_handle(name, &schd, &shsv, SERVICE_ALL_ACCESS, SERVICE_ALL_ACCESS);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __inner_get_config(shsv, &pconfigw, &configsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (pconfigw->dwStartType != (DWORD) mode) {
        pconfigw->dwStartType = mode;
        ret =  __inner_set_configw(shsv, pconfigw, configsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("[%s] set [%d] error[%d]", name, startmode, ret);
            goto fail;
        }
    }

    __inner_get_config(NULL, &pconfigw, &configsize);
    __open_handle(NULL, &schd, &shsv, SERVICE_ALL_ACCESS, SERVICE_ALL_ACCESS);
    return 0;
fail:
    __inner_get_config(NULL, &pconfigw, &configsize);
    __open_handle(NULL, &schd, &shsv, SERVICE_ALL_ACCESS, SERVICE_ALL_ACCESS);
    SETERRNO(ret);
    return ret;
}


static int __stop_depends(SC_HANDLE schd, SC_HANDLE shsv, int mills);

#define CALC_TIMEOUT()                                          \
 do {                                                           \
    cticks = get_current_ticks();                               \
    if (mills > 0) {                                            \
        ret = need_wait_times(sticks, cticks, mills);           \
        if (ret < 0) {                                          \
            ret = -WAIT_TIMEOUT;                                \
            ERROR_INFO("wait [%s] stopped timed out", name);    \
            goto fail;                                          \
        }                                                       \
    }                                                           \
 } while(0)

int __inner_stop_service(SC_HANDLE schd, const char* name, int mills)
{
    SC_HANDLE shsv = NULL;
    int ret;
    SERVICE_STATUS_PROCESS* pssp = NULL;
    SERVICE_STATUS* psvcsts=NULL;
    uint64_t sticks, cticks;
    BOOL bret;

    sticks = get_current_ticks();
    pssp = (SERVICE_STATUS_PROCESS*) malloc(sizeof(*pssp));
    if (pssp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*pssp), ret);
        goto fail;
    }

    shsv = __open_svc(schd, name , SERVICE_ALL_ACCESS);
    if (shsv == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    ret  = __inner_get_state(shsv, pssp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (pssp->dwCurrentState == SERVICE_STOPPED) {
        goto succ;
    } else if (pssp->dwCurrentState == SERVICE_STOP_PENDING) {
        while (1) {
            CALC_TIMEOUT();

            ret = __inner_get_state(shsv, pssp);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }

            if (pssp->dwCurrentState != SERVICE_STOP_PENDING) {
                if (pssp->dwCurrentState == SERVICE_STOPPED) {
                    goto succ;
                }
                ret = -ERROR_INTERNAL_ERROR;
                ERROR_INFO("[%s] state [%d]", name, pssp->dwCurrentState);
                goto fail;
            }

            /*wait for a 100*/
            ret = 100;
            CALC_TIMEOUT();
            if (ret > 100) {
                ret = 100;
            }
            SleepEx(ret, TRUE);
        }
    }


    ret = __stop_depends(schd, shsv, mills);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    psvcsts = (SERVICE_STATUS*) malloc(sizeof(*psvcsts));
    if (psvcsts == NULL) {
    	GETERRNO(ret);
    	ERROR_INFO("alloc %d error[%d]", sizeof(*psvcsts), ret);
    	goto fail;
    }

    bret = ControlService(shsv, SERVICE_CONTROL_STOP, psvcsts);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not stop [%s] error[%d]", name, ret);
        goto fail;
    }

    ret = __inner_get_state(shsv, pssp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (pssp->dwCurrentState == SERVICE_STOPPED) {
        goto succ;
    } else if (pssp->dwCurrentState != SERVICE_STOP_PENDING) {
        ret = - ERROR_INTERNAL_ERROR;
        ERROR_INFO("[%s]not valid state [%d]", name, pssp->dwCurrentState);
        goto fail;
    }


    while (1) {
        ret = __inner_get_state(shsv, pssp);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        if (pssp->dwCurrentState == SERVICE_STOPPED) {
            goto succ;
        } else if (pssp->dwCurrentState != SERVICE_STOP_PENDING) {
            ret = - ERROR_INTERNAL_ERROR;
            ERROR_INFO("[%s]not valid state [%d]", name, pssp->dwCurrentState);
            goto fail;
        }

        /*wait for a 100*/
        ret = 100;
        CALC_TIMEOUT();
        if (ret > 100) {
            ret = 100;
        }
        SleepEx(ret, TRUE);
    }


succ:
	if (psvcsts != NULL) {
		free(psvcsts);
	}
	psvcsts = NULL;
    if (pssp != NULL) {
        free(pssp);
    }
    pssp = NULL;
    __close_svc(&shsv);
    return 0;
fail:
	if (psvcsts != NULL) {
		free(psvcsts);
	}
	psvcsts = NULL;
    if (pssp != NULL) {
        free(pssp);
    }
    pssp = NULL;
    __close_svc(&shsv);
    SETERRNO(ret);
    return ret;
}

int __get_enum_services(SC_HANDLE shsv, DWORD enumflag, ENUM_SERVICE_STATUSA** ppenums, int *penumsize)
{
    int ret;
    DWORD needed = 0;
    ENUM_SERVICE_STATUSA* pretenum = NULL;
    int retsize = 0;
    int numenum = 0;
    DWORD returned;
    BOOL bret;

    if (shsv == NULL) {
        if (ppenums && *ppenums) {
            free(*ppenums);
            *ppenums = NULL;
        }
        if (penumsize) {
            *penumsize = 0;
        }
        return 0;
    }
    if (ppenums == NULL || penumsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretenum = *ppenums;
    retsize = *penumsize;
try_again:
    needed = 0;
    bret = EnumDependentServicesA(shsv, enumflag , pretenum, retsize, &needed, &returned);
    if (!bret) {
        GETERRNO(ret);
        if (ret != -ERROR_INSUFFICIENT_BUFFER) {
            goto fail;
        }

        if (pretenum != NULL && pretenum != *ppenums) {
            free(pretenum);
        }
        pretenum = NULL;
        if (retsize < (int)needed) {
            retsize = needed;
        } else {
            retsize <<= 1;
        }
        pretenum = (ENUM_SERVICE_STATUSA*) malloc(retsize);
        if (pretenum == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", retsize , ret);
            goto fail;
        }
        memset(pretenum , 0 , retsize);
        goto try_again;
    }

    numenum = returned;

    if (*ppenums != NULL && *ppenums != pretenum) {
        free(*ppenums);
    }
    *ppenums = pretenum;
    *penumsize = retsize;
    return numenum;
fail:
    if (pretenum != NULL && pretenum != *ppenums) {
        free(pretenum);
    }
    pretenum = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

int __stop_depends(SC_HANDLE schd, SC_HANDLE shsv, int mills)
{
    ENUM_SERVICE_STATUSA* penum = NULL;
    int enumsize = 0;
    int num;
    int i;
    int ret;

    ret = __get_enum_services(shsv, SERVICE_ACTIVE, &penum, &enumsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    num = ret;

    for (i = 0; i < num; i++) {
        ret = __inner_stop_service(schd, penum[i].lpServiceName, mills);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    __get_enum_services(NULL, SERVICE_ACTIVE, &penum, &enumsize);
    return 0;
fail:
    __get_enum_services(NULL, SERVICE_ACTIVE, &penum, &enumsize);
    SETERRNO(ret);
    return ret;
}

int stop_service(const char* name,  int mills)
{
    SC_HANDLE schd = NULL;
    int ret;

    schd = __open_scm(NULL, SERVICE_ALL_ACCESS);
    if (schd == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __inner_stop_service(schd, name, mills);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    __close_scm(&schd);
    return 0;
fail:
    __close_scm(&schd);
    SETERRNO(ret);
    return ret;
}

int start_service(const char* name, int mills)
{
    SC_HANDLE schd = NULL, shsv = NULL;
    int ret;
    SERVICE_STATUS_PROCESS ssp;
    uint64_t sticks, cticks;
    BOOL bret;

    ret = __open_handle(name, &schd, &shsv, SERVICE_ALL_ACCESS, SERVICE_ALL_ACCESS);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    sticks = get_current_ticks();
    /*now we should get the state*/
    ret =  __inner_get_state(shsv, &ssp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        goto succ;
    } else if (ssp.dwCurrentState == SERVICE_START_PENDING) {
        while (1) {
            ret =  __inner_get_state(shsv, &ssp);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            if (ssp.dwCurrentState == SERVICE_RUNNING) {
                goto succ;
            } else if (ssp.dwCurrentState != SERVICE_START_PENDING) {
                ret = -ERROR_INTERNAL_ERROR;
                ERROR_INFO("[%s] state [%d]", name, ssp.dwCurrentState);
                goto fail;
            }

            /*wait for a 100*/
            ret = 100;
            CALC_TIMEOUT();
            if (ret > 100) {
                ret = 100;
            }
            SleepEx(ret, TRUE);
        }
    }

    bret = StartService(shsv, 0, NULL);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("start [%s] error[%d]", name, ret);
        goto fail;
    }

    ret =  __inner_get_state(shsv, &ssp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        goto succ;
    } else if (ssp.dwCurrentState == SERVICE_START_PENDING) {
        while (1) {
            ret =  __inner_get_state(shsv, &ssp);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            if (ssp.dwCurrentState == SERVICE_RUNNING) {
                goto succ;
            } else if (ssp.dwCurrentState != SERVICE_START_PENDING) {
                ret = -ERROR_INTERNAL_ERROR;
                ERROR_INFO("[%s] state [%d]", name, ssp.dwCurrentState);
                goto fail;
            }

            /*wait for a 100*/
            ret = 100;
            CALC_TIMEOUT();
            if (ret > 100) {
                ret = 100;
            }
            SleepEx(ret, TRUE);
        }
    } else {
        ret = -ERROR_INTERNAL_ERROR;
        ERROR_INFO("start [%s] not valid state [%d]", name, ssp.dwCurrentState);
        goto fail;
    }

succ:
    __open_handle(NULL, &schd, &shsv, SERVICE_ALL_ACCESS, SERVICE_ALL_ACCESS);
    return 0;
fail:
    __open_handle(NULL, &schd, &shsv, SERVICE_ALL_ACCESS, SERVICE_ALL_ACCESS);
    SETERRNO(ret);
    return ret;
}
