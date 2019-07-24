#include <win_svc.h>
#include <win_time.h>
#include <win_strop.h>
#include <win_uniansi.h>
#include <win_output_debug.h>
#include <win_proc.h>
#include <win_args.h>
#include <tchar.h>
#include <extargs.h>
#include <win_libev.h>
#include <vector>
#include <log_rcv.h>
#include <log_file.h>


#define  SVCNAME     "svrlog"



typedef struct __args_options {
    int m_verbose;
    int m_global;
    char** m_createfiles;
    char** m_appendfiles;
    char** m_logappends;
    char** m_logcreates;
} args_options_t, *pargs_options_t;


int serve_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int install_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int remove_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int console_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);


#include "args_options.cpp"


static DWORD st_EXITED_MODE = 0;

void exit_event_notify(HANDLE hd,libev_enum_event_t evt,void* pevmain, void* args)
{
    REFERENCE_ARG(hd);
    REFERENCE_ARG(args);
    REFERENCE_ARG(evt);
    libev_break_winev_loop(pevmain);
}

typedef int (*m_init_already_func_t) (void* args,int succ);

int get_log_level(pargs_options_t pargs)
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
    return loglvl;
}

int svrlog_main_loop(HANDLE exitevt,pargs_options_t pargs,pextargs_state_t parsestate, m_init_already_func_t funccall, void* args)
{
    std::vector<LogMonitor*> mons;
    std::vector<LogCallback*> callbacks;
    void* pevmain=NULL;
    int ret;
    int i;
    DWORD j,k;
    LogMonitor* pcurmon=NULL;
    LogCallback* curcallback=NULL;

    REFERENCE_ARG(parsestate);

    pevmain = libev_init_winev();
    if (pevmain == NULL) {
        GETERRNO(ret);
        goto out;
    }

    pcurmon = new LogMonitor(pevmain, 0);
    mons.push_back(pcurmon);

    if (pargs->m_global) {
        pcurmon = new LogMonitor(pevmain, 1);
        mons.push_back(pcurmon);
    }

    /*now to create the file*/
    for(i=0;pargs->m_appendfiles && pargs->m_appendfiles[i] != NULL;i++) {
        curcallback = new LogFileCallback(pevmain,pargs->m_appendfiles[i],1);
        callbacks.push_back(curcallback);
    }

    for (i=0;pargs->m_createfiles && pargs->m_createfiles[i]!=NULL;i++) {
        curcallback = new LogFileCallback(pevmain,pargs->m_createfiles[i],0);
        callbacks.push_back(curcallback);
    }

    /*to start callback*/
    for (j=0;j<callbacks.size();j++) {
        curcallback = callbacks.at(j);
        ret = curcallback->start();
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    /*now to add callback*/
    for (j=0;j<mons.size();j++) {
        pcurmon = mons.at(j);
        for (k=0;k<callbacks.size();k++) {
            curcallback = callbacks.at(k);
            ret = pcurmon->add_log_callback(curcallback);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
        }
    }

    /*now to start mons */
    for(j=0;j<mons.size();j++) {
        pcurmon = mons.at(j);
        ret = pcurmon->start();
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    ret = libev_insert_handle(pevmain,exitevt,exit_event_notify,NULL,INFINIT_TIME);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    if (funccall != NULL) {
        ret = funccall(args,1);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }        
    }

    libev_winev_loop(pevmain);

    ret = 0;
out:
    /*first to stop monitor*/
    while(mons.size() > 0) {
        pcurmon = mons.at(0);
        mons.erase(mons.begin());
        delete pcurmon;
        pcurmon = NULL;
    }

    while(callbacks.size() > 0) {
        curcallback = callbacks.at(0);
        callbacks.erase(callbacks.begin());
        delete curcallback;
        curcallback = NULL;
    }

    libev_free_winev(&pevmain);
    SETERRNO(ret);
    return ret;
}

int main_loop(HANDLE exitevt, char* pipename, int maxmills)
{
    int ret;
    HANDLE waithds[2];
    DWORD waitnum = 0;
    DWORD dret;
    int timeoutmills = 0;

    maxmills = maxmills;
    if (pipename) {
        pipename = pipename;
    }


bind_pipe_again:
    /*to reset the event*/
    if (st_EXITED_MODE) {
        ret = -ERROR_CONTROL_C_EXIT;
        goto fail;
    }


    while (1) {
        waitnum = 0;
        waithds[waitnum] = exitevt;
        waitnum ++;
        timeoutmills = 15000;
        dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, (DWORD)timeoutmills, TRUE);
        if (dret == WAIT_OBJECT_0) {
            break;
        }
    }
    goto bind_pipe_again;


fail:
    SETERRNO(ret);
    return ret;
}


static HANDLE st_hEvent = NULL;


DWORD WINAPI svc_ctrl_handler( DWORD dwCtrl , DWORD type, LPVOID peventdata, LPVOID puserdata)
{
    int ret;
    DEBUG_INFO("dwCtrl 0x%lx", dwCtrl);
    type = type;
    if (puserdata) {
        puserdata = puserdata;
    }
    if (peventdata) {
        peventdata = peventdata;
    }
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        ret = svc_report_mode(SERVICE_STOP_PENDING, 500);
        if (ret < 0) {
            ERROR_INFO("ctrl handle stop pending error %d\n", ret);
        }
        // Signal the service to stop.
        st_EXITED_MODE = 1;
        SetEvent(st_hEvent);
        return NO_ERROR;



    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    }
    return NO_ERROR ;
}


int svc_main_loop()
{
    int ret;
    int beginrunning = 0;

try_again:
    st_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_hEvent == NULL) {
        GETERRNO(ret);
        ERROR_INFO("%s could not create event %d\n", SVCNAME, ret);
        goto fail;
    }

    if (beginrunning  == 0)   {
        ret = svc_report_mode(SERVICE_RUNNING, 0);
        if (ret < 0) {
            ERROR_INFO("%s report running error %d\n", SVCNAME, ret);
            goto fail;
        }
        beginrunning = 1;
    }


    ret = main_loop(st_hEvent, NULL, 1000);


    DEBUG_INFO("%s return  main loop[%d]", SVCNAME, ret);

    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;
    if (st_EXITED_MODE == 0)  {
        goto try_again;
    }
    DEBUG_INFO("%s exit main loop", SVCNAME);
    return ret;
fail:
    DEBUG_INFO("%s fail main loop [%d]" , SVCNAME, ret);
    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;
    return ret;
}

VOID WINAPI svc_main( DWORD dwArgc, TCHAR **lpszArgv )
{
    int ret;
    DWORD i;
    char** args = NULL;

    args = copy_args((int)dwArgc, lpszArgv);
    if (args != NULL) {
        for (i = 0; i < dwArgc; i++) {
            DEBUG_INFO("[%s] [%ld]=[%s]", SVCNAME, i, args[i]);
        }
        free_args(&args);
    }


    DEBUG_INFO("%s start event log", SVCNAME);
    dwArgc = dwArgc;
    lpszArgv = lpszArgv;
    DEBUG_INFO("%s in main\n ", SVCNAME);
    ret = svc_init_mode(SVCNAME, svc_ctrl_handler, NULL);
    if (ret < 0) {
        ERROR_INFO("%s can not init svc\n", SVCNAME);
        return ;
    }
    svc_main_loop();
    DEBUG_INFO("%s close event log", SVCNAME);
    SleepEx(500, TRUE);
    svc_report_mode(SERVICE_STOPPED, 0);
    svc_close_mode();
    return ;
}

int _wwtmain(int argc, _TCHAR* argv[])
{
    argc = argc;
    argv = argv;
    InitOutputEx(BASE_LOG_DEBUG, NULL);
    DEBUG_INFO("start %s\n", SVCNAME);
    return svc_start(SVCNAME, svc_main);
}


int serve_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(popt);
    ret = -ERROR_NOT_SUPPORTED;
    SETERRNO(ret);
    return ret;
}
int install_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(popt);
    ret = -ERROR_NOT_SUPPORTED;
    SETERRNO(ret);
    return ret;
}
int remove_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(popt);
    ret = -ERROR_NOT_SUPPORTED;
    SETERRNO(ret);
    return ret;
}


BOOL WINAPI HandlerConsoleRoutine(DWORD dwCtrlType)
{
    BOOL bret = TRUE;
    switch (dwCtrlType) {
    case CTRL_C_EVENT:
        DEBUG_INFO("CTRL_C_EVENT\n");
        break;
    case CTRL_BREAK_EVENT:
        DEBUG_INFO("CTRL_BREAK_EVENT\n");
        break;
    case CTRL_CLOSE_EVENT:
        DEBUG_INFO("CTRL_CLOSE_EVENT\n");
        break;
    case CTRL_LOGOFF_EVENT:
        DEBUG_INFO("CTRL_LOGOFF_EVENT\n");
        break;
    case CTRL_SHUTDOWN_EVENT:
        DEBUG_INFO("CTRL_SHUTDOWN_EVENT\n");
        break;
    default:
        DEBUG_INFO("ctrltype %d\n", dwCtrlType);
        bret = FALSE;
        break;
    }

    if (bret && st_hEvent) {
        DEBUG_INFO("setevent 0x%x\n", st_hEvent);
        SetEvent(st_hEvent);
    }

    return bret;
}


int console_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int loglvl = get_log_level(pargs);
    output_debug_cfg_t cfg;
    BOOL bret;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    memset(&cfg,0,sizeof(cfg));
    cfg.m_disableflag = WINLIB_DBWIN_DISABLED;
    cfg.m_ppoutcreatefile = pargs->m_logcreates;
    cfg.m_ppoutappendfile = pargs->m_logappends;
    InitOutputEx(loglvl, &cfg);
    st_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_hEvent == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create exit event %d\n", ret);
        goto out;
    }
    bret = SetConsoleCtrlHandler(HandlerConsoleRoutine, TRUE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
        goto out;
    }

    DEBUG_INFO("global [%s]", pargs->m_global ? "True" : "False");

    svrlog_main_loop(st_hEvent,pargs,parsestate,NULL,NULL);
    ret = 0;
out:
    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;
    SETERRNO(ret);
    return ret;    
}


int _tmain(int argc, TCHAR* argv[])
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