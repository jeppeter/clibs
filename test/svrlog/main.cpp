#include <win_svc.h>
#include <win_time.h>
#include <win_strop.h>
#include <win_uniansi.h>
#include <win_output_debug.h>
#include <win_proc.h>
#include <tchar.h>


#define  SVCNAME     "svrlog"


static DWORD st_EXITED_MODE = 0;


int main_loop(HANDLE exitevt, char* pipename, int maxmills)
{
    int ret;
    HANDLE waithds[2];
    DWORD waitnum = 0;
    DWORD dret;
    int timeoutmills=0;

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


DWORD WINAPI svc_ctrl_handler( DWORD dwCtrl ,DWORD type,LPVOID peventdata,LPVOID puserdata)
{
    int ret;
    DEBUG_INFO("dwCtrl 0x%lx", dwCtrl);
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
            ERROR_INFO("%s report running error %d\n", SVCNAME,ret);
            goto fail;
        }
        beginrunning = 1;        
    }


    ret = main_loop(st_hEvent, NULL, 1000);

    
    DEBUG_INFO("%s return  main loop[%d]",SVCNAME, ret);

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
    DEBUG_INFO("%s fail main loop [%d]" ,SVCNAME,ret);
    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;
    return ret;
}

VOID WINAPI svc_main( DWORD dwArgc, LPSTR *lpszArgv )
{
    int ret;
    DWORD i;

    for (i=0;i<dwArgc;i++) {
        DEBUG_INFO("[%ld]=[%s]", i,lpszArgv[i]);
    }

    DEBUG_INFO("%s start event log",SVCNAME);
    dwArgc = dwArgc;
    lpszArgv = lpszArgv;
    DEBUG_INFO("%s in main\n ",SVCNAME);
    ret = svc_init_mode(SVCNAME, svc_ctrl_handler, NULL);
    if (ret < 0) {
        ERROR_INFO("%s can not init svc\n",SVCNAME);
        return ;
    }
    svc_main_loop();
    DEBUG_INFO("%s close event log",SVCNAME);
    SleepEx(500,TRUE);
    svc_report_mode(SERVICE_STOPPED, 0);
    svc_close_mode();
    return ;
}

int _tmain(int argc, _TCHAR* argv[])
{
	argc = argc;
	argv = argv;
    InitOutputEx(BASE_LOG_DEBUG,NULL);
    DEBUG_INFO("start %s\n",SVCNAME);
    return svc_start(SVCNAME, svc_main);
}
