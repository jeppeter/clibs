#include <extargs.h>
#include <win_svc.h>
#include <win_time.h>
#include <win_strop.h>
#include <win_uniansi.h>
#include <win_proc.h>
#include <win_evt.h>
#include <win_user.h>

#include <tchar.h>
#include <proto_api.h>
#include <proto_win.h>


#define  TSTSVR_PIPE "\\\\.\\pipe\\tstsvr_pipe"
#define  SVCNAME     "tstsvr"


typedef struct __args_options {
    int m_verbose;
} args_options_t, *pargs_options_t;


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
            DEBUG_INFO("free %p", *ppdata);
            free(*ppdata);
            *ppdata = NULL;
        }
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

    retsize = (size_t) * datasize;
    pretdata = *ppdata;

    if (retsize < sizeof(pipe_hdr_t) || pretdata == NULL) {
        if (retsize  < sizeof(pipe_hdr_t)) {
            retsize = 16;
        }
        pretdata = (char*)malloc(retsize);
        if (pretdata == NULL) {
            GETERRNO(ret);
            ERROR_INFO("malloc %d error [%d]", retsize, ret);
            goto fail;
        }
        DEBUG_INFO("alloc %p", pretdata);
    }
    memset(pretdata, 0, retsize);

    ASSERT_IF(retlen == 0);
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
        DEBUG_INFO("alloc %p", ptmpdata);
        if (retlen > 0) {
            memcpy(ptmpdata, pretdata, (size_t)retlen);
        }
        if (pretdata && pretdata != *ppdata) {
            DEBUG_INFO("free %p", pretdata);
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
    DEBUG_BUFFER_FMT(phdr, sizeof(*phdr), "header");
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
        DEBUG_INFO("retlen %d datalen %d", retlen, phdr->m_datalen);
    } else {
        ret = (int)dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -WAIT_TIMEOUT;
        }
        DEBUG_INFO("retlen %d datalen %d", retlen, phdr->m_datalen);
        ERROR_INFO("wait error [%d] %d", ret, dret);
        goto fail;
    }

    if (retlen < (int)phdr->m_datalen) {
        goto try_read_more;
    }

read_all:
    if (*ppdata && pretdata != *ppdata) {
        DEBUG_INFO("free %p", *ppdata);
        free(*ppdata);
        *ppdata = NULL;
    }
    *ppdata = pretdata;
    *datasize = (int)retsize;

    return retlen;

fail:
    if (ptmpdata) {
        DEBUG_INFO("free %p", ptmpdata);
        free(ptmpdata);
    }
    ptmpdata = NULL;

    if (pretdata && pretdata != *ppdata) {
        DEBUG_INFO("free %p" , pretdata);
        free(pretdata);
    }
    pretdata = NULL;
    SETERRNO(ret);
    return ret;
}

int run_cmd(HANDLE exitevt, ppipe_hdr_t phdr, int hdrlen)
{
    char* pcurptr = NULL;
    int i;
    int cnt = 0;
    int passlen = 0;
    int curlen = 0;
    int totallen = (int)(hdrlen - sizeof(pipe_hdr_t));
    char* pout = NULL, *perr = NULL;
    int outsize = 0, errsize = 0;
    int exitcode = 0;
    int ret;
    char* cmdline = NULL;
    int cmdsize = 0;

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    cnt = 0;
    for (passlen = 0, i = 0; passlen < (totallen - 1); i++) {
        curlen = (int)(strlen(pcurptr) + 1);
        if (i > 0) {
            ret = append_snprintf_safe(&cmdline, &cmdsize, " %s", pcurptr);
        } else {
            ret = snprintf_safe(&cmdline, &cmdsize, "%s", pcurptr);
        }
        passlen += curlen;
        cnt ++;
        pcurptr += curlen;
    }

    DEBUG_INFO("count %d [%s]", cnt, cmdline);

    ret = wts_run_cmd_event_output_single(exitevt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, cmdline);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run wts outputv error[%d]", ret);
        goto fail;
    }

    DEBUG_INFO("cmd line [%s]", cmdline);
    DEBUG_INFO("run exit [%d]" , exitcode);



    wts_run_cmd_event_output_single(exitevt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, NULL);

    snprintf_safe(&cmdline, &cmdsize, NULL);
    return 0;
fail:
    wts_run_cmd_event_output_single(exitevt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, NULL);
    snprintf_safe(&cmdline, &cmdsize, NULL);
    SETERRNO(ret);
    return ret;
}

int change_password(HANDLE exitevt, ppipe_hdr_t phdr, int hdrlen)
{
    char* user,*oldpass,*newpass;
    char* pcurptr;
    int ret;

    REFERENCE_ARG(exitevt);
    REFERENCE_ARG(hdrlen);

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    user = pcurptr;
    pcurptr += strlen(user);
    pcurptr ++;
    oldpass = pcurptr;
    pcurptr += strlen(oldpass);
    pcurptr ++;
    newpass = pcurptr;

    ret = user_change_password(user,oldpass,newpass); 
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

static char* st_POWRSHELL_MOUNT_SH = "powershell -ExecutionPolicy ByPass -Command \"$svrip=\\\"%s\\\";;;$netshare=\\\"%s\\\";;;$user=\\\"%s\\\";;;$passwd=\\\"%s\\\";;;net use | Select-String -Pattern \\\"^OK\\\" | Select-String  -Pattern $svrip | Select-String -Pattern $netshare | Tee-Object -Variable ttobj | Out-Null;;;if ($ttobj.length -gt 0) {;;    Write-Host \\\"run ok 0\\\" ;;;    exit(0);;;};;Write-Host \\\"no \\\\$svrip\\$netshare\\\";;;$ttobj;;;;;net use |  Select-String -Pattern $svrip |Tee-Object -Variable ttobj | Out-Null;;;;;if ($ttobj.length -gt 0) {;;        foreach($c in $ttobj) {;;        $s = $c -replace \\\"\\s+\\\",\\\" \\\";;;        $arr = $s.split(\\\" \\\");;;        Write-Host \\\"[\\\"$arr[1]\\\"]\\\";;;        net use $arr[1] /delete;;;    };;};;$chars=\\\"ABCDEFGHIJKLMNOPQRSTUVWXYZ\\\";;;$i = 3;;;while ($i -lt 26) {;;    $mntlabel = $chars[$i];;;    $c = \\\"$mntlabel\\\";;;    $c += \\\":\\\";;;    Write-Host \\\"c [$c]\\\";;;    Write-Host \\\"net use $c \\\\$svrip\\$netshare /user:$user $passwd\\\";;;    net use $c \\\\$svrip\\$netshare /user:$user $passwd;;;    if ($?) {;;        exit(0);;;    };;    $i++;;;};;;;Write-Host \\\"can not mount \\\\$svrip\\$netshare /user:$user $passwd\\\";;;exit(3);;;;;;;\"";
static char* st_POWRSHELL_GET_MNT = "powershell -ExecutionPolicy ByPass -Command \"$svrip=\\\"%s\\\";;;$netshare=\\\"%s\\\";;;$user=\\\"%s\\\";;;$passwd=\\\"%s\\\";;;;;$chars=\\\"ABCDEFGHIJKLMNOPQRSTUVWXYZ\\\";;;;;net use | Select-String -Pattern \\\"^OK\\\" | Select-String  -Pattern $svrip | Select-String -Pattern $netshare | Tee-Object -Variable ttobj | Out-Null;;;if ($ttobj.length -gt 0) {;;    $s = $ttobj -replace \\\"\\s+\\\", \\\" \\\";;;    $arr = $s.split(\\\" \\\");;;    $cv = $arr[1].ToUpper();;;    $i =0;;;    while ($i -lt 26) {;;        $cg = $chars[$i];;;        $cg += \\\":\\\";;;        if ($cg.equals($cv)) {;;            exit($i+1);;;        };;        $i ++;;;    };;};;;;;;exit(255);\"";


int netshare_cmd(HANDLE exitevt, ppipe_hdr_t phdr, int hdrlen)
{
    char* pcurptr = NULL;
    int i;
    int passlen = 0;
    int curlen = 0;
    int totallen = (int)(hdrlen - sizeof(pipe_hdr_t));
    char* username = NULL, *passwd = NULL, *svrip = NULL, *netshare = NULL;
    int exitcode = 0;
    int ret;
    char* cmdline = NULL;
    int cmdsize = 0;

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    for (passlen = 0, i = 0; passlen < (totallen - 1); i++) {
        curlen = (int)(strlen(pcurptr) + 1);
        switch (i) {
        case 0:
            svrip = pcurptr;
            break;
        case 1:
            netshare = pcurptr;
            break;
        case 2:
            username = pcurptr;
            break;
        case 3:
            passwd = pcurptr;
            break;
        default:
            break;
        }
        passlen += curlen;
        pcurptr += curlen;
    }

    if (username == NULL || passwd == NULL || svrip == NULL || netshare == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("no username or passwd or svrip or netshare specified");
        goto fail;
    }

    ret= snprintf_safe(&cmdline,&cmdsize,st_POWRSHELL_MOUNT_SH,svrip,netshare,username,passwd);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    DEBUG_INFO("mount cmdline [%s]",cmdline);


    ret = wts_run_cmd_event_output_single(exitevt, NULL, 0, NULL,NULL,NULL,NULL, &exitcode, 0, cmdline);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run wts outputv error[%d]", ret);
        goto fail;
    }

    DEBUG_INFO("run mount [%d]", exitcode);
    if (exitcode != 0) {
        ret = exitcode;
        if (ret > 0) {
            ret = -ret;
        }
        goto fail;
    }

    ret= snprintf_safe(&cmdline,&cmdsize,st_POWRSHELL_GET_MNT,svrip,netshare,username,passwd);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    DEBUG_INFO("getmount cmdline [%s]",cmdline);
    ret = wts_run_cmd_event_output_single(exitevt, NULL, 0, NULL,NULL,NULL,NULL, &exitcode, 0, cmdline);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run wts outputv error[%d]", ret);
        goto fail;
    }

    DEBUG_INFO("get mount ret[%d]",exitcode);



    snprintf_safe(&cmdline, &cmdsize, NULL);
    return 0;
fail:
    snprintf_safe(&cmdline, &cmdsize, NULL);
    SETERRNO(ret);
    return ret;

}

int run_powershell(HANDLE exitevt)
{
    char* cmdline=NULL;
    int cmdsize=0;
    int ret;
    int exitcode;

    ret = snprintf_safe(&cmdline,&cmdsize,"powershell -Command \"\" ");
    if (ret < 0 ) {
        GETERRNO(ret);
        goto fail;
    }

    ret = wts_run_cmd_event_output_single(exitevt, NULL,0,NULL,NULL,NULL,NULL,&exitcode,0,cmdline);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    DEBUG_INFO("run [%s] exitcode [%d]", cmdline, exitcode);


    snprintf_safe(&cmdline,&cmdsize,NULL);
    return 0;
fail:
    snprintf_safe(&cmdline,&cmdsize,NULL);
    SETERRNO(ret);
    return ret;
}


static DWORD st_EXITED_MODE = 0;


int main_loop(HANDLE exitevt, char* pipename, int maxmills)
{
    char* pindata = NULL;
    int indatasize = 0, indatalen = 0;
    int ret;
    HANDLE hpipe = NULL;
    OVERLAPPED *prdov = NULL, *pwrov = NULL;
    HANDLE waithds[2];
    DWORD waitnum = 0;
    DWORD dret;
    ppipe_hdr_t phdr = NULL;


bind_pipe_again:
    /*to reset the event*/
    if (st_EXITED_MODE) {
        ret = -ERROR_CONTROL_C_EXIT;
        goto fail;
    }
    run_powershell(exitevt);
    bind_pipe(NULL, exitevt, &hpipe, &prdov, &pwrov);
    ret = bind_pipe(pipename, exitevt, &hpipe, &prdov, &pwrov);
    if (ret < 0) {
        GETERRNO(ret);
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

    DEBUG_INFO("bind [%s] succ", pipename);



    while (1) {
        run_powershell(exitevt);
        ret = read_pipe_data(exitevt, hpipe, prdov, maxmills, &pindata, &indatasize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("will build pipe again");
            if (ret ==  -ERROR_CONTROL_C_EXIT)  {
                break;
            }
            goto bind_pipe_again;
        }

        indatalen = ret;
        DEBUG_BUFFER_FMT(pindata, ret, "indatalen [%d]", indatalen);
        phdr = (ppipe_hdr_t) pindata;
        if (phdr->m_cmd == EXECUTE_COMMAND) {
            ret = run_cmd(exitevt, phdr, indatalen);
            if (ret < 0) {
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == NETSHARE_MOUNT) {
            ret = netshare_cmd(exitevt,phdr,indatalen);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;                
            }
        } else if (phdr->m_cmd == CHG_USER_PASS) {
            ret = change_password(exitevt,phdr,indatalen);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        }

    }


    bind_pipe(NULL, exitevt, &hpipe, &prdov, &pwrov);
    read_pipe_data(NULL, NULL, NULL, 0, &pindata, &indatasize);
    return 0;

fail:
    bind_pipe(NULL, exitevt, &hpipe, &prdov, &pwrov);
    read_pipe_data(NULL, NULL, NULL, 0, &pindata, &indatasize);
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

    case SERVICE_CONTROL_SESSIONCHANGE:
        switch(type) {
            case WTS_SESSION_LOGON:
                DEBUG_INFO("session logon");
                SetEvent(st_hEvent);
                break;
        }
        
        break;


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
        ERROR_INFO("could not create event %d\n", ret);
        goto fail;
    }

    if (beginrunning  == 0)   {
        ret = svc_report_mode(SERVICE_RUNNING, 0);
        if (ret < 0) {
            ERROR_INFO("report running error %d\n", ret);
            goto fail;
        }
        beginrunning = 1;        
    }


    ret = main_loop(st_hEvent, TSTSVR_PIPE, 1000);

    
    DEBUG_LOG_EVENT("return  main loop[%d]", ret);

    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;
    if (st_EXITED_MODE == 0)  {
        goto try_again;
    }
    DEBUG_LOG_EVENT("exit main loop");
    return ret;
fail:
    DEBUG_LOG_EVENT("fail main loop [%d]" ,ret);
    if (st_hEvent) {
        CloseHandle(st_hEvent);
    }
    st_hEvent = NULL;
    return ret;
}

VOID WINAPI svc_main( DWORD dwArgc, TCHAR**lpszArgv )
{
    int ret;
    init_event_log(BASE_EVENT_TRACE,"svrtest");

    REFERENCE_ARG(dwArgc);
    REFERENCE_ARG(lpszArgv);

    DEBUG_LOG_EVENT("start event log");
    DEBUG_INFO("in main\n ");
    ret = svc_init_mode(SVCNAME, svc_ctrl_handler, NULL);
    if (ret < 0) {
        ERROR_INFO("can not init svc\n");
        return ;
    }
    svc_main_loop();
    DEBUG_LOG_EVENT("close event log");
    close_event_log();
    SleepEx(500,TRUE);
    svc_report_mode(SERVICE_STOPPED, 0);
    svc_close_mode();
    return ;
}

int _tmain(int argc, _TCHAR* argv[])
{
    int argsize=0;
    char* args=NULL;
    int ret;
    int i;
    output_debug_cfg_t cfg;
    char* outfile[] = {"c:\\output.log",NULL};
    char* appfile[] = {"c:\\append.log",NULL};
    memset(&cfg,0,sizeof(cfg));
    cfg.m_ppoutcreatefile = outfile;
    cfg.m_ppoutappendfile = appfile;
    argc = argc;
    argv = argv;
    InitOutputEx(BASE_LOG_DEBUG,&cfg);
    DEBUG_INFO("start %s\n",SVCNAME);
    for (i=0;i<argc;i++) {
        ret = TcharToAnsi(argv[i], &args,&argsize);
        if (ret >= 0) {
            DEBUG_INFO("[%d]=[%s]", i, args);
        }
    }
    TcharToAnsi(NULL,&args,&argsize);
    ret = svc_start(SVCNAME, svc_main);
    DEBUG_INFO("return from svc_start %d", ret);
    return ret;
}
