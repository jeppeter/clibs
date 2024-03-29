#include <extargs.h>
#include <win_svc.h>
#include <win_time.h>
#include <win_strop.h>
#include <win_uniansi.h>
#include <win_proc.h>
#include <win_evt.h>
#include <win_user.h>
#include <win_prn.h>
#include <win_map.h>
#include <win_args.h>


#include <tchar.h>
#include <proto_api.h>
#include <proto_win.h>

#include <stdio.h>
#include <stdlib.h>

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

    ret = is_wts_enabled();
    DEBUG_INFO("wts [%s]",ret > 0 ? "enabled" : "disabled");

    DEBUG_INFO("count %d [%s]", cnt, cmdline);

    ret = wts_run_cmd_event_output_single(exitevt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, cmdline);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run wts outputv error[%d]", ret);
        goto fail;
    }

    DEBUG_INFO("cmd line [%s]", cmdline);

    DEBUG_BUFFER_FMT(pout,outsize,"runout [%d]", exitcode);
    DEBUG_BUFFER_FMT(perr,errsize,"errout");


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

int run_wts_detach(HANDLE exitevt,ppipe_hdr_t phdr, int hdrlen)
{
    char* pcurptr = NULL;
    int ret;
    char* cmdline = NULL;

    REFERENCE_ARG(exitevt);
    REFERENCE_ARG(hdrlen);

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    cmdline = pcurptr;


    ret = wts_start_cmd_single_detach(0,cmdline);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run wts [%s][%d]", cmdline, ret);
        goto fail;
    }

    DEBUG_INFO("run [%s] ret [%d]", cmdline,ret);
    return 0;
fail:
    SETERRNO(ret);
    return ret;    
}


int get_process_num(HANDLE exitevt,ppipe_hdr_t phdr, int hdrlen)
{
    char* pcurptr = NULL;
    int ret;
    char** ppnames=NULL;
    int numproc =0;
    int * pfinded=NULL;
    int leftlen=0;
    int curlen = 0;
    int i;

    REFERENCE_ARG(exitevt);
    REFERENCE_ARG(hdrlen);

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    leftlen = (hdrlen - (int)sizeof(pipe_hdr_t));

    while(leftlen > 1) {
        curlen = (int)strlen(pcurptr);
        numproc ++;
        pcurptr += (curlen + 1);
        leftlen -= (curlen + 1);
    }

    if (numproc == 0) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("no proc name specified");
        goto fail;
    }

    ppnames = (char**) malloc(sizeof(ppnames[0]) *numproc);
    if (ppnames == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc [%d] error[%d]", sizeof(ppnames[0]) * numproc, ret);
        goto fail;
    }
    memset(ppnames,0, sizeof(ppnames[0]) * numproc);

    pfinded = (int*) malloc(sizeof(pfinded[0]) * numproc);
    if (pfinded == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc [%d] error[%d]", sizeof(pfinded[0]) * numproc, ret);
        goto fail;
    }
    memset(pfinded, 0, sizeof(pfinded[0]) * numproc);

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    leftlen = hdrlen - (int)sizeof(pipe_hdr_t);

    i = 0;
    while(leftlen > 1) {
        curlen = (int)strlen(pcurptr);
        ppnames[i] = pcurptr;
        pcurptr += (curlen + 1);
        leftlen -= (curlen + 1);
        i ++;
    }

    ret = process_num(ppnames,numproc, pfinded);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    for (i=0;i<numproc;i++) {
        DEBUG_INFO("[%d].[%s]=[%d]", i,ppnames[i], pfinded[i]);
    }

    if (ppnames) {
        free(ppnames);
    }
    ppnames = NULL;
    if (pfinded) {
        free(pfinded);
    }
    pfinded = NULL;
    numproc = 0;
    return 0;
fail:
    if (ppnames) {
        free(ppnames);
    }
    ppnames = NULL;
    if (pfinded) {
        free(pfinded);
    }
    pfinded = NULL;
    numproc = 0;
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


int addprn_cmd(HANDLE exitevt,ppipe_hdr_t phdr, int hdrlen)
{
    char* pcurptr = NULL;
    int i;
    int cnt = 0;
    int passlen = 0;
    int curlen = 0;
    int totallen = (int)(hdrlen - sizeof(pipe_hdr_t));
    char* remoteip=NULL,*name=NULL,*user=NULL,*password=NULL;
    int ret;

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    cnt = 0;
    for (passlen = 0, i = 0; passlen < (totallen - 1); i++) {
        curlen = (int)(strlen(pcurptr) + 1);
        switch(i) {
        case 0:
            remoteip = pcurptr;
            break;
        case 1:
            name = pcurptr;
            break;
        case 2:
            user = pcurptr;
            break;
        case 3:
            password=pcurptr;
            break;
        }
        passlen += curlen;
        cnt ++;
        pcurptr += curlen;
    }

    if (remoteip == NULL || name == NULL || user == NULL || password == NULL) {
        ret = -ERROR_INVALID_PARAMETER ;
        ERROR_INFO("no remoteip | name | user | password specified");
        goto fail;
    }

    ret = add_share_printer(exitevt,name,remoteip,user,password);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    DEBUG_INFO("addprn [%s][%s][%s][%s] succ",remoteip,name,user,password);

    return 0;
fail:
    SETERRNO(ret);
    return ret;    
}


int delprn_cmd(HANDLE exitevt,ppipe_hdr_t phdr, int hdrlen)
{
    char* pcurptr = NULL;
    int i;
    int cnt = 0;
    int passlen = 0;
    int curlen = 0;
    int totallen = (int)(hdrlen - sizeof(pipe_hdr_t));
    char* remoteip=NULL,*name=NULL;
    int ret;

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    cnt = 0;
    for (passlen = 0, i = 0; passlen < (totallen - 1); i++) {
        curlen = (int)(strlen(pcurptr) + 1);
        switch(i) {
        case 0:
            remoteip = pcurptr;
            break;
        case 1:
            name = pcurptr;
            break;
        }
        passlen += curlen;
        cnt ++;
        pcurptr += curlen;
    }

    if (remoteip == NULL || name == NULL) {
        ret = -ERROR_INVALID_PARAMETER ;
        ERROR_INFO("no remoteip | name specified");
        goto fail;
    }

    ret = del_share_printer(exitevt,name,remoteip);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    DEBUG_INFO("delprn [%s][%s] succ", remoteip,name);

    return 0;
fail:
    SETERRNO(ret);
    return ret;    
}


int saveprn_cmd(HANDLE exitevt,ppipe_hdr_t phdr, int hdrlen)
{
    char* pcurptr = NULL;
    int i;
    int cnt = 0;
    int passlen = 0;
    int curlen = 0;
    int totallen = (int)(hdrlen - sizeof(pipe_hdr_t));
    char* exportfile=NULL;
    int ret;

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    cnt = 0;
    for (passlen = 0, i = 0; passlen < (totallen - 1); i++) {
        curlen = (int)(strlen(pcurptr) + 1);
        switch(i) {
        case 0:
            exportfile = pcurptr;
            break;
        }
        passlen += curlen;
        cnt ++;
        pcurptr += curlen;
    }

    if (exportfile) {
        ret = -ERROR_INVALID_PARAMETER ;
        ERROR_INFO("no exportfile specified");
        goto fail;
    }

    ret = save_printer_exportfile(exitevt,exportfile);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    DEBUG_INFO("save printer exportfile [%s] succ", exportfile);
    return 0;
fail:
    SETERRNO(ret);
    return ret;    
}

int restoreprn_cmd(HANDLE exitevt,ppipe_hdr_t phdr, int hdrlen)
{
    char* pcurptr = NULL;
    int i;
    int cnt = 0;
    int passlen = 0;
    int curlen = 0;
    int totallen = (int)(hdrlen - sizeof(pipe_hdr_t));
    char* exportfile=NULL;
    int ret;

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    cnt = 0;
    for (passlen = 0, i = 0; passlen < (totallen - 1); i++) {
        curlen = (int)(strlen(pcurptr) + 1);
        switch(i) {
        case 0:
            exportfile = pcurptr;
            break;
        }
        passlen += curlen;
        cnt ++;
        pcurptr += curlen;
    }

    if (exportfile == NULL) {
        ret = -ERROR_INVALID_PARAMETER ;
        ERROR_INFO("no exportfile specified");
        goto fail;
    }

    ret = restore_printer_exportfile(exitevt,exportfile);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    DEBUG_INFO("restore printer exportfile [%s] succ", exportfile);
    return 0;
fail:
    SETERRNO(ret);
    return ret;    
}

int back_run_cmd(HANDLE exitevt, ppipe_hdr_t phdr, int hdrlen)
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

    ret = run_cmd_event_output_single(exitevt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, cmdline);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not run wts outputv error[%d]", ret);
        goto fail;
    }

    DEBUG_INFO("cmd line [%s]", cmdline);

    DEBUG_BUFFER_FMT(pout,outsize,"runout [%d]", exitcode);
    DEBUG_BUFFER_FMT(perr,errsize,"errout");


    run_cmd_event_output_single(exitevt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, NULL);

    snprintf_safe(&cmdline, &cmdsize, NULL);
    return 0;
fail:
    run_cmd_event_output_single(exitevt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, NULL);
    snprintf_safe(&cmdline, &cmdsize, NULL);
    SETERRNO(ret);
    return ret;
}

int map_mem_cmd(HANDLE exitevt, ppipe_hdr_t phdr, int hdrlen,void** ppmap)
{
    char* pcurptr = NULL;
    int i;
    int passlen = 0;
    int curlen = 0;
    int totallen = (int)(hdrlen - sizeof(pipe_hdr_t));
    int ret;
    char* memname = NULL;
    uint64_t memsize=0;
    char* pendptr = NULL;

    REFERENCE_ARG(exitevt);

    pcurptr = (char*) phdr;
    pcurptr += sizeof(pipe_hdr_t);
    for (passlen = 0, i = 0; passlen < (totallen - 1); i++) {
        if (i == 0) {
            memname = pcurptr;
        } else if (i == 1) {
            ret = parse_number(pcurptr,&memsize,&pendptr);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
        }
        curlen = (int)(strlen(pcurptr) + 1);
        passlen += curlen;
        pcurptr += curlen;
    }

    unmap_buffer(ppmap);

    if (memname == NULL || memsize == 0) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret= map_buffer(memname,WINLIB_MAP_FILE_READ|WINLIB_MAP_FILE_WRITE|WINLIB_MAP_FILE_EXEC|WINLIB_MAP_CREATE | WINLIB_MAP_FORALL | WINLIB_MAP_GLOBAL,memsize,ppmap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    DEBUG_INFO("map [%s] [0x%llx] succ", memname,memsize);

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}


int unmap_mem_cmd(HANDLE exitevt, ppipe_hdr_t phdr, int hdrlen,void** ppmap)
{
    REFERENCE_ARG(exitevt);
    REFERENCE_ARG(phdr);
    REFERENCE_ARG(hdrlen);
    unmap_buffer(ppmap);
    return 0;
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
    void* pmap=NULL;


bind_pipe_again:
    /*to reset the event*/
    if (st_EXITED_MODE) {
        ret = -ERROR_CONTROL_C_EXIT;
        goto fail;
    }
    //run_powershell(exitevt);
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
        //run_powershell(exitevt);
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
        } else if (phdr->m_cmd == WTS_DETACH_RUN) {
            ret = run_wts_detach(exitevt,phdr,indatasize);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == PROCESS_NUM_CMD) {
            ret = get_process_num(exitevt,phdr,indatalen);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == ADDPRN_CMD) {
            ret = addprn_cmd(exitevt,phdr,indatalen);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == DELPRN_CMD) {
            ret = delprn_cmd(exitevt,phdr,indatalen);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == SAVEPRN_CMD) {
            ret = saveprn_cmd(exitevt,phdr,indatalen);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == RESTOREPRN_CMD) {
            ret = restoreprn_cmd(exitevt,phdr,indatalen);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == BACK_CMD_RUN) {
            ret = back_run_cmd(exitevt,phdr,indatalen);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == MAP_MEM_CMD) {
            ret = map_mem_cmd(exitevt,phdr,indatalen,&pmap);
            if (ret < 0) {
                if (ret == -ERROR_CONTROL_C_EXIT) {
                    break;
                }
                goto bind_pipe_again;
            }
        } else if (phdr->m_cmd == UNMAP_MEM_CMD) {
            ret = unmap_mem_cmd(exitevt,phdr,indatalen,&pmap);
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
    unmap_buffer(&pmap);
    return 0;

fail:
    bind_pipe(NULL, exitevt, &hpipe, &prdov, &pwrov);
    read_pipe_data(NULL, NULL, NULL, 0, &pindata, &indatasize);
    unmap_buffer(&pmap);
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
