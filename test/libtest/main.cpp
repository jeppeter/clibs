

#pragma warning(push)

#pragma warning(disable:4668)
#pragma warning(disable:4820)
#pragma warning(disable:4577)



#pragma warning(push)

#pragma warning(disable:4623)
#pragma warning(disable:4626)
#pragma warning(disable:5027)
#include <extargs.h>
#pragma warning(pop)

#include <win_fileop.h>
#include <win_output_debug.h>
#include <win_args.h>
#include <win_strop.h>
#include <win_err.h>
#include <win_proc.h>
#include <win_window.h>
#include <win_verify.h>
#include <win_netinter.h>
#include <win_time.h>
#include <win_uniansi.h>
#include <win_envop.h>
#include <win_regex.h>
#include <win_svc.h>
#include <win_regop.h>
#include <win_ver.h>
#include <win_acl.h>
#include <win_priv.h>
#include <win_com.h>
#include <win_dbg.h>
#include <win_base64.h>
#include <win_user.h>
#include <win_namedpipe.h>
#include <win_prn.h>



#include <jvalue.h>
#include <crypt_md5.h>

#include <proto_api.h>
#include <proto_win.h>
#include <Lm.h>

#pragma warning(push)
#pragma warning(disable:4530)
#include <vector>
#pragma warning(pop)

#include <sddl.h>
#include <aclapi.h>

#include "vssetup.h"

#pragma warning(pop)

#if _MSC_VER >= 1910
#pragma warning(push)
/*disable Spectre warnings*/
#pragma warning(disable:5045)
#endif


#define  MIN_SID_SIZE          32

typedef struct __args_options {
    char* m_classname;
    char* m_input;
    char* m_output;
    char* m_errout;
    char* m_pipename;
    int m_verbose;
    int m_timeout;
    int m_bufsize;
    int m_hidewindow;
    int m_privenable;
    int m_res1;
} args_options_t, *pargs_options_t;

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"Netapi32.lib")

#ifdef __cplusplus
extern "C" {
#endif



int mktemp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int readencode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pidargv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int findwindow_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int fullpath_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int winverify_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int netinter_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int quote_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int runv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int runsingle_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int run_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int outc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrlap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int clilap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sendmsg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setcompname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getcompname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int regexec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int iregexec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int runevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int runvevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int runsevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getcp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setcp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int existsvc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svcstate_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svchdl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svcmode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int regbinget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int regbinset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int winver_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setowner_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getsid_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setgroup_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int removesacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int removedacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int addsacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int adddacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int dumpsacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int dumpdacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int utf8toansi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ansitoutf8_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int windbg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int execdbg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int startdetach_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getexe_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getexedir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int encbase64_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int decbase64_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getsess_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getpidsname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sessrunv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setregstr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrcmd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int uselist_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrnetmount_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int chgpass_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrchgpass_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int vsinsted_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int npsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int npcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pipedata_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int mkdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int wtsdetachrun_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int utf8touni_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int unitoutf8_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int startproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int checkproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrcheckproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int dbgcode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int version_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int mkdrv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int mksvc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int listmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int addprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int delprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int saveprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int restoreprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svraddprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrdelprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrsaveprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrrestoreprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int enumdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int md5sum_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int checkpriv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int iswts_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int utf8json_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int termproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int listproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int okpassword_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrbackrun_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int procsecget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int procsecset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getprocwin_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getenvval_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int enumwintext_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);


#define PIPE_NONE                0
#define PIPE_READY               1
#define PIPE_WAIT_READ           2
#define PIPE_WAIT_WRITE          3
#define PIPE_WAIT_CONNECT        4


#ifdef __cplusplus
};
#endif

#include "args_options.cpp"


#define  GET_OPT_TYPE(num, desc, typeof)                                          \
do{                                                                               \
    char* __pendptr;                                                              \
    uint64_t __num;                                                               \
    if (parsestate->leftargs &&                                                   \
        parsestate->leftargs[idx] != NULL) {                                      \
        ret = parse_number(parsestate->leftargs[idx],&__num,&__pendptr);          \
        if (ret < 0) {                                                            \
            GETERRNO(ret);                                                        \
            fprintf(stderr,"%s error[%d]\n", desc, ret);                          \
            goto out;                                                             \
        }                                                                         \
        num = (typeof)__num;                                                      \
        idx ++;                                                                   \
    }                                                                             \
} while(0)

#define  GET_OPT_NUM64(num,desc)          GET_OPT_TYPE(num,desc, uint64_t)
#define  GET_OPT_INT(num, desc)           GET_OPT_TYPE(num,desc,int)

int init_log_level(pargs_options_t pargs)
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
    //fprintf(stdout, "verbose [%d]\n", pargs->m_verbose);
    return INIT_LOG(loglvl);
}


int readencode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* templstr = NULL;
    int templsize = 0;
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            ret = read_file_encoded(parsestate->leftargs[i], &templstr, &templsize);
            if (ret < 0) {
                fprintf(stderr, "can not read [%s] error[%d]\n", parsestate->leftargs[i], ret);
                goto out;
            }
            fprintf(stdout, "%s\n----------------------\n%s\n+++++++++++++++++++++++++\n", parsestate->leftargs[i], templstr);
        }
    }
out:
    read_file_encoded(NULL, &templstr, &templsize);
    return ret;
}


static HANDLE st_ExitEvt = NULL;

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

    if (bret && st_ExitEvt) {
        DEBUG_INFO("setevent 0x%x\n", st_ExitEvt);
        SetEvent(st_ExitEvt);
    }

    return bret;
}


#include "filetest.cpp"
#include "proctest.cpp"
#include "windowtest.cpp"
#include "nettest.cpp"
#include "strtest.cpp"
#include "svctest.cpp"
#include "regtest.cpp"
#include "acltest.cpp"
#include "envtest.cpp"
#include "modtest.cpp"
#include "prntest.cpp"
#include "crypttest.cpp"
#include "privtest.cpp"

int version_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    REFERENCE_ARG(argc);
    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(popt);
    printf("%s version 1.0.1 compiled at [%s %s] cl version[%d]\n", argv[0], __DATE__, __TIME__, _MSC_VER);
    return 0;
}


int iswts_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);

    init_log_level(pargs);

    fprintf(stdout, "wts [%s]\n", is_wts_enabled() > 0 ? "enabled" : "disabled");

    return 0;

}

int utf8json_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    jvalue* mainpj = NULL;
    jvalue* filepj = NULL;
    jentry** entries = NULL;
    jentry* curentry = NULL;
    const char* key = NULL;
    jvalue* value = NULL;
    jvalue* insertval = NULL;
    jvalue* replval = NULL;
    unsigned int entrysize = 0;
    char* filebuf = NULL;
    int filesize = 0;
    int filelen = 0;
    char* fname = NULL;
    unsigned int rdlen = 0;
    char* poutbuf = NULL;
    unsigned int outbufsize = 0;
    int i;
    unsigned int j;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);

    mainpj = jobject_create();
    if (mainpj == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create object error");
        goto out;
    }

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        fname = parsestate->leftargs[i];
        ret = read_file_whole(fname, &filebuf, &filesize);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }

        filelen = ret;
        rdlen = 0;
        filepj = jvalue_read(filebuf, &rdlen);
        if (filepj == NULL) {
            GETERRNO(ret);
            ERROR_INFO("parse [%s] error[%d]", fname, ret);
            goto out;
        }
        if ((int)rdlen > filelen) {
            ret = -ERROR_INVALID_PARAMETER;
            ERROR_INFO("[%s] overread", fname);
            goto out;
        }

        entries = jobject_entries(filepj, &entrysize);
        if (entries == NULL) {
            DEBUG_INFO("entries 0");
            goto next;
        }

        for (j = 0; j < entrysize; j++) {
            curentry = entries[j];
            key = curentry->key;
            value = curentry->value;

            insertval = jvalue_clone(value);
            if (insertval == NULL) {
                GETERRNO(ret);
                ERROR_INFO("clone[%s] value error[%d]", key, ret);
                goto out;
            }

            replval = jobject_put(mainpj, key, insertval, &ret);
            if (ret != 0) {
                GETERRNO(ret);
                ERROR_INFO("put value [%s] error[%d]", key, ret);
                goto out;
            }
            if (replval != NULL) {
                DEBUG_INFO("replace [%s]" , key);
                jvalue_destroy(replval);
                replval = NULL;
            }
            insertval = NULL;
        }

next:
        jentries_destroy(&entries);
        if (filepj) {
            jvalue_destroy(filepj);
        }
        filepj = NULL;
        read_file_whole(NULL, &filebuf, &filesize);
        filelen  = 0;
    }

    /*now to jvalue_write_raw*/
    poutbuf = jvalue_write_raw(mainpj, &outbufsize);
    if (poutbuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not write mainpj [%d]", ret);
        goto out;
    }

    __debug_buf(stdout, poutbuf, (int)outbufsize);

    ret = 0;
out:
    if (poutbuf) {
        free(poutbuf);
    }
    poutbuf = NULL;
    outbufsize = 0;
    if (insertval) {
        jvalue_destroy(insertval);
    }
    insertval = NULL;

    jentries_destroy(&entries);
    read_file_whole(NULL, &filebuf, &filesize);
    filelen = 0;
    if (filepj) {
        jvalue_destroy(filepj);
    }
    filepj = NULL;
    if (mainpj) {
        jvalue_destroy(mainpj);
    }
    mainpj = NULL;
    SETERRNO(ret);
    return ret;
}

int termproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int pid = -1;
    int idx;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx]; idx++) {
        pid = atoi(parsestate->leftargs[idx]);
        ret = kill_process(pid);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not kill [%d] error[%d]", pid, ret);
            goto out;
        }
        fprintf(stdout, "[%d]kill [%d] succ\n", idx, pid);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int listproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    const char* procname = NULL;
    int idx;
    int j;
    pargs_options_t pargs = (pargs_options_t) popt;
    int* pids = NULL;
    int retlen = 0;
    int retsize = 0;
    init_log_level(pargs);


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx]; idx++) {
        procname = parsestate->leftargs[idx];
        ret = list_proc(procname, &pids, &retsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not get [%s] error[%d]", procname, ret);
            goto out;
        }
        retlen = ret;
        fprintf(stdout, "get [%s] [%d]", procname, retlen);
        for (j = 0; j < retlen; j++) {
            if ((j % 5) == 0) {
                fprintf(stdout, "\n%05d:", j);
            }
            fprintf(stdout, " %08d", pids[j]);
        }
        fprintf(stdout, "\n");
    }

    ret = 0;
out:
    list_proc(NULL, &pids, &retsize);
    SETERRNO(ret);
    return ret;
}

int okpassword_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* user = NULL;
    char* password = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);

    user = parsestate->leftargs[0];
    password = parsestate->leftargs[1];

    ret = user_password_ok(user, password);
    if (ret < 0) {
        fprintf(stderr, "logon [%s:%s] error[%d]\n", user, password, ret);
        goto out;
    }

    fprintf(stdout, "logon [%s][%s] succ\n", user, password);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrbackrun_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(BACK_CMD_RUN, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int procsecget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    int pid;


    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);
    init_log_level(pargs);

    ret = init_nt_envop_funcs();
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }


    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] != NULL ; i ++) {
        pid = atoi(parsestate->leftargs[i]);
        ret = dump_process_security(stdout,pid);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    ret = 0;
out:
    fini_nt_envop_funcs();
    SETERRNO(ret);
    return ret;
}

int procsecset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int pid;
    char* maskstr;
    char* modestr;
    char* inheritstr;
    char* username=NULL;


    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);
    init_log_level(pargs);

    ret = init_nt_envop_funcs();
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    pid = atoi(parsestate->leftargs[0]);
    maskstr = parsestate->leftargs[1];
    modestr = parsestate->leftargs[2];
    inheritstr = parsestate->leftargs[3];
    username = parsestate->leftargs[4];

    ret = proc_dacl_set(NULL,pid,maskstr,modestr,inheritstr,username);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    fprintf(stdout, "set [%s] mask [%s] mode[%s] inherit [%s] user[%s] succ\n",
    parsestate->leftargs[0],parsestate->leftargs[1],parsestate->leftargs[2],parsestate->leftargs[3],
    parsestate->leftargs[4]);
    ret = 0;
out:
    fini_nt_envop_funcs();
    SETERRNO(ret);
    return ret;
}

int getprocwin_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    HANDLE *phds=NULL;
    int hdsize=0;
    int hdlen=0;
    int i;
    int j;
    int pid;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    for (i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        pid = atoi(parsestate->leftargs[i]);
        if (pid != 0) {
            ret = get_window_from_pid(pid,&phds,&hdsize);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            hdlen = ret;
            fprintf(stdout,"[%d] windows",pid);
            for (j=0;j<hdlen;j++) {
                if ((j%5) == 0){
                    fprintf(stdout,"\n");
                }
                fprintf(stdout," %p",phds[j]);
            }
            fprintf(stdout,"\n");
        }
    }

    ret=  0;
out:
    get_window_from_pid(0,&phds,&hdsize);
    hdlen = 0;
    SETERRNO(ret);
    return ret;
}

int getenvval_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* varname=NULL;
    char* valstr=NULL;
    size_t valsize=0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    for (i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        varname = parsestate->leftargs[i];
        ret = _dupenv_s(&valstr,&valsize,varname);
        if (ret == 0) {
            fprintf(stdout,"[%s]=[%s]\n",varname,valstr);
        } else {
            fprintf(stdout,"[%s] not set\n",varname);
        }

        if (valstr) {
            free(valstr);
        }
        valstr = NULL;
        valsize = 0;
    }

    ret = 0;
    if (valstr) {
        free(valstr);
    }
    valstr = NULL;
    valsize = 0;
    SETERRNO(ret);
    return ret;
}

BOOL CALLBACK enum_windows_desktop(HWND hwnd,LPARAM lparam)
{
    char wintext[50];
    DWORD pid;
    DWORD dret;
    int ret;

    REFERENCE_ARG(lparam);

    dret = GetWindowThreadProcessId(hwnd,&pid);
    if (dret != 0) {
        DEBUG_INFO("[%p]=pid[%d]", hwnd,pid);
    }
    
    ret = GetWindowTextA(hwnd,wintext,50);
    if (ret != 0) {
        DEBUG_INFO("[%p]=[%s]",hwnd,wintext);
    }

    return TRUE;
}

BOOL CALLBACK enum_win_text(HWND hwnd,LPARAM lparam)
{
    int ret;
    char wintext[50];
    REFERENCE_ARG(lparam);
    ret = GetWindowTextA(hwnd,wintext,50);
    if (ret != 0) {
        DEBUG_INFO("[%p]=[%s]", hwnd,wintext);
    }
    return TRUE;
}

int enumwintext_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    HDESK hdesk=NULL;
    TCHAR* ptdesk=NULL;
    int tdesksize=0;
    char* deskname=NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    BOOL bret;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    deskname = parsestate->leftargs[0];
    ret = AnsiToTchar(deskname,&ptdesk,&tdesksize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    hdesk = OpenDesktop(ptdesk,0,FALSE,DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
    if (hdesk == NULL) {
        GETERRNO(ret);
        ERROR_INFO("could not open [%s] error[%d]", deskname, ret);
        goto out;
    }

    bret = EnumDesktopWindows(hdesk,enum_win_text,NULL);
    if (!bret){
        GETERRNO(ret);
        ERROR_INFO("could not enum win [%d]", ret);
        goto out;
    }

    fprintf(stdout,"enum [%s] succ\n",deskname);
    ret = 0;
out:
    if(hdesk != NULL) {
        CloseDesktop(hdesk);
    }
    hdesk = NULL;
    AnsiToTchar(NULL,&ptdesk,&tdesksize);
    SETERRNO(ret);
    return ret;
}

#include "dbgcode.cpp"

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

#if _MSC_VER >= 1910
#pragma warning(pop)
#endif