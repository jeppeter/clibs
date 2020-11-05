

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




int startdetach_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char** progv = NULL;
    int createflags = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    progv = parsestate->leftargs;
    ret = start_cmdv_detach(createflags, progv);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not start");
        if (parsestate->leftargs) {
            for (i = 0; parsestate->leftargs[i] != NULL; i++) {
                if (i > 0) {
                    fprintf(stderr, " ");
                }
                fprintf(stderr, "[%s]", parsestate->leftargs[i]);
            }
        }
        fprintf(stderr, " error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "start ");
    if (parsestate->leftargs) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            if (i > 0) {
                fprintf(stdout, " ");
            }
            fprintf(stdout, "[%s]", parsestate->leftargs[i]);
        }
    }
    fprintf(stdout, " pid[%d]\n", ret);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int getexe_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* pwhole = NULL;
    int wholesize = 0;
    init_log_level(pargs);
    argc = argc;
    argv = argv;
    parsestate = parsestate;

    ret = get_executable_wholepath(0, &pwhole, &wholesize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "get whole path error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "whole path [%s]\n", pwhole);

    ret = 0;
out:
    get_executable_wholepath(1, &pwhole, &wholesize);
    SETERRNO(ret);
    return ret;
}

int getexedir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* pwhole = NULL;
    int wholesize = 0;
    init_log_level(pargs);

    argc = argc;
    argv = argv;
    parsestate = parsestate;

    ret = get_executable_dirname(0, &pwhole, &wholesize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "get whole path error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "whole path dirname [%s]\n", pwhole);

    ret = 0;
out:
    get_executable_dirname(1, &pwhole, &wholesize);
    SETERRNO(ret);
    return ret;
}

int encbase64_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    char* input = NULL;
    char* output = NULL;
    char* inbuf = NULL;
    int insize = 0, inlen = 0;
    char* outbuf = NULL;
    int outsize = 0;
    int outlen = 0;
    int ret;
    char* expandline = NULL;
    int expandsize = 0;
    int expandlen = 0;

    init_log_level(pargs);
    argc = argc;
    argv = argv;
    input = parsestate->leftargs[0];
    output = parsestate->leftargs[1];

    ret = read_file_whole(input, &inbuf, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read %s error%d\n", input, ret);
        goto out;
    }
    inlen = ret;

    outsize = 32;
try_again:
    if (outbuf) {
        free(outbuf);
    }
    outbuf = NULL;
    outbuf = (char*)malloc((size_t)outsize);
    if (outbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "alloc %d error%d\n", outsize, ret );
        goto out;
    }

    ret = encode_base64((unsigned char*)inbuf, inlen, outbuf, outsize);
    if (ret < 0) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            outsize <<= 1;
            goto try_again;
        }
        fprintf(stderr, "can not encode base\n");
        __debug_buf(stderr, inbuf, insize);
        fprintf(stderr, "error [%d]\n", ret);
        goto out;
    }

    outlen = ret;
    ret = base64_splite_line(outbuf, outlen, 76, &expandline, &expandsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "expand line error[%d]\n", ret);
        goto out;
    }

    expandlen = ret;

    fprintf(stdout, "inlen [%d]outlen [%d]\n", inlen, expandlen);
    ret = write_file_whole(output, expandline, expandlen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] error[%d]\n", output, ret );
        goto out;
    }

    fprintf(stdout, "encode [%s] => [%s] succ\n", input, output );
    ret = 0;

out:
    base64_splite_line(NULL, 0, 0, &expandline, &expandsize);
    read_file_whole(NULL, &inbuf, &insize);
    if (outbuf) {
        free(outbuf);
    }
    outbuf = NULL;
    SETERRNO(ret);
    return ret;

}
int decbase64_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    char* input = NULL;
    char* output = NULL;
    char* inbuf = NULL;
    int insize = 0, inlen = 0;
    char* outbuf = NULL;
    int outsize = 0;
    int outlen = 0;
    int ret;
    char* compactbuf = NULL;
    int compactlen = 0, compactsize = 0;

    init_log_level(pargs);
    argc = argc;
    argv = argv;
    input = parsestate->leftargs[0];
    output = parsestate->leftargs[1];

    ret = read_file_whole(input, &inbuf, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read %s error%d\n", input, ret);
        goto out;
    }
    inlen = ret;


    ret = base64_compact_line(inbuf, inlen, &compactbuf, &compactsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "compact error[%d]\n", ret);
        goto out;
    }
    compactlen = ret;

    outsize = 32;
try_again:
    if (outbuf) {
        free(outbuf);
    }
    outbuf = NULL;
    outbuf = (char*)malloc((size_t)outsize);
    if (outbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "alloc %d error%d\n", outsize, ret );
        goto out;
    }



    ret = decode_base64(compactbuf, compactlen, (unsigned char*)outbuf, outsize);
    if (ret < 0) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            outsize <<= 1;
            goto try_again;
        }
        fprintf(stderr, "can not decode base\n");
        __debug_buf(stderr, inbuf, insize);
        fprintf(stderr, "error [%d]\n", ret);
        goto out;
    }

    outlen = ret;
    fprintf(stdout, "inlen [%d]outlen [%d]\n", inlen, outlen);
    ret = write_file_whole(output, outbuf, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] error[%d]\n", output, ret );
        goto out;
    }

    fprintf(stdout, "decode [%s] => [%s] succ\n", input, output );
    ret = 0;

out:
    base64_compact_line(NULL, 0, &compactbuf, &compactsize);
    read_file_whole(NULL, &inbuf, &insize);
    if (outbuf) {
        free(outbuf);
    }
    outbuf = NULL;
    SETERRNO(ret);
    return ret;
}


int getsess_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);

    argc = argc;
    argv = argv;
    parsestate = parsestate;

    ret = get_desktop_session();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get desktop session [%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "session [%d]\n", ret);

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int getpidsname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    DWORD *ppids = NULL;
    int size = 0, cnt;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    char* procname;
    int j;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        procname = parsestate->leftargs[i];
        ret = get_pids_by_name(procname, &ppids, &size);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not get [%s] error[%d]\n", procname, ret);
            goto out;
        }
        cnt = ret;
        fprintf(stdout, "find [%s] count[%d]", procname, cnt);
        for (j = 0; j < cnt; j++) {
            if ((j % 5) == 0) {
                fprintf(stdout, "\n%d ", j);
            }
            fprintf(stdout, " %d", (int)ppids[j]);
        }
        fprintf(stdout, "\n");
    }

    ret = 0;
out:
    get_pids_by_name(NULL, &ppids, &size);
    SETERRNO(ret);
    return ret;
}

int sessrunv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int retpid = -1;
    int num;
    DWORD sessid = 0;
    int cnt = 0;
    char** progv = NULL;
    int i;
    int idx = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        cnt ++;
    }

    if (cnt < 2) {
        ret =  -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "need session progv...\n");
        goto out;
    }

    num = 0;
    GET_OPT_INT(num, "session id");
    sessid = (DWORD)num;
    progv = &(parsestate->leftargs[1]);

    ret = start_cmdv_session_detach(sessid, progv);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not start [");
        for (i = 1; i < cnt; i++) {
            if (i > 1) {
                fprintf(stderr, " ");
            }
            fprintf(stderr, "%s", parsestate->leftargs[i]);
        }
        fprintf(stderr, "] on session[%d] error[%d]\n", (int)sessid, ret);
        goto out;
    }
    retpid = ret;

    fprintf(stdout, "run [");
    for (i = 1; i < cnt; i++) {
        if (i > 1) {
            fprintf(stdout, " ");
        }
        fprintf(stdout, "%s", parsestate->leftargs[i]);
    }
    fprintf(stdout, "] on session[%d] [%d]succ\n", (int)sessid, retpid);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int setregstr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* path;
    char* key;
    char* val;
    void* pregop = NULL;
    int idx = 0;
    int cnt = 0;

    argc = argc;
    argv = argv;
    init_log_level(pargs);
    for (idx = 0; parsestate->leftargs && parsestate->leftargs[idx] ; idx++) {
        cnt ++;
    }

    if (cnt < 3) {
        fprintf(stderr, "need path key val\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    path = parsestate->leftargs[0];
    key = parsestate->leftargs[1];
    val = parsestate->leftargs[2];

    pregop = open_hklm(path, ACCESS_KEY_ALL);
    if (pregop == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] for write [%d]\n", path, ret);
        goto out;
    }

    ret = set_hklm_string(pregop, key, val);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s].[%s] value [%s] error[%d]\n", path, key, val, ret);
        goto out;
    }

    fprintf(stdout, "write [%s].[%s] value [%s] succ\n", path, key, val);
    ret = 0;
out:
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;
}

int __send_svr_pipe(uint32_t cmd, pextargs_state_t parsestate, pargs_options_t pargs)
{
    char* pipename = NULL;
    HANDLE hpipe = NULL;
    OVERLAPPED *prdov = NULL, *pwrov = NULL;
    size_t totallen = 0;
    pipe_hdr_t *phdr = NULL;
    int ret;
    BOOL bret;
    int i;
    char* pcurptr = NULL;
    size_t curlen;


    pipename = pargs->m_pipename;
    if (pipename == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "no pipename\n");
        goto out;
    }

    st_ExitEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_ExitEvt == NULL) {
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

    ret = connect_pipe(pipename, st_ExitEvt, &hpipe, &prdov, &pwrov);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not connect pipe [%s] error[%d]\n", pipename, ret);
        goto out;
    }

    /*now format the buffer*/
    totallen = 0;
    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i] != NULL ; i++) {
        totallen += (strlen(parsestate->leftargs[i]) + 1);
    }

    if (totallen > 0) {
        totallen ++;
        totallen += sizeof(*phdr);
    }

    if (totallen == 0) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "can not accept zero command\n");
        goto out;
    }

    phdr = (pipe_hdr_t*)malloc(totallen);
    if (phdr == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(phdr, 0, totallen);
    phdr->m_datalen = (uint32_t)totallen;
    phdr->m_cmd = cmd;

    pcurptr = (char*) phdr;
    pcurptr += sizeof(*phdr);

    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i]; i++) {
        curlen = strlen(parsestate->leftargs[i]);
        memcpy(pcurptr, parsestate->leftargs[i], curlen);
        pcurptr += (curlen + 1);
    }
    DEBUG_BUFFER_FMT(phdr, (int)totallen, "buffer write");

    ret = write_pipe_data(st_ExitEvt, hpipe, pwrov, pargs->m_timeout, (char*)phdr, (int)totallen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] with len [%zd] error[%d]\n", pipename, totallen, ret);
        goto out;
    }

    DEBUG_INFO("Sleep before");
    if (pargs->m_timeout != 0) {
        SleepEx((DWORD)pargs->m_timeout, TRUE);
    } else {
        SleepEx(1000, TRUE);
    }

    DEBUG_INFO("Sleep after");

    ret = 0;
out:
    if (st_ExitEvt) {
        CloseHandle(st_ExitEvt);
    }
    st_ExitEvt = NULL;

    if (phdr) {
        free(phdr);
    }
    phdr = NULL;
    connect_pipe(NULL, NULL, &hpipe, &prdov, &pwrov);
    SETERRNO(ret);
    return ret;
}

int svrcmd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(EXECUTE_COMMAND, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int svrnetmount_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(NETSHARE_MOUNT, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int chgpass_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* user, *oldpass, *newpass;
    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    user = parsestate->leftargs[0];
    oldpass = parsestate->leftargs[1];
    newpass = parsestate->leftargs[2];
    ret = user_change_password(user, oldpass, newpass);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not change [%s] pass [%s] => [%s] error[%d]\n", user, oldpass, newpass, ret);
        goto out;
    }

    fprintf(stdout, "change [%s] pass[%s] => [%s] succ\n", user, oldpass, newpass);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int svrchgpass_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(CHG_USER_PASS, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int vsinsted_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* version = NULL;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] != NULL ; i++) {
        version = parsestate->leftargs[i];
        ret = is_visual_studio_installed(version);
        if (ret < 0) {
            fprintf(stdout, "%s not installed\n", version);
        } else {
            fprintf(stdout, "%s installed\n", version);
        }
    }

    return 0;
}

#define  MAX_WAIT_NUM   3

int npsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* pipename = NULL;
    int ret;
    int argcnt = 0;
    char** filecon = NULL;
    int* filelen = NULL;
    int i;
    char** fnames = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    BOOL bret;
    void* pnp = NULL;
    int curidx;
    uint32_t rcvlen = 0;
    uint32_t needlen = 0;
    uint32_t wholelen = 0;
    char* preadbuf = NULL;
    char* ptmpreadbuf = NULL;
    uint32_t rcvsize = 0;
    std::vector<char*> wbufs;
    std::vector<int> wlens;
    char* pwritebuf = NULL;
    int writelen = 0;
    char* pcurwrite = NULL;
    int curwritelen = 0;
    HANDLE curhd;
    HANDLE waithds[MAX_WAIT_NUM];
    DWORD dret;
    DWORD waitnum = 0;
    int filesize = 0;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);
    pipename = pargs->m_pipename;

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        argcnt ++;
    }


    if (argcnt > 0) {
        fnames = parsestate->leftargs;
        filecon = (char**) malloc(sizeof(*filecon) * argcnt);
        if (filecon == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not alloc [%zu] error[%d]", sizeof(*filecon) * argcnt, ret);
            goto out;
        }
        memset(filecon, 0, sizeof(*filecon) * argcnt);

        filelen = (int*) malloc(sizeof(*filelen) * argcnt);
        if (filelen == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not alloc [%zu] error[%d]", sizeof(*filelen) * argcnt, ret);
            goto out;
        }
        memset(filelen, 0, sizeof(*filelen) * argcnt);

        for (i = 0; i < argcnt; i++) {
            filesize = 0;
            ret = read_file_whole(fnames[i], &(filecon[i]), &filesize);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("[%d].[%s] read error[%d]", i, fnames[i], ret);
                goto out;
            }
            filelen[i] = ret;
        }
    }

    st_ExitEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_ExitEvt == NULL) {
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



try_again:
    close_namedpipe(&pnp);
    if (ptmpreadbuf) {
        free(ptmpreadbuf);
    }
    ptmpreadbuf = NULL;
    if (preadbuf) {
        free(preadbuf);
    }
    preadbuf = NULL;


    if (pcurwrite) {
        free(pcurwrite);
    }
    pcurwrite = NULL;
    curwritelen = 0;
    if (pwritebuf) {
        free(pwritebuf);
    }
    pwritebuf = NULL;
    writelen = 0;
    while (wbufs.size() > 0) {
        ASSERT_IF(wbufs.size() == wlens.size());
        pcurwrite = wbufs.at(0);
        wbufs.erase(wbufs.begin());
        if (pcurwrite) {
            free(pcurwrite);
        }
        pcurwrite = NULL;
        curwritelen = wlens.at(0);
        wlens.erase(wlens.begin());
    }

    pnp = bind_namedpipe(pipename);
    if (pnp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("bind [%s] error[%d]", pipename, ret);
        goto out;
    }

    DEBUG_INFO("bind [%s]", pipename);

    if (get_namedpipe_connstate(pnp) > 0) {
        while (1) {
            waitnum = 0;
            waithds[waitnum] = st_ExitEvt;
            waitnum ++;
            waithds[waitnum] = get_namedpipe_connevt(pnp);
            waitnum ++;

            dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, INFINITE, FALSE);
            if ((dret < (WAIT_OBJECT_0 + waitnum))) {
                curhd = waithds[(dret - WAIT_OBJECT_0)];
                if (curhd == st_ExitEvt) {
                    ret = 0;
                    goto out;
                } else if (curhd == get_namedpipe_connevt(pnp)) {
                    ret = complete_namedpipe_connpending(pnp);
                    if (ret < 0) {
                        GETERRNO(ret);
                        ERROR_INFO("wait connect[%s] error[%d]", pipename, ret);
                        goto try_again;
                    }
                    if (ret > 0) {
                        break;
                    }
                }
            } else {
                ERROR_INFO("wait connect[%s] error[%d]", pipename, dret);
                goto try_again;
            }
        }
    }

    DEBUG_INFO("client connect[%s]", pipename);

    curidx = 0;
    rcvlen = 0;
    needlen = sizeof(uint32_t);
    rcvsize = 256;
    preadbuf = (char*)malloc((size_t)rcvsize);
    if (preadbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not alloc [%d] error[%d]\n", rcvsize, ret );
        goto out;
    }

    while (1) {
        waitnum = 0;
        memset(waithds, 0, sizeof(waithds));
        ASSERT_IF(waitnum < MAX_WAIT_NUM);
        waithds[waitnum] = st_ExitEvt;
        waitnum ++;
        if (get_namedpipe_rdstate(pnp) == 0) {
read_again:
            ret = read_namedpipe(pnp, &(preadbuf[rcvlen]), (int)(needlen - rcvlen));
            if (ret < 0) {
                ERROR_INFO("read [%s] error[%d]", pipename, ret);
                goto try_again;
            }
            rcvlen += ret;
            if (get_namedpipe_rdstate(pnp) == 0) {
                if (needlen == sizeof(uint32_t)) {
                    rcvlen = needlen;
                    memcpy(&wholelen, &(preadbuf[0]), sizeof(uint32_t));
                    needlen = wholelen;
                    if (needlen > rcvsize) {
                        rcvsize = needlen;
                        ptmpreadbuf = (char*)malloc(rcvsize);
                        if (ptmpreadbuf == NULL) {
                            GETERRNO(ret);
                            fprintf(stderr, "cannot alloc [%d] error[%d]\n", rcvsize , ret);
                            goto out;
                        }
                        if (rcvlen > 0) {
                            memcpy(ptmpreadbuf, preadbuf, rcvlen);
                        }
                        if (preadbuf) {
                            free(preadbuf);
                        }
                        preadbuf = ptmpreadbuf;
                        ptmpreadbuf = NULL;
                    }
                    if (needlen == sizeof(uint32_t)) {
                        goto reply_read;
                    }

                    ret = read_namedpipe(pnp, &(preadbuf[rcvlen]), (int)(needlen - rcvlen));
                    if (ret < 0) {
                        GETERRNO(ret);
                        ERROR_INFO("read [%s] error[%d]", pipename, ret);
                        goto try_again;
                    }

                    rcvlen += ret;
                    if (get_namedpipe_rdstate(pnp) == 0) {
                        rcvlen = needlen;
                        goto reply_read;
                    }
                    ASSERT_IF(waitnum < MAX_WAIT_NUM);
                    waithds[waitnum] = get_namedpipe_rdevt(pnp);
                    waitnum ++;
                } else if (needlen > sizeof(uint32_t)) {
                    rcvlen = needlen;
reply_read:
                    DEBUG_BUFFER_FMT(preadbuf,
                                     (int)needlen,
                                     "read packet [%d]",
                                     curidx);
                    if (curidx >= argcnt) {
                        curidx = 0;
                    }
                    if (curidx >= argcnt) {
                        writelen = (int)needlen;
                    } else {
                        writelen = (int)(sizeof(uint32_t) + filelen[curidx]);
                    }
                    pwritebuf = (char*)malloc((size_t)writelen);
                    if (pwritebuf == NULL) {
                        GETERRNO(ret);
                        fprintf(stderr, "alloc %d error[%d]\n", writelen, ret);
                        goto out;
                    }
                    if (curidx >= argcnt) {
                        memcpy(pwritebuf, preadbuf, needlen);
                    } else {
                        memcpy(pwritebuf, &writelen, sizeof(uint32_t));
                        memcpy(&(pwritebuf[sizeof(uint32_t)]),
                               filecon[curidx],
                               (size_t)filelen[curidx]);
                    }
                    if (pcurwrite == NULL) {
                        pcurwrite = pwritebuf;
                        curwritelen = writelen;
                        pwritebuf = NULL;
                        writelen = 0;
                        ret = write_namedpipe(pnp, pcurwrite, curwritelen);
                        if (ret < 0) {
                            fprintf(stderr, "can not write [%s] error[%d]\n", pipename, ret);
                            goto try_again;
                        }
                        if (get_namedpipe_wrstate(pnp) == 0) {
                            free(pcurwrite);
                            pcurwrite = NULL;
                            curwritelen = 0;
                        }
                    } else {
                        wbufs.push_back(pwritebuf);
                        wlens.push_back(writelen);
                        pwritebuf = NULL;
                        writelen = 0;
                    }
                    curidx ++;
                    needlen = sizeof(uint32_t);
                    rcvlen = 0;
                    goto read_again;
                }
            } else {
                ASSERT_IF(waitnum < MAX_WAIT_NUM);
                waithds[waitnum] = get_namedpipe_rdevt(pnp);
                waitnum ++;
            }
        } else {
            ASSERT_IF(waitnum < MAX_WAIT_NUM);
            waithds[waitnum] = get_namedpipe_rdevt(pnp);
            waitnum ++;
        }

        if (get_namedpipe_wrstate(pnp) == 0) {
write_again:
            if (pcurwrite != NULL) {
                free(pcurwrite);
            }
            pcurwrite = NULL;
            curwritelen = 0;
            if (wbufs.size() > 0) {
                pcurwrite = wbufs.at(0);
                wbufs.erase(wbufs.begin());
                curwritelen = wlens.at(0);
                wlens.erase(wlens.begin());
                ret = write_namedpipe(pnp, pcurwrite, curwritelen);
                if (ret < 0) {
                    GETERRNO(ret);
                    fprintf(stderr, "write [%s] error[%d]\n", pipename, ret);
                    goto try_again;
                }
                if (get_namedpipe_wrstate(pnp) == 0) {
                    goto write_again;
                } else {
                    ASSERT_IF(waitnum < MAX_WAIT_NUM);
                    waithds[waitnum] = get_namedpipe_wrevt(pnp);
                    waitnum ++;
                }
            }
        } else {
            ASSERT_IF(waitnum < MAX_WAIT_NUM);
            waithds[waitnum] = get_namedpipe_wrevt(pnp);
            waitnum ++;
        }

        dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, INFINITE, FALSE);
        if (dret < (WAIT_OBJECT_0 + waitnum)) {
            curhd = waithds[(dret - WAIT_OBJECT_0)];
            if (curhd == st_ExitEvt) {
                break;
            } else if (curhd == get_namedpipe_rdevt(pnp)) {
                ret = complete_namedpipe_rdpending(pnp);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not complete [%s]", pipename);
                    goto try_again;
                }

                if (ret > 0) {
                    if (needlen == sizeof(uint32_t)) {
                        rcvlen = needlen;
                        memcpy(&needlen, preadbuf, sizeof(uint32_t));
                        if (needlen > rcvsize) {
                            rcvsize = needlen;
                            ASSERT_IF(ptmpreadbuf == NULL);
                            ptmpreadbuf = (char*)malloc(rcvsize);
                            if (ptmpreadbuf == NULL) {
                                GETERRNO(ret);
                                ERROR_INFO("can not alloc [%d] error[%d]", rcvsize , ret);
                                goto out;
                            }
                            if (rcvlen > 0) {
                                memcpy(ptmpreadbuf, preadbuf, rcvlen);
                            }
                            if (preadbuf) {
                                free(preadbuf);
                            }
                            preadbuf = ptmpreadbuf;
                            ptmpreadbuf = NULL;
                        }

                        if (needlen == sizeof(uint32_t)) {
                            goto wait_write;
                        }
                    } else if (needlen > sizeof(uint32_t)) {
wait_write:
                        DEBUG_BUFFER_FMT(preadbuf, (int)needlen, "[%d] packet" , curidx);
                        if (curidx >= argcnt) {
                            curidx = 0;
                        }

                        if (curidx >= argcnt) {
                            writelen = (int)needlen;
                        } else {
                            writelen = (int)(sizeof(uint32_t) + filelen[curidx]);
                        }

                        pwritebuf = (char*) malloc((size_t)writelen);
                        if (pwritebuf == NULL) {
                            GETERRNO(ret);
                            ERROR_INFO("alloc [%d] error[%d]", writelen, ret);
                            goto out;
                        }

                        if (curidx >= argcnt) {
                            memcpy(pwritebuf, preadbuf, (size_t)writelen);
                        } else {
                            memcpy(pwritebuf, &writelen, sizeof(uint32_t));
                            memcpy(&(pwritebuf[sizeof(uint32_t)]), filecon[curidx], (size_t)filelen[curidx]);
                        }

                        if (pcurwrite == NULL) {
                            pcurwrite = pwritebuf;
                            curwritelen = writelen;
                            pwritebuf = NULL;
                            writelen = 0;
                            ret = write_namedpipe(pnp, pcurwrite, curwritelen);
                            if (ret < 0) {
                                GETERRNO(ret);
                                ERROR_INFO("write [%s] error[%d]", pipename, ret);
                                goto try_again;
                            }
                            if (get_namedpipe_wrstate(pnp) == 0) {
                                free(pcurwrite);
                                curwritelen = 0;
                            }
                        } else {
                            wbufs.push_back(pwritebuf);
                            wlens.push_back(writelen);
                            pwritebuf = NULL;
                            writelen = 0;
                        }
                        curidx ++;
                    }
                }
            } else if (curhd == get_namedpipe_wrevt(pnp)) {
                ret = complete_namedpipe_wrpending(pnp);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not complete [%s]", pipename);
                    goto try_again;
                }
            }
        } else if (dret == WAIT_TIMEOUT) {
            continue;
        } else {
            ERROR_INFO("dret [%ld] error", dret);
            goto try_again;
        }
    }

    ret = 0;
out:
    close_namedpipe(&pnp);
    if (ptmpreadbuf) {
        free(ptmpreadbuf);
    }
    ptmpreadbuf = NULL;
    if (preadbuf) {
        free(preadbuf);
    }
    preadbuf = NULL;


    if (pcurwrite) {
        free(pcurwrite);
    }
    pcurwrite = NULL;
    curwritelen = 0;
    if (pwritebuf) {
        free(pwritebuf);
    }
    pwritebuf = NULL;
    writelen = 0;
    while (wbufs.size() > 0) {
        ASSERT_IF(wbufs.size() == wlens.size());
        pcurwrite = wbufs.at(0);
        wbufs.erase(wbufs.begin());
        if (pcurwrite) {
            free(pcurwrite);
        }
        pcurwrite = NULL;
        curwritelen = wlens.at(0);
        wlens.erase(wlens.begin());
    }

    ASSERT_IF(wbufs.size() == 0);
    ASSERT_IF(wlens.size() == 0);

    if (filecon != NULL && filelen != NULL) {
        for (i = 0; i < argcnt ; i++) {
            read_file_whole(NULL, &(filecon[i]), &(filelen[i]));
        }
    }

    if (filecon) {
        free(filecon);
    }
    filecon = NULL;

    if (filelen) {
        free(filelen);
    }
    filelen = NULL;
    argcnt = 0;
    SETERRNO(ret);
    return ret;
}

int npcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    void* pnp = NULL;
    char** filecon = NULL;
    int *filelen = NULL;
    int argcnt = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int curidx = 0;
    char** fnames = NULL;
    char* pipename = NULL;
    char* pwritebuf = NULL;
    int writelen = 0;
    uint32_t writesize = 0;
    char* preadbuf = NULL;
    int needlen = 0;
    int rcvlen = 0;
    int ridx = 0;
    HANDLE waithds[MAX_WAIT_NUM];
    DWORD waitnum;
    int i;
    BOOL bret;
    uint32_t rcvsize = 0;
    char* ptmpreadbuf = NULL;
    DWORD dret;
    HANDLE curhd;
    int filesize = 0;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    pipename = pargs->m_pipename;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        argcnt ++;
    }

    if (argcnt > 0) {
        fnames = parsestate->leftargs;
        filecon = (char**) malloc(sizeof(*filecon) * argcnt);
        if (filecon == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "can not alloc [%zu] error[%d]\n", sizeof(*filecon)* argcnt, ret);
            goto out;
        }
        memset(filecon, 0, sizeof(*filecon) * argcnt);

        filelen = (int*) malloc(sizeof(*filelen) * argcnt);
        if (filelen == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "can not alloc [%zu] error[%d]\n", sizeof(*filelen)* argcnt, ret);
            goto out;
        }
        memset(filelen, 0, sizeof(*filelen) * argcnt);

        for (i = 0; i < argcnt; i++) {
            filesize = 0;
            ret = read_file_whole(fnames[i], &(filecon[i]), &filesize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "[%d].[%s] read error[%d]\n", i, fnames[i], ret);
                goto out;
            }
            filelen[i] = ret;
        }
    }

    st_ExitEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_ExitEvt == NULL) {
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


    pnp = connect_namedpipe(pipename);
    if (pnp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not connect [%s] error[%d]", pipename, ret);
        goto out;
    }

    DEBUG_INFO("connect [%s]", pipename);

    curidx = 0;
    ridx = 0;
    rcvlen = 0;
    needlen = sizeof(uint32_t);
    rcvsize = 256;
    preadbuf = (char*)malloc(rcvsize);
    if (preadbuf == NULL ) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc[%d] error[%d]", rcvsize, ret);
        goto out;
    }
    writesize = 0;
    while (curidx < argcnt || ridx < argcnt) {
        DEBUG_INFO("curidx [%d] ridx [%d] argcnt [%d]", curidx, ridx, argcnt);
        waitnum = 0;
        waithds[waitnum] = st_ExitEvt;
        waitnum ++;
        if (get_namedpipe_wrstate(pnp) == 0) {
write_again:
            if (curidx < argcnt) {
                if (writesize < (filelen[curidx] + sizeof(uint32_t))) {
                    writesize = (filelen[curidx] + sizeof(uint32_t));
                    if (pwritebuf) {
                        free(pwritebuf);
                    }
                    pwritebuf = NULL;
                    pwritebuf = (char*) malloc(writesize);
                    if (pwritebuf == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc [%d] error[%d]", writesize, ret);
                        goto out;
                    }
                }
                ASSERT_IF(pwritebuf != NULL);
                writelen = (int)(filelen[curidx] + sizeof(uint32_t));
                memcpy(&(pwritebuf[0]), &writelen, sizeof(uint32_t));
                memcpy(&(pwritebuf[sizeof(uint32_t)]), filecon[curidx], (size_t)filelen[curidx]);
                ret = write_namedpipe(pnp, pwritebuf, writelen);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not write [%s].[%d] error[%d]", pipename, curidx, ret);
                    goto out;
                }
                if (get_namedpipe_wrstate(pnp) == 0) {
                    curidx ++;
                    goto write_again;
                }
                ASSERT_IF(waitnum < MAX_WAIT_NUM);
                waithds[waitnum] = get_namedpipe_wrevt(pnp);
                waitnum ++;
            }
        } else {
            ASSERT_IF(waitnum < MAX_WAIT_NUM);
            waithds[waitnum] = get_namedpipe_wrevt(pnp);
            waitnum ++;
        }
        if (get_namedpipe_rdstate(pnp) == 0) {
read_again:
            if (ridx < argcnt) {
                ret = read_namedpipe(pnp, &(preadbuf[rcvlen]), (needlen - rcvlen));
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("can not read [%s] error[%d]", pipename, ret);
                    goto out;
                }
                DEBUG_INFO("read [%d]", ret);
                if (get_namedpipe_rdstate(pnp) == 0) {
                    rcvlen = needlen;
                    if (needlen == sizeof(uint32_t)) {
                        memcpy(&needlen, preadbuf, sizeof(uint32_t));
                        if (needlen > (int)rcvsize) {
                            rcvsize = (uint32_t)needlen;
                            ptmpreadbuf = (char*)malloc(rcvsize);
                            if (ptmpreadbuf == NULL) {
                                GETERRNO(ret);
                                ERROR_INFO("can not alloc [%d] error[%d]", rcvsize , ret);
                                goto out;
                            }
                            if (rcvlen > 0) {
                                memcpy(ptmpreadbuf, preadbuf, (size_t)rcvlen);
                            }
                            if (preadbuf) {
                                free(preadbuf);
                            }
                            preadbuf = ptmpreadbuf;
                            ptmpreadbuf = NULL;
                        }

                        if (needlen > sizeof(uint32_t)) {
                            ret = read_namedpipe(pnp, &(preadbuf[rcvlen]), (needlen - rcvlen));
                            rcvlen += ret;
                            if (ret < 0) {
                                GETERRNO(ret);
                                ERROR_INFO("read [%s] error[%d]", pipename, ret);
                                goto out;
                            }
                        }

                        if (get_namedpipe_rdstate(pnp) == 0) {
                            rcvlen = needlen;
                            goto read_more;
                        }
                    } else if (needlen > sizeof(uint32_t)) {
                        rcvlen = needlen;
read_more:
                        DEBUG_BUFFER_FMT(preadbuf, needlen, "read [%d] packet", ridx);
                        ridx ++;
                        needlen = sizeof(uint32_t);
                        rcvlen = 0;
                        goto read_again;
                    }
                } else {
                    ASSERT_IF(waitnum < MAX_WAIT_NUM);
                    waithds[waitnum] = get_namedpipe_rdevt(pnp);
                    waitnum ++;
                }
            }
        } else {
            ASSERT_IF(waitnum < MAX_WAIT_NUM);
            waithds[waitnum] = get_namedpipe_rdevt(pnp);
            waitnum ++;
        }

        dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, 500, FALSE);
        if (dret < (WAIT_OBJECT_0 + waitnum)) {
            curhd = waithds[(dret - WAIT_OBJECT_0)];
            if (curhd == st_ExitEvt) {
                break;
            } else if (curhd == get_namedpipe_rdevt(pnp)) {
                DEBUG_INFO("rdevt");
                ret = complete_namedpipe_rdpending(pnp);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("complete [%s] read error[%d]", pipename, ret);
                    goto out;
                }

                if (ret > 0) {
                    DEBUG_INFO("needlen [%d]", needlen);
                    if (needlen > sizeof(uint32_t)) {
                        rcvlen = needlen;
dump_again:
                        DEBUG_BUFFER_FMT(preadbuf, needlen, "read [%d] packet", ridx);
                        needlen = sizeof(uint32_t);
                        rcvlen = 0;
                        ridx ++;
                    } else if (needlen == sizeof(uint32_t)) {
                        rcvlen = needlen;
                        memcpy(&needlen, preadbuf, sizeof(uint32_t));
                        DEBUG_INFO("more [%d]", needlen);
                        if (needlen == sizeof(uint32_t)) {
                            goto dump_again;
                        }

                        if (needlen > (int)rcvsize) {
                            rcvsize = (uint32_t)needlen;
                            ptmpreadbuf = (char*)malloc(rcvsize);
                            if (ptmpreadbuf == NULL) {
                                GETERRNO(ret);
                                ERROR_INFO("can not alloc [%d] error[%d]", rcvsize , ret);
                                goto out;
                            }
                            if (rcvlen > 0) {
                                memcpy(ptmpreadbuf, preadbuf, (size_t)rcvlen);
                            }
                            if (preadbuf) {
                                free(preadbuf);
                            }
                            preadbuf = ptmpreadbuf;
                            ptmpreadbuf = NULL;
                        }
                    }
                }
            } else if (curhd == get_namedpipe_wrevt(pnp)) {
                ret = complete_namedpipe_wrpending(pnp);
                if (ret < 0) {
                    GETERRNO(ret);
                    ERROR_INFO("complete [%s] write error[%d]", pipename, ret);
                    goto out;
                }

                if (ret > 0) {
                    curidx ++;
                }
            }
        } else if (dret == WAIT_TIMEOUT) {
            continue;
        } else {
            GETERRNO(ret);
            ERROR_INFO("wait error [%d] [%d]", dret, ret);
            goto out;
        }
    }


    ret = 0;
out:
    close_namedpipe(&pnp);
    if (filecon != NULL && filelen != NULL) {
        for (i = 0; i < argcnt; i++) {
            read_file_whole(NULL, &(filecon[i]), &(filelen[i]));
        }
    }

    if (pwritebuf) {
        free(pwritebuf);
    }
    pwritebuf = NULL;
    writelen = 0;
    writesize = 0;

    if (preadbuf) {
        free(preadbuf);
    }
    preadbuf = NULL;
    rcvlen = 0;
    needlen = 0;
    rcvsize = 0;

    if (ptmpreadbuf) {
        free(ptmpreadbuf);
    }
    ptmpreadbuf = NULL;

    if (filecon) {
        free(filecon);
    }
    filecon = NULL;

    if (filelen) {
        free(filelen);
    }
    filelen = NULL;
    argcnt = 0;
    SETERRNO(ret);
    return ret;
}


static int format_pipe_data(jvalue* pj, char** ppsndbuf, int* psndsize)
{
    jentry** entries = NULL;
    jentry* pcurentry = NULL;
    unsigned int entriesizes = 0;
    int ret;
    int sndlen = 0;
    char* pstr = NULL;
    int strsize = 0;
    char* valstr = NULL;
    unsigned int valsize = 0;
    int retlen = 0;
    char* pretbuf = NULL;
    unsigned int i;


    if (psndsize == NULL || ppsndbuf == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    retlen = *psndsize;
    pretbuf = *ppsndbuf;

    entries = jobject_entries(pj, &entriesizes);
    if (entries == NULL) {
        ret = snprintf_safe(&pstr, &strsize, "");
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    } else {
        for (i = 0; i < entriesizes; i++) {
            pcurentry = entries[i];
            switch (pcurentry->value->type) {
            case JNONE:
            case JBOOL:
            case JNULL:
            case JINT:
            case JINT64:
            case JREAL:
            case JSTRING:
            case JARRAY:
            case JOBJECT:
                if (valstr) {
                    free(valstr);
                }
                valstr = NULL;
                valsize = 0;
                valstr = jvalue_write(pcurentry->value, &valsize);
                if (valstr == NULL) {
                    GETERRNO(ret);
                    goto fail;
                }
                ret = append_snprintf_safe(&pstr, &strsize, "%s=%s\n", pcurentry->key, valstr);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
                break;
            default:
                ret = -ERROR_INVALID_PARAMETER;
                goto fail;
            }
        }
    }

    sndlen = (int)(strlen(pstr) + sizeof(uint32_t));
    if (retlen < sndlen || pretbuf == NULL) {
        if (retlen < sndlen) {
            retlen = sndlen;
        }
        pretbuf = (char*) malloc((size_t)retlen);
        if (pretbuf == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }
    memcpy(pretbuf, &sndlen, sizeof(uint32_t));
    if (sndlen > sizeof(uint32_t)) {
        memcpy(&(pretbuf[sizeof(uint32_t)]), pstr, (sndlen - sizeof(uint32_t)));
    }

    if (*ppsndbuf && *ppsndbuf != pretbuf) {
        free(*ppsndbuf);
    }
    *ppsndbuf = pretbuf;
    *psndsize = retlen;

    snprintf_safe(&pstr, &strsize, NULL);
    if (valstr) {
        free(valstr);
    }
    valstr = NULL;
    valsize = 0;
    jentries_destroy(&entries);

    return sndlen;
fail:
    if (pretbuf && pretbuf != *ppsndbuf) {
        free(pretbuf);
    }
    pretbuf = NULL;

    snprintf_safe(&pstr, &strsize, NULL);
    if (valstr) {
        free(valstr);
    }
    valstr = NULL;
    valsize = 0;
    jentries_destroy(&entries);
    SETERRNO(ret);
    return ret;
}

int pipedata_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* fname;
    jvalue* pj = NULL;
    char* filecon = NULL;
    int filesize = 0;
    int ret;
    unsigned int size;
    char* poutdata = NULL;
    int outsize = 0;
    int outlen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        fname = parsestate->leftargs[i];
        ret = read_file_whole(fname, &filecon, &filesize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("read [%s] error[%d]", fname, ret);
            goto out;
        }

        if (pj) {
            jvalue_destroy(pj);
        }
        pj = NULL;
        size = 0;
        pj = jvalue_read(filecon, &size);
        if (pj == NULL) {
            GETERRNO(ret);
            ERROR_INFO("[%s] not json file", fname);
            goto out;
        }

        ret = format_pipe_data(pj, &poutdata, &outsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("format pipe [%s] error[%d]", fname, ret);
            goto out;
        }
        outlen = ret;
        DEBUG_BUFFER_FMT(poutdata, outlen, "[%s] format data", fname);
    }

    ret = 0;
out:
    if (pj) {
        jvalue_destroy(pj);
    }
    pj = NULL;
    read_file_whole(NULL, &filecon, &filesize);
    SETERRNO(ret);
    return ret;
}


int mkdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    char* dirname = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        dirname = parsestate->leftargs[i];
        ret = create_directory(dirname);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("create [%s] error[%d]", dirname, ret);
            goto out;
        }
        fprintf(stdout, "create %s [%s]\n", dirname, ret > 0 ? "created" : "exists");
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int wtsdetachrun_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(WTS_DETACH_RUN, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int utf8touni_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* putf8 = NULL;
    int utf8size = 0;
    int utf8len = 0;
    wchar_t* puni = NULL;
    int unisize = 0, unilen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    ret = __get_code(parsestate, &putf8, &utf8size);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    utf8len = ret;
    ret = Utf8ToUnicode(putf8, &puni, &unisize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not trans buffer [%d]\n", ret);
        goto out;
    }
    unilen = ret;

    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    __debug_buf(stdout, putf8, utf8len);
    fprintf(stdout, "unicode buffer [%d]\n", unilen);
    __debug_buf(stdout, (char*)puni, unilen);
    ret = 0;
out:
    Utf8ToUnicode(NULL, &puni, &unisize);
    __get_code(NULL, &putf8, &utf8size);
    SETERRNO(ret);
    return ret;
}


int unitoutf8_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    char* putf8 = NULL;
    int utf8size = 0;
    int utf8len = 0;
    wchar_t* puni = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    ret = __get_code(parsestate, &pbuf, &bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    buflen = ret;
    puni = (wchar_t*)pbuf;

    ret = UnicodeToUtf8(puni, &putf8, &utf8size);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not trans buffer [%d]\n", ret);
        goto out;
    }
    utf8len = ret;

    fprintf(stdout, "unicode buffer [%d]\n", buflen);
    __debug_buf(stdout, pbuf, buflen);
    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    __debug_buf(stdout, putf8, utf8len);
    ret = 0;
out:
    UnicodeToUtf8(NULL, &putf8, &utf8size);
    __get_code(NULL, &pbuf, &bufsize);
    SETERRNO(ret);
    return ret;
}

int startproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int createflags = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    int ret;
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    if (pargs->m_hidewindow) {
        createflags |= PROC_NO_WINDOW;
    }

    ret = start_cmdv_detach(createflags, parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "start [");
        for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", parsestate->leftargs[i] );
        }
        fprintf(stderr, "] error[%d]\n", ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int checkproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int numproc = 0;
    int ret;
    char** ppnames = NULL;
    int i;
    int* pfinded = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        numproc ++;
    }

    ppnames = (char**) malloc(sizeof(ppnames[0]) * numproc);
    if (ppnames == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc [%d] error[%d]", sizeof(ppnames[0]) * numproc, ret);
        goto out;
    }

    pfinded = (int*) malloc(sizeof(pfinded[0]) * numproc);
    if (pfinded == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not alloc [%d] error[%d]", sizeof(pfinded[0]) * numproc, ret);
        goto out;
    }

    memset(pfinded, 0, sizeof(pfinded[0]) * numproc);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        ppnames[i] = parsestate->leftargs[i];
    }

    ret = process_num(ppnames, numproc, pfinded);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "find proc [");
        for (i = 0; i < numproc; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", ppnames[i]);
        }
        fprintf(stderr, "] error [%d]\n", ret);
        goto out;
    }
    for (i = 0; i < numproc; i++) {
        fprintf(stdout, "[%s]        run [%d]", ppnames[i], pfinded[i]);
    }


    ret = 0;
out:
    if (ppnames) {
        free(ppnames);
    }
    ppnames = NULL;

    if (pfinded) {
        free(pfinded);
    }
    pfinded = NULL;

    SETERRNO(ret);
    return ret;
}

int svrcheckproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    ret = __send_svr_pipe(PROCESS_NUM_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int version_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    REFERENCE_ARG(argc);
    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(popt);
    printf("%s version 1.0.1 compiled at [%s %s] cl version[%d]\n", argv[0], __DATE__, __TIME__, _MSC_VER);
    return 0;
}

int __mk_svc_handler(pextargs_state_t parsestate, pargs_options_t pargs, int drivemode)
{
    char* binpath = NULL;
    char* svcname = NULL;
    int svcnamesize = 0;
    int allocname = 0;
    char* desc = NULL;
    int descsize = 0;
    int allocdesc = 0;
    int startmode = SVC_START_ON_DEMAND;
    char* pstart = NULL;
    int idx = 0;
    char* pcurptr = NULL;
    char* lastptr = NULL;
    int ret;

    REFERENCE_ARG(pargs);

    binpath = parsestate->leftargs[idx];
    idx ++;

    if (parsestate->leftargs[idx]) {
        svcname = parsestate->leftargs[idx];
        idx ++;
    } else {
        pcurptr = strrchr(binpath, '\\');
        if (pcurptr) {
            pcurptr ++;
        } else {
            pcurptr = binpath;
        }
        ret = snprintf_safe(&svcname, &svcnamesize, "%s", pcurptr);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        lastptr = svcname + strlen(svcname);
        while (lastptr != svcname) {
            if (*lastptr == '.') {
                *lastptr = '\0';
                break;
            }
            lastptr --;
        }
        allocname = 1;
    }

    if (parsestate->leftargs[idx]) {
        desc = parsestate->leftargs[idx];
        idx ++;
    } else {
        ret = snprintf_safe(&desc, &descsize, "%s description", svcname);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        allocdesc = 1;
    }

    if (parsestate->leftargs[idx]) {
        pstart = parsestate->leftargs[idx];
        idx ++;
        if (_stricmp(pstart, "demand") == 0) {
            startmode = SVC_START_ON_DEMAND;
        } else if (_stricmp(pstart, "auto") == 0) {
            startmode = SVC_START_ON_AUTO;
        } else if (_stricmp(pstart, "boot") == 0) {
            startmode = SVC_START_ON_BOOT;
        } else if (_stricmp(pstart, "system") == 0) {
            startmode = SVC_START_ON_SYSTEM;
        } else if (_stricmp(pstart, "disable") == 0) {
            startmode = SVC_START_ON_DISABLED;
        } else {
            ret = -ERROR_INVALID_PARAMETER;
            ERROR_INFO("[%s] not support type start mode", pstart);
            goto out;
        }
    }

    if (drivemode) {
        ret = create_driver(svcname, desc, binpath, startmode);
    } else {
        ret = create_service(svcname, desc, binpath, startmode);
    }
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("create %s [%s] [%s] [%s] mode[%d] error[%d]", drivemode ? "driver" : "service",
                   svcname, desc, binpath, startmode, ret);
        goto out;
    }

    fprintf(stdout, "create %s [%s] [%s] [%s] mode[%d] succ\n", drivemode ? "driver" : "service",
            svcname, desc, binpath, startmode);
    ret = 0;
out:
    if (allocdesc) {
        snprintf_safe(&desc, &descsize, NULL);
    }
    desc = NULL;
    descsize = 0;
    allocdesc = 0;
    if (allocname) {
        snprintf_safe(&svcname, &svcnamesize, NULL);
    }
    svcname = NULL;
    svcnamesize = 0;
    allocname = 0;
    SETERRNO(ret);
    return ret;
}


int mkdrv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    return __mk_svc_handler(parsestate, pargs, 1);
}
int mksvc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    return __mk_svc_handler(parsestate, pargs, 0);
}

int listmod_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int idx = 0;
    int lastidx = 0;
    int procid = 0;
    char* modname = NULL;
    int maxlen = 0;
    int i;
    pmod_info_t pinfo = NULL;
    int infosize = 0;
    int infolen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    GET_OPT_INT(procid, "procid");
    if (parsestate->leftargs && parsestate->leftargs[idx]) {
        lastidx = idx;
        for (; parsestate->leftargs && parsestate->leftargs[lastidx]; lastidx ++ ) {
            modname = parsestate->leftargs[lastidx];
            ret = get_module_info(procid, modname, &pinfo, &infosize);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not get [%d] mod[%s] error[%d]", procid, modname, ret);
                goto out;
            }
            infolen = (int)(ret / sizeof(*pinfo));
            for (i = 0; i < infolen; i++) {
                if ((int)strlen(pinfo[i].m_modfullname) > maxlen) {
                    maxlen = (int)strlen(pinfo[i].m_modfullname);
                }
            }
        }
        lastidx = idx;
        fprintf(stdout, "%-*s %-*s %-*s      \n", maxlen, "name", 16, "addr", 8, "size");
        for (; parsestate->leftargs && parsestate->leftargs[lastidx]; lastidx ++ ) {
            modname = parsestate->leftargs[lastidx];
            ret = get_module_info(procid, modname, &pinfo, &infosize);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("can not get [%d] mod[%s] error[%d]", procid, modname, ret);
                goto out;
            }
            infolen = (int)(ret / sizeof(*pinfo));
            for (i = 0; i < infolen; i++) {
                fprintf(stdout, "%-*s %p %d\n", maxlen, pinfo[i].m_modfullname, pinfo[i].m_pimgbase,
                        pinfo[i].m_modsize);
            }
        }
    } else {
        ret = get_module_info(procid, "", &pinfo, &infosize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not get [%d] mod[%s] error[%d]", procid, modname, ret);
            goto out;
        }
        infolen = (int)(ret / sizeof(*pinfo));
        DEBUG_INFO("infolen [%d]", infolen);
        for (i = 0; i < infolen; i++) {
            if ((int)strlen(pinfo[i].m_modfullname) > maxlen) {
                maxlen = (int)strlen(pinfo[i].m_modfullname);
            }
        }
        fprintf(stdout, "%-*s %-*s %-*s      \n", maxlen, "name", 16, "addr", 8, "size");
        ret = get_module_info(procid, "", &pinfo, &infosize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not get [%d] mod[%s] error[%d]", procid, modname, ret);
            goto out;
        }
        infolen = (int)(ret / sizeof(*pinfo));
        DEBUG_INFO("infolen [%d]", infolen);
        for (i = 0; i < infolen; i++) {
            fprintf(stdout, "%-*s %p %d\n", maxlen, pinfo[i].m_modfullname, pinfo[i].m_pimgbase,
                    pinfo[i].m_modsize);
        }
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int getprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    pprinter_list_t pprn = NULL;
    int prnsize = 0, prnlen = 0;
    int i;
    size_t namelen = 0, sharelen = 0, iplen = 0, typelen = 0;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    REFERENCE_ARG(parsestate);
    init_log_level(pargs);

    ret = get_printer_list(0, NULL, &pprn, &prnsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not get printer list [%d]", ret);
        goto out;
    }
    prnlen = ret;

    namelen = strlen("name") ;
    iplen = strlen("ip");
    typelen = strlen("type");
    sharelen = strlen("share");

    for (i = 0; i < prnlen; i++) {
        if (strlen(pprn[i].m_name) >= namelen) {
            namelen = strlen(pprn[i].m_name) + 1;
        }
        if (strlen(pprn[i].m_sharename) >= sharelen) {
            sharelen = strlen(pprn[i].m_sharename) + 1;
        }

        if (strlen(pprn[i].m_ip) >= iplen) {
            iplen = strlen(pprn[i].m_ip) + 1;
        }

        if (strlen(pprn[i].m_type) >= typelen) {
            typelen = strlen(pprn[i].m_type) + 1;
        }
    }

    fprintf(stdout, "items %-*s %-*s %-*s %-*s\n", (int)namelen, "name", (int)typelen, "type", (int)sharelen, "share", (int)iplen, "ip");
    for (i = 0; i < prnlen; i++) {
        fprintf(stdout, "%03d   %-*s %-*s %-*s %-*s\n", i, (int)namelen, pprn[i].m_name, (int)typelen, pprn[i].m_type,
                (int)sharelen, pprn[i].m_sharename, (int)iplen, pprn[i].m_ip);
    }
    ret = 0;
out:
    get_printer_list(1, NULL, &pprn, &prnsize);
    prnlen = 0;
    SETERRNO(ret);
    return ret;
}

int addprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* remoteip = NULL;
    char* name = NULL;
    char* user = NULL;
    char* password = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;
    int i = 0;
    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        if (i == 0) {
            remoteip = parsestate->leftargs[i];
        } else if (i == 1) {
            name = parsestate->leftargs[i];
        } else if (i == 2) {
            user = parsestate->leftargs[i];
        } else if (i == 3) {
            password = parsestate->leftargs[i];
        }
    }

    if (remoteip == NULL || name == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "need remoteip and name\n");
        goto out;
    }

    ret = add_share_printer(NULL, name, remoteip, user, password);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not add [\\\\%s\\%s] with user[%s] password[%s] error[%d]\n",
                remoteip, name, user ? user : "guest", password ? password : "", ret);
        goto out;
    }

    fprintf(stdout, "add [\\\\%s\\%s] succ\n", remoteip, name);

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int delprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* remoteip = NULL;
    char* name = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);

    remoteip = parsestate->leftargs[0];
    name = parsestate->leftargs[1];

    ret = del_share_printer(NULL, name, remoteip);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not delete printer [%s].[%s] error[%d]", remoteip, name, ret);
        goto out;
    }

    fprintf(stdout, "delete \\\\%s\\%s succ\n", remoteip, name);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;

}
int saveprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char*exportfile = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    init_log_level(pargs);
    exportfile = parsestate->leftargs[0];

    ret = save_printer_exportfile(NULL, exportfile);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("save printer configuration [%s] error[%d]", exportfile, ret);
        goto out;
    }

    fprintf(stdout, "save printer configuration [%s] succ\n", exportfile);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int restoreprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char*exportfile = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);
    exportfile = parsestate->leftargs[0];

    ret = restore_printer_exportfile(NULL, exportfile);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("restore printer configuration [%s] error[%d]", exportfile, ret);
        goto out;
    }

    fprintf(stdout, "restore printer configuration [%s] succ\n", exportfile);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svraddprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(ADDPRN_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrdelprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(DELPRN_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrsaveprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(SAVEPRN_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svrrestoreprn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);

    ret = __send_svr_pipe(RESTOREPRN_CMD, parsestate, pargs);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

typedef struct __enum_dir {
    FILE* m_fp;
    char* m_lastdir;
    int m_indent;
    int m_depth;
} enum_dir_t, *penum_dir_t;

int __print_directory(char* basedir, char* curdir, char* curpat, void* arg)
{
#if 0
    REFERENCE_ARG(basedir);
    REFERENCE_ARG(curdir);
    REFERENCE_ARG(curpat);
    REFERENCE_ARG(arg);
    return 1;
#else
    int i, j;
    int curdepth = 0;
    char* pcurptr = NULL;
    int ret;

    penum_dir_t penum = (penum_dir_t) arg;
    if (penum->m_lastdir == NULL) {
        fprintf(penum->m_fp, "%s\n", basedir);
        penum->m_depth = 1;
    } else if (strcmp(penum->m_lastdir, curdir) != 0) {
        pcurptr = curdir + strlen(basedir);
        curdepth = 1;
        /*skip \ */
        pcurptr ++;
        while (1) {
            if ( pcurptr == NULL || *pcurptr == '\0') {
                break;
            }
            curdepth ++;
            pcurptr = strchr(pcurptr, '\\');
            if (pcurptr != NULL) {
                /*skip the \\ */
                pcurptr ++;
            }
        }
        penum->m_depth = curdepth;
    }

    for (i = 0; i < penum->m_depth; i++) {
        for (j = 0; j < penum->m_indent; j++) {
            fprintf(penum->m_fp, " ");
        }
    }
    fprintf(penum->m_fp, "%s\n", curpat);
    if (penum->m_lastdir) {
        free(penum->m_lastdir);
    }
    penum->m_lastdir = NULL;
    penum->m_lastdir = _strdup(curdir);
    if (penum->m_lastdir == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    return 1;
fail:
    SETERRNO(ret);
    return ret;
#endif
}

int enumdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    enum_dir_t enumdir;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* basedir = NULL;
    int ret;
    FILE* fp = stdout;


    memset(&enumdir, 0, sizeof(enumdir));
    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    if (pargs->m_output != NULL) {
        ret = fopen_s(&fp, pargs->m_output, "w");
        if (ret != 0) {
            GETERRNO(ret);
            ERROR_INFO("open %s error[%d]", pargs->m_output, ret);
            goto out;
        }
    }

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i++) {
        basedir = parsestate->leftargs[i];
        if (enumdir.m_lastdir) {
            free(enumdir.m_lastdir);
        }
        enumdir.m_lastdir = NULL;
        enumdir.m_depth = 0;
        enumdir.m_indent = 4;
        enumdir.m_fp = fp;

        ret = enumerate_directory(basedir, __print_directory, &enumdir);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("enumerate directory [%s] error[%d]", basedir, ret);
            goto out;
        }
    }

    ret = 0;
out:
    if (enumdir.m_lastdir) {
        free(enumdir.m_lastdir);
    }
    enumdir.m_lastdir = NULL;

    if (fp != stdout && fp != NULL) {
        fclose(fp);
    }
    fp = NULL;
    SETERRNO(ret);
    return ret;
}

int format_md5_digest(pmd5_state_t p, char* fmt, int size)
{
    char* pcur = fmt;
    int leftlen = size;
    int ret;
    int i;
    unsigned char* pc;

    for (i = 0; i < 4; i++) {
        pc = (unsigned char*) & (p->state[i]);
        ret = snprintf(pcur, (size_t)leftlen, "%02x%02x%02x%02x", pc[0], pc[1], pc[2], pc[3]);
        if (ret < 0 || ret >= (leftlen - 1)) {
            return -1;
        }
        pcur += ret;
        leftlen -= ret;
    }
    return 0;
}

int md5sum_file(char* fname, uint64_t size, char* digest, int digsize)
{
    void* pf = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    uint64_t fsize = 0;
    int overed = 0;
    uint64_t cursize;
    md5_state_t s;
    unsigned char bufdig[70];
    int ret;

    bufsize = 1024 * 1024;
    pbuf = (char*)malloc((size_t)bufsize);
    if (pbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }


    pf = open_file(fname, READ_MODE);
    if (pf == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    fsize = get_file_size(pf);
    cursize = 0;
    init_md5_state(&s);
    while (cursize < size || size == 0) {
        buflen = bufsize;
        if ((uint64_t)buflen > (fsize - cursize)) {
            buflen = (int) (fsize - cursize);
        }
        DEBUG_BUFFER_FMT(pbuf, (buflen > 0x20 ? 0x20 : buflen), "[%s] at [0x%llx]", fname, cursize);
        ret = read_file(pf, cursize, pbuf, (uint32_t)buflen);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        md5sum((unsigned char*)pbuf, (unsigned int) buflen, bufdig, &s);
        cursize += buflen;
        if (cursize == fsize) {
            overed = 1;
            break;
        }
    }

    if (overed == 0 || (buflen & 0x3f) == 0) {
        md5sum((unsigned char*)pbuf, (unsigned int)0, bufdig, &s);
    }

    format_md5_digest(&s, digest, digsize);

    if (pbuf) {
        free(pbuf);
    }
    close_file(&pf);

    return overed;
fail:
    if (pbuf) {
        free(pbuf);
    }
    close_file(&pf);
    SETERRNO(ret);
    return ret;
}

int md5sum_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    char* fname;
    char digest[64];
    int i;
    int ret;


    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        fname = parsestate->leftargs[i];
        ret = md5sum_file(fname, 0, digest, sizeof(digest));
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("calc [%s] error[%d]", fname, ret);
            goto out;
        }
        fprintf(stdout, "[%s] => [%s]\n", fname, digest);
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

typedef int (*m_enable_priv_func_t)(void);
typedef int (*m_disable_priv_func_t)(void);
typedef int (*m_get_priv_func_t)(void);

typedef struct __priv_funcs
{
    char* m_name;
    m_enable_priv_func_t m_enfunc;
    m_disable_priv_func_t m_disfunc;
    m_get_priv_func_t m_getfunc;
} priv_funcs_t, *ppriv_funcs_t;


static priv_funcs_t st_priv_funcs [] =
{
    {"security", enable_security_priv, disable_security_priv, is_security_priv},
    {"takeown", enable_takeown_priv, disable_takeown_priv, is_takeown_priv},
    {"restore", enable_restore_priv, disable_restore_priv, is_restore_priv},
    {"backup", enable_backup_priv, disable_backup_priv, is_backup_priv},
    {"impersonate", enable_impersonate_priv, disable_impersonate_priv, is_impersonate_priv},
    {"audit", enable_audit_priv, disable_audit_priv, is_audit_priv},
    {"debug", enable_debug_priv, disable_debug_priv, is_debug_priv},
    {"tcb", enable_tcb_priv, disable_tcb_priv, is_tcb_priv},
    {NULL, NULL, NULL, NULL}
};

ppriv_funcs_t __find_priv_funcs(char* name, ppriv_funcs_t plast)
{
    int i;
    if (name == NULL) {
        if (plast == NULL) {
            if (st_priv_funcs[0].m_name != NULL) {
                return &(st_priv_funcs[0]);
            }
            return NULL;
        }

        for (i = 0; st_priv_funcs[i].m_name != NULL; i++) {
            if (&(st_priv_funcs[i]) == plast) {
                if (st_priv_funcs[(i + 1)].m_name != NULL) {
                    return &(st_priv_funcs[i + 1]);
                }
            }
        }
        return NULL;
    }

    for (i = 0; st_priv_funcs[i].m_name; i++) {
        if (_stricmp(st_priv_funcs[i].m_name, name) == 0) {
            return &(st_priv_funcs[i]);
        }
    }
    return NULL;
}

int call_priv_func(ppriv_funcs_t privfunc, pargs_options_t pargs)
{
    int ret;
    int val;
    int enabled = 0;

    if (pargs->m_privenable) {
        ret = privfunc->m_enfunc();
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("enable [%s] error[%d]", privfunc->m_name, ret);
            goto fail;
        }
        enabled = 1;
    }

    ret = privfunc->m_getfunc();
    if ( ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get [%s] error[%d]", privfunc->m_name, ret);
        goto fail;
    }

    val = ret;

    if (pargs->m_privenable) {
        ret = privfunc->m_disfunc();
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("disable [%s] error[%d]", privfunc->m_name, ret);
            goto fail;
        }
        enabled = 0;
    }

    return val;
fail:
    if (enabled) {
        privfunc->m_disfunc();
        enabled = 0;
    }
    SETERRNO(ret);
    return ret;

}

int checkpriv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    pargs_options_t pargs = (pargs_options_t)popt;
    ppriv_funcs_t privfunc = NULL;
    int ret;
    char* privname;

    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    if (parsestate->leftargs == NULL || parsestate->leftargs[0] == NULL) {
        privfunc = NULL;
        while (1) {
            privfunc = __find_priv_funcs(NULL, privfunc);
            if (privfunc == NULL) {
                break;
            }
            ret = call_priv_func(privfunc, pargs);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            fprintf(stdout, "[%s]=[%d]\n", privfunc->m_name, ret);
        }
    }  else {
        for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
            privname = parsestate->leftargs[i];
            privfunc = __find_priv_funcs(privname, NULL);
            if (privfunc == NULL) {
                fprintf(stderr, "no [%s] found\n", privname);
                continue;
            }
            ret = call_priv_func(privfunc, pargs);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            fprintf(stdout, "[%s]=[%d]\n", privfunc->m_name, ret);
        }
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
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