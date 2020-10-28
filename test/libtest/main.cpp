

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
#include "set_acl.h"

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

int mktemp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
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
        for (i = 0; parsestate->leftargs[i] != NULL ; i++) {
            ret = mktempfile_safe(parsestate->leftargs[i], &templstr, &templsize);
            //ret = 0;
            if (ret < 0) {
                fprintf(stderr, "can not parse [%s] error(%d)\n", parsestate->leftargs[i], ret);
                goto out;
            }
            fprintf(stdout, "[%d]%s => %s\n", i, parsestate->leftargs[i], templstr);
        }
    }
out:
    get_temp_pipe_name(NULL, &templstr, &templsize);
    return ret;
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

int pidargv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char** ppargv = NULL;
    int argvsize = 0;
    int pid = -1;
    int ret = 0;
    int totalret = 0;
    int i, j;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            pid = atoi(parsestate->leftargs[i]);
            ret = get_pid_argv(pid, &ppargv, &argvsize);
            if (ret < 0) {
                fprintf(stderr, "can not get [%d] error[%d]\n", pid, ret);
                totalret = ret;
                continue;
            }
            for (j = 0; j < ret; j++) {
                fprintf(stdout, "[%d][%d]=[%s]\n", pid, j, ppargv[j]);
            }
        }
    }
    get_pid_argv(-1, &ppargv, &argvsize);
    return totalret;
}

int findwindow_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i, j;
    int pid = -1;
    int ret = 0;
    int totalret = 0;
    HWND* pwnd = NULL;
    pargs_options_t poption = (pargs_options_t) popt;
    argv = argv;
    argc = argc;
    int wndsize = 0;
    init_log_level(poption);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            pid = atoi(parsestate->leftargs[i]);
            ret = get_win_handle_by_classname(poption->m_classname, pid, &pwnd, &wndsize);
            if (ret < 0) {
                GETERRNO(ret);
                totalret = ret;
                fprintf(stderr, "can not get [%d] class[%s] error[%d]\n", pid, poption->m_classname, ret);
                continue;
            }
            fprintf(stdout, "get [%d] class [%s]:", pid, poption->m_classname);
            for (j = 0; j < ret; j++) {
                if ((j % 5) == 0) {
                    fprintf(stdout, "\n    ");
                }
                fprintf(stdout, " 0x%p", pwnd[j]);
            }
            fprintf(stdout, "\n");
        }

    } else {
        ret = get_win_handle_by_classname(poption->m_classname, -1, &pwnd, &wndsize);
        if (ret < 0) {
            GETERRNO(ret);
            totalret = ret;
            fprintf(stderr, "can not get [%s] on pid[%d] error[%d]\n", poption->m_classname, pid, ret);
            goto out;
        }
        fprintf(stdout, "get class [%s]:", poption->m_classname);
        for (j = 0; j < ret; j++) {
            if ((j % 5) == 0) {
                fprintf(stdout, "\n    ");
            }
            fprintf(stdout, " 0x%p", pwnd[j]);
        }
        fprintf(stdout, "\n");

    }

    ret = totalret;
out:
    get_win_handle_by_classname(NULL, -1, &pwnd, &wndsize);
    SETERRNO(-ret);
    return ret;
}

int fullpath_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pfullpath = NULL;
    int fullsize = 0;
    int i;
    pargs_options_t pargs = (pargs_options_t)popt;
    argv = argv;
    argc = argc;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i ++) {
            ret = get_full_path(parsestate->leftargs[i], &pfullpath, &fullsize);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
            fprintf(stdout, "[%d][%s] => [%s]\n", i, parsestate->leftargs[i], pfullpath);
        }
    }

    ret = 0;
out:
    get_full_path(NULL, &pfullpath, &fullsize);
    SETERRNO(-ret);
    return ret;
}

int winverify_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int totalret = 0;
    int ret;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs) {
        i = 0;
        while (parsestate->leftargs[i] != NULL) {
            ret = verify_windows_pe(parsestate->leftargs[i]);
            if (ret < 0) {
                GETERRNO(ret);
                totalret = ret;
                fprintf(stderr, "[%d] verify [%s] error[%d]\n", i, parsestate->leftargs[i], ret);
            } else {
                fprintf(stdout, "[%d]verify [%s] succ\n", i, parsestate->leftargs[i]);
            }
            i ++;
        }
    }

    SETERRNO(totalret);
    return totalret;
}

#define TYPE_PRINTF(type,stype)          \
do {                                     \
    if (pinfo->m_type & type) {          \
        if (typefp > 0) {                \
            fprintf(fp, "|");            \
        }                                \
        fprintf(fp, "%s", stype);        \
        typefp ++;                       \
    }                                    \
} while(0)

void debug_net_adapter(pnet_inter_info_t pinfo, FILE* fp, const char* fmt, ...)
{
    va_list ap;
    int typefp = 0;
    if (fmt != NULL) {
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        fprintf(fp, "\n");
    }

    fprintf(fp, "m_adaptername[%s]\n", pinfo->m_adaptername);
    fprintf(fp, "m_adapternickname[%s]\n", pinfo->m_adapternickname);
    fprintf(fp, "m_adapterip4[%s]\n", pinfo->m_adapterip4);
    fprintf(fp, "m_adapterip6[%s]\n", pinfo->m_adapterip6);
    fprintf(fp, "m_adaptermask4[%s]\n", pinfo->m_adaptermask4);
    fprintf(fp, "m_adaptermask6[%s]\n", pinfo->m_adaptermask6);
    fprintf(fp, "m_adaptergw[%s]\n", pinfo->m_adaptergw);
    fprintf(fp, "m_adapterdns[%s]\n", pinfo->m_adapterdns);
    fprintf(fp, "m_adaptermac[%s]\n", pinfo->m_adaptermac);
    fprintf(fp, "m_mtu[%d]\n", pinfo->m_mtu);

    fprintf(fp, "m_type ");
    TYPE_PRINTF(ETHER_NET, "ETHER_NET");
    TYPE_PRINTF(IP4_NET, "IP4_NET");
    TYPE_PRINTF(IP6_NET, "IP6_NET");
    if (typefp == 0) {
        fprintf(fp, "0");
    }
    fprintf(fp, "\n");
    return ;
}

int netinter_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pnet_inter_info_t pinfos = NULL;
    int infosize = 0;
    int i, j;
    int num;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);
    argc = argc;
    argv = argv;

    if (parsestate->leftargs == NULL) {
        ret = get_all_adapter_info(0, NULL, &pinfos, &infosize);
        if (ret < 0 ) {
            GETERRNO(ret);
            fprintf(stderr, "can not get adapter info error[%d]\n", ret);
            goto out;
        }
        num = ret;
        for (i = 0; i < num; i++) {
            debug_net_adapter(&(pinfos[i]), stdout, "[%d] adapter", i);
        }
    } else {
        for (i = 0; parsestate->leftargs[i] != NULL ; i ++) {
            ret = get_all_adapter_info(0, parsestate->leftargs[i], &pinfos, &infosize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "can not get adapter for [%s] error[%d]\n", parsestate->leftargs[i], ret);
                goto out;
            }
            num = ret;
            for (j = 0; j < num; j++) {
                debug_net_adapter(&(pinfos[j]), stdout, "[%d] adapter for [%s]", j, parsestate->leftargs[i]);
            }
        }
    }

    ret = 0;
out:
    get_all_adapter_info(1, NULL, &pinfos, &infosize);
    SETERRNO(ret);
    return ret;
}

int quote_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char* qstr = NULL;
    int qsize = 0;
    int i;

    argc = argc;
    argv = argv;
    popt = popt;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        ret = quote_string(&qstr, &qsize, parsestate->leftargs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "[%d][%s] quoted [%s]\n", i, parsestate->leftargs[i], qstr);
    }
    ret = 0;
out:
    quote_string(&qstr, &qsize, NULL);
    SETERRNO(ret);
    return ret;
}

void __debug_buf(FILE* fp, char* ptr, int size)
{
    int i, lasti;
    unsigned char* pcur = (unsigned char*)ptr;
    unsigned char* plast = pcur;

    for (i = 0; i < size; i++) {
        if ((i % 16) == 0) {
            if (i > 0) {
                fprintf(fp, "    ");
                while (plast != pcur) {
                    if (isprint((char) *plast)) {
                        fprintf(fp, "%c", *plast);
                    } else {
                        fprintf(fp, ".");
                    }
                    plast ++;
                }
                fprintf(fp, "\n");
            }
            fprintf(fp, "0x%08x:", i);
        }
        fprintf(fp, " 0x%02x", *pcur);
        pcur ++;
    }

    if (plast != pcur) {
        lasti = i;
        /*now we should give out*/
        while ((lasti % 16)) {
            fprintf(fp, "     ");
            lasti ++;
        }
        fprintf(fp, "    ");
        while (plast != pcur) {
            if (isprint((char) *plast)) {
                fprintf(fp, "%c", *plast);
            } else {
                fprintf(fp, ".");
            }
            plast ++;
        }
        fprintf(fp, "\n");
    }
    fflush(fp);
    return;
}

int runv_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int i;
    int ret;
    char** ppoutbuf = NULL;
    int *poutsize = NULL;
    char** pperrbuf = NULL;
    int *perrsize = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_whole(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        insize = ret;
    }

    if (pargs->m_output != NULL) {
        ppoutbuf = &outbuf;
        poutsize = &outsize;
    }

    if (pargs->m_errout != NULL) {
        pperrbuf = &errbuf;
        perrsize = &errsize;
    }

    ret = run_cmd_outputv(inbuf, insize, ppoutbuf, poutsize, pperrbuf, perrsize, &exitcode, pargs->m_timeout, parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run cmd [");
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", parsestate->leftargs[i]);
        }
        fprintf(stderr, "] error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "run cmd [");
    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        if (i > 0) {
            fprintf(stdout, ",");
        }
        fprintf(stdout, "%s", parsestate->leftargs[i]);
    }
    fprintf(stdout, "] succ\n");
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input --------------------\n");
        __debug_buf(stdout, inbuf, insize);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        __debug_buf(stdout, outbuf, outsize);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        __debug_buf(stdout, errbuf, errsize);
        fprintf(stdout, "errout ++++++++++++++++++++\n");
    }

    ret = 0;
out:
    run_cmd_outputv(NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_whole(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}

int runsingle_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int ret;
    char** ppoutbuf = NULL;
    int *poutsize = NULL;
    char** pperrbuf = NULL;
    int *perrsize = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_whole(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        insize = ret;
    }

    if (pargs->m_output != NULL) {
        ppoutbuf = &outbuf;
        poutsize = &outsize;
    }

    if (pargs->m_errout != NULL) {
        pperrbuf = &errbuf;
        perrsize = &errsize;
    }

    ret = run_cmd_output_single(inbuf, insize, ppoutbuf, poutsize, pperrbuf, perrsize, &exitcode, pargs->m_timeout, parsestate->leftargs[0]);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run single cmd [%s] error[%d]\n", parsestate->leftargs[0], ret);
        goto out;
    }

    fprintf(stdout, "run cmd [%s] succ\n", parsestate->leftargs[0]);
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input --------------------\n");
        __debug_buf(stdout, inbuf, insize);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        __debug_buf(stdout, outbuf, outsize);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        __debug_buf(stdout, errbuf, errsize);
        fprintf(stdout, "errout ++++++++++++++++++++\n");
    }

    ret = 0;
out:
    run_cmd_output_single(NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_whole(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}


int outc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    char* ptmpbuf = NULL;
    char* pinbuf = NULL;
    int insize = 0;
    int inlen = 0;
    char** ppllines = NULL;
    int lsize = 0;
    int llen = 0;
    argc = argc;
    argv = argv;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            fprintf(stderr, "stderr %s\n", parsestate->leftargs[i]);
            Sleep(1000);
            fprintf(stdout, "stdout %s\n", parsestate->leftargs[i]);
        }
    } else {

        insize = 1024;
        pinbuf = (char*) malloc((size_t)insize);
        if (pinbuf == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", insize, ret);
            goto out;
        }
        while (1) {
            ret = (int)fread(&(pinbuf[inlen]), 1, (size_t) (insize - inlen), stdin);
            if (ret < 0 ) {
                if (feof(stdin)) {
                    break;
                }
                GETERRNO(ret);
                ERROR_INFO("read [%d] error[%d]", inlen, ret);
                goto out;
            }

            inlen += ret;
            if (ret == 0) {
                break;
            }
            if (inlen >= insize) {
                insize <<= 1;
                ptmpbuf = (char*) malloc((size_t)insize);
                if (ptmpbuf == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", insize, ret);
                    goto out;
                }
                memset(ptmpbuf, 0, (size_t)insize);
                if (inlen > 0) {
                    memcpy(pinbuf, ptmpbuf, (size_t)inlen);
                }
                if (pinbuf) {
                    free(pinbuf);
                }
                pinbuf = ptmpbuf;
                ptmpbuf = NULL;
            }
        }

        ret = split_lines(pinbuf, &ppllines, &lsize);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        llen = ret;
        for (i = 0; i < llen; i++) {
            fprintf(stderr, "stderr %s\n", ppllines[i]);
            Sleep(1000);
            fprintf(stdout, "stdout %s\n", ppllines[i]);
        }
    }
    ret = 0;
out:
    split_lines(NULL, &ppllines, &lsize);
    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    if (pinbuf != NULL) {
        free(pinbuf);
    }
    pinbuf = NULL;
    insize = 0;
    inlen = 0;
    SETERRNO(ret);
    return ret;
}

int run_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pout = NULL;
    int outsize = 0;
    char* perr = NULL;
    int errsize = 0;
    int exitcode = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    parsestate = parsestate;
    init_log_level(pargs);


    ret = run_cmd_output(NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, "libtest.exe", "outc", "little", "big", NULL);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    if (exitcode != 0) {
        GETERRNO(ret);
        ERROR_INFO("exitcode %d", ret);
        goto out;
    }

    fprintf(stdout, "read stdout------------\n");
    fprintf(stdout, "%s", pout);
    fprintf(stdout, "++++++++++++++++++++++++++\n");
    fprintf(stdout, "read stderr------------\n");
    fprintf(stdout, "%s", perr);
    fprintf(stdout, "++++++++++++++++++++++++++\n");

    ret = 0;
out:
    run_cmd_output(NULL, 0, &pout, &outsize, &perr, &errsize, NULL, 0, NULL);
    SETERRNO(ret);
    return ret;
}

void __close_handle_note_2(HANDLE *phd, const char* fmt, ...)
{
    va_list ap;
    BOOL bret;
    char* errstr = NULL;
    int errsize = 0;
    int ret;
    int res;
    if (phd && *phd != INVALID_HANDLE_VALUE && *phd != NULL) {
        bret = CloseHandle(*phd);
        if (!bret && fmt != NULL) {
            GETERRNO(ret);
            va_start(ap, fmt);
            res = vsnprintf_safe(&errstr, &errsize, fmt, ap);
            if (res >= 0) {
                ERROR_INFO("%s error[%d]", errstr, ret);
            }
            vsnprintf_safe(&errstr, &errsize, NULL, ap);
        }
        *phd = INVALID_HANDLE_VALUE;
    }
    return;
}


#define MIN_BUF_SIZE    0x400

int __create_pipe_2(char* name , int wr, HANDLE *ppipe, OVERLAPPED* pov, HANDLE *pevt, int *pstate)
{
    int ret;
    int res;
    BOOL bret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    DWORD omode = 0;
    DWORD pmode = 0;
    if (name == NULL) {
        if ( ppipe != NULL && *ppipe != NULL &&
                *ppipe != INVALID_HANDLE_VALUE && pov != NULL) {
            if (pstate && (*pstate != PIPE_NONE && *pstate != PIPE_READY)) {
                bret = CancelIoEx(*ppipe, pov);
                if (!bret) {
                    GETERRNO(res);
                    ERROR_INFO("cancel io error[%d] at state [%d]", res, *pstate);
                }
            }
        }

        if (ppipe != NULL && *ppipe != NULL &&
                *ppipe != INVALID_HANDLE_VALUE &&
                pstate != NULL &&
                (*pstate == PIPE_WAIT_READ && *pstate == PIPE_WAIT_WRITE )) {
            bret = DisconnectNamedPipe(*ppipe);
            if (!bret) {
                GETERRNO(res);
                ERROR_INFO("disconnect error[%d]", res);
            }
        }
        __close_handle_note_2(pevt, "event close");
        __close_handle_note_2(ppipe, "pipe close");
        if (pov != NULL) {
            memset(pov, 0 , sizeof(*pov));
        }
        return 0;
    }

    if (ppipe == NULL || pevt == NULL || pov == NULL || pstate == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (*ppipe != NULL || *pevt != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    *pstate = PIPE_NONE;
    *pevt = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (*pevt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not create event for[%s] error[%d]", name, ret);
        goto fail;
    }

    memset(pov, 0 , sizeof(*pov));
    pov->hEvent = *pevt;

    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (wr) {
        omode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        pmode = PIPE_TYPE_MESSAGE | PIPE_WAIT;
    } else {
        omode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        pmode = PIPE_TYPE_MESSAGE  | PIPE_WAIT;
    }

    DEBUG_INFO("create %s [%s]", wr ? "write" : "read", name);

    *ppipe = CreateNamedPipe(ptname, omode, pmode, 1, MIN_BUF_SIZE * sizeof(TCHAR), MIN_BUF_SIZE * sizeof(TCHAR), 5000, NULL);
    if (*ppipe == NULL ||
            *ppipe == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("create [%s] for %s error[%d]", name, wr ? "write" : "read", ret);
        goto fail;
    }


    bret = ConnectNamedPipe(*ppipe, pov);
    if (!bret) {
        GETERRNO(ret);
        if (ret != -ERROR_IO_PENDING && ret != -ERROR_PIPE_CONNECTED) {
            ERROR_INFO("connect [%s] for %s error[%d]", name, wr ? "write" : "read", ret);
            goto fail;
        }
        if (ret == -ERROR_IO_PENDING) {
            DEBUG_INFO("[%s] connect pending" , name);
            *pstate = PIPE_WAIT_CONNECT;
        } else {
            *pstate = PIPE_READY;
        }
    } else {
        /*ok so we got ready*/
        *pstate = PIPE_READY;
    }


    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    AnsiToTchar(NULL, &ptname, &tnamesize);
    __close_handle_note_2(pevt, "%s event", name);
    __close_handle_note_2(ppipe, "%s server pipe", name);
    memset(pov, 0, sizeof(*pov));
    SETERRNO(ret);
    return ret;
}

#define LEAST_UNIQ_NUM    50

int __get_temp_pipe_name_2(char* prefix, char** pptmp, int *psize)
{
    TCHAR* tmpdirbuf = NULL;
    size_t tmpdirsize = 0, tmpdirlen;
    TCHAR* ptprefix = NULL;
    int prefixsize = 0;
    TCHAR* tmpfilebuf = NULL;
    size_t tmpfilesize = 0, tmpfilelen;

    int ret, nlen;
    DWORD dret;
    UINT uniq, uret;
    TCHAR* prealname = NULL;
    TCHAR* pcmpname = NULL;


    if (prefix == NULL) {
        if (pptmp && *pptmp && psize) {
            TcharToAnsi(NULL, pptmp, psize);
        }
        return 0;
    }

    ret = AnsiToTchar(prefix, &ptprefix, &prefixsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    tmpdirsize = 1024 * sizeof(TCHAR);
    tmpfilesize = 1024 * sizeof(TCHAR);
try_again:
    if (tmpdirbuf != NULL) {
        free(tmpdirbuf);
    }
    tmpdirbuf = NULL;
    tmpdirbuf = (TCHAR*) malloc(tmpdirsize);
    if (tmpdirbuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tmpdirsize, ret);
        goto fail;
    }
    memset(tmpdirbuf, 0 , tmpdirsize);
    dret = GetTempPath((DWORD)(tmpdirsize / sizeof(TCHAR)), tmpdirbuf);
    if (dret == 0) {
        GETERRNO(ret);
        ERROR_INFO("get temp path error[%d]", ret);
        goto fail;
    } else if (dret >= (tmpdirsize / sizeof(TCHAR))) {
        tmpdirsize <<= 1;
        goto try_again;
    }

    if (tmpfilebuf != NULL) {
        free(tmpfilebuf);
    }
    tmpfilebuf = NULL;
    tmpfilebuf = (TCHAR*) malloc(tmpfilesize);
    if (tmpfilebuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tmpfilesize , ret);
        goto fail;
    }
    tmpdirlen = _tcslen(tmpdirbuf);
    if (tmpfilesize < ((tmpdirlen + LEAST_UNIQ_NUM + strlen(prefix)) * sizeof(TCHAR))) {
        tmpfilesize = ((tmpdirlen + LEAST_UNIQ_NUM + strlen(prefix)) * sizeof(TCHAR));
        goto try_again;
    }
    memset(tmpfilebuf, 0 , tmpfilesize);
    //uniq = (UINT)(LEAST_UNIQ_NUM + strlen(prefix));
    uniq = 0;

    uret = GetTempFileName(tmpdirbuf, ptprefix, uniq, tmpfilebuf);
    if (uret == 0) {
        GETERRNO(ret);
        ERROR_INFO("get temp file name error[%s]", ret);
        goto fail;
    }

    prealname = tmpfilebuf;
    pcmpname = tmpdirbuf;
    while (*prealname == *pcmpname) {
        prealname ++;
        pcmpname ++;
    }

    while ( *prealname == __TEXT('\\')) {
        prealname ++;
    }

    tmpdirlen = _tcslen(tmpdirbuf);
    tmpfilelen = _tcslen(tmpfilebuf);
    DEBUG_BUFFER_FMT(tmpdirbuf, (int)((tmpdirlen + 1) * sizeof(TCHAR)), NULL);
    DEBUG_BUFFER_FMT(tmpfilebuf, (int)((tmpfilelen + 1) * sizeof(TCHAR)), NULL);

    DEBUG_INFO("tmpfilebuf %p prealname %p", tmpfilebuf, prealname);

    ret = TcharToAnsi(prealname, pptmp, psize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    nlen = ret;
    if (tmpdirbuf != NULL) {
        free(tmpdirbuf);
    }
    tmpdirbuf = NULL;
    tmpdirsize = 0;
    if (tmpfilebuf != NULL) {
        free(tmpfilebuf);
    }
    tmpfilebuf = NULL;
    tmpfilesize = 0;
    AnsiToTchar(NULL, &ptprefix, &prefixsize);
    return nlen;
fail:
    if (tmpdirbuf != NULL) {
        free(tmpdirbuf);
    }
    tmpdirbuf = NULL;
    tmpdirsize = 0;
    if (tmpfilebuf != NULL) {
        free(tmpfilebuf);
    }
    tmpfilebuf = NULL;
    tmpfilesize = 0;
    AnsiToTchar(NULL, &ptprefix, &prefixsize);
    SETERRNO(ret);
    return ret;
}


int svrlap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    HANDLE svrpipe = NULL;
    HANDLE evt = NULL;
    OVERLAPPED ov;
    int state = PIPE_NONE;
    int wr = 0;
    HANDLE waithds[1];
    DWORD waitnum;
    DWORD dret;
    char* poutbuf = NULL;
    size_t outsize = 0;
    size_t outlen = 0;
    char* pinbuf = NULL;
    size_t insize = 0;
    size_t inlen = 0;
    DWORD wtime;
    pargs_options_t pargs = (pargs_options_t) popt;
    uint64_t sticks = 0, cticks = 0;
    DWORD cbret;
    char* pipename = NULL;
    char* ptmpbuf = NULL;
    BOOL bret;
    char* pipebasename = NULL;
    int pipebasesize = 0;
    char* tmppipe = NULL;
    int tmppipesize = 0;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (pargs->m_input != NULL) {
        wr = 1;
        ret = read_file_whole(pargs->m_input, &poutbuf, (int*)&outsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
    }

    if (parsestate->leftargs != NULL && parsestate->leftargs[0] != NULL) {
        pipename = parsestate->leftargs[0];
    } else {
        ret = __get_temp_pipe_name_2("pipe", &pipebasename, &pipebasesize);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }

        ret = snprintf_safe(&tmppipe, &tmppipesize, "\\\\.\\pipe\\%s", pipebasename);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "create pipe %s\n", tmppipe);
        pipename = tmppipe;
    }


    ret = __create_pipe_2(pipename, wr, &svrpipe, &ov, &evt, &state);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "create %s error[%d]\n", pipename, ret);
        goto out;
    }

    if (pargs->m_timeout > 0) {
        sticks = get_current_ticks();
    }

    if (wr == 0) {
        insize = MIN_BUF_SIZE;
        pinbuf = (char*) malloc(insize);
        if (pinbuf == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "alloc %zu error[%d]\n", insize, ret);
            goto out;
        }
        memset(pinbuf, 0, insize);
    }

    while (1) {
        waitnum = 0;
        memset(waithds, 0 , sizeof(waithds));
        if (state == PIPE_WAIT_CONNECT) {
            waithds[0] = evt;
            waitnum ++;
        } else if (wr && state == PIPE_WAIT_WRITE) {
            waithds[0] = evt;
            waitnum ++;
        } else if (wr == 0 && state == PIPE_WAIT_READ) {
            waithds[0] = evt;
            waitnum ++;
        }

        if (waitnum > 0) {
            wtime = INFINITE;
            if (pargs->m_timeout > 0) {
                cticks = get_current_ticks();
                ret = need_wait_times(sticks, cticks, pargs->m_timeout);
                if (ret < 0) {
                    ret = -WAIT_TIMEOUT;
                    ERROR_INFO("wait [%s] timedout", pipename);
                    goto out;
                }
                wtime = (DWORD)ret;
            }
            dret = WaitForMultipleObjectsEx(waitnum, waithds, FALSE, wtime, FALSE);
            if (dret != WAIT_OBJECT_0) {
                GETERRNO(ret);
                ERROR_INFO("wait [%s] ret[%ld] error[%d]", pipename, dret, ret);
                goto out;
            }
        }

        if (state == PIPE_WAIT_CONNECT) {
            DEBUG_INFO("%s connect", pipename);
            state = PIPE_READY;
        }

        if (state == PIPE_WAIT_READ) {
            /*ok this is for the */
            bret = GetOverlappedResult(svrpipe, &(ov), &cbret, FALSE);
            if (!bret) {
                GETERRNO(ret);
                if (ret != -ERROR_IO_PENDING && ret != -ERROR_MORE_DATA && ret != -ERROR_BROKEN_PIPE) {
                    ERROR_INFO("read [%s] at [%zu] error[%d]", pipename, inlen, ret);
                    goto out;
                }
                if (ret == -ERROR_BROKEN_PIPE) {
                    state = PIPE_READY;
                    break;
                }

                if (ret == -ERROR_MORE_DATA) {
                    inlen += cbret;
                    if (inlen > insize) {
                        ERROR_INFO("cbret [%d]", cbret);
                        inlen = insize;
                    }
                    DEBUG_INFO("inlen [%zu] insize[%zu]", inlen, insize);
                    if (inlen == insize) {
                        state = PIPE_READY;
                    }
                }
            } else {
                inlen += cbret;
                if (inlen > insize) {
                    ERROR_INFO("cbret [%d]", cbret);
                    inlen = insize;
                }
                DEBUG_INFO("inlen [%zu] insize[%zu] cbret[%d]", inlen, insize, cbret);
                if (inlen == insize) {
                    state = PIPE_READY;
                }
            }
        }

        if (state == PIPE_WAIT_WRITE) {
            bret = GetOverlappedResult(svrpipe, &(ov), &cbret, FALSE);
            if (!bret) {
                GETERRNO(ret);
                if (ret != -ERROR_IO_PENDING) {
                    ERROR_INFO("write [%s] [%zu] error[%d]", pipename, outlen, ret);
                    goto out;
                }
                outlen += cbret;
                if (outlen > outsize) {
                    ERROR_INFO("ret [%d] cbret [%d] outlen [%zu] outsize[%zu]", ret, cbret, outlen, outsize);
                    outlen = outsize;
                }
            } else {
                outlen += cbret;
                if (outlen > outsize) {
                    ERROR_INFO("cbret [%d] outlen [%zu] outsize[%zu]", cbret, outlen, outsize);
                    outlen = outsize;
                }
            }


            DEBUG_INFO("outlen [%zu] outsize [%zu]", outlen, outsize);
            if (outlen == outsize) {
                /*that is all ok so break*/
                break;
            }
        }

        if (state == PIPE_READY) {
            if (wr) {
                bret = WriteFile(svrpipe, &(poutbuf[outlen]), (DWORD)(outsize - outlen), &cbret, &(ov));
                if (!bret) {
                    GETERRNO(ret);
                    if (ret != -ERROR_IO_PENDING) {
                        ERROR_INFO("write [%s] [%zu] error[%d]", pipename, outlen, ret);
                        goto out;
                    }
                    state = PIPE_WAIT_WRITE;
                } else {
                    outlen += cbret;
                    if (outlen > outsize) {
                        ERROR_INFO("cbret [%d] outlen[%zu] outsize[%zu]", cbret, outlen, outsize);
                        outlen = outsize;
                    }
                }
                if (outlen == outsize) {
                    /*all writed ,so out*/
                    break;
                }
            } else {
                if (inlen == insize) {
                    insize <<= 1;
                    ptmpbuf = (char*) malloc(insize);
                    if (ptmpbuf == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc %zu error[%d]", insize, ret);
                        goto out;
                    }
                    memset(ptmpbuf, 0 , insize);
                    if (inlen > 0) {
                        memcpy(ptmpbuf, pinbuf, inlen);
                    }

                    if (pinbuf) {
                        free(pinbuf);
                    }
                    pinbuf = NULL;
                    pinbuf = ptmpbuf;
                    ptmpbuf = NULL;
                }

                bret = ReadFile(svrpipe, &(pinbuf[inlen]), (DWORD)(insize - inlen), &cbret, &(ov));
                if (!bret) {
                    GETERRNO(ret);
                    if (ret != -ERROR_IO_PENDING && ret != -ERROR_BROKEN_PIPE) {
                        ERROR_INFO("read [%s] [%zu] error[%d]", pipename, inlen, ret);
                        goto out;
                    }

                    if (ret == -ERROR_BROKEN_PIPE) {
                        state = PIPE_READY;
                        break;
                    }
                    state = PIPE_WAIT_READ;
                } else {
                    inlen += cbret;
                    if (inlen > insize) {
                        ERROR_INFO("cbret [%d] inlen[%zu] insize[%zu]", cbret, inlen, insize);
                        inlen = insize;
                    }
                }
            }
        }
    }

    if (wr == 0) {
        fprintf(stdout, "read [%s] --------------------\n", pipename);
        __debug_buf(stdout, pinbuf, (int)inlen);
        fprintf(stdout, "read [%s] ++++++++++++++++++++\n", pipename);
    }
    ret = 0;
out:

    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    if (pinbuf != NULL) {
        free(pinbuf);
    }
    pinbuf = NULL;
    insize = 0;

    read_file_whole(NULL, &poutbuf, (int*)&outsize);
    __create_pipe_2(NULL, 0, &svrpipe, &ov, &evt, &state);
    snprintf_safe(&tmppipe, &tmppipesize, NULL);
    __get_temp_pipe_name_2(NULL, &pipebasename, &pipebasesize);
    SETERRNO(ret);
    return ret;
}

int __connect_pipe_2(char* name, int wr, HANDLE* pcli)
{
    int ret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    HANDLE phd = NULL;
    BOOL bret;
    DWORD omode;

    if (name == NULL) {
        if (pcli) {
            if (*pcli != NULL &&
                    *pcli != INVALID_HANDLE_VALUE) {
                bret = CloseHandle(*pcli);
                if (!bret) {
                    GETERRNO(ret);
                    ERROR_INFO("close handle error[%d]", ret);
                }
            }
            *pcli = NULL;
        }
        return 0;
    }

    if (pcli == NULL || (*pcli != NULL && *pcli != INVALID_HANDLE_VALUE )) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (wr) {
        omode = GENERIC_WRITE;
    } else {
        omode = GENERIC_READ;
    }

    phd = CreateFile(ptname, omode, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (phd == INVALID_HANDLE_VALUE) {
        GETERRNO(ret);
        ERROR_INFO("open file [%s] error[%d]", name, ret);
        goto fail;
    }

    *pcli = phd;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    if (phd != NULL) {
        CloseHandle(phd);
    }
    phd = NULL;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return ret;
}

int clilap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* pipename = NULL;
    HANDLE hd = INVALID_HANDLE_VALUE;
    int wr = 0;
    DWORD cbret;
    char* poutbuf = NULL;
    int outsize = 0;
    int outlen = 0;
    char* pinbuf = NULL;
    char* ptmpbuf = NULL;
    int insize = 1024;
    int inlen = 0;
    BOOL bret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("no pipe name");
        goto out;
    }

    pipename = parsestate->leftargs[0];
    wr = 0;
    if (pargs->m_input != NULL) {
        wr = 1;
        ret = read_file_whole(pargs->m_input, &poutbuf, &outsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("read file [%s] error[%d]", pargs->m_input, ret);
            goto out;
        }
    }

    ret = __connect_pipe_2(pipename, wr, &(hd));
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("client [%s] for %s error[%d]", pipename, wr ? "write" : "read", ret);
        goto out;
    }

    if (wr) {
        while (outlen < outsize) {
            bret = WriteFile(hd, &(poutbuf[outlen]), (DWORD)(outsize - outlen), &cbret, NULL);
            if (!bret) {
                GETERRNO(ret);
                if (ret != -ERROR_IO_PENDING) {
                    ERROR_INFO("write [%s] [%d] error[%d]", pipename, outlen, ret);
                    goto out;
                }
                continue;
            }
            outlen += cbret;
        }
    } else {
        pinbuf = (char*) malloc((size_t)insize);
        if (pinbuf == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", insize, ret);
            goto out;
        }
        while (1) {
            bret = ReadFile(hd, &(pinbuf[inlen]), (DWORD)(insize - inlen), &cbret, NULL);
            if (!bret) {
                GETERRNO(ret);
                if (ret != -ERROR_IO_PENDING && ret != -ERROR_BROKEN_PIPE) {
                    ERROR_INFO("read [%s] [%d] error[%d]", pipename, inlen, ret);
                    goto out;
                }
                if (ret == -ERROR_BROKEN_PIPE) {
                    break;
                }
                continue;
            }
            inlen += cbret;
            if (inlen >= insize) {
                inlen = insize;
                insize <<= 2;
                ptmpbuf = (char*) malloc((size_t)insize);
                if (ptmpbuf == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", insize, ret);
                    goto out;
                }
                memset(ptmpbuf, 0, (size_t)insize);
                if (inlen > 0) {
                    memcpy(ptmpbuf, pinbuf, (size_t)inlen);
                }
                if (pinbuf) {
                    free(pinbuf);
                }
                pinbuf = ptmpbuf;
                ptmpbuf = NULL;
            }
        }

        fprintf(stdout, "read [%s] ------------------------\n", pipename);
        __debug_buf(stdout, pinbuf, inlen);
        fprintf(stdout, "read [%s] ++++++++++++++++++++++++\n", pipename);
    }

    ret = 0;
out:
    read_file_whole(NULL, &poutbuf, &outsize);
    if (pinbuf != NULL) {
        free(pinbuf);
    }
    pinbuf = NULL;
    insize = 0;
    inlen = 0;
    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    __connect_pipe_2(NULL, 0, &hd);
    SETERRNO(ret);
    return ret;
}


int sendmsg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    int cnt = 0;
    int idx = 0;
    HWND hwnd = NULL;
    UINT msg = 0;
    WPARAM wparam = 0;
    LPARAM lparam = 0;
    LRESULT lret;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (parsestate->leftargs != NULL) {
        for (cnt = 0; parsestate->leftargs[cnt] != NULL; cnt ++) {

        }
    }

    if (cnt < 4 || (cnt % 4) != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "sendmsg hwnd msg wparam lparam\n");
        goto out;
    }


    while (parsestate->leftargs[idx] != NULL) {
        GET_OPT_TYPE(hwnd, "get hwnd", HWND);
        GET_OPT_TYPE(msg, "get msg", UINT);
        GET_OPT_TYPE(wparam, "get wparam", WPARAM);
        GET_OPT_TYPE(lparam, "get lparam", LPARAM);

        lret = SendMessage(hwnd, msg, wparam, lparam);
#if _M_X64
        fprintf(stdout, "send [%p] msg[%d:0x%x] with wparam [%lld:0x%llx] lparam[%lld:0x%llx] ret[%lld]\n",
                hwnd, msg, msg,
                wparam, wparam,
                lparam, lparam, lret);
#else
        fprintf(stdout, "send [%p] msg[%d:0x%x] with wparam [%d:0x%x] lparam[%ld:0x%lx] ret[%ld]\n",
                hwnd, msg, msg,
                wparam, wparam,
                lparam, lparam, lret);
#endif
        if (pargs->m_timeout > 0) {
            SleepEx((DWORD)pargs->m_timeout, TRUE);
        }
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int getcompname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pcompname = NULL;
    int compnamesize = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int num;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    num = atoi(parsestate->leftargs[0]);
    if (num < 1 || num > 7) {
        ERROR_INFO("not valid type [%d]", num);
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }
    DEBUG_INFO("num %d", num);

    if (num & COMPUTER_NAME_DNS) {
        ret = get_computer_name(COMPUTER_NAME_DNS, &pcompname, &compnamesize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("error [%d]", ret);
            goto out;
        }
        fprintf(stdout, "DNS computer name [%s]\n", pcompname);
    }

    if (num & COMPUTER_NAME_NETBIOS) {
        ret = get_computer_name(COMPUTER_NAME_NETBIOS, &pcompname, &compnamesize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("error [%d]", ret);
            goto out;
        }
        fprintf(stdout, "NETBIOS computer name [%s]\n", pcompname);
    }

    if (num & COMPUTER_NAME_PHYS) {
        ret = get_computer_name(COMPUTER_NAME_PHYS, &pcompname, &compnamesize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("error [%d]", ret);
            goto out;
        }
        fprintf(stdout, "PHYS computer name [%s]\n", pcompname);
    }

    ret = 0;
out:
    get_computer_name(COMPUTER_NAME_NONE, &pcompname, &compnamesize);
    SETERRNO(ret);
    return ret;
}

int setcompname_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* compname = NULL;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int num;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    num = atoi(parsestate->leftargs[0]);
    compname = parsestate->leftargs[1];
    if (num < 1 || num > 7) {
        ERROR_INFO("not valid type [%d]", num);
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    if (num & COMPUTER_NAME_DNS) {
        ret = set_computer_name(COMPUTER_NAME_DNS, compname);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "set DNS compname [%s] succ\n", compname);
    }

    if (num & COMPUTER_NAME_NETBIOS) {
        ret = set_computer_name(COMPUTER_NAME_NETBIOS, compname);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "set NETBIOS compname [%s] succ\n", compname);
    }

    if (num & COMPUTER_NAME_PHYS) {
        ret = set_computer_name(COMPUTER_NAME_PHYS, compname);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        fprintf(stdout, "set PHYS compname [%s] succ\n", compname);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}


int regexec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* preg = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int argcnt = 0;
    int i, j, retlen;
    int *pstartpos = NULL, *pendpos = NULL;
    int possize = 0;
    int ret;
    char* pcurstr = NULL;
    char* pmatchstr = NULL;
    size_t matchsize = 0;
    size_t matchlen = 0;
    int handled = 0;

    argc = argc;
    argv = argv;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("arg must restr instr...");
        goto out;
    }

    ret = regex_compile(parsestate->leftargs[0], REGEX_NONE, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not compile [%s]", parsestate->leftargs[0]);
        goto out;
    }

    for (i = 1; i < argcnt; i++) {
        pcurstr = parsestate->leftargs[i];
        handled = 0;
try_again:
        ret = regex_exec(preg, pcurstr, &pstartpos, &pendpos, &possize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not exec [%s] for [%s] error[%d]", pcurstr, parsestate->leftargs[0], ret);
            goto out;
        }
        retlen = ret;
        if (retlen > 0) {
            fprintf(stdout, "[%s] find [%s]\n", parsestate->leftargs[0], pcurstr);
            for (j = 0; j < retlen; j++) {
                matchlen = (size_t)(pendpos[j] - pstartpos[j]);
                if (matchlen >= matchsize || pmatchstr == NULL) {
                    if (pmatchstr) {
                        free(pmatchstr);
                    }
                    pmatchstr = NULL;
                    matchsize = (matchlen + 3);
                    pmatchstr = (char*) malloc(matchsize);
                    if (pmatchstr == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc %d error[%d]", matchsize, ret);
                        goto out;
                    }
                }
                memset(pmatchstr, 0 , matchsize);
                memcpy(pmatchstr, &(pcurstr[pstartpos[j]]), matchlen);
                fprintf(stdout, "    [%03d] %s\n", j, pmatchstr);
            }
            /*we move to the next to find*/
            pcurstr = &(pcurstr[pendpos[0]]);
            handled ++;
            goto try_again;
        } else {
            if (handled == 0) {
                fprintf(stdout, "[%s] not find in [%s]\n", parsestate->leftargs[0], pcurstr);
            }
        }
    }

    ret = 0;
out:
    if (pmatchstr != NULL) {
        free(pmatchstr);
    }
    pmatchstr = NULL;
    matchsize = 0;
    regex_exec(NULL, NULL, &pstartpos, &pendpos, &possize);
    regex_compile(NULL, REGEX_NONE, &preg);
    SETERRNO(ret);
    return ret;
}

int iregexec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* preg = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int argcnt = 0;
    int i, j, retlen;
    int *pstartpos = NULL, *pendpos = NULL;
    int possize = 0;
    int ret;
    char* pcurstr = NULL;
    char* pmatchstr = NULL;
    size_t matchsize = 0;
    size_t matchlen = 0;

    argc = argc;
    argv = argv;
    init_log_level(pargs);
    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("arg must restr instr...");
        goto out;
    }

    ret = regex_compile(parsestate->leftargs[0], REGEX_IGNORE_CASE, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not compile [%s]", parsestate->leftargs[0]);
        goto out;
    }

    for (i = 1; i < argcnt; i++) {
        pcurstr = parsestate->leftargs[i];
        ret = regex_exec(preg, pcurstr, &pstartpos, &pendpos, &possize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not exec [%s] for [%s] error[%d]", pcurstr, parsestate->leftargs[0], ret);
            goto out;
        }
        retlen = ret;
        if (retlen > 0) {
            fprintf(stdout, "[%s] find [%s]\n", parsestate->leftargs[0], pcurstr);
            for (j = 0; j < retlen; j++) {
                matchlen = (size_t)(pendpos[j] - pstartpos[j]);
                if (matchlen >= matchsize || pmatchstr == NULL) {
                    if (pmatchstr) {
                        free(pmatchstr);
                    }
                    pmatchstr = NULL;
                    matchsize = (matchlen + 3);
                    pmatchstr = (char*) malloc(matchsize);
                    if (pmatchstr == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("alloc %d error[%d]", matchsize, ret);
                        goto out;
                    }
                }
                memset(pmatchstr, 0 , matchsize);
                memcpy(pmatchstr, &(pcurstr[pstartpos[j]]), matchlen);
                fprintf(stdout, "    [%03d] %s\n", j, pmatchstr);
            }
        } else {
            fprintf(stdout, "[%s] not find in [%s]\n", parsestate->leftargs[0], pcurstr);
        }
    }

    ret = 0;
out:
    if (pmatchstr != NULL) {
        free(pmatchstr);
    }
    pmatchstr = NULL;
    matchsize = 0;
    regex_exec(NULL, NULL, &pstartpos, &pendpos, &possize);
    regex_compile(NULL, REGEX_NONE, &preg);
    SETERRNO(ret);
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


int runevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pout = NULL;
    int outsize = 0;
    char* perr = NULL;
    int errsize = 0;
    int exitcode = 0;
    BOOL bret;
    int res;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    parsestate = parsestate;
    init_log_level(pargs);

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


    ret = run_cmd_event_output(st_ExitEvt, NULL, 0, &pout, &outsize, &perr, &errsize, &exitcode, 0, "libtest.exe", "outc", "little", "big", NULL);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    if (exitcode != 0) {
        GETERRNO(ret);
        ERROR_INFO("exitcode %d", ret);
        goto out;
    }

    fprintf(stdout, "read stdout------------\n");
    fprintf(stdout, "%s", pout);
    fprintf(stdout, "++++++++++++++++++++++++++\n");
    fprintf(stdout, "read stderr------------\n");
    fprintf(stdout, "%s", perr);
    fprintf(stdout, "++++++++++++++++++++++++++\n");

    ret = 0;
out:
    if (st_ExitEvt != NULL && st_ExitEvt != INVALID_HANDLE_VALUE) {
        bret = CloseHandle(st_ExitEvt);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("can not close[%p] error[%d]", st_ExitEvt, res);
        }
    }
    st_ExitEvt = NULL;
    run_cmd_event_output(st_ExitEvt, NULL, 0, &pout, &outsize, &perr, &errsize, NULL, 0, NULL);
    SETERRNO(ret);
    return ret;
}

int runvevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int i;
    int ret;
    char** ppoutbuf = NULL;
    int *poutsize = NULL;
    char** pperrbuf = NULL;
    int *perrsize = NULL;
    BOOL bret;
    int res;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

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


    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_whole(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        insize = ret;
    }

    if (pargs->m_output != NULL) {
        ppoutbuf = &outbuf;
        poutsize = &outsize;
    }

    if (pargs->m_errout != NULL) {
        pperrbuf = &errbuf;
        perrsize = &errsize;
    }

    ret = run_cmd_event_outputv(st_ExitEvt, inbuf, insize, ppoutbuf, poutsize, pperrbuf, perrsize, &exitcode, pargs->m_timeout, parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run cmd [");
        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            if (i > 0) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", parsestate->leftargs[i]);
        }
        fprintf(stderr, "] error[%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "run cmd [");
    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        if (i > 0) {
            fprintf(stdout, ",");
        }
        fprintf(stdout, "%s", parsestate->leftargs[i]);
    }
    fprintf(stdout, "] succ\n");
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input --------------------\n");
        __debug_buf(stdout, inbuf, insize);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        __debug_buf(stdout, outbuf, outsize);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        __debug_buf(stdout, errbuf, errsize);
        fprintf(stdout, "errout ++++++++++++++++++++\n");
    }

    ret = 0;
out:
    if (st_ExitEvt != NULL && st_ExitEvt != INVALID_HANDLE_VALUE) {
        bret = CloseHandle(st_ExitEvt);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("can not close[%p] error[%d]", st_ExitEvt, res);
        }
    }
    st_ExitEvt = NULL;
    run_cmd_event_outputv(st_ExitEvt, NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_whole(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}

int runsevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* inbuf = NULL;
    int insize = 0;
    char* outbuf = NULL;
    int outsize = 0;
    char* errbuf = NULL;
    int errsize = 0;
    int exitcode;
    int ret;
    char** ppoutbuf = NULL;
    int *poutsize = NULL;
    char** pperrbuf = NULL;
    int *perrsize = NULL;
    BOOL bret;
    int res;
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);

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

    argc = argc;
    argv = argv;
    if (pargs->m_input != NULL) {
        ret = read_file_whole(pargs->m_input, &inbuf, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        insize = ret;
    }

    if (pargs->m_output != NULL) {
        ppoutbuf = &outbuf;
        poutsize = &outsize;
    }

    if (pargs->m_errout != NULL) {
        pperrbuf = &errbuf;
        perrsize = &errsize;
    }

    ret = run_cmd_event_output_single(st_ExitEvt, inbuf, insize, ppoutbuf, poutsize, pperrbuf, perrsize, &exitcode, pargs->m_timeout, parsestate->leftargs[0]);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run single cmd [%s] error[%d]\n", parsestate->leftargs[0], ret);
        goto out;
    }

    fprintf(stdout, "run cmd [%s] succ\n", parsestate->leftargs[0]);
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input --------------------\n");
        __debug_buf(stdout, inbuf, insize);
        fprintf(stdout, "input ++++++++++++++++++++\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output --------------------\n");
        __debug_buf(stdout, outbuf, outsize);
        fprintf(stdout, "output ++++++++++++++++++++\n");
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout --------------------\n");
        __debug_buf(stdout, errbuf, errsize);
        fprintf(stdout, "errout ++++++++++++++++++++\n");
    }

    ret = 0;
out:
    if (st_ExitEvt != NULL && st_ExitEvt != INVALID_HANDLE_VALUE) {
        bret = CloseHandle(st_ExitEvt);
        if (!bret) {
            GETERRNO(res);
            ERROR_INFO("can not close[%p] error[%d]", st_ExitEvt, res);
        }
    }
    st_ExitEvt = NULL;
    run_cmd_event_output_single(st_ExitEvt, NULL, 0, &outbuf, &outsize, &errbuf, &errsize, &exitcode, -1, NULL);
    read_file_whole(NULL, &inbuf, &insize);
    SETERRNO(ret);
    return ret;
}

int getcp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int cp = 0;
    int ret = 0;

    argc = argc;
    argv = argv;
    popt = popt;
    parsestate = parsestate;

    cp = get_codepage();
    if (cp < 0) {
        ret = cp;
        fprintf(stderr, "can not get code page error[%d]\n", ret);
        goto out;
    }
    fprintf(stdout, "code page [%d]\n", cp);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int setcp_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int cp = 437;
    int idx = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        fprintf(stderr, "no codepage specified\n");
        ret = -ERROR_INVALID_PARAMETER;
    }

    GET_OPT_INT(cp, "code page");
    ret = set_codepage(cp);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not set code page [%d] error[%d]\n", cp, ret);
        goto out;
    }
    fprintf(stdout, "set code page[%d] succ\n", cp);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int existsvc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int i;
    int ret;
    char* svcname = NULL;
    int exist = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);
    argv = argv;
    argc = argc;

    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i] != NULL ; i++) {
            svcname = parsestate->leftargs[i];
            exist = is_service_exist(svcname);
            if (exist < 0) {
                GETERRNO(ret);
                fprintf(stderr, "[%s] check error[%d]\n", svcname, ret );
                goto out;
            }
            fprintf(stdout, "%s %s\n", svcname, exist ? "exists" : "not exists" );
        }
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svcstate_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int i;
    char* name;
    char* mode;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);
    argc = argc ;
    argv = argv;

    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i]; i++) {
            name = parsestate->leftargs[i];
            ret = service_running_mode(name);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "%s can not get running mode [%d]", name, ret);
                goto out;
            }
            switch (ret) {
            case SVC_STATE_UNKNOWN:
                mode = "unknown";
                break;
            case SVC_STATE_STOPPED:
                mode = "stopped";
                break;
            case SVC_STATE_START_PENDING:
                mode = "start pending";
                break;
            case SVC_STATE_RUNNING:
                mode = "running";
                break;
            case SVC_STATE_STOP_PENDING:
                mode = "stop pending";
                break;
            case SVC_STATE_PAUSED:
                mode = "paused";
                break;
            case SVC_STATE_PAUSE_PENDING:
                mode = "pause pending";
                break;
            case SVC_STATE_CONTINUE_PENDING:
                mode = "continue pending";
                break;
            default:
                fprintf(stderr, "[%s] get state [%d]\n", name, ret);
                ret = -1;
                goto out;
            }
            fprintf(stdout, "%s mode %s\n", name, mode);
        }
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}
int svchdl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int cnt = 0;
    int ret;
    char* name = NULL;
    int i;
    char* action = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);
    argc = argc;
    argv = argv;

    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (cnt < 2) {
        fprintf(stderr, "need at least 2 args\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    action = parsestate->leftargs[0];

    if (strcmp(action, "start") == 0 || strcmp(action, "stop") == 0) {
    } else {
        fprintf(stderr, "not support handle [%s]\n", action);
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    for (i = 1; i < cnt; i++) {
        name = parsestate->leftargs[i];
        if (strcmp(action, "start") == 0) {
            ret = start_service(name, pargs->m_timeout);
        } else if (strcmp(action, "stop") == 0) {
            ret = stop_service(name, pargs->m_timeout);
        } else {
            ret = -ERROR_INVALID_PARAMETER;
        }

        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "%s %s failed error[%d]\n", action, name, ret);
            goto out;
        }
        fprintf(stdout, "%s %s succ\n", action, name);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int svcmode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int cnt = 0;
    char* mode = NULL;
    char* name = NULL;
    int modeset = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_level(pargs);
    argc = argc;
    argv = argv;


    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (cnt < 1) {
        fprintf(stderr, "need at least one arg\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }
    name = parsestate->leftargs[0];

    if (cnt == 1) {
        ret = get_service_start_mode(name);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not get [%s] start mode error[%d]\n", name, ret);
            goto out;
        }

        switch (ret) {
        case SVC_START_ON_UNKNOWN:
            mode = "unknown";
            break;
        case SVC_START_ON_BOOT:
            mode = "boot";
            break;
        case SVC_START_ON_SYSTEM:
            mode = "system";
            break;
        case SVC_START_ON_AUTO:
            mode = "auto";
            break;
        case SVC_START_ON_DEMAND:
            mode = "demand";
            break;
        case SVC_START_ON_DISABLED:
            mode = "disabled";
            break;
        default:
            fprintf(stderr, "[%s] start mode [%d] error\n", name, ret);
            ret = -ERROR_INTERNAL_ERROR;
            goto out;
        }
        fprintf(stdout, "[%s] start mode [%s]\n", name, mode);
    } else {
        mode = parsestate->leftargs[1];
        if (strcmp(mode , "boot") == 0) {
            modeset = SVC_START_ON_BOOT;
        } else if (strcmp(mode, "system") == 0) {
            modeset = SVC_START_ON_SYSTEM;
        } else if (strcmp(mode, "auto") == 0) {
            modeset = SVC_START_ON_AUTO;
        } else if (strcmp(mode, "demand") == 0) {
            modeset = SVC_START_ON_DEMAND;
        } else if (strcmp(mode, "disabled") == 0) {
            modeset = SVC_START_ON_DISABLED;
        } else {
            fprintf(stderr, "not supported start mode [%s]\n", mode);
            ret = - ERROR_INVALID_PARAMETER;
            goto out;
        }

        ret = config_service_start_mode(name, modeset);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%s] config start mode [%s] error[%d]\n", name, mode, ret);
            goto out;
        }
        fprintf(stdout, "[%s] config start mode [%s] succ\n", name , mode);
    }

    ret = 0;

out:
    SETERRNO(ret);
    return ret;
}

int regbinget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* pregop = NULL;
    int ret;
    int cnt = 0;
    char* path = NULL;
    char* property = NULL;
    void* pdata = NULL;
    int datasize = 0;
    int nret;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (cnt < 2) {
        fprintf(stderr, "at least path and property\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    path = parsestate->leftargs[0];
    property = parsestate->leftargs[1];

    pregop = open_hklm(path, ACCESS_KEY_READ);
    if (pregop == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] error[%d]", path, ret);
        goto out;
    }

    ret = query_hklm_binary(pregop, property, &pdata, &datasize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] property binary error[%d]\n", property, ret);
        goto out;
    }

    nret = ret;
    fprintf(stdout, "get [%s].[%s] data [%d]\n", path, property, nret);
    __debug_buf(stdout, (char*)pdata, nret);
    ret = 0;

out:
    query_hklm_binary(NULL, NULL, &pdata, &datasize);
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;
}
int regbinset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    void* pregop = NULL;
    int ret;
    int cnt = 0;
    char* path = NULL;
    char* property = NULL;
    unsigned char* pdata = NULL;
    unsigned char* ptmpdata = NULL;
    int datasize = 0;
    int datalen = 0;
    int curch = 0;
    int offset = 0;
    int idx;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (cnt < 4 || ((cnt - 2) % 2 != 0)) {
        fprintf(stderr, "at least path and property\n");
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    path = parsestate->leftargs[0];
    property = parsestate->leftargs[1];

    pregop = open_hklm(path, ACCESS_KEY_READ | ACCESS_KEY_WRITE);
    if (pregop == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "can not open [%s] error[%d]", path, ret);
        goto out;
    }

    ret = query_hklm_binary(pregop, property, (void**)&pdata, &datasize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] property binary error[%d]\n", property, ret);
        goto out;
    }

    datalen = ret;
    fprintf(stdout, "[%s].[%s] datalen[%d]\n", path, property, datalen);
    __debug_buf(stdout, (char*)pdata, datalen);
    idx = 2;
    while (idx < cnt) {
        GET_OPT_INT(offset, "offset");
        GET_OPT_INT(curch, "ch");

        if (offset >= datasize) {
            datasize = (offset + 1);
            ptmpdata = (unsigned char*)malloc((size_t)datasize);
            if (ptmpdata == NULL) {
                fprintf(stderr, "alloc %d error[%d]\n", datasize, ret);
                goto out;
            }
            memset(ptmpdata, 0, (size_t)datasize);
            if (datalen > 0) {
                memcpy(ptmpdata, pdata, (size_t)datalen);
            }
            if (pdata != NULL) {
                free(pdata);
            }
            pdata = ptmpdata;
            ptmpdata = NULL;
            datalen = datasize;
        }

        pdata[offset] = (unsigned char)curch;
    }

    fprintf(stdout, "[%s].[%s] set [%d]\n", path, property, datalen );
    __debug_buf(stdout, (char*)pdata, datalen);

    ret = set_hklm_binary(pregop, property, pdata, datalen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not set [%s].[%s] error[%d]\n", path, property, ret);
        goto out;
    }
    fprintf(stdout, "set success\n");
    ret = 0;
out:
    if (ptmpdata) {
        free(ptmpdata);
    }
    ptmpdata = NULL;
    query_hklm_binary(NULL, NULL, (void**)&pdata, &datasize);
    close_hklm(&pregop);
    SETERRNO(ret);
    return ret;
}


int winver_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    init_log_level(pargs);
    argc = argc;
    argv = argv;
    parsestate = parsestate;

    fprintf(stdout, "win7 %s\n", is_win7() ? "true" : "false");
    fprintf(stdout, "win10 %s\n", is_win10() ? "true" : "false");

    return 0;
}
int get_max_str(int a, const char* str)
{
    int b = 0;
    if (str != NULL) {
        b = (int)strlen(str);
    }
    if (a > b) {
        return a;
    }
    return b;
}



int getacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    int i, j;
    void* pacl = NULL;
    const char* fname;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* user = NULL;
    int usersize = 0;
    char* action = NULL;
    int actionsize = 0;
    char* right = NULL;
    int rightsize = 0;
    char* inherit = NULL;
    int inheritsize = 0;
    char* owner = NULL, *group = NULL;
    int ownersize = 0, grpsize = 0;
    int maxownersize = 0;
    int maxgroupsize = 0;
    int maxusersize = 0;
    int maxactionsize = 0;
    int maxrightsize = 0;
    int maxinheritsize = 0;
    int maxfilesize = 0;
    init_log_level(pargs);
    argc = argc;
    argv = argv;


    if (parsestate->leftargs) {
        ret = snprintf_safe(&user, &usersize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&action, &actionsize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&right, &rightsize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&inherit, &inheritsize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&owner, &ownersize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        ret = snprintf_safe(&group, &grpsize, " ");
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }

        for (i = 0; parsestate->leftargs[i] != NULL ; i++) {
            fname = parsestate->leftargs[i];
            maxfilesize = get_max_str(maxfilesize, fname);
            ret = get_file_acls(fname, &pacl);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%d][%s] acl error[%d]\n", i, fname, ret);
                goto out;
            }

            ret = get_file_owner(pacl, &owner, &ownersize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%s] owner error[%d]\n", fname, ret);
                goto out;
            }
            maxownersize = get_max_str(maxownersize, owner);

            ret = get_file_group(pacl, &group, &grpsize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%s] group error[%d]\n", fname, ret);
                goto out;
            }
            maxgroupsize = get_max_str(maxgroupsize, group);


            j = 0;
            while (1) {
                ret = get_sacl_user(pacl, j, &user, &usersize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl user error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxusersize = get_max_str(maxusersize, user);

                ret = get_sacl_action(pacl, j, &action, &actionsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl action with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl action error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxactionsize = get_max_str(maxactionsize, action);

                ret = get_sacl_right(pacl, j, &right, &rightsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl right with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl right error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxrightsize = get_max_str(maxrightsize, right);

                ret = get_sacl_inheritance(pacl, j, &inherit, &inheritsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl inherit with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl inherit error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxinheritsize = get_max_str(maxinheritsize, inherit);

                j ++;
            }
            j = 0;
            while (1) {
                ret = get_dacl_user(pacl, j, &user, &usersize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxusersize = get_max_str(maxusersize, user);

                ret = get_dacl_action(pacl, j, &action, &actionsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl action with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl action error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxactionsize = get_max_str(maxactionsize, action);

                ret = get_dacl_right(pacl, j, &right, &rightsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl right with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl right error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxrightsize = get_max_str(maxrightsize, right);

                ret = get_dacl_inheritance(pacl, j, &inherit, &inheritsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl inherit with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl inherit error[%d]\n", i, fname, ret);
                    goto out;
                }
                maxinheritsize = get_max_str(maxinheritsize, inherit);
                j ++;
            }
        }

        for (i = 0; parsestate->leftargs[i] != NULL; i++) {
            fname = parsestate->leftargs[i];
            ret = get_file_acls(fname, &pacl);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%d][%s] acl error[%d]\n", i, fname, ret);
                goto out;
            }

            ret = get_file_owner(pacl, &owner, &ownersize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%s] owner error[%d]\n", fname, ret);
                goto out;
            }


            ret = get_file_group(pacl, &group, &grpsize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "get [%s] group error[%d]\n", fname, ret);
                goto out;
            }


            j = 0;
            while (1) {
                ret = get_sacl_user(pacl, j, &user, &usersize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl user error[%d]\n", i, fname, ret);
                    goto out;
                }
                ret = get_sacl_action(pacl, j, &action, &actionsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl action with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl action error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_sacl_right(pacl, j, &right, &rightsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl right with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl right error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_sacl_inheritance(pacl, j, &inherit, &inheritsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get sacl inherit with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] sacl inherit error[%d]\n", i, fname, ret);
                    goto out;
                }

                fprintf(stdout, "[%03d][%03d]%-5s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n", i, j, "sacl",
                        maxfilesize + 1, fname, maxownersize + 1 , owner,
                        maxgroupsize + 1, group, maxusersize + 1, user,
                        maxactionsize + 1 , action, maxrightsize + 1 , right,
                        maxinheritsize + 1, inherit);

                j ++;
            }
            j = 0;
            while (1) {
                ret = get_dacl_user(pacl, j, &user, &usersize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_dacl_action(pacl, j, &action, &actionsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl action with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl action error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_dacl_right(pacl, j, &right, &rightsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl right with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl right error[%d]\n", i, fname, ret);
                    goto out;
                }

                ret = get_dacl_inheritance(pacl, j, &inherit, &inheritsize);
                if (ret < 0) {
                    GETERRNO(ret);
                    if (ret == -ERROR_NO_MORE_ITEMS) {
                        fprintf(stderr, "funny to get dacl inherit with no items\n");
                        break;
                    }
                    fprintf(stderr, "get [%d][%s] dacl inherit error[%d]\n", i, fname, ret);
                    goto out;
                }

                fprintf(stdout, "[%03d][%03d]%-5s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n", i, j, "dacl",
                        maxfilesize + 1, fname, maxownersize + 1 , owner,
                        maxgroupsize + 1, group, maxusersize + 1, user,
                        maxactionsize + 1 , action, maxrightsize + 1 , right,
                        maxinheritsize + 1, inherit);
                j ++;
            }
        }
    }
    ret = 0;
out:
    get_file_group(NULL, &group, &grpsize);
    get_file_owner(NULL, &owner, &ownersize);
    get_sacl_inheritance(NULL, 0, &inherit, &inheritsize);
    get_sacl_right(NULL, 0, &right, &rightsize);
    get_sacl_action(NULL, 0, &action, &actionsize);
    get_sacl_user(NULL, 0, &user, &usersize);
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}

int setowner_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* owner = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int i, ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "need owner files...\n");
        goto out;
    }
    owner = parsestate->leftargs[0];
    for (i = 1; parsestate->leftargs[i] != NULL; i++) {
        fname = parsestate->leftargs[i];
        ret = set_file_owner(fname, owner);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%d][%s] set owner error[%d]\n", i, fname, ret);
            goto out;
        }

        fprintf(stdout, "[%d][%s] owner [%s] succ\n", i, fname, owner);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int getsid_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t)popt;
    int i, ret;
    char* psidstr = NULL;
    int strsize = 0;
    char* username = NULL;
    argc = argc;
    argv = argv;

    init_log_level(pargs);
    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] != NULL ; i ++) {
        username = parsestate->leftargs[i];
        ret = get_name_sid(username, &psidstr, &strsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%d][%s] sid error[%d]\n", i, username, ret);
            goto out;
        }
        fprintf(stdout, "[%d][%s] sid [%s]\n", i, username, psidstr);
    }

    ret = 0;
out:
    get_name_sid(NULL, &psidstr, &strsize);
    SETERRNO(ret);
    return ret;
}

int setgroup_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* group = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int i, ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "need group files...\n");
        goto out;
    }
    group = parsestate->leftargs[0];
    for (i = 1; parsestate->leftargs[i] != NULL; i++) {
        fname = parsestate->leftargs[i];
        ret = set_file_group(fname, group);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "[%d][%s] set group error[%d]\n", i, fname, ret);
            goto out;
        }
        fprintf(stdout, "[%d][%s] group [%s] succ\n", i, fname, group);
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int removesacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* action = NULL;
    char* username = NULL;
    char* right = NULL;
    char* inherit = NULL;
    void* pacl = NULL;
    const char* usage = "fname username action right [inherit] to remove the sacl";
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    fname = parsestate->leftargs[0];
    if (parsestate->leftargs[1] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    username = parsestate->leftargs[1];
    if (parsestate->leftargs[2] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    action = parsestate->leftargs[2];
    if (parsestate->leftargs[3] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    right = parsestate->leftargs[3];
    if (parsestate->leftargs[4] != NULL) {
        inherit = parsestate->leftargs[4];
    }
    ret = get_file_acls(fname, &pacl);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] acl error[%d]\n", fname, ret);
        goto out;
    }

    ret = remove_sacl(pacl, username, action, right, inherit);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "[%s] remove sacl [%s][%s][%s][%s] error[%d]\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify", ret);
        goto out;
    }

    fprintf(stdout, "[%s] remove sacl [%s][%s][%s][%s] succ\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify");
    ret = 0;
out:
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}

int removedacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* action = NULL;
    char* username = NULL;
    char* right = NULL;
    char* inherit = NULL;
    const char* usage = "fname username action right [inherit] to remove the dacl";
    void* pacl = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    fname = parsestate->leftargs[0];
    if (parsestate->leftargs[1] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    username = parsestate->leftargs[1];
    if (parsestate->leftargs[2] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    action = parsestate->leftargs[2];
    if (parsestate->leftargs[3] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    right = parsestate->leftargs[3];
    if (parsestate->leftargs[4] != NULL) {
        inherit = parsestate->leftargs[4];
    }
    ret = get_file_acls(fname, &pacl);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] acl error[%d]\n", fname, ret);
        goto out;
    }


    ret = remove_dacl(pacl, username, action, right, inherit);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "[%s] remove dacl [%s][%s][%s][%s] error[%d]\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify", ret);
        goto out;
    }

    fprintf(stdout, "[%s] remove dacl [%s][%s][%s][%s] succ\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify");
    ret = 0;
out:
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}

int addsacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* action = NULL;
    char* username = NULL;
    char* right = NULL;
    char* inherit = NULL;
    const char* usage = "fname username action right [inherit] to add the sacl";
    void* pacl = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    fname = parsestate->leftargs[0];
    if (parsestate->leftargs[1] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    username = parsestate->leftargs[1];
    if (parsestate->leftargs[2] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    action = parsestate->leftargs[2];
    if (parsestate->leftargs[3] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    right = parsestate->leftargs[3];
    if (parsestate->leftargs[4] != NULL) {
        inherit = parsestate->leftargs[4];
    }
    ret = get_file_acls(fname, &pacl);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] acl error[%d]\n", fname, ret);
        goto out;
    }


    ret = add_sacl(pacl, username, action, right, inherit);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "[%s] add sacl [%s][%s][%s][%s] error[%d]\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify", ret);
        goto out;
    }

    fprintf(stdout, "[%s] add sacl [%s][%s][%s][%s] succ\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify");
    ret = 0;
out:
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}


int adddacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* fname = NULL;
    char* action = NULL;
    char* username = NULL;
    char* right = NULL;
    char* inherit = NULL;
    const char* usage = "fname username action right [inherit] to add the dacl";
    void* pacl = NULL;
    pargs_options_t pargs = (pargs_options_t)popt;
    int ret;
    argc = argc;
    argv = argv;

    init_log_level(pargs);

    if (parsestate->leftargs == NULL ||
            parsestate->leftargs[0] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    fname = parsestate->leftargs[0];
    if (parsestate->leftargs[1] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    username = parsestate->leftargs[1];
    if (parsestate->leftargs[2] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    action = parsestate->leftargs[2];
    if (parsestate->leftargs[3] == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        fprintf(stderr, "%s\n", usage);
        goto out;
    }
    right = parsestate->leftargs[3];
    if (parsestate->leftargs[4] != NULL) {
        inherit = parsestate->leftargs[4];
    }
    ret = get_file_acls(fname, &pacl);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get [%s] acl error[%d]\n", fname, ret);
        goto out;
    }

    ret = add_dacl(pacl, username, action, right, inherit);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "[%s] add dacl [%s][%s][%s][%s] error[%d]\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify", ret);
        goto out;
    }

    fprintf(stdout, "[%s] add dacl [%s][%s][%s][%s] succ\n", fname, username, action, right, inherit != NULL ? inherit : "notmodify");
    ret = 0;
out:
    get_file_acls(NULL, &pacl);
    SETERRNO(ret);
    return ret;
}

int __get_security_descriptor_from_string_2(char* sddl, PSECURITY_DESCRIPTOR* ppdp)
{
    int ret;
    BOOL bret;
    TCHAR* ptsddl = NULL;
    int tsddlsize = 0;
    ULONG dpsize = 0;
    if (sddl == NULL) {
        if (ppdp && *ppdp) {
            LocalFree(*ppdp);
            *ppdp = NULL;
        }
        return 0;
    }
    if (ppdp == NULL || *ppdp != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        GETERRNO(ret);
        return ret;
    }

    ret = AnsiToTchar(sddl, &ptsddl, &tsddlsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = ConvertStringSecurityDescriptorToSecurityDescriptor(ptsddl, SDDL_REVISION_1, ppdp, &dpsize);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not convert [%s] to security_descriptor error[%d]", sddl, ret);
        goto fail;
    }

    AnsiToTchar(NULL, &ptsddl, &tsddlsize);
    return (int)GetSecurityDescriptorLength(*ppdp);
fail:
    AnsiToTchar(NULL, &ptsddl, &tsddlsize);
    SETERRNO(ret);
    return ret;
}

static int __get_dacl_from_descriptor(PSECURITY_DESCRIPTOR psdp, PACL* ppacl)
{
    BOOL bacldefault, bacl;
    BOOL bret;
    PACL acl = NULL;
    int ret;
    int retval = 1;

    bacl = FALSE;
    bacldefault = FALSE;
    bret = GetSecurityDescriptorDacl(psdp, &bacl, &acl, &bacldefault);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("get acl error[%d]", ret);
        goto fail;
    }

    if (!bacl) {
        retval = 0;
        acl = NULL;
    }
    if (ppacl && acl != NULL) {
        *ppacl = acl;
    }

    return retval;
fail:
    SETERRNO(ret);
    return NULL;
}

static int __get_sid_name(PSID psid, char** ppstr, int *pstrsize)
{
    SID_NAME_USE siduse;
    TCHAR* ptuser = NULL, *ptdomain = NULL;
    DWORD tusersize = 0, tuserlen = 0;
    DWORD tdomainsize = 0, tdomainlen = 0;
    char* pname = NULL, *pdomain = NULL;
    int namesize = 0, namelen = 0, domainsize = 0, domainlen = 0;
    int ret;
    BOOL bret;
    int retlen;

    if (psid == NULL) {
        return snprintf_safe(ppstr, pstrsize, NULL);
    }

    tusersize = 32;
    tdomainsize = 32;
try_get_sid_old:
    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;
    ptuser = (TCHAR*) malloc(tusersize * sizeof(TCHAR));
    if (ptuser == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tusersize * sizeof(TCHAR), ret);
        goto fail;
    }

    ptdomain = (TCHAR*)malloc(tdomainsize * sizeof(TCHAR));
    if (ptdomain == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tdomainsize * sizeof(TCHAR), ret);
        goto fail;
    }
    tuserlen = tusersize;
    tdomainlen = tdomainsize;
    bret = LookupAccountSid(NULL, psid, ptuser, &tuserlen, ptdomain, &tdomainlen, &siduse);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            tusersize = tuserlen << 1;
            tdomainsize = tdomainlen << 1;
            goto try_get_sid_old;
        }
        ERROR_INFO("get sid error [%d]", ret);
        goto fail;
    }
    ret = TcharToAnsi(ptuser, &pname, &namesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    namelen = ret;

    ret = TcharToAnsi(ptdomain, &pdomain, &domainsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    domainlen = ret;

    if (domainlen > 0) {
        DEBUG_INFO("domain [%s] name [%s]", pdomain, pname);
        ret = snprintf_safe(ppstr, pstrsize, "%s\\%s", pdomain, pname);
    } else {
        ret = snprintf_safe(ppstr, pstrsize, "%s", pname);
    }
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;

    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;
    TcharToAnsi(NULL, &pname, &namesize);
    TcharToAnsi(NULL, &pdomain, &domainsize);
    return retlen;
fail:
    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;
    TcharToAnsi(NULL, &pname, &namesize);
    TcharToAnsi(NULL, &pdomain, &domainsize);
    SETERRNO(ret);
    return ret;
}


static void __debug_access_inner_2(PEXPLICIT_ACCESS pcuracc, const char* prefix)
{
    PSID psid = NULL;
    int ret;
    char* name = NULL;
    int namesize = 0;
    DEBUG_INFO("%s grfAccessPermissions [0x%lx]", prefix, pcuracc->grfAccessPermissions);
    if ((pcuracc->grfAccessPermissions & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL) {
        DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_ALL);
    } else {
        if (pcuracc->grfAccessPermissions & DELETE) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_DELETE);
        }
        if (pcuracc->grfAccessPermissions & READ_CONTROL) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_READ_CONTROL);
        }
        if (pcuracc->grfAccessPermissions & WRITE_DAC) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_WRITE_DAC);
        }
        if (pcuracc->grfAccessPermissions & WRITE_OWNER) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_WRITE_OWNER);
        }
        if (pcuracc->grfAccessPermissions & SYNCHRONIZE) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_SYNCHRONIZE);
        }
    }


    switch (pcuracc->grfAccessMode) {
    case NOT_USED_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_NOT_USED);
        break;
    case GRANT_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_GRANT);
        break;
    case SET_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_SET);
        break;
    case DENY_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_DENY);
        break;
    case REVOKE_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_REVOKE);
        break;
    case SET_AUDIT_SUCCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_AUDIT_SUCC);
        break;
    case SET_AUDIT_FAILURE:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_AUDIT_FAIL);
        break;
    default:
        DEBUG_INFO("%s grfAccessMode [0x%lx]", prefix, pcuracc->grfAccessMode);
    }

    DEBUG_INFO("%s grfInheritance [0x%x]", prefix, pcuracc->grfInheritance);
    if (pcuracc->grfInheritance == 0) {
        if ((pcuracc->grfInheritance & NO_INHERITANCE) == NO_INHERITANCE) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_NO_INHERITANCE);
        }
    } else {
        if ((pcuracc->grfInheritance & CONTAINER_INHERIT_ACE) == CONTAINER_INHERIT_ACE) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_CONTAINER_INHERIT_ACE);
        }

        if ((pcuracc->grfInheritance & INHERIT_NO_PROPAGATE) == INHERIT_NO_PROPAGATE) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_INHERIT_NO_PROPAGATE);
        }

        if ((pcuracc->grfInheritance & INHERIT_ONLY) == INHERIT_ONLY) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_INHERIT_ONLY);
        }
        if ((pcuracc->grfInheritance & OBJECT_INHERIT_ACE) == OBJECT_INHERIT_ACE) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_OBJECT_INHERIT_ACE);
        }
        if ((pcuracc->grfInheritance & SUB_CONTAINERS_AND_OBJECTS_INHERIT) == SUB_CONTAINERS_AND_OBJECTS_INHERIT) {
            DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        }
    }

    DEBUG_INFO("%s pMultipleTrustee [%p]", prefix, pcuracc->Trustee.pMultipleTrustee);
    DEBUG_INFO("%s MultipleTrusteeOperation [0x%x]", prefix, pcuracc->Trustee.MultipleTrusteeOperation);
    DEBUG_INFO("%s TrusteeForm [0x%x]", prefix, pcuracc->Trustee.TrusteeForm);
    DEBUG_INFO("%s TrusteeType [0x%x]", prefix, pcuracc->Trustee.TrusteeType);

    if (pcuracc->Trustee.TrusteeForm == TRUSTEE_IS_SID  &&
            pcuracc->Trustee.TrusteeType == TRUSTEE_IS_UNKNOWN &&
            pcuracc->Trustee.ptstrName != NULL) {
        psid = (PSID) pcuracc->Trustee.ptstrName;
        ret = __get_sid_name(psid, &name, &namesize);
        if (ret > 0) {
            DEBUG_INFO("%s name [%s]", prefix, name);
        }
    }
    __get_sid_name(NULL, &name, &namesize);
    return;
}

static void __debug_access_2(PEXPLICIT_ACCESS paccess, int accnum)
{
    char* prefix = NULL;
    int prefixsize = 0;
    int ret;
    int i;
    for (i = 0; i < accnum; i++) {
        ret = snprintf_safe(&prefix, &prefixsize, "[%d]", i);
        if (ret > 0) {
            __debug_access_inner_2(&(paccess[i]), prefix);
        }
    }
    snprintf_safe(&prefix, &prefixsize, NULL);
    return;
}

static void __free_trustee_2(PTRUSTEE* pptrustee);

static void __release_trustee_2(PTRUSTEE ptrustee)
{
    if (ptrustee) {
        __free_trustee_2(&(ptrustee->pMultipleTrustee));
        ptrustee->MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        ptrustee->TrusteeForm = TRUSTEE_IS_SID;
        ptrustee->TrusteeType = TRUSTEE_IS_UNKNOWN;
        if (ptrustee->ptstrName) {
            LocalFree(ptrustee->ptstrName);
            ptrustee->ptstrName = NULL;
        }
    }
    return;
}

static void __free_trustee_2(PTRUSTEE *pptrustee)
{
    PTRUSTEE ptrustee = NULL;
    if (pptrustee && *pptrustee) {
        ptrustee = *pptrustee;
        __release_trustee_2(ptrustee);
        LocalFree(ptrustee);
        *pptrustee = NULL;
    }
    return ;
}


static int __init_trustee_2(PTRUSTEE ptrustee)
{
    memset(ptrustee, 0 , sizeof(*ptrustee));
    ptrustee->pMultipleTrustee = NULL;
    ptrustee->MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ptrustee->TrusteeForm = TRUSTEE_IS_SID;
    ptrustee->TrusteeType = TRUSTEE_IS_UNKNOWN;
    ptrustee->ptstrName = NULL;
    return 0;
}


static int __init_explicit_access_2(PEXPLICIT_ACCESS pacc)
{
    memset(pacc, 0 , sizeof(*pacc));
    pacc->grfAccessPermissions = 0;
    pacc->grfAccessMode = NOT_USED_ACCESS;
    pacc->grfInheritance = NO_INHERITANCE;
    return __init_trustee_2(&(pacc->Trustee));
}

static void __release_explicit_access_2(PEXPLICIT_ACCESS pacc)
{
    if (pacc) {
        __release_trustee_2(&(pacc->Trustee));
    }
    return;
}



static void __free_explicit_access_array_2(PEXPLICIT_ACCESS *ppacc, int *psize)
{
    if (ppacc && *ppacc && psize ) {
        int i;
        PEXPLICIT_ACCESS pacc = NULL;
        int size = *psize;
        pacc = *ppacc;
        for (i = 0; i < size; i++) {
            __release_explicit_access_2(&(pacc[i]));
        }
        LocalFree(pacc);
    }
    if (ppacc) {
        *ppacc = NULL;
    }
    if (psize) {
        *psize = 0;
    }
    return;
}

static PEXPLICIT_ACCESS __alloc_explicit_access_array_2(int size)
{
    PEXPLICIT_ACCESS pnewacc = NULL;
    int sz = size;
    int ret;
    int i;

    pnewacc = (PEXPLICIT_ACCESS)LocalAlloc(LMEM_FIXED, sizeof(*pnewacc) * sz);
    if (pnewacc == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*pnewacc)*sz, ret);
        goto fail;
    }
    memset(pnewacc, 0, sizeof(*pnewacc) * sz);
    for (i = 0; i < sz; i++) {
        ret = __init_explicit_access_2(&(pnewacc[i]));
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    return pnewacc;
fail:
    __free_explicit_access_array_2(&pnewacc, &sz);
    SETERRNO(ret);
    return NULL;
}

static int __copy_sid_2(PSID osid, PSID* ppnsid)
{
    int sidsize = 0;
    int ret;
    BOOL bret;

    if (osid == NULL) {
        if (ppnsid && *ppnsid) {
            LocalFree(*ppnsid);
            *ppnsid = NULL;
        }
        return 0;
    }

    if (ppnsid  == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    sidsize = MIN_SID_SIZE;
copy_sid_again:
    if (*ppnsid != NULL) {
        LocalFree(*ppnsid);
    }
    *ppnsid = NULL;
    *ppnsid = (PSID)LocalAlloc(LMEM_FIXED, (SIZE_T)sidsize);
    if ((*ppnsid) == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sidsize, ret);
        goto fail;
    }
    bret = CopySid((DWORD)sidsize, (*ppnsid), osid);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            sidsize <<= 1;
            goto copy_sid_again;
        }
        ERROR_INFO("copy sid error[%d]", ret);
        goto fail;
    }
    return sidsize;
fail:
    if (*ppnsid) {
        LocalFree(*ppnsid);
        *ppnsid = NULL;
    }
    SETERRNO(ret);
    return ret;
}

static int __trans_aceflags_to_inherit_2(BYTE flags, DWORD * pinherit)
{
    DWORD inherit = 0;

    if (flags == FAILED_ACCESS_ACE_FLAG) {
        inherit |= INHERIT_NO_PROPAGATE;
    }

    if (flags == CONTAINER_INHERIT_ACE) {
        inherit |= CONTAINER_INHERIT_ACE;
    }
    if (flags == FAILED_ACCESS_ACE_FLAG) {
        inherit |= NO_INHERITANCE;
    }
    if (flags == INHERIT_ONLY_ACE) {
        inherit |= INHERIT_ONLY_ACE;
    }

    if (flags == INHERITED_ACE) {
        inherit |= INHERIT_ONLY;
    }
    if (flags == NO_PROPAGATE_INHERIT_ACE) {
        inherit |= NO_PROPAGATE_INHERIT_ACE;
    }
    if (flags == OBJECT_INHERIT_ACE) {
        inherit |= OBJECT_INHERIT_ACE;
    }
    if (flags == SUCCESSFUL_ACCESS_ACE_FLAG) {
        inherit |= SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    }
    *pinherit = inherit;
    return 0;
}

static int __get_explicit_access_2(PACL acl, PEXPLICIT_ACCESS *ppaccess, int *psize)
{
    int accnum = 0;
    int ret;
    PEXPLICIT_ACCESS pretaccess = NULL;
    int retsize = 0;
    void* curp;
    ACE_HEADER* pheader = NULL;
    int i;
    BOOL bret;
    PEXPLICIT_ACCESS pcuracc = NULL;
    PACCESS_ALLOWED_ACE pallowace = NULL;
    PACCESS_ALLOWED_CALLBACK_ACE pallowcallbackace = NULL;
    PACCESS_ALLOWED_CALLBACK_OBJECT_ACE pallowcallbackobjace = NULL;
    PACCESS_ALLOWED_OBJECT_ACE pallowobjace = NULL;
    ACCESS_DENIED_ACE* pdenyace = NULL;
    PACCESS_DENIED_CALLBACK_ACE pdenycallbackace = NULL;
    PACCESS_DENIED_CALLBACK_OBJECT_ACE pdenycallbackobjace = NULL;
    PACCESS_DENIED_OBJECT_ACE pdenyobjace = NULL;

    if (acl == NULL) {
        if (ppaccess && *ppaccess) {
            LocalFree(*ppaccess);
            *ppaccess = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }
    if (ppaccess == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretaccess = *ppaccess;
    retsize = *psize;

    if (*ppaccess != NULL || *psize != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (retsize < acl->AceCount || pretaccess == NULL) {
        retsize = acl->AceCount;
        pretaccess = __alloc_explicit_access_array_2(retsize);
        if (pretaccess == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    } else {
        for (i = 0; i < retsize; i++) {
            __release_explicit_access_2(&(pretaccess[i]));
            ret = __init_explicit_access_2(&(pretaccess[i]));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
        }
    }

    /*now we should give the output*/
    accnum = 0;
    for (i = 0; i < acl->AceCount; i++) {
        /*now to give the count*/
        bret = GetAce(acl, (DWORD)i, &curp);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("get [%d] error[%d]", i, ret);
            goto fail;
        }
        pheader = (ACE_HEADER*) curp;
        pcuracc = &(pretaccess[accnum]);
        switch (pheader->AceType) {
        case ACCESS_ALLOWED_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_ACE_TYPE][%d]", i, pheader->AceType);
            pallowace = (PACCESS_ALLOWED_ACE) pheader;
            pcuracc->grfAccessMode = GRANT_ACCESS;
            pcuracc->grfAccessPermissions = pallowace->Mask;
            ret = __trans_aceflags_to_inherit_2(pallowace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pallowace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_CALLBACK_ACE_TYPE][%d]", i, pheader->AceType);
            pallowcallbackace = (PACCESS_ALLOWED_CALLBACK_ACE) pheader;
            pcuracc->grfAccessMode = GRANT_ACCESS;
            pcuracc->grfAccessPermissions = pallowcallbackace->Mask;
            ret = __trans_aceflags_to_inherit_2(pallowcallbackace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pallowcallbackace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            pallowcallbackobjace = (PACCESS_ALLOWED_CALLBACK_OBJECT_ACE) pheader;
            pcuracc->grfAccessMode = GRANT_ACCESS;
            pcuracc->grfAccessPermissions = pallowcallbackobjace->Mask;
            ret = __trans_aceflags_to_inherit_2(pallowcallbackobjace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pallowcallbackobjace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_COMPOUND_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_ALLOWED_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            pallowobjace = (PACCESS_ALLOWED_OBJECT_ACE) pheader;
            pcuracc->grfAccessMode = GRANT_ACCESS;
            pcuracc->grfAccessPermissions = pallowobjace->Mask;
            ret = __trans_aceflags_to_inherit_2(pallowobjace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pallowobjace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_DENIED_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_DENIED_ACE_TYPE][%d]", i, pheader->AceType);
            pdenyace = (ACCESS_DENIED_ACE*) pheader;
            pcuracc->grfAccessMode = DENY_ACCESS;
            pcuracc->grfAccessPermissions = pdenyace->Mask;
            ret = __trans_aceflags_to_inherit_2(pdenyace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pdenyace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_DENIED_CALLBACK_ACE_TYPE][%d]", i, pheader->AceType);
            pdenycallbackace = (PACCESS_DENIED_CALLBACK_ACE) pheader;
            pcuracc->grfAccessMode = DENY_ACCESS;
            pcuracc->grfAccessPermissions = pdenycallbackace->Mask;
            ret = __trans_aceflags_to_inherit_2(pdenycallbackace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pdenycallbackace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            pdenycallbackobjace = (PACCESS_DENIED_CALLBACK_OBJECT_ACE) pheader;
            pcuracc->grfAccessMode = DENY_ACCESS;
            pcuracc->grfAccessPermissions = pdenycallbackobjace->Mask;
            ret = __trans_aceflags_to_inherit_2(pdenycallbackobjace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pdenycallbackobjace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_DENIED_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            pdenyobjace = (PACCESS_DENIED_OBJECT_ACE) pheader;
            pcuracc->grfAccessMode = DENY_ACCESS;
            pcuracc->grfAccessPermissions = pdenyobjace->Mask;
            ret = __trans_aceflags_to_inherit_2(pdenyobjace->Header.AceFlags, &(pcuracc->grfInheritance));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret = __copy_sid_2((PSID) & (pdenyobjace->SidStart), (PSID*) & (pcuracc->Trustee.ptstrName));
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            accnum ++;
            break;
        case ACCESS_MAX_MS_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_MAX_MS_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case ACCESS_MAX_MS_V2_ACE_TYPE:
            DEBUG_INFO("[%d] type [ACCESS_MAX_MS_V2_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_ALARM_CALLBACK_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_AUDIT_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_AUDIT_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_AUDIT_CALLBACK_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_AUDIT_OBJECT_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            DEBUG_INFO("[%d] type [SYSTEM_MANDATORY_LABEL_ACE_TYPE][%d]", i, pheader->AceType);
            break;
        default:
            ERROR_INFO("[%d] type [%d]", pheader->AceType);
            break;
        }

    }

    if (*ppaccess && *ppaccess != pretaccess) {
        __free_explicit_access_array_2(ppaccess, psize);
    }
    *ppaccess = pretaccess;
    *psize = retsize;
    DEBUG_INFO("get [%p] ppaccess [%p] size [%d]", acl, *ppaccess, *psize);
    __debug_access_2(*ppaccess, accnum);
    return accnum;

fail:
    if (pretaccess && pretaccess != *ppaccess) {
        __free_explicit_access_array_2(&pretaccess, &retsize);
    } else if (pretaccess != NULL) {
        for (i = 0; i < retsize; i++) {
            __release_explicit_access_2(&(pretaccess[i]));
        }
    }
    pretaccess = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

#pragma comment(lib,"Advapi32.lib")

int dumpsacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    PSECURITY_DESCRIPTOR pdp = NULL;
    char* sddl = NULL;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i]; i++) {
            sddl = parsestate->leftargs[i];
            ret = __get_security_descriptor_from_string_2(sddl, &pdp);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "can not change [%d][%s] error[%d]\n", i, sddl, ret);
                goto out;
            }
            DEBUG_BUFFER_FMT(pdp, ret, "[%d][sacl][%s]", i , sddl);
            __get_security_descriptor_from_string_2(NULL, &pdp);
        }
    }

    ret = 0;
out:
    __get_security_descriptor_from_string_2(NULL, &pdp);
    SETERRNO(ret);
    return ret;
}



int dumpdacl_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    PSECURITY_DESCRIPTOR pdp = NULL;
    char* sddl = NULL;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;
    PACL pacl = NULL;
    PEXPLICIT_ACCESS paccess = NULL;
    int accsize = 0;
    int accnum = 0;
    int dpsize = 0;

    argc = argc;
    argv = argv;
    init_log_level(pargs);


    if (parsestate->leftargs != NULL) {
        for (i = 0; parsestate->leftargs[i]; i++) {
            sddl = parsestate->leftargs[i];
            ret = __get_security_descriptor_from_string_2(sddl, &pdp);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "can not change [%d][%s] error[%d]\n", i, sddl, ret);
                goto out;
            }
            dpsize = ret;

            ret = __get_dacl_from_descriptor(pdp, &pacl);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "[%d][%s]can not get dacl error[%d]", i, sddl, ret);
                goto out;
            } else if (ret == 0) {
                fprintf(stdout, "[%d][%s] no dacl\n", i, sddl);
                goto next_one;
            }


            ret = __get_explicit_access_2(pacl, &paccess, &accsize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "[%d][%s]can not get explicit access error[%d]\n", i, sddl, ret);
                goto out;
            }
            accnum = ret;

            DEBUG_BUFFER_FMT(pdp, dpsize, "[%d][dacl][%s] for [%d] explicit access", i , sddl, accnum);
next_one:
            __get_explicit_access_2(NULL, &paccess, &accsize);
            accnum = 0;
            __get_security_descriptor_from_string_2(NULL, &pdp);
        }
    }

    ret = 0;
out:
    __get_explicit_access_2(NULL, &paccess, &accsize);
    __get_security_descriptor_from_string_2(NULL, &pdp);
    SETERRNO(ret);
    return ret;
}

int __get_code(pextargs_state_t parsestate, char** ppcode, int* psize)
{
    int cnt = 0;
    int ret;
    char* pcode = NULL;
    int retsize = 0;
    int num = 0;
    int idx;
    int i;
    if (parsestate == NULL) {
        if (ppcode && *ppcode) {
            free(*ppcode);
            *ppcode = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }

    if (retsize <= cnt || pcode == NULL) {
        if (retsize <= cnt) {
            retsize = cnt + 1;
        }
        pcode = (char*)malloc((size_t)retsize);
        if (pcode == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "alloc %d error[%d]\n", retsize, ret);
            goto fail;
        }
    }
    memset(pcode, 0, (size_t)retsize);
    idx = 0;
    for (i = 0; i < cnt; i++) {
        GET_OPT_INT(num, "number");
        /*we change the idx*/
        pcode[i] = (char)num;
    }


    if (*ppcode && *ppcode != pcode) {
        free(*ppcode);
    }
    *ppcode = pcode;
    *psize = retsize;
    return cnt;
out:
fail:
    if (pcode && pcode != *ppcode) {
        free(pcode);
    }
    pcode = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}


int utf8toansi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* putf8 = NULL;
    int utf8size = 0;
    int utf8len = 0;
    char* pansi = NULL;
    int ansisize = 0, ansilen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    ret = __get_code(parsestate, &putf8, &utf8size);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    utf8len = ret;
    ret = Utf8ToAnsi(putf8, &pansi, &ansisize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not trans buffer [%d]\n", ret);
        goto out;
    }
    ansilen = ret;

    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    __debug_buf(stdout, putf8, utf8len);
    fprintf(stdout, "ansi buffer [%d]\n", ansilen);
    __debug_buf(stdout, pansi, ansilen);
    ret = 0;
out:
    Utf8ToAnsi(NULL, &pansi, &ansisize);
    __get_code(NULL, &putf8, &utf8size);
    SETERRNO(ret);
    return ret;
}

int ansitoutf8_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* putf8 = NULL;
    int utf8size = 0;
    int utf8len = 0;
    char* pansi = NULL;
    int ansisize = 0, ansilen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;

    argc = argc;
    argv = argv;
    init_log_level(pargs);
    ret = __get_code(parsestate, &pansi, &ansisize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    ansilen = ret;
    ret = AnsiToUtf8(pansi, &putf8, &utf8size);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not trans buffer [%d]\n", ret);
        goto out;
    }
    utf8len = ret;

    fprintf(stdout, "ansi buffer [%d]\n", ansilen);
    __debug_buf(stdout, pansi, ansilen);
    fprintf(stdout, "utf8 buffer [%d]\n", utf8len);
    __debug_buf(stdout, putf8, utf8len);
    ret = 0;
out:
    AnsiToUtf8(NULL, &putf8, &utf8size);
    __get_code(NULL, &pansi, &ansisize);
    SETERRNO(ret);
    return ret;
}

static void* st_pdbg = NULL;

BOOL WINAPI HandlerCtrlcRoutine(DWORD dwCtrlType)
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

#ifdef  _M_X64
    int ret;
    if (st_pdbg) {
        ret = windbg_interrupt(st_pdbg);
        if (ret < 0) {
            ERROR_INFO("can not interrupt [%d]", ret);
            bret = FALSE;
        }
    }
#endif  /* _M_X64*/

    return bret;
}


int windbg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
#ifdef _M_X64
    pargs_options_t pargs = (pargs_options_t) popt;
    int cnt = 0;
    int i;
    void* pdbg = NULL;
    int ret = 0;
    char* pcmd = NULL;
    int cmdsize = 0;
    char* pcurquote = NULL;
    int curquotesize = 0;
    BOOL bret;


    argc = argc;
    argv = argv;
    init_log_level(pargs);

    while (parsestate->leftargs != NULL && parsestate->leftargs[cnt] != NULL) {
        cnt ++;
    }

    for (i = 0; i < cnt; i++) {
        ret = quote_string(&pcurquote, &curquotesize, "%s", parsestate->leftargs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
        if (i > 0) {
            ret = append_snprintf_safe(&pcmd, &cmdsize, " %s", pcurquote);
        } else {
            ret = snprintf_safe(&pcmd, &cmdsize, "%s", pcurquote);
        }
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }


    bret = SetConsoleCtrlHandler(HandlerCtrlcRoutine, TRUE);
    if (!bret) {
        GETERRNO(ret);
        fprintf(stderr, "can not set ctrl handler [%d]", ret);
        goto out;
    }


    ret = initialize_com();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not initialized com [%d]\n", ret);
        goto out;
    }

    ret = windbg_create_client("", &pdbg);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get client error[%d]\n", ret);
        goto out;
    }

    st_pdbg = pdbg;

    ret = windbg_start_process_single(pdbg, pcmd, WIN_DBG_FLAGS_CHILDREN | WIN_DBG_FLAGS_HEAP);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "create [%s] error[%d]\n", pcmd, ret);
        goto out;
    }

    ret = windbg_go(pdbg);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "go [%s] error[%d]\n", pcmd, ret);
        goto out;
    }

    fprintf(stdout, "dbg [%s] succ\n", pcmd);
    ret = 0;
out:
    st_pdbg = NULL;
    windbg_create_client(NULL, &pdbg);
    uninitialize_com();
    snprintf_safe(&pcmd, &cmdsize, NULL);
    quote_string(&pcurquote, &curquotesize, NULL);
    SETERRNO(ret);
    return ret;
#else  /*_M_X64*/
    int ret = -ERROR_NOT_SUPPORTED;
    popt = popt;
    argc = argc;
    argv = argv;
    parsestate = parsestate;
    SETERRNO(ret);
    return ret;
#endif /*_M_X64*/
}

int execdbg_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
#ifdef _M_X64
    char* singlecmd = NULL;
    char* runcmd = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    void* pdbg = NULL;
    char* pout = NULL;
    int outsize = 0;
    int outlen = 0;
    BOOL bret;
    char* readbuf = NULL, *pptr;
    size_t readsize = 512;
    size_t slen;

    argc = argc;
    argv = argv;
    init_log_level(pargs);

    singlecmd = parsestate->leftargs[0];

    bret = SetConsoleCtrlHandler(HandlerCtrlcRoutine, TRUE);
    if (!bret) {
        GETERRNO(ret);
        fprintf(stderr, "can not set ctrl handler [%d]", ret);
        goto out;
    }


    ret = initialize_com();
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not initialized com [%d]\n", ret);
        goto out;
    }

    ret = windbg_create_client("", &pdbg);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "can not get client error[%d]\n", ret);
        goto out;
    }

    st_pdbg = pdbg;

    ret = windbg_start_process_single(pdbg, singlecmd, WIN_DBG_FLAGS_CHILDREN | WIN_DBG_FLAGS_HEAP);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "create [%s] error[%d]\n", singlecmd, ret);
        goto out;
    }

    readbuf = (char*) malloc(readsize);
    if (readbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "alloc [%zu] readbuf error[%d]\n", readsize, ret);
        goto out;
    }

    while (1) {
        fprintf(stdout, "dbg>");
        fflush(stdout);
        pptr = fgets(readbuf, (int)readsize, stdin);
        if (pptr == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "read error[%d]\n", ret);
            goto out;
        }
        slen = strlen(readbuf);
        if (slen >= readsize) {
            continue;
        }
        pptr = readbuf + slen;
        DEBUG_INFO("pptr [%p] readbuf [%p]", pptr, readbuf);
        while (pptr >= readbuf &&
                (*pptr == '\r' || *pptr == '\n' || *pptr == '\0')) {
            DEBUG_INFO("pptr [%p] [0x%02x]", pptr, *pptr);
            *pptr = '\0';
            pptr --;
        }


        if (strcmp(readbuf, "exit") == 0) {
            break;
        }
        ret = windbg_exec(pdbg, readbuf);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "run [%s] error [%d]\n", readbuf, ret);
            goto out;
        }
        ret = windbg_get_out(pdbg, WIN_DBG_OUTPUT_OUT, &pout, &outsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get out for [%s] error[%d]\n", runcmd, ret);
            goto out;
        }
        outlen = ret;
        fprintf(stdout, "%s", pout);
    }

    ret = 0;
out:
    st_pdbg = NULL;
    windbg_get_out(NULL, WIN_DBG_FLAGS_FREE, &pout, &outsize);
    windbg_create_client(NULL, &pdbg);
    uninitialize_com();
    SETERRNO(ret);
    return ret;
#else /*_M_X64*/
    int ret = -ERROR_NOT_SUPPORTED;
    popt = popt;
    argc = argc;
    argv = argv;
    parsestate = parsestate;
    SETERRNO(ret);
    return ret;
#endif /*_M_X64*/
}

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

    ret = init_nt_funcs();
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }


    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] != NULL ; i ++) {
        pid = atoi(parsestate->leftargs[i]);
        ret = dump_process_security(pid);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    ret = 0;
out:
    fini_nt_funcs();
    SETERRNO(ret);
    return ret;
}

int procsecset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int pid;
    ACCESS_MASK mask;
    ACCESS_MODE mode;
    DWORD inherit;
    char* username=NULL;


    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);
    init_log_level(pargs);

    ret = init_nt_funcs();
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    pid = atoi(parsestate->leftargs[0]);
    ret = get_mask_from_str(stderr,parsestate->leftargs[1], &mask);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = get_mode_from_str(stderr,parsestate->leftargs[2],&mode);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = get_inherit_from_str(stderr,parsestate->leftargs[3], &inherit);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    username = parsestate->leftargs[4];

    ret = proc_dacl_set(pid,mask,mode,inherit,username);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    ret = 0;
out:
    fini_nt_funcs();
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