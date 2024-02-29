

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
#include <win_evt.h>
#include <win_map.h>
#include <win_output_debug_cfg.h>
#include <win_gui.h>
#include <win_sock.h>
#include <win_hdl.h>
#include <win_serial.h>
#include <win_hwinfo.h>
#include <win_usb.h>
#include <win_libev.h>


#include <jvalue.h>
#include <crypt_md5.h>
#include <crypt_rsa.h>
#include <crypt_aes.h>
#include <crypt_sha256.h>
#include <stdarg.h>

#include <proto_api.h>
#include <proto_win.h>
#include <Lm.h>
#include <time.h>

#pragma warning(push)
#pragma warning(disable:4530)
#include <vector>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4514)
#pragma warning(disable:4668)
#include <setupapi.h>
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
#define  MINI_BUFFER_SIZE      256

typedef struct __args_options {
    char* m_classname;
    char* m_input;
    char* m_output;
    char* m_errout;
    char* m_pipename;
    char* m_rsafile;
    char* m_aesfile;
    int m_verbose;
    int m_timeout;
    int m_bufsize;
    int m_hidewindow;
    int m_privenable;
    int m_disablecon;
    char** m_appfiles;
    char** m_outfiles;
    int m_disablefile;
    int m_disabledb;
    char** m_exlogs;
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
int regsplit_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int iregsplit_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
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
int simpleansi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
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
int jsonget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int termproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int listproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int okpassword_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrbackrun_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int procsecget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int procsecset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getprocwin_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getenvval_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int enumwintext_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int protectkill_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int openmux_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int waitevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setevt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int pipesvrtimeout_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int existproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int waitexit_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sendctrlc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int waitctrlc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int rsaenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int rsadec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int rsaverify_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int rsasign_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int aesenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int aesdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sha256sum_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int outputdebug_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int idvtooloutput_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int dllproc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int creatememmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int readmemmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int writememmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrcreatememmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int svrunmapmemmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int outputdebugex_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int regenumkey_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int regenumvalue_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int netservnames_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int arpreq_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int enumdisplay_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setdisplay_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int jsonlist_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsockconn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsockacc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstclisockrd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstclisockwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsvrsockrd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsvrsockwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getmsepoch_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsvrsockrdwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstclisockrdwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int regdelvalue_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int regdelkey_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int handles_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int disabledebug_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sercfgget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sercfgset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int serread_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int serwrite_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int bootuptime_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int lsusb_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int lshwinfo_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int lsmem_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int lscpu_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int lsaudio_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int displayinfo_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getdpi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setdpi_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int setregdword_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int queryregdword_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int evchatsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int evchatcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int stdinev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int stdoutev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sockacc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int nslookup_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);


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
    output_debug_cfg_t cfg={0};
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

    cfg.m_disableflag = 0;
    if (pargs->m_disabledb) {
        cfg.m_disableflag |= WINLIB_DBWIN_DISABLED;
    }
    if (pargs->m_disablefile) {
        cfg.m_disableflag |= WINLIB_FILE_DISABLED;
    }

    if (pargs->m_disablecon) {
        cfg.m_disableflag |= WINLIB_CONSOLE_DISABLED;
    }

    cfg.m_ppoutcreatefile = pargs->m_outfiles;
    cfg.m_ppoutappendfile = pargs->m_appfiles;

    return InitOutputEx(loglvl,&cfg);
}

int parse_get_hex_val(unsigned char ch)
{
    int val=0;
    if (ch >= '0' && ch<='9')
    {
        val = ch - '0';
    }
    else if (ch >= 'a' && ch<='f')
    {
        val = ch - 'a' + 10;
    }
    else if (ch >= 'A' && ch<='F')
    {
        val = ch - 'A' + 10;
    }
    return val;
}


int read_file_whole_stdin(int freed, char* fname, char** ppout, int* psize)
{
    int ret = 0;
    size_t rets;
    int retlen = 0;
    size_t retsize = 0;
    char* pretout = NULL;
    char* ptmpbuf = NULL;
    if (freed) {
        if (ppout && *ppout) {
            free(*ppout);
            *ppout = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppout == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (fname != NULL) {
        return read_file_whole(fname, ppout, psize);
    }

    pretout = *ppout;
    retsize = (size_t)(*psize);

    if (pretout == NULL || retsize < MINI_BUFFER_SIZE) {
        if (retsize < MINI_BUFFER_SIZE) {
            retsize = MINI_BUFFER_SIZE;
        }
        pretout = (char*) malloc(retsize);
        if (pretout == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }
    memset(pretout, 0, retsize);
    while (1) {
        rets = fread(&(pretout[retlen]), 1, (size_t)(retsize - retlen), stdin);
        if (rets == 0) {
            if (feof(stdin)) {
                break;
            }

            if (ferror(stdin)) {
                GETERRNO(ret);
                ERROR_INFO("read stdin [%d] error[%d]", retlen, ret);
                goto fail;
            }
        }
        retlen += (int)rets;
        if (retlen >= (int)retsize) {
            retsize <<= 1;
            ptmpbuf = (char*) malloc(retsize);
            if (ptmpbuf == NULL) {
                GETERRNO(ret);
                goto fail;
            }

            memset(ptmpbuf, 0, retsize);
            if (retlen > 0) {
                memcpy(ptmpbuf, pretout, (size_t)retlen);
            }
            if (pretout && pretout != *ppout) {
                free(pretout);
            }
            pretout = ptmpbuf;
            ptmpbuf = NULL;
        }
    }

    if (*ppout && *ppout != pretout) {
        free(*ppout);
    }
    *ppout = pretout;
    *psize = (int)retsize;
    return retlen;
fail:
    if (pretout && pretout != *ppout) {
        free(pretout);
    }
    pretout = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

int write_file_whole_stdout(char* fname, char* pout, int outlen)
{
    int ret;
    size_t rets;
    if (fname) {
        return write_file_whole(fname, pout, outlen);
    }

    rets = fwrite(pout,(size_t)outlen, 1, stdout);
    if (rets != 1) {
        GETERRNO(ret);
        goto fail;
    }

    return outlen;
fail:
    SETERRNO(ret);
    return ret;
}

void debug_buffer(FILE* fp, char* ptr, int size,const char* fmt,...)
{
    int i, lasti;
    unsigned char* pcur = (unsigned char*)ptr;
    unsigned char* plast = pcur;
    va_list ap;
    if (fmt) {
        va_start(ap,fmt);
        vfprintf(fp,fmt,ap);
        fprintf(fp,"\n");
    }


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
        DEBUG_INFO("CTRL_C_EVENT");
        break;
    case CTRL_BREAK_EVENT:
        DEBUG_INFO("CTRL_BREAK_EVENT");
        break;
    case CTRL_CLOSE_EVENT:
        DEBUG_INFO("CTRL_CLOSE_EVENT");
        break;
    case CTRL_LOGOFF_EVENT:
        DEBUG_INFO("CTRL_LOGOFF_EVENT");
        break;
    case CTRL_SHUTDOWN_EVENT:
        DEBUG_INFO("CTRL_SHUTDOWN_EVENT");
        break;
    default:
        DEBUG_INFO("ctrltype %d", dwCtrlType);
        bret = FALSE;
        break;
    }

    if (bret && st_ExitEvt) {
        DEBUG_INFO("setevent 0x%x", st_ExitEvt);
        SetEvent(st_ExitEvt);
    }

    return bret;
}

static int st_run = 1;

BOOL WINAPI HandlerConsoleRunOk(DWORD dwCtrlType)
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

    if (bret ) {
        st_run = 0;
    }

    return bret;
}

HANDLE set_ctrlc_handle()
{
    BOOL bret;
    int ret;
    if (st_ExitEvt != NULL) {
        return st_ExitEvt;
    }

    st_ExitEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (st_ExitEvt == NULL) {
        GETERRNO(ret);
        ERROR_INFO("create exit event %d\n", ret);
        goto fail;
    }
    bret = SetConsoleCtrlHandler(HandlerConsoleRoutine, TRUE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("SetControlCtrlHandler Error(%d)", ret);
        goto fail;
    }

    return st_ExitEvt;
fail:
    if (st_ExitEvt != NULL) {
        CloseHandle(st_ExitEvt);
    }
    st_ExitEvt = NULL;
    SETERRNO(ret);
    return NULL;
}

void close_ctrlc_handle()
{
    if (st_ExitEvt != NULL) {
        CloseHandle(st_ExitEvt);
    }
    st_ExitEvt = NULL;
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
#include "maptest.cpp"
#include "memop.cpp"
#include "protectkill.cpp"
#include "pipecmd.cpp"
#include "guitest.cpp"
#include "tstjson.cpp"
#include "tstsock.cpp"
#include "tstfile.cpp"
#include "tstev.cpp"

int version_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    REFERENCE_ARG(argc);
    REFERENCE_ARG(parsestate);
    REFERENCE_ARG(popt);
    printf("%s version 1.0.1 compiled at [%s %s] cl version[%d]\n", argv[0], __DATE__, __TIME__, _MSC_VER);
    return 0;
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