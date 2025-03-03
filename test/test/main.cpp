

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
#include <algorithm>
#include <memory>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4514)
#pragma warning(disable:4668)
#include <setupapi.h>
#pragma warning(pop)


#include <sddl.h>
#include <aclapi.h>


#pragma warning(pop)

#if _MSC_VER >= 1910
#pragma warning(push)
/*disable Spectre warnings*/
#pragma warning(disable:5045)
#endif


#define  MIN_SID_SIZE          32
#define  MINI_BUFFER_SIZE      256

typedef struct __args_options {
    int m_verbose;
    int m_isexist;
    int m_isfile;
    int m_isdir;
} args_options_t, *pargs_options_t;

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"Netapi32.lib")

#ifdef __cplusplus
extern "C" {
#endif





#define PIPE_NONE                0
#define PIPE_READY               1
#define PIPE_WAIT_READ           2
#define PIPE_WAIT_WRITE          3
#define PIPE_WAIT_CONNECT        4


#ifdef __cplusplus
};
#endif

#include "args_options.cpp"



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



int _tmain(int argc, TCHAR* argv[])
{
    char** args = NULL;
    int ret = 0;
    args_options_t argsoption;
    pextargs_state_t pextstate = NULL;
    const char* name;

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

    if (argsoption.m_isexist != 0)  {
        if (pextstate->leftargs == NULL && pextstate->leftargs[0] == NULL) {
            ret = 1;
            goto out;
        }
        name = pextstate->leftargs[0];
        if (exist_file(name) || exist_dir(name)) {
            /*ok*/
        } else {
            ret = 1;
            goto out;
        }

    } else if (argsoption.m_isfile) {
        if (pextstate->leftargs == NULL && pextstate->leftargs[0] == NULL) {
            ret = 1;
            goto out;
        }
        name = pextstate->leftargs[0];
        if (exist_file(name)) {
            /*ok*/
        } else {
            ret = 1;
            goto out;
        }        
    } else if (argsoption.m_isdir) {
        if (pextstate->leftargs == NULL && pextstate->leftargs[0] == NULL) {
            ret = 1;
            goto out;
        }
        name = pextstate->leftargs[0];
        if (exist_dir(name)) {
            /*ok*/
        } else {
            ret = 1;
            goto out;
        }        

    } else {
        ret = 1;
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