#include <ux_output_debug.h>
#include <ux_args.h>
#include <extargs.h>
#include <ux_err.h>
#include <ux_time_op.h>
#include <ux_proc.h>
#include <ux_fileop.h>
#include <ux_regex.h>
#include <ux_strop.h>
#include <ux_sock.h>

#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <ctype.h>

#include <crypt_md5.h>

typedef struct __args_options {
    int m_verbose;
    int m_timeout;
    char* m_input;
    char* m_output;
    char* m_errout;
    int m_withevt;
    int m_mask;
} args_options_t, *pargs_options_t;

int debug_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sleep_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int run_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int runsingle_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int mntdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getmnt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getdev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getfstype_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int realpath_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int regexec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int iregexec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int split_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int splitre_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int mkdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int cpfile_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int readoffset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int writeoffset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int readlines_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int exists_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int md5_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsockconn_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsockacc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstclisockrd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsvrsockwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);

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


#include "args_options.cpp"

int init_log_verbose(pargs_options_t pargs)
{
    int loglvl = BASE_LOG_ERROR;
    int ret;
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
    ret = INIT_LOG(loglvl);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("init [%d] verbose error[%d]", pargs->m_verbose, ret);
        SETERRNO(ret);
        return ret;
    }
    return 0;
}

#include "tstdebug.cpp"
#include "tstproc.cpp"
#include "tstregex.cpp"
#include "tstdev.cpp"
#include "tststr.cpp"
#include "tstfile.cpp"
#include "tstsock.cpp"

int main(int argc, char* argv[])
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
    if (ret < 0) {
        GETERRNO(ret);
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