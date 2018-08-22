#include <ux_output_debug.h>
#include <ux_args.h>
#include <extargs.h>
#include <ux_err.h>
#include <ux_time_op.h>
#include <ux_proc.h>
#include <ux_fileop.h>
#include <ux_regex.h>
#include <ux_strop.h>

#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <ctype.h>

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

int debug_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    ret = init_log_verbose(pargs);
    if (ret < 0) {
        GETERRNO(ret);
        return ret;
    }

    TRACE_INFO("hello world");
    DEBUG_INFO("hello world");
    INFO_INFO("hello world");
    WARN_INFO("hello world");
    ERROR_INFO("hello world");
    FATAL_INFO("hello world");

    TRACE_BUFFER(pargs, sizeof(*pargs));
    DEBUG_BUFFER(pargs, sizeof(*pargs));
    INFO_BUFFER(pargs, sizeof(*pargs));
    WARN_BUFFER(pargs, sizeof(*pargs));
    ERROR_BUFFER(pargs, sizeof(*pargs));
    FATAL_BUFFER(pargs, sizeof(*pargs));

    TRACE_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    DEBUG_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    INFO_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    WARN_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    ERROR_BUFFER_FMT(pargs, sizeof(*pargs), "args for");
    FATAL_BUFFER_FMT(pargs, sizeof(*pargs), "args for");

    return 0;
}

int sleep_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    int i;
    int curmills;
    int smills;
    uint64_t sticks;
    uint64_t cticks;
    pargs_options_t pargs = (pargs_options_t) popt;
    ret = init_log_verbose(pargs);
    if (ret < 0) {
        GETERRNO(ret);
        return ret;
    }


    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        curmills = atoi(parsestate->leftargs[i]);
        sticks = get_cur_ticks();
        smills = curmills;
        if ((i % 2) == 0) {
            if (smills > 50) {
                smills -= 10;
            }
        } else {
            if (smills > 50) {
                smills += 10;
            }
        }
        sched_out(smills);
        ret = time_left(sticks, curmills);
        cticks = get_cur_ticks();
        fprintf(stdout, "[%d] [%d] [%lld:0x%llx] [%lld:0x%llx] %s\n",
                i, curmills, (long long int)sticks, (long long unsigned int)sticks,
                (long long int) cticks, (long long unsigned int)cticks,
                (ret > 0 ? "not expired" : "expired"));
    }

    ret = 0;
    SETERRNO(ret);
    return ret;
}

static int st_evtfd = -1;

void sig_handler(int signo)
{
    uint64_t u;
    int ret;
    if (st_evtfd >= 0) {
        u = 1;
        ret = write(st_evtfd, &u, sizeof(u));
        if (ret != sizeof(u)) {
            GETERRNO(ret);
            fprintf(stderr, "int write error[%d]", ret);
        }
    }
    return;
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



int run_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char** ppout = NULL;
    char** pperr = NULL;
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    char* pout = NULL;
    int outsize = 0;
    char* perr = NULL;
    int errsize = 0;
    sighandler_t sighdl = SIG_ERR;
    int exitcode;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    if (pargs->m_input) {
        ret = read_file_whole(pargs->m_input, &pin, &insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        inlen = ret;
    }

    if (pargs->m_output != NULL) {
        ppout = &pout;
    }

    if (pargs->m_errout != NULL) {
        pperr = &perr;
    }

    if (pargs->m_withevt) {
        st_evtfd = eventfd(0, 0);
        if (st_evtfd < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not create event fd error[%d]\n", ret);
            goto out;
        }

        sighdl = signal(SIGINT, sig_handler);
        if (sighdl == SIG_ERR) {
            GETERRNO(ret);
            fprintf(stderr, "signal SIGINT error[%d]", ret);
            goto out;
        }
    }

    ret = run_cmd_event_outputv(st_evtfd, pin, inlen, ppout, &outsize, pperr, &errsize, &exitcode, pargs->m_timeout, parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "run command error [%d]\n", ret);
        goto out;
    }

    fprintf(stdout, "run command [");
    for (i = 0; parsestate->leftargs[i]; i++) {
        if (i > 0) {
            fprintf(stdout, ",");
        }
        fprintf(stdout, "%s", parsestate->leftargs[i]);
    }
    fprintf(stdout, "] exitcode [%d]\n", exitcode);
    if (pargs->m_input != NULL) {
        fprintf(stdout, "input out\n");
        __debug_buf(stdout, pin, inlen);
    } else {
        fprintf(stdout, "input none\n");
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout, "output\n");
        __debug_buf(stdout, pout, outsize);
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout, "errout\n");
        __debug_buf(stdout, perr, errsize);
    }

    ret = 0;
out:
    run_cmd_event_outputv(-1, NULL, 0, &pout, &outsize, &perr, &errsize, NULL, 0, NULL);
    read_file_whole(NULL, &pin, &insize);
    if (st_evtfd >= 0) {
        close(st_evtfd);
    }
    st_evtfd = -1;
    SETERRNO(ret);
    return ret;
}


int mntdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* mntdir = NULL;
    int mntsize = 0;
    int i;
    char* dev = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        dev = parsestate->leftargs[i];
        ret = dev_get_mntdir(dev, &mntdir, &mntsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not get [%s] error[%d]", dev, ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout, "[%s] mount [%s]\n", dev, mntdir);
        } else {
            fprintf(stdout, "[%s] not mounted\n", dev);
        }
    }

    ret = 0;
out:
    dev_get_mntdir(NULL, &mntdir, &mntsize);
    SETERRNO(ret);
    return ret;
}

int getmnt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* mntdir = NULL;
    int mntsize = 0;
    int i;
    char* path = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* prealpath = NULL;
    int realsize = 0;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        path = parsestate->leftargs[i];
        ret = realpath_safe(path, &prealpath, &realsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get real path for [%s] error[%d]\n", path, ret);
            goto out;
        }
        ret = path_get_mntdir(prealpath, &mntdir, &mntsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not get [%s] error[%d]", path, ret);
            goto out;
        }
        fprintf(stdout, "[%s] mount [%s]\n", path, mntdir);
    }

    ret = 0;
out:
    realpath_safe(NULL, &prealpath, &realsize);
    path_get_mntdir(NULL, &mntdir, &mntsize);
    SETERRNO(ret);
    return ret;
}


int getdev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pdev = NULL;
    int devsize = 0;
    int i;
    char* path = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        path = parsestate->leftargs[i];
        ret = mntdir_get_dev(path, &pdev, &devsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s]device error[%d]\n", path, ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout, "[%s] mount [%s]\n", path, pdev);
        } else {
            fprintf(stdout, "[%s] not device mount\n", path);
        }

    }

    ret = 0;
out:
    mntdir_get_dev(NULL, &pdev, &devsize);
    SETERRNO(ret);
    return ret;
}

int getfstype_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pfstype = NULL;
    int fssize = 0;
    int i;
    char* path = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        path = parsestate->leftargs[i];
        ret = mntdir_get_fstype(path, &pfstype, &fssize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s]device error[%d]\n", path, ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout, "[%s] mount [%s]\n", path, pfstype);
        } else {
            fprintf(stdout, "[%s] not mount directory\n", path);
        }

    }

    ret = 0;
out:
    mntdir_get_fstype(NULL, &pfstype, &fssize);
    SETERRNO(ret);
    return ret;
}

int realpath_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* prealpath = NULL;
    int realsize = 0;
    int i;
    char* path = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs[i] != NULL; i++) {
        path = parsestate->leftargs[i];
        ret = realpath_safe(path, &prealpath, &realsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s]realpath error[%d]\n", path, ret);
            goto out;
        }
        fprintf(stdout, "[%d][%s] realpath [%s]\n", i, path, prealpath);
    }

    ret = 0;
out:
    realpath_safe(NULL, &prealpath, &realsize);
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
    init_log_verbose(pargs);
    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2) {
        ret = -EINVAL;
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
            fprintf(stdout, "    left[%s]\n", pcurstr);
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
    int handled = 0;
    char** pplines=NULL;
    int lsize=0,llen=0;

    argc = argc;
    argv = argv;
    init_log_verbose(pargs);
    if (parsestate->leftargs != NULL) {
        while (parsestate->leftargs[argcnt] != NULL) {
            argcnt ++;
        }
    }

    if (argcnt < 2 && pargs->m_input == NULL) {
        ret = -EINVAL;
        ERROR_INFO("arg must restr instr...");
        goto out;
    }

    ret = regex_compile(parsestate->leftargs[0], REGEX_IGNORE_CASE, &preg);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not compile [%s]", parsestate->leftargs[0]);
        goto out;
    }

    if (argcnt >= 2) {
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
                fprintf(stdout, "    left[%s]\n", pcurstr);
                handled ++;
                goto try_again;
            } else {
                if (handled == 0) {
                    fprintf(stdout, "[%s] not find in [%s]\n", parsestate->leftargs[0], pcurstr);
                }
            }
        }
    } else {
        ret = read_file_lines(pargs->m_input, &pplines,&lsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not read [%s] error[%d]\n", pargs->m_input, ret);
            goto out;
        }
        llen = ret;
        for (i=0;i<llen;i++) {
            pcurstr = pplines[i];
            handled = 0;
file_try_again:
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
                fprintf(stdout, "    left[%s]\n", pcurstr);
                handled ++;
                goto file_try_again;
            } else {
                if (handled == 0) {
                    fprintf(stdout, "[%s] not find in [%s]\n", parsestate->leftargs[0], pcurstr);
                }
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
    read_file_lines(NULL,&pplines,&lsize);
    regex_exec(NULL, NULL, &pstartpos, &pendpos, &possize);
    regex_compile(NULL, REGEX_NONE, &preg);
    SETERRNO(ret);
    return ret;
}


int split_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* splitchars = NULL;
    char* instr = NULL;
    int i, j;
    int cnt = 0;
    char** pparrs = NULL;
    int arrsize = 0, arrlen = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }
    argc = argc;
    argv = argv;
    init_log_verbose(pargs);


    if (cnt < 1) {
        ret = -EINVAL;
        fprintf(stderr, "[spltichars] instr ... to set\n");
        goto out;
    }

    if (cnt == 1) {
        instr = parsestate->leftargs[0];
        ret = split_chars(instr, NULL, &pparrs, &arrsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "split [%s] error[%d]", instr, ret);
            goto out;
        }
        arrlen = ret;
        fprintf(stdout, "split [%s] with NULL\n", instr);
        for (i = 0; i < arrlen; i++) {
            fprintf(stdout, "    [%d]=[%s]\n", i, pparrs[i]);
        }
    } else {
        splitchars = parsestate->leftargs[0];
        for (i = 1; i < cnt; i++) {
            instr = parsestate->leftargs[i];
            ret = split_chars(instr, splitchars, &pparrs, &arrsize);
            if (ret < 0) {
                GETERRNO(ret);
                fprintf(stderr, "split [%s] with [%s] error[%d]\n", instr, splitchars, ret);
                goto out;
            }
            arrlen = ret;
            fprintf(stdout, "split [%s] with [%s]\n", instr, splitchars);
            for (j = 0; j < arrlen; j++) {
                fprintf(stdout, "    [%d]=[%s]\n", j, pparrs[j]);
            }
        }
    }

    ret = 0;
out:
    split_chars(NULL, NULL, &pparrs, &arrsize);
    SETERRNO(ret);
    return ret;
}

int splitre_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* splitchars = NULL;
    char* instr = NULL;
    int i, j;
    int cnt = 0;
    char** pparrs = NULL;
    int arrsize = 0, arrlen = 0;
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    if (parsestate->leftargs) {
        while (parsestate->leftargs[cnt] != NULL) {
            cnt ++;
        }
    }
    argc = argc;
    argv = argv;
    init_log_verbose(pargs);


    if (cnt < 2) {
        ret = -EINVAL;
        fprintf(stderr, "splti_regular_expression instr ... to set\n");
        goto out;
    }

    splitchars = parsestate->leftargs[0];
    for (i = 1; i < cnt; i++) {
        instr = parsestate->leftargs[i];
        ret = split_chars_re(instr, splitchars , REGEX_NONE, &pparrs, &arrsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "split [%s] with [%s] error[%d]\n", instr, splitchars, ret);
            goto out;
        }
        arrlen = ret;
        fprintf(stdout, "split [%s] with [%s]\n", instr, splitchars);
        for (j = 0; j < arrlen; j++) {
            fprintf(stdout, "    [%d]=[%s]\n", j, pparrs[j]);
        }
    }

    ret = 0;
out:
    split_chars_re(NULL, NULL, REGEX_NONE, &pparrs, &arrsize);
    SETERRNO(ret);
    return ret;
}

int mkdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* dir = NULL;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i] != NULL; i++) {
        dir = parsestate->leftargs[i];
        ret = mkdir_p(dir, pargs->m_mask);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not mkdir [%s] error[%d]\n", dir, ret);
            goto out;
        }

        fprintf(stdout, "[%d][%s] [%s]\n", i, dir, ret > 0 ? "created" : "exists");
    }

    ret  = 0;
out:
    SETERRNO(ret);
    return ret;
}
int cpfile_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* srcfile = NULL;
    char* dstfile = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;


    srcfile = parsestate->leftargs[0];
    dstfile = parsestate->leftargs[1];
    ret = cp_file(srcfile, dstfile);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "cp [%s] => [%s] error[%d]\n", srcfile, dstfile, ret);
        goto out;
    }

    fprintf(stdout, "cp [%s] => [%s] size[%d]\n", srcfile, dstfile, ret);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int readoffset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* infile = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;
    uint64_t offset = 0;
    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    GET_OPT_NUM64(offset, "offset");
    GET_OPT_INT(bufsize, "buffer size");

    if (pargs->m_input == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the input by --input|-i\n");
        goto out;
    }
    infile = pargs->m_input;

    pbuf = (char*)malloc(bufsize);
    if (pbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "alloc %d error[%d]\n", bufsize, ret);
        goto out;
    }

    ret = read_offset_file(infile, offset, pbuf, bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read [%s] error[%d]\n", infile, ret );
        goto  out;
    }
    buflen = ret;
    fprintf(stdout, "read [%s] ret[%d]\n", infile, buflen);
    __debug_buf(stdout, pbuf, buflen);
    ret = 0;
out:
    if (pbuf) {
        free(pbuf);
    }
    pbuf = NULL;
    SETERRNO(ret);
    return ret;
}


int writeoffset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* infile = NULL;
    char* outfile = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;
    uint64_t offset = 0;
    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    GET_OPT_NUM64(offset, "offset");

    if (pargs->m_input == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the input by --input|-i\n");
        goto out;
    }
    infile = pargs->m_input;
    if (pargs->m_output == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the output by --output|-o\n");
        goto out;
    }
    outfile = pargs->m_output;

    ret = read_file_whole(infile, &pbuf, &bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read [%s] error[%d]\n", infile, ret );
        goto out;
    }
    buflen = ret;

    ret = write_offset_file(outfile, offset, pbuf, buflen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] error[%d]\n", outfile, ret);
        goto out;
    }

    fprintf(stdout, "read [%s] => [%s] offset[%ld:0x%lx] len[%d]\n", infile, outfile, offset, offset, buflen);
    __debug_buf(stdout, pbuf, buflen);
    ret = 0;
out:
    read_file_whole(NULL, &pbuf, &bufsize);
    SETERRNO(ret);
    return ret;
}

int readlines_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char** pplines = NULL;
    int lsize = 0, llen = 0;
    int i, j;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* infile = NULL;
    int ret;
    int maxlen = 0;
    int maxi;

    init_log_verbose(pargs);

    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i] != NULL ; i++) {
        infile = parsestate->leftargs[i];
        ret = read_file_lines(infile, &pplines, &lsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "read [%s] error[%d]\n", infile, ret);
            goto out;
        }
        llen = ret;

        maxi = 1;
        maxlen = 1;
        while (maxi < llen) {
            maxi *= 10;
            maxlen ++;
        }

        fprintf(stdout, "[%d] [%s] lines[%d]\n", i, infile, llen);
        for (j = 0; j < llen; j++) {
            fprintf(stdout, "    [%*d][%s]\n", maxlen, j, pplines[j]);
        }
    }

    ret = 0;
out:
    read_file_lines(NULL, &pplines, &lsize);
    SETERRNO(ret);
    return ret;
}

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