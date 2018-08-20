#include <ux_output_debug.h>
#include <ux_args.h>
#include <extargs.h>
#include <ux_err.h>
#include <ux_time_op.h>
#include <ux_proc.h>
#include <ux_fileop.h>

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
} args_options_t, *pargs_options_t;

int debug_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sleep_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int run_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int mntdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getmnt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getdev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int getfstype_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);

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
    int ret=0;
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


    for (i=0;parsestate->leftargs[i] != NULL;i++) {
    	curmills = atoi(parsestate->leftargs[i]);
    	sticks = get_cur_ticks();
    	smills = curmills;
    	if ((i%2) == 0){
    		if (smills > 50) {
    			smills -= 10;
    		}
    	} else {
    		if (smills > 50) {
    			smills += 10;
    		}
    	}
    	sched_out(smills);
    	ret = time_left(sticks,curmills);
    	cticks = get_cur_ticks();
    	fprintf(stdout,"[%d] [%d] [%lld:0x%llx] [%lld:0x%llx] %s\n",
    			i,curmills,(long long int)sticks,(long long unsigned int)sticks,
    			(long long int) cticks,(long long unsigned int)cticks,
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
        ret = write(st_evtfd,&u,sizeof(u));
        if (ret != sizeof(u)) {
            GETERRNO(ret);
            fprintf(stderr,"int write error[%d]",ret);
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
    int ret=0;
    char** ppout=NULL;
    char** pperr=NULL;
    char* pin=NULL;
    int insize=0;
    int inlen=0;
    char* pout=NULL;
    int outsize=0;
    char* perr=NULL;
    int errsize=0;
    sighandler_t sighdl=SIG_ERR;
    int exitcode;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    if (pargs->m_input) {
        ret = read_file_whole(pargs->m_input,&pin,&insize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr,"read [%s] error[%d]\n", pargs->m_input,ret);
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
        st_evtfd = eventfd(0,0);
        if (st_evtfd < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not create event fd error[%d]\n",ret);
            goto out;
        }

        sighdl = signal(SIGINT, sig_handler);
        if (sighdl == SIG_ERR) {
            GETERRNO(ret);
            fprintf(stderr,"signal SIGINT error[%d]",ret);
            goto out;
        }
    }

    ret = run_cmd_event_outputv(st_evtfd,pin,inlen,ppout,&outsize,pperr,&errsize,&exitcode,pargs->m_timeout,parsestate->leftargs);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"run command error [%d]\n",ret);
        goto out;
    }

    fprintf(stdout,"run command [");
    for (i=0;parsestate->leftargs[i];i++) {
        if (i > 0) {
            fprintf(stdout,",");
        }
        fprintf(stdout,"%s", parsestate->leftargs[i]);
    }
    fprintf(stdout,"] exitcode [%d]\n", exitcode);
    if (pargs->m_input != NULL) {
        fprintf(stdout,"input out\n");
        __debug_buf(stdout,pin,inlen);
    }

    if (pargs->m_output != NULL) {
        fprintf(stdout,"output\n");
        __debug_buf(stdout,pout,outsize);
    }

    if (pargs->m_errout != NULL) {
        fprintf(stdout,"errout\n");
        __debug_buf(stdout,perr,errsize);
    }

    ret = 0;
out:
    run_cmd_event_outputv(-1, NULL, 0,&pout, &outsize, &perr, &errsize, NULL, 0, NULL);
    read_file_whole(NULL,&pin,&insize);
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
    char* mntdir=NULL;
    int mntsize=0;
    int i;
    char* dev=NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i=0;parsestate->leftargs[i]!=NULL;i++) {
        dev = parsestate->leftargs[i];
        ret = dev_get_mntdir(dev, &mntdir,&mntsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr,"can not get [%s] error[%d]", dev,ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout,"[%s] mount [%s]\n", dev, mntdir);
        } else {
            fprintf(stdout,"[%s] not mounted\n", dev);
        }
    }

    ret = 0;
out:
    dev_get_mntdir(NULL,&mntdir,&mntsize);
    SETERRNO(ret);
    return ret;
}

int getmnt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* mntdir=NULL;
    int mntsize=0;
    int i;
    char* path=NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* prealpath=NULL;
    int realsize=0;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i=0;parsestate->leftargs[i]!=NULL;i++) {
        path = parsestate->leftargs[i];
        ret = realpath_safe(path,&prealpath,&realsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr,"get real path for [%s] error[%d]\n", path, ret);
            goto out;
        }
        ret = path_get_mntdir(prealpath, &mntdir,&mntsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr,"can not get [%s] error[%d]", path,ret);
            goto out;
        }
        fprintf(stdout,"[%s] mount [%s]\n", path, mntdir);
    }

    ret = 0;
out:
    realpath_safe(NULL,&prealpath,&realsize);
    path_get_mntdir(NULL,&mntdir,&mntsize);
    SETERRNO(ret);
    return ret;    
}


int getdev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pdev=NULL;
    int devsize=0;
    int i;
    char* path=NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i=0;parsestate->leftargs[i]!=NULL;i++) {
        path = parsestate->leftargs[i];
        ret = mntdir_get_dev(path,&pdev,&devsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s]device error[%d]\n", path, ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout,"[%s] mount [%s]\n", path, pdev);    
        } else {
            fprintf(stdout,"[%s] not device mount\n", path);
        }
        
    }

    ret = 0;
out:
    mntdir_get_dev(NULL,&pdev,&devsize);
    SETERRNO(ret);
    return ret;    
}

int getfstype_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* pfstype=NULL;
    int fssize=0;
    int i;
    char* path=NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i=0;parsestate->leftargs[i]!=NULL;i++) {
        path = parsestate->leftargs[i];
        ret = mntdir_get_fstype(path,&pfstype,&fssize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "get [%s]device error[%d]\n", path, ret);
            goto out;
        }
        if (ret > 0) {
            fprintf(stdout,"[%s] mount [%s]\n", path, pfstype);    
        } else {
            fprintf(stdout,"[%s] not mount directory\n", path);
        }
        
    }

    ret = 0;
out:
    mntdir_get_fstype(NULL,&pfstype,&fssize);
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