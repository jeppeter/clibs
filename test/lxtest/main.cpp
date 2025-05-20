#define  _XOPEN_SOURCE
#include <time.h>
#include <ux_output_debug.h>
#include <ux_output_debug_cfg.h>
#include <ux_args.h>
#include <extargs.h>
#include <ux_err.h>
#include <ux_time_op.h>
#include <ux_proc.h>
#include <ux_fileop.h>
#include <ux_regex.h>
#include <ux_strop.h>
#include <ux_sock.h>
#include <ux_tty.h>
#include <ux_libev.h>
#include <ux_dbg.h>

#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <ctype.h>
#include <termios.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <lzma.h>
#include <assert.h>

#include <crypt_md5.h>
#include <base64_code.h>

#include "pingtotal.h"

typedef struct __args_options {
    int m_verbose;
    int m_timeout;
    char* m_input;
    char* m_output;
    char* m_errout;
    int m_withevt;
    int m_mask;
    int m_bauderate;
    int m_xonxoff;
    int m_csbits;
    int m_times;
    int m_nexttime;
    char** m_logfiles;
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
int tstclisockwr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int tstsvrsockrd_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int backtrace_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int fmttime_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ttyread_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ttywrite_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ttycfgget_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int ttycfgset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int useropen_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int unlzma_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int writev_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int scandir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int evchatsvr_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int evchatcli_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int sockaddrinfmt_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int noechopass_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int encbase64_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int decbase64_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int icmpping_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int logtst_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int procmap_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);
int backtrace2_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt);


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

#if 1
#define  LOG_DEBUG(...) do {                                                                      \
    fprintf(stderr,"[%d][%s:%d]:",getpid(),__FILE__,__LINE__);                       \
    fprintf(stderr,__VA_ARGS__);                                                                  \
    fprintf(stderr, "\n");                                                                        \
    fflush(stderr);                                                                               \
}while(0)
#else
#define  LOG_DEBUG(...) do{} while(0)
#endif

#define PARSE_VALUE(vnum,typev,note)                                                              \
do{                                                                                               \
    if (pcurptr != NULL) {                                                                        \
        ret = parse_number(pcurptr,&num,&pendptr);                                                \
        if (ret < 0) {                                                                            \
            GETERRNO(ret);                                                                        \
            fprintf(stderr,"parse [%s:%d] [%s] error[%d]\n",__FILE__,__LINE__,pcurptr,ret);       \
            goto fail;                                                                            \
        }                                                                                         \
        vnum = (typev) num;                                                                       \
        pcurptr = pendptr;                                                                        \
        if (*pcurptr == ',') {                                                                    \
            pcurptr ++;                                                                           \
        }                                                                                         \
        if (*pcurptr == '\0') {                                                                   \
            pcurptr = NULL;                                                                       \
        }                                                                                         \
        LOG_DEBUG("parse [%s] [%s]",note,pcurptr != NULL ? pcurptr : "NULL" );                    \
    }                                                                                             \
} while(0)

int parse_type(char** pptype,int *itype)
{
    int type = UXLIB_DEBUGOUT_FILE_TRUNC;

    if (pptype == NULL || *pptype == NULL || **pptype == '\0') {
        if (itype != NULL) {
            *itype = type;
        }
        if (pptype != NULL) {
            *pptype = NULL;
        }
        return 0;
    }
    char* ptype = *pptype;
    int slen = 0;
    int ret;
    if (strncmp(ptype,"trunc",5) == 0) {
        type = UXLIB_DEBUGOUT_FILE_TRUNC;
        slen = 5;
    } else if (strncmp(ptype,"stderr",6) == 0) {
        type = UXLIB_DEBUGOUT_FILE_STDERR;
        slen = 6;
    } else if (strncmp(ptype,"append",6) == 0) {
        type = UXLIB_DEBUGOUT_FILE_APPEND;
        slen = 6;
    } else if (strncmp(ptype,"background",10) == 0) {
        type = UXLIB_DEBUGOUT_FILE_BACKGROUND;
        slen = 10;
    } else if (strncmp(ptype,"rotate",6) == 0) {
        type = UXLIB_DEBUGOUT_FILE_ROTATE;
        slen = 6;
    } else {        
        ret = -EINVAL;
        fprintf(stderr, "%s not valid\n", ptype);
        goto fail;

    }

    ptype += slen;
    if (*ptype != '\0' && *ptype != ',') {
        ret = -EINVAL;
        fprintf(stderr, "%s not valid\n", ptype);
        goto fail;
    }

    if (*ptype == ',') {
        ptype += 1;
    }
    *pptype = ptype;
    *itype = type;

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int parse_fmtflags(char** pptype,int *ifmtflags)
{
    int cfmtflags = 0;
    int slen = 0;
    char* curptr=NULL;
    if (pptype == NULL || *pptype == NULL || **pptype == '\0') {
        *ifmtflags = UXLIB_OUTPUT_ALL_MASK;
        if (pptype != NULL) {
            *pptype = NULL;
        }
        return 0;
    }

    curptr = *pptype;

    while(*curptr != '\0' && *curptr != ',') {
        if (strncmp(curptr,"location",8) == 0) {
            cfmtflags |= UXLIB_OUTPUT_LOCATION;
            slen = 8;
        } else if (strncmp(curptr,"timestamp",9) == 0) {
            cfmtflags |= UXLIB_OUTPUT_TIMESTAMP;
            slen = 9;
        } else if (strncmp(curptr,"level",5) == 0) {
            cfmtflags |= UXLIB_OUTPUT_LEVEL;
            slen = 5;
        } else if (strncmp(curptr,"msg",3) == 0) {
            cfmtflags |= UXLIB_OUTPUT_MSG;
            slen = 3;
        } else if (strncmp(curptr,"all",3) == 0) {
            cfmtflags |= UXLIB_OUTPUT_ALL_MASK;
            slen = 3;
        } else {
            break;
        }
        curptr += slen;
        if (*curptr == '|') {
            curptr += 1;
        }
    }

    if (cfmtflags == 0) {
        cfmtflags = UXLIB_OUTPUT_ALL_MASK;
    }

    if (*curptr == ',') {
        curptr += 1;
    }

    *pptype = curptr;
    *ifmtflags = cfmtflags;
    return 0;
}

int parse_level(char** pptype, int *ilevel,int deflevel)
{
    int ret=0;
    char* curptr=NULL;
    int slen = 0;
    int level = deflevel;
    if (pptype == NULL || *pptype == NULL || **pptype== '\0') {
        *ilevel = deflevel;
        if (pptype != NULL) {
            *pptype = NULL;
        }
        return 0;
    }
    curptr = *pptype;

    if (strncmp(curptr,"fatal",5) == 0)  {
        level = BASE_LOG_FATAL;
        slen = 5;
    } else if (strncmp(curptr,"error",5) == 0) {
        level = BASE_LOG_ERROR;
        slen = 5;
    } else if (strncmp(curptr,"warn",4) == 0) {
        level = BASE_LOG_WARN;
        slen = 4;
    } else if (strncmp(curptr,"info",4) == 0) {
        level = BASE_LOG_INFO;
        slen = 4;
    } else if (strncmp(curptr,"debug",5) == 0) {
        level = BASE_LOG_DEBUG;
        slen = 5;
    } else if (strncmp(curptr,"trace",5) == 0) {
        level = BASE_LOG_TRACE;
        slen = 5;
    } else {
        ret = -EINVAL;
        fprintf(stderr, "%s not valid\n", curptr);
        goto fail;
    }

    curptr += slen;
    if (*curptr != ',' && *curptr != '\0') {
        ret = -EINVAL;
        fprintf(stderr, "%s not valid\n",curptr );
        goto fail;
    }

    if (*curptr == ',') {
        curptr += 1;
    }
    *pptype = curptr;
    *ilevel = level;

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}


int parse_cfgs(OutputCfg& cfgs, const char* line,int defaultlevel)
{
    OutfileCfg* pcfg=NULL;
    char* fname=NULL;
    int level = defaultlevel;
    int fmtflag = UXLIB_OUTPUT_ALL_MASK;
    int type = UXLIB_DEBUGOUT_FILE_TRUNC;
    int ntype = UXLIB_DEBUGOUT_FILE_TRUNC;
    int maxfiles = 0;
    uint64_t size = 0;
    char* pcurptr = (char*)line;
    int len=0;
    uint64_t num;
    char* pendptr=NULL;
    char* lastptr = NULL;
    int ret;
    char* pdir=NULL;
    int dirsize=0;
    if (line == NULL) {
        return 0;
    }

    pcfg = new OutfileCfg();
    LOG_DEBUG("pcurptr [%s]",pcurptr);
    if (strncmp(pcurptr,"stderr,",7)==0 || strcmp(pcurptr,"stderr") == 0) {
        pcurptr += 6;
        if (*pcurptr == ',') {
            pcurptr += 1;
        }
        type = UXLIB_DEBUGOUT_FILE_STDERR;
        if (*pcurptr == '\0') {
            pcurptr = NULL;
        }
    } else if (strncmp(line,"background,",11) == 0 || strcmp(pcurptr,"background") == 0) {
        pcurptr += 10;
        if (*pcurptr == ',') {
            pcurptr += 1;
        }
        type = UXLIB_DEBUGOUT_FILE_BACKGROUND;
        if (*pcurptr == '\0') {
            pcurptr = NULL;
        }
    }  else {
        pcurptr = strchr((char*)line,',');
        if (pcurptr != NULL) {
            pcurptr ++;
        }

        if (pcurptr == NULL) {
            fname = strdup(line);
            LOG_DEBUG("fname [%s]", fname);
        } else {
            len = (int)(pcurptr - line);
            LOG_DEBUG("len %d",len);
            fname = (char*)malloc((size_t)len);
            if (fname == NULL) {
                GETERRNO(ret);
                goto fail;
            }
            memset(fname,0,(size_t)len);
            memcpy(fname, line, (size_t)(len-1));
            LOG_DEBUG("fname [%s]",fname);
        }        

        if ( pcurptr != NULL && *pcurptr == '\0') {
            pcurptr = NULL;
        }
    }

    LOG_DEBUG("pcurptr [%s]",pcurptr);
    lastptr = pcurptr;
    ret = parse_type(&pcurptr,&ntype);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    if (ntype != type && type != UXLIB_DEBUGOUT_FILE_TRUNC && lastptr != NULL && *lastptr != '\0') {
        ret = -EINVAL;
        LOG_DEBUG("not valid type");
        goto fail;
    } else if (lastptr != NULL && *lastptr != '\0') {
        /*we set type*/
        LOG_DEBUG("type [%d] => [%d]",type,ntype);
        type = ntype;
    } 
    LOG_DEBUG("type [%d]",type);

    LOG_DEBUG("pcurptr [%s]",pcurptr);
    ret = parse_fmtflags(&pcurptr,&fmtflag);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    LOG_DEBUG("fmtflag [0x%x]",fmtflag);

    LOG_DEBUG("pcurptr [%s]",pcurptr);
    PARSE_VALUE(size,uint64_t,"size");
    LOG_DEBUG("size [0x%lx]",size);
    LOG_DEBUG("pcurptr [%s]",pcurptr);
    PARSE_VALUE(maxfiles,int,"maxfiles");
    LOG_DEBUG("maxfiles [%d]",maxfiles);
    LOG_DEBUG("pcurptr [%s]",pcurptr);
    ret = parse_level(&pcurptr,&level,defaultlevel);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    LOG_DEBUG("pcurptr [%s]",pcurptr);
    LOG_DEBUG("level [%d]", level);

    ret = pcfg->set_file_type(fname,type,size,maxfiles);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"[%s:%d] set file type error[%d]\n",__FILE__,__LINE__,ret);
        goto fail;
    }
    ret = pcfg->set_level(level);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"[%s:%d] set level error[%d]\n",__FILE__,__LINE__,ret);
        goto fail;
    }
    ret = pcfg->set_format(fmtflag);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr,"[%s:%d] set format error[%d]\n",__FILE__,__LINE__,ret);
        goto fail;
    }

    if (type != UXLIB_DEBUGOUT_FILE_STDERR && type != UXLIB_DEBUGOUT_FILE_BACKGROUND) {
        /*now we should get the dirname*/
        ret = get_dirname(fname,&pdir,&dirsize);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        if (pdir != NULL && strlen(pdir) > 0) {
            ret = mkdir_p(pdir,0644);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
        }
    }

    ret = cfgs.insert_config(*pcfg);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    get_dirname(NULL,&pdir,&dirsize);
    if (fname) {
        free(fname);
    }
    fname = NULL;
    if (pcfg){
        delete pcfg;
    }
    pcfg = NULL;
    LOG_DEBUG("out 0");
    return 1;
fail:
    get_dirname(NULL,&pdir,&dirsize);
    if (fname) {
        free(fname);
    }
    fname = NULL;
    if (pcfg){
        delete pcfg;
    }
    pcfg = NULL;
    SETERRNO(ret);
    return ret;
}


int init_log_verbose(pargs_options_t pargs)
{
    int loglvl = BASE_LOG_ERROR;
    int ret;
    int cnt = 0;
    int i;
    OutputCfg* pcfgs = NULL;
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

    pcfgs = new OutputCfg();


    for(i=0;pargs->m_logfiles != NULL && pargs->m_logfiles[i];i++) {
        ret = parse_cfgs(*pcfgs,pargs->m_logfiles[i],loglvl);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        cnt += 1;
    }



    if (cnt > 0) {
        LOG_DEBUG("pcfgs");
        ret = init_log_ex(pcfgs);
        if (ret < 0) {
            GETERRNO(ret);
            LOG_DEBUG("error %d", ret);
            goto fail;
        }
        LOG_DEBUG("ret %d", ret);
    } else {
        ret = INIT_LOG(loglvl);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("init [%d] verbose error[%d]", pargs->m_verbose, ret);
            SETERRNO(ret);
            goto fail;
        }
    }

    if (pcfgs) {
        delete pcfgs;
    }
    pcfgs = NULL;

    return 0;
fail:
    if (pcfgs) {
        delete pcfgs;
    }
    pcfgs = NULL;
    SETERRNO(ret);
    return ret;
}

void print_buffer(FILE* fp, unsigned char* pbuf, int buflen, const char* fmt, ...)
{
    va_list ap;
    int i;
    int lasti;
    fprintf(fp, "buffer [%p] size[0x%x:%d]", pbuf, buflen, buflen);
    if (fmt != NULL) {
        va_start(ap, fmt);
        fprintf(fp, " ");
        vfprintf(fp, fmt, ap);
    }
    for (i = 0, lasti = 0; i < buflen; i++) {
        if ((i % 16) == 0) {
            if (i > 0) {
                fprintf(fp, "    ");
                while (lasti != i) {
                    if (pbuf[lasti] >= ' ' && pbuf[lasti] <= 0x7e) {
                        fprintf(fp, "%c", pbuf[lasti]);
                    } else {
                        fprintf(fp, ".");
                    }
                    lasti ++;
                }
            }
            fprintf(fp, "\n0x%08x:", i);
        }
        fprintf(fp, " 0x%02x", pbuf[i]);
    }

    if (lasti != i) {
        while ((i % 16) != 0) {
            fprintf(fp, "     ");
            i ++;
        }
        fprintf(fp, "    ");
        while (lasti < buflen) {
            if (pbuf[lasti] >= ' ' && pbuf[lasti] <= 0x7e) {
                fprintf(fp, "%c", pbuf[lasti]);
            } else {
                fprintf(fp, ".");
            }
            lasti ++;
        }
    }
    fprintf(fp,"\n");
    return;
}

static int st_evtfd = -1;

void sig_handler(int signum)
{
    uint64_t lval=1;
    if (signum == SIGINT && st_evtfd >= 0) {
        ERROR_INFO("call SIGINT write evtfd %d",st_evtfd);
        write(st_evtfd,&lval,sizeof(lval));
    } else if (signum == SIGSEGV) {
        BACKTRA
    }
    return ;
}

int init_sighandler(void)
{
    int ret;
    sighandler_t sigret;
    if (st_evtfd < 0) {
        st_evtfd = eventfd(0,EFD_NONBLOCK);
        if (st_evtfd < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }
    sigret = signal(SIGINT,sig_handler);
    if (sigret == SIG_ERR) {
        GETERRNO(ret);
        goto fail;
    }

    return st_evtfd;
fail:
    if (st_evtfd >= 0) {
        close(st_evtfd);
    }
    st_evtfd = -1;
    SETERRNO(ret);
    return ret;
}

void fini_sighandler(void)
{
    if (st_evtfd >= 0) {
        close(st_evtfd);
    }
    st_evtfd = -1;
    return;
}


#include "tstdebug.cpp"
#include "tstproc.cpp"
#include "tstregex.cpp"
#include "tstdev.cpp"
#include "tststr.cpp"
#include "tstfile.cpp"
#include "tstsock.cpp"
#include "tstev.cpp"
#include "tstnet.cpp"


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