#define _LARGEFILE64_SOURCE
#include <ux_output_debug.h>
#include <ux_err.h>
#include <ux_strop.h>
#include <ux_time_op.h>

#include <pthread.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <execinfo.h>
#include <vector>
#include <ux_output_debug_cfg.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#define  UX_OUTPUT_DEBUG(...)  do{fprintf(stderr,"[%s:%d]:",__FILE__,__LINE__),fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\n"); fflush(stderr);} while(0)


#include "ux_output_debug_cfg.cpp"
#include "ux_output_debug_file.cpp"

static int st_output_opened = 0;
static int st_log_inited = 0;
static pthread_mutex_t st_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::vector<DebugOutIO*> *st_log_output_ios = NULL;

int error_out(const char* fmt, ...)
{
    va_list ap;
    int ret = 0;
    va_start(ap, fmt);
    ret += vfprintf(stderr, fmt, ap);
    ret += fprintf(stderr, "\n");
    return ret;
}



void __free_log_output()
{
    if (st_log_output_ios != NULL) {
        while(st_log_output_ios->size() > 0) {
            DebugOutIO* pv = st_log_output_ios->at(0);
            st_log_output_ios->erase(st_log_output_ios->begin());
            delete pv;
        }
        delete st_log_output_ios;
    }
    st_log_output_ios = NULL;
}


#define  MINI_FMT_SIZE           32

int __inner_time_format(int freed, char** ppfmt, size_t *pfmtsize)
{
    char* pretfmt = NULL;
    size_t retsize = 0;
    int retlen = 0;
    int ret;
    size_t sret;
    time_t nowt;
    struct tm nowtime,*prettm;

    if (freed) {
        if (ppfmt && *ppfmt) {
            free(*ppfmt);
            *ppfmt = NULL;
        }
        if (pfmtsize) {
            *pfmtsize = 0;
        }
        return 0;
    }
    if (ppfmt == NULL || pfmtsize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    retsize = *pfmtsize;
    pretfmt = *ppfmt;

    if (pretfmt == NULL || retsize < MINI_FMT_SIZE) {
        if (retsize < MINI_FMT_SIZE) {
            retsize = MINI_FMT_SIZE;
        }
        pretfmt = (char*)malloc(retsize);
        if (pretfmt == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }

    memset(pretfmt , 0, retsize);


    nowt = time(NULL);
    prettm = localtime_r(&nowt,&nowtime);
    if (prettm == NULL) {
        GETERRNO(ret);
        goto fail;
    }
try_again:
    sret = strftime(pretfmt, retsize - 1, "%Y-%m-%d %H:%M:%S", &nowtime);
    if (sret == 0) {
        retsize <<= 1;
        if (pretfmt && pretfmt != *ppfmt) {
            free(pretfmt);
        }
        pretfmt = NULL;
        pretfmt = (char*)malloc(retsize);
        if (pretfmt == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        goto try_again;
    }
    retlen = (int)sret;

    if (*ppfmt && *ppfmt != pretfmt) {
        free(*ppfmt);
    }
    *ppfmt = pretfmt;
    *pfmtsize = retsize;
    return retlen;
fail:
    /*no pretfmt here*/
    if (pretfmt != NULL && pretfmt != *ppfmt) {
        free(pretfmt);
    }
    pretfmt = NULL;
    SETERRNO(ret);
    return ret;
}





const char* _get_loglevel_note(int loglvl)
{
    if (loglvl < BASE_LOG_ERROR) {
        return "<FATAL>";
    } else if (loglvl >= BASE_LOG_ERROR && loglvl < BASE_LOG_WARN) {
        return "<ERROR>";
    } else if (loglvl >= BASE_LOG_WARN && loglvl < BASE_LOG_INFO) {
        return "<WARN>";
    } else if (loglvl >= BASE_LOG_INFO && loglvl < BASE_LOG_DEBUG) {
        return "<INFO>";
    } else if (loglvl >= BASE_LOG_DEBUG && loglvl < BASE_LOG_TRACE) {
        return "<DEBUG>";
    }
    return "<TRACE>";
}


static int __call_out_line(int level, const char* file, int lineno, const char* fmt, va_list ap)
{
    int ret;
    int retsize = 0;
    char* fmttime = NULL;
    size_t timesize = 0;
    char* msg = NULL;
    int msgsize = 0;
    char* locstr = NULL;
    int locsize = 0;
    char* timestr = NULL;
    int tmsize = 0;
    uint32_t i;
    DebugOutIO* pout = NULL;


    ret = __inner_time_format(0, &fmttime, &timesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = str_append_vsnprintf_safe(&msg, &msgsize, fmt, ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = str_append_snprintf_safe(&locstr, &locsize, "[%s:%d]", file, lineno);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = str_append_snprintf_safe(&timestr, &tmsize, "time(0x%llx):%s", (unsigned int)get_cur_ticks(), fmttime);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pthread_mutex_lock(&st_log_mutex);
    for (i = 0; st_log_output_ios != NULL && i < st_log_output_ios->size(); i++) {
        pout = st_log_output_ios->at(i);
        ret = pout->write_log(level, locstr, timestr, _get_loglevel_note(level), msg);
        if (ret < 0) {
            GETERRNO(ret);
            pthread_mutex_unlock(&st_log_mutex);
            goto fail;
        }

        if (retsize < ret) {
            retsize = ret;
        }
    }


    pthread_mutex_unlock(&st_log_mutex);


    str_append_vsnprintf_safe(&msg, &msgsize, NULL, NULL);
    str_append_snprintf_safe(&locstr, &locsize, NULL);
    str_append_snprintf_safe(&timestr, &tmsize, NULL);
    __inner_time_format(1, &fmttime, &timesize);
    return retsize;
fail:
    str_append_vsnprintf_safe(&msg, &msgsize, NULL, NULL);
    str_append_snprintf_safe(&locstr, &locsize, NULL);
    str_append_snprintf_safe(&timestr, &tmsize, NULL);
    __inner_time_format(1, &fmttime, &timesize);
    SETERRNO(ret);
    return ret;
}

void debug_out_string(int level, const char* file, int lineno, const char* fmt, ...)
{
    va_list ap;

    if (st_log_inited == 0 || fmt == NULL) {
        return ;
    }


    va_start(ap, fmt);
    __call_out_line(level, file, lineno, fmt, ap);
    return ;
}



static void __inner_buffer_output(int level, const char* file,int lineno, unsigned char* pBuffer, int buflen, const char* fmt, va_list ap)
{
    int ret;
    char* fmttime = NULL;
    size_t timesize = 0;
    char* msg = NULL;
    int msgsize = 0;
    char* locstr = NULL;
    int locsize = 0;
    char* timestr = NULL;
    int tmsize = 0;
    uint32_t i;
    DebugOutIO* pout = NULL;


    ret = __inner_time_format(0, &fmttime, &timesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = str_append_snprintf_safe(&msg, &msgsize, "buffer[0x%p] size[%d:0x%x]", pBuffer, buflen, buflen);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    if (fmt != NULL) {
        ret = str_append_vsnprintf_safe(&msg, &msgsize, " ", ap);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        ret = str_append_vsnprintf_safe(&msg, &msgsize, fmt, ap);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    ret = str_append_snprintf_safe(&locstr, &locsize, "[%s:%d]", file, lineno);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = str_append_snprintf_safe(&timestr, &tmsize, "time(0x%llx):%s", (unsigned int)get_cur_ticks(), fmttime);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    pthread_mutex_lock(&st_log_mutex);
    if (st_log_output_ios != NULL) {
        for (i = 0; i < st_log_output_ios->size(); i++) {
            pout = st_log_output_ios->at(i);
            ret = pout->write_buffer_log(level, locstr, timestr, _get_loglevel_note(level), msg, pBuffer, buflen);
        }
    }


    pthread_mutex_unlock(&st_log_mutex);


    str_append_vsnprintf_safe(&msg, &msgsize, NULL, NULL);
    str_append_snprintf_safe(&locstr, &locsize, NULL);
    str_append_snprintf_safe(&timestr, &tmsize, NULL);
    __inner_time_format(1, &fmttime, &timesize);
    return;
fail:
    str_append_vsnprintf_safe(&msg, &msgsize, NULL, NULL);
    str_append_snprintf_safe(&locstr, &locsize, NULL);
    str_append_snprintf_safe(&timestr, &tmsize, NULL);
    __inner_time_format(1, &fmttime, &timesize);
    SETERRNO(ret);
    return;
}

static int __output_backtrace_format_out(int level, int stkidx, const char* file, int lineno, void** ppfuncs , int funclen, const char* fmt, va_list ap)
{
    int retlen = 0;
    int ret;
    char** ppsymbols=NULL;
    int i;
    char* msg=NULL;
    int msgsize=0;
    char* pretfmt=NULL;
    int fmtsize=0;
    char* locstr=NULL;
    int locsize=0;
    char* timestr=NULL;
    int tmsize=0;
    DebugOutIO* pout=NULL;


    ret = __inner_time_format(0, &pretfmt, (size_t*)&fmtsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    ret = str_append_snprintf_safe(&locstr, &locsize, "[%s:%d]", file, lineno);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = str_append_snprintf_safe(&timestr, &tmsize, "time(0x%llx):%s", (unsigned int)get_cur_ticks(), pretfmt);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    ret = append_snprintf_safe(&msg,&msgsize," SYMBOLSFUNC ");
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (fmt != NULL) {
        ret = str_append_vsnprintf_safe(&msg, &msgsize, " ", ap);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        ret = str_append_vsnprintf_safe(&msg, &msgsize, fmt, ap);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }



    ppsymbols = backtrace_symbols(ppfuncs,funclen);
    if (ppsymbols == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    for(i=stkidx;i<funclen;i++) {
        ret = append_snprintf_safe(&msg,&msgsize,"\nFUNC[%d] [%s] [%p]", i - stkidx,ppsymbols[i], ppfuncs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }


    pthread_mutex_lock(&st_log_mutex);
    for(i=0;st_log_output_ios!=NULL && i < (int)st_log_output_ios->size();i++) {
        pout = st_log_output_ios->at(i);
        ret = pout->write_log(level, locstr, timestr, _get_loglevel_note(level), msg);       
    }

    pthread_mutex_unlock(&st_log_mutex);

    if (ppsymbols) {
        free(ppsymbols);
    }
    ppsymbols = NULL;

    snprintf_safe(&msg, &msgsize,NULL);
    __inner_time_format(1,&pretfmt,(size_t*)&fmtsize);

    return retlen;
fail:
    if (ppsymbols) {
        free(ppsymbols);
    }
    ppsymbols = NULL;
    snprintf_safe(&msg, &msgsize,NULL);
    __inner_time_format(1,&pretfmt,(size_t*)&fmtsize);
    SETERRNO(ret);
    return ret;
}

void debug_buffer_fmt(int level, const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, ...)
{
    va_list ap;
    if (st_log_inited == 0) {
        return;
    }
    if (fmt != NULL) {
        va_start(ap, fmt);
    }
    __inner_buffer_output(level, file, lineno, pBuffer, buflen, fmt, ap);
    return;
}


void backtrace_out_string(int level,int stkidx, const char* file, int lineno, const char* fmt,...)
{
    va_list ap;
    void** ppfuncs = NULL;
    int funcsize=0;
    int funclen = 0;
    int ret;
    if (st_log_inited == 0) {
        return;
    }
    if (fmt != NULL) {
        va_start(ap, fmt);
    }

    funcsize = 4;


    while(1) {
        if (ppfuncs != NULL) {
            free(ppfuncs);
        }
        ppfuncs = NULL;

        ppfuncs = (void**) malloc(sizeof(*ppfuncs) * funcsize);
        if (ppfuncs == NULL) {
            GETERRNO(ret);
            goto out;
        }

        ret = backtrace(ppfuncs,funcsize);
        if (ret < funcsize) {
            funclen = ret;
            break;
        }
        funcsize <<= 1;
    }


    ret = __output_backtrace_format_out(level,stkidx + 1,file,lineno,ppfuncs , funclen,fmt,ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

out:
    if (ppfuncs) {
        free(ppfuncs);
    }
    ppfuncs = NULL;
    return ;
}

int __init_basic_log_env(void)
{
    if (st_log_inited != 0) {
        return 0;
    }
    pthread_mutex_init(&st_log_mutex,NULL);

    if (st_output_opened == 0) {
        openlog(NULL, LOG_PID, LOG_USER);
        st_output_opened = 1;
    }

    st_log_output_ios = new std::vector<DebugOutIO*>();
    return 1;
}

void __fini_basic_log_env(void)
{
    __free_log_output();
    pthread_mutex_destroy(&st_log_mutex);
    if (st_output_opened > 0) {
        closelog();
        st_output_opened = 0;
    }
    return;
}

int init_log(int loglvl)
{
    int ret;
    OutputCfg* pcfgs =new OutputCfg();
    OutfileCfg* p = NULL;

    p = new OutfileCfg();
    ret = p->set_file_type(NULL,UXLIB_DEBUGOUT_FILE_STDERR,0,0);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    ret = p->set_level(loglvl);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = pcfgs->insert_config(*p);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    p = NULL;

    ret = init_log_ex(pcfgs);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (p) {
        delete p;
    }
    p = NULL;

    if (pcfgs) {
        delete pcfgs;
    }
    pcfgs = NULL;

    return 0;
fail:
    if (p) {
        delete p;
    }
    p = NULL;

    if (pcfgs) {
        delete pcfgs;
    }
    pcfgs = NULL;
    SETERRNO(ret);
    return ret;
}

void fini_log(void)
{
    __fini_basic_log_env();
    st_log_inited = 0;
    return;
}


int init_log_ex(OutputCfg* pcfgs)
{
    int ret;
    OutfileCfg* pcfg = NULL;
    int i;
    DebugOutIO* pout = NULL;
    if (st_log_inited == 0) {
        ret = __init_basic_log_env();
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        st_log_inited = 1;
    }



    pthread_mutex_lock(&st_log_mutex);

    __free_log_output();
    ASSERT_IF(st_log_output_ios == NULL);
    st_log_output_ios =  new std::vector<DebugOutIO*>();
    for (i = 0;; i++) {
        pcfg = pcfgs->get_config(i);
        if (pcfg == NULL) {
            break;
        }
        pout = get_cfg_out(pcfg);
        if (pout == NULL) {
            GETERRNO(ret);
            pthread_mutex_unlock(&st_log_mutex);
            goto fail;
        }
        st_log_output_ios->push_back(pout);
    }

    pthread_mutex_unlock(&st_log_mutex);
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}
