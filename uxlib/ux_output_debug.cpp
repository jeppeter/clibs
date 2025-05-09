#define _LARGEFILE64_SOURCE
#include <ux_output_debug.h>
#include <ux_err.h>
#include <ux_strop.h>

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

#include "ux_output_debug_cfg.cpp"
#include "ux_output_debug_file.cpp"

static int st_output_loglvl = BASE_LOG_DEFAULT;
static int st_output_opened = 0;
static int st_log_inited = 0;
static pthread_mutex_t st_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::vector<DebugOutIO*> *st_log_output_ios = NULL;



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

    __time64_t nowt;
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



typedef int (output_func_t)(int level, char* outstr);

static int __syslog_output(int level, char* outstr)
{
    int priority = LOG_ERR;
    int outlen=0;
    switch (level) {
    case BASE_LOG_FATAL:
        priority = LOG_EMERG;
        break;
    case BASE_LOG_ERROR:
        priority = LOG_ERR;
        break;
    case BASE_LOG_WARN:
        priority = LOG_WARNING;
        break;
    case BASE_LOG_INFO:
        priority = LOG_NOTICE;
        break;
    case BASE_LOG_DEBUG:
        priority = LOG_INFO;
        break;
    case BASE_LOG_TRACE:
        priority = LOG_DEBUG;
        break;
    }

    if (st_output_opened == 0) {
        openlog(NULL, LOG_PID, LOG_USER);
        st_output_opened = 1;
    }

    if (outstr != NULL) {
    	outlen = strlen(outstr);	
    }
    

    syslog(priority, "%s\n", outstr);
    return outlen;
}

static int __stderr_output(int level, char* outstr)
{
	int outlen = 0;
    level = level;
    fprintf(stderr, "%s\n", outstr);
    fflush(stderr);
    if (outstr != NULL) {
    	outlen = strlen(outstr);
    }
    return outlen;
}


static int __output_format_buffer_v(char** ppbuf, int *pbufsize, int level, const char* file, int lineno, const char* fmt, va_list ap)
{
    int retlen = 0;
    int ret;
    struct timespec ts;
    uint64_t millsecs;

    if (ppbuf == NULL || pbufsize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    if (fmt == NULL) {    	
        if (*ppbuf) {
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }

    switch (level) {
    case BASE_LOG_FATAL:
        ret = snprintf_safe(ppbuf, pbufsize, "<FATAL>");
        break;
    case BASE_LOG_ERROR:
        ret = snprintf_safe(ppbuf, pbufsize, "<ERROR>");
        break;
    case BASE_LOG_WARN:
        ret = snprintf_safe(ppbuf, pbufsize, "<WARN>");
        break;
    case BASE_LOG_INFO:
        ret = snprintf_safe(ppbuf, pbufsize, "<INFO>");
        break;
    case BASE_LOG_DEBUG:
        ret = snprintf_safe(ppbuf, pbufsize, "<DEBUG>");
        break;
    case BASE_LOG_TRACE:
        ret = snprintf_safe(ppbuf, pbufsize, "<TRACE>");
        break;
    default:
        ret = -EINVAL;
        SETERRNO(ret);
        break;
    }
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = clock_gettime(CLOCK_MONOTONIC , &ts);
    if (ret  < 0) {
        GETERRNO(ret);
        goto fail;
    }

    millsecs = ts.tv_sec * 1000;
    millsecs += (ts.tv_nsec / (1000 * 1000));

    ret = append_snprintf_safe(ppbuf, pbufsize, " [%s:%d]:time(%lld:0x%llx)", file, lineno, millsecs, millsecs);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = append_vsnprintf_safe(ppbuf, pbufsize, fmt, ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    retlen = ret;
    return retlen;
fail:
    snprintf_safe(ppbuf, pbufsize,NULL);
    SETERRNO(ret);
    return ret;
}

static int __output_format_buffer(char** ppbuf, int *pbufsize, int level, const char* file, int lineno, const char* fmt, ...)
{
    va_list ap;
    if (fmt != NULL) {
    	va_start(ap, fmt);	
    }    
    return __output_format_buffer_v(ppbuf, pbufsize, level, file, lineno, fmt, ap);
}

static int __call_out_line(int level, const char* file, int lineno, const char* fmt, va_list ap)
{
    char* pbuf = NULL;
    int bufsize = 0;
    int ret;

    ret = __output_format_buffer_v(&pbuf, &bufsize, level, file, lineno, fmt, ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = fn(level, pbuf);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    __output_format_buffer_v(&pbuf, &bufsize, level, file, lineno, NULL, ap);
    return 0;
fail:
    __output_format_buffer_v(&pbuf, &bufsize, level, file, lineno, NULL, ap);
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



static void __inner_buffer_output(int level, const char* file,int lineno, unsigned char* pBuffer, int buflen, const char* fmt, va_list ap, output_func_t fn)
{
    int ret;
    char* pbuf = NULL;
    int bufsize = 0;
    unsigned char* pcurptr, *plastptr;
    int i;

    ret = __output_format_buffer(&pbuf, &bufsize, level, file, lineno, "buf[%p] size[%d:0x%x]", pBuffer, buflen, buflen);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    if (fmt != NULL) {
        ret = append_vsnprintf_safe(&pbuf, &bufsize, fmt, ap);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    ret = fn(level, pbuf);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    pcurptr = pBuffer;
    plastptr = pcurptr;
    for (i = 0; i < buflen ; i++) {
        if ((i % 16) == 0) {
            if (i > 0) {
                ret = append_snprintf_safe(&pbuf, &bufsize, "    ");
                if (ret < 0) {
                    GETERRNO(ret);
                    goto out;
                }
                while (plastptr != pcurptr) {
                    if (isprint(*plastptr)) {
                        ret = append_snprintf_safe(&pbuf, &bufsize, "%c", *plastptr);
                    } else {
                        ret = append_snprintf_safe(&pbuf, &bufsize, ".");
                    }
                    if (ret < 0) {
                        GETERRNO(ret);
                        goto out;
                    }
                    plastptr ++;
                }

                ret = fn(level, pbuf);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto out;
                }
            }
            ret = snprintf_safe(&pbuf, &bufsize, "0x%08x:", i);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
        }
        ret = append_snprintf_safe(&pbuf,&bufsize," 0x%02x",*pcurptr);
        if (ret < 0) {
        	GETERRNO(ret);
        	goto out;
        }
        pcurptr ++;
    }

    if (pcurptr != plastptr) {
    	while((i % 16)  != 0) {
    		ret = append_snprintf_safe(&pbuf,&bufsize,"     ");
    		if (ret < 0) {
    			GETERRNO(ret);
    			goto out;
    		}
    		i ++;
    	}

    	ret = append_snprintf_safe(&pbuf,&bufsize,"    ");
    	if (ret < 0) {
    		GETERRNO(ret);
    		goto out;
    	}

    	while(pcurptr != plastptr) {
    		if (isprint(*plastptr)) {
    			ret = append_snprintf_safe(&pbuf,&bufsize,"%c",*plastptr);
    		} else {
    			ret = append_snprintf_safe(&pbuf,&bufsize,".");
    		}
    		if (ret < 0) {
    			GETERRNO(ret);
    			goto out;
    		}
    		plastptr ++;
    	}

    	ret = fn(level,pbuf);
    	if (ret < 0) {
    		GETERRNO(ret);
    		goto out;
    	}    	
    }

out:
    snprintf_safe(&pbuf, &bufsize, NULL);
    return;
}

static int __output_backtrace_format_v(char** ppbuf, int *pbufsize, int level, int stkidx, const char* file, int lineno, void** ppfuncs , int funclen, const char* fmt, va_list ap)
{
    int retlen = 0;
    int ret;
    struct timespec ts;
    uint64_t millsecs;
    char** ppsymbols=NULL;
    int i;

    if (ppbuf == NULL || pbufsize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    if (fmt == NULL) {
        if (*ppbuf) {
            free(*ppbuf);
        }
        *ppbuf = NULL;
        *pbufsize = 0;
        return 0;
    }

    switch (level) {
    case BASE_LOG_FATAL:
        ret = snprintf_safe(ppbuf, pbufsize, "<FATAL>");
        break;
    case BASE_LOG_ERROR:
        ret = snprintf_safe(ppbuf, pbufsize, "<ERROR>");
        break;
    case BASE_LOG_WARN:
        ret = snprintf_safe(ppbuf, pbufsize, "<WARN>");
        break;
    case BASE_LOG_INFO:
        ret = snprintf_safe(ppbuf, pbufsize, "<INFO>");
        break;
    case BASE_LOG_DEBUG:
        ret = snprintf_safe(ppbuf, pbufsize, "<DEBUG>");
        break;
    case BASE_LOG_TRACE:
        ret = snprintf_safe(ppbuf, pbufsize, "<TRACE>");
        break;
    default:
        ret = -EINVAL;
        SETERRNO(ret);
        break;
    }
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = clock_gettime(CLOCK_MONOTONIC , &ts);
    if (ret  < 0) {
        GETERRNO(ret);
        goto fail;
    }

    millsecs = ts.tv_sec * 1000;
    millsecs += (ts.tv_nsec / (1000 * 1000));

    ret = append_snprintf_safe(ppbuf, pbufsize, " [%s:%d]:time(%lld:0x%llx)", file, lineno, millsecs, millsecs);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = append_snprintf_safe(ppbuf,pbufsize," SYMBOLSFUNC ");
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = append_vsnprintf_safe(ppbuf, pbufsize, fmt, ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ppsymbols = backtrace_symbols(ppfuncs,funclen);
    if (ppsymbols == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    for(i=stkidx;i<funclen;i++) {
        ret = append_snprintf_safe(ppbuf,pbufsize,"\nFUNC[%d] [%s] [%p]", i - stkidx,ppsymbols[i], ppfuncs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }
    retlen = ret;

    if (ppsymbols) {
        free(ppsymbols);
    }
    ppsymbols = NULL;

    return retlen;
fail:
    if (ppsymbols) {
        free(ppsymbols);
    }
    ppsymbols = NULL;
    snprintf_safe(ppbuf, pbufsize,NULL);
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
    char* pbuf=NULL;
    int bufsize=0;
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


    ret = __output_backtrace_format_v(&pbuf,&bufsize,level,stkidx + 1,file,lineno,ppfuncs , funclen,fmt,ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }




out:
    __output_backtrace_format_v(&pbuf,&bufsize,level,0,NULL,0,NULL,0,NULL,ap);
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
    ret = __init_basic_log_env();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    st_log_inited = 1;

    st_output_loglvl = loglvl;
    return 0;
fail:
    __fini_basic_log_env();
    st_log_inited = 0;
    SETERRNO(ret);
    return ret;
}

void fini_log(void)
{
    __fini_basic_log_env();
    st_log_inited = 0;
    return;
}


int init_output_ex(OutputCfg* pcfgs)
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

    pthread_mutex_lock(&st_log_mutex);
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}
