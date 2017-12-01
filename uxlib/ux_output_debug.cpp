#include <ux_output_debug.h>
#include <ux_err.h>
#include <ux_strop.h>
#include <syslog.h>

static int st_output_loglvl = BASE_LOG_DEFAULT;
static int st_output_opened = 0;

int init_log(int loglvl)
{
    if (st_output_opened == 0) {
        openlog(NULL, LOG_PID, LOG_USER);
        st_output_opened = 1;
    }
    st_output_loglvl = loglvl;
    return 0;
}

void fini_log(void)
{
    if (st_output_opened > 0) {
        closelog();
        st_output_opened = 0;
    }
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
    

    syslog(priority, "%s", outstr);
    return outlen;
}

static int __stderr_output(int level, char* outstr)
{
	int outlen = 0;
    level = level;
    fprintf(stderr, "%s", outstr);
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
    snprintf_safe(ppbuf, pbufsize);
    SETERRNO(ret);
    return ret;
}

static int __output_format_buffer(char** ppbuf, int *pbufsize, int level, const char* file, int lineno, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    return __output_format_buffer_v(ppbuf, pbufsize, level, file, lineno, fmt, ap);
}

static int __call_out_line(int level, const char* file, int lineno, const char* fmt, va_list ap, output_func_t fn)
{
    char* pbuf = NULL;
    int bufsize = 0;

    ret = __output_format_buffer_v(&pbuf, &bufsize, level, file, lineno, fmt, ap);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = append_snprintf_safe(&pbuf, &bufsize, "\n");
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

    if (level > st_output_loglvl || fmt == NULL) {
        return ;
    }

    va_start(ap, fmt);
    __call_out_line(level, file, lineno, fmt, ap, __syslog_output);
    return ;
}

void console_out_string(int level, const char* file, int lineno, const char* fmt, ...)
{
    va_list ap;
    if (level > st_output_loglvl || fmt == NULL) {
        return ;
    }

    va_start(ap, fmt);
    __call_out_line(level, file, lineno, fmt, ap, __stderr_output);
    return ;
}


static void __inner_buffer_output(int level, const char* file, lineno, unsigned char* pBuffer, int buflen, const char* fmt, va_list ap, output_func_t fn)
{
    int ret;
    char* pbuf = NULL;
    int bufsize = 0;
    va_list ap;
    unsigned char* pcurptr, plastptr;
    int i;


    ret = __output_format_buffer(&pbuf, &bufsize, level, file, lineno, "buf[%p] size[%d:0x%x]", pBuffer, buflen, buflen);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    if (fmt != NULL) {
        va_start(ap, fmt);
        ret = append_vsnprintf_safe(&pbuf, &bufsize, fmt, ap);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    }

    ret = append_snprintf_safe(&pbuf, &bufsize, "\n");
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = fn(level, pbuf);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    /*now put output*/
    append_snprintf_safe(&pbuf, &bufsize, NULL);

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
                ret = append_snprintf_safe(&pbuf, &bufsize, "\n");
                if (ret < 0) {
                    GETERRNO(ret);
                    goto out;
                }
                ret = fn(level, pbuf);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto out;
                }
            }
            ret = snprintf_safe(&pbuf, &bufsize, "0x%08x", i);
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
    	while(i < 16) {
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
    	ret = append_snprintf_safe(&pbuf,&bufsize,"\n");
    	if (ret < 0) {
    		GETERRNO(ret);
    		goto out;
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

void debug_buffer_fmt(int level, const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, ...)
{
    va_list ap;
    if (level > st_output_loglvl) {
        return;
    }
    if (fmt != NULL) {
        va_start(ap, fmt);
    }
    __inner_buffer_output(level, file, lineno, pBuffer, buflen, fmt, ap, __syslog_output);
    return;
}

void console_buffer_fmt(int level,const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...)
{
    va_list ap;
    if (level > st_output_loglvl) {
        return;
    }
    if (fmt != NULL) {
        va_start(ap, fmt);
    }
    __inner_buffer_output(level, file, lineno, pBuffer, buflen, fmt, ap, __stderr_output);
    return;
}