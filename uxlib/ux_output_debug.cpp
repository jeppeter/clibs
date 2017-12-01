#include <ux_output_debug.h>
#include <ux_err.h>
#include <ux_strop.h>
#include <syslog.h>

static int st_output_loglvl = BASE_LOG_DEFAULT;

int init_log(int loglvl)
{
    openlog(NULL, LOG_PID, LOG_USER);
    st_output_loglvl = loglvl;
    return 0;
}

void fini_log(void)
{
    closelog();
}

static int __output_format_buffer(char** ppbuf, int *pbufsize, int level, const char* file, int lineno, const char* fmt, va_list ap)
{
    int retlen = 0;
    int ret;

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

    switch (loglvl) {
    case BASE_LOG_FATAL:
        ret = snprintf_safe(ppbuf, pbufsize, "<fatal>");
        break;
    case BASE_LOG_ERROR:
        ret = snprintf_safe(ppbuf, pbufsize, "<error>");
        break;
    case BASE_LOG_WARN:
        ret = snprintf_safe(ppbuf, pbufsize, "<warn>");
        break;
    case BASE_LOG_INFO:
        ret = snprintf_safe(ppbuf, pbufsize, "<info>");
        break;
    case BASE_LOG_DEBUG:
        ret = snprintf_safe(ppbuf, pbufsize, "<debug>");
        break;
    case BASE_LOG_TRACE:
        ret = snprintf_safe(ppbuf, pbufsize, "<trace>");
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

    ret = append_snprintf_safe(ppbuf,pbufsize," [%s:%d]", file,lineno);
    if (ret < 0) {
    	GETERRNO(ret);
    	goto fail;
    }

    ret = append_vsnprintf_safe(ppbuf,pbufsize,fmt,ap);
    if (ret < 0) {
    	GETERRNO(ret);
    	goto fail;
    }

    ret = append_snprintf_safe(ppbuf,pbufsize,"\n");
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


void debug_out_string(int level, const char* file, int lineno, const char* fmt, ...)
{
	int ret;
	char* pbuf=NULL;
	int bufsize=0;
	int outlen=0;
	va_list ap;
	int priority = LOG_NOTICE;

	if (level > st_output_loglvl || fmt == NULL) {
		return ;
	}

	va_start(ap,fmt);
	ret = __output_format_buffer(&pbuf,&bufsize,level,file,lineno,fmt,ap);
	if (ret < 0) {
		goto out;
	}

	switch(level) {
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
		priority = LOG_INFO;
	}

	syslog()

out:
	__output_format_buffer(&pbuf,&bufsize,level,file,lineno,NULL,ap);
	return;
}