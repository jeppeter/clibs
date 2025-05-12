#ifndef __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__
#define __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__

#include <stdio.h>
#include <stdlib.h>

#ifndef __UX_INNER_DEFINED__
#define __UX_INNER_DEFINED__
#endif
#include <ux_inner.h>
#undef  __UX_INNER_DEFINED__



#define  BASE_LOG_FATAL        0
#define  BASE_LOG_ERROR        10
#define  BASE_LOG_WARN         20
#define  BASE_LOG_INFO         30
#define  BASE_LOG_DEBUG        40
#define  BASE_LOG_TRACE        50

#define  BASE_LOG_DEFAULT      BASE_LOG_ERROR

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

void debug_out_string(int level,const char* file,int lineno,const char* fmt,...);
void debug_buffer_fmt(int level,const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
void backtrace_out_string(int level,int stkidx, const char* file, int lineno, const char* fmt,...);

int init_log(int loglvl);
void fini_log();

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#define __INNER_BACKGROUND_OUTPUT(level,...) do{debug_out_string(level,__FILE__,__LINE__,__VA_ARGS__);} while(0)

#define __OUTPUT_INFO(lvl,...)                                      \
    do{                                                             \
        __INNER_BACKGROUND_OUTPUT(lvl,__VA_ARGS__);                 \
    }while(0)

#define FATAL_INFO(...)   __OUTPUT_INFO(BASE_LOG_FATAL,__VA_ARGS__)
#define ERROR_INFO(...)   __OUTPUT_INFO(BASE_LOG_ERROR,__VA_ARGS__)
#define WARN_INFO(...)    __OUTPUT_INFO(BASE_LOG_WARN,__VA_ARGS__)
#define INFO_INFO(...)    __OUTPUT_INFO(BASE_LOG_INFO,__VA_ARGS__)
#define DEBUG_INFO(...)   __OUTPUT_INFO(BASE_LOG_DEBUG,__VA_ARGS__)
#define TRACE_INFO(...)   __OUTPUT_INFO(BASE_LOG_TRACE,__VA_ARGS__)


#define __OUTPUT_BUFFER(lvl,ptr,blen)                                                           \
    do{                                                                                         \
        debug_buffer_fmt(lvl,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);                  \
    }while(0)

#define __OUTPUT_BUFFER_FMT(lvl,ptr,blen,...)                                                       \
    do{                                                                                             \
        debug_buffer_fmt(lvl,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);               \
    }while(0)

#define  FATAL_BUFFER(ptr,blen)  __OUTPUT_BUFFER(BASE_LOG_FATAL,ptr,blen)
#define  ERROR_BUFFER(ptr,blen)  __OUTPUT_BUFFER(BASE_LOG_ERROR,ptr,blen)
#define  WARN_BUFFER(ptr,blen)   __OUTPUT_BUFFER(BASE_LOG_WARN,ptr,blen)
#define  INFO_BUFFER(ptr,blen)   __OUTPUT_BUFFER(BASE_LOG_INFO,ptr,blen)
#define  DEBUG_BUFFER(ptr,blen)  __OUTPUT_BUFFER(BASE_LOG_DEBUG,ptr,blen)
#define  TRACE_BUFFER(ptr,blen)  __OUTPUT_BUFFER(BASE_LOG_TRACE,ptr,blen)


#define  FATAL_BUFFER_FMT(ptr,blen,...)  __OUTPUT_BUFFER_FMT(BASE_LOG_FATAL,ptr,blen,__VA_ARGS__)
#define  ERROR_BUFFER_FMT(ptr,blen,...)  __OUTPUT_BUFFER_FMT(BASE_LOG_ERROR,ptr,blen,__VA_ARGS__)
#define  WARN_BUFFER_FMT(ptr,blen,...)   __OUTPUT_BUFFER_FMT(BASE_LOG_WARN,ptr,blen,__VA_ARGS__)
#define  INFO_BUFFER_FMT(ptr,blen,...)   __OUTPUT_BUFFER_FMT(BASE_LOG_INFO,ptr,blen,__VA_ARGS__)
#define  DEBUG_BUFFER_FMT(ptr,blen,...)  __OUTPUT_BUFFER_FMT(BASE_LOG_DEBUG,ptr,blen,__VA_ARGS__)
#define  TRACE_BUFFER_FMT(ptr,blen,...)  __OUTPUT_BUFFER_FMT(BASE_LOG_TRACE,ptr,blen,__VA_ARGS__)


#define  BACKTRACE_FATAL(stkidx,...)            backtrace_out_string(BASE_LOG_FATAL,(stkidx),__FILE__,__LINE__,__VA_ARGS__)
#define  BACKTRACE_ERROR(stkidx,...)            backtrace_out_string(BASE_LOG_ERROR,(stkidx),__FILE__,__LINE__,__VA_ARGS__)
#define  BACKTRACE_WARN(stkidx,...)             backtrace_out_string(BASE_LOG_WARN,(stkidx),__FILE__,__LINE__,__VA_ARGS__)    
#define  BACKTRACE_INFO(stkidx,...)             backtrace_out_string(BASE_LOG_INFO,(stkidx),__FILE__,__LINE__,__VA_ARGS__)
#define  BACKTRACE_DEBUG(stkidx,...)            backtrace_out_string(BASE_LOG_DEBUG,(stkidx),__FILE__,__LINE__,__VA_ARGS__)
#define  BACKTRACE_TRACE(stkidx,...)            backtrace_out_string(BASE_LOG_TRACE,(stkidx),__FILE__,__LINE__,__VA_ARGS__)

#define  INIT_LOG(loglvl)  init_log(loglvl)
#define  FINI_LOG()        fini_log()



#endif /* __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__ */
