#ifndef  __WIN_OUTPUT_DEBUG_H__
#define  __WIN_OUTPUT_DEBUG_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define  BASE_LOG_FATAL        0
#define  BASE_LOG_ERROR        10
#define  BASE_LOG_WARN         20
#define  BASE_LOG_INFO         30
#define  BASE_LOG_DEBUG        40
#define  BASE_LOG_TRACE        50

#define  BASE_LOG_DEFAULT      BASE_LOG_ERROR


#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#define WIN_CONSOLE_OUTPUT     1
#define WIN_BACKGROUND_OUTPUT  1

#ifdef __cplusplus
extern "C" {
#endif

WINLIB_API void DebugOutString(int loglvl,const char* file,int lineno,const char* fmt,...);
WINLIB_API void ConsoleOutString(int loglvl,const char* file,int lineno,const char* fmt,...);
WINLIB_API void DebugBufferFmt(int loglvl,const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
WINLIB_API void ConsoleBufferFmt(int loglvl,const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
WINLIB_API int  InitOutput(int loglvl);
WINLIB_API void FiniOutput();
WINLIB_API int error_out(const char* fmt, ...);


#ifdef __cplusplus
};
#endif

#define __INNER_BACKGROUND_OUTPUT(loglvl,fmt,...) DebugOutString(loglvl,__FILE__,__LINE__,fmt,__VA_ARGS__)
#define __INNER_CONSOLE_OUTPUTU(loglvl,fmt,...)  ConsoleOutString(loglvl,__FILE__,__LINE__,fmt,__VA_ARGS__)

#if defined(WIN_CONSOLE_OUTPUT) && defined(WIN_BACKGROUND_OUTPUT)
#define DEBUG_INFO(fmt,...) \
	do{ \
		__INNER_BACKGROUND_OUTPUT(BASE_LOG_DEBUG,fmt,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(BASE_LOG_DEBUG,fmt,__VA_ARGS__);\
	}while(0)

#elif defined(WIN_BACKGROUND_OUTPUT)
#define DEBUG_INFO(fmt,...) __INNER_BACKGROUND_OUTPUT(BASE_LOG_DEBUG,fmt,__VA_ARGS__)
#elif defined(WIN_CONSOLE_OUTPUT)
#define DEBUG_INFO(fmt,...) __INNER_CONSOLE_OUTPUTU(BASE_LOG_DEBUG,fmt,__VA_ARGS__)
#else
#define DEBUG_INFO(fmt,...)
#endif

#define ERROR_INFO  DEBUG_INFO



#if defined(WIN_CONSOLE_OUTPUT) && defined(WIN_BACKGROUND_OUTPUT)

#define  DEBUG_BUFFER(ptr,blen) \
	do{\
		DebugBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
		ConsoleBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
	}while(0)

#define  DEBUG_BUFFER_FMT(ptr,blen,...)  \
	do{\
		DebugBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
		ConsoleBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
	}while(0)


#elif defined(WIN_CONSOLE_OUTPUT)

#define  DEBUG_BUFFER(ptr,blen) ConsoleBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL)
#define  DEBUG_BUFFER_FMT(ptr,blen,...) ConsoleBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__)


#elif defined(WIN_BACKGROUND_OUTPUT)

#define  DEBUG_BUFFER(ptr,blen) DebugBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL)
#define  DEBUG_BUFFER_FMT(ptr,blen,...) DebugBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__)

#else
#define  DEBUG_BUFFER(ptr,blen)
#define  DEBUG_BUFFER_FMT(ptr,blen,...)

#endif

#define  INIT_LOG(loglvl)  InitOutput(loglvl)
#define  FINI_LOG()        FiniOutput()


#endif /*__WIN_OUTPUT_DEBUG_H__*/
