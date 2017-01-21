#ifndef  __WIN_OUTPUT_DEBUG_H__
#define  __WIN_OUTPUT_DEBUG_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


#ifdef __cplusplus
extern "C" {
#endif

WINLIB_API void DebugOutString(const char* file,int lineno,const char* fmt,...);
WINLIB_API void DebugBufferFmt(const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
WINLIB_API int error_out(const char* fmt, ...);


#ifdef __cplusplus
};
#endif

#define __INNER_BACKGROUND_OUTPUT(fmt,...) DebugOutString(__FILE__,__LINE__,fmt,__VA_ARGS__)
#define __INNER_CONSOLE_OUTPUTU(fmt,...)  \
	do{\
		fprintf(stderr,"[%s:%d] ",__FILE__,__LINE__);\
		fprintf(stderr,fmt,__VA_ARGS__);\
		fprintf(stderr,"\n");\
	}while(0)

#if defined(WIN_CONSOLE_OUTPUT) && defined(WIN_BACKGROUND_OUTPUT)
#define DEBUG_INFO(fmt,...) \
	do{ \
		__INNER_BACKGROUND_OUTPUT(fmt,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(fmt,__VA_ARGS__);\
	}while(0)



#elif defined(WIN_BACKGROUND_OUTPUT)
#define DEBUG_INFO(fmt,...) __INNER_BACKGROUND_OUTPUT(fmt,__VA_ARGS__)
#elif defined(WIN_CONSOLE_OUTPUT)
#define DEBUG_INFO(fmt,...) __INNER_CONSOLE_OUTPUTU(fmt,__VA_ARGS__)
#else
#define DEBUG_INFO(fmt,...)
#endif

#define ERROR_INFO  DEBUG_INFO


#define  DEBUG_BUFFER(ptr,blen) DebugBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL)
#define  DEBUG_BUFFER_FMT(ptr,blen,...) DebugBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__)



#endif /*__WIN_OUTPUT_DEBUG_H__*/
