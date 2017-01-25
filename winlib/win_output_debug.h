#ifndef  __WIN_OUTPUT_DEBUG_H__
#define  __WIN_OUTPUT_DEBUG_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#define WIN_CONSOLE_OUTPUT     1
#define WIN_BACKGROUND_OUTPUT  1

#ifdef __cplusplus
extern "C" {
#endif

WINLIB_API void DebugOutString(const char* file,int lineno,const char* fmt,...);
WINLIB_API void ConsoleOutString(const char* file,int lineno,const char* fmt,...);
WINLIB_API void DebugBufferFmt(const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
WINLIB_API void ConsoleBufferFmt(const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
WINLIB_API int error_out(const char* fmt, ...);


#ifdef __cplusplus
};
#endif

#define __INNER_BACKGROUND_OUTPUT(fmt,...) DebugOutString(__FILE__,__LINE__,fmt,__VA_ARGS__)
#define __INNER_CONSOLE_OUTPUTU(fmt,...)  ConsoleOutString(__FILE__,__LINE__,fmt,__VA_ARGS__)

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



#if defined(WIN_CONSOLE_OUTPUT) && defined(WIN_BACKGROUND_OUTPUT)

#define  DEBUG_BUFFER(ptr,blen) \
	do{\
		DebugBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
		ConsoleBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
	}while(0)

#define  DEBUG_BUFFER_FMT(ptr,blen,...)  \
	do{\
		DebugBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
		ConsoleBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
	}while(0)


#elif defined(WIN_CONSOLE_OUTPUT)

#define  DEBUG_BUFFER(ptr,blen) ConsoleBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL)
#define  DEBUG_BUFFER_FMT(ptr,blen,...) ConsoleBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__)


#elif defined(WIN_BACKGROUND_OUTPUT)

#define  DEBUG_BUFFER(ptr,blen) DebugBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL)
#define  DEBUG_BUFFER_FMT(ptr,blen,...) DebugBufferFmt(__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__)

#else
#define  DEBUG_BUFFER(ptr,blen)
#define  DEBUG_BUFFER_FMT(ptr,blen,...)

#endif




#endif /*__WIN_OUTPUT_DEBUG_H__*/
