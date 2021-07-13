#ifndef  __WIN_OUTPUT_DEBUG_H__
#define  __WIN_OUTPUT_DEBUG_H__

//#include <stdio.h>
//#include <stdlib.h>
#include <win_err.h>

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

#define WINLIB_CONSOLE_DISABLED              1
#define WINLIB_DBWIN_DISABLED                2
#define WINLIB_FILE_DISABLED                 3

#ifdef __cplusplus
extern "C" {
#endif


typedef struct __output_debug_cfg {
	char** m_ppoutcreatefile; /*end with NULL*/
	char** m_ppoutappendfile; /*end with NULL*/
	int m_disableflag; /*disable console*/
	int m_reserv1;
} output_debug_cfg_t, *poutput_debug_cfg_t;

WINLIB_API void DebugOutString(int loglvl,const char* file,int lineno,const char* fmt,...);
WINLIB_API void ConsoleOutString(int loglvl,const char* file,int lineno,const char* fmt,...);
WINLIB_API void FileOutString(int loglvl,const char* file,int lineno,const char* fmt,...);
WINLIB_API void DebugBufferFmt(int loglvl,const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
WINLIB_API void ConsoleBufferFmt(int loglvl,const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
WINLIB_API int  InitOutput(int loglvl);
WINLIB_API int  InitOutputEx(int loglvl,poutput_debug_cfg_t pcfg);
WINLIB_API void FiniOutput(void);
WINLIB_API int error_out(const char* fmt, ...);
WINLIB_API void FileBufferFmt(int loglvl, const char* file, int lineno, unsigned char* pBuffer, int buflen, const char* fmt, ...);


#ifdef __cplusplus
};
#endif

#define __INNER_BACKGROUND_OUTPUT(loglvl,fmt,...) DebugOutString(loglvl,__FILE__,__LINE__,fmt,__VA_ARGS__)
#define __INNER_CONSOLE_OUTPUTU(loglvl,fmt,...)  ConsoleOutString(loglvl,__FILE__,__LINE__,fmt,__VA_ARGS__)
#define __INNER_FILE_OUTPUT(loglvl,fmt,...)  FileOutString(loglvl,__FILE__,__LINE__,fmt,__VA_ARGS__)

#define DEBUG_INFO(fmt,...) \
	do{ \
		__INNER_BACKGROUND_OUTPUT(BASE_LOG_DEBUG,fmt,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(BASE_LOG_DEBUG,fmt,__VA_ARGS__);\
		__INNER_FILE_OUTPUT(BASE_LOG_DEBUG,fmt,__VA_ARGS__);\
	}while(0)

#define ERROR_INFO(fmt,...)  \
	do{  \
		__INNER_BACKGROUND_OUTPUT(BASE_LOG_ERROR,fmt,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(BASE_LOG_ERROR,fmt,__VA_ARGS__);\
		__INNER_FILE_OUTPUT(BASE_LOG_ERROR,fmt,__VA_ARGS__);\
	}while(0)

#define WARN_INFO(fmt,...)   \
	do { \
		__INNER_BACKGROUND_OUTPUT(BASE_LOG_WARN,fmt,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(BASE_LOG_WARN,fmt,__VA_ARGS__);\
		__INNER_FILE_OUTPUT(BASE_LOG_WARN,fmt,__VA_ARGS__);\
	} while(0)



#define  DEBUG_BUFFER(ptr,blen) \
	do{\
		DebugBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
		ConsoleBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
		FileBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
	}while(0)

#define  DEBUG_BUFFER_FMT(ptr,blen,...)  \
	do{\
		DebugBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
		ConsoleBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
		FileBufferFmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
	}while(0)


#define  ERROR_BUFFER(ptr,blen) \
	do{\
		DebugBufferFmt(BASE_LOG_ERROR,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
		ConsoleBufferFmt(BASE_LOG_ERROR,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
		FileBufferFmt(BASE_LOG_ERROR,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
	}while(0)

#define  ERROR_BUFFER_FMT(ptr,blen,...)  \
	do{\
		DebugBufferFmt(BASE_LOG_ERROR,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
		ConsoleBufferFmt(BASE_LOG_ERROR,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
		FileBufferFmt(BASE_LOG_ERROR,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
	}while(0)


#define  INIT_LOG(loglvl)  InitOutput(loglvl)
#define  FINI_LOG()        FiniOutput()


#endif /*__WIN_OUTPUT_DEBUG_H__*/
