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
void console_out_string(int level,const char* file,int lineno,const char* fmt,...);
void debug_buffer_fmt(int level,const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);
void console_buffer_fmt(int level,const char* file,int lineno,unsigned char* pBuffer,int buflen,const char* fmt,...);

int init_log(int loglvl);
void fini_log();

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#define __INNER_BACKGROUND_OUTPUT(level,...) do{debug_out_string(level,__FILE__,__LINE__,__VA_ARGS__);} while(0)
#define __INNER_CONSOLE_OUTPUTU(level,...)   do{console_out_string(level,__FILE__,__LINE__,__VA_ARGS__);} while(0)

#define DEBUG_INFO(...) \
	do{ \
		__INNER_BACKGROUND_OUTPUT(BASE_LOG_DEBUG,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(BASE_LOG_DEBUG,__VA_ARGS__);\
	}while(0)


#define ERROR_INFO(...) \
	do {\
		__INNER_BACKGROUND_OUTPUT(BASE_LOG_ERROR,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(BASE_LOG_ERROR,__VA_ARGS__);\
	}while(0)




#define  DEBUG_BUFFER(ptr,blen) \
	do{\
		debug_buffer_fmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
		console_buffer_fmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
	}while(0)

#define  DEBUG_BUFFER_FMT(ptr,blen,...)  \
	do{\
		debug_buffer_fmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
		console_buffer_fmt(BASE_LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
	}while(0)

#define  INIT_LOG(loglvl)  init_log(loglvl)
#define  FINI_LOG()        fini_log()



#endif /* __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__ */
