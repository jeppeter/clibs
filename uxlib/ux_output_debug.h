#ifndef __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__
#define __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__

#include <stdio.h>
#include <stdlib.h>

#ifndef __UX_INNER_DEFINE__
#define __UX_INNER_DEFINE__
#endif

#include <ux_inner.h>

#undef  __UX_INNER_DEFINE__


#define  LOG_FATAL        0
#define  LOG_ERROR        10
#define  LOG_WARN         20
#define  LOG_INFO         30
#define  LOG_DEBUG        40
#define  LOG_TRACE        50

#define  LOG_DEFAULT      LOG_ERROR

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

#define __INNER_BACKGROUND_OUTPUT(level,fmt,...) debug_out_string(level,__FILE__,__LINE__,fmt,__VA_ARGS__)
#define __INNER_CONSOLE_OUTPUTU(level,fmt,...)  console_out_string(level,__FILE__,__LINE__,fmt,__VA_ARGS__)

#define DEBUG_INFO(fmt,...) \
	do{ \
		__INNER_BACKGROUND_OUTPUT(LOG_DEBUG,fmt,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(LOG_DEBUG,fmt,__VA_ARGS__);\
	}while(0)


#define ERROR_INFO(fmt,...) \
	do {\
		__INNER_BACKGROUND_OUTPUT(LOG_ERROR,fmt,__VA_ARGS__);\
		__INNER_CONSOLE_OUTPUTU(LOG_ERROR,fmt,__VA_ARGS__);\
	}while(0)




#define  DEBUG_BUFFER(ptr,blen) \
	do{\
		debug_buffer_fmt(LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
		console_buffer_fmt(LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,NULL);\
	}while(0)

#define  DEBUG_BUFFER_FMT(ptr,blen,...)  \
	do{\
		debug_buffer_fmt(LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
		console_buffer_fmt(LOG_DEBUG,__FILE__,__LINE__,(unsigned char*)ptr,blen,__VA_ARGS__);\
	}while(0)

#define  INIT_LOG(loglvl)  init_log(loglvl)
#define  FINI_LOG()        fini_log()



#endif /* __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__ */
