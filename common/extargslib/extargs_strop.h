#ifndef __EXTARGS_STR_OP_H__
#define __EXTARGS_STR_OP_H__

#include <stdarg.h>
#include <stdbool.h>

/*for safe use*/
#ifndef __EXTARGS_INNER_INCLUDE__
#define __EXTARGS_INNER_INCLUDE__
#endif

#include <extargs_inner.h>

#undef __EXTARGS_INNER_INCLUDE__


#ifdef __cplusplus
extern "C"{
#endif


#ifndef __cplusplus
typedef _Bool BOOL;
#endif

EXTARGSLIB_API int extargs_find_endof_inbuf(void* pbuf,int bufsize);
EXTARGSLIB_API int extargs_vsnprintf_safe(char** ppbuf,int *pbufsize,const char* fmt,va_list ap);
EXTARGSLIB_API int extargs_snprintf_safe(char** ppbuf,int *pbufsize,const char* fmt,...);
EXTARGSLIB_API int extargs_append_vsnprintf_safe(char** ppbuf,int *pbufsize,const char* fmt,va_list ap);
EXTARGSLIB_API int extargs_append_snprintf_safe(char**ppbuf,int*pbufsize,const char* fmt,...);
EXTARGSLIB_API BOOL extargs_str_match_wildcard(const char* regpat,const char* str);
EXTARGSLIB_API void extargs_str_lower_case(const char* pstr);
EXTARGSLIB_API void extargs_str_upper_case(const char* pstr);
EXTARGSLIB_API void extargs_str_underscore_case(const char* pstr);
EXTARGSLIB_API void extargs_str_hiphen_case(const char* pstr);
EXTARGSLIB_API char* extargs_str_quoted_case(const char* pstr);
EXTARGSLIB_API char* extargs_str_in_str(const char* pstr,const char *search);
EXTARGSLIB_API char* extargs_safe_strdup(const char* str);

#ifdef __cplusplus
};
#endif


#endif /*__EXTARGS_STR_OP_H__*/