#ifndef __UX_STR_OP_H__
#define __UX_STR_OP_H__

#include <stdarg.h>

#undef __UX_INNER_DEFINED__
#define __UX_INNER_DEFINED__
#include <ux_inner.h>
#undef __UX_INNER_DEFINED__


#ifdef __cplusplus
extern "C"{
#endif

int find_endof_inbuf(void* pbuf,int bufsize);
int vsnprintf_safe(char** ppbuf,int *pbufsize,const char* fmt,va_list ap);
int snprintf_safe(char** ppbuf,int *pbufsize,const char* fmt,...);
int append_vsnprintf_safe(char** ppbuf,int *pbufsize,const char* fmt,va_list ap);
int append_snprintf_safe(char**ppbuf,int*pbufsize,const char* fmt,...);
bool str_match_wildcard(const char* regpat,const char* str);
void str_lower_case(const char* pstr);
char* str_in_str(const char* pstr,const char *search);

#ifdef __cplusplus
};
#endif


#endif /*__UX_STR_OP_H__*/