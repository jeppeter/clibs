#ifndef __DEBUG_JVALUE_H__
#define __DEBUG_JVALUE_H__

#include <jvalue.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void debug_jvalue(FILE* fp,jvalue* value,const char* file,int lineno,const char* fmt,...);
void debug_buffer(FILE* fp, void* pbuffer, int buflen, char* file, int lineno, const char* fmt, ...);


#ifdef __cplusplus
};
#endif


#endif /*__DEBUG_JVALUE_H__*/