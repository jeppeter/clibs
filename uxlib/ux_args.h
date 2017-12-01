#ifndef __UX_ARGS_H_26841CD9A377EB98D1A8624A9AFFADCE__
#define __UX_ARGS_H_26841CD9A377EB98D1A8624A9AFFADCE__

#include <ux_err.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

void free_args(char*** pppargs);
char** copy_args(int argc,char *argv[]);
int  parse_number(char* str,uint64_t *pnum,char** ppend);
int  parse_int(char* str,int64_t* pnum,char**ppend);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_ARGS_H_26841CD9A377EB98D1A8624A9AFFADCE__ */
