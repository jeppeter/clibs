#ifndef __WIN_REGOP_H_3846E88D0AF44B2AABE7076223742390__
#define __WIN_REGOP_H_3846E88D0AF44B2AABE7076223742390__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


#define ACCESS_KEY_READ       0x1
#define ACCESS_KEY_WRITE      0x2
#define ACCESS_KEY_ALL        0x4


WINLIB_API void* open_hklm(const char* psubkey,int accessmode);
WINLIB_API int query_hklm_string(void* pregop,const char* path,char** ppretval,int *pretsize);
WINLIB_API int query_hklm_binary(void* pregop,const char* path,void** ppdata,int *pdatasize);
WINLIB_API int set_hklm_binary(void* pregop, const char* path, void* pdata, int size);
WINLIB_API int set_hklm_string(void* pregop, const char* path, char* valstr);
WINLIB_API void close_hklm(void** ppregop);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_REGOP_H_3846E88D0AF44B2AABE7076223742390__ */
