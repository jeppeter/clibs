#ifndef __WIN_REGOP_H_3846E88D0AF44B2AABE7076223742390__
#define __WIN_REGOP_H_3846E88D0AF44B2AABE7076223742390__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define ACCESS_KEY_READ       0x1
#define ACCESS_KEY_WRITE      0x2
#define ACCESS_KEY_ALL        0x4


void* open_hklm(const char* psubkey,int accessmode);
int query_hklm_string(void* pregop,const char* path,char** ppretval,int *pretsize);
int query_hklm_binary(void* pregop,const char* path,void** ppdata,int *pdatasize);
int set_hklm_binary(void* pregop, const char* path, void* pdata, int size);
void close_hklm(void** ppregop);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_REGOP_H_3846E88D0AF44B2AABE7076223742390__ */
