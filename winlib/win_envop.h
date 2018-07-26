#ifndef __WIN_ENVOP_H_65CC41A9CD077A8759BB97D7F81A5D94__
#define __WIN_ENVOP_H_65CC41A9CD077A8759BB97D7F81A5D94__

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#ifdef __cplusplus
extern "C" {
#endif

#define  COMPUTER_NAME_NONE         0
#define  COMPUTER_NAME_DNS          1
#define  COMPUTER_NAME_NETBIOS      2
#define  COMPUTER_NAME_PHYS         4

#define  EN_US_CODEPAGE             437

WINLIB_API int get_env_variable(char* envvar,char** ppenvval,int* pvalsize);
WINLIB_API int get_computer_name(int type, char** ppname,int *pnamesize);
WINLIB_API int set_computer_name(int type,char* pname);
WINLIB_API int get_codepage(void);
WINLIB_API int set_codepage(int cp);

#ifdef __cplusplus
};
#endif


#endif /* __WIN_ENVOP_H_65CC41A9CD077A8759BB97D7F81A5D94__ */
