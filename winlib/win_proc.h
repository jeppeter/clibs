#ifndef __WIN_PROC_H_25C1849750B170DECA8546855D8BE495__
#define __WIN_PROC_H_25C1849750B170DECA8546855D8BE495__

#include <Windows.h>

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#ifdef __cplusplus
extern "C" {
#endif


typedef int (*win_enum_func_t)(HWND hwnd,void* param);

WINLIB_API int get_pid_argv(int pid,char*** pppargv,int *pargvsize);
WINLIB_API int get_win_handle(win_enum_func_t pcallback,void* param);


#ifdef __cplusplus
};
#endif



#endif /* __WIN_PROC_H_25C1849750B170DECA8546855D8BE495__ */
