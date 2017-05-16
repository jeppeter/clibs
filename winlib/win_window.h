#ifndef __WIN_WINDOW_H_C408B03B8AE4FAC8777BFD55BB31AA2E__
#define __WIN_WINDOW_H_C408B03B8AE4FAC8777BFD55BB31AA2E__

#include <Windows.h>

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#ifdef __cplusplus
extern "C" {
#endif

int get_window_handle(const char* typeclass,HWND *ppwnd[],int *pwinsize);

#ifdef __cplusplus
};
#endif


#endif /* __WIN_WINDOW_H_C408B03B8AE4FAC8777BFD55BB31AA2E__ */
