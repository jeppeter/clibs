#ifndef __WIN_DBG_H_CB2C50B5564C62D409571AABA1425EC8__
#define __WIN_DBG_H_CB2C50B5564C62D409571AABA1425EC8__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


#define WIN_DBG_FLAGS_CHILDREN                   0x1
#define WIN_DBG_FLAGS_HEAP                       0x2

#define WIN_DBG_FLAGS_FREE                       0x0
#define WIN_DBG_OUTPUT_OUT                       0x1

WINLIB_API int windbg_create_client(char* option, void** ppclient);
WINLIB_API int windbg_start_process_single(void* pclient, char* cmd, int flags);
WINLIB_API int windbg_stop_process(void* pclient);
WINLIB_API int windbg_go(void* pclient);
WINLIB_API int windbg_exec(void* pclient, const char* cmd);
WINLIB_API int windbg_get_out(void* pclient,int flags, char** ppout, int *psize);
WINLIB_API int windbg_interrupt(void* pclient);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_DBG_H_CB2C50B5564C62D409571AABA1425EC8__ */
