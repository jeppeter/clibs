#ifndef __WIN_TCPING_H_E6B1F5CA2B49401C3012CC9B645EA000__
#define __WIN_TCPING_H_E6B1F5CA2B49401C3012CC9B645EA000__

#include <win_types.h>

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


WINLIB_API void* init_tcping_sock(int type);
WINLIB_API void free_tcping_sock(void** ppsock);
WINLIB_API int send_tcping_request(void* psock,const char* ip);
WINLIB_API int tcping_complete_read(void* psock);
WINLIB_API int tcping_complete_write(void* psock);
WINLIB_API HANDLE get_tcping_read_evt(void* psock);
WINLIB_API HANDLE get_tcping_write_evt(void* psock);
WINLIB_API int tcping_is_read_mode(void* psock);
WINLIB_API int tcping_is_write_mode(void* psock);
WINLIB_API int tcping_send_cnt(void* psock);
WINLIB_API int recv_tcping_response(void* psock,uint64_t* pval);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_TCPING_H_E6B1F5CA2B49401C3012CC9B645EA000__ */
