#ifndef __WIN_SOCK_H_3416A85870F7CA4F6AB69687D35EE5CF__
#define __WIN_SOCK_H_3416A85870F7CA4F6AB69687D35EE5CF__


#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#include <win_types.h>


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


WINLIB_API int init_socket(void);
WINLIB_API void fini_socket(void);
WINLIB_API void free_socket(void** pptcp);
WINLIB_API void* connect_tcp_socket(char* ipaddr,int port,char* bindip,int bindport,int connected);
WINLIB_API int complete_tcp_connect(void* ptcp);
WINLIB_API int complete_tcp_accept(void* ptcp);
WINLIB_API void* bind_tcp_socket(char* ipaddr,int port,int backlog);
WINLIB_API void* accept_tcp_socket(void* ptcp);
WINLIB_API int read_tcp_socket(void* ptcp, uint8_t* pbuf,int bufsize);
WINLIB_API int write_tcp_socket(void* ptcp, uint8_t* pbuf,int bufsize);
WINLIB_API HANDLE get_tcp_connect_handle(void* ptcp);
WINLIB_API HANDLE get_tcp_accept_handle(void* ptcp);
WINLIB_API HANDLE get_tcp_read_handle(void* ptcp);
WINLIB_API HANDLE get_tcp_write_handle(void* ptcp);
WINLIB_API int complete_tcp_connect(void* ptcp);
WINLIB_API int complete_tcp_read(void* ptcp);
WINLIB_API int complete_tcp_write(void* ptcp);


#ifdef __cplusplus
};
#endif /* __cplusplus*/



#endif /* __WIN_SOCK_H_3416A85870F7CA4F6AB69687D35EE5CF__ */
