#ifndef __UX_SOCK_H_4AB7C67E7898F78EE1403D0ED9240C2E__
#define __UX_SOCK_H_4AB7C67E7898F78EE1403D0ED9240C2E__

#include <ux_err.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

int init_socket(void);
void fini_socket(void);
void free_socket(void** pptcp);
void* connect_tcp_socket(const char* ipaddr,int port,const char* bindip,int bindport,int connected);
int complete_tcp_connect(void* ptcp);
int complete_tcp_accept(void* ptcp);
void* bind_tcp_socket(const char* ipaddr,int port,int backlog);
void* accept_tcp_socket(void* ptcp);
int read_tcp_socket(void* ptcp, uint8_t* pbuf,int bufsize);
int write_tcp_socket(void* ptcp, uint8_t* pbuf,int bufsize);
int get_tcp_connect_handle(void* ptcp);
int get_tcp_accept_handle(void* ptcp);
int get_tcp_read_handle(void* ptcp);
int get_tcp_write_handle(void* ptcp);
int complete_tcp_connect(void* ptcp);
int complete_tcp_read(void* ptcp);
int complete_tcp_write(void* ptcp);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_SOCK_H_4AB7C67E7898F78EE1403D0ED9240C2E__ */
