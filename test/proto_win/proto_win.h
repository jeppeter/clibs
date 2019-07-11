#ifndef __PROTO_WIN_H_74CC5F6CA292AF061D0DDD79EDD21DD7__
#define __PROTO_WIN_H_74CC5F6CA292AF061D0DDD79EDD21DD7__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#include <Windows.h>

int read_file_overlapped(HANDLE hd, OVERLAPPED* ov, HANDLE evt, void* pbuf, int size);
int get_overlapped_res(HANDLE hd , OVERLAPPED* ov, HANDLE evt, int wr);
int write_file_overlap(HANDLE hd, OVERLAPPED *ov, HANDLE evt, void* pbuf, int size);
int write_pipe_data(HANDLE exitevt, HANDLE hpipe, OVERLAPPED* ov, int maxmills, char* pdata, int datalen);
void free_overlap(OVERLAPPED** ppov);
OVERLAPPED* alloc_overlap(const char* fmt, ...);
int bind_pipe(char* pipename, HANDLE exitevt, HANDLE* phd, OVERLAPPED** pprdov, OVERLAPPED** ppwrov);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __PROTO_WIN_H_74CC5F6CA292AF061D0DDD79EDD21DD7__ */
