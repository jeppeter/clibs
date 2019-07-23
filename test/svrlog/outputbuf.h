#ifndef __OUTPUTBUF_H_3F243D2FAE7083F19980E14907B823DB__
#define __OUTPUTBUF_H_3F243D2FAE7083F19980E14907B823DB__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

void* create_output_buf(int global, int maxcnt);
HANDLE get_output_evt(void* pof);
int get_output_buf(void* pof,char** ppbuf,int* bufsize);
void free_output_memory(char** ppbuf,int * bufsize);
void free_output_buf(void*ppof);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __OUTPUTBUF_H_3F243D2FAE7083F19980E14907B823DB__ */
