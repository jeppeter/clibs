#ifndef __OUTPUTBUF_H_3F243D2FAE7083F19980E14907B823DB__
#define __OUTPUTBUF_H_3F243D2FAE7083F19980E14907B823DB__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

typedef struct __dbwin_buffer {
	DWORD procid;
	char data[4096- sizeof(DWORD)];
} dbwin_buffer_t,*pdbwin_buffer_t;

void* create_output_buf(int global, int maxcnt);
HANDLE get_output_evt(void* pof);
int get_output_buf(void* pof,pdbwin_buffer_t* ppdbwin);
void free_output_memory(pdbwin_buffer_t pdbwin);
void free_output_buf(void**ppof);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __OUTPUTBUF_H_3F243D2FAE7083F19980E14907B823DB__ */
