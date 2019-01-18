#ifndef __WIN_DBG_H_CB2C50B5564C62D409571AABA1425EC8__
#define __WIN_DBG_H_CB2C50B5564C62D409571AABA1425EC8__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define WIN_DBG_FLAGS_CHILDREN                   0x1
#define WIN_DBG_FLAGS_HEAP                       0x2

int windbg_create_client(char* option, void** ppclient);
int windbg_start_process_single(void* pclient, char* cmd, int flags);
int windbg_stop_process(void* pclient);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_DBG_H_CB2C50B5564C62D409571AABA1425EC8__ */
