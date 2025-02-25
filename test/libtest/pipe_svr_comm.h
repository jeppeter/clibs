// this file is generated by program
#ifndef __PIPE_SVR_COMM_H_F74A2AEABE5DC67143DDE3BAC76985C3__
#define __PIPE_SVR_COMM_H_F74A2AEABE5DC67143DDE3BAC76985C3__

#include "pipe_comm.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#ifdef __cplusplus
};
#endif /* __cplusplus*/

class pipe_svr_comm
{
public:
	pipe_svr_comm(char* pipename);
	~pipe_svr_comm();
	int init();
	int is_read_mode();
	int is_write_mode();
	HANDLE get_read_evt();
	HANDLE get_write_evt();
	int read_json(jvalue** ppj);
	int write_json(jvalue* pj);	
	int complete_write(void);
	int complete_read(void);
	int is_accept_mode();
	HANDLE get_accept_evt();
	int complete_accept();
private:
	void __uninit();
private:
	pipe_comm* m_pipe;
	void* m_realpipe;
	char* m_pipename;
	int m_inited;
	int m_reserv1;
};

#endif /* __PIPE_SVR_COMM_H_F74A2AEABE5DC67143DDE3BAC76985C3__ */
