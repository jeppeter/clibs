// this file is generated by program
#ifndef __SOCK_CLI_COMM_H_668A1F9FB04286719BDCD77110AE5C15__
#define __SOCK_CLI_COMM_H_668A1F9FB04286719BDCD77110AE5C15__

#include "sock_comm.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#ifdef __cplusplus
};
#endif /* __cplusplus*/

class sock_cli_comm
{
public:
	sock_cli_comm(char* ipaddr,int port);
	~sock_cli_comm();
	int init();
	int is_read_mode();
	int is_write_mode();
	int is_connect_mode();
	HANDLE get_read_evt();
	HANDLE get_write_evt();
	HANDLE get_connect_evt();
	int read_json(jvalue** ppj);
	int write_json(jvalue* pj);	
	int complete_write(void);
	int complete_read(void);
	int complete_connect(void);
private:
	void __uninit();
private:
	sock_comm* m_sock;
	void* m_realsock;
	char* m_ipaddr;
	int m_port;
	int m_inited;
};


#endif /* __SOCK_CLI_COMM_H_668A1F9FB04286719BDCD77110AE5C15__ */
