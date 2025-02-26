#include "sock_cli_comm.h"
#include <win_sock.h>

#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(push)
#pragma warning(disable:5045)
#pragma warning(disable:4530)
#endif
#endif /* _MSC_VER*/

sock_cli_comm::sock_cli_comm(char* ipaddr,int port)
{
	this->m_ipaddr = _strdup(ipaddr);
	this->m_port = port;
	this->m_inited = 0;
	this->m_sock = NULL;
	this->m_realsock = NULL;
}

void sock_cli_comm::__uninit()
{
	free_socket(&(this->m_realsock));
	if (this->m_sock) {
		delete this->m_sock;
	}
	this->m_sock = NULL;
	return ;	
}

sock_cli_comm::~sock_cli_comm()
{
	if (this->m_inited) {
		this->__uninit();
		this->m_inited = 0;
	}
	if (this->m_ipaddr) {
		free(this->m_ipaddr);
	}
	this->m_ipaddr = NULL;	
}



int sock_cli_comm::init()
{
	int ret = 0;
	HANDLE hret=NULL;
	if (this->m_ipaddr == NULL) {
		ret = -ERROR_NOT_ENOUGH_MEMORY;
		SETERRNO(ret);
		return ret;
	}

	if (this->m_inited == 0) {
		this->m_realsock = connect_tcp_socket(this->m_ipaddr,this->m_port,NULL,0,0);
		if (this->m_realsock == NULL) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
		hret = get_tcp_connect_handle(this->m_realsock);
		if (hret == NULL) {
			this->m_sock = new sock_comm(this->m_realsock);
			this->m_realsock = NULL;
		}

		this->m_inited = 1;
		ret = 1;
	}
	return ret;
fail:
	this->__uninit();
	SETERRNO(ret);
	return ret;
}

int sock_cli_comm::is_read_mode()
{
	int ret = 0;
	if (this->m_inited && this->m_sock) {
		ret = this->m_sock->is_read_mode();
	}
	return ret;
}

int sock_cli_comm::is_write_mode()
{
	int ret = 0;
	if (this->m_inited && this->m_sock) {
		ret = this->m_sock->is_write_mode();
	}
	return ret;
}

int sock_cli_comm::complete_read()
{
	int ret;
	if (this->m_inited == 0 || this->m_sock == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_sock->complete_read();
}

int sock_cli_comm::complete_write()
{
	int ret;
	if (this->m_inited == 0 || this->m_sock == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_sock->complete_write();
}

int sock_cli_comm::read_json(jvalue** ppj)
{
	int ret;
	if (this->m_inited == 0 || this->m_sock == NULL) {
		ret = -ERROR_NOT_READY;
		DEBUG_INFO("realsock %p sock %p",this->m_realsock,this->m_sock);
		SETERRNO(ret);
		return ret;
	}
	return this->m_sock->read_json(ppj);
}


int sock_cli_comm::write_json(jvalue* pj)
{
	int ret;
	if (this->m_inited == 0 || this->m_sock == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_sock->write_json(pj);
}

HANDLE sock_cli_comm::get_read_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited && this->m_sock) {
		hret = this->m_sock->get_read_evt();
	}
	return hret;
}

HANDLE sock_cli_comm::get_write_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited && this->m_sock) {
		hret = this->m_sock->get_write_evt();
	}
	return hret;
}

int sock_cli_comm::is_connect_mode()
{
	int ret =0;
	HANDLE hret;
	if (this->m_inited && this->m_realsock) {
		hret = get_tcp_connect_handle(this->m_realsock);
		if (hret != NULL) {
			ret = 1;
		}
	}
	return ret;
}

HANDLE sock_cli_comm::get_connect_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited && this->m_realsock) {
		hret = get_tcp_connect_handle(this->m_realsock);
	}
	return hret;
}

int sock_cli_comm::complete_connect()
{
	int ret;
	if (this->m_inited == 0 || this->m_realsock == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	ret = complete_tcp_connect(this->m_realsock);
	if (ret < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	} else if (ret == 0) {
		DEBUG_INFO("complete connect 0");
		return 0;
	}

	ASSERT_IF(this->m_sock == NULL);
	this->m_sock = new sock_comm(this->m_realsock);
	this->m_realsock = NULL;
	ret = this->m_sock->init();
	if (ret < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	}
	DEBUG_INFO("sock new %p",this->m_sock);
	return 1;
}


#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(pop)
#endif
#endif /* _MSC_VER*/