#include "sock_svr_comm.h"
#include <win_sock.h>

#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(push)
#pragma warning(disable:5045)
#pragma warning(disable:4530)
#endif
#endif /* _MSC_VER*/

sock_svr_comm::sock_svr_comm(char* ipaddr,int port)
{
	this->m_ipaddr = _strdup(ipaddr);
	this->m_port = port;
	this->m_inited = 0;
	this->m_realsock = NULL;
	this->m_chldsock = NULL;
}

void sock_svr_comm::__uninit()
{
	if (this->m_realsock != NULL) {
		DEBUG_INFO("close [%s]",tcp_sock_sockname(this->m_realsock));
	}
	if (this->m_chldsock) {
		DEBUG_INFO("close chldsock [%s]:[%s]", tcp_sock_sockname(this->m_chldsock),tcp_sock_peername(this->m_chldsock));
	}
	free_socket(&(this->m_realsock));
	free_socket(&(this->m_chldsock));
	return ;	
}

sock_svr_comm::~sock_svr_comm()
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

int sock_svr_comm::is_accept_mode()
{
	int ret =0;
	HANDLE hret;
	if (this->m_inited) {
		hret = get_tcp_accept_handle(this->m_realsock);
		if (hret != NULL) {
			ret = 1;
		}
	}
	return ret;
}

int sock_svr_comm::complete_accept()
{
	int ret;
	if (this->m_inited == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	if (this->is_accept_mode() == 0 || this->m_chldsock) {
		return 1;
	}

	ASSERT_IF(this->m_chldsock == NULL);

	ret = complete_tcp_accept(this->m_realsock);
	if (ret < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	} else if (ret == 0) {
		return 0;
	}

	this->m_chldsock = accept_tcp_socket(this->m_realsock);
	if (this->m_chldsock == NULL) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	}
	return 1;
}


int sock_svr_comm::init()
{
	int ret = 0;
	if (this->m_ipaddr == NULL) {
		ret = -ERROR_NOT_ENOUGH_MEMORY;
		SETERRNO(ret);
		return ret;
	}

	if (this->m_inited == 0) {
		this->m_realsock = bind_tcp_socket(this->m_ipaddr,this->m_port,5);
		if (this->m_realsock == NULL) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
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


HANDLE sock_svr_comm::get_accept_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited) {
		hret = get_tcp_accept_handle(this->m_realsock);
	}
	return hret;
}

sock_comm* sock_svr_comm::get_accept()
{
	sock_comm* pcomm =NULL;
	if(this->m_chldsock!=NULL) {
		pcomm = new sock_comm(this->m_chldsock);
		this->m_chldsock = NULL;
	}
	return pcomm;
}

#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(pop)
#endif
#endif /* _MSC_VER*/