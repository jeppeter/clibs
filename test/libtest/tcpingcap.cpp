#include "tcpingcap.h"


int TcpingCap::__reset_parameter()
{
	this->m_verbose = 0;
	this->m_times = 10;
	this->m_curtime = 0;
	this->m_timeout = 5000;
	this->m_nexttime = 3000;

	return 0;
}

TcpingCap::TcpingCap(int aftype,const char* ipstr,const char* portstr,void* pev,IEvCombo* pcombo)
{
	this->m_tcpingtype = aftype;
	this->m_ipstr = ipstr;
	if (portstr != NULL) {
		this->m_port = atoi(portstr);	
	} else {
		this->m_port = -1;
	}
	this->m_evmain = pev;
	this->m_combo = pcombo;

	this->m_sock = NULL;

	this->__reset_parameter();


	this->m_evthd = NULL;
	this->m_inserthd = 0;

	this->m_tmoutguid = 0;
	this->m_tmoutok = 0;
	this->m_tmnextguid = 0;
	this->m_tmnextok = 0;

	/*tcpingval ok*/

	
}


void TcpingCap::__remove_events()
{
	int ret;
	if (this->m_evmain != NULL) {
		if (this->m_inserthd != 0) {
			ret = libev_remove_handle(this->m_evmain,this->m_evthd);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("remove [%s:%d] evthd %x error %d",this->m_ipstr.c_str(),this->m_port,this->m_evthd, ret);
			}
			this->m_inserthd = 0;
		}

		if (this->m_tmoutok != 0) {
			ret = libev_remove_timer(this->m_evmain,this->m_tmoutguid);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("remove [%s:%d] tmout 0x%llx error %d", this->m_ipstr.c_str(),this->m_port, this->m_tmoutguid,ret);
			}
			this->m_tmoutok = 0;
			this->m_tmoutguid = 0;
		}

		if (this->m_tmnextok != 0) {
			ret = libev_remove_timer(this->m_evmain,this->m_tmnextguid);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("remove [%s:%d] tmnext 0x%llx error %d", this->m_ipstr.c_str(),this->m_port, this->m_tmnextguid,ret);
			}
			this->m_tmnextok = 0;
			this->m_tmnextguid = 0;
		}
	}
}

void TcpingCap::__remove_component()
{
	if (this->m_combo) {
		this->m_combo->remove_ev_component(this,0);
	}
}

void TcpingCap::__release_resource()
{
	this->__remove_events();
	this->__remove_component();

	free_tcping_sock(&this->m_sock);
	this->m_tcpingval.clear();
}

TcpingCap::~TcpingCap()
{
	this->__release_resource();

	this->m_ipstr = "";
	this->m_port = -1;

	this->__reset_parameter();
}



int TcpingCap::start()
{
	int ret;
	if (this->m_sock == NULL) {
		this->m_sock = init_tcping_sock(this->m_tcpingtype);
		if (this->m_sock == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	} else {

	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}