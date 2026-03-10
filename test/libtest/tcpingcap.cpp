#include "tcpingcap.h"

TcpingCap::TcpingCap(const char* ipportstr,int timeout,int nextout,int times)
{
	this->m_verbose = 0;
	this->m_ip = NULL;
	this->m_port = 0;
	if (ipportstr) {
		this->m_ipstr = _strdup(ipportstr);	
	} else {
		this->m_ipstr = NULL;
	}
	
	this->m_tcpingtype = AF_INET;
	this->m_expire = 0;
	this->m_nextstart = 0;
	this->m_times = times;
	this->m_timeout = timetout;
	this->m_nexttime = nextout;
	this->m_tcpingval = NULL;
}

void TcpingCap::__free_ipstr()
{
	if (this->m_ip) {
		free(this->m_ip);
	}
	this->m_ip = NULL;

	this->m_port = 0;
	return;
}

void TcpingCap::__release_resource()
{
	free_tcping_sock(&(this->m_sock));
	if (this->m_tcpingval) {
		while(this->m_tcpingval->size()) {
			this->m_tcpingval->erase(this->m_tcpingval->begin());
		}
		delete this->m_tcpingval;		
	}

	if (this->m_ip) {
		free(this->m_ip);
	}
	this->m_ip = NULL;
	this->m_port = 0;

	this->m_tcpingval = NULL;
	this->m_expire = 0;
	this->m_nextstart = 0;
}

TcpingCap::~TcpingCap()
{
	this->__release_resource();
	if (this->m_ipstr) {
		free(this->m_ipstr);
		this->m_ipstr = NULL;
	}
}


int TcpingCap::__parse_ipstr()
{
	if (this->m_ip) {
		free(this->m_ip);
	}
}

int TcpingCap::__start_alloc()
{

}