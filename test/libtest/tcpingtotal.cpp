#define _HAS_EXCEPTIONS 0

#include "tcpingtotal.h"

#include <win_output_debug.h>

#pragma warning(push)

#if defined(_MSC_VER)
#if _MSC_VER >= 1910
#pragma warning(disable:5045)
#endif
#endif


TcpingTotal::TcpingTotal(void* pev,int times,int timeout,int nexttime)
{
	this->m_evmain = pev;
	this->m_times = times;
	this->m_timeout = timeout;
	this->m_nexttime = nexttime;
	this->m_indestruct = 0;
}

void TcpingTotal::__release_resource()
{
	while (this->m_caps.size() > 0) {
		TcpingCap* pcap = this->m_caps.at(0);
		/*to free functions*/
		this->m_caps.erase(this->m_caps.begin());
		delete pcap;
		pcap = NULL;
	}
}

TcpingCap* TcpingTotal::__get_cap(void* pthis,int& idx)
{
	int i;
	TcpingCap* pcap=NULL;
	for(i=0;i< (int)this->m_caps.size();i++) {
		pcap = this->m_caps.at((uint64_t)i);
		if (pcap == pthis) {
			idx = i;
			return pcap;
		}
	}
	idx = -1;
	return NULL;
}

void TcpingTotal::notify_event(void* pthis,ev_combo_event_t event)
{
	TcpingCap* pcap;
	int idx;
	int ret;
	pcap = this->__get_cap(pthis,idx);
	if (pcap == NULL) {
		return;
	}

	if (event == remove_event) {
		this->m_caps.erase(this->m_caps.begin() + idx);

		if (this->m_caps.size() == 0 && this->m_indestruct == 0 && this->m_evmain != NULL) {
			/*if we have no other ,and it will not in destructor ,so we should break loop*/
			libev_break_winev_loop(this->m_evmain);
		}

		return;
	} else if (event == get_result_event) {
		std::string cstr;
		while(1) {
			ret = pcap->get_result(cstr);
			if (ret == 0) {
				break;
			}
			DEBUG_INFO("%s",cstr.c_str());
		}
	}

	return;
}

TcpingTotal::~TcpingTotal()
{
	this->m_indestruct = 1;
	this->__release_resource();
	this->m_times = 0;
	this->m_timeout = 0;
	this->m_nexttime = 0;

	this->m_indestruct = 0;
}

int TcpingTotal::start_tcping(int aftype,const char* ipstr, char* portstr)
{
	TcpingCap* pcap=NULL;
	int ret;

	pcap = new TcpingCap(aftype,ipstr,portstr,this->m_evmain,this);
	pcap->set_timeout(this->m_timeout);
	pcap->set_times(this->m_times);
	pcap->set_nexttime(this->m_nexttime);

	ret = pcap->start();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	this->m_caps.push_back(pcap);
	pcap = NULL;
	return 0;
fail:
	if (pcap) {
		delete pcap;
	}
	SETERRNO(ret);
	return ret;
}

int TcpingTotal::set_timeout(int timeout)
{
	int ret;
	ret = this->m_timeout;
	this->m_timeout = timeout;
	return ret;
}

int TcpingTotal::set_nexttime(int nextime)
{
	int ret;
	ret = this->m_nexttime;
	this->m_nexttime = nextime;
	return ret;
}

int TcpingTotal::set_times(int times)
{
	int ret;
	ret = this->m_times;
	this->m_times = times;
	return ret;
}

#pragma warning(pop)