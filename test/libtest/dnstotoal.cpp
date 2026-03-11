#include "dnstotal.h"


DnsTotal::DnsTotal()
{

}

DnsTotal::~DnsTotal()
{
	this->__release_resource();
}

void DnsTotal::__release_resource()
{
	while(this->m_iparrs.size() > 0) {
		DnsCap* cur = this->m_iparrs.at(0);
		this->m_iparrs.erase(this->m_iparrs.begin());
		delete cur;
		cur = NULL;
	}

	this->m_dnsnames.clear();


	while(this->m_mapdns.count() > 0 ) {
		this->m_mapdns.erase(this->m_mapdns.begin());
	}

	this->m_ipmaps.clear();
	this->m_ipres.clear();
	this->m_errs.clear();
	return;
}