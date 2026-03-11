#include "dnscap.h"

#include <win_dns.h>



#pragma warning(push)
#if defined(_MSC_VER)
#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif
#endif


DnsCap::DnsCap(int aftype,const char* dnsname,char* portstr)
{
	this->m_dnsqry = NULL;
	this->m_aftype = aftype;
	if (dnsname != NULL) {
		this->m_dnsname = _strdup(dnsname);	
	} else {
		this->m_dnsname = NULL;
	}
	
	if (portstr != NULL) {
		this->m_portstr = _strdup(portstr);	
	} else {
		this->m_portstr = NULL;
	}
	
}

DnsCap::~DnsCap()
{
	this->__release_resource();
	if (this->m_dnsname) {
		free(this->m_dnsname);
	}
	this->m_dnsname = NULL;

	if (this->m_portstr) {
		free(this->m_portstr);
	}
	this->m_portstr = NULL;
}

void DnsCap::__stop_query()
{
	free_dns_query(&this->m_dnsqry);
	return;
}

void DnsCap::__release_resource()
{
	this->__stop_query();
	return;
}

int DnsCap::start_query()
{
	int ret;
	if (this->m_dnsname == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO(" ");
		SETERRNO(ret);
		return ret;
	}

	this->__stop_query();

	this->m_dnsqry = start_dns_query(this->m_aftype,this->m_dnsname,this->m_portstr);
	if (this->m_dnsqry == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	return is_dns_query_completed(this->m_dnsqry);
fail:
	SETERRNO(ret);
	return ret;

}

HANDLE DnsCap::get_complete_evt()
{
	HANDLE hret =NULL;
	if (this->m_dnsqry != NULL) {
		hret = dns_query_get_complete_evt(this->m_dnsqry);
	}
	return hret;
}

HANDLE DnsCap::get_error_evt()
{
	HANDLE hret =NULL;
	if (this->m_dnsqry != NULL) {
		hret = dns_query_get_error_evt(this->m_dnsqry);
	}
	return hret;
}

int DnsCap::is_completed()
{
	int ret =0;
	if (this->m_dnsqry) {
		ret = is_dns_query_completed(this->m_dnsqry);
	}
	return ret;
}

int DnsCap::is_error()
{
	int ret =0;
	if (this->m_dnsqry) {
		ret = is_dns_query_error(this->m_dnsqry);
	}
	return ret;
}


int DnsCap::need_time(int timeout)
{
	int ret = -ERROR_NOT_READY;
	if (this->m_dnsqry) {
		ret = dns_query_time_left(this->m_dnsqry,timeout);
	}
	if (ret < 0) {
		SETERRNO(ret);	
	}	
	return ret;
}

int DnsCap::get_result(int idx,char** ppstr,int *psize)
{
	if (this->m_dnsqry == NULL) {
		return 0;
	}

	return dns_query_get_result(this->m_dnsqry,idx,ppstr,psize);
}


#pragma warning(pop)