#include "dnscap.h"

#include <win_dns.h>



#pragma warning(push)
#if defined(_MSC_VER)
#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif
#endif


DnsCap::DnsCap(int aftype,const char* dnsname,char* portstr,void* pev,IEvCombo* pcombo)
{
	this->m_dnsqry = NULL;
	this->m_aftype = aftype;
	this->m_dnsname = dnsname;
	this->m_timeout = 5000;
	if (portstr != NULL) {
		this->m_portstr = portstr;
	} else {
		this->m_portstr = "";
	}

	this->m_combo = pcombo;
	this->m_evmain = pev;

	this->m_compevt = NULL;
	this->m_insertcomp = 0;

	this->m_errevt = NULL;
	this->m_inserterr = 0;

	this->m_tmoutguid = 0;
	this->m_inserttmout = 0;
}

void DnsCap::__call_remove()
{
	if (this->m_combo != NULL) {
		this->m_combo->notify_event(this,remove_event);
	}
}

void DnsCap::__call_notify()
{
	if (this->m_combo != NULL) {
		this->m_combo->notify_event(this,get_result_event);
	}
}

DnsCap::~DnsCap()
{
	this->__release_resource();
	this->__call_remove();
	this->m_dnsname = "";
	this->m_portstr = "";
	this->m_evmain = NULL;
	this->m_combo = NULL;
}

void DnsCap::__stop_query()
{
	this->__remove_comp_evt();
	this->__remove_error_evt();
	this->__remove_timeout_guid();

	free_dns_query(&this->m_dnsqry);

	this->m_compevt = NULL;
	this->m_errevt = NULL;
	this->m_tmoutguid = 0;
	return;
}

void DnsCap::__release_resource()
{
	this->__stop_query();
	return;
}

void DnsCap::__remove_timeout_guid()
{
	if (this->m_inserttmout != 0) {
		ret = libev_remove_timer(this->m_evmain,this->m_tmoutguid);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove [%s:%s] tmoutguid 0x%llx error %d", this->m_dnsname.c_str(), this->m_portstr.c_str(), this->m_tmoutguid,ret);
		}
		this->m_inserttmout = 0;
		this->m_tmoutguid = 0;
	}
	return;
}

int DnsCap::start()
{
	int ret;
	int completed = 0;
	if (this->m_dnsname.length() == 0) {
		ret = -ERROR_INVALID_PARAMETER;
		ERROR_INFO(" ");
		SETERRNO(ret);
		return ret;
	}

	this->__stop_query();

	this->m_dnsqry = start_dns_query(this->m_aftype,this->m_dnsname.c_str(),this->m_portstr.length() == 0 ? NULL : this->m_portstr.c_str());
	if (this->m_dnsqry == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret =  is_dns_query_completed(this->m_dnsqry);
	if (ret > 0) {
		this->__call_notify();
		completed = 1;
	}
	return completed;
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