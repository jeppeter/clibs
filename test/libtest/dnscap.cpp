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

void DnsCap::__remove_error_evt()
{
	if (this->m_inserterr != 0) {
		ret = libev_remove_handle(this->m_evmain,this->m_errevt);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove [%s:%s] errevt error %d", this->m_dnsname.c_str(),this->m_portstr.c_str(),ret);
		}
		this->m_inserterr = 0;
	}
	return;
}

void DnsCap::__remove_comp_evt()
{
	if (this->m_insertcomp != 0) {
		ret = libev_remove_handle(this->m_evmain,this->m_compevt);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove [%s:%s] compevt error %d", this->m_dnsname.c_str(),this->m_portstr.c_str(),ret);
		}
		this->m_insertcomp = 0;
	}
	return;
}

int DnsCap::__insert_timeout_guid()
{
	int ret;
	if (this->m_inserttmout == 0) {
		ret = libev_insert_timer(this->m_evmain,&this->m_tmoutguid,DnsCap::dnscap_timeout,this,this->m_timeout,0);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_inserttmout = 1;
	} else {
		ret = -ERROR_ALREADY_EXISTS;
		ERROR_INFO("already exist [%s:%s] tmout guid", this->m_dnsname.c_str(),this->m_portstr.c_str());
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int DnsCap::__insert_error_evt()
{
	int ret;
	if (this->m_inserterr == 0) {
		ret = libev_insert_handle(this->m_evmain,this->m_errevt,DnsCap::dnscap_callback,this);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_inserterr = 1;
	} else {
		ret = -ERROR_ALREADY_EXISTS;
		ERROR_INFO("already exist [%s:%s] errevt", this->m_dnsname.c_str(),this->m_portstr.c_str());
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int DnsCap::__insert_comp_evt()
{
	int ret;
	if (this->m_insertcomp == 0) {
		ret = libev_insert_handle(this->m_evmain,this->m_compevt,DnsCap::dnscap_callback,this);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_insertcomp = 1;
	} else {
		ret = -ERROR_ALREADY_EXISTS;
		ERROR_INFO("already exist [%s:%s] compevt", this->m_dnsname.c_str(),this->m_portstr.c_str());
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
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
	} else {
		/*now we should set value*/
		this->m_compevt = dns_query_get_complete_evt(this->m_dnsqry);
		this->m_errevt = dns_query_get_error_evt(this->m_dnsqry);
		if (this->m_compevt == NULL || this->m_errevt == NULL) {
			ret = -ERROR_INVALID_PARAMTER;
			ERROR_INFO("can not get compevt or errevt");
			goto fail;
		}

		ret = this->__insert_comp_evt();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = this->__insert_error_evt();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = this->__insert_timeout_guid();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

	}
	return completed;
fail:
	this->__stop_query();
	SETERRNO(ret);
	return ret;
}

int DnsCap::__fill_dns_info()
{
	int idx = 0;
	int ret;
	char* pdns=NULL;
	int dnssize=0;
	std::string vstr;
	while(1) {
		ret = dns_query_get_result(this->m_dnsqry,idx,&pdns,&dnssize);
		if (ret == 0) {
			break;
		}

		vstr = this->m_dnsname;
		if (this->m_portstr.length() > 0) {
			vstr += ',';
			vstr += this->m_portstr;
		}
		vstr += ';';
		vstr += pdns;
		if (this->m_portstr.length() > 0) {
			vstr += ',';
			vstr += this->m_portstr;
		}
		vstr += ';'
		this->m_results.push_back(vstr);
		idx += 1;
	}

	dns_query_get_result(NULL,-1,&pdns,&dnssize);
	return 0;
}

int DnsCap::__fill_dns_error()
{
	std::string vstr;

	vstr = "ERROR";
	vstr += this->m_dnsname;
	if (this->m_portstr.length() > 0) {
		vstr += ';';
		vstr += ',';
		vstr += this->m_portstr;
	}
	vstr += ';';
	this->m_results.push_back(vstr);
	return 0;
}

int DnsCap::_timeout_func(uint64_t guid,libev_enum_event_t event)
{
	if (guid == this->m_tmoutguid) {
		ret = this->__fill_dns_error();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->__remove_timeout_guid();
		this->__remove_comp_evt();
		this->__remove_error_evt();
		this->__call_notify();
		/*to exists*/
		ret = -ERROR_ALREADY_EXISTS;
		SETERRNO(ret);
		return ret;
	} else {
		ERROR_INFO("0x%llx not guid", guid);
	}
	return 0;
}

int DnsCap::_callback_func(HANDLE hd,libev_enum_event_t event)
{
	if (hd == this->m_compevt) {
		/*now to */
		ret = is_dns_query_completed(this->m_dnsqry);
		if (ret != 0) {
			ret = this->__fill_dns_info();
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			this->__remove_timeout_guid();
			this->__remove_comp_evt();
			this->__remove_error_evt();
			this->__call_notify();
			/*to exists*/
			ret = -ERROR_ALREADY_EXISTS;
			SETERRNO(ret);
			return ret;
		}
	} else if (hd == this->m_errevt) {
		ret = is_dns_query_error(this->m_dnsqry);
		if (ret != 0) {
			ret = this->__fill_dns_error();
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			this->__remove_timeout_guid();
			this->__remove_comp_evt();
			this->__remove_error_evt();
			this->__call_notify();
			/*exit*/
			ret = -ERROR_ALREADY_EXISTS;
			SETERRNO(ret);
			return ret;
		}

	} else {
		ERROR_INFO("hd 0x%x not ok",hd);
	}
	return 0;
}

int DnsCap::dnscap_callback(HANDLE hd,libev_enum_event_t event,void* pevmain,void* args)
{
	DnsCap* pThis= (DnsCap*)args;
	ret = pThis->_callback_func(hd,event);
	if (ret < 0) {
		delete pThis;
	}
	return 0;
}

int DnsCap::dnscap_timeout(uint64_t guid,libev_enum_event_t event,void* pevmain,void* args)
{
	DnsCap* pThis= (DnsCap*)args;
	ret = pThis->_timeout_func(hd,event);
	if (ret < 0) {
		delete pThis;
	}
	return 0;
}



#pragma warning(pop)