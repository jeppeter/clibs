#include "dnscap.h"
#include <ux_dns.h>
#include <ux_output_debug.h>




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

	this->m_evtfd = -1;
	this->m_insertfd = 0;

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
	this->__remove_evtfd();
	this->__remove_timeout_guid();

	free_dns_query(&this->m_dnsqry);
	this->m_results.clear();

	this->m_evtfd = -1;
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
	int ret;
	if (this->m_inserttmout != 0) {
		ret = del_uxev_timer(this->m_evmain,this->m_tmoutguid);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove [%s:%s] tmoutguid 0x%llx error %d", this->m_dnsname.c_str(), this->m_portstr.c_str(), this->m_tmoutguid,ret);
		}
		this->m_inserttmout = 0;
		this->m_tmoutguid = 0;
	}
	return;
}


void DnsCap::__remove_evtfd()
{
	int ret;
	if (this->m_insertfd != 0) {
		ret = delete_uxev_callback(this->m_evmain,this->m_evtfd);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove [%s:%s] compevt error %d", this->m_dnsname.c_str(),this->m_portstr.c_str(),ret);
		}
		this->m_insertfd = 0;
	}
	return;
}

int DnsCap::__insert_timeout_guid()
{
	int ret;
	if (this->m_inserttmout == 0) {
		ret = add_uxev_timer(this->m_evmain,(uint32_t)this->m_timeout,0,&this->m_tmoutguid,DnsCap::dnscap_timeout,this);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_inserttmout = 1;
	} else {
		ret = -EBUSY;
		ERROR_INFO("already exist [%s:%s] tmout guid", this->m_dnsname.c_str(),this->m_portstr.c_str());
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


int DnsCap::__insert_evtfd()
{
	int ret;
	if (this->m_insertfd == 0) {
		ret = add_uxev_callback(this->m_evmain,this->m_evtfd,READ_EVENT,DnsCap::dnscap_callback,this);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_insertfd = 1;
	} else {
		ret = -EBUSY;
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
		ret = -EINVAL;
		ERROR_INFO("not set dnsname");
		SETERRNO(ret);
		return ret;
	}

	this->__stop_query();

	this->m_dnsqry = start_dns_query(this->m_aftype,this->m_dnsname.c_str(),this->m_portstr.length() == 0 ? NULL : (char*)this->m_portstr.c_str());
	if (this->m_dnsqry == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret =  is_dns_query_completed(this->m_dnsqry);
	if (ret > 0) {
		ret = this->__fill_dns_info();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->__call_notify();
		completed = 1;
	} else {
		/*now we should set value*/
		this->m_evtfd = dns_query_get_complete_evt(this->m_dnsqry);
		if (this->m_evtfd < 0) {
			ret = - EINVAL;
			ERROR_INFO("can not get evtfd");
			goto fail;
		}

		ret = this->__insert_evtfd();
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
		vstr += ';';
		DEBUG_INFO("insert [%s]", vstr.c_str());
		this->m_results.push_back(vstr);
		idx += 1;
	}

	dns_query_get_result(NULL,-1,&pdns,&dnssize);
	return 0;
}

int DnsCap::__fill_dns_error()
{
	std::string vstr;

	vstr = "ERROR;";
	vstr += this->m_dnsname;
	if (this->m_portstr.length() > 0) {
		vstr += ',';
		vstr += this->m_portstr;
	}
	vstr += ';';
	this->m_results.push_back(vstr);
	return 0;
}

int DnsCap::_timeout_func(uint64_t guid,int event)
{
	int ret;

	if (guid == this->m_tmoutguid) {
		ret = this->__fill_dns_error();
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("fill [%s:%s] error %d", this->m_dnsname.c_str(), this->m_portstr.c_str(), ret);
			goto fail;
		}
		this->__remove_timeout_guid();
		this->__remove_evtfd();
		this->__call_notify();
		/*to exists*/
		ret = -EBUSY;
		SETERRNO(ret);
		return ret;
	} else {
		ERROR_INFO("0x%llx not guid", guid);
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int DnsCap::_callback_func(int fd,int event)
{
	int ret;
	int error;

	if (fd == this->m_evtfd) {
		/*now to */
		ret = is_dns_query_completed(this->m_dnsqry);
		if (ret != 0) {
			ret = dns_query_get_error_code(this->m_dnsqry,&error);
			if (ret != 0) {
				if (error != 0) {
					ret = this->__fill_dns_error();
				} else {
					ret = this->__fill_dns_info();
				}
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}					
				this->__remove_timeout_guid();
				this->__remove_evtfd();
				this->__call_notify();
				/*to exists*/
				ret = -EBUSY;
				SETERRNO(ret);
				return ret;
			}
		}
	} else {
		ERROR_INFO("fd %d not ok",fd);
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int DnsCap::dnscap_callback(void* pev,uint64_t fd,int event,void* arg)
{
	DnsCap* pThis= (DnsCap*)arg;
	int ret;

	ret = pThis->_callback_func(fd,event);
	if (ret < 0) {
		DEBUG_INFO("delete [%s:%s]", pThis->m_dnsname.c_str(),pThis->m_portstr.c_str());
		delete pThis;
	}
	return 0;
}

int DnsCap::dnscap_timeout(void* pev,uint64_t fd,int event,void* arg)
{
	DnsCap* pThis= (DnsCap*)arg;
	int ret;

	ret = pThis->_timeout_func(fd,event);
	if (ret < 0) {
		delete pThis;
	}
	return 0;
}

int DnsCap::set_timeout(int timeout)
{
	int ret = this->m_timeout;
	this->m_timeout = timeout;
	return ret;
}

int DnsCap::get_result(std::string& vstr)
{
	if(this->m_results.size() == 0) {
		return 0;
	}

	vstr = this->m_results.at(0);
	this->m_results.erase(this->m_results.begin());
	return 1;
}

