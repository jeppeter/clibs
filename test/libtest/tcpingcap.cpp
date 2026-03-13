#define _HAS_EXCEPTIONS 0

#include "tcpingcap.h"

#include <win_output_debug.h>
#include <win_tcping.h>
#include <win_time.h>
#include <win_strop.h>

#include <time.h>

#pragma warning(push)

#if defined(_MSC_VER)
#if _MSC_VER >= 1910
#pragma warning(disable:5045)
#endif
#endif

int TcpingCap::__reset_parameter()
{
	this->m_times = 0;
	this->m_curtime = 0;
	this->m_timeout = 5000;
	this->m_nexttime = 3000;
	return 0;
}

int TcpingCap::set_timeout(int timeout)
{
	int ret;
	ret = this->m_timeout;
	this->m_timeout = timeout;
	return ret;
}

int TcpingCap::set_nexttime(int nextime)
{
	int ret;
	ret = this->m_nexttime;
	this->m_nexttime = nextime;
	return ret;
}

int TcpingCap::set_times(int times)
{
	int ret;
	ret = this->m_times;
	this->m_times = times;
	return ret;
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

void TcpingCap::__remove_evthd()
{
	int ret;
	if (this->m_inserthd != 0) {
		ret = libev_remove_handle(this->m_evmain,this->m_evthd);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove [%s:%d] evthd %x error %d",this->m_ipstr.c_str(),this->m_port,this->m_evthd, ret);
		}
		this->m_inserthd = 0;
	}
	return;
}

void TcpingCap::__remove_tmout()
{
	int ret;
	if (this->m_tmoutok != 0) {
		ret = libev_remove_timer(this->m_evmain,this->m_tmoutguid);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove [%s:%d] tmout 0x%llx error %d", this->m_ipstr.c_str(),this->m_port, this->m_tmoutguid,ret);
		}
		this->m_tmoutok = 0;
		this->m_tmoutguid = 0;
	}
	return;
}

void TcpingCap::__remove_tmnextout()
{
	int ret;
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

void TcpingCap::__remove_events()
{
	this->__remove_evthd();
	this->__remove_tmout();
	this->__remove_tmnextout();
	return ;
}

void TcpingCap::__remove_component()
{
	if (this->m_combo) {
		this->m_combo->notify_event(this,remove_event);
	}
}

void TcpingCap::__release_resource()
{
	this->__remove_events();

	free_tcping_sock(&this->m_sock);
	this->m_evthd = NULL;
	this->m_tcpingval.clear();
}

TcpingCap::~TcpingCap(void)
{
	DEBUG_INFO("TcpingCap destructor");
	this->__release_resource();
	this->__remove_component();

	this->m_evmain = NULL;
	this->m_combo = NULL;

	this->m_ipstr = "";
	this->m_port = -1;

	this->__reset_parameter();
}

int TcpingCap::__insert_tmnextout()
{
	int ret;
	if (this->m_tmnextok == 0) {
		this->m_tmnextguid = 0;
		ret = libev_insert_timer(this->m_evmain,&this->m_tmnextguid,TcpingCap::tcping_timeout,this,(uint32_t)this->m_nexttime,0);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_tmnextok = 1;
	} else {
		ERROR_INFO("already insert tmnextout");
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int TcpingCap::__insert_tmout()
{
	int ret;
	if(this->m_tmoutok == 0) {
		this->m_tmoutguid = 0;
		ret = libev_insert_timer(this->m_evmain,&this->m_tmoutguid,TcpingCap::tcping_timeout,this,(uint32_t)this->m_timeout,0);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_tmoutok = 1;
	} else {
		ERROR_INFO("already insert tmout");
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int TcpingCap::__insert_evthd()
{
	int ret;
	if(this->m_inserthd == 0) {
		ret = libev_insert_handle(this->m_evmain,this->m_evthd,TcpingCap::tcping_callback,this);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_inserthd = 1;
	} else {
		ERROR_INFO("already insert evt");
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int TcpingCap::_get_now_str(std::string& tstr,uint64_t val)
{
	time_t nowt;
	struct tm ctm;
	char* ptime=NULL;
	int tsize=0;
	char* ccstr=NULL;
	int ccsize=0;
	int ret;


	nowt = time(NULL);
	ret = time_to_tm(&nowt,&ctm);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	tstr = "TCPINGCAP;";
	ret = snprintf_safe(&ccstr,&ccsize,"%s,%d",this->m_ipstr.c_str(),this->m_port);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	tstr += ccstr;
	tstr += ";";
	ret = tm_to_str(&ctm,&ptime,&tsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	tstr += ptime;
	ret = snprintf_safe(&ccstr,&ccsize,"0x%llx",val);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	tstr += ccstr;

	tm_to_str(NULL,&ptime,&tsize);
	snprintf_safe(&ccstr,&ccsize,NULL);
	return 0;
fail:
	tm_to_str(NULL,&ptime,&tsize);
	snprintf_safe(&ccstr,&ccsize,NULL);
	SETERRNO(ret);
	return ret;
}

int TcpingCap::__collect_value()
{
	uint64_t val;
	int ret;
	std::string tstr;
	ret = get_tcping_tick(this->m_sock,&val);
	if (ret < 0 ) {
		GETERRNO(ret);
		goto fail;
	}
	ret = this->_get_now_str(tstr,val);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	this->m_tcpingval.push_back(tstr);

	return 0;
fail:
	SETERRNO(ret);
	return ret;	
}

int TcpingCap::__switch_to_next_wait()
{
	int ret;

	ASSERT_IF(this->m_sock != NULL);


	this->__remove_evthd();
	this->__remove_tmout();

	ret = this->__insert_tmnextout();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int TcpingCap::__call_notify()
{
	int ret = 0;
	if (this->m_combo != NULL) {
		this->m_combo->notify_event(this,get_result_event);
		ret = 1;
	}
	return ret;
}

int TcpingCap::__switch_to_start()
{
	int ret;
	this->__remove_tmnextout();

	ASSERT_IF(this->m_sock != NULL);

	ret = resend_tcping_request(this->m_sock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = this->__insert_evthd();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret=  this->__insert_tmout();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


int TcpingCap::start()
{
	int ret;
	if (this->m_evmain == NULL) {
		ret  = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	this->__release_resource();

	this->m_sock = init_tcping_sock(this->m_tcpingtype);
	if (this->m_sock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = send_tcping_request(this->m_sock, this->m_ipstr.c_str(),this->m_port);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (ret > 0) {
		ret = this->__collect_value();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = this->__call_notify();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = this->__switch_to_next_wait();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else {
		if (this->m_evthd == NULL) {
			this->m_evthd = get_tcping_evt(this->m_sock);
			if (this->m_evthd == NULL) {
				GETERRNO(ret);
				ERROR_INFO("can not get evthd");
				goto fail;
			}
		}

		ret = this->__switch_to_start();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	return 0;
fail:
	this->__release_resource();
	SETERRNO(ret);
	return ret;
}

int TcpingCap::__collect_and_switch_next()
{
	int ret;
	ret = this->__collect_value();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	
	ret = this->__call_notify();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret=  this->__switch_to_next_wait();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

fail:
	SETERRNO(ret);
	return ret;	
}

int TcpingCap::__handle_evt(HANDLE hd,libev_enum_event_t event)
{
	int ret;

	REFERENCE_ARG(hd);
	REFERENCE_ARG(event);
	ASSERT_IF(this->m_sock != NULL);
	ret = tcping_complete(this->m_sock);
	if (ret < 0) {
		ERROR_INFO("complete error");
		return 0;
	} else if (ret == 0) {
		return 0;
	} 

	ret = this->__collect_and_switch_next();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 1;
fail:
	SETERRNO(ret);
	return ret;	
}

int TcpingCap::__inc_and_check_times_over()
{
	int ret = 0;
	this->m_curtime += 1;
	if (this->m_times != 0 && this->m_curtime >= this->m_times) {
		ret = 1;
	}
	return ret;
}


int TcpingCap::tcping_callback(HANDLE hd,libev_enum_event_t event,void* pevmain,void* args)
{
	int ret;
	TcpingCap* pThis = (TcpingCap*) args;
	REFERENCE_ARG(pevmain);
	ret = pThis->__handle_evt(hd,event);
	if (ret < 0) {
		delete pThis;
	}
	return 0;
}

int TcpingCap::__handle_timeout(uint64_t guid, libev_enum_event_t event)
{
	int ret;
	REFERENCE_ARG(event);
	if (this->m_tmoutok != 0 && this->m_tmoutguid == guid) {
		std::string cstr;
		/*we remove this before call back*/
		this->__remove_tmout();
		/*ok this will give */
		ret = this->_get_now_str(cstr,TCP_PING_FAIL_VALUE);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}


		this->m_tcpingval.push_back(cstr);
		ret = this->__call_notify();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		ret = resend_tcping_request(this->m_sock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			ret = this->__collect_and_switch_next();
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		} else {
			ret = this->__switch_to_start();
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}

	} else if (this->m_tmnextok != 0 && this->m_tmnextguid == guid) {
		this->__remove_tmnextout();
		ret = this->__switch_to_start();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = this->__inc_and_check_times_over();
		if (ret != 0) {
			ret = -ERROR_ARITHMETIC_OVERFLOW;
			ERROR_INFO("ERROR_ARITHMETIC_OVERFLOW");
			goto fail;
		}
	} else {
		ERROR_INFO("notify with 0x%llx guid" ,guid);
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;	
}

int TcpingCap::tcping_timeout(uint64_t guid,libev_enum_event_t event,void* pevmain,void* args)
{
	int ret;
	REFERENCE_ARG(pevmain);
	TcpingCap* pThis = (TcpingCap*) args;
	ret = pThis->__handle_timeout(guid,event);
	if (ret < 0) {
		delete pThis;
	}
	return 0;
}

int TcpingCap::get_result(std::string& vstr)
{
	int ret = 0;

	if (this->m_tcpingval.size() > 0) {
		vstr = this->m_tcpingval.at(0);
		this->m_tcpingval.erase(this->m_tcpingval.begin());
		ret = 1;
	} else {
		vstr = "";
	}
	return ret;
}

#pragma warning(pop)