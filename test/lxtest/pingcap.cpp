#include <ux_sock.h>
#include "pingcap.h"
#include <ux_output_debug.h>
#include <ux_err.h>
#include <ux_time_op.h>
#include <ux_strop.h>

#include <time.h>


#define UNREACHABLE_VALUE  0xffffffffffffffff



PingCap::PingCap(int pingtype,const char* ip,int times,int timeout,int nexttime,void* pev,IEvCombo* pcombo)
{
	this->m_sock = NULL;
	this->m_ip = ip;

	this->m_pingtype = pingtype;
	this->m_times = times;
	this->m_timeout = timeout;
	this->m_nexttime = nexttime;

	this->m_rdfd = -1;
	this->m_wrfd = -1;
	this->m_tmoutguid = 0;
	this->m_tmnextguid = 0;

	this->m_inserttmout = 0;
	this->m_inserttmnext = 0;
	this->m_insertrd = 0;
	this->m_insertwr = 0;

	this->m_evmain = pev;
	this->m_combo = pcombo;

}

int PingCap::set_timeout(int timeout)
{
	int ret;
	ret = this->m_timeout;
	this->m_timeout = timeout;
	return ret;
}

int PingCap::set_nexttime(int nextime)
{
	int ret;
	ret = this->m_nexttime;
	this->m_nexttime = nextime;
	return ret;
}

int PingCap::set_times(int times)
{
	int ret;
	ret = this->m_times;
	this->m_times = times;
	return ret;
}


PingCap::~PingCap()
{
	this->__release_resource();
	this->m_ip = "";
	this->__call_remove();
}


void PingCap::__call_remove()
{
	if (this->m_combo) {
		this->m_combo->notify_event(this,remove_event);
	}
}

void PingCap::__call_notify()
{
	if (this->m_combo) {
		this->m_combo->notify_event(this,get_result_event);
	}
}


void PingCap::__remove_tmout()
{
	int ret;
	if (this->m_inserttmout != 0) {
		ret= del_uxev_timer(this->m_evmain,this->m_tmoutguid);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove tmout [%s] error %d", this->m_ip.c_str(), ret);
		}
		this->m_inserttmout = 0;
		this->m_tmoutguid = 0;
	}
	return;
}

void PingCap::__remove_tmnext()
{
	int ret;
	if (this->m_inserttmnext != 0) {
		ret= del_uxev_timer(this->m_evmain,this->m_tmnextguid);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove tmnext [%s] error %d", this->m_ip.c_str(), ret);
		}
		this->m_inserttmnext = 0;
		this->m_tmnextguid = 0;
	}
	return;
}

void PingCap::__remove_rd()
{
	int ret;
	if (this->m_insertrd != 0) {
		ret= delete_uxev_callback(this->m_evmain,this->m_rdfd);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove rdfd [%s] error %d", this->m_ip.c_str(), ret);
		}
		this->m_insertrd = 0;
	}
	return;
}

void PingCap::__remove_wr()
{
	int ret;
	if (this->m_insertwr != 0) {
		ret= delete_uxev_callback(this->m_evmain,this->m_wrfd);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("remove wrfd [%s] error %d", this->m_ip.c_str(), ret);
		}
		this->m_insertwr = 0;
	}
	return;
}


int PingCap::__insert_tmout()
{
	int ret;
	if (this->m_inserttmout == 0) {
		ret= add_uxev_timer(this->m_evmain,this->m_timeout,0,&this->m_tmoutguid,PingCap::ping_timeout,this);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("insert tmout [%s] error %d", this->m_ip.c_str(), ret);
			goto fail;
		}
		this->m_inserttmout = 1;
	} else {
		ERROR_INFO("already insert tmout for [%s]", this->m_ip.c_str());
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::__insert_tmnext()
{
	int ret;
	if (this->m_inserttmnext == 0) {
		ret= add_uxev_timer(this->m_evmain,this->m_nexttime,0,&this->m_tmnextguid,PingCap::ping_timeout,this);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("insert tmnext [%s] error %d", this->m_ip.c_str(), ret);
			goto fail;
		}
		this->m_inserttmnext = 1;
	} else {
		ERROR_INFO("already insert tmnext for [%s]", this->m_ip.c_str());
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::__insert_rd()
{
	int ret;
	if (this->m_insertrd == 0) {
		ret= add_uxev_callback(this->m_evmain,this->m_rdfd,PingCap::ping_callback,this);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("insert rdevt [%s] error %d", this->m_ip.c_str(), ret);
		}
		this->m_insertrd = 1;
	} else {
		ERROR_INFO("already insert [%s] rdevt", this->m_ip.c_str());
	}
	return 0;
}

int PingCap::__insert_wr()
{
	int ret;
	if (this->m_insertwr == 0) {
		ret= libev_insert_handle(this->m_evmain,this->m_wrevt,PingCap::ping_callback,this);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("insert wrevt [%s] error %d", this->m_ip.c_str(), ret);
		}
		this->m_insertwr = 1;
	} else {
		ERROR_INFO("already insert [%s] wrevt", this->m_ip.c_str());
	}
	return 0;
}


void PingCap::__release_resource()
{
	this->__remove_tmout();
	this->__remove_tmnext();
	this->__remove_rd();
	this->__remove_wr();

	free_ping_sock(&this->m_sock);
	this->m_rdevt = NULL;
	this->m_wrevt = NULL;
	this->m_pingval.clear();
	return;
}

int PingCap::__get_now_str(std::string& tstr,uint64_t val)
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


	tstr = "PINGCAP;";
	ret = snprintf_safe(&ccstr,&ccsize,"%s",this->m_ip.c_str());
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
	tstr += ';';
	ret = snprintf_safe(&ccstr,&ccsize,"0x%llx",val);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	tstr += ccstr;
	tstr += ';';

	DEBUG_INFO("[%s]", tstr.c_str());

	tm_to_str(NULL,&ptime,&tsize);
	snprintf_safe(&ccstr,&ccsize,NULL);
	return 0;
fail:
	tm_to_str(NULL,&ptime,&tsize);
	snprintf_safe(&ccstr,&ccsize,NULL);
	SETERRNO(ret);
	return ret;
}

int PingCap::__inc_and_check_next()
{
	int ret = 0;
	this->m_curtime += 1;
	if (this->m_times != 0 && this->m_curtime >= this->m_times)	 {
		ret = 1;
	}
	return ret;
}

int PingCap::__collect_value_and_next(uint64_t val)
{
	std::string tstr;
	int ret;

	ret = this->__get_now_str(tstr,val);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	this->m_pingval.push_back(tstr);

	/*now to remove the values*/
	this->__remove_rd();
	this->__remove_wr();
	this->__remove_tmout();

	ret = this->__insert_tmnext();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	this->__call_notify();

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::__restart()
{
	int ret;
	int completed = 0;
	uint64_t val;

	ASSERT_IF(this->m_sock != NULL);
	this->__remove_wr();
	this->__remove_rd();
	this->__remove_tmout();
	this->__remove_tmnext();

	this->m_wrevt = NULL;
	this->m_rdevt = NULL;

	ret = send_ping_request(this->m_sock, this->m_ip.c_str());
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		ret = recv_ping_response(this->m_sock,&val);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			/**/
			ret = this->__collect_value_and_next(val);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}

			ret = this->__inc_and_check_next();
			if (ret > 0) {
				completed = 1;
			}
		} else {
			this->m_rdevt = get_ping_read_evt(this->m_sock);
			if (this->m_rdevt == NULL) {
				ret = - ERROR_INVALID_PARAMETER;
				ERROR_INFO("can not get rdevt for [%s]", this->m_ip.c_str());
				goto fail;
			}
			ret = this->__insert_rd();
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			ret = this->__insert_tmout();
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}
	} else {
		this->m_wrevt = get_ping_write_evt(this->m_sock);
		if (this->m_wrevt == NULL) {
			ret = - ERROR_INVALID_PARAMETER;
			ERROR_INFO("can not get wrevt for [%s]", this->m_ip.c_str());
			goto fail;
		}
		ret = this->__insert_wr();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		ret = this->__insert_tmout();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::start()
{
	int ret;
	int completed = 0;
	if (this->m_ip.length() == 0) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	this->__release_resource();

	this->m_sock = init_ping_sock(this->m_pingtype);
	if (this->m_sock == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = this->__restart();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		completed = 1;
	}

	
	return completed;
fail:
	this->__release_resource();
	SETERRNO(ret);
	return ret;
}



int PingCap::get_result(std::string& vstr)
{
	int ret = 0;
	if (this->m_pingval.size () > 0) {
		vstr = this->m_pingval.at(0);
		this->m_pingval.erase(this->m_pingval.begin());
		ret = 1;
	}
	return ret;
}

int PingCap::_callback_func(HANDLE hd)
{
	int ret;
	int completed = 0;
	uint64_t val;
	if (hd == this->m_wrevt) {
		ASSERT_IF(this->m_sock != NULL);
		ret = ping_complete_write(this->m_sock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			this->__remove_wr();
			ret = recv_ping_response(this->m_sock,&val);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			} else if (ret > 0) {
				/*now */
				ret = this->__collect_value_and_next(val);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				ret = this->__inc_and_check_next();
				if (ret != 0) {
					completed = 1;
				}
			} else {
				this->m_rdevt = get_ping_read_evt(this->m_sock);
				if (this->m_rdevt == NULL) {
					GETERRNO(ret);
					goto fail;
				}

				ret = this->__insert_rd();
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
			}
		}
	} else if (hd == this->m_rdevt) {
		ASSERT_IF(this->m_sock != NULL);
		ret = ping_complete_read(this->m_sock);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail; 
		} else if (ret > 0) {
			ret = recv_ping_response(this->m_sock,&val);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			} else if (ret > 0) {
				ret = this->__collect_value_and_next(val);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				ret=  this->__inc_and_check_next();
				if (ret != 0) {
					completed = 1;
				}
			} else {
				ret = - ERROR_INVALID_PARAMETER;
				ERROR_INFO("recv ping response on [%s]", this->m_ip.c_str());
				goto fail;
			}
		}
	}
	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::ping_callback(HANDLE hd,libev_enum_event_t event,void* pevmain,void* args)
{
	PingCap* pThis = (PingCap*) args;
	int ret;
	REFERENCE_ARG(pevmain);
	REFERENCE_ARG(event);
	ret = pThis->_callback_func(hd);
	if (ret < 0 || ret > 0) {
		DEBUG_INFO("before del %p", pThis);
		delete pThis;
		DEBUG_INFO("after del %p", pThis);
	}
	return 0;
}

int PingCap::__timeout(uint64_t guid)
{
	int ret;
	int completed = 0;
	if (guid == this->m_tmoutguid) {
		ret = this->__collect_value_and_next(MAX_TIME_VALUE);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = this->__inc_and_check_next();
		if (ret > 0) {
			completed = 1;
		}

	} else if (guid == this->m_tmnextguid) {
		/*we remove tmnext*/
		this->__remove_tmnext();
		/*now to start value*/
		ret = this->__restart();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			completed = 1;
		}
	}
	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::ping_timeout(uint64_t guid,libev_enum_event_t event,void* pevmain,void* args)
{
	PingCap* pThis = (PingCap*) args;
	int ret;
	REFERENCE_ARG(event);
	REFERENCE_ARG(pevmain);
	ret = pThis->__timeout(guid);
	if (ret < 0 || ret > 0) {
		delete pThis;
	}
	return 0;	
}



