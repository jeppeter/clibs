
#pragma warning(push)
#pragma warning(disable:4668)
#pragma warning(disable:4820)

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma warning(pop)

#include "pingcap.h"
#include <win_output_debug.h>
#include <win_err.h>
#include <win_time.h>

#pragma warning(push)
#pragma warning(disable:4530)
#pragma warning(disable:4577)
#pragma warning(disable:5045)

#define UNREACHABLE_VALUE  0xffffffffffffffff


PingCap::PingCap(const char* ip,int timeout,int nextout,int times)
{
	this->m_verbose = 0;
	this->m_sock = NULL;
	this->m_ip = _strdup(ip);
	this->m_pingtype = AF_INET;
	this->m_expire = 0;
	this->m_nextstart = 0;
	this->m_times = times;
	this->m_timeout = timeout;
	this->m_nexttime = nextout;
	this->m_pingval = NULL;
}

PingCap::~PingCap()
{
	this->__release_resource();
	if (this->m_ip) {
		free(this->m_ip);
	}
	this->m_ip = NULL;	

}

void PingCap::_print_result(const char* file, int line,uint64_t val)
{
	if (this->m_verbose > 0) {
		printf("[%s:%d] %s ttl %lld\n",file,line,this->m_ip, val);
	}
	return;
}

void PingCap::__release_resource()
{
	free_ping_sock(&this->m_sock);
	if (this->m_pingval) {
		while(this->m_pingval->size() > 0) {
			this->m_pingval->erase(this->m_pingval->begin());
		}
		delete this->m_pingval;
	}
	this->m_pingval = NULL;
	this->m_expire = 0;
	this->m_nextstart = 0;
	return;
}

int PingCap::__start_alloc()
{
	int ret;
	uint64_t val;
	/*now to init*/
	ASSERT_IF(this->m_sock == NULL);
	ASSERT_IF(this->m_pingval != NULL);
	DEBUG_INFO("m_pingtype %d", this->m_pingtype);
	this->m_sock = init_ping_sock(this->m_pingtype);
	if (this->m_sock == NULL) {
		GETERRNO(ret);
		DEBUG_INFO("ret %d", ret);
		goto fail;
	}
	ret = send_ping_request(this->m_sock,this->m_ip);
	this->m_expire = get_current_ticks();
	if (ret < 0) {
		GETERRNO(ret);
		DEBUG_INFO("error [%d]", this->m_ip);
		goto fail;
	} else if (ret > 0) {
		ret = recv_ping_response(this->m_sock,&val);
		if (ret < 0) {
			GETERRNO(ret);
			DEBUG_INFO("recv [%s] error %d", this->m_ip, ret);
			goto fail;
		} else if (ret > 0) {
			this->_print_result(__FILE__,__LINE__,val);
			this->m_pingval->push_back(val);
			this->m_expire = 0;
			this->m_nextstart = get_current_ticks();
		}
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::_get_ping_type()
{
	struct addrinfo hints;
	struct addrinfo* pres=NULL;
	int ret;

	memset(&hints,0,sizeof(hints));
	hints.ai_flags = 0;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = 0;


	DEBUG_INFO(" ");
	ret = getaddrinfo(this->m_ip,"0",&hints,&pres);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("get [%s] addrinfo error %d", this->m_ip,ret);
		goto fail;
	}

	if (pres == NULL) {
		GETERRNO(ret);
		ERROR_INFO("get [%s] null", this->m_ip);
		goto fail;
	}

	DEBUG_INFO(" ");
	this->m_pingtype = pres->ai_addr->sa_family;
	if (pres != NULL) {
		freeaddrinfo(pres);	
	}
	pres = NULL;
	return 1;
fail:
	if (pres != NULL) {
		freeaddrinfo(pres);	
	}
	pres = NULL;
	SETERRNO(ret);
	return ret;
}

int PingCap::start()
{
	int ret;
	if (this->m_ip == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	ret = this->_get_ping_type();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	this->__release_resource();
	if (this->m_pingval == NULL) {
		this->m_pingval = new std::vector<uint64_t>();
	}

	ret = this->__start_alloc();
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("ret %d", ret);
		goto fail;
	}
	
	return 0;
fail:
	this->__release_resource();
	SETERRNO(ret);
	return ret;
}

int PingCap::get_mode()
{
	int ret;
	int retval = NONE_MODE;
	uint64_t cticks;
	if (this->m_sock == NULL) {
		return NONE_MODE;
	}

	if ((int)this->m_pingval->size() >= this->m_times && this->m_times != 0) {
		DEBUG_INFO("[%s] COMPLETE_MODE", this->m_ip);
		return COMPLETE_MODE;
	}

	if (this->m_expire == 0 && this->m_nextstart != 0) {
		cticks = get_current_ticks();
		ret = need_wait_times(this->m_nextstart,cticks,this->m_nexttime);
		if (ret < 0) {
			DEBUG_INFO("[%s] START_MODE", this->m_ip);
			return START_MODE;
		} else {
			DEBUG_INFO("[%s] NEXT_MODE", this->m_ip);
			return NEXT_MODE;
		}
	}

	if (this->m_expire != 0) {
		cticks = get_current_ticks();
		ret = need_wait_times(this->m_expire,cticks,this->m_timeout);
		if (ret < 0) {
			DEBUG_INFO("[%s] EXPIRE_MODE", this->m_ip);
			return EXPIRE_MODE;
		}
		retval = NONE_MODE;
		if (ping_is_read_mode(this->m_sock) != 0) {
			DEBUG_INFO("[%s] READ_MODE", this->m_ip);
			retval |= READ_MODE;
		}
		if (ping_is_write_mode(this->m_sock) != 0) {
			DEBUG_INFO("[%s] WRITE_MODE", this->m_ip);
			retval |= WRITE_MODE;
		}
	}
	return retval;
}

HANDLE PingCap::get_read_evt()
{
	HANDLE hret=NULL;
	if (this->m_sock) {
		hret = get_ping_read_evt(this->m_sock);
	}
	return hret;
}

HANDLE PingCap::get_write_evt()
{
	HANDLE hret=NULL;
	if (this->m_sock) {
		hret = get_ping_write_evt(this->m_sock);
	}
	DEBUG_INFO("[%s] hret %p", this->m_ip, hret);
	return hret;
}

int PingCap::send_ping()
{
	int ret;
	if (this->m_sock == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}
	ret = send_ping_request(this->m_sock,this->m_ip);
	this->m_expire = get_current_ticks();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	return ret;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::read_ping(uint64_t& val)
{
	uint64_t cval;
	int ret;
	if (this->m_sock == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	ret = recv_ping_response(this->m_sock,&cval);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		this->_print_result(__FILE__,__LINE__,val);
		this->m_expire = 0;
		this->m_pingval->push_back(cval);
		val = cval;
	}
	return ret;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::get_result(int idx,uint64_t& val)
{
	if (this->m_pingval != NULL && idx < (int)this->m_pingval->size()) {
		uint64_t cval;
		cval = this->m_pingval->at((uint64_t)idx);
		val = cval;
		return 1;
	}
	return 0;
}

int PingCap::get_mean_result(uint64_t& val)
{
	uint64_t tval=0;
	uint64_t mval = 0;
	int ret=0;
	uint64_t cval;
	uint64_t succcnt = 0;
	int idx;
	if (this->m_pingval != NULL && this->m_pingval->size() > 0) {
		for(idx=0;idx < (int)this->m_pingval->size();idx++) {
			cval = this->m_pingval->at((uint64_t)idx);
			if (cval != UNREACHABLE_VALUE) {
				tval += cval;	
				succcnt += 1;
			}			
		}
		if (succcnt != 0) {
			mval = tval / succcnt;
		}
		ret = 1;
	}
	val = mval;
	return ret;
}

double PingCap::get_succ_ratio()
{
	double ratio = 0.0;
	double succcnt = 0.0;
	double allcnt = 0.0;
	int idx = 0;
	uint64_t cval;
	if (this->m_pingval != NULL && this->m_pingval->size() > 0) {
		for(idx=0;idx < (int)this->m_pingval->size();idx++) {
			cval = this->m_pingval->at((uint64_t)idx);
			if (cval != UNREACHABLE_VALUE) {
				succcnt += 1.0;
			}
			allcnt += 1.0;		
		}
		if (allcnt != 0.0) {
			ratio = succcnt / allcnt;
		}
	}
	return ratio;	
}

int PingCap::restart(int timeout)
{
	int ret;
	if (this->m_pingtype == 0) {
		ret = this->_get_ping_type();
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (this->m_sock) {
		free_ping_sock(&this->m_sock);
	}
	if (timeout != 0) {
		/*this means expired*/
		this->_print_result(__FILE__,__LINE__,UNREACHABLE_VALUE);
		this->m_pingval->push_back(UNREACHABLE_VALUE);
	}

	ret = this->__start_alloc();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::complete_read_evt()
{
	int ret;
	int retv=0;
	uint64_t cval;

	if (this->m_sock == NULL){
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	ret = ping_complete_read(this->m_sock);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		retv = 1;
		ret = recv_ping_response(this->m_sock,&cval);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		} else if (ret > 0) {
			this->m_expire = 0;
			this->m_nextstart = get_current_ticks();
			this->_print_result(__FILE__,__LINE__,cval);
			ASSERT_IF(this->m_pingval != NULL);
			this->m_pingval->push_back(cval);
		}
	}
	return retv;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::complete_write_evt()
{
	int ret;
	int retv=0;
	uint64_t cval;

	if (this->m_sock == NULL){
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	ret = ping_complete_write(this->m_sock);
	if (ret < 0) {
		GETERRNO(ret);
		DEBUG_INFO(" ");
		if (ret != -WSAENETUNREACH && ret != -WSAENETRESET) {
			goto fail;
		}

		/*this is unreachable , so reset*/
		cval = UNREACHABLE_VALUE;
		this->m_pingval->push_back(cval);
		this->_print_result(__FILE__,__LINE__,cval);
		/*this is for next restart*/
		this->m_expire = 0;
		this->m_nextstart = get_current_ticks();
		retv= 1;
	} else if (ret > 0) {
		retv = 1;
		ret = recv_ping_response(this->m_sock,&cval);
		if (ret < 0) {
			GETERRNO(ret);
			DEBUG_INFO(" ");
			goto fail;
		} else if (ret > 0) {
			this->m_expire = 0;
			this->m_nextstart = get_current_ticks();
			this->_print_result(__FILE__,__LINE__,cval);
			ASSERT_IF(this->m_pingval != NULL);
			this->m_pingval->push_back(cval);
		}
	}
	return retv;
fail:
	SETERRNO(ret);
	return ret;
}

int PingCap::get_expire()
{
	int retval = 0x7fffffff;
	int ret;
	uint64_t cticks;
	cticks = get_current_ticks();
	if (this->m_expire != 0) {
		ret = need_wait_times(this->m_expire,cticks,this->m_timeout);
		if (ret < 0) {
			retval = 0;
		} else {
			retval = ret;
		}
	}
	return retval;
}

int PingCap::get_next_expire()
{
	int retval = 0x7fffffff;
	int ret;
	uint64_t cticks;
	cticks = get_current_ticks();
	if (this->m_expire == 0) {
		ret = need_wait_times(this->m_nextstart,cticks,this->m_nexttime);
		if (ret < 0) {
			retval = 0;
		} else {
			retval = ret;
		}
	}
	return retval;	
}

int PingCap::set_verbose(int verbose)
{
	int oldval = this->m_verbose;
	this->m_verbose = verbose;
	return oldval;
}

#pragma warning(pop)