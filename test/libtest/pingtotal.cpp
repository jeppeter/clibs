#include "pingtotal.h"
#include <win_err.h>
#include <win_libev.h>


#pragma warning(push)
#pragma warning(disable:5045)

PingTotal::PingTotal(int timeout,int nexttime,int times, void* pev)
{
	this->m_ipcnt.clear();
	this->m_ipfail.clear();
	this->m_iptotal.clear();
	this->m_ips.clear();
	this->m_evmain = pev;
	this->m_timeout = 5000;
	this->m_nexttime = 1000;
	this->m_times = 0;

	this->m_deleted = 0;
}

void PingTotal::__release_resource()
{
	while(this->m_ips.size() != 0) {
		auto iter = this->m_ips.begin();
		PingCap* pcap = iter->first;
		this->m_ips.erase(iter);
		delete pcap;
		pcap = NULL;
	}

	this->m_ipcnt.clear();
	this->m_ipfail.clear();
	this->m_iptotal.clear();
}

PingTotal::~PingTotal()
{
	this->m_deleted = 1;
	this->__release_resource();

	this->m_evmain = NULL;

	this->m_deleted = 0;
}

void PingTotal::notify_event(void* ptr,ev_combo_event_t event)
{
	auto iter = this->m_ips.find((PingCap*)ptr);
	if (iter == this->m_ips.end()) {
		return;
	}

	PingCap* pcap = iter->first;
	std::string name = iter->second;

	if (event == remove_event) {
		this->m_ips.erase(iter);
		delete pcap;
		pcap = NULL;
	} else if (event == get_result_event) {
		this->__get_info(pcap,name);		
	}
	return;
}

int PingTotal::set_timeout(int timeout)
{
	int ret;
	ret = this->m_timeout;
	this->m_timeout = timeout;
	return ret;
}

int PingTotal::set_nexttime(int nextime)
{
	int ret;
	ret = this->m_nexttime;
	this->m_nexttime = nextime;
	return ret;
}

int PingTotal::set_times(int times)
{
	int ret;
	ret = this->m_times;
	this->m_times = times;
	return ret;
}

int PingTotal::__get_single_info(std::string& name, std::string& vstr)
{
	size_t np=0;
	std::string hxstr;
	int ret;
	int cnt;
	uint64_t val;
	char* pendptr;

	/*format PINGCAP;192.168.3.11;2020-10-01 12:20:20;0x11;*/
	for(cnt=0;cnt < 3;cnt += 1) {
		np = vstr.find(';',np + 1);
		if (np == std::string::npos) {
			ret = - ERROR_INVALID_PARAMETER;
			ERROR_INFO("[%d]can not parse [%s]",cnt, vstr.c_str());
			goto fail;
		}
	}

	/*to skip ;0x*/
	hxstr = vstr.substr(np + 3, vstr.length() - 1);
	val = std::stoull(hxstr,&pendptr,16);
	DEBUG_INFO("[%s] val 0x%llx", vstr.c_str(),val);

	if (val == MAX_TIME_VALUE) {
		auto iter = this->m_ipcnt.find(name);
		if (iter == this->m_ipcnt.end()) {
			this->m_ipcnt.insert({name,0});
		} 

		auto iter = this->m_ipfail.find(name);
		if (iter == this->m_ipfail.end()) {
			this->m_ipfail.insert({name,1});
		} else {
			iter->second += 1;
		}

		auto iter = this->m_iptotal.find(name);
		if (iter == this->m_iptotal.end()) {
			this->m_iptotal.insert({name,0.0});
		}	
	} else {
		auto iter = this->m_ipcnt.find(name);
		if (iter == this->m_ipcnt.end()) {
			this->m_ipcnt.insert({name,1});
		}  else {
			iter->second += 1;
		}

		auto iter = this->m_ipfail.find(name);
		if (iter == this->m_ipfail.end()) {
			this->m_ipfail.insert({name,0});
		}

		auto iter = this->m_iptotal.find(name);
		double iv = (double) val;
		if (iter == this->m_iptotal.end()) {
			this->m_iptotal.insert({name,iv});
		} else {
			iter->second += iv;
		}
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int PingTotal::__get_info(PingCap* pcap, std::string& name)
{
	std::string vstr;
	int ret;
	int cnt=0;

	while(1) {
		ret = pcap->get_result(vstr);
		if (ret == 0) {
			break;
		}

		ret = this->__get_single_info(name,vstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		cnt += 1;
	}
	
	return cnt;
fail:
	SETERRNO(ret);
	return ret;

}

int PingTotal::add_host(int aftype,const char* ip)
{
	PingCap* pcap=NULL;
	int ret;
	std::string name;
	int completed = 0;

	pcap = new PingCap(aftype,ip,this->m_time,this->m_timeout,this->m_nexttime,this->m_evmain,this);
	ret = pcap->start();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	} else if (ret > 0) {
		/*now we should get the filters*/
		name = ip;
		ret = this->__get_info(pcap,name);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		delete pcap;
		pcap = NULL;
		completed = 1;
	} else {
		/*now to give the map*/
		name = ip;
		this->m_ips.insert({pcap,name});
		pcap = NULL;
	}

	if (pcap) {
		delete pcap;
	}
	pcap = NULL;

	return completed;
fail:
	if (pcap) {
		delete pcap;
	}
	pcap = NULL;
	SETERRNO(ret);
	return ret;
}

int PingTotal::get_mean(std::map<std::string,double>& res)
{
	int ret;
	int cnt=0;

	for(auto iter = this->m_ipcnt.begin(),cnt = 0; iter != this->m_ipcnt.end(); ++ iter,cnt += 1) {
		std::string name = iter->first;
		if (iter->second == 0) {
			res.insert({name,0.0});
		} else {
			auto citer = this->m_iptotal.find(name);
			if (citer == this->m_iptotal.end()) {
				ret = - ERROR_INVALID_PARAMETER;
				ERROR_INFO("can not find [%s] for iptotal", name.c_str());
				goto fail;
			}

			double cval = citer->second / iter->second;
			res.insert({name,cval});
		}
	}

	return cnt;
fail:
	SETERRNO(ret);
	return ret;
}


int PingTotal::get_succ_ratio(std::map<std::string,double>& res)
{
	int ret;
	int cnt = 0;
	for(auto iter = this->m_ipcnt.begin(), cnt = 0; iter != this->m_ipcnt.end() ; ++ iter, cnt += 1) {
		uint64_t succcnt = iter->second;
		std::string name = iter->first;
		auto citer = this->m_ipfail.find(name);
		if (citer == this->m_ipfail.end()) {
			ret = - ERROR_INVALID_PARAMETER;
			ERROR_INFO("can not find [%s] for ipfail", name.c_str());
			goto fail;
		}

		uint64_t failcnt = citer->second;

		if (failcnt == 0) {
			res.insert({name,0.0});
		} else if (succcnt == 0) {
			res.insert({name,1.0});
		} else {
			double cval = (double)succcnt / (double)(succcnt + failcnt);
			res.insert({name,cval});
		}
	}

	return cnt;
fail:
	SETERRNO(ret);
	return ret;
}

int PingTotal::get_tasks()
{
	return (int) this->m_ips.size();
}

#pragma warning(pop)