#define _HAS_EXCEPTIONS 0

#include "dnstotal.h"
#include <win_output_debug.h>

#include <iterator>


#pragma warning(push)
#if defined(_MSC_VER)
#if _MSC_VER >= 1910
/*disable Spectre warnings*/
#pragma warning(disable:5045)
#endif
#endif


DnsTotal::DnsTotal(void* pevmain,int timeout)
{
	this->m_evmain = pevmain;
	this->m_timeout = timeout;
	this->m_indelprog = 0;
}

int DnsTotal::set_timeout(int timeout)
{
	int ret =this->m_timeout;
	this->m_timeout = timeout;
	return ret;
}

DnsTotal::~DnsTotal()
{
	this->m_indelprog = 1;
	this->__release_resource();
	this->m_indelprog = 0;
}

void DnsTotal::__release_resource()
{
	while(this->m_iparrs.size() > 0) {
		DnsCap* cur = this->m_iparrs.at(0);
		this->m_iparrs.erase(this->m_iparrs.begin());
		delete cur;
		cur = NULL;
	}

	this->m_ipres.clear();
	return;
}

int DnsTotal::__split_name(char* pname,std::string& name, std::string& ports)
{
	std::string ns = pname;
	size_t sidx;
	ports = "";
	name = "";

	sidx = ns.find(',');
	if (sidx == std::string::npos) {
		name = pname;
	} else {
		name = ns.substr(0,sidx);
		ports = ns.substr(sidx+1,ns.length() - sidx-1);
	}
	DEBUG_INFO("name %s ports %s",name.c_str(),ports.c_str());
	return 0;
}

DnsCap* DnsTotal::__find_dns(void* parg,int *pidx)
{
	DnsCap* pret = NULL;
	DnsCap* pcap = NULL;
	int i;

	for(i=0;i< (int)this->m_iparrs.size() ;i += 1) {
		pcap = this->m_iparrs.at((uint64_t)i);
		if (pcap == parg) {
			pret = pcap;
			if (pidx) {
				*pidx = i;
			}
			break;
		}
	}

	return pret;
}

int DnsTotal::__get_result(DnsCap* pcap)
{
	int ret;
	std::string vstr;
	std::string partname;
	std::string dname;
	std::string ports;
	size_t ns;
	size_t passlen;
	int cnt = 0;
	while(1) {
		ret = pcap->get_result(vstr);
		if (ret == 0) {
			break;
		}

		DEBUG_INFO("get [%s]", vstr.c_str());
		if (vstr.compare(0,6,"ERROR;") == 0) {
			/*now to get the value*/
			ns = vstr.find(';',6);
			if (ns != std::string::npos) {
				partname = vstr.substr(6,ns);
			} else {
				partname = vstr.substr(6,vstr.length()-1);
			}
			this->m_iperrs.push_back(partname);
			cnt = 1;
		} else {
			passlen = 0;
			std::string k;
			std::vector<std::string> vvec;
			ns = vstr.find(';',0);
			if (ns == std::string::npos) {
				k = vstr;
				passlen = vstr.length();
			} else {
				k = vstr.substr(0,ns);
				passlen = ns + 1;
			}
			DEBUG_INFO("k [%s]", k.c_str());

			auto iter = this->m_ipres.find(k);
			if (iter != this->m_ipres.end()) {
				std::copy(iter->second.begin(),iter->second.end(),std::back_inserter(vvec));
			}


			while(passlen < vstr.length()) {
				ns = vstr.find(';',passlen);
				if (ns == std::string::npos) {
					partname = vstr.substr(ns,vstr.length() - ns -1);
					DEBUG_INFO("ns %d partname [%s]", ns, partname.c_str());
					vvec.push_back(partname);
					passlen = vstr.length();
					break;
				}

				partname = "";
				partname = vstr.substr(passlen,ns- passlen);
				DEBUG_INFO("new [%d:%d] [%s] vstr [%s]",passlen, ns - passlen, partname.c_str(),vstr.c_str());
				passlen = ns + 1;
				vvec.push_back(partname);
				cnt += 1;
			}

			if (iter != this->m_ipres.end()) {
				iter->second = vvec;
			} else {
				this->m_ipres.insert({k,vvec});
			}
		}		
	}
	return cnt;
}

void DnsTotal::notify_event(void* parg, ev_combo_event_t event)
{
	int idx=0;
	DnsCap* pcap = this->__find_dns(parg,&idx);
	if (pcap == NULL) {
		return;
	}
	DEBUG_INFO("find %p %d",parg, idx);
	if (event == remove_event) {
		this->m_iparrs.erase(this->m_iparrs.begin() + idx);
		if (this->m_indelprog == 0 && this->m_iparrs.size() == 0) {
			if (this->m_evmain) {
				/*to break the loop*/
				libev_break_winev_loop(this->m_evmain);
			}
		}
	} else if (event == get_result_event) {
		this->__get_result(pcap);
	}
	return ;
}

int DnsTotal::start_dns(int aftype,char* pstr)
{

	DnsCap* pcap = NULL;
	std::string ns,ports;
	int ret;

	ret = this->__split_name(pstr,ns,ports);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	pcap = new DnsCap(aftype,(const char*)ns.c_str(),ports.length() == 0 ? (char*)NULL: (char*)ports.c_str(),this->m_evmain,this);
	pcap->set_timeout(this->m_timeout);
	ret = pcap->start();
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	} else if (ret > 0) {
		/*we do not need to insert*/
		ret = this->__get_result(pcap);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		delete pcap;
		pcap = NULL;
	} else {
		DEBUG_INFO("insert %p",pcap);
		this->m_iparrs.push_back(pcap);	
	}
	
	/*do not clear*/
	pcap = NULL;

	return 0;
fail:
	if (pcap) {
		delete pcap;
	}
	pcap = NULL;
	SETERRNO(ret);
	return ret;
}



int DnsTotal::get_result(std::map<std::string,std::vector<std::string>>& res)
{
	int cnt=0;
	res.clear();
	for(auto iter = this->m_ipres.begin();iter != this->m_ipres.end();++ iter) {
		res.insert({iter->first,iter->second});
		cnt += 1;
	}
	return cnt;
}

int DnsTotal::get_errors(std::vector<std::string>& errs)
{
	int cnt =0;
	errs.clear();

	std::copy(this->m_iperrs.begin(),this->m_iperrs.end(),std::back_inserter(errs));
	cnt = (int)this->m_iperrs.size();
	return cnt;
}

int DnsTotal::get_dns_query()
{
	return (int)this->m_iparrs.size();
}

#pragma warning(pop)