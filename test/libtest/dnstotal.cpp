#define _HAS_EXCEPTIONS 0

#include "dnstotal.h"
#include <win_output_debug.h>


#pragma warning(push)
#if defined(_MSC_VER)
#if _MSC_VER >= 1910
/*disable Spectre warnings*/
#pragma warning(disable:5045)
#endif
#endif


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

	while(this->m_endips.size() > 0) {
		DnsCap* cur = this->m_endips.at(0);
		this->m_endips.erase(this->m_endips.begin());
		delete cur;
		cur = NULL;		
	}

	this->m_dnsnames.clear();
	this->m_ports.clear();
	this->m_aftypes.clear();


	this->m_ipres.clear();
	this->m_errs.clear();
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

	pcap = new DnsCap(aftype,(const char*)ns.c_str(),ports.length() == 0 ? (char*)NULL: (char*)ports.c_str());
	ret = pcap->start_query();
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}


	this->m_dnsnames.push_back(pstr);
	this->m_ports.push_back(ports);
	this->m_aftypes.push_back(aftype);
	this->m_iparrs.push_back(pcap);
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

int DnsTotal::__handle_error(int idx)
{
	DnsCap* pcur = this->m_iparrs.at((uint64_t)idx);
	DEBUG_INFO("error %d", idx);
	std::string cstr = this->m_dnsnames.at((uint64_t)idx);
	this->m_dnsnames.erase(this->m_dnsnames.begin() + idx);
	this->m_aftypes.erase(this->m_aftypes.begin() + idx);
	this->m_iparrs.erase(this->m_iparrs.begin() + idx);
	this->m_endips.push_back(pcur);
	this->m_errs.insert({cstr,1});
	return 0;
}

int DnsTotal::__handle_complete(int idx)
{
	std::vector<std::string> dnsarr;
	DEBUG_INFO("complete %d", idx);
	char* ptmpstr=NULL;
	int tmpsize=0;
	DnsCap* pcur = this->m_iparrs.at((uint64_t)idx);
	int j;
	std::string name = this->m_dnsnames.at((uint64_t)idx);
	std::string portstr = this->m_ports.at((uint64_t)idx);
	int ret;


	j = 0;
	while(1) {
		std::string curstr = "";
		ret = pcur->get_result(j,&ptmpstr,&tmpsize);
		if (ret < 0) {
			GETERRNO(ret);
			pcur->get_result(-1,&ptmpstr,&tmpsize);
			goto fail;
		}else if (ret == 0) {
			pcur->get_result(-1,&ptmpstr,&tmpsize);
			break;
		}

		curstr += ptmpstr;
		if (portstr.length() >0) {
			curstr += ';';
			curstr += portstr;
		}

		dnsarr.push_back(curstr);
		j += 1;
	}


	this->m_dnsnames.erase(this->m_dnsnames.begin() + idx);
	this->m_ports.erase(this->m_ports.begin() + idx);
	this->m_aftypes.erase(this->m_aftypes.begin() + idx);
	this->m_iparrs.erase(this->m_iparrs.begin() + idx);
	this->m_endips.push_back(pcur);
	this->m_ipres.insert({name,dnsarr});
	return 0;

fail:
	SETERRNO(ret);
	return ret;
}

int DnsTotal::loop(HANDLE exithd,int timeout)
{
	int ret;
	HANDLE* waithdls=NULL;
	DWORD waitnum=0;
	DnsCap* pcur=NULL;
	int i;
	int waitsize=0;
	waitsize = 1 + (int)this->m_iparrs.size() * 2;
	DWORD dtime,dret ;
	HANDLE hdl;
	int cont;

	waithdls = (HANDLE*)malloc(sizeof(*waithdls) * waitsize);
	if (waithdls == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	while (this->m_iparrs.size() > 0) {
		cont = 1;

		dtime = (DWORD)timeout;
		while(cont) {
			cont = 0;
			for(i=0;i<(int)this->m_iparrs.size();i++) {
				pcur = this->m_iparrs.at((uint64_t)i);
				if (pcur->is_error() != 0 ) {
					ret = this->__handle_error(i);
					if (ret < 0) {
						GETERRNO(ret);
						ERROR_INFO(" ");
						goto fail;
					}
					cont = 1;
					break;
				}

				if (pcur->is_completed() != 0) {
					ret = this->__handle_complete(i);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
					cont = 1;
					break;
				}
				/*time out so do this remove*/
				ret = pcur->need_time(timeout);
				if (ret < 0) {
					DEBUG_INFO("[%d]need time %d",i ,ret);
					ret = this->__handle_error(i);
					cont = 1;
					break;
				} else if ((int)dtime > ret) {
					dtime = (DWORD)ret;
				}
			}
		}

		cont = 1;

		waitnum = 0;
		while (cont != 0) {
			cont = 0;
			waitnum = 0;
			if (exithd != NULL) {
				waithdls[waitnum] = exithd;
				waitnum += 1;
			}


			for(i=0;i< (int)this->m_iparrs.size();i++) {
				pcur = this->m_iparrs.at((uint64_t)i);
				if (pcur->is_error() != 0) {
					ret = this->__handle_error(i);
					if (ret < 0) {
						GETERRNO(ret);
						pcur = NULL;
						goto fail;
					}
					cont = 1;
					break;
				}

				if (pcur->is_completed() != 0) {
					ret = this->__handle_complete(i);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
					cont=1;
					break;
				}

				waithdls[waitnum] = pcur->get_complete_evt();
				if (waithdls[waitnum] != NULL) {
					waitnum += 1;
				}

				waithdls[waitnum] = pcur->get_error_evt();
				if (waithdls[waitnum] != NULL) {
					waitnum += 1;
				}				
			}
		}

		if (waitnum == 0 || this->m_iparrs.size() == 0) {
			break;
		}




		dret = WaitForMultipleObjectsEx(waitnum,waithdls,FALSE,dtime,TRUE);
		if (dret < (WAIT_OBJECT_0 + waitnum)) {
			hdl = waithdls[(dret- WAIT_OBJECT_0)];
			if (hdl == exithd) {
				ret = -WSAEINTR;
				ERROR_INFO("exithdl");
				goto fail;
			}

			for(i=0;i< (int)this->m_iparrs.size();i++) {
				pcur = this->m_iparrs.at((uint64_t)i);
				if (pcur->get_complete_evt() == hdl) {
					ret = this->__handle_complete(i);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
					break;
				}

				if (pcur->get_error_evt() == hdl) {
					ret = this->__handle_error(i);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
					break;					
				}
			}

		} else if (dret != WAIT_TIMEOUT) {
			GETERRNO(ret);
			ERROR_INFO("wait timeout");
			goto fail;
		}
	}


	if (waithdls) {
		free(waithdls);
	}
	waithdls = NULL;


	return 0;
fail:
	if (waithdls) {
		free(waithdls);
	}
	waithdls = NULL;

	SETERRNO(ret);
	return ret;
}

int DnsTotal::get_result(std::map<std::string,std::vector<std::string>>& res)
{
	int cnt=0;
	res.clear();
	for(auto iter = this->m_ipres.begin();iter != this->m_ipres.end();++ iter) {
		res.insert({iter->first,this->m_ipres[iter->first]});
		cnt += 1;
	}
	return cnt;
}

int DnsTotal::get_error(std::vector<std::string>& res)
{
	int cnt = 0;
	res.clear();
	for(auto iter = this->m_errs.begin();iter != this->m_errs.end(); ++ iter) {
		res.push_back(iter->first);
		cnt += 1;
	}
	return cnt;
}

#pragma warning(pop)