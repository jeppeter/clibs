#ifndef __DNSTOTAL_H_8B63989FF2928F6B4D0A89F9339B2A23__
#define __DNSTOTAL_H_8B63989FF2928F6B4D0A89F9339B2A23__

#include "evcombo.h"
#include "dnscap.h"
#include <vector>
#include <string>
#include <map>

class DnsTotal : public IEvCombo
{
public:
	DnsTotal(void* pevmain,int timeout);
	virtual ~DnsTotal();
	virtual void notify_event(void* ptr,ev_combo_event_t event);
	int start_dns(int aftype,char* pstr);
	int set_timeout(int timeout);
	int get_result(std::map<std::string,std::vector<std::string>>& res);
	int get_errors(std::vector<std::string>& errs);
	int get_dns_query();

private:
	void __release_resource();
	int __split_name(char* pname,std::string& name, std::string& ports);
	int __handle_error(int idx);
	int __handle_complete(int idx);
	DnsCap* __find_dns(void* parg, int *pidx);
	int __get_result(DnsCap* pcap);

private:
	std::vector<DnsCap*> m_iparrs;
	void* m_evmain;
	std::map<std::string,std::vector<std::string>> m_ipres;
	std::vector<std::string> m_iperrs;
	int m_indelprog;
	int m_timeout;
};


#endif /* __DNSTOTAL_H_8B63989FF2928F6B4D0A89F9339B2A23__ */
