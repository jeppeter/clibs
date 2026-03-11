#ifndef __DNSTOTAL_H_8B63989FF2928F6B4D0A89F9339B2A23__
#define __DNSTOTAL_H_8B63989FF2928F6B4D0A89F9339B2A23__

#include "dnscap.h"
#include <vector>
#include <map>
#include <string>

class DnsTotal 
{
public:
	DnsTotal();
	virtual ~DnsTotal();
	int start_dns(int aftype,char* pstr);
	int loop(HANDLE exithd,int timeout);
	int is_complete(char* pstr);
	int get_result(char* pstr,int idx,char** ppstr,int* psize);
	int get_error(char* pstr, char** ppstr, int *psize);

private:
	void __release_resource();
	int __split_name(char* pname,std::string& name, std::string& ports);
	int __handle_error(int idx);
	int __handle_complete(int idx);

private:
	std::vector<DnsCap*> m_iparrs;
	std::vector<DnsCap*> m_endips;
	std::vector<std::string> m_dnsnames;
	std::vector<std::string> m_ports;
	std::vector<int> m_aftypes;
	std::map<std::string,std::vector<std::string>> m_ipres;
	std::map<std::string,int> m_errs;
};


#endif /* __DNSTOTAL_H_8B63989FF2928F6B4D0A89F9339B2A23__ */
