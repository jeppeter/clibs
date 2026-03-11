#ifndef __DNSTOTOAL_H_8B63989FF2928F6B4D0A89F9339B2A23__
#define __DNSTOTOAL_H_8B63989FF2928F6B4D0A89F9339B2A23__

#include "dnscap.h"
#include <vector>
#include <map>

class DnsTotal 
{
public:
	DnsTotal();
	virtual ~DnsTotal();
	int start_dns(int aftype,char* pstr);
	int loop();
	int is_complete(char* pstr);
	int get_result(char* pstr,int idx,char** ppstr,int* psize);
	int get_error(char* pstr, char** ppstr, int *psize);

private:
	void __release_resource();

private:
	std::vector<DnsCap*> m_iparrs;
	std::vector<std::string> m_dnsnames;
	std::vector<int> m_aftypes;
	std::map<std::string,DnsCap*> m_mapdns;
	std::map<std::string,std::map<std::string,std::string>> m_ipmaps;
	std::map<std::string,std::vector<std::string>> m_ipres;
	std::map<std::string,std::string> m_errs;
};


#endif /* __DNSTOTOAL_H_8B63989FF2928F6B4D0A89F9339B2A23__ */
