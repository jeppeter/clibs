#ifndef __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__
#define __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__

#include "evcombo.h"
#include <ux_libev.h>
#include <vector>
#include <string>

class DnsCap : public IEvRunner
{
public:
	DnsCap(int aftype,const char* dnsname,char* portstr,void* pev,IEvCombo* pcombo);
	virtual ~DnsCap();
	virtual int start();
	virtual int get_result(std::string& vstr);
	int set_timeout(int timeout);

private:
	static int dnscap_callback(void* pev,uint64_t fd,int event,void* arg);
	static int dnscap_timeout(void* pev,uint64_t fd,int event,void* arg);

private:
	int _callback_func(int fd,int event);
	int _timeout_func(uint64_t guid, int event);

	int __fill_dns_info();
	int __fill_dns_error();

	void __call_notify();
	void __call_remove();
	void __release_resource();
	void __stop_query();

	void __remove_timeout_guid();
	int __insert_timeout_guid();
	void __remove_evtfd();
	int __insert_evtfd();

private:
	int m_aftype;
	int m_timeout;
	void* m_dnsqry;
	std::string m_dnsname;
	std::string m_portstr;

	IEvCombo* m_combo;
	void* m_evmain;	


	int m_evtfd;
	int m_insertfd;

	uint64_t m_tmoutguid;
	int m_inserttmout;

	std::vector<std::string> m_results;
};

#endif /* __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__ */
