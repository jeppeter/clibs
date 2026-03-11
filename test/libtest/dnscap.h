#ifndef __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__
#define __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__

#include <win_err.h>

class DnsCap
{
public:
	DnsCap(int aftype,const char* dnsname,char* portstr);
	virtual ~DnsCap();
	HANDLE get_complete_evt();
	HANDLE get_error_evt();
	int is_completed();
	int is_error();
	int start_query();
	int need_time(int timeout);
	int get_result(int idx,char** ppstr,int *psize);
private:
	void __release_resource();
	void __stop_query();
private:
	int m_aftype;
	int m_reserv1;
	void* m_dnsqry;
	char* m_dnsname;
	char* m_portstr;
};

#endif /* __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__ */
