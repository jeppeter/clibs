#ifndef __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__
#define __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__

#include <win_err.h>
#include "evcombo.h"
#include <win_libev.h>

class DnsCap : public IEvRunner
{
public:
	DnsCap(int aftype,const char* dnsname,char* portstr,void* pev,IEvCombo* pcombo);
	virtual ~DnsCap();
	virtual int start();
	virtual int get_result(std::string& vstr);
	int set_timeout(int timeout);

private:
	static int dnscap_callback(HANDLE hd,libev_enum_event_t event,void* pevmain,void* args);
	static int dnscap_timeout(uint64_t guid,libev_enum_event_t event,void* pevmain,void* args);

private:
	int _callback_func(HANDLE hd,libev_enum_event_t event);
	int _timeout_func(uint64_t guid, libev_enum_event_t event);
	void __call_notify();
	void __call_remove();
	void __release_resource();
	void __stop_query();

	void __remove_timeout_guid();
	int __insert_timeout_guid();
	void __remove_error_evt();
	int __insert_error_evt();
	void __remove_comp_evt();
	int __insert_comp_evt();

private:
	int m_aftype;
	int m_timeout;
	void* m_dnsqry;
	std::string m_dnsname;
	std::string m_portstr;

	IEvCombo* m_combo;
	void* m_evmain;	


	HANDLE m_compevt;
	int m_insertcomp;
	HANDLE m_errevt;
	int m_inserterr;

	uint64_t m_tmoutguid;
	int m_inserttmout;
};

#endif /* __DNSCAP_H_6301675AB6BAABD6DC4827D9043391E5__ */
