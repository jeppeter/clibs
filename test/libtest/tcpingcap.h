#ifndef __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__
#define __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__

#include <vector>
#include <win_libev.h>
#include <string>
#include "evcombo.h"


class TcpingCap 
{
public:
	TcpingCap(int aftype,const char* ipstr,const char* portstr,void* pev,IEvCombo* pcombo);
	virtual ~TcpingCap();
	int set_timeout(int timeout);
	int set_nexttime(int nextime);
	int set_times(int times);
	int set_verbose(int verbose);
	int start();

private:
	static int tcping_callback(HANDLE hd,libev_enum_event_t event,void* pevmain,void* args);
	static int tcping_timeout(uint64_t guid,libev_enum_event_t event,void* pevmain,void* args);


private:
	void __remove_evthd();
	void __remove_tmout();
	void __remove_tmnextout();

	int __insert_evthd();
	int __insert_tmout();
	int __insert_tmnextout();
	void __remove_events();
	void __remove_component();


	int __reset_parameter();
	int __switch_to_next_wait();
	int __switch_to_start();

	int __handle_evt(HANDLE hd,libev_enum_event_t event);
	int __handle_timeout(uint64_t guid,libev_enum_event_t event);

	int __call_notify();
	

private:
	int m_tcpingtype;
	std::string m_ipstr;
	int m_port;
	void* m_evmain;
	IEvCombo* pcombo;

	void* m_sock;

	int m_verbose;	
	int m_times;
	int m_curtime;
	int m_timeout;
	int m_nexttime;


	HANDLE m_evthd;
	int m_inserthd;

	uint64_t m_tmoutguid;
	int m_tmoutok;
	uint64_t m_tmnextguid;
	int m_tmnextok;
	std::vector<uint64_t> m_tcpingval;
};


#endif /* __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__ */
