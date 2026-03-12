#ifndef __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__
#define __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__

#include <vector>
#include <win_libev.h>
#include <string>
#include "evcombo.h"

#include <vector>


class TcpingCap 
{
public:
	TcpingCap(int aftype,const char* ipstr,const char* portstr,void* pev,IEvCombo* pcombo);
	virtual ~TcpingCap();
	int set_timeout(int timeout);
	int set_nexttime(int nextime);
	int set_times(int times);
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

	void __release_resource();

	int __collect_value();
	int __collect_and_switch_next();
	int __inc_and_check_times_over();


	int __reset_parameter();
	int __switch_to_next_wait();
	int __switch_to_start();

	int __handle_evt(HANDLE hd,libev_enum_event_t event);
	int __handle_timeout(uint64_t guid,libev_enum_event_t event);

	int __call_notify();


private:
	std::string m_ipstr;
	int m_port;
	int m_tcpingtype;
	void* m_evmain;
	IEvCombo* m_combo;

	void* m_sock;

	int m_times;
	int m_curtime;
	int m_timeout;
	int m_nexttime;


	HANDLE m_evthd;
	uint64_t m_tmoutguid;
	uint64_t m_tmnextguid;

	int m_inserthd;
	int m_tmoutok;
	int m_tmnextok;
	int m_reserv1;

	std::vector<uint64_t> m_tcpingval;
};


#endif /* __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__ */
