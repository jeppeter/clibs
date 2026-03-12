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
	static tcping_callback(HANDLE hd,libev_enum_event_t event,void* pevmain,void* args);
	static tcping_timeout(uint64_t guid,libev_enum_event_t event,void* pevmain,void* args);


private:
	void __remove_events();
	void __remove_component();
	int __reset_parameter();

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
