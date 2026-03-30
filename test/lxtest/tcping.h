#ifndef __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__
#define __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__

#include <vector>
#include <ux_libev.h>
#include <string>
#include "evcombo.h"

#include <vector>


class TcpingCap : public IEvRunner
{
public:
	TcpingCap(int aftype,const char* ipstr,const char* portstr,void* pev,IEvCombo* pcombo);
	//virtual ~IEvRunner();
	virtual ~TcpingCap(void);
	int set_timeout(int timeout);
	int set_nexttime(int nextime);
	int set_times(int times);
	virtual int start();
	virtual int get_result(std::string& vstr);

private:
	static int tcping_callback(void* pev,uint64_t fd,int event,void* arg);
	static int tcping_timeout(void* pev,uint64_t fd,int event,void* arg);


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

	int __handle_evt(int fd,int event);
	int __handle_timeout(uint64_t guid,int event);

	int __call_notify();

	int _get_now_str(std::string& tstr,uint64_t val);
	int __start_tcping();


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
	uint64_t m_startticks;

	int m_inserthd;
	int m_tmoutok;
	int m_tmnextok;
	int m_error;

	std::vector<std::string> m_tcpingval;
};


#endif /* __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__ */
