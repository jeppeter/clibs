#ifndef __TCPINGTOTAL_H_F0F9821FF614549F406852B779173CB9__
#define __TCPINGTOTAL_H_F0F9821FF614549F406852B779173CB9__

#include "evcombo.h"
#include "tcpingcap.h"
#include <vector>
#include <ux_libev.h>

class TcpingTotal : public IEvCombo
{
public:
	TcpingTotal(void* pev,int times,int timeout,int nexttime);
	virtual ~TcpingTotal();
	virtual void notify_event(void* ptr,ev_combo_event_t event);
	int start_tcping(int aftype,const char* ipstr, char* portstr);
	int set_times(int times);
	int set_timeout(int timeout);
	int set_nexttime(int nexttime);
	int get_tasks();

private:
	void __release_resource();
	TcpingCap* __get_cap(void* pthis,int& idx);

private:
	void* m_evmain;
	std::vector<TcpingCap*> m_caps;

	int m_times;
	int m_nexttime;
	int m_timeout;

	int m_indestruct;
};

#endif /* __TCPINGTOTAL_H_F0F9821FF614549F406852B779173CB9__ */
