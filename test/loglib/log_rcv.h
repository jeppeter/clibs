#ifndef __LOG_RCV_H_5A2EE3B5EB2ED26636E87A3752BA8DBC__
#define __LOG_RCV_H_5A2EE3B5EB2ED26636E87A3752BA8DBC__

#include <win_map.h>
#include <win_evt.h>
#include <win_libev.h>
#include <log_inter.h>
#include <vector>

class LogMonitor
{
public:
	LogMonitor(void* pevmain,int global=0);
	virtual ~LogMonitor();
	int add_log_callback(LogCallback* pcallback);
	int remove_log_callback(LogCallback* pcallback);
	int start();

private:
	void __remove_all_callbacks();

private:
	void* m_pevmain;
	int m_global;
	std::vector<LogCallback*> m_pcallback;
};

#endif /* __LOG_RCV_H_5A2EE3B5EB2ED26636E87A3752BA8DBC__ */
