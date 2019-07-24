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
	void __remove_data_ready_evt();
	HANDLE __create_event_name(char* name);
	static void handle_data_ready(HANDLE hd,libev_enum_event_t evt,void* pevmain, void* args);

private:
	void* m_pevmain;
	int m_global;
	std::vector<LogCallback*> m_pcallback;
	HANDLE m_buffready;
	HANDLE m_dataready;
	void* m_mapbuf;
	int m_inserted;
	char* m_pcurdata;
	int m_cursize;
	int m_curlen;
};

#endif /* __LOG_RCV_H_5A2EE3B5EB2ED26636E87A3752BA8DBC__ */
