#ifndef __LOG_CONSOLE_H_38587978222C71BD746D9FA9FEBD46A2__
#define __LOG_CONSOLE_H_38587978222C71BD746D9FA9FEBD46A2__

#include <log_inter.h>

#pragma warning(push)
#pragma warning(disable:4514)
#include <stdio.h>
#pragma warning(pop)



class LogConsole : public LogCallback
{
public:
	LogConsole(void* pevmain,int stderrmode=1);
	virtual ~LogConsole();
	virtual int handle_log_buffer(char* pbuf,int buflen);
	virtual int start();

private:
	void* m_pevmain;
	FILE* m_fp;
};

#endif /* __LOG_CONSOLE_H_38587978222C71BD746D9FA9FEBD46A2__ */
