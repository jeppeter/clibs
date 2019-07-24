#ifndef __LOG_INTER_H_74EFA84A6E7766FEEC1F6C558A071327__
#define __LOG_INTER_H_74EFA84A6E7766FEEC1F6C558A071327__

#include <win_libev.h>

class LogCallback 
{
public:
	virtual LogCallback(void* pevmain) {};
	virtual ~LogCallback() = 0;
	virtual int handle_log_buffer(char* pbuf,int buflen);
	virutal int start();
};


#endif /* __LOG_INTER_H_74EFA84A6E7766FEEC1F6C558A071327__ */
