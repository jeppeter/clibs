#ifndef __LOG_INTER_H_74EFA84A6E7766FEEC1F6C558A071327__
#define __LOG_INTER_H_74EFA84A6E7766FEEC1F6C558A071327__

#include <win_libev.h>

class LogCallback 
{
public:
	virtual ~LogCallback() {};
	virtual int handle_log_buffer(char* pbuf,int buflen)=0;
	virtual int start()=0;
};


#endif /* __LOG_INTER_H_74EFA84A6E7766FEEC1F6C558A071327__ */
