#include <log_rcv.h>

LogMonitor::LogMonitor(void* pevmain,int global)
{
	this->m_pevmain = pevmain;
	this->m_global = global;
	this->m_pcallback = NULL;
}

void LogMonitor::__remove_all_callbacks()
{
	if (this->m_pcallback) {
		while(this->m_pcallback->size() > 0) {
			this->m_pcallback->erase(this->m_pcallback->begin());
		}
		delete this->m_pcallback;
		this->m_pcallback = NULL;
	}
	return;
}


LogMonitor::~LogMonitor()
{
	this->__remove_all_callbacks();
}

int LogMonitor::add_log_callback(LogCallback* pcallback)
{
	int ret;
	int findidx=-1;
	DWORD i;
	if (this->m_pcallback == NULL) {
		ret = -ERROR_APP_INIT_FAILURE;
		SETERRNO(ret);
		return ret;
	}
	for (i=0;i<this->m_pcallback->size();i++) {
		if (this->m_pcallback->at(i) == pcallback) {
			findidx = (int) i;
			break;
		}
	}

	if (findidx >= 0) {
		ret = -ERROR_ALREADY_EXISTS;
		SETERRNO(ret);
		return ret;
	}
	this->m_pcallback->push_back(pcallback);
	return (int) this->m_pcallback->size() - 1;
}

int LogMonitor::remove_log_callback(LogCallback* pcallback)
{
	int ret = 0;
	int findidx=-1;
	DWORD i;
	if (this->m_pcallback != NULL) {
		for (i=0;i<this->m_pcallback->size();i++) {
			if (this->m_pcallback->at(i) == pcallback){
				findidx = (int) i;
				break;
			}
		}

		if (findidx >= 0) {
			this->m_pcallback->erase( this->m_pcallback->begin() + findidx);
			ret = 1;
		}
	}
	return ret;
}