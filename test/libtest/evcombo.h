#ifndef __EVCOMBO_H_9C6BB9CD28732F9654EB0DB80140E41F__
#define __EVCOMBO_H_9C6BB9CD28732F9654EB0DB80140E41F__


#include <string>

typedef enum {
	remove_event = 0,
	get_result_event,
} ev_combo_event_t;


class IEvCombo {
public:
	virtual ~IEvCombo() {};
	virtual void notify_event(void* ptr,ev_combo_event_t event)=0;
};

class IEvRunner {
public:
	virtual ~IEvRunner(void) {};
	virtual int start()=0;
	virtual int get_result(std::string& vstr)=0;
};

#endif /* __EVCOMBO_H_9C6BB9CD28732F9654EB0DB80140E41F__ */
