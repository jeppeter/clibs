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
	/*
	return < 0 for failed
	== 0 for it in progress
	> 0 for completed
	*/
	virtual int start()=0;
	/*
	return == 0 for no more information
	> 0 get one information
	*/
	virtual int get_result(std::string& vstr)=0;
};

#endif /* __EVCOMBO_H_9C6BB9CD28732F9654EB0DB80140E41F__ */
