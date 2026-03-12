#ifndef __EVCOMBO_H_9C6BB9CD28732F9654EB0DB80140E41F__
#define __EVCOMBO_H_9C6BB9CD28732F9654EB0DB80140E41F__


class IEvCombo {
	virtual void remove_ev_component(void* ptr,int _event=0);
	virtual int notify_result(void* ptr, int _event=0);
}

#endif /* __EVCOMBO_H_9C6BB9CD28732F9654EB0DB80140E41F__ */
