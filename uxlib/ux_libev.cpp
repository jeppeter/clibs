#include <ux_libev.h>
#include <ux_output_debug.h>
#include <ux_strop.h>
#include <ux_time_op.h>

#include <rb_tree.h>


#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define  UX_EV_MAGIC   0x99cde2123

typedef struct __ux_ev_callback {
	uint64_t m_evid;
	int m_fd;
	int m_event;
	evt_callback_func_t m_callback;
	void* m_arg;
} ux_ev_callback_t, *pux_ev_callback_t;

typedef struct __ux_timer_callback {
	uint64_t m_timerid;
	uint64_t m_starttime;
	int m_interval;
	int m_conti;
	evt_callback_func_t m_callback;
	void* m_arg;
} ux_timer_callback_t, *pux_timer_callback_t;

typedef struct __ux_ev {
	uint32_t m_magic;
	int m_exited;
	int m_epollfd;
	int m_dummyfd;
	uint64_t m_uuid;
	int m_timernum;
	int m_evtnum;	
	RB_TREE* m_evtcall;
	RB_TREE* m_evtuuid;
	RB_TREE* m_timerguid;
	RB_TREE* m_timercall;
	ux_timer_callback_t m_timerguidsearch;
	ux_ev_callback_t m_evtsearch;
} ux_ev_t, *pux_ev_t;

void __free_uxev_callback(pux_ev_callback_t* ppcallback)
{
	if (ppcallback && *ppcallback) {
		pux_ev_callback_t pcallback = *ppcallback;
		pcallback->m_evid = 0;
		pcallback->m_fd = -1;
		pcallback->m_event = 0;
		pcallback->m_callback = NULL;
		pcallback->m_arg = NULL;
		free(pcallback);
		*ppcallback = NULL;
	}
	return ;
}

pux_ev_callback_t __alloc_uxcallback(int fd, int event, evt_callback_func_t callback, void* arg)
{
	pux_ev_callback_t pcallback = NULL;
	int ret;

	pcallback = (pux_ev_callback_t)malloc(sizeof(*pcallback));
	if (pcallback == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pcallback, 0, sizeof(*pcallback));
	pcallback->m_evid = 0;
	pcallback->m_fd = fd;
	pcallback->m_event = event;
	pcallback->m_callback = callback;
	pcallback->m_arg = arg;

	return pcallback;
fail:
	__free_uxev_callback(&pcallback);
	SETERRNO(ret);
	return NULL;
}

void __free_uxtimer_callback(pux_timer_callback_t* ppcallback) {
	if (ppcallback && *ppcallback) {
		pux_timer_callback_t pcallback = *ppcallback;
		pcallback->m_timerid = 0;
		pcallback->m_starttime = 0;
		pcallback->m_interval = 0;
		pcallback->m_conti = 0;
		pcallback->m_callback = NULL;
		free(pcallback);
		*ppcallback = NULL;
	}
}

pux_timer_callback_t __alloc_uxtimer(int interval, int conti, evt_callback_func_t callback, void* arg)
{
	pux_timer_callback_t ptimer = NULL;
	int ret;

	ptimer = (pux_timer_callback_t) malloc(sizeof(*ptimer));
	if (ptimer == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(ptimer, 0, sizeof(*ptimer));
	ptimer->m_timerid = 0;
	ptimer->m_interval = interval;
	ptimer->m_conti = conti;
	ptimer->m_starttime = get_cur_ticks();
	ptimer->m_callback = callback;
	ptimer->m_arg = arg;

	return ptimer;
fail:
	__free_uxtimer_callback(&ptimer);
	SETERRNO(ret);
	return NULL;
}

int timer_guid_compare(void* a, void* b)
{
	pux_timer_callback_t pa = (pux_timer_callback_t) a;
	pux_timer_callback_t pb = (pux_timer_callback_t) b;

	if (pa->m_timerid > pb->m_timerid) {
		return 1;
	} else if (pa->m_timerid < pb->m_timerid) {
		return -1;
	}
	return 0;
}

int timer_tick_compare(void* a,void* b)
{
	pux_timer_callback_t pa = (pux_timer_callback_t) a;
	pux_timer_callback_t pb = (pux_timer_callback_t) b;

	uint64_t atick;
	uint64_t btick;
	addr_t aaddr;
	addr_t baddr;

	atick = pa->m_starttime + pa->m_interval;
	btick = pb->m_starttime + pb->m_interval;
	aaddr = (addr_t) pa;
	baddr = (addr_t) pb;

	if (atick < btick) {
		return -1;
	} else if (atick > btick) {
		return 1;
	}

	if (aaddr < baddr) {
		return -1;
	}
	if (aaddr > baddr) {
		return 1;
	}

	return 0;
}



int evt_fd_compare(void* a, void* b)
{
	pux_ev_callback_t pa = (pux_ev_callback_t) a;
	pux_ev_callback_t pb = (pux_ev_callback_t) b;

	if (pa->m_fd < pb->m_fd) {
		return -1;
	} else if (pa->m_fd > pb->m_fd) {
		return 1;
	}
	return 0;
}

int evt_uuid_compare(void* a,void* b)
{
	pux_ev_callback_t pa = (pux_ev_callback_t) a;
	pux_ev_callback_t pb = (pux_ev_callback_t) b;

	if (pa->m_evid < pb->m_evid) {
		return -1;
	} else if (pa->m_evid > pb->m_evid) {
		return 1;
	}
	return 0;
}

void timer_destroy_func(void* a)
{
	pux_timer_callback_t pa = (pux_timer_callback_t) a;
	__free_uxtimer_callback(&pa);
	return;
}

void evt_destroy_func(void* a)
{
	pux_ev_callback_t pa = (pux_ev_callback_t) a;
	__free_uxev_callback(&pa);
	return ;
}

void* malloc_func(size_t sz)
{
	return malloc(sz);
}

void free_func(void* ptr)
{
	free(ptr);
	return;
}


void __free_uxev_inner(pux_ev_t* ppev)
{
	if (ppev && *ppev) {
		pux_ev_t pev = *ppev;
		//ERROR_INFO("magic 0x%x UX_EV_MAGIC 0x%x", pev->m_magic, UX_EV_MAGIC);
		//ERROR_INFO(" ");
		if (pev->m_epollfd >= 0) {
			close(pev->m_epollfd);
		}
		pev->m_epollfd = -1;

		if (pev->m_dummyfd >= 0) {
			close(pev->m_dummyfd);
		}
		pev->m_dummyfd = -1;

		/*to destroy the uuid*/
		destroy_rb_tree(&(pev->m_evtuuid),1);
		/*destroy real evtcall*/
		destroy_rb_tree(&(pev->m_evtcall),0);

		/*do not free the timer*/
		destroy_rb_tree(&(pev->m_timercall),1);
		/*this will remove the timer*/
		destroy_rb_tree(&(pev->m_timerguid),0);

		pev->m_magic = 0;
		pev->m_uuid = 1;
		pev->m_exited = 1;
		free(pev);
		*ppev = NULL;
	}
}

void free_uxev(void** ppev1)
{
	pux_ev_t* ppev = (pux_ev_t*) ppev1;
	__free_uxev_inner(ppev);
	return;
}

void* init_uxev(int flag)
{
	pux_ev_t pev = NULL;
	int ret;
	int flags = 0;
	struct epoll_event evt;

	pev = (pux_ev_t)malloc(sizeof(*pev));
	if (pev == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pev, 0, sizeof(*pev));
	pev->m_magic = (uint32_t)UX_EV_MAGIC;
	pev->m_epollfd = -1;
	pev->m_dummyfd = -1;
	pev->m_exited = 0;
	pev->m_evtnum = 0;
	pev->m_evtcall = NULL;
	pev->m_evtuuid = NULL;
	pev->m_timernum = 0;
	pev->m_timercall = NULL;
	pev->m_timerguid = NULL;
	/*we started from timer id*/
	pev->m_uuid = 1;

	memset(&(pev->m_timerguidsearch),0,sizeof(pev->m_timerguidsearch));
	memset(&(pev->m_evtsearch),0,sizeof(pev->m_evtsearch));

	if ((flag & LIBEV_CLOEXEC) != 0) {
		flags |= EPOLL_CLOEXEC;
	}

	pev->m_epollfd = epoll_create1(flags);
	if (pev->m_epollfd < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not epoll_create1 error[%d]", ret);
		goto fail;
	}

	/*to add this for at least timer will go on*/
	pev->m_dummyfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (pev->m_dummyfd < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not create dummyfd error[%d]", ret);
		goto fail;
	}

	memset(&evt, 0, sizeof(evt));
	evt.events = EPOLLIN;
	evt.data.fd = pev->m_dummyfd;
	DEBUG_BUFFER_FMT(&evt,sizeof(evt),"add dummyfd EPOLLIN");

	ret = epoll_ctl(pev->m_epollfd, EPOLL_CTL_ADD, pev->m_dummyfd, &evt);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("not let dummyfd insert");
		goto fail;
	}


	return pev;
fail:
	__free_uxev_inner(&pev);
	SETERRNO(ret);
	return NULL;
}

int add_uxev_timer(void* pev1, int interval, int conti, uint64_t* ptimeid, evt_callback_func_t callback, void* arg)
{
	int ret;
	pux_timer_callback_t ptimer = NULL;
	pux_ev_t pev = (pux_ev_t) pev1;
	RB_NODE* node=NULL;


	if (callback == NULL || interval <= 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (pev->m_timerguid == NULL) {
		pev->m_timerguid = init_rb_tree(malloc_func,free_func,timer_guid_compare,timer_destroy_func,NULL);
		if (pev->m_timerguid == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (pev->m_timercall == NULL) {
		pev->m_timercall = init_rb_tree(malloc_func,free_func,timer_tick_compare,timer_destroy_func,NULL);
		if (pev->m_timercall == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	ptimer = __alloc_uxtimer(interval, conti, callback, arg);
	if (ptimer == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ptimer->m_timerid = pev->m_uuid;
	pev->m_uuid += 1;

	node = rb_insert(pev->m_timerguid, ptimer);
	if (node == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	node = rb_insert(pev->m_timercall,ptimer);
	if (node == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	ptimer = NULL;
	pev->m_timernum += 1;

	return 1;
fail:
	if (ptimer != NULL) {
		if (pev->m_timerguid != NULL) {
			node = rb_find(pev->m_timerguid,ptimer);
			if (node != NULL) {
				rb_delete(pev->m_timerguid,node,1);
			}			
		}

		if (pev->m_timercall != NULL) {
			node = rb_find(pev->m_timercall,ptimer);
			if (node != NULL) {
				rb_delete(pev->m_timercall,node,1);
			}
		}
	}
	__free_uxtimer_callback(&ptimer);
	SETERRNO(ret);
	return ret;
}

#if 0
int __find_timer_idx(pux_ev_t pev, uint64_t timeid)
{
	int fidx = -1;
	int i;

	for (i = 0; i < pev->m_timernum; i++) {
		if (pev->m_timercall[i]->m_timerid == timeid) {
			fidx = i;
			break;
		}
	}
	return fidx;
}
#endif

pux_timer_callback_t __find_timer_by_guid(pux_ev_t pev,uint64_t timerid)
{
	pux_timer_callback_t pfind=NULL;
	RB_NODE* node=NULL;
	int ret;

	if (pev->m_timerguid == NULL) {
		ret = -ENOENT;
		SETERRNO(ret);
		return NULL;
	}

	pev->m_timerguidsearch.m_timerid = timerid;

	node = rb_find(pev->m_timerguid, &(pev->m_timerguidsearch));
	if (node == NULL) {
		ret = -ENOKEY;
		goto fail;
	}

	pfind = (pux_timer_callback_t) rb_node_get(node);
	return pfind;
fail:
	SETERRNO(ret);
	return NULL;
}

int del_uxev_timer(void* pev1, uint64_t timerid)
{
	//int ret = 0;
	pux_ev_t pev = (pux_ev_t)pev1;
	RB_NODE* node=NULL,*node2=NULL;
	pux_timer_callback_t pfind = NULL;


	pfind = __find_timer_by_guid(pev,timerid);
	if (pfind == NULL) {
		return 0;
	}
	node2 = rb_find(pev->m_timercall,pfind);
	if (node2 == NULL) {
		ERROR_INFO("can not find %d in timercall",timerid);
	} else {		
		/*we not delete pfind*/
		rb_delete(pev->m_timercall, node2,1);
	}

	/*we not delete ptimer*/
	rb_delete(pev->m_timerguid, node,1);
	__free_uxtimer_callback(&pfind);
	pev->m_timernum -= 1;
	return 1;
}

int modi_uxev_timer_callback(void* pev1, uint64_t timeid, evt_callback_func_t callback)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	pux_timer_callback_t pfind = NULL;
	if ( callback == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	pfind = __find_timer_by_guid(pev,timeid);
	if (pfind == NULL) {
		return 0;
	}

	pfind->m_callback = callback;
	return 1;
}


int modi_uxev_timer_interval(void* pev1, uint64_t timeid, int interval)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	RB_NODE* node = NULL;
	pux_timer_callback_t pfind = NULL;
	if ( interval <= 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	pfind = __find_timer_by_guid(pev,timeid);
	if (pfind == NULL) {
		return 0;
	}

	/*modified the search index ,so we should reinsert it into the rb_tree*/
	node = rb_find(pev->m_timercall,pfind);
	if (node == NULL) {
		ret = -EINVAL;
		goto fail;
	}

	/*now we should delete RB_NODE not the void**/
	rb_delete(pev->m_timercall,node,1);
	node = NULL;


	pfind->m_interval = interval;
	pfind->m_starttime = get_cur_ticks();

	node = rb_insert(pev->m_timercall,pfind);
	if (node == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int modi_uxev_timer_conti(void* pev1, uint64_t timeid, int conti)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	pux_timer_callback_t pfind = NULL;
	if ( conti < 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	pfind = __find_timer_by_guid(pev,timeid);
	if (pfind == NULL) {
		return 0;
	}

	pfind->m_conti = conti;
	return 1;
}

int add_uxev_callback(void* pev1, int fd, int event, evt_callback_func_t func, void* args)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	pux_ev_callback_t pcallback = NULL;
	int insertpoll = 0;
	int ret;
	int res;
	struct epoll_event evtinsert;
	RB_NODE* node=NULL,*node2=NULL;

	if (fd < 0) {
		ret = -EINVAL;
		ERROR_INFO("fd %d", fd);
		SETERRNO(ret);
		return ret;
	}

	if (func == NULL) {
		ret = -EINVAL;
		ERROR_INFO("func %p", func);
		SETERRNO(ret);
		return ret;
	}

	if (pev->m_evtcall == NULL) {
		pev->m_evtcall = init_rb_tree(malloc_func,free_func,evt_fd_compare,evt_destroy_func,NULL);
		if (pev->m_evtcall == NULL) {
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;
		}
	}

	if (pev->m_evtuuid == NULL) {
		pev->m_evtuuid = init_rb_tree(malloc_func,free_func,evt_uuid_compare,evt_destroy_func,NULL);
		if (pev->m_evtuuid == NULL){
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;
		}
	}

	pcallback = __alloc_uxcallback(fd, event, func, args);
	if (pcallback == NULL) {
		GETERRNO(ret);
		ERROR_INFO(" ");
		goto fail;
	}

	pcallback->m_evid = pev->m_uuid;
	pev->m_uuid += 1;

	memset(&evtinsert, 0, sizeof(evtinsert));
	evtinsert.events = 0;
	if ((event & READ_EVENT) != 0) {
		DEBUG_INFO("add EPOLLIN");
		evtinsert.events |= EPOLLIN;
	}
	if ((event & WRITE_EVENT) != 0) {
		DEBUG_INFO("add EPOLLOUT");
		evtinsert.events |= EPOLLOUT;
	}
	if ((event & ERROR_EVENT) != 0) {
		DEBUG_INFO("add EPOLLERR");
		evtinsert.events |= EPOLLERR;
	}

	if ((event & ET_TRIGGER) != 0) {
		DEBUG_INFO("add EPOLLET");
		evtinsert.events |= EPOLLET;
	}
	//evtinsert.events |= EPOLLET;
	evtinsert.data.fd = fd;

	DEBUG_BUFFER_FMT(&evtinsert,sizeof(evtinsert),"add fd %d events 0x%x",fd,evtinsert.events);

	ret = epoll_ctl(pev->m_epollfd, EPOLL_CTL_ADD, fd, &evtinsert);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("insert [%d] error[%d]", fd, ret);
		goto fail;
	}
	insertpoll = 1;

	node = rb_insert(pev->m_evtcall, pcallback);
	if (node == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	node2 = rb_insert(pev->m_evtuuid,pcallback);
	if (node2 == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	pcallback = NULL;

	pev->m_evtnum += 1;


	return 1;
fail:
	if (node2 != NULL) {
		rb_delete(pev->m_evtuuid,node2,1);
		node2 = NULL;
	}


	if (node != NULL) {
		rb_delete(pev->m_evtcall,node,1);
		node = NULL;
	}


	if (insertpoll) {
		res = epoll_ctl(pev->m_epollfd, EPOLL_CTL_DEL, fd, &evtinsert);
		if (res < 0) {
			ERROR_INFO("can not remove [%d]", fd);
		}
	}
	insertpoll = 0;
	__free_uxev_callback(&pcallback);
	SETERRNO(ret);
	return ret;
}


pux_ev_callback_t __find_uuid_callback(pux_ev_t pev, uint64_t uuid)
{
	RB_NODE* node=NULL;
	int ret;
	if (pev->m_evtuuid == NULL) {
		ret = -ENOENT;
		SETERRNO(ret);
		return NULL;
	}

	pev->m_evtsearch.m_evid = uuid;
	node = rb_find(pev->m_evtuuid,&(pev->m_evtsearch));
	if (node == NULL) {
		ret = -ENOKEY;
		SETERRNO(ret);
		return NULL;
	}
	return (pux_ev_callback_t) rb_node_get(node);
}


pux_ev_callback_t __find_evtcall_by_fd(pux_ev_t pev,int fd)
{
	pux_ev_callback_t pfind = NULL;
	RB_NODE* node=NULL;
	int ret;

	if (pev->m_evtcall == NULL) {
		ret = -ENOENT;
		goto fail;
	}

	pev->m_evtsearch.m_fd = fd;

	node = rb_find(pev->m_evtcall,&(pev->m_evtsearch));
	if (node == NULL) {
		ret = -ENOKEY;
		goto fail;
	}

	pfind = (pux_ev_callback_t) rb_node_get(node);

	return pfind;
fail:
	SETERRNO(ret);
	return NULL;
}

int delete_uxev_callback(void* pev1, int fd)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	struct epoll_event evtremove;
	pux_ev_callback_t pfind = NULL;
	RB_NODE* node= NULL;
	if ( fd < 0 ) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	pfind = __find_evtcall_by_fd(pev,fd);
	if (pfind == NULL) {
		return 0;
	}


	memset(&evtremove, 0, sizeof(evtremove));
	evtremove.events = 0;
	if (pfind->m_event & READ_EVENT) {
		evtremove.events |= EPOLLIN;
	}
	if ((pfind->m_event & WRITE_EVENT) != 0) {
		evtremove.events |= EPOLLOUT;
	}
	if ((pfind->m_event & ERROR_EVENT) != 0) {
		evtremove.events |= EPOLLERR;
	}
	ret = epoll_ctl(pev->m_epollfd, EPOLL_CTL_DEL, fd, &evtremove);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not remove [%d]", fd);
		SETERRNO(ret);
		return ret;
	}
	node = rb_find(pev->m_evtcall,pfind);
	if (node != NULL) {
		rb_delete(pev->m_evtcall,node,1);
		node = NULL;
	}

	node = rb_find(pev->m_evtuuid,pfind);
	if (node != NULL) {
		rb_delete(pev->m_evtuuid,node,1);
		node = NULL;
	}

	/*not delete */
	__free_uxev_callback(&pfind);

	pev->m_evtnum -= 1;

	return 1;
}

int break_uxev(void* pev1)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	//int ret;

	pev->m_exited = 1;
	DEBUG_INFO("set m_exited");
	return 0;
}

int __get_max_wait_mills(pux_ev_t pev, int maxmills)
{
	int retmills = maxmills;
	int retv;
	RB_NODE* node;
	pux_timer_callback_t ptimer=NULL;


	node = rb_first(pev->m_timercall);
	if (node != NULL) {
		ptimer = (pux_timer_callback_t) rb_node_get(node);
		retv = time_left(ptimer->m_starttime, ptimer->m_interval);
		if (retv <= 0) {
			/*we need one time*/
			retmills = 1;
		} else if (retv < retmills) {
			retmills = retv;
		}
	}

	//DEBUG_INFO("retmills %d",retmills);
	return retmills;
}

int loop_uxev(void* pev1)
{
	int ret;
	pux_ev_t pev = (pux_ev_t)pev1;
	struct epoll_event *pmostevt = NULL;
	uint64_t* puuids = NULL;
	uint64_t* ptimerids = NULL;
	int timercnt = 0;
	int maxepollnum = 4;
	int waitmills = 0;
	int i;
	int notievt;
	int timeleft;
	int evnum;
	int timenum;
	int uuidcnt=0;
	pux_ev_callback_t pfind;
	pux_timer_callback_t ptimer=NULL;
	RB_NODE* node=NULL;



	if (pev->m_evtnum > 16) {
		maxepollnum = pev->m_evtnum >> 2;
	}

	pmostevt = (struct epoll_event* ) malloc(sizeof(*pmostevt) * maxepollnum);
	if (pmostevt == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	puuids = (uint64_t*)malloc(sizeof(*puuids) * maxepollnum);
	if (puuids == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	timercnt = pev->m_timernum;
	if (timercnt > 0) {
		ptimerids = (uint64_t*) malloc(sizeof(*ptimerids) * timercnt);
		if (ptimerids == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}



	while (pev->m_exited == 0) {
		DEBUG_INFO("pev->m_exited %d",pev->m_exited);
		/*for most at 30 seconds*/
		waitmills = __get_max_wait_mills(pev, 30000);
		//DEBUG_INFO("waitmills %d",waitmills);
		memset(pmostevt, 0, sizeof(*pmostevt) * maxepollnum);
		SETERRNO(0);
		ret = epoll_wait(pev->m_epollfd, pmostevt, maxepollnum, waitmills);
		if (ret < 0) {
			GETERRNO_DIRECT(ret);
			if (ret != 0 && ret != -EINTR && ret != -EAGAIN && ret != -EWOULDBLOCK) {
				ERROR_INFO("wait epoll fd error[%d]", ret);
				goto fail;
			}
		}
		DEBUG_INFO("ret %d", ret);
		evnum = 0;
		uuidcnt = 0;
		if (ret > 0) {
			evnum = ret;
			//DEBUG_BUFFER_FMT(pmostevt,sizeof(*pmostevt)* evnum,"most evt");
			for (i = 0; i < evnum; i++) {
				DEBUG_INFO("[%d].[%d] fd [%d]",evnum,i,pmostevt[i].data.fd);
				pfind = __find_evtcall_by_fd(pev, pmostevt[i].data.fd);
				if (pfind != NULL) {
					puuids[uuidcnt] = pfind->m_evid;
					uuidcnt ++;
				}
			}
		}

		timenum = 0;
		if (timercnt < pev->m_timernum) {
			timercnt = pev->m_timernum;
			if (ptimerids) {
				free(ptimerids);
			}
			ptimerids = NULL;
			ptimerids = (uint64_t*)malloc(sizeof(*ptimerids) * timercnt);
			if (ptimerids == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		} else if (timercnt > (pev->m_timernum >> 1))  {
			timercnt = pev->m_timernum;
			if (ptimerids) {
				free(ptimerids);
			}
			ptimerids = NULL;
			ptimerids = (uint64_t*)malloc(sizeof(*ptimerids) * timercnt);
			if (ptimerids == NULL) {
				GETERRNO(ret);
				goto fail;
			}
		}

		timenum = 0;
		node = rb_first(pev->m_timercall);
		while(timenum < timercnt) {
			if (node == NULL) {
				break;
			}
			ptimer = (pux_timer_callback_t) rb_node_get(node);
			timeleft = time_left(ptimer->m_starttime,ptimer->m_interval);
			if (timeleft > 0) {
				/*nothing to handle*/
				break;
			}
			ptimerids[timenum] = ptimer->m_timerid;
			timenum += 1;
			node = rb_node_next(node);
		}



		if (uuidcnt > 0) {
			for (i = 0; i < uuidcnt; i++) {
				pfind = __find_uuid_callback(pev,puuids[i]);
				if (pfind != NULL) {
					notievt = 0;
					if ((pmostevt[i].events & EPOLLIN) != 0 ) {
						notievt |= READ_EVENT;
					}
					if ((pmostevt[i].events & EPOLLOUT) != 0) {
						notievt |= WRITE_EVENT;
					}
					if ((pmostevt[i].events & EPOLLERR) != 0) {
						notievt |= ERROR_EVENT;
					}
					ret = pfind->m_callback(pev1, pfind->m_fd, notievt, pfind->m_arg);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
				}
			}
		}

		for (i = 0; i < timenum; i++) {
			ptimer = __find_timer_by_guid(pev, ptimerids[i]);
			if (ptimer != NULL) {
				/*this maybe change the timercall so we handle delete and set for next time*/
				DEBUG_INFO("call timercall %p",ptimer->m_callback);
				ret = ptimer->m_callback(pev1, ptimer->m_timerid, TIME_EVENT, ptimer->m_arg);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
			}
		}

		for (i = 0; i < timenum; i++) {
			ptimer = __find_timer_by_guid(pev, ptimerids[i]);
			if (ptimer != NULL) {
				if (ptimer->m_conti == 0) {
					del_uxev_timer(pev1, ptimer->m_timerid);
				} else {
					/*we start next cycle*/

					node = rb_find(pev->m_timercall,ptimer);
					if (node != NULL) {
						rb_delete(pev->m_timercall,node,1);
					}

					/*to modified the compare index ,so reinsert it*/
					ptimer->m_starttime = get_cur_ticks();
					node = rb_insert(pev->m_timercall,ptimer);
					if (node == NULL) {
						GETERRNO(ret);
						goto fail;
					}
				}
			}
		}
	}


	if (puuids) {
		free(puuids);
	}
	puuids = NULL;

	if (ptimerids) {
		free(ptimerids);
	}
	ptimerids = NULL;

	if (pmostevt) {
		free(pmostevt);
	}
	pmostevt = NULL;

	return 0;
fail:
	if (puuids) {
		free(puuids);
	}
	puuids = NULL;

	if (ptimerids) {
		free(ptimerids);
	}
	ptimerids = NULL;

	if (pmostevt) {
		free(pmostevt);
	}
	pmostevt = NULL;
	SETERRNO(ret);
	return ret;
}