#include <ux_libev.h>
#include <ux_output_debug.h>
#include <ux_strop.h>
#include <ux_time_op.h>


#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define  UX_EV_MAGIC   0x99cde2123

typedef struct __ux_ev_callback{
	int m_fd;
	int m_event;
	evt_callback_func_t m_callback;
	void* m_arg;
} ux_ev_callback_t,*pux_ev_callback_t;

typedef struct __ux_timer_callback {
	uint64_t m_timerid;
	uint64_t m_starttime;
	int m_interval;
	int m_conti;
	evt_callback_func_t m_callback;
	void* m_arg;
} ux_timer_callback_t,*pux_timer_callback_t;

typedef struct __ux_ev {
	uint32_t m_magic;
	int m_exited;
	int m_deleted;
	int m_epollfd;
	int m_evtnum;
	int m_timernum;
	int m_dummyfd;
	uint64_t m_timeprodid;
	pux_ev_callback_t* m_evtcall;
	pux_timer_callback_t* m_timercall;
} ux_ev_t,*pux_ev_t;

void __free_uxev_callback(pux_ev_callback_t* ppcallback)
{
	if (ppcallback && *ppcallback) {
		pux_ev_callback_t pcallback = *ppcallback;
		pcallback->m_fd = -1;
		pcallback->m_event = 0;
		pcallback->m_callback = NULL;
		pcallback->m_arg = NULL;
		free(pcallback);
		*ppcallback = NULL;
	}
	return ;
}

pux_ev_callback_t __alloc_uxcallback(int fd,int event,evt_callback_func_t callback,void* arg)
{
	pux_ev_callback_t pcallback = NULL;
	int ret;

	pcallback = (pux_ev_callback_t)malloc(sizeof(*pcallback));
	if (pcallback == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pcallback,0,sizeof(*pcallback));
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

pux_timer_callback_t __alloc_uxtimer(int interval,int conti,evt_callback_func_t callback,void* arg)
{
	pux_timer_callback_t ptimer=NULL;
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

void __free_uxev_inner(pux_ev_t* ppev)
{
	if (ppev && *ppev) {
		pux_ev_t pev = *ppev;
		int i;
		if (pev->m_magic == UX_EV_MAGIC) {
			if (pev->m_epollfd >= 0) {
				close(pev->m_epollfd);
			}
			pev->m_epollfd = -1;

			if (pev->m_dummyfd >= 0) {
				close(pev->m_dummyfd);
			}
			pev->m_dummyfd = -1;

			if (pev->m_evtcall) {
				for(i=0;i<pev->m_evtnum;i++) {
					if (pev->m_evtcall[i]) {
						__free_uxev_callback(&(pev->m_evtcall[i]));
					}
				}
				free(pev->m_evtcall);
				pev->m_evtcall = NULL;
			}
			pev->m_evtnum = 0;

			if (pev->m_timercall) {
				for(i=0;i< pev->m_timernum;i++) {
					if (pev->m_timercall[i]) {
						__free_uxtimer_callback(&(pev->m_timercall[i]));
					}
				}
				free(pev->m_timercall);
				pev->m_timercall = NULL;
			}
			pev->m_timernum = 0;
			pev->m_magic = 0;
			pev->m_timeprodid = 1;
			pev->m_exited = 1;
			pev->m_deleted = 0;
			free(pev);
			*ppev = NULL;
		}
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
	int flags =0;
	struct epoll_event evt;

	pev = (pux_ev_t)malloc(sizeof(*pev));
	if (pev == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pev,0,sizeof(*pev));
	pev->m_magic = (uint32_t)UX_EV_MAGIC;
	pev->m_epollfd = -1;
	pev->m_dummyfd = -1;
	pev->m_exited = 0;
	pev->m_deleted = 0;
	pev->m_evtnum = 0;
	pev->m_evtcall = NULL;
	pev->m_timernum = 0;
	pev->m_timercall = NULL;
	/*we started from timer id*/
	pev->m_timeprodid = 1;

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
	pev->m_dummyfd = eventfd(0,EFD_NONBLOCK | EFD_CLOEXEC);
	if (pev->m_dummyfd < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not create dummyfd error[%d]",ret);
		goto fail;
	}

	memset(&evt,0,sizeof(evt));
	evt.events = EPOLLIN;
	evt.data.fd = pev->m_dummyfd;

	ret = epoll_ctl(pev->m_epollfd,EPOLL_CTL_ADD,pev->m_dummyfd,&evt);
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

int add_uxev_timer(void* pev1,int interval,int conti,uint64_t* ptimeid,evt_callback_func_t callback,void* arg)
{
	uint64_t ntimerid=0;
	int ntimernum = 0;
	pux_timer_callback_t* pptimers = NULL;
	int ret;
	pux_timer_callback_t ptimer= NULL;
	pux_ev_t pev = (pux_ev_t) pev1;

	if (pev->m_magic != UX_EV_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (callback == NULL || interval <= 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	ptimer = __alloc_uxtimer(interval,conti,callback,arg);
	if (ptimer == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ntimerid = pev->m_timeprodid ++;
	ptimer->m_timerid = ntimerid;

	ntimernum = pev->m_timernum + 1;

	pptimers = (pux_timer_callback_t*) malloc(sizeof(*pptimers) * ntimernum);
	if (pptimers == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pptimers,0, sizeof(*pptimers) * ntimernum);
	if (pev->m_timernum > 0) {
		memcpy(pptimers, pev->m_timercall,sizeof(*pptimers) * pev->m_timernum);
	}

	if (pev->m_timercall) {
		free(pev->m_timercall);
	}
	pev->m_timercall = pptimers;
	pptimers = NULL;
	pev->m_timercall[pev->m_timernum] = ptimer;
	ptimer = NULL;
	pev->m_timernum += 1;
	if (ptimeid) {
		*ptimeid = ntimerid;
	}

	return 1;
fail:
	if (pptimers) {
		free(pptimers);
	}
	pptimers = NULL;
	__free_uxtimer_callback(&ptimer);
	SETERRNO(ret);
	return ret;
}

int __find_timer_idx(pux_ev_t pev, uint64_t timeid)
{
	int fidx = -1;
	int i;

	for (i=0;i<pev->m_timernum;i++) {
		if (pev->m_timercall[i]->m_timerid == timeid) {
			fidx = i;
			break;
		}
	}
	return fidx;
}

int del_uxev_timer(void* pev1, uint64_t timerid)
{
	int ret = 0;
	int fidx=-1;
	int i;
	pux_ev_t pev = (pux_ev_t)pev1;

	if (pev->m_magic != UX_EV_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	fidx =  __find_timer_idx(pev,timerid);
	if (fidx < 0) {
		/*nothing to deleted*/
		return 0;
	}

	__free_uxtimer_callback(&pev->m_timercall[fidx]);
	for(i=0;i < (pev->m_timernum - 1);i++) {
		pev->m_timercall[i] = pev->m_timercall[i+1];
	}
	pev->m_timercall[pev->m_timernum - 1] = NULL;
	pev->m_timernum -= 1;
	if (pev->m_timernum == 0) {
		free(pev->m_timercall);
		pev->m_timercall = NULL;
	}
	/*to make sure deleted*/
	pev->m_deleted += 1;
	return 1;
}

int modi_uxev_timer_callback(void* pev1,uint64_t timeid, evt_callback_func_t callback)
{
	int fidx=-1;
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	if (pev->m_magic != UX_EV_MAGIC || callback == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	fidx = __find_timer_idx(pev,timeid);
	if (fidx < 0) {
		return 0;
	}

	pev->m_timercall[fidx]->m_callback = callback;
	return 1;
}


int modi_uxev_timer_interval(void* pev1, uint64_t timeid, int interval)
{
	int fidx = -1;
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	if (pev->m_magic != UX_EV_MAGIC || interval <= 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	fidx = __find_timer_idx(pev,timeid);
	if (fidx < 0) {
		return 0;
	}

	pev->m_timercall[fidx]->m_interval = interval;
	return 1;
}

int modi_uxev_timer_conti(void* pev1,uint64_t timeid,int conti)
{
	int fidx = -1;
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	if (pev->m_magic != UX_EV_MAGIC || conti < 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	fidx = __find_timer_idx(pev,timeid);
	if (fidx < 0) {
		return 0;
	}

	pev->m_timercall[fidx]->m_conti = conti;
	return 1;
}

int add_uxev_callback(void* pev1,int fd,int event, evt_callback_func_t func,void* args)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	pux_ev_callback_t pcallback = NULL;
	pux_ev_callback_t *pparr = NULL;
	int insertpoll= 0;
	int nsize = 0;
	int ret;
	int res;
	struct epoll_event evtinsert;
	if (pev->m_magic != UX_EV_MAGIC || fd < 0 || func == NULL ) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	pcallback = __alloc_uxcallback(fd,event,func,args);
	if (pcallback == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(&evtinsert,0,sizeof(evtinsert));
	evtinsert.events = 0;
	if ((event & READ_EVENT)!= 0) {
		evtinsert.events |= EPOLLIN;
	}
	if ((event & WRITE_EVENT) != 0) {
		evtinsert.events |= EPOLLOUT;
	}
	if ((event & ERROR_EVENT) != 0) {
		evtinsert.events |= EPOLLERR;
	}
	evtinsert.data.fd = fd;

	ret = epoll_ctl(pev->m_epollfd,EPOLL_CTL_ADD,fd,&evtinsert);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("insert [%d] error[%d]", fd,ret);
		goto fail;
	}
	insertpoll = 1;

	nsize = pev->m_evtnum + 1;
	pparr = (pux_ev_callback_t*) malloc(sizeof(*pparr) * nsize);
	if (pparr == NULL ){
		GETERRNO(ret);
		goto fail;
	}
	memset(pparr,0,sizeof(*pparr) * nsize);
	if (pev->m_evtnum > 0) {
		memcpy(pparr,pev->m_evtcall,sizeof(*pparr) * pev->m_evtnum);
	}

	pparr[pev->m_evtnum] = pcallback;
	pcallback = NULL;
	if (pev->m_evtcall) {
		free(pev->m_evtcall);
	}
	pev->m_evtcall = pparr;
	pparr = NULL;
	pev->m_evtnum = nsize;

	return 1;
fail:
	if (insertpoll) {
		res = epoll_ctl(pev->m_epollfd,EPOLL_CTL_DEL,fd,&evtinsert);
		if (res < 0) {
			ERROR_INFO("can not remove [%d]",fd);
		}
	}
	insertpoll = 0;
	if (pparr) {
		free(pparr);
	}
	pparr = NULL;
	__free_uxev_callback(&pcallback);
	SETERRNO(ret);
	return ret;
}

int __find_fd_callback(pux_ev_t pev,int fd)
{
	int fidx = -1;
	int i;
	for(i=0;i<pev->m_evtnum;i++) {
		if (pev->m_evtcall[i]->m_fd == fd) {
			fidx = i;
			break;
		}
	}
	return fidx;
}

int delete_uxev_callback(void* pev1,int fd,int event)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	struct epoll_event evtremove;
	int fidx= -1;
	int i;
	if (pev->m_magic != UX_EV_MAGIC || fd < 0 ) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	fidx = __find_fd_callback(pev,fd);
	if (fidx < 0) {
		return 0;
	}

	memset(&evtremove,0,sizeof(evtremove));
	evtremove.events = 0;
	if (pev->m_evtcall[fidx]->m_event & READ_EVENT) {
		evtremove.events |= EPOLLIN;
	}
	if ((pev->m_evtcall[fidx]->m_event & WRITE_EVENT) != 0) {
		evtremove.events |= EPOLLOUT;
	}
	if ((pev->m_evtcall[fidx]->m_event & ERROR_EVENT) != 0) {
		evtremove.events |= EPOLLERR;
	}
	ret = epoll_ctl(pev->m_epollfd,EPOLL_CTL_DEL,fd,&evtremove);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not remove [%d]",fd);
		SETERRNO(ret);
		return ret;
	}

	for(i=fidx;i<(pev->m_evtnum-1);i++) {
		pev->m_evtcall[i] = pev->m_evtcall[i+1];
	}
	pev->m_evtcall[pev->m_evtnum-1] = NULL;
	pev->m_evtnum -= 1;
	if (pev->m_evtnum == 0) {
		free(pev->m_evtcall);
		pev->m_evtcall = NULL;
	}
	/*to make sure we modified the functions*/
	pev->m_deleted += 1;
	return 1;
}

int break_uxev(void* pev1)
{
	pux_ev_t pev = (pux_ev_t)pev1;
	int ret;
	if (pev->m_magic != UX_EV_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}
	pev->m_exited = 1;
	return 0;
}

int __get_max_wait_mills(pux_ev_t pev,int maxmills)
{
	int retmills = maxmills;
	int i;
	int retv;
	for(i=0;i<pev->m_timernum;i++) {

		retv = time_left(pev->m_timercall[i]->m_starttime,pev->m_timercall[i]->m_interval);
		if (retv < 0) {
			/*we need one time*/
			retmills = 1;
			break;
		}

		if (retv < retmills) {
			retmills = retv;
		}
	}
	return retmills;
}

int loop_uxev(void* pev1)
{
	int ret;
	pux_ev_t pev = (pux_ev_t)pev1;
	struct epoll_event *pmostevt = NULL;
	int maxepolnum = 4;
	int waitmills = 0;
	int fidx=-1;
	int i;
	int notievt;
	int timeleft;


	if (pev->m_magic != UX_EV_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (pev->m_evtnum > 16) {
		maxepolnum = pev->m_evtnum >> 2;
	}

	pmostevt = (struct epoll_event* ) malloc(sizeof(*pmostevt) * maxepolnum);
	if (pmostevt == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	while(pev->m_exited == 0) {
		/*we handled all the deleted*/
		pev->m_deleted = 0;
		/*for most at 30 seconds*/
		waitmills = __get_max_wait_mills(pev,30000);
		SETERRNO(0);
		ret = epoll_wait(pev->m_epollfd,pmostevt,maxepolnum,waitmills);
		if (ret < 0) {
			GETERRNO_DIRECT(ret);
			if (ret == 0) {
				continue;
			}
			if (ret == -EINTR) {
				continue;
			}
			ERROR_INFO("wait epoll fd error[%d]", ret);
			goto fail;
		}

		if (ret > 0) {
			for (i=0;i<ret;i++) {
				if (pev->m_deleted > 0) {
					/*it deleted so we not get right now*/
					goto next_cycle;
				}
				fidx = __find_fd_callback(pev,pmostevt[i].data.fd);
				if (fidx >= 0) {
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
					ret = pev->m_evtcall[fidx]->m_callback(pev1,pev->m_evtcall[fidx]->m_fd,notievt,pev->m_evtcall[fidx]->m_arg);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
				}
			}
		}

		for(i=0;i<pev->m_timernum;i++) {
			if (pev->m_deleted) {
				/*has modified so we should give next cycle*/
				goto next_cycle;
			}
			timeleft = time_left(pev->m_timercall[i]->m_starttime,pev->m_timercall[i]->m_interval);
			if (timeleft < 0) {
				ret = pev->m_timercall[i]->m_callback(pev1,pev->m_timercall[i]->m_timerid,TIME_EVENT,pev->m_timercall[i]->m_arg);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				if (pev->m_timercall[i]->m_conti == 0) {
					del_uxev_timer(pev1,pev->m_timercall[i]->m_timerid);
				} else {
					/*we start next cycle*/
					pev->m_timercall[i]->m_starttime = get_cur_ticks();
				}
			}
		}
	next_cycle:
		pev1 = pev1;
	}


	if (pmostevt) {
		free(pmostevt);
	}
	pmostevt = NULL;

	return 0;
fail:
	if (pmostevt) {
		free(pmostevt);
	}
	pmostevt = NULL;
	SETERRNO(ret);
	return ret;
}