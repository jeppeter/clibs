#include <ux_libev.h>
#include <ux_output_debug.h>
#include <ux_strop.h>
#include <ux_time_op.h>


#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define  UX_EV_MAGIC   0x99cde2123

typedef struct __ux_ev_callback{
	int m_fd;
	int m_event;
	evt_callback_func_t m_callback;
} ux_ev_callback_t,*pux_ev_callback_t;

typedef struct __ux_timer_callback {
	uint64_t m_timerid;
	uint64_t m_starttime;
	int m_interval;
	int m_conti;
	evt_callback_func_t m_callback;
} ux_timer_callback_t,*pux_timer_callback_t;

typedef struct __ux_ev {
	uint32_t m_magic;
	int m_epollfd;
	int m_evtnum;
	int m_timernum;
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
		free(pcallback);
		*ppcallback = NULL;
	}
	return ;
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

pux_timer_callback_t __alloc_uxtimer(int interval,int conti,evt_callback_func_t callback)
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

	pev = (pux_ev_t)malloc(sizeof(*pev));
	if (pev == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pev,0,sizeof(*pev));
	pev->m_magic = (uint32_t)UX_EV_MAGIC;
	pev->m_epollfd = -1;
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

	return pev;
fail:
	__free_uxev_inner(&pev);
	SETERRNO(ret);
	return NULL;
}

int add_uxev_timer(void* pev1,int interval,int conti,uint64_t* ptimeid,evt_callback_func_t callback)
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

	ptimer = __alloc_uxtimer(interval,conti,callback);
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