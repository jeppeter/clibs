#include <ux_libev.h>
#include <ux_err.h>
#include <ux_output_debug.h>
#include <ux_strop.h>
#include <unistd.h>
#include <stdlib.h>

#define  UX_EV_MAGIC   0x99cde2123

typedef struct __ux_ev_callback{
	int m_fd;
	int m_event;
	evt_callback_func_t m_callback;
} ux_ev_callback_t,*pux_ev_callback_t;

typedef struct __ux_ev {
	uint32_t m_magic;
	int m_epollfd;
	int m_evtnum;
	pux_ev_callback_t* m_evtcall;
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
			pev->m_magic = 0;
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