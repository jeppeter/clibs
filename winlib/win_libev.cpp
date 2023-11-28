

#include <win_libev.h>
#include <win_output_debug.h>
#include <win_err.h>

#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4530)
#pragma warning(disable:4514)
#pragma warning(disable:4577)

#include <vector>

#pragma warning(pop)


#if _MSC_VER >= 1910
#pragma warning(push)
#pragma warning(disable:5045)
#endif

typedef struct __libev_evt_call {
    uint64_t m_guid;
    HANDLE m_handle;
    libev_evt_callback_t m_func;
    void* m_args;
} libev_evt_call_t,*plibev_evt_call_t;

typedef struct __libev_evt_timer {
    uint64_t m_guid;
    libev_evt_timer_t m_func;
    void* m_args;
    uint64_t m_startticks;
    uint32_t m_interval;
    int m_conti;
} libev_evt_timer_t,*plibev_evt_timer_t;

typedef struct __libev_win_ev{
    int m_exited;
    uint32_t m_waitsize;
    uint32_t m_waitnum;
    uint64_t m_guid;
    HANDLE *m_pwaits;
    HANDLE m_htmevt[1];
    std::vector<plibev_evt_timer_t> *m_ptimers;
    std::vector<plibev_evt_call_t> *m_pcallers;
} libev_win_ev_t,*plibev_win_ev_t;


void __free_winev_timer(plibev_evt_timer_t* pptimer)
{
    if (pptimer && *pptimer) {
        plibev_evt_timer_t ptimer = *pptimer;
        ptimer->m_guid = 0;
        ptimer->m_func = NULL;
        ptimer->m_args = NULL;
        ptimer->m_startticks = 0;
        ptimer->m_interval = 0;
        ptimer->m_conti = 0;
        free(ptimer);
        *pptimer = NULL;
    }
    return;
}

void __free_winev_call(plibev_evt_call_t* ppcaller)
{
    if (ppcaller && *ppcaller) {
        plibev_evt_call_t pcaller = *ppcaller;
        pcaller->m_guid = 0;
        pcaller->m_handle = NULL;
        pcaller->m_func = NULL;
        pcaller->m_args = NULL;
        free(pcaller);
        *ppcaller = NULL;
    }
    return ;
}

void __free_winev(plibev_win_ev_t* ppev)
{
    if (ppev && *ppev) {
        plibev_win_ev_t pev = *ppev;
        if (pev->m_ptimers != NULL) {
            while(pev->m_ptimers->size() > 0) {
                plibev_evt_timer_t ptimer = pev->m_ptimers->at(0);
                pev->m_ptimers->erase(pev->m_ptimers->begin());
                __free_winev_timer(&ptimer);
                ptimer = NULL;
            }
            delete pev->m_ptimers;
            pev->m_ptimers = NULL;
        }

        if (pev->m_pcallers != NULL) {
            while(pev->m_pcallers->size() > 0) {
                plibev_evt_call_t pcall = pev->m_pcallers->at(0);
                pev->m_pcallers->erase(pev->m_pcallers->begin());
                __free_winev_call(&pcall);                
            }
            delete pev->m_pcallers;
            pev->m_pcallers = NULL;
        }

        if (pev->m_pwaits) {
            free(pev->m_pwaits);
        }
        pev->m_pwaits = NULL;
        pev->m_waitsize = 0;

        if (pev->m_htmevt[0] != NULL) {
            CloseHandle(pev->m_htmevt[0]);
        }
        pev->m_htmevt[0] = NULL;
        pev->m_exited = 0;
        pev->m_guid = 0;
        free(pev);
        *ppev = NULL;
    }
    return ;
}

plibev_win_ev_t __alloc_winev()
{
    plibev_win_ev_t pev = NULL;
    int ret;

    pev = (plibev_win_ev_t)malloc(sizeof(*pev));
    if (pev == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pev,0,sizeof(*pev));
    pev->m_exited = 0;
    pev->m_waitsize = 0;
    pev->m_waitnum = 0;
    pev->m_pwaits = NULL;
    pev->m_htmevt[0] = CreateEvent(NULL,TRUE,TRUE,NULL);
    if (pev->m_htmevt[0] == NULL) {
        GETERRNO(ret);
        ERROR_INFO("cannot create htmevt");
        goto fail;
    }

    pev->m_ptimers = new std::vector<plibev_evt_timer_t>();
    pev->m_pcallers = new std::vector<plibev_evt_call_t>();
    return pev;
fail:
    __free_winev(&pev);
    SETERRNO(ret);
    return NULL;
}


void libev_free_winev(void** ppevmain)
{
    plibev_win_ev_t* ppev = (plibev_win_ev_t) ppevmain;
    __free_winev(ppev);
    return ;
}

void* libev_init_winev()
{
    return (void*) __alloc_winev();
}


plibev_evt_timer_t __alloc_winev_timer(libev_evt_timer_t pfunc,void* args,uint32_t interval, int conti)
{
    plibev_evt_timer_t ptimer = NULL;
    int ret;

    ptimer = (plibev_evt_timer_t) malloc(sizeof(*ptimer));
    if (ptimer == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    memset(ptimer, 0, sizeof(*ptimer));
    ptimer->m_guid = 0;
    ptimer->m_func = pfunc;
    ptimer->m_args = args;
    ptimer->m_interval = interval;
    ptimer->m_conti = conti;
    ptimer->m_startticks = get_current_ticks();

    return ptimer;
fail:
    __free_winev_timer(&ptimer);
    SETERRNO(ret);
    return NULL;
}

int libev_insert_timer(void* pevmain,unit64_t* pguid,libev_evt_timer_t pfunc,void* args,uint32_t timemills,int conti)
{
    plibev_evt_timer_t ptimer = NULL;
    int ret;
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;

    if (pguid == NULL || pfunc == NULL || timemills == 0 || pev == NULL)  {
        ret = -ERROR_INVALID_PARAMETERS;
        SETERRNO(ret);
        return ret;
    }

    ptimer = __alloc_winev_timer(pfunc,args,timemills,conti);
    if (ptimer == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    pev->m_guid += 1;
    ptimer->m_guid = pev->m_guid;
    pev->m_ptimers->push(ptimer);
    ptimer = NULL;

    *pguid = pev->m_guid;
    return 1;
fail:
    __free_winev_timer(&ptimer);
    SETERRNO(ret);
    return ret;
}

plibev_evt_call_t __alloc_winev_call(HANDLE hd,libev_evt_callback_t pfunc, void* args)
{
    plibev_evt_call_t pcall = NULL;

    pcall =(plibev_evt_call_t) malloc(sizeof(*pcall));
    if (pcall == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pcall, 0 ,sizeof(*pcall));
    pcall->m_guid = 0;
    pcall->m_handle = hd;
    pcall->m_func = pfunc;
    pcall->m_args = args;

    return pcall;
fail:
    __free_winev_call(&pcall);
    SETERRNO(ret);
    return NULL;
}

int libev_insert_handle(void* pevmain,HANDLE hd,libev_evt_callback_t pfunc,void* args)
{
    int ret;
    plibev_evt_call_t pcall = NULL;
    int retlen=0;
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    HANDLE* ptmp= NULL;
    int nsize=0;

    if (pev == NULL || hd == NULL || pfunc == NULL) {
        ret = -ERROR_INVALID_PARAMETERS;
        SETERRNO(ret);
        return ret;
    }

    pcall = __alloc_winev_call(hd,pfunc,args);
    if (pcall == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    pev->m_guid += 1;
    pcall->m_guid = pev->m_guid;
    

    if (pev->m_waitnum >= pev->m_waitsize) {
        if (pev->m_waitnum == 0) {
            nsize = 4;
        } else {
            nsize = pev->m_waitsize << 1;
        }
        ptmp = (HANDLE*) malloc(sizeof(*ptmp) * nsize);
        if (ptmp == NULL) {
            GETERRNO(ret);
            goto fail;
        }

        memset(ptmp, 0 ,sizeof(*ptmp) * nsize);
        if (pev->m_waitnum > 0) {
            memcpy(ptmp,pev->m_pwaits,sizeof(*ptmp) * pev->m_waitnum);
        }
        if (pev->m_pwaits != NULL) {
            free(pev->m_pwaits);
        }
        pev->m_pwaits = ptmp;
        ptmp = NULL;
    }

    pev->m_pwaits[pev->m_waitnum] = hd;
    pev->m_waitnum += 1;

    pev->m_pcallers.push(pcall);
    return pev->m_waitsize;
fail:
    if (ptmp) {
        free(ptmp);
    }
    ptmp = NULL;
    __free_winev_call(&pcall);
    SETERRNO(ret);
    return ret;
}

int __find_evt_call(plibev_win_ev_t pev,HANDLE hd)
{
    unsigned int i;
    for(i=0;i<pev->m_pcallers->size();i++) {
        plibev_evt_call_t pcall = pev->m_pcallers->at(i);
        if (pcall->m_handle == hd) {
            return i;
        }
    }
    return -1;
}

int __find_evt_call_by_guid(plibev_win_ev_t pev, uint64_t guid)
{
    unsigned int i;
    for(i=0;i<pev->m_pcallers->size();i++) {
        plibev_evt_call_t pcall = pev->m_pcallers->at(i);
        if (pcall->m_guid == guid) {
            return i;
        }
    }
    return -1;    
}

int __find_evt_timer(plibev_win_ev_t pev, uint64_t guid)
{
    unsigned int i;
    for(i=0;i<pev->m_ptimers->size();i++) {
        plibev_evt_timer_t ptimer = pev->m_ptimers->at(i);
        if (ptimer->m_guid == guid) {
            return i;
        }
    }
    return -1;    
}

int libev_remove_timer(void* pevmain,uint64_t guid)
{
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    int fidx=-1;
    int ret;

    if (pev == NULL || guid == 0) {
        ret = -ERROR_INVALID_PARAMETERS;
        SETERRNO(ret);
        return ret;
    }

    fidx = __find_evt_timer(pev,guid);
    if (fidx < 0) {
        return 0;
    }

    plibev_evt_timer_t ptimer = pev->m_ptimers->at(fidx);
    pev->m_ptimers->erase(pev->m_ptimers->begin() + fidx);
    __free_winev_timer(&ptimer);
    return 1;
}

int libev_remove_handle(void* pevmain,HANDLE hd)
{
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    int fidx=-1;
    int ret;
    HANDLE* ptmp =NULL;

    if (pev == NULL || hd == NULL) {
        ret = -ERROR_INVALID_PARAMETERS;
        SETERRNO(ret);
        return ret;
    }

    fidx = __find_evt_call(pev,hd);
    if (fidx < 0) {
        return 0;
    }

    plibev_evt_call_t pcall = pev->m_pcallers->at(fidx);
    pev->m_pcallers->erase(pev->m_pcallers->begin() + fidx);
    __free_winev_call(&pcall);

    if (pev->m_pwaits != NULL) {
        for(i=fidx;i<(pev->m_waitnum-1);i++) {
            pev->m_pwaits[i] = pev->m_pwaits[i+1];
        }
        pev->m_pwaits[pev->m_waitnum] = NULL;
        pev->m_waitnum -= 1;
        /*so big we shrink*/
        if (pev->m_waitsize > (pev->m_waitnum << 2)) {
            if (pev->m_waitnum != 0) {
                ptmp = (HANDLE*)malloc(sizeof(*ptmp) * pev->m_waitnum * 4);
                if (ptmp != NULL) {
                    memset(ptmp,0,sizeof(*ptmp) * pev->m_waitnum * 4);
                    if (pev->m_waitnum > 0) {
                        memcpy(ptmp,pev->m_pwaits,sizeof(*ptmp) * pev->m_waitnum);
                    }
                    if (pev->m_pwaits) {
                        free(pev->m_pwaits);
                    }
                    pev->m_pwaits = ptmp;
                    ptmp = NULL;
                    pev->m_waitsize = pev->m_waitnum * 4;
                }
            }
        }
    }

    return 1;
}

void libev_break_winev_loop(void* pevmain)
{
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    if (pev == NULL) {
        return;
    }
    pev->m_exited = 1;
    return ;
}

int __get_max_mills(plibev_win_ev_t pev, int maxmills)
{
    int retmills = maxmills;
    unsigned int i;
    int ret;
    uint64_t cticks = get_current_ticks();
    for(i=0;i<pev->m_ptimers->size();i++) {
        plibev_evt_timer_t ptimer = pev->m_ptimers->at(i);
        ret = need_wait_times(ptimer->m_startticks,cticks,ptimer->m_interval);
        if (ret < 0) {
            return 1;
        }
        if (ret < retmills) {
            retmills = ret;
        }
    }
    return retmills;
}


int libev_winev_loop(void* pevmain)
{
    int ret;
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    int maxmills = 30000;
    DWORD waitnum;

    if (pev == NULL) {
        ret = -ERROR_INVALID_PARAMETERS;
        SETERRNO(ret);
        return ret;
    }

    while(pev->m_exited == 0) {
        maxmills = __get_max_mills(pev,30000);
        if (pev->m_waitnum > 0) {
            waitnum = pev->m_waitnum;
            dret = WaitForMultipleObjectsEx(pev->m_waitnum,pev->m_pwaits,FALSE,maxmills,TRUE);
        } else {
            waitnum = 1;
            dret = WaitForMultipleObjectsEx(1,pev->m_htmevt,FALSE,maxmills,TRUE);
        }
        if (dret >= WAIT_OBJECT_0 && dret < (WAIT_OBJECT_0 + waitnum - 1)) {
            if (pev->m_waitnum > 0) {
                hd = pev->m_pwaits[(dret - WAIT_OBJECT_0)];
            }
        } else if (dret == WAIT_TIMEOUT) {

        } else {
            GETERRNO(ret);
            ERROR_INFO("wait error [%ld] %d", dret,ret);
            goto fail;
        }
    }


    return 0;
fail:
    SETERRNO(ret);
    return ret;
}


/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/
/**************************************************************/

/*we should at least 10 second timer*/
#define  MINIMUM_TIMER_VALUE   ((uint32_t)10000)
#define INFINITE_TIME64        ((uint64_t)0xffffffffffffffffULL)


uint32_t __libev_get_mininum_time(plibev_win_ev_t pevmain,uint64_t curtick)
{
    uint32_t retval = INFINIT_TIME;
    unsigned int i;

    if (pevmain->m_ptimer_mills_vec) {
        for  (i = 0; i < pevmain->m_ptimer_mills_vec->size() ; i ++) {
            if ((pevmain->m_ptimer_mills_vec->at(i) <= curtick)) {
                retval = 1;
                break;
            }

            if ((pevmain->m_ptimer_mills_vec->at(i) - curtick) < retval) {
                retval =(uint32_t) (pevmain->m_ptimer_mills_vec->at(i) - curtick);
            }
        }
    }

    if (retval > MINIMUM_TIMER_VALUE) {
        retval = MINIMUM_TIMER_VALUE;
    }

    return retval;
}

uint32_t __libev_get_minmum_event_time(plibev_win_ev_t pevmain,uint64_t curtick)
{
    uint32_t retval = INFINIT_TIME;
    uint32_t curval;
    unsigned int i;

    if (pevmain->m_pmills_vec) {
        for (i=0; i<pevmain->m_pmills_vec->size(); i++) {
            if (curtick >= pevmain->m_pmills_vec->at(i)) {
                retval = 1;
                break;
            }

            curval = (uint32_t) (pevmain->m_pmills_vec->at(i) - curtick);
            if (curval < retval) {
                retval = curval;
            }
        }
    }

    return retval;
}

int __libev_format_handles(plibev_win_ev_t pevmain,HANDLE pHandles[],uint32_t hdsize,uint64_t curtick)
{
    uint32_t numevt=0;
    uint32_t i;
    curtick = curtick;

    if (pevmain->m_phandle_vec) {
        numevt =(uint32_t) pevmain->m_phandle_vec->size();
    }
    ASSERT_IF(pHandles);
    ASSERT_IF(hdsize >= (1 + numevt));


    memset(pHandles,0,sizeof(pHandles[0]) * hdsize);
    pHandles[0] = pevmain->m_htmevt;

    for (i=0; i<numevt; i++) {
        pHandles[1+i] = pevmain->m_phandle_vec->at(i);
    }

    return (int)(1+numevt);
}

int __libev_realloc_handles(plibev_win_ev_t pevmain)
{
    uint32_t expands=1;

    if (pevmain->m_phandle_vec) {
        expands += (uint32_t)pevmain->m_phandle_vec->size();
    }

    if (expands > pevmain->m_waitsize) {
        if (pevmain->m_pwaits) {
            free(pevmain->m_pwaits);
        }
        pevmain->m_pwaits = NULL;
        pevmain->m_waitsize = expands;
        pevmain->m_pwaits = (HANDLE*)malloc(sizeof(pevmain->m_pwaits[0])*expands);
        if (pevmain->m_pwaits ==NULL) {
            return -1;
        }

        return 1;
    }

    return 0;
}


int __libev_find_event(plibev_win_ev_t pevmain,HANDLE hevent)
{
    int ret =-1;
    unsigned int i;

    if (pevmain->m_phandle_vec) {
        for (i=0; i<pevmain->m_phandle_vec->size(); i++) {
            if (hevent == pevmain->m_phandle_vec->at(i)) {
                ret = (int)i;
                break;
            }
        }
    }
    return ret;
}


int __libev_handle_event(plibev_win_ev_t pevmain,uint64_t curtick,int idx)
{
    HANDLE hevt;
    libev_evt_callback_t callback;
    void* args;
    int ret =0;
    int findidx=-1;

    curtick = curtick;

    /*backup the vector ,for it will call callback functions ,and it may be modify the vector*/
    ASSERT_IF(pevmain->m_phandle_vec && pevmain->m_phandle_vec->size() > 0);
    ASSERT_IF(pevmain->m_phandle_vec->size() == pevmain->m_pfunc_vec->size());
    ASSERT_IF(pevmain->m_pargs_vec->size() == pevmain->m_pargs_vec->size());

    findidx = __libev_find_event(pevmain,pevmain->m_pwaits[idx]);
    if (findidx >= 0) {
        hevt = pevmain->m_phandle_vec->at((const uint64_t)findidx);
        callback = pevmain->m_pfunc_vec->at((const uint64_t)findidx);
        args = pevmain->m_pargs_vec->at((const uint64_t)findidx);
        //DEBUG_INFO("call event 0x%x",hevt);
        callback(hevt,normal_event,pevmain,args);
        ret = 1;
    }

    return ret;
}



int __libev_handle_event_timeout(plibev_win_ev_t pevmain,uint64_t curtick)
{
    std::vector<libev_evt_callback_t> callbacks;
    std::vector<void*> args;
    std::vector<uint64_t> endticks;
    std::vector<HANDLE> hevts;
    unsigned int i;
    int ret=0;
    int find;

    /*to store the vector ,as it will call when in call back ,remove the vectors*/
    if (pevmain->m_phandle_vec) {
        for (i = 0; i<pevmain->m_phandle_vec->size(); i++) {
            hevts.push_back(pevmain->m_phandle_vec->at(i));
            callbacks.push_back(pevmain->m_pfunc_vec->at(i));
            args.push_back(pevmain->m_pargs_vec->at(i));
            endticks.push_back(pevmain->m_pmills_vec->at(i));
        }
    }

    for (i=0; i<endticks.size(); i++) {
        if (endticks[i] != INFINITE_TIME64 && curtick >= endticks[i]) {
            find = __libev_find_event(pevmain, hevts[i]);
            if (find >= 0) {
                callbacks[i](hevts[i],timeout_event,pevmain,args[i]);
                ret ++;
            }
        }
    }

    return ret;
}


int __libev_find_timer_func(plibev_win_ev_t pevmain,libev_evt_callback_t func,void* args)
{
    int ret=-1;
    unsigned int i;

    if (pevmain->m_ptimer_func_vec) {
        for (i =0; i<pevmain->m_ptimer_func_vec->size(); i++) {
            if (pevmain->m_ptimer_func_vec->at(i) == func) {
                if (pevmain->m_ptimer_args_vec->at(i) == args) {
                    ret = (int)i;
                    break;
                }
            }
        }
    }

    return ret;
}


int __libev_handle_timer(plibev_win_ev_t pevmain,uint64_t curtick)
{
    std::vector<libev_evt_callback_t> callbacks;
    std::vector<void*> args;
    std::vector<uint64_t> endticks;
    unsigned int i;
    int ret=0;
    int find;

    /*to store the vector ,as it will call when in call back ,remove the vectors*/
    if (pevmain->m_ptimer_func_vec) {
        for (i =0; i<pevmain->m_ptimer_func_vec->size(); i++) {
            callbacks.push_back(pevmain->m_ptimer_func_vec->at(i));
            args.push_back(pevmain->m_ptimer_args_vec->at(i));
            endticks.push_back(pevmain->m_ptimer_mills_vec->at(i));
        }
    }

    for (i=0; i<endticks.size(); i++) {
        if (endticks[i] <= curtick) {
            find = __libev_find_timer_func(pevmain, callbacks[i],args[i]);
            if (find >= 0) {
                //DEBUG_INFO("callback[%d] 0x%p args 0x%p endticks 0x%I64x curtick 0x%I64x",
                //           i,callbacks[i],args[i],endticks[i],curtick);
                callbacks[i](NULL,timer_event,pevmain,args[i]);
                ret ++;
            }
        }
    }
    return ret;
}

int __libev_handle_event_abandon(plibev_win_ev_t pevmain,uint64_t curtick,int idx)
{
    HANDLE hevt;
    libev_evt_callback_t callback;
    void* args;
    int ret =0;

    curtick = curtick;
    /*backup the vector ,for it will call callback functions ,and it may be modify the vector*/
    ASSERT_IF(pevmain->m_phandle_vec && pevmain->m_phandle_vec->size() > 0);
    ASSERT_IF(pevmain->m_phandle_vec->size() == pevmain->m_pfunc_vec->size());
    ASSERT_IF(pevmain->m_pargs_vec->size() == pevmain->m_pargs_vec->size());

    if (pevmain->m_phandle_vec && (int)pevmain->m_phandle_vec->size() > idx) {
        hevt = pevmain->m_phandle_vec->at((const uint64_t)idx);
        callback = pevmain->m_pfunc_vec->at((const uint64_t)idx);
        args = pevmain->m_pargs_vec->at((const uint64_t)idx);
        callback(hevt,abandon_event,pevmain,args);
        ret = 1;
    }

    return ret;
}

int __libev_handle_event_failed(plibev_win_ev_t pevmain)
{
    std::vector<libev_evt_callback_t> callbacks;
    std::vector<void*> args;
    std::vector<uint64_t> endticks;
    std::vector<HANDLE> hevts;
    unsigned int i;
    int ret=0;
    int find;

    /*to store the vector ,as it will call when in call back ,remove the vectors*/
    if (pevmain->m_phandle_vec) {
        for (i = 0; i<pevmain->m_phandle_vec->size(); i++) {
            hevts.push_back(pevmain->m_phandle_vec->at(i));
            callbacks.push_back(pevmain->m_pfunc_vec->at(i));
            args.push_back(pevmain->m_pargs_vec->at(i));
            endticks.push_back(pevmain->m_pmills_vec->at(i));
        }
    }

    for (i=0; i<endticks.size(); i++) {
        find = __libev_find_event(pevmain, hevts[i]);
        if (find >= 0) {
            callbacks[i](hevts[i],failed_event,pevmain,args[i]);
            ret ++;
        }
    }

    return ret;
}

int __libev_recalc_timer(plibev_win_ev_t pevmain,uint64_t curtick)
{
    unsigned int i;
    uint64_t mills;
    uint32_t pertime;
    int ret=0;

    if (pevmain->m_ptimer_mills_vec) {
        for (i=0; i<pevmain->m_ptimer_mills_vec->size(); i++) {
            mills = pevmain->m_ptimer_mills_vec->at(i);
            if ( mills != INFINITE_TIME64 && mills <= curtick) {
                pertime = pevmain->m_ptimer_time_vec->at(i);
                mills += pertime;
                /*set the next ok times*/
                pevmain->m_ptimer_mills_vec->at(i) = mills;
                ret ++;
            }
        }
    }
    return ret;
}

uint64_t __libev_get_tick_count()
{
    return GetTickCount64();
}

void __libev_debug_wait_handle(plibev_win_ev_t pevmain,int waitnum)
{
    int i;
    for(i=0; i<waitnum; i++) {
        DEBUG_INFO("wait[%d] = 0x%x",i,pevmain->m_pwaits[i]);
    }
    for (i=0; i<(int)pevmain->m_phandle_vec->size(); i++) {
        DEBUG_INFO("handle[%d]=0x%x",i,pevmain->m_phandle_vec->at((const uint64_t)i));
    }
    return ;
}

int libev_winev_loop(void* pevmain1)
{
    plibev_win_ev_t pevmain = (plibev_win_ev_t) pevmain1;
    uint32_t timemillsval,evtmillsval,realmills,waitnum;
    uint64_t curtick;
    DWORD dret;
    int ret;
    while(pevmain->m_exited == 0) {
        curtick = __libev_get_tick_count();
        timemillsval = __libev_get_mininum_time(pevmain, curtick);
        evtmillsval = __libev_get_minmum_event_time(pevmain,curtick);
        ret = __libev_realloc_handles(pevmain);
        if (ret < 0) {
            goto fail;
        }
        realmills = timemillsval ;
        if (evtmillsval < timemillsval) {
            realmills = evtmillsval;
        }

        waitnum = (uint32_t)__libev_format_handles(pevmain,pevmain->m_pwaits,pevmain->m_waitsize,curtick);

        dret = WaitForMultipleObjectsEx(waitnum,pevmain->m_pwaits,FALSE,realmills,TRUE);
        curtick = __libev_get_tick_count();
        //DEBUG_INFO("wait ret %d",dret);
        //__debug_wait_handle(pevmain,waitnum);
        if ( dret >= (WAIT_OBJECT_0 +1)&& dret <= (WAIT_OBJECT_0 + waitnum - 1)) {
            ret = __libev_handle_event(pevmain, curtick, (int)(dret-WAIT_OBJECT_0));
        } else if (dret == WAIT_OBJECT_0) {
            ret = __libev_handle_timer(pevmain,curtick);
            ResetEvent(pevmain->m_htmevt);
        } else if (dret == WAIT_TIMEOUT) {
            ret = __libev_handle_event_timeout(pevmain,curtick);
            if (ret < 0) {
                goto fail;
            }
            ret = __libev_handle_timer(pevmain,curtick);
            if (ret < 0) {
                goto fail;
            }
        } else if (dret >= (WAIT_ABANDONED_0 + 1) && dret <= (WAIT_ABANDONED_0 + waitnum -1)) {
            ret = __libev_handle_event_abandon(pevmain,curtick,(int)(dret - WAIT_ABANDONED_0 - 1));
        } else if (dret == WAIT_ABANDONED_0) {
            /*that is critical ,so we goto fail*/
            ret = -1;
            goto fail;
        } else if (dret == WAIT_FAILED) {
            __libev_handle_event_failed(pevmain);
            ret = -1;
            goto fail;
        }


        if (ret < 0) {
            goto fail;
        }

        ret = __libev_recalc_timer(pevmain,curtick);
        if (ret < 0) {
            goto fail;
        }
    }

    return 0;

fail:
    return ret;
}


#define FREE_VEC(pvec)  \
do\
{\
	if ((pvec)){\
		while(pvec->size()>0){\
			pvec->pop_back();\
		}\
		delete pvec;\
	}\
	pvec = NULL;\
}while(0)


void libev_free_winev(void** ppevmain1)
{
    plibev_win_ev_t pevmain;
    if (ppevmain1 == NULL) {
        return;
    }
    pevmain = (plibev_win_ev_t)*ppevmain1;
    if (pevmain == NULL) {
        return ;
    }
    pevmain->m_exited = 0;
    if (pevmain->m_pwaits) {
        free(pevmain->m_pwaits);
    }
    pevmain->m_pwaits = NULL;
    pevmain->m_waitsize = 0;

    if (pevmain->m_htmevt) {
        CloseHandle(pevmain->m_htmevt);
    }
    pevmain->m_htmevt = NULL;



    FREE_VEC(pevmain->m_phandle_vec);
    FREE_VEC(pevmain->m_pfunc_vec);
    FREE_VEC(pevmain->m_pargs_vec);
    FREE_VEC(pevmain->m_pmills_vec);

    FREE_VEC(pevmain->m_ptimer_func_vec);
    FREE_VEC(pevmain->m_ptimer_args_vec);
    FREE_VEC(pevmain->m_ptimer_mills_vec);
    FREE_VEC(pevmain->m_ptimer_time_vec);

    free(pevmain);
    *ppevmain1 = NULL;
    return ;
}


void* libev_init_winev()
{
    plibev_win_ev_t pevmain=NULL;

    pevmain = (plibev_win_ev_t)malloc(sizeof(*pevmain));
    if (pevmain == NULL) {
        goto fail;
    }

    memset(pevmain,0,sizeof(*pevmain));
    pevmain->m_exited = 0;
    pevmain->m_pwaits = NULL;
    pevmain->m_waitsize = 0;

    pevmain->m_htmevt = CreateEvent(NULL,TRUE,TRUE,NULL);
    if (pevmain->m_htmevt == NULL) {
        goto fail;
    }

    pevmain->m_phandle_vec = new std::vector<HANDLE>();
    pevmain->m_pfunc_vec = new std::vector<libev_evt_callback_t>();
    pevmain->m_pargs_vec = new std::vector<void*>();
    pevmain->m_pmills_vec = new std::vector<uint64_t>();

    pevmain->m_ptimer_func_vec = new std::vector<libev_evt_callback_t>();
    pevmain->m_ptimer_args_vec = new std::vector<void*>();
    pevmain->m_ptimer_mills_vec = new std::vector<uint64_t>();
    pevmain->m_ptimer_time_vec = new std::vector<uint32_t>();

    return pevmain;
fail:
    libev_free_winev((void**)&pevmain);
    return NULL;
}

#define PUSH_BACK(pvec,mem) \
do\
{\
	pvec->push_back(mem);\
}while(0)


int libev_insert_timer(void* pevmain1, libev_evt_callback_t pfunc, void * args, uint32_t timemills)
{
    plibev_win_ev_t pevmain = (plibev_win_ev_t) pevmain1;
    uint64_t curtick;
    int find=0;
    uint64_t nexttick;
    if (pevmain == NULL) {
        return -1;
    }

    if (timemills == INFINIT_TIME) {
        return -1;
    }

    find = __libev_find_timer_func(pevmain, pfunc,args);
    if (find >= 0) {
        return -1;
    }

    curtick = __libev_get_tick_count();
    nexttick = curtick + timemills;

    ASSERT_IF(pevmain->m_ptimer_func_vec && pevmain->m_ptimer_args_vec );
    ASSERT_IF(pevmain->m_ptimer_mills_vec && pevmain->m_ptimer_time_vec);

    PUSH_BACK(pevmain->m_ptimer_func_vec,pfunc);
    PUSH_BACK(pevmain->m_ptimer_args_vec,args);
    PUSH_BACK(pevmain->m_ptimer_mills_vec,nexttick);
    PUSH_BACK(pevmain->m_ptimer_time_vec,timemills);
    return 1;
}

#define ERASE_AT(pvec,idx) \
do\
{\
	pvec->erase(pvec->begin()+idx);\
}while(0)

int libev_remove_timer(void* pevmain1, libev_evt_callback_t pfunc, void * args)
{
    int ret =0;
    plibev_win_ev_t pevmain = (plibev_win_ev_t) pevmain1;

    if (pevmain ) {
        ASSERT_IF(pevmain->m_ptimer_func_vec && pevmain->m_ptimer_args_vec );
        ASSERT_IF(pevmain->m_ptimer_mills_vec && pevmain->m_ptimer_time_vec);
        ret = __libev_find_timer_func(pevmain, pfunc,args);
        if (ret < 0) {
            return 0;
        }

        ERASE_AT(pevmain->m_ptimer_func_vec,ret);
        ERASE_AT(pevmain->m_ptimer_args_vec,ret);
        ERASE_AT(pevmain->m_ptimer_mills_vec,ret);
        ERASE_AT(pevmain->m_ptimer_time_vec,ret);
        return 1;
    }

    return 0;
}


int libev_insert_handle(void* pevmain1, HANDLE hd, libev_evt_callback_t pfunc, void * args, uint32_t timemills)
{
    plibev_win_ev_t pevmain = (plibev_win_ev_t) pevmain1;
    int find=-1;
    uint64_t curtick;
    uint64_t nexttick;
    if (pevmain == NULL || hd == NULL) {
        return -1;
    }

    find = __libev_find_event(pevmain,hd);
    if (find >= 0) {
        return -1;
    }

    //DEBUG_INFO("insert 0x%x",hd);
    nexttick = INFINITE_TIME64;
    if (timemills != INFINIT_TIME) {
        curtick = __libev_get_tick_count();
        nexttick = curtick + timemills;
    }

    PUSH_BACK(pevmain->m_phandle_vec,hd);
    PUSH_BACK(pevmain->m_pfunc_vec,pfunc);
    PUSH_BACK(pevmain->m_pargs_vec,args);
    PUSH_BACK(pevmain->m_pmills_vec, nexttick);

    return 1;
}

int libev_remove_handle(void* pevmain1, HANDLE hd)
{
    int find=-1;
    plibev_win_ev_t pevmain = (plibev_win_ev_t) pevmain1;

    if (pevmain == NULL) {
        return -1;
    }

    find = __libev_find_event(pevmain,hd);
    if (find < 0) {
        return 0;
    }

    //DEBUG_INFO("remove 0x%x",hd);
    ERASE_AT(pevmain->m_phandle_vec, find);
    ERASE_AT(pevmain->m_pfunc_vec, find);
    ERASE_AT(pevmain->m_pargs_vec, find);
    ERASE_AT(pevmain->m_pmills_vec, find);

    return 1;
}

void libev_break_winev_loop(void* pevmain1)
{
    plibev_win_ev_t pevmain = (plibev_win_ev_t) pevmain1;
    if (pevmain) {
        pevmain->m_exited = 1;
    }
    return ;
}

#if _MSC_VER >= 1910
#pragma warning(pop)
#endif
