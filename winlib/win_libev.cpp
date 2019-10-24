

#include <win_libev.h>
#include <win_output_debug.h>
#include <win_err.h>

#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4530)

#if _MSC_VER >= 1910
#pragma warning(disable:4514)
#pragma warning(disable:4577)
#endif

#include <vector>

#pragma warning(pop)


#if _MSC_VER >= 1910
#pragma warning(push)
#pragma warning(disable:5045)
#endif

typedef struct __libev_win_ev{
    int m_exited;
    uint32_t m_waitsize;
    HANDLE *m_pwaits;
    HANDLE m_htmevt;
    std::vector<HANDLE> *m_phandle_vec;
    std::vector<libev_evt_callback_t> *m_pfunc_vec;
    std::vector<void*> *m_pargs_vec;
    std::vector<uint64_t> *m_pmills_vec;
    std::vector<libev_evt_callback_t> *m_ptimer_func_vec;
    std::vector<void*> *m_ptimer_args_vec;
    std::vector<uint64_t> *m_ptimer_mills_vec;
    std::vector<uint32_t> *m_ptimer_time_vec;
} libev_win_ev_t,*plibev_win_ev_t;



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
