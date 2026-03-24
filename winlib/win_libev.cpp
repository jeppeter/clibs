

#include <win_libev.h>
#include <win_output_debug.h>
#include <win_time.h>
#include <win_err.h>

#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4530)
#pragma warning(disable:4514)
#pragma warning(disable:4577)

#include <vector>
#include <map>
#include <rb_tree.h>

#pragma warning(pop)

#pragma warning(push)

#if defined(_MSC_VER)
#if _MSC_VER >= 1910
#pragma warning(disable:5045)
#endif
#endif

typedef struct __libev_evt_call {
    uint64_t m_guid;
    HANDLE m_handle;
    libev_evt_callback_t m_func;
    void* m_args;
} libev_evt_call_t,*plibev_evt_call_t;

typedef struct __libev_evt_timer {
    uint64_t m_guid;
    libev_timer_callback_t m_func;
    void* m_args;
    uint64_t m_startticks;
    uint32_t m_interval;
    int m_conti;
} libev_evt_timer_t,*plibev_evt_timer_t;

typedef struct __libev_win_ev{
    int m_exited;
    uint32_t m_waitsize;
    uint32_t m_waitnum;
    int m_reserv1;
    uint64_t m_guid;
    HANDLE *m_pwaits;
    HANDLE m_htmevt[1];
    std::map<uint64_t,plibev_evt_timer_t> *m_ptimers;
    std::map<HANDLE,plibev_evt_call_t> *m_pcallers;
    RB_TREE* m_rbtimer;
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

        /*we do not free the timers*/
        destroy_rb_tree(&(pev->m_rbtimer),1);

        if (pev->m_ptimers != NULL) {
            while(pev->m_ptimers->size() > 0) {
                auto iter = pev->m_ptimers->begin();
                plibev_evt_timer_t ptimer = iter->second;
                pev->m_ptimers->erase(iter);
                __free_winev_timer(&ptimer);
                ptimer = NULL;
            }
            delete pev->m_ptimers;
            pev->m_ptimers = NULL;
        }

        if (pev->m_pcallers != NULL) {
            while(pev->m_pcallers->size() > 0) {
                auto iter = pev->m_pcallers->begin();
                plibev_evt_call_t pcall = iter->second;
                pev->m_pcallers->erase(iter);
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
        pev->m_waitnum = 0;

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

void* timer_malloc_func(size_t size)
{
    return malloc(size);
}

void timer_free_func(void* ptr)
{
    free(ptr);
    return;
}

int timer_compare_func(void* a, void* b)
{
    plibev_evt_timer_t pa= (plibev_evt_timer_t)a;
    plibev_evt_timer_t pb = (plibev_evt_timer_t)b;
    uint64_t aaddr,baddr;
    uint64_t atick=0 ,btick=0;

    atick = pa->m_startticks + pa->m_interval;
    btick = pb->m_startticks + pb->m_interval;

    if (atick < btick) {
        return -1;
    } else if (atick > btick) {
        return 1;
    } else {

        aaddr = (uint64_t)((addr_t)pa);
        baddr = (uint64_t)((addr_t)pb);
        if (aaddr < baddr) {
            return -1;
        } else if (aaddr > baddr) {
            return 1;
        }
    }
    return 0;    
}

void timer_destroy_func(void* a)
{
    /*we can not call this*/
    ASSERT_IF(a == NULL);
    return;
}

void timer_print_func(void* arg,FILE* fp,int tab)
{
    fp = fp;
    arg = arg;
    tab = tab;
    return;
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

    pev->m_rbtimer = init_rb_tree(timer_malloc_func,timer_free_func,timer_compare_func,timer_destroy_func,timer_print_func);
    if (pev->m_rbtimer == NULL) {
        GETERRNO(ret);
        ERROR_INFO("cannot create rbtimer");
        goto fail;
    }

    pev->m_ptimers = new std::map<uint64_t,plibev_evt_timer_t>();
    pev->m_pcallers = new std::map<HANDLE,plibev_evt_call_t>();
    return pev;
fail:
    __free_winev(&pev);
    SETERRNO(ret);
    return NULL;
}


void libev_free_winev(void** ppevmain)
{
    plibev_win_ev_t* ppev = (plibev_win_ev_t*) ppevmain;
    __free_winev(ppev);
    return ;
}

void* libev_init_winev()
{
    return (void*) __alloc_winev();
}


plibev_evt_timer_t __alloc_winev_timer(libev_timer_callback_t pfunc,void* args,uint32_t interval, int conti)
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

int libev_insert_timer(void* pevmain,uint64_t* pguid,libev_timer_callback_t pfunc,void* args,uint32_t timemills,int conti)
{
    plibev_evt_timer_t ptimer = NULL;
    int ret;
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    RB_NODE* node=NULL;

    if (pguid == NULL || pfunc == NULL || timemills == 0 || pev == NULL)  {
        ret = -ERROR_INVALID_PARAMETER;
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

    node = rb_insert(pev->m_rbtimer,ptimer);
    if (node == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    pev->m_ptimers->insert({pev->m_guid,ptimer});
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
    int ret;

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
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    HANDLE* ptmp= NULL;
    DWORD nsize=0;

    if (pev == NULL || hd == NULL || pfunc == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("pev %p hd %p pfunc %p",pev,hd,pfunc);
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
            nsize = (pev->m_waitsize << 1);
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
        pev->m_waitsize = nsize;
        ptmp = NULL;
    }

    //DEBUG_INFO("insert[%d] %p func %p",pev->m_waitnum,hd,pcall->m_func);
    pev->m_pwaits[pev->m_waitnum] = hd;
    pev->m_waitnum += 1;

    pev->m_pcallers->insert({hd,pcall});
    ASSERT_IF(pev->m_waitnum == pev->m_pcallers->size());
    ASSERT_IF(pev->m_waitnum <= pev->m_waitsize);
    return (int)pev->m_pcallers->size();
fail:
    if (ptmp) {
        free(ptmp);
    }
    ptmp = NULL;
    __free_winev_call(&pcall);
    SETERRNO(ret);
    return ret;
}

#if 0
int __find_evt_call(plibev_win_ev_t pev,HANDLE hd)
{
    unsigned int i;
    for(i=0;i<pev->m_pcallers->size();i++) {
        plibev_evt_call_t pcall = pev->m_pcallers->at(i);
        if (pcall->m_handle == hd) {
            return (int)i;
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
            return (int)i;
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
            return (int)i;
        }
    }
    return -1;    
}
#endif

int libev_remove_timer(void* pevmain,uint64_t guid)
{
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    int ret;

    if (pev == NULL || guid == 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    auto iter = pev->m_ptimers->find(guid);
    if (iter == pev->m_ptimers->end()) {
        /* nothing to find*/
        return 0;
    }


    plibev_evt_timer_t ptimer = iter->second;

    RB_NODE* node = rb_find(pev->m_rbtimer,ptimer);
    if (node != NULL) {
        rb_delete(pev->m_rbtimer,node,1);
    }
    pev->m_ptimers->erase(iter);
    __free_winev_timer(&ptimer);
    return 1;
}

int libev_remove_handle(void* pevmain,HANDLE hd)
{
    plibev_win_ev_t pev = (plibev_win_ev_t) pevmain;
    int fidx=-1;
    int ret;
    HANDLE* ptmp =NULL;
    int i;


    if (pev == NULL || hd == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    auto iter = pev->m_pcallers->find(hd);
    if (iter == pev->m_pcallers->end()) {
        return 0;
    }


    //DEBUG_INFO("remove handle %p",hd);

    plibev_evt_call_t pcall = iter->second;
    pev->m_pcallers->erase(iter);
    __free_winev_call(&pcall);
    if (pev->m_pwaits != NULL) {
        fidx = -1;
        for(i=0;i<(int)(pev->m_waitnum);i++) {
            //DEBUG_INFO("[%d] %p => %p",i,pev->m_pwaits[i],pev->m_pwaits[i+1]);
            if (fidx < 0) {
                if (pev->m_pwaits[i] == hd)  {
                    fidx = i;
                    continue;
                }                
            } else {
                /*to put the handle*/
                pev->m_pwaits[i-1] = pev->m_pwaits[i];
            }
        }
        pev->m_pwaits[pev->m_waitnum-1] = NULL;
        pev->m_waitnum -= 1;
        //DEBUG_INFO("waitnum %d",pev->m_waitnum);
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
            } else {
                if (pev->m_pwaits != NULL) {
                    free(pev->m_pwaits);
                }                
                pev->m_pwaits = NULL;
                pev->m_waitsize = 0;
            }
        }
    }


    ASSERT_IF(pev->m_pcallers->size() == pev->m_waitnum);
    ASSERT_IF(pev->m_waitnum <= pev->m_waitsize );

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
    int ret;
    RB_NODE* node = rb_first(pev->m_rbtimer);
    if (node != NULL) {
        /* now we should give */
        uint64_t cticks = get_current_ticks();
        plibev_evt_timer_t ptimer = (plibev_evt_timer_t)rb_node_get(node);
        ret = need_wait_times(ptimer->m_startticks,cticks,(int)ptimer->m_interval);
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
    std::vector<uint64_t> timerguids;
    DWORD dret;
    HANDLE hd;
    unsigned int i;
    uint64_t cticks;
    plibev_evt_timer_t  ptimer;

    if (pev == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    while(pev->m_exited == 0) {
        maxmills = __get_max_mills(pev,30000);
        if (pev->m_waitnum > 0) {
            waitnum = pev->m_waitnum;
            //DEBUG_INFO("waitnum %d",waitnum);
            dret = WaitForMultipleObjectsEx(pev->m_waitnum,pev->m_pwaits,FALSE,(DWORD)maxmills,TRUE);
        } else {
            waitnum = 1;
            dret = WaitForMultipleObjectsEx(1,pev->m_htmevt,FALSE,(DWORD)maxmills,TRUE);
        }
        if (dret < (WAIT_OBJECT_0 + waitnum)) {
            if (pev->m_waitnum > 0) {
                hd = pev->m_pwaits[(dret - WAIT_OBJECT_0)];
            } else {
                hd = pev->m_htmevt[0];
            }
            //DEBUG_INFO("[%d]hd %p",dret,hd);
            auto iter = pev->m_pcallers->find(hd);

            if (iter != pev->m_pcallers->end()) {
                plibev_evt_call_t pcall = iter->second;
                //DEBUG_INFO("pcall->m_func %p",pcall->m_func);
                ret = pcall->m_func(pcall->m_handle,normal_event,pev,pcall->m_args);
                //DEBUG_INFO("pcall->m_func %p ret %d",pcall->m_func, ret);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
            }
        } else if (dret != WAIT_TIMEOUT) {
            GETERRNO(ret);
            ERROR_INFO("wait error [%ld] %d", dret,ret);
            goto fail;
        } 
        /*now to check for the timer*/
        timerguids.clear();
        RB_NODE* node = rb_first(pev->m_rbtimer);
        while(1) {
            if (node == NULL) {
                break;
            }

            cticks = get_current_ticks();
            ptimer = (plibev_evt_timer_t)rb_node_get(node);
            ret = need_wait_times(ptimer->m_startticks,cticks,(int)ptimer->m_interval);
            if (ret < 0) {
                /*we add timer*/
                timerguids.push_back(ptimer->m_guid);
            } else {
                /*no timers*/
                break;
            }
            node = rb_node_next(node);
        }

        for(i=0;i<timerguids.size();i++) {
            auto iter = pev->m_ptimers->find(timerguids.at((uint64_t)i));
            if (iter != pev->m_ptimers->end()) {
                ptimer = iter->second;
                //DEBUG_INFO("call ptimer %p", ptimer->m_func);
                ret = ptimer->m_func(timerguids.at(i),timer_event,pev,ptimer->m_args);
                //DEBUG_INFO("call ptimer %p ret %d", ptimer->m_func, ret);
                if (ret < 0) {
                    GETERRNO(ret);
                    goto fail;
                }
            }
        }

        //DEBUG_INFO("find timers update");
        /*now to make running again*/
        for(i=0;i<timerguids.size();i++) {
            auto iter = pev->m_ptimers->find(timerguids.at((uint64_t)i));
            if (iter != pev->m_ptimers->end()) {
                ptimer = iter->second;
                node = rb_find(pev->m_rbtimer,ptimer);
                if (node != NULL) {
                    /*to get the timer*/
                    rb_delete(pev->m_rbtimer,node,1);
                }
                if (ptimer->m_conti == 0) {
                    pev->m_ptimers->erase(iter);
                    __free_winev_timer(&ptimer);
                } else {
                    ptimer->m_startticks = get_current_ticks();
                    node = rb_insert(pev->m_rbtimer,ptimer);
                    if (node == NULL) {
                        GETERRNO(ret);
                        ERROR_INFO("can not insert timer %lld", ptimer->m_guid);
                        goto fail;
                    }
                }
            }
        }
        //DEBUG_INFO("exited %d", pev->m_exited);
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}


#pragma warning(pop)