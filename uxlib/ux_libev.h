#ifndef __UX_LIBEV_H_67994DBB1801B781E9DC25491EF003BC__
#define __UX_LIBEV_H_67994DBB1801B781E9DC25491EF003BC__

#include <ux_err.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define   READ_EVENT             1
#define   WRITE_EVENT            2
#define   ERROR_EVENT            4
#define   TIME_EVENT             8

#define   LIBEV_CLOEXEC          1

typedef int (*evt_callback_func_t)(void* pev,uint64_t fd,int event,void* arg);

void free_uxev(void** ppev);
void* init_uxev(int flag);
int add_uxev_timer(void* pev1,int interval,int conti,uint64_t* ptimeid,evt_callback_func_t callback,void* arg);
int del_uxev_timer(void* pev,uint64_t timeid);
int modi_uxev_timer_callback(void* pev,uint64_t timeid, evt_callback_func_t callback);
int modi_uxev_timer_interval(void* pev, uint64_t timeid, int interval);
int modi_uxev_timer_conti(void* pev,uint64_t timeid,int conti);
int add_uxev_callback(void* pev,int fd,int event, evt_callback_func_t func,void* args);
int delete_uxev_callback(void* pev,int fd,int event);
int break_uxev(void* pev);
int loop_uxev(void* pev);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_LIBEV_H_67994DBB1801B781E9DC25491EF003BC__ */
