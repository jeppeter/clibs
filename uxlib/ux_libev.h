#ifndef __UX_LIBEV_H_67994DBB1801B781E9DC25491EF003BC__
#define __UX_LIBEV_H_67994DBB1801B781E9DC25491EF003BC__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define   READ_EVENT             1
#define   WRITE_EVENT            2
#define   ERROR_EVENT            4
#define   TIME_EVENT             8

typedef int (*evt_callback_func_t)(void* pev,int fd,int event);

void free_uxev(void** ppev);
void* init_uxev(void);
int add_uxev_callback(void* pev,int fd,int event, evt_callback_func_t func,void* args);
int delete_uxev(void* pev,int fd,int event);
int break_uxev(void* pev);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_LIBEV_H_67994DBB1801B781E9DC25491EF003BC__ */
