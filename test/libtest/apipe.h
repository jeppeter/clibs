#ifndef __APIPE_H_B4A40817CE75B35EDB43A8B470107604__
#define __APIPE_H_B4A40817CE75B35EDB43A8B470107604__

#include <win_err.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/



typedef struct __async_evt {
    HANDLE m_evt;   /*this event must be manual set*/
    DWORD  m_errorcode;
    DWORD  m_cbret;
} async_evt_t,*pasync_evt_t;


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __APIPE_H_B4A40817CE75B35EDB43A8B470107604__ */
