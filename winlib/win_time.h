#ifndef __WIN_TIME_H__
#define __WIN_TIME_H__

#include <win_types.h>

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#ifdef __cplusplus
extern "C" {
#endif

WINLIB_API uint64_t get_current_ticks(void);
WINLIB_API int need_wait_times(uint64_t sticks, uint64_t eticks, int timeout);
WINLIB_API int sleep_mill(int mills);

#ifdef __cplusplus
};
#endif


#endif /*__WIN_TIME_H__*/