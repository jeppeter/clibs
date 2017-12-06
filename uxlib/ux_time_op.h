#ifndef __UX_TIME_OP_H_686634303970A7D7715CF3E0E6A06914__
#define __UX_TIME_OP_H_686634303970A7D7715CF3E0E6A06914__

#include <ux_err.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

uint64_t get_cur_ticks();
int is_time_expired(uint64_t startticks,uint32_t expiremills);
int sched_out(int mills);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_TIME_OP_H_686634303970A7D7715CF3E0E6A06914__ */
