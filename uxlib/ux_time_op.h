#ifndef __UX_TIME_OP_H_686634303970A7D7715CF3E0E6A06914__
#define __UX_TIME_OP_H_686634303970A7D7715CF3E0E6A06914__

#include <ux_err.h>
#include <time.h>

#define  MAX_TIME_VALUE      0xffffffffffffffffULL

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

uint64_t get_cur_ticks();
int time_left(uint64_t startticks,uint32_t expiremills);
int need_wait_times(uint64_t startticks, uint64_t curticks,int expiremills);
int sched_out(int mills);
int tm_to_str(struct tm* ptm, char** ppstr, int *psize);
int tm_from_str(char* str, struct tm* ptm);
int tm_to_time(struct tm* ptm, time_t* ptime);
int time_to_tm(time_t* ptime,struct tm *ptm);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_TIME_OP_H_686634303970A7D7715CF3E0E6A06914__ */
