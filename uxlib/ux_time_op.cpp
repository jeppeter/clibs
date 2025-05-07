#include <ux_time_op.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

uint64_t get_cur_ticks()
{
	struct timespec ts;
	int ret;
	uint64_t retmills=0;

	ret = clock_gettime(CLOCK_MONOTONIC,&ts);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	retmills += ts.tv_sec * 1000;
	retmills += ((ts.tv_nsec % 1000000000) / 1000000);
	return retmills;
fail:
	SETERRNO(ret);
	return ULLONG_MAX;

}

int time_left(uint64_t startticks,uint32_t expiremills)
{
	uint64_t curticks;
	int ret;
	SETERRNO(0);
	curticks = get_cur_ticks();
	GETERRNO_DIRECT(ret);
	if (curticks != ULLONG_MAX || ret == 0) {
		if (curticks < (expiremills + startticks) && curticks >= startticks) {
			return (int)(startticks + expiremills - curticks);
		}

		if ((ULLONG_MAX - startticks) < expiremills) {
			if (curticks > 0 && curticks < (expiremills - (ULLONG_MAX - startticks))) {
				return (expiremills - (ULLONG_MAX - startticks)) - curticks;
			}
			if (curticks >= startticks && curticks < ULLONG_MAX) {
				return (expiremills - (curticks - startticks));
			}
		}
	}
	return 0;
}

#define  MAX_TICK_COUNT  (0xffffffffffffffffULL)

int need_wait_times(uint64_t sticks, uint64_t eticks,int timeout)
{
	uint64_t leftticks;
	if (eticks > sticks && eticks >= (sticks + timeout)) {
		return -1;
	}

	if ((eticks < sticks)) {
		leftticks = (MAX_TICK_COUNT - sticks);
		leftticks += eticks;
		if ((int)leftticks >= timeout) {
			return -1;
		}

		return (timeout - (int)leftticks);
	}

	return (int)(timeout - (eticks - sticks));	
}

int sched_out(int mills)
{
	int ret;
	ret = usleep(mills * 1000);
	if (ret < 0) {
		return ret;
	}
	return 0;
}