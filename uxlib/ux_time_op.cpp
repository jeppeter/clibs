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

int is_time_expired(uint64_t startticks,uint32_t expiremills)
{
	uint64_t curticks;
	int ret;
	SETERRNO(0);
	curticks = get_cur_ticks();
	GETERRNO_DIRECT(ret);
	if (curticks != ULLONG_MAX || ret == 0) {
		if (curticks > (startticks + expiremills)) {
			return 0;
		}
		if ((ULLONG_MAX- startticks) < expiremills) {
			if (curticks > (expiremills - (ULLONG_MAX - startticks))) {
				return 0;
			}
		}
	}
	return 1;
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