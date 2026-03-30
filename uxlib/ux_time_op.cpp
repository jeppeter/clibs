#include <ux_time_op.h>
#include <ux_strop.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

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

int tm_to_str(struct tm* ptm, char** ppstr, int *psize)
{
    if (ptm == NULL) {
        return snprintf_safe(ppstr,psize,NULL);
    }

    return snprintf_safe(ppstr,psize,"%04d-%02d-%02d %02d:%02d:%02d",ptm->tm_year + 1900 ,ptm->tm_mon+1,ptm->tm_mday,ptm->tm_hour,ptm->tm_min,ptm->tm_sec);
}


#define SKIP_NUM(ptr)                                                                             \
do{                                                                                               \
    while(1) {                                                                                    \
        if ((*ptr)< '0' || (*ptr) > '9') {                                                        \
            break;                                                                                \
        }                                                                                         \
        ptr ++;                                                                                   \
    }                                                                                             \
}while(0)

#define MATCH_CHAR(ptr,ch)                                                                        \
do{                                                                                               \
    if ((*ptr) != ch) {                                                                           \
        ret = -EINVAL;                                                                            \
        goto fail;                                                                                \
    }                                                                                             \
    ptr ++;                                                                                       \
}while(0)

int tm_from_str(char* str, struct tm* ptm)
{
    int ret;
    char* pcurptr=NULL;
    struct tm *psettm=NULL;
    if (str == NULL || ptm == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    psettm = (struct tm*)malloc(sizeof(*psettm));
    if (psettm == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    pcurptr = str;

    memset(psettm, 0, sizeof(*psettm));
    psettm->tm_year = atoi(pcurptr);
    psettm->tm_year -= 1900;
    SKIP_NUM(pcurptr);
    MATCH_CHAR(pcurptr,'-');
    psettm->tm_mon = atoi(pcurptr);
    psettm->tm_mon -= 1;
    if (psettm->tm_mon < 0) {
        ret =-EINVAL;
        goto fail;
    }
    SKIP_NUM(pcurptr);
    MATCH_CHAR(pcurptr,'-');
    psettm->tm_mday = atoi(pcurptr);
    SKIP_NUM(pcurptr);

    while(1) {
        if (*pcurptr != ' ') {
            break;
        }
        pcurptr ++;
    }

    psettm->tm_hour = atoi(pcurptr);
    SKIP_NUM(pcurptr);
    MATCH_CHAR(pcurptr,':');

    psettm->tm_min = atoi(pcurptr);
    SKIP_NUM(pcurptr);
    MATCH_CHAR(pcurptr,':');

    psettm->tm_sec = atoi(pcurptr);

    memcpy(ptm,psettm,sizeof(*psettm));
    if (psettm) {
        free(psettm);
    }
    psettm = NULL;
    return 0;
fail:
    if (psettm) {
        free(psettm);
    }
    psettm = NULL;

    SETERRNO(ret);
    return ret;
}

int tm_to_time(struct tm* ptm, time_t* ptime)
{
    int ret;
    if (ptm == NULL || ptime == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }
    *ptime = mktime(ptm);
    return 0;
}

int time_to_tm(time_t* ptime,struct tm *ptm)
{
    int ret;
    struct tm* pret=NULL;

    if (ptm == NULL || ptime == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pret = localtime_r(ptime,ptm);
    if (pret == NULL) {
        GETERRNO(ret);
        SETERRNO(ret);
        return ret;
    }
    return 0;
}
