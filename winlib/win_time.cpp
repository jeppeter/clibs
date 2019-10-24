#include <win_time.h>
#include <Windows.h>

#define  MAX_TICK_COUNT  (0xffffffffffffffffULL)

uint64_t get_current_ticks(void)
{
	ULONGLONG ticks;

	ticks = GetTickCount64();
	return ticks;
}

int need_wait_times(uint64_t sticks, uint64_t eticks, int timeout)
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

int sleep_mill(int mills)
{
	Sleep(mills);
	return 0;
}
