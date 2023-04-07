#include <win_usb.h>

int list_usb_roots(int freed, pusb_root_t* ppur, int *psize)
{
	int retlen = 0;
	if (freed) {
		if (ppur && *ppur) {
			free(*ppur);
			*ppur = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	return retlen;
}