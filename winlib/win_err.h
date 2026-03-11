#ifndef __WIN_ERR_H__
#define __WIN_ERR_H__

#pragma warning(push)
#pragma warning(disable:4668)
#pragma warning(disable:4820)
#pragma warning(disable:4530)
#pragma warning(disable:4577)


#include <Windows.h>
#include <win_output_debug.h>

#pragma warning(pop)



#define SETERRNO(ret)       _set_error(ret)

__forceinline void _set_error(int ret)
{
	DWORD dret = (DWORD)ret;
	if (ret < 0) {
		dret = (DWORD) -ret;
	}
	SetLastError(dret);
	return;
}


#define GETERRNO(__ret)                                       \
	do{                                                       \
		 __ret = (int)GetLastError();                         \
		 if (__ret > 0) {                                     \
		 	__ret = -__ret;                                   \
		 }                                                    \
		 if (__ret == 0) {                                    \
		 	__ret = -1;                                       \
		 }                                                    \
	}while(0)
#define GETERRNO_DIRECT(ret) do{(ret) = -(int)GetLastError();}while(0)

#define ASSERT_IF(expr)                                       \
	do                                                        \
	{                                                         \
		if (!(expr)){                                         \
			ERROR_INFO("expression %s not asserted",#expr);   \
			abort();                                          \
		}                                                     \
	}                                                         \
	while(0)


#endif /*__WIN_ERR_H__*/
