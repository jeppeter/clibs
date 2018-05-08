#ifndef __WIN_ERR_H__
#define __WIN_ERR_H__

#include <Windows.h>
#include <win_output_debug.h>

#define SETERRNO(ret)         \
	do{ \
		int ___ret = (ret); \
		if (___ret > 0) { \
			SetLastError((DWORD)___ret);\
		} else { \
			SetLastError((DWORD)-___ret);\
		}\
	}while(0)
#define GETERRNO(__ret) \
	do{\
		 __ret = (int)GetLastError();\
		 if (__ret > 0) {\
		 	__ret = -__ret;\
		 } \
		 if (__ret == 0) {\
		 	__ret = -1;\
		 } \
	}while(0)
#define GETERRNO_DIRECT(ret) do{(ret) = -(int)GetLastError();}while(0)

#define ASSERT_IF(expr)  \
	do\
	{\
		if (!(expr)){\
			ERROR_INFO("expression %s not asserted",#expr);\
			abort();\
		}\
	}\
	while(0)


#endif /*__WIN_ERR_H__*/
