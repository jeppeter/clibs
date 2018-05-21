#ifndef __WIN_ERR_H__
#define __WIN_ERR_H__

#include <Windows.h>
#include <win_output_debug.h>

#define SETERRNO(ret)                                         \
	do{                                                       \
		int ___ret = (ret);                                   \
		if (___ret > 0) {                                     \
			SetLastError((DWORD)___ret);                      \
		} else {                                              \
			SetLastError((DWORD)-___ret);                     \
		}                                                     \
	}while(0)

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

#define ALLOC_ERROR_GOTO(type,ptr,size,label)                 \
    do{                                                       \
    	ptr = (type*) malloc((size_t) (size));                \
    	if ((ptr) == NULL) {                                  \
    		GETERRNO(ret);                                    \
    		ERROR_INFO("alloc %d error[%d]", (size), ret);    \
    		goto label;                                       \
    	}                                                     \
    }while(0)

#define ALLOC_SIZEOF_GOTO(type, ptr, label)  ALLOC_ERROR_GOTO(type,ptr, sizeof(type),label)
#define ALLOC_SIZEOF(type,ptr)               ALLOC_SIZEOF_GOTO(type,ptr,fail)
#define ALLOC_ERROR(type,ptr,size)           ALLOC_ERROR_GOTO(type,ptr,size,fail)
#define ALLOC_PTR_TYPEOF(ptr)                ALLOC_SIZEOF(typeof(ptr),ptr)                     


#define FREE_CHECK(ptr)                                       \
    do{                                                       \
    	if ((ptr) != NULL) {                                  \
    		free((ptr));                                      \
    	}                                                     \
    	ptr = NULL;                                           \
    }while(0)

#define CHECK_NULL_LABEL_FMT(ptr, label,...)                  \
    do{                                                       \
    	if ((ptr) == NULL) {                                  \
    		GETERRNO(ret);                                    \
    		ERROR_INFO(__VA_ARGS__);                          \
    		goto label;                                       \
    	}                                                     \
    }while(0)

#define CHECK_NULL_FAIL(ptr,...)             CHECK_NULL_LABEL_FMT(ptr,fail,__VA_ARGS__)
#define CHECK_CLOSE_HANDLE_FMT(hdl,...)                       \
    do{                                                       \
    	BOOL _bret;                                           \
    	if (hdl != NULL && hdl != INVALID_HANDLE_VALUE) {     \
    		_bret = CloseHandle((hdl));                       \
    		if (!_bret) {                                     \
    			GETERRNO(res);                                \
    			ERROR_INFO(__VA_ARGS__);                      \
    		}                                                 \
    	}                                                     \
    }while(0)


#endif /*__WIN_ERR_H__*/
