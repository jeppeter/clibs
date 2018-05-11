#ifndef __JVALUE_EX_H_1925191D9BD53040673DA5AC12E8E994__
#define __JVALUE_EX_H_1925191D9BD53040673DA5AC12E8E994__

#include "jvalue.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

WINLIB_API  void free_jvalue(jvalue** ppj);
WINLIB_API  int add_jobject(jvalue* pj, const char* pkey, const char* value);

#ifdef __cplusplus
}
#endif /* __cplusplus*/

#endif /* __JVALUE_EX_H_1925191D9BD53040673DA5AC12E8E994__ */
