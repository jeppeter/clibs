#ifndef __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__
#define __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__

#include <stdio.h>
#include <stdlib.h>

#ifndef __UX_INNER_DEFINE__
#define __UX_INNER_DEFINE__
#endif

#include <ux_inner.h>

#undef  __UX_INNER_DEFINE__


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

void DebugOutString(const char* file,int lineno,const char* fmt,...);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_OUTPUT_DEBUG_H_4E51594137D81AAE3E9474E2018745D5__ */
