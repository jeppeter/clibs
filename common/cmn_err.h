#ifndef __CMN_ERR_H_A6D6C31E06CEB6BB4AFDAA3EF4E38907__
#define __CMN_ERR_H_A6D6C31E06CEB6BB4AFDAA3EF4E38907__

#if defined(_WIN32) || defined(_WIN64)
/* this is the windows compiler */
#include <win_err.h>


/*include win_inner for WINLIB_API define*/
#ifndef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#endif
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#elif defined(__GNUC__)
/* this is for the unix gcc*/
#include <ux_err.h>

#ifndef __UX_INNER_DEFINED__
#define __UX_INNER_DEFINED__
#endif

#include <ux_inner.h>

#undef __UX_INNER_DEFINED__

#else
#error "not supported comilers"
#endif



#endif /* __CMN_ERR_H_A6D6C31E06CEB6BB4AFDAA3EF4E38907__ */
