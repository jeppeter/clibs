#ifndef __WIN_PRIV_H_42F3970B7071BE6584FDEB901119D183__
#define __WIN_PRIV_H_42F3970B7071BE6584FDEB901119D183__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


WINLIB_API int enable_security_priv(void);
WINLIB_API int disable_security_priv(void);
WINLIB_API int enable_takeown_priv(void);
WINLIB_API int disable_takeown_priv(void);
WINLIB_API int enable_restore_priv(void);
WINLIB_API int disable_restore_priv(void);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_PRIV_H_42F3970B7071BE6584FDEB901119D183__ */
