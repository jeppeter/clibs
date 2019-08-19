#ifndef __WIN_USER_H_2E2D3253C4E4E70BB559BE70960D094D__
#define __WIN_USER_H_2E2D3253C4E4E70BB559BE70960D094D__


#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


WINLIB_API int user_change_password(char* user, char* oldpassword,char* newpassword);

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/




#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_USER_H_2E2D3253C4E4E70BB559BE70960D094D__ */
