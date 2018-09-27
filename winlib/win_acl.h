#ifndef __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__
#define __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__


WINLIB_API int get_file_acls(const char* fname, void** ppacl);
WINLIB_API int set_file_acls(const char* fname, void* pacl);

WINLIB_API int get_file_owner(void* pacl, const char** ppusername,int *pusersize);
WINLIB_API int get_file_group(void* pacl, const char** ppgroup,int *pgrpsize);
WINLIB_API int set_file_owner(void* pacl, const char* username);
WINLIB_API int set_file_group(void* pacl, const char* groupname);

WINLIB_API int remove_sacl_user(void* pacl,const char* username,const char* action,const char* right);
WINLIB_API int add_sacl_user(void* pacl,const char* username,const char* action,const char* right);
WINLIB_API int get_sacl_user(void* pacl,int idx,char** ppuser,int *pusersize);
WINLIB_API int get_sacl_action(void* pacl, int idx,char** ppaction,int* pactionsize);
WINLIB_API int get_sacl_right(void* pacl,int idx,char** ppright,int *prightsize);

WINLIB_API int remove_dacl_user(void* pacl,const char* username,const char* action,const char* right);
WINLIB_API int add_dacl_user(void* pacl,const char* username,const char* action,const char* right);
WINLIB_API int get_dacl_user(void* pacl,int idx,char** ppuser,int *pusersize);
WINLIB_API int get_dacl_action(void* pacl, int idx,char** ppaction,int* pactionsize);
WINLIB_API int get_dacl_right(void* pacl,int idx,char** ppright,int *prightsize);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__ */
