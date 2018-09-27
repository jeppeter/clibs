#ifndef __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__
#define __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#undef __WINLIB_INNER_INCLUDE__
#define __WINLIB_INNER_INCLUDE__
#include <win_inner.h>
#undef __WINLIB_INNER_INCLUDE__

#define ACL_ACTION_NOT_USED         "notused"
#define ACL_ACTION_GRANT            "grant"
#define ACL_ACTION_SET              "set"
#define ACL_ACTION_DENY             "deny"
#define ACL_ACTION_REVOKE           "revoke"
#define ACL_ACTION_AUDIT_SUCC       "auditsucc"
#define ACL_ACTION_AUDIT_FAIL       "auditfail"


#define ACL_RIGHT_DELETE            "delete"
#define ACL_RIGHT_READ_CONTROL      "readcontrol"
#define ACL_RIGHT_WRITE_DAC         "writedac"
#define ACL_RIGHT_WRITE_OWNER       "writeowner"
#define ACL_RIGHT_SYNCHRONIZE       "synchronize"

#define ACL_RIGHT_ALL               "all"

#define ACL_COMMON_SEP              ";"


WINLIB_API int get_file_acls(const char* fname, void** ppacl);
WINLIB_API int set_file_acls(const char* fname, void* pacl);

WINLIB_API int get_file_owner(void* pacl, char** ppusername,int *pusersize);
WINLIB_API int get_file_group(void* pacl, char** ppgroup,int *pgrpsize);


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
