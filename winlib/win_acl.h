#ifndef __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__
#define __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

int get_file_acls(const char* fname, void** ppacl);
int set_file_acls(const char* fname, void* pacl);

int set_file_owner(void* pacl, const char* username);
int set_file_group(void* pacl, const char* groupname);

int remove_sacl_user(void* pacl,const char* username,const char* action,const char* right);
int add_sacl_user(void* pacl,const char* username,const char* action,const char* right);
int get_sacl_user(void* pacl,int idx,char** ppuser,int *pusersize);
int get_sacl_action(void* pacl, int idx,char** ppaction,int* pactionsize);
int get_sacl_right(void* pacl,int idx,char** ppright,int *prightsize);

int remove_dacl_user(void* pacl,const char* username,const char* action,const char* right);
int add_dacl_user(void* pacl,const char* username,const char* action,const char* right);
int get_dacl_user(void* pacl,int idx,char** ppuser,int *pusersize);
int get_dacl_action(void* pacl, int idx,char** ppaction,int* pactionsize);
int get_dacl_right(void* pacl,int idx,char** ppright,int *prightsize);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__ */
