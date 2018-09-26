#ifndef __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__
#define __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

int get_file_acl(const char* fname, void** ppacl);
int set_file_acl(const char* fname, void* pacl);
int remove_acl_user(void* pacl,const char* username,const char* action,const char* right);
int add_acl_user(void* pacl,const char* username,const char* action,const char* right);
int get_acl_user(void* pacl,int idx,char** ppuser,int *pusersize);
int get_acl_action(void* pacl, int idx,char** ppaction,int* pactionsize);
int get_acl_right(void* pacl,int idx,char** ppright,int *prightsize);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_ACL_H_67353EE5027406E3E0B6DB2DB8140A3A__ */
