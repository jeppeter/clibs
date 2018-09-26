#include <win_acl.h>
#include <win_err.h>
#include <win_types.h>
#include <win_uniansi.h>


#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>


#define   WIN_ACL_MAGIC            0x3021211

#define   SET_WIN_ACL_MAGIC(pacl)  do{if ((pacl) != NULL) { (pacl)->m_magic = WIN_ACL_MAGIC;}} while(0)
#define   IS_WIN_ACL_MAGIC(pacl)  ((pacl) == NULL || ((pacl)->m_magic == WIN_ACL_MAGIC))

typedef struct __win_acl {
	uint32_t  m_magic;
	PSID m_owner;
	PSID m_group;
	PACL m_dacl;
	PACL m_sacl;
	PSECURITY_DESCRIPTOR m_psdp;
} win_acl_t,*pwin_acl_t;

void __free_win_acl(pwin_acl_t* ppacl)
{
	if (ppacl && *ppacl) {
		pwin_acl_t pacl = *ppacl;
		if (IS_WIN_ACL_MAGIC(pacl)) {
			if (pacl->m_psdp) {
				LocalFree(pacl->m_psdp);
				pacl->m_psdp = NULL;
			}
			if (pacl->m_owner) {
				LocalFree(pacl->m_owner);
			}
			pacl->m_owner = NULL;
			if (pacl->m_group) {

			}

			pacl->m_magic = 0;

		}
		free(pacl);
		*ppacl = NULL;
	}
}

pwin_acl_t __alloc_win_acl()
{
	pwin_acl_t pacl=NULL;
	int ret;
	pacl = (pwin_acl_t)malloc(sizeof(*pacl));
	if (pacl == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc %ld error [%d]", sizeof(*pacl), ret);
		goto fail;
	}
	memset(pacl,0,sizeof(*pacl));
	SET_WIN_ACL_MAGIC(pacl);
	pacl->m_psdp = NULL;
	return pacl;
fail:
	__free_win_acl(&pacl);
	SETERRNO(ret);
	return NULL;
}


int get_file_acl(const char* fname, void** ppacl1)
{
	int ret;
	pwin_acl_t pretacl=NULL;
	TCHAR* ptname=NULL;
	int tnamesize=0;
	DWORD dret;
	if (fname == NULL) {
		if (ppacl1 && *ppacl1) {
			pretacl = (pwin_acl_t)*ppacl1;
			__free_win_acl(&pretacl);
			*ppacl1 = NULL;
		}
		return 0;
	}

	if (ppacl1 == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}
	pretacl = (pwin_acl_t)*ppacl1;
	if (pretacl == NULL) {
		pretacl = __alloc_win_acl();
		if (pretacl == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (pretacl->m_psdp != NULL) {
		LocalFree(pretacl->m_psdp);
		pretacl->m_psdp = NULL;
	}

	ret = AnsiToTchar(fname, &ptname,&tnamesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	dret = GetNamedSecurityInfo(ptname,SE_FILE_OBJECT,BACKUP_SECURITY_INFORMATION,
			NULL,NULL,NULL,NULL,&(pretacl->m_psdp));
	if (dret != ERROR_SUCCESS) {
		ret = dret;
		if (ret > 0) {
			ret = -ret;
		}
		if (ret == 0) {
			ret = -1;
		}
		ERROR_INFO("get [%s] security descriptor error[%d]", fname, ret);
		goto fail;
	}

	*ppacl1 = pretacl;
	return 0;
fail:
	AnsiToTchar(NULL,&ptname,&tnamesize);
	if (pretacl != NULL && pretacl != *ppacl1) {
		__free_win_acl(&pretacl);
	}
	SETERRNO(ret);
	return ret;
}

int get_acl_user(void* pacl1,int idx,char** ppuser,int *pusersize)
{
	int ret;
	pwin_acl_t pacl=NULL;
	pacl = (pwin_acl_t) pacl1;
	char* pretuser=NULL;
	int usersize=0;
	int retlen=0;
	BOOL bret;
	char* pch=NULL;
	DWORD chlen=0;
	if (pacl == NULL) {
		if (ppuser && *ppuser) {
			free(*ppuser);
			*ppuser = NULL;
		}
		if (pusersize) {
			*pusersize = 0;
		}
		return 0;
	}
	if (ppuser == NULL || pusersize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;		
	}
	pretuser = *ppuser;
	usersize = *pusersize;

	if (!IS_WIN_ACL_MAGIC(pacl) ) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	if (pacl->m_psdp == NULL) {
		retlen = 0;
		goto succ;
	}

try_again:
	chlen = 0;
	bret = ConvertSecurityDescriptorToStringSecurityDescriptor(pacl->m_psdp,SDDL_REVISION_1,BACKUP_SECURITY_INFORMATION,&pch,&chlen);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("get error[%d]", ret);
		goto fail;
	}


	retlen = chlen;

	if (pretuser == NULL || usersize < (retlen + 1)) {
		if (usersize < (retlen + 1)) {
			usersize = (retlen + 1);
		}
		pretuser = (char*)malloc(usersize);
		if (pretuser == NULL) {
			GETERRNO(ret);
			ERROR_INFO("alloc %d error[%d]", usersize, ret);
			goto fail;
		}
	}
	memset(pretuser, 0, usersize);
	memcpy(pretuser, pch, retlen);
succ:
	if (pch) {
		LocalFree(pch);
	}
	pch = NULL;
	chlen = 0;

	if (*ppuser && *ppuser != pretuser) {
		free(*ppuser);
	}
	*ppuser = pretuser;
	*pusersize = usersize;
	return retlen;
fail:
	if (pch) {
		LocalFree(pch);
	}
	pch = NULL;
	chlen = 0;

	if (pretuser && pretuser != *ppuser) {
		free(pretuser);
	}
	pretuser = NULL;
	usersize = 0;
	SETERRNO(ret);
	return ret;
}