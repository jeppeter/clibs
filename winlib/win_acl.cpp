#include <win_acl.h>
#include <win_err.h>
#include <win_types.h>
#include <win_uniansi.h>
#include <win_priv.h>

#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>


#define   WIN_ACL_MAGIC            0x3021211

#define   SET_WIN_ACL_MAGIC(pacl)  do{if ((pacl) != NULL) { (pacl)->m_magic = WIN_ACL_MAGIC;}} while(0)
#define   IS_WIN_ACL_MAGIC(pacl)  ((pacl) == NULL || ((pacl)->m_magic == WIN_ACL_MAGIC))

typedef struct __win_acl {
    uint32_t  m_magic;
    PSECURITY_DESCRIPTOR m_ownersdp;
    PSECURITY_DESCRIPTOR m_groupsdp;
    PSECURITY_DESCRIPTOR m_daclsdp;
    PSECURITY_DESCRIPTOR m_saclsdp;
} win_acl_t, *pwin_acl_t;

void __free_win_acl(pwin_acl_t* ppacl)
{
    if (ppacl && *ppacl) {
        pwin_acl_t pacl = *ppacl;
        if (IS_WIN_ACL_MAGIC(pacl)) {
            if (pacl->m_ownersdp) {
                LocalFree(pacl->m_ownersdp);
                pacl->m_ownersdp = NULL;
            }

            if (pacl->m_groupsdp) {
                LocalFree(pacl->m_groupsdp);
                pacl->m_groupsdp = NULL;
            }

            if (pacl->m_daclsdp) {
                LocalFree(pacl->m_saclsdp);
                pacl->m_saclsdp = NULL;
            }

            if (pacl->m_saclsdp) {
                LocalFree(pacl->m_saclsdp);
                pacl->m_saclsdp = NULL;
            }
            pacl->m_magic = 0;
        }
        free(pacl);
        *ppacl = NULL;
    }
}

pwin_acl_t __alloc_win_acl()
{
    pwin_acl_t pacl = NULL;
    int ret;
    pacl = (pwin_acl_t)malloc(sizeof(*pacl));
    if (pacl == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %ld error [%d]", sizeof(*pacl), ret);
        goto fail;
    }
    memset(pacl, 0, sizeof(*pacl));
    SET_WIN_ACL_MAGIC(pacl);
    pacl->m_ownersdp = NULL;
    pacl->m_groupsdp = NULL;
    pacl->m_saclsdp = NULL;
    pacl->m_daclsdp = NULL;
    return pacl;
fail:
    __free_win_acl(&pacl);
    SETERRNO(ret);
    return NULL;
}


int get_file_acls(const char* fname, void** ppacl1)
{
    int ret;
    pwin_acl_t pacl = NULL;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    DWORD dret;
    int enabled = 0;
    PSID owner = NULL;
    PSID group = NULL;
    PACL sacl = NULL;
    PACL dacl = NULL;
    if (fname == NULL) {
        if (ppacl1 && *ppacl1) {
            pacl = (pwin_acl_t) * ppacl1;
            __free_win_acl(&pacl);
            *ppacl1 = NULL;
        }
        return 0;
    }

    if (ppacl1 == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    pacl = (pwin_acl_t) * ppacl1;
    if (pacl == NULL) {
        pacl = __alloc_win_acl();
        if (pacl == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }

    if (pacl->m_ownersdp) {
        LocalFree(pacl->m_ownersdp);
        pacl->m_ownersdp = NULL;
    }

    if (pacl->m_groupsdp) {
        LocalFree(pacl->m_groupsdp);
        pacl->m_groupsdp = NULL;
    }

    if (pacl->m_daclsdp) {
        LocalFree(pacl->m_saclsdp);
        pacl->m_saclsdp = NULL;
    }

    if (pacl->m_saclsdp) {
        LocalFree(pacl->m_saclsdp);
        pacl->m_saclsdp = NULL;
    }

    ret = AnsiToTchar(fname, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = enable_security_priv();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    enabled = 1;

    dret = GetNamedSecurityInfo(ptname, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION ,
                                &owner, NULL, NULL, NULL, &(pacl->m_ownersdp));
    if (dret != ERROR_SUCCESS) {
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO("get [%s] owner error[%d]", fname, ret);
        goto fail;
    }

    dret = GetNamedSecurityInfo(ptname, SE_FILE_OBJECT, GROUP_SECURITY_INFORMATION ,
                                NULL, &group, NULL, NULL, &(pacl->m_groupsdp));
    if (dret != ERROR_SUCCESS) {
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO("get [%s] group error[%d]", fname, ret);
        goto fail;
    }


    dret = GetNamedSecurityInfo(ptname, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION ,
                                NULL, NULL, NULL, &sacl, &(pacl->m_saclsdp));
    if (dret != ERROR_SUCCESS) {
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO("get [%s] sacl error[%d]", fname, ret);
        goto fail;
    }

    dret = GetNamedSecurityInfo(ptname, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION ,
                                NULL, NULL, &dacl, NULL, &(pacl->m_daclsdp));
    if (dret != ERROR_SUCCESS) {
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO("get [%s] dacl error[%d]", fname, ret);
        goto fail;
    }

    if (enabled) {
        ret = disable_security_priv();
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        enabled = 0;
    }

    *ppacl1 = pacl;
    return 0;
fail:
    if (enabled) {
        disable_security_priv();
    }
    enabled = 0;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    if (pacl != NULL && pacl != *ppacl1) {
        __free_win_acl(&pacl);
    }
    SETERRNO(ret);
    return ret;
}

/*
    if (pacl->m_ownersdp != NULL) {
        chlen = 0;
        if (pch) {
            LocalFree(pch);
        }
        pch = NULL;
        bret = ConvertSecurityDescriptorToStringSecurityDescriptor(pacl->m_ownersdp, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION, &pch, &chlen);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("get error[%d]", ret);
            goto fail;
        }
        DEBUG_INFO("owner [%s]", pch);
    }

    if (pacl->m_groupsdp) {
        chlen = 0;
        if (pch) {
            LocalFree(pch);
        }
        pch = NULL;
        bret = ConvertSecurityDescriptorToStringSecurityDescriptor(pacl->m_groupsdp, SDDL_REVISION_1, GROUP_SECURITY_INFORMATION, &pch, &chlen);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("get error[%d]", ret);
            goto fail;
        }
        DEBUG_INFO("group [%s]", pch);
    }



    if (pacl->m_daclsdp) {
        chlen = 0;
        if (pch) {
            LocalFree(pch);
        }
        pch = NULL;
        bret = ConvertSecurityDescriptorToStringSecurityDescriptor(pacl->m_daclsdp, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &pch, &chlen);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("get error[%d]", ret);
            goto fail;
        }
        DEBUG_INFO("dacl [%s]", pch);
    }
*/

int __get_acl_user(PACL acl, int idx, char** ppuser, int *pusersize)
{
    int ret;
    char* pretuser = NULL;
    int usersize = 0;
    int retlen = 0;
    BOOL bret;
    PEXPLICIT_ACCESS  paccess = NULL, pcuracc = NULL;
    ULONG accnum = 0;
    DWORD dret;
    int i;
    PSID psid;
    char* pname = NULL;
    int namesize = 0;
    char* pdomain = NULL;
    int domainsize = 0;
    TCHAR* ptuser = NULL;
    DWORD tusersize = 0, tuserlen = 0;
    TCHAR* ptdomain = NULL;
    DWORD tdomainsize = 0, tdomainlen = 0;
    SID_NAME_USE siduse;
    idx = idx;
    if (acl == NULL) {
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



    accnum = 0;
    paccess = NULL;
    dret = GetExplicitEntriesFromAcl(acl, &accnum, &paccess);
    if (dret != ERROR_SUCCESS) {
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO("get acl explicit error[%d]", ret);
        goto fail;
    }

    DEBUG_INFO("get accnum [%d]", accnum);
    if ((int)accnum <= idx) {
        retlen = 0;
        goto succ;
    }


    for (i = 0; i < (int)accnum; i++) {
        pcuracc = &(paccess[i]);
        DEBUG_INFO("[%d] grfAccessPermissions [%ld]", i, pcuracc->grfAccessPermissions);
        DEBUG_INFO("[%d] grfAccessMode [%ld]", i, pcuracc->grfAccessMode);
        DEBUG_INFO("[%d] grfInheritance [%ld]", i, pcuracc->grfInheritance);
        DEBUG_INFO("[%d] pMultipleTrustee [%p]", i, pcuracc->Trustee.pMultipleTrustee);
        DEBUG_INFO("[%d] MultipleTrusteeOperation [%d]", i, pcuracc->Trustee.MultipleTrusteeOperation);
        DEBUG_INFO("[%d] TrusteeForm [%d]", i, pcuracc->Trustee.TrusteeForm);
        DEBUG_INFO("[%d] TrusteeType [%d]", i, pcuracc->Trustee.TrusteeType);
        if (pcuracc->Trustee.TrusteeForm == TRUSTEE_IS_SID  &&
                pcuracc->Trustee.TrusteeType == TRUSTEE_IS_UNKNOWN) {
            psid = (PSID) pcuracc->Trustee.ptstrName;
            tusersize = 3;
            tdomainsize = 3;
try_get_sid_old:
            if (ptuser) {
                free(ptuser);
            }
            ptuser = NULL;
            if (ptdomain) {
                free(ptdomain);
            }
            ptdomain = NULL;
            ptuser = (TCHAR*) malloc(tusersize * sizeof(TCHAR));
            if (ptuser == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", tusersize * sizeof(TCHAR), ret);
                goto fail;
            }

            ptdomain = (TCHAR*)malloc(tdomainsize * sizeof(TCHAR));
            if (ptdomain == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", tdomainsize * sizeof(TCHAR), ret);
                goto fail;
            }
            tuserlen = tusersize;
            tdomainlen = tdomainsize;
            bret = LookupAccountSid(NULL, psid, ptuser, &tuserlen, ptdomain, &tdomainlen, &siduse);
            if (!bret) {
                GETERRNO(ret);
                if (ret == -ERROR_INSUFFICIENT_BUFFER) {
                    tusersize = tuserlen << 1;
                    tdomainsize = tdomainlen << 1;
                    goto try_get_sid_old;
                }
                ERROR_INFO("get sid error [%d]", ret);
                goto fail;
            }
            ret = TcharToAnsi(ptuser, &pname, &namesize);
            if (ret > 0) {
                ret = TcharToAnsi(ptdomain, &pdomain, &domainsize);
                if (ret > 0) {
                    DEBUG_INFO("[%d] ptstrName [%s].[%s]", i, pdomain, pname);
                }

            }
        }
    }

    pcuracc = &(paccess[idx]);
    if (pcuracc->Trustee.TrusteeForm != TRUSTEE_IS_SID  ||
            pcuracc->Trustee.TrusteeType != TRUSTEE_IS_UNKNOWN) {
        ret = -ERROR_NOT_SUPPORTED;
        ERROR_INFO("form [%d] type [%d] not supported", pcuracc->Trustee.TrusteeForm,
                   pcuracc->Trustee.TrusteeType);
        goto fail;
    }

    tusersize = 3;
    tdomainsize = 3;
try_get_sid:
    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;
    ptuser = (TCHAR*) malloc(tusersize * sizeof(TCHAR));
    if (ptuser == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tusersize * sizeof(TCHAR), ret);
        goto fail;
    }

    ptdomain = (TCHAR*)malloc(tdomainsize * sizeof(TCHAR));
    if (ptdomain == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", tdomainsize * sizeof(TCHAR), ret);
        goto fail;
    }
    tuserlen = tusersize;
    tdomainlen = tdomainsize;
    bret = LookupAccountSid(NULL, psid, ptuser, &tuserlen, ptdomain, &tdomainlen, &siduse);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            tusersize = tuserlen << 1;
            tdomainsize = tdomainlen << 1;
            goto try_get_sid;
        }
        ERROR_INFO("get sid error [%d]", ret);
        goto fail;
    }
    ret = TcharToAnsi(ptuser, &pname, &namesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;

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
    memcpy(pretuser, pname, retlen);
succ:
    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;

    TcharToAnsi(NULL, &pdomain, &domainsize);
    TcharToAnsi(NULL, &pname, &namesize);
    if (paccess) {
        LocalFree(paccess);
    }
    paccess = NULL;


    if (*ppuser && *ppuser != pretuser) {
        free(*ppuser);
    }
    *ppuser = pretuser;
    *pusersize = usersize;
    return retlen;
fail:
    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;

    TcharToAnsi(NULL, &pdomain, &domainsize);
    TcharToAnsi(NULL, &pname, &namesize);
    if (paccess) {
        LocalFree(paccess);
    }
    paccess = NULL;

    if (pretuser && pretuser != *ppuser) {
        free(pretuser);
    }
    pretuser = NULL;
    usersize = 0;
    SETERRNO(ret);
    return ret;
}

int get_sacl_user(void* pacl1, int idx, char** ppuser, int *pusersize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    BOOL bacldefault,bacl;
    BOOL bret;
    PACL sacl=NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
    	return __get_acl_user(NULL,idx,ppuser,pusersize);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_saclsdp == NULL) {
        retlen = 0;
        goto succ;
    }

    bacldefault = FALSE;
    bacl = FALSE;
    bret = GetSecurityDescriptorSacl(pacl->m_saclsdp, &bacl, &sacl, &bacldefault);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("get sacl error [%d]", ret);
        goto fail;
    }

    if (!bacl)  {
    	ret = -ERROR_INVALID_PARAMETER;
    	ERROR_INFO("not valid sacl");
    	goto fail;
    }

    ret = __get_acl_user(sacl,idx,ppuser,pusersize);
    if (ret < 0) {
    	GETERRNO(ret);
    	goto fail;
    }
    retlen =ret;
succ:
    return retlen;

 fail:
 	SETERRNO(ret);
 	return ret;
}