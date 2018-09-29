#include <win_acl.h>
#include <win_err.h>
#include <win_types.h>
#include <win_uniansi.h>
#include <win_priv.h>
#include <win_strop.h>
#include <win_envop.h>

#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>


#define   WIN_ACL_MAGIC            0x3021211

#define   MIN_SID_SIZE             5
#define   MIN_SECURITY_DESC_SIZE   sizeof(SECURITY_DESCRIPTOR)

#define    SID_GROUP_MODE                    1
#define    SID_OWNER_MODE                    2
#define    SACL_MODE                         3
#define    DACL_MODE                         4

#define   NO_ITEMS_MORE                     ERROR_NO_MORE_ITEMS

#define   SET_WIN_ACL_MAGIC(pacl)  do{if ((pacl) != NULL) { (pacl)->m_magic = WIN_ACL_MAGIC;}} while(0)
#define   IS_WIN_ACL_MAGIC(pacl)  ((pacl) == NULL || ((pacl)->m_magic == WIN_ACL_MAGIC))

typedef struct __win_acl {
    uint32_t  m_magic;
    char* m_fname;
    int m_namesize;
    PSECURITY_DESCRIPTOR m_ownersdp;
    DWORD m_ownersize;
    DWORD m_ownerlen;
    PSECURITY_DESCRIPTOR m_groupsdp;
    DWORD m_grpsize;
    DWORD m_grplen;
    PSECURITY_DESCRIPTOR m_daclsdp;
    DWORD m_daclsize;
    DWORD m_dacllen;
    PSECURITY_DESCRIPTOR m_saclsdp;
    DWORD m_saclsize;
    DWORD m_sacllen;
} win_acl_t, *pwin_acl_t;

void __free_trustee(PTRUSTEE* pptrustee);

void __release_trustee(PTRUSTEE ptrustee)
{
    if (ptrustee) {
        __free_trustee(&(ptrustee->pMultipleTrustee));
        ptrustee->MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        ptrustee->TrusteeForm = TRUSTEE_IS_SID;
        ptrustee->TrusteeType = TRUSTEE_IS_UNKNOWN;
        if (ptrustee->ptstrName) {
            LocalFree(ptrustee->ptstrName);
            ptrustee->ptstrName = NULL;
        }
    }
    return;
}

void __free_trustee(PTRUSTEE *pptrustee)
{
    PTRUSTEE ptrustee = NULL;
    if (pptrustee && *pptrustee) {
        ptrustee = *pptrustee;
        __release_trustee(ptrustee);
        LocalFree(ptrustee);
        *pptrustee = NULL;
    }
    return ;
}

int __init_trustee(PTRUSTEE ptrustee)
{
    memset(ptrustee, 0 , sizeof(*ptrustee));
    ptrustee->pMultipleTrustee = NULL;
    ptrustee->MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ptrustee->TrusteeForm = TRUSTEE_IS_SID;
    ptrustee->TrusteeType = TRUSTEE_IS_UNKNOWN;
    ptrustee->ptstrName = NULL;
    return 0;
}

PTRUSTEE __alloc_trustee(void)
{
    PTRUSTEE ptrustee = NULL;
    int ret;
    ptrustee = (PTRUSTEE)LocalAlloc(LMEM_FIXED, sizeof(*ptrustee));
    if (ptrustee == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*ptrustee), ret);
        goto fail;
    }

    ret = __init_trustee(ptrustee);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    return ptrustee;
fail:
    __free_trustee(&ptrustee);
    SETERRNO(ret);
    return NULL;
}


void __free_win_acl(pwin_acl_t* ppacl)
{
    if (ppacl && *ppacl) {
        pwin_acl_t pacl = *ppacl;
        if (IS_WIN_ACL_MAGIC(pacl)) {
            if (pacl->m_ownersdp) {
                LocalFree(pacl->m_ownersdp);
                pacl->m_ownersdp = NULL;
            }
            pacl->m_ownersize = 0;
            pacl->m_ownerlen = 0;

            if (pacl->m_groupsdp) {
                LocalFree(pacl->m_groupsdp);
                pacl->m_groupsdp = NULL;
            }
            pacl->m_grpsize = 0;
            pacl->m_grplen = 0;

            if (pacl->m_daclsdp) {
                LocalFree(pacl->m_saclsdp);
                pacl->m_saclsdp = NULL;
            }
            pacl->m_saclsize = 0;
            pacl->m_sacllen = 0;

            if (pacl->m_saclsdp) {
                LocalFree(pacl->m_saclsdp);
                pacl->m_saclsdp = NULL;
            }
            pacl->m_daclsize = 0;
            pacl->m_dacllen = 0;

            if (pacl->m_fname) {
                free(pacl->m_fname);
            }
            pacl->m_fname = NULL;
            pacl->m_namesize = 0;

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
    pacl->m_fname = NULL;
    pacl->m_namesize = 0;

    pacl->m_ownersdp = NULL;
    pacl->m_ownersize = 0;
    pacl->m_ownerlen = 0;

    pacl->m_groupsdp = NULL;
    pacl->m_grpsize = 0;
    pacl->m_grplen  = 0;

    pacl->m_saclsdp = NULL;
    pacl->m_saclsize = 0;
    pacl->m_sacllen = 0;

    pacl->m_daclsdp = NULL;
    pacl->m_daclsize = 0;
    pacl->m_dacllen = 0;
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
    int enabled = 0;
    BOOL bret;
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

    if (pacl->m_fname) {
        free(pacl->m_fname);
    }
    pacl->m_fname = NULL;
    pacl->m_namesize = 0;

    pacl->m_fname = strdup(fname);
    if (pacl->m_fname == NULL) {
        GETERRNO(ret);
        ERROR_INFO("strdup [%s] error[%d]", fname, ret);
        goto fail;
    }
    pacl->m_namesize = (int)strlen(fname) + 1;


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
    if (ret >= 0) {
        enabled = 1;
    }

try_owner_sec:
    if (pacl->m_ownersdp) {
        LocalFree(pacl->m_ownersdp);
        pacl->m_ownersdp = NULL;
    }
    if (pacl->m_ownersize < 10) {
        pacl->m_ownersize = 10;
    }
    pacl->m_ownersdp = LocalAlloc(LMEM_FIXED, pacl->m_ownersize);
    if (pacl->m_ownersdp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", pacl->m_ownersize, ret);
        goto fail;
    }
    pacl->m_ownerlen = pacl->m_ownersize;
    bret = GetFileSecurity(ptname, OWNER_SECURITY_INFORMATION, pacl->m_ownersdp, pacl->m_ownersize, &(pacl->m_ownerlen));
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            pacl->m_ownersize = pacl->m_ownerlen << 1;
            goto try_owner_sec;
        }
        ERROR_INFO("get[%s] owner error[%d]", fname, ret);
        goto fail;
    }
    DEBUG_BUFFER_FMT(pacl->m_ownersdp, pacl->m_ownerlen, "owner sdp");

try_grp_sec:
    if (pacl->m_groupsdp) {
        LocalFree(pacl->m_groupsdp);
        pacl->m_groupsdp = NULL;
    }
    if (pacl->m_grpsize < 10) {
        pacl->m_grpsize = 10;
    }
    pacl->m_groupsdp = LocalAlloc(LMEM_FIXED, pacl->m_grpsize);
    if (pacl->m_groupsdp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", pacl->m_grpsize, ret);
        goto fail;
    }
    bret = GetFileSecurity(ptname, GROUP_SECURITY_INFORMATION, pacl->m_groupsdp, pacl->m_grpsize, &(pacl->m_grplen));
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            pacl->m_grpsize = pacl->m_grplen << 1;
            goto try_grp_sec;
        }
        ERROR_INFO("get[%s] group error[%d]", fname, ret);
        goto fail;
    }
    DEBUG_BUFFER_FMT(pacl->m_groupsdp, pacl->m_grplen, "group sdp");

try_sacl_sec:
    if (pacl->m_saclsdp) {
        LocalFree(pacl->m_saclsdp);
        pacl->m_saclsdp = NULL;
    }
    if (pacl->m_saclsize < 10) {
        pacl->m_saclsize = 10;
    }
    pacl->m_saclsdp = LocalAlloc(LMEM_FIXED, pacl->m_saclsize);
    if (pacl->m_saclsdp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", pacl->m_saclsize, ret);
        goto fail;
    }
    bret = GetFileSecurity(ptname, SACL_SECURITY_INFORMATION, pacl->m_saclsdp, pacl->m_saclsize, &(pacl->m_sacllen));
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            pacl->m_saclsize = pacl->m_sacllen << 1;
            goto try_sacl_sec;
        }
        if (ret != -ERROR_PRIVILEGE_NOT_HELD) {
            ERROR_INFO("get[%s] sacl error[%d]", fname, ret);
            goto fail;
        }
        if (pacl->m_saclsdp) {
            LocalFree(pacl->m_saclsdp);
            pacl->m_saclsdp = NULL;
        }
        pacl->m_sacllen = 0;
        pacl->m_saclsize = 0;
    }
    if (pacl->m_saclsdp != NULL) {
        DEBUG_BUFFER_FMT(pacl->m_saclsdp, pacl->m_sacllen, "sacl sdp");
    }



try_dacl_sec:
    if (pacl->m_daclsdp) {
        LocalFree(pacl->m_daclsdp);
        pacl->m_daclsdp = NULL;
    }
    if (pacl->m_daclsize < 10) {
        pacl->m_daclsize = 10;
    }
    pacl->m_daclsdp = LocalAlloc(LMEM_FIXED, pacl->m_daclsize);
    if (pacl->m_daclsdp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", pacl->m_daclsize, ret);
        goto fail;
    }
    bret = GetFileSecurity(ptname, DACL_SECURITY_INFORMATION, pacl->m_daclsdp, pacl->m_daclsize, &(pacl->m_dacllen));
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            pacl->m_daclsize = pacl->m_dacllen << 1;
            goto try_dacl_sec;
        }
        ERROR_INFO("get[%s] dacl error[%d]", fname, ret);
        goto fail;
    }
    DEBUG_BUFFER_FMT(pacl->m_daclsdp, pacl->m_dacllen, "dacl sdp");

    if (enabled) {
        ret = disable_security_priv();
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        enabled = 0;
    }

    DEBUG_BUFFER_FMT(pacl->m_fname, pacl->m_namesize, "fname");
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

int __get_sid_name(PSID psid, char** ppstr, int *pstrsize)
{
    SID_NAME_USE siduse;
    TCHAR* ptuser = NULL, *ptdomain = NULL;
    DWORD tusersize = 0, tuserlen = 0;
    DWORD tdomainsize = 0, tdomainlen = 0;
    char* pname = NULL, *pdomain = NULL;
    int namesize = 0, namelen = 0, domainsize = 0, domainlen = 0;
    int ret;
    BOOL bret;
    int retlen;

    if (psid == NULL) {
        return snprintf_safe(ppstr, pstrsize, NULL);
    }

    tusersize = 32;
    tdomainsize = 32;
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
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    namelen = ret;

    ret = TcharToAnsi(ptdomain, &pdomain, &domainsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    domainlen = ret;

    if (domainlen > 0) {
        DEBUG_INFO("domain [%s] name [%s]", pdomain, pname);
        ret = snprintf_safe(ppstr, pstrsize, "%s\\%s", pdomain, pname);
    } else {
        ret = snprintf_safe(ppstr, pstrsize, "%s", pname);
    }
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;

    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;
    TcharToAnsi(NULL, &pname, &namesize);
    TcharToAnsi(NULL, &pdomain, &domainsize);
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
    TcharToAnsi(NULL, &pname, &namesize);
    TcharToAnsi(NULL, &pdomain, &domainsize);
    SETERRNO(ret);
    return ret;
}


void __debug_access_inner(PEXPLICIT_ACCESS pcuracc, const char* prefix)
{
    PSID psid = NULL;
    int ret;
    char* name = NULL;
    int namesize = 0;
    DEBUG_INFO("%s grfAccessPermissions [0x%lx]", prefix, pcuracc->grfAccessPermissions);
    if ((pcuracc->grfAccessPermissions & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL) {
        DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_ALL);
    } else {
        if (pcuracc->grfAccessPermissions & DELETE) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_DELETE);
        }
        if (pcuracc->grfAccessPermissions & READ_CONTROL) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_READ_CONTROL);
        }
        if (pcuracc->grfAccessPermissions & WRITE_DAC) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_WRITE_DAC);
        }
        if (pcuracc->grfAccessPermissions & WRITE_OWNER) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_WRITE_OWNER);
        }
        if (pcuracc->grfAccessPermissions & SYNCHRONIZE) {
            DEBUG_INFO("%s grfAccessPermissions %s", prefix, ACL_RIGHT_SYNCHRONIZE);
        }
    }


    switch (pcuracc->grfAccessMode) {
    case NOT_USED_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_NOT_USED);
        break;
    case GRANT_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_GRANT);
        break;
    case SET_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_SET);
        break;
    case DENY_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_DENY);
        break;
    case REVOKE_ACCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_REVOKE);
        break;
    case SET_AUDIT_SUCCESS:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_AUDIT_SUCC);
        break;
    case SET_AUDIT_FAILURE:
        DEBUG_INFO("%s grfAccessMode %s", prefix, ACL_ACTION_AUDIT_FAIL);
        break;
    default:
        DEBUG_INFO("%s grfAccessMode [0x%lx]", prefix, pcuracc->grfAccessMode);
    }

    DEBUG_INFO("%s grfInheritance [0x%x]", prefix, pcuracc->grfInheritance);
    if ((pcuracc->grfInheritance & CONTAINER_INHERIT_ACE) == CONTAINER_INHERIT_ACE) {
    	DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_CONTAINER_INHERIT_ACE);
    }

    if ((pcuracc->grfInheritance & INHERIT_NO_PROPAGATE) == INHERIT_NO_PROPAGATE) {
    	DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_INHERIT_NO_PROPAGATE);
    }

    if ((pcuracc->grfInheritance & INHERIT_ONLY) == INHERIT_ONLY) {
    	DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_INHERIT_ONLY);
    }
    if ((pcuracc->grfInheritance & NO_INHERITANCE) == NO_INHERITANCE) {
    	DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_NO_INHERITANCE);
    }
    if ((pcuracc->grfInheritance & OBJECT_INHERIT_ACE) == OBJECT_INHERIT_ACE) {
    	DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_OBJECT_INHERIT_ACE);
    }
    if ((pcuracc->grfInheritance & SUB_CONTAINERS_AND_OBJECTS_INHERIT) == SUB_CONTAINERS_AND_OBJECTS_INHERIT) {
    	DEBUG_INFO("%s grfInheritance %s", prefix, ACL_INHERITANCE_SUB_CONTAINERS_AND_OBJECTS_INHERIT);
    }

    DEBUG_INFO("%s pMultipleTrustee [%p]", prefix, pcuracc->Trustee.pMultipleTrustee);
    DEBUG_INFO("%s MultipleTrusteeOperation [0x%x]", prefix, pcuracc->Trustee.MultipleTrusteeOperation);
    DEBUG_INFO("%s TrusteeForm [0x%x]", prefix, pcuracc->Trustee.TrusteeForm);
    DEBUG_INFO("%s TrusteeType [0x%x]", prefix, pcuracc->Trustee.TrusteeType);

    if (pcuracc->Trustee.TrusteeForm == TRUSTEE_IS_SID  &&
            pcuracc->Trustee.TrusteeType == TRUSTEE_IS_UNKNOWN && 
            pcuracc->Trustee.ptstrName != NULL) {
        psid = (PSID) pcuracc->Trustee.ptstrName;
        ret = __get_sid_name(psid, &name, &namesize);
        if (ret > 0) {
            DEBUG_INFO("%s name [%s]", prefix, name);
        }
    }
    __get_sid_name(NULL, &name, &namesize);
    return;
}

void __debug_access(PEXPLICIT_ACCESS paccess, int accnum)
{
    char* prefix = NULL;
    int prefixsize = 0;
    int ret;
    int i;
    for (i = 0; i < accnum; i++) {
        ret = snprintf_safe(&prefix, &prefixsize, "[%d]", i);
        if (ret > 0) {
            __debug_access_inner(&(paccess[i]), prefix);
        }
    }
    snprintf_safe(&prefix, &prefixsize, NULL);
    return;
}

int __get_explicit_access(PACL acl, PEXPLICIT_ACCESS *ppaccess, int *psize)
{
    int accnum = 0;
    int ret;
    DWORD dret;

    if (acl == NULL) {
        if (ppaccess && *ppaccess) {
            LocalFree(*ppaccess);
            *ppaccess = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }
    if (ppaccess == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (*ppaccess != NULL || *psize != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    dret = GetExplicitEntriesFromAcl(acl, (PULONG)psize, ppaccess);
    if (dret != ERROR_SUCCESS) {
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO("get Entries error[%d]", ret);
        goto fail;
    }
    accnum = *psize;
    __debug_access(*ppaccess, accnum);
    return accnum;

fail:
    SETERRNO(ret);
    return ret;
}

typedef int (*filter_acl_func_t)(PEXPLICIT_ACCESS paccess, int accnum, int idx, char** ppstr, int *pstrsize);

int __get_acl_user_inner(PEXPLICIT_ACCESS paccess, int accnum, int idx, char** ppstr, int *pstrsize)
{
    int ret;
    int retlen = 0;
    BOOL bret;
    PEXPLICIT_ACCESS  pcuracc = NULL;
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
    if (paccess == NULL) {
        return snprintf_safe(ppstr, pstrsize, NULL);
    }
    if (ppstr == NULL || pstrsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }


    if ((int)accnum <= idx) {
    	ret = -NO_ITEMS_MORE;
    	goto fail;
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
    psid = (PSID)pcuracc->Trustee.ptstrName;
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
    if (ptdomain != NULL && tdomainlen > 0) {
        ret = TcharToAnsi(ptdomain, &pdomain, &domainsize);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    if (pdomain != NULL) {
        ret = snprintf_safe(ppstr, pstrsize, "%s\\%s", pdomain, pname);
    } else {
        ret = snprintf_safe(ppstr, pstrsize, "%s", pname);
    }

    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;

    if (ptuser) {
        free(ptuser);
    }
    ptuser = NULL;
    if (ptdomain) {
        free(ptdomain);
    }
    ptdomain = NULL;

    TcharToAnsi(NULL, &pname, &namesize);
    TcharToAnsi(NULL, &pdomain, &domainsize);
    if (retlen == 0) {
        if (ppstr && *ppstr) {
            **ppstr = '\0';
        }
    }
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
    TcharToAnsi(NULL, &pname, &namesize);
    TcharToAnsi(NULL, &pdomain, &domainsize);
    SETERRNO(ret);
    return ret;
}

int __handle_acl_idx_callback(PACL acl, int idx, char** ppstr, int *pstrsize, filter_acl_func_t callback)
{
    PEXPLICIT_ACCESS paccess = NULL;
    int accsize = 0, accnum = 0;
    int retlen;
    int ret;
    if (acl == NULL) {
        if (callback != NULL) {
            return callback(NULL, 0, idx, ppstr, pstrsize);
        }
        if (ppstr && *ppstr) {
            free(*ppstr);
            *ppstr = NULL;
        }
        if (pstrsize) {
            *pstrsize = 0;
        }
        return 0;
    }

    if (callback == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret = __get_explicit_access(acl, &paccess, &accsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    accnum = ret;

    ret = callback(paccess, accnum, idx, ppstr, pstrsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;

    __get_explicit_access(NULL, &paccess, &accsize);
    accnum = 0;
    return retlen;
fail:
    __get_explicit_access(NULL, &paccess, &accsize);
    accnum = 0;
    SETERRNO(ret);
    return ret;
}

int __get_sacl_from_descriptor(PSECURITY_DESCRIPTOR psdp, PACL *ppacl)
{
    BOOL bacldefault, bacl;
    BOOL bret;
    PACL acl = NULL;
    int ret;
    int retval = 1;

    bacl = FALSE;
    bacldefault = FALSE;
    bret = GetSecurityDescriptorSacl(psdp, &bacl, &acl, &bacldefault);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("get acl error[%d]", ret);
        goto fail;
    }

    if (!bacl) {
        retval = 0;
    }
    if (ppacl && acl != NULL) {
        *ppacl = acl;
    }

    return retval;
fail:
    SETERRNO(ret);
    return NULL;
}

int __get_dacl_from_descriptor(PSECURITY_DESCRIPTOR psdp, PACL* ppacl)
{
    BOOL bacldefault, bacl;
    BOOL bret;
    PACL acl = NULL;
    int ret;
    int retval = 1;

    bacl = FALSE;
    bacldefault = FALSE;
    bret = GetSecurityDescriptorDacl(psdp, &bacl, &acl, &bacldefault);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("get acl error[%d]", ret);
        goto fail;
    }

    if (!bacl) {
        retval = 0;
    }
    if (ppacl && acl != NULL) {
        *ppacl = acl;
    }

    return retval;
fail:
    SETERRNO(ret);
    return NULL;
}


int get_sacl_user(void* pacl1, int idx, char** ppuser, int *pusersize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PACL sacl = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __handle_acl_idx_callback(NULL, idx, ppuser, pusersize, __get_acl_user_inner);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_saclsdp == NULL) {
    	ret = -NO_ITEMS_MORE;
    	goto fail;
    }

    ret = __get_sacl_from_descriptor(pacl->m_saclsdp, &sacl);
    if (ret == 0 || sacl == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __handle_acl_idx_callback(sacl, idx, ppuser, pusersize, __get_acl_user_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    if (retlen == 0) {
        if (ppuser && *ppuser) {
            **ppuser = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}

int get_dacl_user(void* pacl1, int idx, char** ppuser, int *pusersize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PACL dacl = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __handle_acl_idx_callback(NULL, idx, ppuser, pusersize, __get_acl_user_inner);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_daclsdp == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __get_dacl_from_descriptor(pacl->m_daclsdp, &dacl);
    if (ret == 0 || dacl == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __handle_acl_idx_callback(dacl, idx, ppuser, pusersize, __get_acl_user_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    if (retlen == 0) {
        if (ppuser && *ppuser) {
            **ppuser = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}

#define  __INNER_SNPRINTF_SAFE(pptr,psize,...)                                                    \
   do {                                                                                           \
   		if (retlen >0) {                                                                          \
   			ret = append_snprintf_safe(pptr,psize,"%c",ACL_COMMON_SEP);                           \
   			if (ret < 0) {                                                                        \
   				GETERRNO(ret);                                                                    \
   				goto fail;                                                                        \
   			}                                                                                     \
   			ret = append_snprintf_safe(pptr,psize, __VA_ARGS__);                                  \
   		} else {                                                                                  \
   			ret = snprintf_safe(pptr,psize,__VA_ARGS__);                                          \
   		}                                                                                         \
   		if (ret < 0) {                                                                            \
   			GETERRNO(ret);                                                                        \
   			goto fail;                                                                            \
   		}                                                                                         \
   		retlen = ret;                                                                             \
   		DEBUG_INFO("[%d] %s",idx,*pptr);                                                          \
   }while(0)

int __get_acl_action_inner(PEXPLICIT_ACCESS paccess, int accnum, int idx, char** ppaction, int *pactionsize)
{
    int ret = 0;
    int retlen = 0;
    PEXPLICIT_ACCESS pcuracc;
    if (paccess == NULL) {
        return snprintf_safe(ppaction, pactionsize, NULL);
    }

    if (accnum <= idx) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }
    pcuracc = &(paccess[idx]);
    switch (pcuracc->grfAccessMode) {
    case NOT_USED_ACCESS:
        __INNER_SNPRINTF_SAFE(ppaction, pactionsize, "%s", ACL_ACTION_NOT_USED);
        break;
    case GRANT_ACCESS:
        __INNER_SNPRINTF_SAFE(ppaction, pactionsize, "%s", ACL_ACTION_GRANT);
        break;
    case SET_ACCESS:
        __INNER_SNPRINTF_SAFE(ppaction, pactionsize, "%s", ACL_ACTION_SET);
        break;
    case DENY_ACCESS:
        __INNER_SNPRINTF_SAFE(ppaction, pactionsize, "%s", ACL_ACTION_DENY);
        break;
    case REVOKE_ACCESS:
        __INNER_SNPRINTF_SAFE(ppaction, pactionsize, "%s", ACL_ACTION_REVOKE);
        break;
    case SET_AUDIT_SUCCESS:
        __INNER_SNPRINTF_SAFE(ppaction, pactionsize, "%s", ACL_ACTION_AUDIT_SUCC);
        break;
    case SET_AUDIT_FAILURE:
        __INNER_SNPRINTF_SAFE(ppaction, pactionsize, "%s", ACL_ACTION_AUDIT_FAIL);
        break;
    default:
        __INNER_SNPRINTF_SAFE(ppaction, pactionsize, "%s", ACL_ACTION_NOT_USED);
        break;
    }
    if (retlen == 0) {
        if (ppaction && *ppaction) {
            **ppaction = '\0';
        }
    }
    return retlen;
fail:
    SETERRNO(ret);
    return ret;
}

int get_sacl_action(void* pacl1, int idx, char** ppaction, int* pactionsize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PACL sacl = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __handle_acl_idx_callback(NULL, idx, ppaction, pactionsize, __get_acl_action_inner);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_saclsdp == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __get_sacl_from_descriptor(pacl->m_saclsdp, &sacl);
    if (ret == 0 || sacl == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __handle_acl_idx_callback(sacl, idx, ppaction, pactionsize, __get_acl_action_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    if (retlen == 0) {
        if (ppaction && *ppaction) {
            **ppaction = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}

int get_dacl_action(void* pacl1, int idx, char** ppaction, int* pactionsize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PACL dacl = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __handle_acl_idx_callback(NULL, idx, ppaction, pactionsize, __get_acl_action_inner);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_daclsdp == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __get_dacl_from_descriptor(pacl->m_daclsdp, &dacl);
    if (ret == 0 || dacl == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __handle_acl_idx_callback(dacl, idx, ppaction, pactionsize, __get_acl_action_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    if (retlen == 0) {
        if (ppaction && *ppaction) {
            **ppaction = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}

int __get_acl_rights_inner(PEXPLICIT_ACCESS paccess, int accnum, int idx, char** ppright, int *prightsize)
{
    int ret = 0;
    int retlen = 0;
    PEXPLICIT_ACCESS pcuracc;
    if (paccess == NULL) {
        return snprintf_safe(ppright, prightsize, NULL);
    }

    if (accnum <= idx) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }
    pcuracc = &(paccess[idx]);
    if ((pcuracc->grfAccessPermissions & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL) {
        __INNER_SNPRINTF_SAFE(ppright, prightsize, "%s", ACL_RIGHT_ALL);
    } else {
        if (pcuracc->grfAccessPermissions & READ_CONTROL) {
            __INNER_SNPRINTF_SAFE(ppright, prightsize, "%s", ACL_RIGHT_READ_CONTROL);
        }
        if (pcuracc->grfAccessPermissions & WRITE_OWNER) {
            __INNER_SNPRINTF_SAFE(ppright, prightsize, "%s", ACL_RIGHT_WRITE_OWNER);
        }
        if (pcuracc->grfAccessPermissions & WRITE_DAC) {
            __INNER_SNPRINTF_SAFE(ppright, prightsize, "%s", ACL_RIGHT_WRITE_DAC);
        }
        if (pcuracc->grfAccessPermissions & DELETE) {
            __INNER_SNPRINTF_SAFE(ppright, prightsize, "%s", ACL_RIGHT_DELETE);
        }
        if (pcuracc->grfAccessPermissions & SYNCHRONIZE) {
            __INNER_SNPRINTF_SAFE(ppright, prightsize, "%s", ACL_RIGHT_SYNCHRONIZE);
        }
    }
    if (retlen == 0) {
        if (ppright && *ppright) {
            **ppright = '\0';
        }
    }
    return retlen;
fail:
    SETERRNO(ret);
    return ret;
}

int get_sacl_right(void* pacl1, int idx, char** ppright, int* prightsize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PACL sacl = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __handle_acl_idx_callback(NULL, idx, ppright, prightsize, __get_acl_rights_inner);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_saclsdp == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __get_sacl_from_descriptor(pacl->m_saclsdp, &sacl);
    if (ret == 0 || sacl == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __handle_acl_idx_callback(sacl, idx, ppright, prightsize, __get_acl_rights_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    if (retlen == 0) {
        if (ppright && *ppright) {
            **ppright = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}

int get_dacl_right(void* pacl1, int idx, char** ppright, int* prightsize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PACL dacl = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __handle_acl_idx_callback(NULL, idx, ppright, prightsize, __get_acl_rights_inner);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_daclsdp == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __get_dacl_from_descriptor(pacl->m_daclsdp, &dacl);
    if (ret == 0 || dacl == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __handle_acl_idx_callback(dacl, idx, ppright, prightsize, __get_acl_rights_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    if (retlen == 0) {
        if (ppright && *ppright) {
            **ppright = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}

int __get_acl_inheritance_inner(PEXPLICIT_ACCESS paccess, int accnum, int idx, char** ppinheritance, int *pinheritancesize)
{
    int ret = 0;
    int retlen = 0;
    PEXPLICIT_ACCESS pcuracc;
    if (paccess == NULL) {
        return snprintf_safe(ppinheritance, pinheritancesize, NULL);
    }

    if (accnum <= idx) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }
    pcuracc = &(paccess[idx]);
    if ((pcuracc->grfInheritance & CONTAINER_INHERIT_ACE) == CONTAINER_INHERIT_ACE) {
    	__INNER_SNPRINTF_SAFE(ppinheritance,pinheritancesize,"%s",ACL_INHERITANCE_CONTAINER_INHERIT_ACE);
    }

    if ((pcuracc->grfInheritance & INHERIT_NO_PROPAGATE) == INHERIT_NO_PROPAGATE) {
    	__INNER_SNPRINTF_SAFE(ppinheritance,pinheritancesize,"%s",ACL_INHERITANCE_INHERIT_NO_PROPAGATE);
    }

    if ((pcuracc->grfInheritance & INHERIT_ONLY) == INHERIT_ONLY) {
    	__INNER_SNPRINTF_SAFE(ppinheritance,pinheritancesize,"%s",ACL_INHERITANCE_INHERIT_ONLY);
    }

    if ((pcuracc->grfInheritance & NO_INHERITANCE) == NO_INHERITANCE) {
    	__INNER_SNPRINTF_SAFE(ppinheritance,pinheritancesize,"%s",ACL_INHERITANCE_NO_INHERITANCE);
    }

    if ((pcuracc->grfInheritance & OBJECT_INHERIT_ACE) == OBJECT_INHERIT_ACE) {
    	__INNER_SNPRINTF_SAFE(ppinheritance,pinheritancesize,"%s",ACL_INHERITANCE_OBJECT_INHERIT_ACE);
    }

    if ((pcuracc->grfInheritance & SUB_CONTAINERS_AND_OBJECTS_INHERIT) == SUB_CONTAINERS_AND_OBJECTS_INHERIT) {
    	__INNER_SNPRINTF_SAFE(ppinheritance,pinheritancesize,"%s",ACL_INHERITANCE_SUB_CONTAINERS_AND_OBJECTS_INHERIT);
    }

    if (retlen == 0) {
        if (ppinheritance && *ppinheritance) {
            **ppinheritance = '\0';
        }
    }
    return retlen;
fail:
    SETERRNO(ret);
    return ret;
}


int get_sacl_inheritance(void* pacl1,int idx, char** ppinheritance,int *pinheritancesize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PACL sacl = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __handle_acl_idx_callback(NULL, idx, ppinheritance, pinheritancesize, __get_acl_inheritance_inner);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_saclsdp == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __get_sacl_from_descriptor(pacl->m_saclsdp, &sacl);
    if (ret == 0 || sacl == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __handle_acl_idx_callback(sacl, idx, ppinheritance, pinheritancesize, __get_acl_inheritance_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    if (retlen == 0) {
        if (ppinheritance && *ppinheritance) {
            **ppinheritance = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}

int get_dacl_inheritance(void* pacl1,int idx, char** ppinheritance,int *pinheritancesize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PACL dacl = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __handle_acl_idx_callback(NULL, idx, ppinheritance, pinheritancesize, __get_acl_inheritance_inner);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    if (pacl->m_daclsdp == NULL) {
        ret = -NO_ITEMS_MORE;
        goto fail;
    }

    ret = __get_dacl_from_descriptor(pacl->m_daclsdp, &dacl);
    if (ret == 0 || dacl == NULL) {
        ret = - NO_ITEMS_MORE;
        goto fail;
    }

    ret = __handle_acl_idx_callback(dacl, idx, ppinheritance, pinheritancesize, __get_acl_inheritance_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    if (retlen == 0) {
        if (ppinheritance && *ppinheritance) {
            **ppinheritance = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}


int __get_owner_sid(pwin_acl_t pacl, PSID* ppsid)
{
    BOOL bret;
    int ret;
    BOOL bdefault = FALSE;

    bret = GetSecurityDescriptorOwner(pacl->m_ownersdp, ppsid, &bdefault);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("get owner error[%d]", ret);
        goto fail;
    }

    return 1;
fail:
    SETERRNO(ret);
    return ret;
}

int __get_group_sid(pwin_acl_t pacl, PSID* ppsid)
{
    BOOL bret;
    int ret;
    BOOL bdefault = FALSE;

    bret = GetSecurityDescriptorGroup(pacl->m_ownersdp, ppsid, &bdefault);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("get group error[%d]", ret);
        goto fail;
    }

    return 1;
fail:
    SETERRNO(ret);
    return ret;
}



int get_file_owner(void* pacl1, char** ppusername, int *pusersize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PSID ownersid = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __get_sid_name(NULL, ppusername, pusersize);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret = __get_owner_sid(pacl, &ownersid);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    } else if (ret == 0) {
        retlen = 0;
        goto succ;
    }

    ret = __get_sid_name(ownersid, ppusername, pusersize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
succ:
    if (retlen == 0) {
        if (ppusername && *ppusername) {
            **ppusername = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}

int get_file_group(void* pacl1, char** ppgrpname, int *pgrpsize)
{
    int ret;
    pwin_acl_t pacl = NULL;
    int retlen = 0;
    PSID groupsid = NULL;
    pacl = (pwin_acl_t) pacl1;
    if (pacl == NULL) {
        return __get_sid_name(NULL, ppgrpname, pgrpsize);
    }

    if (!IS_WIN_ACL_MAGIC(pacl) ) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    ret = __get_group_sid(pacl, &groupsid);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    } else if (ret == 0) {
        retlen = 0;
        goto succ;
    }

    ret = __get_sid_name(groupsid, ppgrpname, pgrpsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
succ:
    if (retlen == 0) {
        if (ppgrpname && *ppgrpname) {
            **ppgrpname = '\0';
        }
    }
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}


int __get_sid_from_name(const char* name, PSID* ppsid, int *psidsize)
{
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    int ret;
    int retlen = 0;
    int sidsize = 0;
    DWORD sidlen = 0;
    PSID psid = NULL;
    TCHAR* ptdomain = NULL;
    int tdomainsize = 0;
    DWORD tdomainlen = 0;
    SID_NAME_USE buse;
    BOOL bret;
    if (name == NULL) {
        if (ppsid && *ppsid) {
            LocalFree(*ppsid);
            *ppsid = NULL;
        }
        if (psidsize) {
            *psidsize = 0;
        }
        return 0;
    }
    if (ppsid == NULL || psidsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    psid = *ppsid;
    sidsize = *psidsize;

    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (psid == NULL || sidsize < MIN_SID_SIZE) {
        if (sidsize < MIN_SID_SIZE) {
            sidsize = MIN_SID_SIZE;
        }
        psid = LocalAlloc(LMEM_FIXED, sidsize);
        if (psid == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", sidsize, ret);
            goto fail;
        }
    }

try_again:
    sidlen = sidsize;
    tdomainlen = tdomainsize;
    buse = SidTypeUnknown;
    bret = LookupAccountName(NULL, ptname, psid, &sidlen, ptdomain, &tdomainlen, &buse);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            sidsize = sidlen << 1;
            tdomainsize = tdomainlen << 1;
            if (psid && psid != *ppsid) {
                LocalFree(psid);
            }
            psid = NULL;
            psid = LocalAlloc(LMEM_FIXED, sidsize);
            if (psid == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", sidsize, ret);
                goto fail;
            }
            if (ptdomain) {
                LocalFree(ptdomain);
            }
            ptdomain = NULL;
            ptdomain = (TCHAR*)LocalAlloc(LMEM_FIXED, tdomainsize);
            if (ptdomain == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", tdomainsize, ret);
                goto fail;
            }
            goto try_again;
        }
        ERROR_INFO("lookup account for [%s] error[%d]", name, ret);
        goto fail;
    }
    retlen = sidlen;

    if (ptdomain) {
        LocalFree(ptdomain);
    }
    ptdomain = NULL;
    tdomainsize = 0;
    tdomainlen = 0;
    if (*ppsid && *ppsid != psid) {
        LocalFree(*ppsid);
    }
    *ppsid = psid;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    return retlen;
fail:
    if (ptdomain) {
        LocalFree(ptdomain);
    }
    ptdomain = NULL;
    tdomainsize = 0;
    tdomainlen = 0;
    if (psid && psid != *ppsid) {
        LocalFree(psid);
    }
    psid = NULL;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return ret;
}


int __new_sid_descriptor(PSID psid, int mode , PSECURITY_DESCRIPTOR *ppsdp, int *psize)
{
    DWORD dplen = 0;
    int ret;
    int retlen;
    DWORD dret;
    PSECURITY_DESCRIPTOR pdp = NULL;
    PTRUSTEE_A  ptrustee = NULL;
    int trusteesize = 0;

    if (psid == NULL) {
        if (ppsdp && *ppsdp) {
            LocalFree(*ppsdp);
            *ppsdp = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }
    if (ppsdp == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (*ppsdp != NULL || *psize != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    ptrustee = __alloc_trustee();
    if (ptrustee == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*ptrustee), ret);
        goto fail;
    }
    BuildTrusteeWithSid(ptrustee, psid);

    dplen = 0;
    if (mode == SID_GROUP_MODE) {
        dret = BuildSecurityDescriptor(NULL, ptrustee, 0, NULL, 0, NULL, NULL, &dplen, &pdp);
    } else if (mode == SID_OWNER_MODE) {
        dret = BuildSecurityDescriptor(ptrustee, NULL, 0, NULL, 0, NULL, NULL, &dplen, &pdp);
    } else {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("mode [%d:0x%x] not valid", mode, mode);
        ptrustee->ptstrName = NULL;
        goto fail;
    }
    /*not double free*/
    ptrustee->ptstrName = NULL;
    if (dret != ERROR_SUCCESS) {
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO("build [%s] error[%d]", mode == SID_OWNER_MODE ? "owner" : "group", ret);
        goto fail;
    }

    *ppsdp = pdp;
    *psize = dplen;
    retlen = dplen;

    __free_trustee(&ptrustee);
    return retlen;
fail:
    if (pdp) {
        LocalFree(pdp);
    }
    pdp = NULL;
    __free_trustee(&ptrustee);
    SETERRNO(ret);
    return ret;
}

int __set_current_user_owner(char* name, PSECURITY_DESCRIPTOR *ppodp)
{
	BOOL bret;
	DWORD dret;
    int ret;
    int retval = 0;
    char* curuser = NULL;
    int usersize = 0;
    PSID pcursid = NULL;
    int sidsize = 0;
    PSECURITY_DESCRIPTOR pownerdp = NULL;
    PSECURITY_DESCRIPTOR pnewownerdp = NULL;
    DWORD ownersize = 0, ownerlen = 0, newdpsize = 0;
    PSID posid = NULL;
    BOOL bdefault = FALSE;
    PTRUSTEE pnewtrustee = NULL;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    if (name == NULL || ppodp == NULL || *ppodp != NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    ret = AnsiToTchar(name, &ptname,&tnamesize);
    if (ret < 0) {
    	GETERRNO(ret);
    	goto fail;
    }

    ret = get_current_user(0, &curuser, &usersize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    ret = __get_sid_from_name(curuser, &pcursid, &sidsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ownersize = 32;
get_owner_again:
    if (pownerdp) {
        LocalFree(pownerdp);
        pownerdp = NULL;
    }
    pownerdp = (PSECURITY_DESCRIPTOR) LocalAlloc(LMEM_FIXED, ownersize);
    if (pownerdp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", ownersize, ret);
        goto fail;
    }
    /*now to get the owner */
    ownerlen = ownersize;
    bret = GetFileSecurity(ptname, OWNER_SECURITY_INFORMATION, pownerdp, ownersize, &ownerlen);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            ownersize = ownerlen << 1;
            goto get_owner_again;
        }
        ERROR_INFO("get owner error[%d]" , ret);
        goto fail;
    }

    bdefault = FALSE;
    bret = GetSecurityDescriptorOwner(pownerdp, &posid, &bdefault);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not get sid [%d]", ret);
        goto fail;
    }

    if (posid == NULL || !EqualSid(posid, pcursid)) {
        /*this is not the same , so we should set the */
        pnewtrustee = __alloc_trustee();
        if (pnewtrustee == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        pnewtrustee->ptstrName = (decltype(pnewtrustee->ptstrName)(pcursid));
        /*do not double free pcursid */
        pcursid = NULL;
        dret = BuildSecurityDescriptor(pnewtrustee, NULL, 0, NULL, 0, NULL, NULL, &newdpsize, &pnewownerdp);
        if (dret != ERROR_SUCCESS) {
            ret = dret;
            if (ret > 0) {
                ret = -ret;
            }
            if (ret == 0) {
                ret = -1;
            }
            ERROR_INFO("build new user error[%d]", ret);
            goto fail;
        }
        /*not double free */
        pnewtrustee->ptstrName = NULL;

        /*now first to set for the security*/
        bret = SetFileSecurity(ptname, OWNER_SECURITY_INFORMATION, pnewownerdp);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("renew new owner [%s] error[%d]", curuser, ret);
            goto fail;
        }

        if (ppodp) {
        	/*we replace to upper caller*/
        	*ppodp = pownerdp;
        	pownerdp = NULL;
        }
        retval = 1;
    }

    if (pnewownerdp){
    	LocalFree(pnewownerdp);
    }
    pnewownerdp = NULL;
    __free_trustee(&pnewtrustee);
    if (pownerdp) {
        LocalFree(pownerdp);
        pownerdp = NULL;
    }
    __get_sid_from_name(NULL, &pcursid, &sidsize);
    get_current_user(1, &curuser, &usersize);
    AnsiToTchar(NULL,&ptname,&tnamesize);
    return retval;
fail:
    if (pnewownerdp){
    	LocalFree(pnewownerdp);
    }
    pnewownerdp = NULL;
    __free_trustee(&pnewtrustee);
    if (pownerdp) {
        LocalFree(pownerdp);
        pownerdp = NULL;
    }
	__get_sid_from_name(NULL, &pcursid, &sidsize);
	get_current_user(1, &curuser, &usersize);
	AnsiToTchar(NULL,&ptname,&tnamesize);
    SETERRNO(ret);
    return ret;
}

int __restore_old_owner(char* name, PSECURITY_DESCRIPTOR pdp)
{
	int ret;
	TCHAR* ptname=NULL;
	int tnamesize=0;
	BOOL bret;

	ret = AnsiToTchar(name,&ptname,&tnamesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	bret = SetFileSecurity(ptname,OWNER_SECURITY_INFORMATION,pdp);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("restore [%s] owner error[%d]", name ,ret);
		goto fail;
	}

	AnsiToTchar(NULL,&ptname,&tnamesize);
	return 0;
fail:
	AnsiToTchar(NULL,&ptname,&tnamesize);
	SETERRNO(ret);
	return ret;
}

int __set_file_descriptor(char* name, SECURITY_INFORMATION  info, PSECURITY_DESCRIPTOR pdp)
{
    BOOL bret;
    int ret;
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    int enbltakeown = 0;
    int enblrestore = 0;
    const char* infostr = NULL;
    int chguser = 0;
    PSECURITY_DESCRIPTOR pownerdp=NULL;

    ret = AnsiToTchar(name, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }


    if (info == OWNER_SECURITY_INFORMATION) {
        infostr = "owner";
    } else if (info == GROUP_SECURITY_INFORMATION) {
        infostr = "group";
    } else if (info == SACL_SECURITY_INFORMATION) {
        infostr = "sacl";
    } else if (info == DACL_SECURITY_INFORMATION) {
        infostr = "dacl";
    } else {
        infostr = "unknown";
    }

    ret = enable_takeown_priv();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    enbltakeown = 1;

    ret = enable_restore_priv();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    enblrestore = 1;


    if (info == DACL_SECURITY_INFORMATION) {
        /*because the DACL will need the current owner ,so we should change the user to current*/
        ret = __set_current_user_owner(name, &pownerdp);
        if (ret < 0) {
        	GETERRNO(ret);
        	goto fail;
        }
        chguser = ret;
    }



    bret = SetFileSecurity(ptname, info, pdp);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("set [%s] [%s][%d] error[%d]", name, infostr, info, ret);
        goto fail;
    }

    if (chguser) {
    	ret = __restore_old_owner(name, pownerdp);
    	if (ret < 0) {
    		GETERRNO(ret);
    		goto fail;
    	}
    	chguser = 0;
    }

    if (enblrestore) {
        ret = disable_restore_priv();
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }
    enblrestore = 0;

    if (enbltakeown) {
        ret = disable_takeown_priv();
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }
    enbltakeown = 0;

    if (pownerdp) {
        LocalFree(pownerdp);
    }
    pownerdp = NULL;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    if (chguser) {
    	__restore_old_owner(name,pownerdp);
    	chguser = 0;
    }

    if (enblrestore) {
        disable_restore_priv();
    }
    enblrestore = 0;

    if (enbltakeown) {
        disable_takeown_priv();
    }
    enbltakeown = 0;


    if (pownerdp) {
        LocalFree(pownerdp);
    }
    pownerdp = NULL;
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return ret;
}


int set_file_owner(const char* fname, const char* username)
{
    int ret = 0;
    int sidsize = 0;
    PSID psid = NULL;
    int dpsize = 0;
    int dplen = 0;
    PSECURITY_DESCRIPTOR pdp = NULL;
    ret = __get_sid_from_name(username, &psid, &sidsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    DEBUG_BUFFER_FMT(psid, ret, "sid for [%s]", username);
    ret = __new_sid_descriptor(psid, SID_OWNER_MODE, &pdp, &dpsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    dplen = ret;
    DEBUG_BUFFER_FMT(pdp, dplen, "dp with sid");
    /*psid is LocalFree in __new_sid_descriptor*/
    psid = NULL;
    sidsize = 0;


    ret = __set_file_descriptor((char*)fname, OWNER_SECURITY_INFORMATION, pdp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }



    __new_sid_descriptor(NULL, SID_OWNER_MODE, &pdp, &dpsize);
    __get_sid_from_name(NULL, &psid, &sidsize);
    return 0;
fail:
    __new_sid_descriptor(NULL, SID_OWNER_MODE, &pdp, &dpsize);
    __get_sid_from_name(NULL, &psid, &sidsize);
    SETERRNO(ret);
    return ret;
}

int set_file_acls(const char* fname, void* pacl1)
{
    fname = fname;
    pacl1 = pacl1;
    return 0;
}

int get_name_sid(const char* name, char** ppsid, int *psize)
{
    PSID psid = NULL;
    int sidsize = 0;
    TCHAR* ptsid = NULL;
    int ret;
    BOOL bret;
    int retlen = 0;

    if (name == NULL) {
        return TcharToAnsi(NULL, ppsid, psize);
    }

    ret = __get_sid_from_name(name, &psid, &sidsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = ConvertSidToStringSid(psid, &ptsid);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("convert sid string error[%d]", ret);
        goto fail;
    }

    ret = TcharToAnsi(ptsid, ppsid, psize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;

    if (ptsid) {
        LocalFree(ptsid);
    }
    ptsid = NULL;
    __get_sid_from_name(NULL, &psid, &sidsize);

    if (retlen == 0) {
        if (ppsid && *ppsid) {
            **ppsid = '\0';
        }
    }
    return retlen;
fail:
    if (ptsid) {
        LocalFree(ptsid);
    }
    ptsid = NULL;
    __get_sid_from_name(NULL, &psid, &sidsize);
    SETERRNO(ret);
    return ret;
}

int set_file_group(const char* fname, const char* groupname)
{
    int ret = 0;
    int sidsize = 0;
    PSID psid = NULL;
    int dpsize = 0;
    int dplen = 0;
    PSECURITY_DESCRIPTOR pdp = NULL;
    ret = __get_sid_from_name(groupname, &psid, &sidsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    DEBUG_BUFFER_FMT(psid, ret, "sid for [%s]", groupname);
    ret = __new_sid_descriptor(psid, SID_GROUP_MODE, &pdp, &dpsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    dplen = ret;
    DEBUG_BUFFER_FMT(pdp, dplen, "dp with sid");
    /*to make this NULL because we will LocalFree psid when success*/
    psid = NULL;
    sidsize = 0;


    ret = __set_file_descriptor((char*)fname, GROUP_SECURITY_INFORMATION, pdp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    __new_sid_descriptor(NULL, SID_GROUP_MODE, &pdp, &dpsize);
    __get_sid_from_name(NULL, &psid, &sidsize);
    return 0;
fail:
    __new_sid_descriptor(NULL, SID_GROUP_MODE, &pdp, &dpsize);
    __get_sid_from_name(NULL, &psid, &sidsize);
    SETERRNO(ret);
    return ret;
}

int __get_action(const char* action, ACCESS_MODE* pmode)
{
    int ret = 0;
    if (pmode == NULL || action == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }
    if (strcmp(action, ACL_ACTION_NOT_USED) == 0) {
        *pmode = NOT_USED_ACCESS;
    } else if (strcmp(action, ACL_ACTION_GRANT) == 0) {
        *pmode = GRANT_ACCESS;
    } else if (strcmp(action, ACL_ACTION_SET) == 0) {
        *pmode = SET_ACCESS;
    } else if (strcmp(action, ACL_ACTION_DENY) == 0) {
        *pmode = DENY_ACCESS;
    } else if (strcmp(action, ACL_ACTION_REVOKE) == 0) {
        *pmode = REVOKE_ACCESS;
    } else if (strcmp(action, ACL_ACTION_AUDIT_SUCC) == 0) {
        *pmode = SET_AUDIT_SUCCESS;
    } else if (strcmp(action, ACL_ACTION_AUDIT_FAIL) == 0) {
        *pmode = SET_AUDIT_FAILURE;
    } else {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("not valid action [%s]", action);
        goto fail;
    }

    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __get_right(const char* right, ACCESS_MASK *pperm)
{
    int ret = 0;
    char* pptr = (char*)right;
    ACCESS_MASK perm = 0;

    if (right == NULL || pperm == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    while (*pptr != '\0') {
        if (strncmp(pptr, ACL_RIGHT_ALL, strlen(ACL_RIGHT_ALL)) == 0) {
            perm |= STANDARD_RIGHTS_ALL;
            pptr += strlen(ACL_RIGHT_ALL);
        } else if (strncmp(pptr, ACL_RIGHT_DELETE, strlen(ACL_RIGHT_DELETE)) == 0) {
            perm |= DELETE;
            pptr += strlen(ACL_RIGHT_DELETE);
        } else if (strncmp(pptr , ACL_RIGHT_READ_CONTROL, strlen(ACL_RIGHT_READ_CONTROL)) == 0) {
            perm |= READ_CONTROL;
            pptr += strlen(ACL_RIGHT_READ_CONTROL);
        } else if (strncmp(pptr, ACL_RIGHT_WRITE_DAC, strlen(ACL_RIGHT_WRITE_DAC)) == 0) {
            perm |= WRITE_DAC;
            pptr += strlen(ACL_RIGHT_WRITE_DAC);
        } else if (strncmp(pptr, ACL_RIGHT_WRITE_OWNER, strlen(ACL_RIGHT_WRITE_OWNER)) == 0) {
            perm |= WRITE_OWNER;
            pptr += strlen(ACL_RIGHT_WRITE_OWNER);
        } else if (strncmp(pptr, ACL_RIGHT_SYNCHRONIZE, strlen(ACL_RIGHT_SYNCHRONIZE)) == 0) {
            perm |= SYNCHRONIZE;
            pptr += strlen(ACL_RIGHT_SYNCHRONIZE);
        } else {
            ret = -ERROR_INVALID_PARAMETER;
            ERROR_INFO("not valid part [%s]", pptr);
            goto fail;
        }

        if (*pptr != ACL_COMMON_SEP && *pptr != '\0') {
            ret = -ERROR_INVALID_PARAMETER;
            ERROR_INFO("not valid part [%s]", pptr);
            goto fail;
        }

        if (*pptr == ACL_COMMON_SEP) {
            pptr ++ ;
        }
    }

    *pperm = perm;
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

typedef int (*sdp_new_callback_t)(PEXPLICIT_ACCESS paccess, int accnum, PSID psid, ACCESS_MODE mode, ACCESS_MASK perm, void* arg, PSECURITY_DESCRIPTOR* ppsdp, int* psize);

int __handle_sdp_acl(PACL acl, PSID psid,  ACCESS_MODE mode, ACCESS_MASK perm, void* arg, PSECURITY_DESCRIPTOR* ppsdp, int *psize, sdp_new_callback_t callback)
{
    PEXPLICIT_ACCESS paccess = NULL;
    int accsize = 0, accnum = 0;
    int retlen = 0;
    int ret;

    ret = __get_explicit_access(acl, &paccess, &accsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    accnum = ret;

    ret = callback(paccess, accnum, psid, mode, perm, arg, ppsdp, psize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
    __get_explicit_access(NULL, &paccess, &accsize);
    return retlen;
fail:
    __get_explicit_access(NULL, &paccess, &accsize);
    accnum = 0;
    SETERRNO(ret);
    return ret;
}


int __copy_trustee(PTRUSTEE ptrustee, PTRUSTEE pnewtrustee)
{
    PTRUSTEE pmul = NULL;
    PSID posid = NULL;
    PSID pnsid = NULL;
    DWORD nsidsize = 0;
    int ret;
    BOOL bret;
    if (pnewtrustee->pMultipleTrustee) {
        LocalFree(pnewtrustee->pMultipleTrustee);
        pnewtrustee->pMultipleTrustee = NULL;
    }
    if (pnewtrustee->ptstrName != NULL) {
        LocalFree(pnewtrustee->ptstrName);
        pnewtrustee->ptstrName = NULL;
    }

    if (ptrustee->pMultipleTrustee) {
        pmul = __alloc_trustee();
        if (pmul == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        ret = __copy_trustee(ptrustee->pMultipleTrustee, pmul);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        pnewtrustee->pMultipleTrustee = pmul;
        pmul = NULL;
    }

    pnewtrustee->TrusteeType = ptrustee->TrusteeType;
    pnewtrustee->TrusteeForm = ptrustee->TrusteeForm;
    pnewtrustee->MultipleTrusteeOperation = ptrustee->MultipleTrusteeOperation;

    if (ptrustee->TrusteeType == TRUSTEE_IS_SID &&
            ptrustee->ptstrName != NULL) {
        posid = (PSID) ptrustee->ptstrName;
        nsidsize = MIN_SID_SIZE;
try_again:
        if (pnsid) {
            LocalFree(pnsid);
            pnsid = NULL;
        }
        pnsid = LocalAlloc(LMEM_FIXED, nsidsize);
        if (pnsid == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", nsidsize, ret);
            goto fail;
        }

        bret = CopySid(nsidsize, pnsid, posid);
        if (!bret) {
            GETERRNO(ret);
            if (ret == -ERROR_INSUFFICIENT_BUFFER) {
                nsidsize <<= 1;
                goto try_again;
            }
            ERROR_INFO("copy sid error[%d]", ret);
            goto fail;
        }
        pnewtrustee->ptstrName = (decltype(pnewtrustee->ptstrName)(pnsid));
        /*not free again*/
        pnsid = NULL;
    }


    return 0;
fail:
    if (pnsid) {
        LocalFree(pnsid);
    }
    pnsid = NULL;
    __free_trustee(&pmul);
    SETERRNO(ret);
    return ret;
}

int __init_explicit_access(PEXPLICIT_ACCESS pacc)
{
    memset(pacc, 0 , sizeof(*pacc));
    pacc->grfAccessPermissions = 0;
    pacc->grfAccessMode = NOT_USED_ACCESS;
    pacc->grfInheritance = NO_INHERITANCE;
    return __init_trustee(&(pacc->Trustee));
}

void __release_explicit_access(PEXPLICIT_ACCESS pacc)
{
    if (pacc) {
        __release_trustee(&(pacc->Trustee));
    }
    return;
}

void __free_explicit_access(PEXPLICIT_ACCESS *ppacc)
{
    if (ppacc && *ppacc) {
        PEXPLICIT_ACCESS pacc = *ppacc;
        __release_explicit_access(pacc);
        LocalFree(pacc);
        *ppacc = NULL;
    }
    return;
}

void __free_explicit_access_array(PEXPLICIT_ACCESS *ppacc, int *psize)
{
    if (ppacc && *ppacc && psize ) {
        int i;
        PEXPLICIT_ACCESS pacc = NULL;
        int size = *psize;
        pacc = *ppacc;
        for (i = 0; i < size; i++) {
            __release_explicit_access(&(pacc[i]));
        }
        LocalFree(pacc);
    }
    if (ppacc) {
        *ppacc = NULL;
    }
    if (psize) {
        *psize = 0;
    }
    return;
}

int __copy_explicit_access(PEXPLICIT_ACCESS paccess, PEXPLICIT_ACCESS pnewacc)
{
    int ret;
    pnewacc->grfAccessPermissions = paccess->grfAccessPermissions;
    pnewacc->grfAccessMode = paccess->grfAccessMode;
    pnewacc->grfInheritance = paccess->grfInheritance;
    ret = __copy_trustee(&(paccess->Trustee), &(pnewacc->Trustee));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}

int __copy_explicit_access_array(PEXPLICIT_ACCESS poaccess, int onum , PEXPLICIT_ACCESS *ppnacc, int *pnnum)
{
    PEXPLICIT_ACCESS pnewacc = NULL;
    int newaccsize = 0;
    int newaccnum = 0;
    int ret;
    int i;
    if (poaccess == NULL) {
        __free_explicit_access_array(ppnacc, pnnum);
        return 0;
    }
    if (ppnacc == NULL || pnnum == NULL ||
            *ppnacc != NULL || *pnnum != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    newaccsize = onum;
    pnewacc = (PEXPLICIT_ACCESS)LocalAlloc(LMEM_FIXED, sizeof(*pnewacc) * newaccsize);
    if (pnewacc == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", sizeof(*pnewacc)*newaccsize, ret);
        goto fail;
    }

    memset(pnewacc, 0, sizeof(*pnewacc)*newaccsize);
    for (i = 0; i < newaccsize; i++) {
        ret = __init_explicit_access(&(pnewacc[i]));
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    for (i = 0; i < onum; i++) {
        if ((poaccess[i].grfAccessPermissions & STANDARD_RIGHTS_ALL) == 0) {
            continue;
        }
        ASSERT_IF(newaccnum < newaccsize);
        ret = __copy_explicit_access(&(poaccess[i]), &(pnewacc[newaccnum]));
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        newaccnum ++;
    }

    *ppnacc = pnewacc;
    *pnnum = newaccsize;

    return newaccnum;
fail:
    __free_explicit_access_array(&pnewacc, &newaccsize);
    SETERRNO(ret);
    return ret;
}


int __remove_acl_inner(PEXPLICIT_ACCESS paccess, int accnum, PSID psid, ACCESS_MODE mode, ACCESS_MASK perm, void* arg, PSECURITY_DESCRIPTOR *ppsdp, int *psize)
{
    DWORD ctrl = (DWORD)((addr_t)arg);
    int i;
    PEXPLICIT_ACCESS pcuracc = NULL, pfoundacc = NULL;
    PSID osid = NULL;
    int ret = 0;
    int retlen = 0;
    PEXPLICIT_ACCESS pnewacc = NULL;
    int newaccsize = 0, newaccnum = 0;
    DWORD dplen = 0;
    PSECURITY_DESCRIPTOR pdp = NULL;
    DWORD dret;

    if (paccess == NULL && accnum != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (ppsdp == NULL || psize == NULL ||
            *ppsdp != NULL || *psize != 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (accnum == 0) {
        goto direct_build;
    }

    for (i = 0; i < accnum; i++) {
        pcuracc = &(paccess[i]);
        if (pcuracc->grfAccessMode == mode &&
                pcuracc->Trustee.TrusteeType == TRUSTEE_IS_SID) {
            osid = (PSID) pcuracc->Trustee.ptstrName;
            if (osid != NULL && EqualSid(osid, psid)) {
                pfoundacc = pcuracc;
                break;
            }
        }
    }

    if (pfoundacc != NULL) {
        /*now we should handle*/
        pfoundacc->grfAccessPermissions &= ~(perm);
    }


    ret = __copy_explicit_access_array(paccess, accnum, &pnewacc, &newaccsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    newaccnum = ret;

direct_build:
    if (ctrl == SACL_MODE) {
        dret = BuildSecurityDescriptor(NULL, NULL, 0, NULL, newaccnum, pnewacc, NULL, &dplen, &pdp);
    } else if (ctrl == DACL_MODE) {
        dret = BuildSecurityDescriptor(NULL, NULL, newaccnum, pnewacc, 0, NULL, NULL, &dplen, &pdp);
    } else {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("ctrl [%d:0x%x] not valid", ctrl, ctrl);
        goto fail;
    }

    if (dret != ERROR_SUCCESS) {
        ret = dret;
        if (ret > 0) {
            ret = -ret;
        }
        if (ret == 0) {
            ret = -1;
        }
        ERROR_INFO("build [%d] access for [%s] error[%d]", newaccnum, ctrl == SACL_MODE ? "SACL" : "DACL", ret);
        goto fail;
    }

    DEBUG_BUFFER_FMT(pdp, dplen, "[%s] SECURITY_DESCRIPTOR", ctrl == SACL_MODE ? "SACL" : "DACL");

    *ppsdp = pdp;
    *psize = dplen;
    retlen = dplen;
    __copy_explicit_access_array(NULL, 0, &pnewacc, &newaccnum);
    return retlen;
fail:
    if (pdp) {
        LocalFree(pdp);
    }
    pdp = NULL;
    dplen = 0;
    __copy_explicit_access_array(NULL, 0, &pnewacc, &newaccnum);
    SETERRNO(ret);
    return ret;
}

int remove_sacl(void* pacl1, const char* username, const char* action, const char* right)
{
    pwin_acl_t pacl = (pwin_acl_t) pacl1;
    PACL sacl = NULL;
    int ret;
    PSID psid = NULL;
    int sidsize = 0;
    ACCESS_MODE mode = NOT_USED_ACCESS;
    ACCESS_MASK perm = 0;
    PSECURITY_DESCRIPTOR pdp = NULL;
    int dpsize = 0, dplen = 0;


    if (pacl == NULL || username == NULL || action == NULL || right == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pacl->m_saclsdp == NULL) {
        ret = -ERROR_NOT_FOUND;
        goto fail;
    }

    ret = __get_sid_from_name(username, &psid, &sidsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __get_action(action, &mode);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __get_right(right, &perm);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __get_sacl_from_descriptor(pacl->m_saclsdp, &sacl);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __handle_sdp_acl(sacl, psid, mode, perm, (void*)SACL_MODE, &pdp, &dpsize, __remove_acl_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    dplen = ret;

    ret = __set_file_descriptor(pacl->m_fname, SACL_SECURITY_INFORMATION, pdp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (pacl->m_saclsdp) {
        LocalFree(pacl->m_saclsdp);
        pacl->m_saclsdp = NULL;
    }
    pacl->m_saclsdp = pdp;
    pdp = NULL;
    pacl->m_saclsize = dpsize;
    pacl->m_sacllen = dplen;


    if (pdp) {
        LocalFree(pdp);
    }
    pdp = NULL;
    dpsize = 0;
    dplen = 0;
    __get_sid_from_name(NULL, &psid, &sidsize);
    return 0;
fail:
    if (pdp) {
        LocalFree(pdp);
    }
    pdp = NULL;
    dpsize = 0;
    dplen = 0;
    __get_sid_from_name(NULL, &psid, &sidsize);
    SETERRNO(ret);
    return ret;
}

int remove_dacl(void* pacl1, const char* username, const char* action, const char* right)
{
    pwin_acl_t pacl = (pwin_acl_t) pacl1;
    PACL dacl = NULL;
    int ret;
    PSID psid = NULL;
    int sidsize = 0;
    ACCESS_MODE mode = NOT_USED_ACCESS;
    ACCESS_MASK perm = 0;
    PSECURITY_DESCRIPTOR pdp = NULL;
    int dpsize = 0, dplen = 0;


    if (pacl == NULL || username == NULL || action == NULL || right == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pacl->m_daclsdp == NULL) {
        ret = -ERROR_NOT_FOUND;
        goto fail;
    }

    ret = __get_sid_from_name(username, &psid, &sidsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __get_action(action, &mode);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __get_right(right, &perm);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __get_dacl_from_descriptor(pacl->m_daclsdp, &dacl);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = __handle_sdp_acl(dacl, psid, mode, perm, (void*)DACL_MODE, &pdp, &dpsize, __remove_acl_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    dplen = ret;

    ret = __set_file_descriptor(pacl->m_fname, DACL_SECURITY_INFORMATION, pdp);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (pacl->m_daclsdp) {
        LocalFree(pacl->m_daclsdp);
        pacl->m_daclsdp = NULL;
    }
    pacl->m_daclsdp = pdp;
    pdp = NULL;
    pacl->m_daclsize = dpsize;
    pacl->m_dacllen = dplen;


    if (pdp) {
        LocalFree(pdp);
    }
    pdp = NULL;
    dpsize = 0;
    dplen = 0;
    __get_sid_from_name(NULL, &psid, &sidsize);
    return 0;
fail:
    if (pdp) {
        LocalFree(pdp);
    }
    pdp = NULL;
    dpsize = 0;
    dplen = 0;
    __get_sid_from_name(NULL, &psid, &sidsize);
    SETERRNO(ret);
    return ret;
}