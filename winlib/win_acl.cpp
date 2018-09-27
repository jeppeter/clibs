#include <win_acl.h>
#include <win_err.h>
#include <win_types.h>
#include <win_uniansi.h>
#include <win_priv.h>
#include <win_strop.h>

#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>


#define   WIN_ACL_MAGIC            0x3021211

#define   SET_WIN_ACL_MAGIC(pacl)  do{if ((pacl) != NULL) { (pacl)->m_magic = WIN_ACL_MAGIC;}} while(0)
#define   IS_WIN_ACL_MAGIC(pacl)  ((pacl) == NULL || ((pacl)->m_magic == WIN_ACL_MAGIC))

typedef struct __win_acl {
    uint32_t  m_magic;
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
        DEBUG_INFO("enabled security priviledge");
    } else {
    	DEBUG_INFO("not enable security priviledge");
    }

try_owner_sec:
    if (pacl->m_ownersdp) {
        LocalFree(pacl->m_ownersdp);
        pacl->m_ownersdp = NULL;
    }
    if (pacl->m_ownersize < 10) {
    	pacl->m_ownersize = 10;
    }
    pacl->m_ownersdp = LocalAlloc(LMEM_FIXED,pacl->m_ownersize);
    if (pacl->m_ownersdp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", pacl->m_ownersize, ret);
        goto fail;
    }
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
    DEBUG_INFO("get owner [%p] size[%d] len[%d]", pacl->m_ownersdp, pacl->m_ownersize, pacl->m_ownerlen);

try_grp_sec:
	if (pacl->m_groupsdp) {
		LocalFree(pacl->m_groupsdp);
		pacl->m_groupsdp = NULL;
	}
	if (pacl->m_grpsize < 10) {
		pacl->m_grpsize = 10;
	}
	pacl->m_groupsdp = LocalAlloc(LMEM_FIXED,pacl->m_grpsize);
	if (pacl->m_groupsdp == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc %d error[%d]", pacl->m_grpsize, ret);
		goto fail;
	}
	bret = GetFileSecurity(ptname, GROUP_SECURITY_INFORMATION,pacl->m_groupsdp, pacl->m_grpsize, &(pacl->m_grplen));
	if (!bret) {
		GETERRNO(ret);
		if (ret == -ERROR_INSUFFICIENT_BUFFER) {
			pacl->m_grpsize = pacl->m_grplen << 1;
			goto try_grp_sec;
		}
		ERROR_INFO("get[%s] group error[%d]", fname, ret);
		goto fail;
	}
	DEBUG_INFO("get group [%p] size[%d] len[%d]", pacl->m_groupsdp, pacl->m_grpsize, pacl->m_grplen);

try_sacl_sec:
	if (pacl->m_saclsdp) {
		LocalFree(pacl->m_saclsdp);
		pacl->m_saclsdp = NULL;
	}
	if (pacl->m_saclsize < 10) {
		pacl->m_saclsize = 10;
	}
	pacl->m_saclsdp = LocalAlloc(LMEM_FIXED,pacl->m_saclsize);
	if (pacl->m_saclsdp == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc %d error[%d]", pacl->m_saclsize, ret);
		goto fail;
	}
	bret = GetFileSecurity(ptname,SACL_SECURITY_INFORMATION,pacl->m_saclsdp, pacl->m_saclsize, &(pacl->m_sacllen));
	if (!bret) {
		GETERRNO(ret);
		if (ret == -ERROR_INSUFFICIENT_BUFFER) {
			pacl->m_saclsize = pacl->m_sacllen << 1;
			goto try_sacl_sec;
		}
		ERROR_INFO("get[%s] sacl error[%d]", fname, ret);
		goto fail;
	}
	DEBUG_INFO("get sacl [%p] size[%d] len[%d]", pacl->m_saclsdp, pacl->m_saclsize, pacl->m_sacllen);


try_dacl_sec:
	if (pacl->m_daclsdp) {
		LocalFree(pacl->m_daclsdp);
		pacl->m_daclsdp = NULL;
	}
	if (pacl->m_daclsize < 10) {
		pacl->m_daclsize = 10;
	}
	pacl->m_daclsdp = LocalAlloc(LMEM_FIXED,pacl->m_daclsize);
	if (pacl->m_daclsdp == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc %d error[%d]", pacl->m_daclsize, ret);
		goto fail;
	}
	bret = GetFileSecurity(ptname,DACL_SECURITY_INFORMATION,pacl->m_daclsdp, pacl->m_daclsize, &(pacl->m_dacllen));
	if (!bret) {
		GETERRNO(ret);
		if (ret == -ERROR_INSUFFICIENT_BUFFER) {
			pacl->m_daclsize = pacl->m_dacllen << 1;
			goto try_dacl_sec;
		}
		ERROR_INFO("get[%s] dacl error[%d]", fname, ret);
		goto fail;
	}
	DEBUG_INFO("get dacl [%p] size[%d] len[%d]", pacl->m_daclsdp, pacl->m_daclsize, pacl->m_dacllen);

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

void __debug_access(PEXPLICIT_ACCESS paccess, int accnum)
{
    int i;
    PEXPLICIT_ACCESS pcuracc;
    PSID psid = NULL;
    int ret;
    BOOL bret;
    SID_NAME_USE siduse;
    TCHAR* ptuser = NULL, *ptdomain = NULL;
    DWORD tusersize = 0, tuserlen = 0;
    DWORD tdomainsize = 0, tdomainlen = 0;
    char* pname = NULL, *pdomain = NULL;
    int namesize = 0, domainsize = 0;
    for (i = 0; i < (int)accnum; i++) {
        pcuracc = &(paccess[i]);
        DEBUG_INFO("[%d] grfAccessPermissions [0x%lx]", i, pcuracc->grfAccessPermissions);
        if ((pcuracc->grfAccessPermissions & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL) {
            DEBUG_INFO("[%d] grfAccessPermissions %s", i, ACL_RIGHT_ALL);
        } else {
            if (pcuracc->grfAccessPermissions & DELETE) {
                DEBUG_INFO("[%d] grfAccessPermissions %s", i, ACL_RIGHT_DELETE);
            }
            if (pcuracc->grfAccessPermissions & READ_CONTROL) {
                DEBUG_INFO("[%d] grfAccessPermissions %s", i, ACL_RIGHT_READ_CONTROL);
            }
            if (pcuracc->grfAccessPermissions & WRITE_DAC) {
                DEBUG_INFO("[%d] grfAccessPermissions %s", i, ACL_RIGHT_WRITE_DAC);
            }
            if (pcuracc->grfAccessPermissions & WRITE_OWNER) {
                DEBUG_INFO("[%d] grfAccessPermissions %s", i, ACL_RIGHT_WRITE_OWNER);
            }
            if (pcuracc->grfAccessPermissions & SYNCHRONIZE) {
                DEBUG_INFO("[%d] grfAccessPermissions %s", i, ACL_RIGHT_SYNCHRONIZE);
            }
        }


        switch (pcuracc->grfAccessMode) {
        case NOT_USED_ACCESS:
            DEBUG_INFO("[%d] grfAccessMode %s", i, ACL_ACTION_NOT_USED);
            break;
        case GRANT_ACCESS:
            DEBUG_INFO("[%d] grfAccessMode %s", i, ACL_ACTION_GRANT);
            break;
        case SET_ACCESS:
            DEBUG_INFO("[%d] grfAccessMode %s", i, ACL_ACTION_SET);
            break;
        case DENY_ACCESS:
            DEBUG_INFO("[%d] grfAccessMode %s", i, ACL_ACTION_DENY);
            break;
        case REVOKE_ACCESS:
            DEBUG_INFO("[%d] grfAccessMode %s", i, ACL_ACTION_REVOKE);
            break;
        case SET_AUDIT_SUCCESS:
            DEBUG_INFO("[%d] grfAccessMode %s", i, ACL_ACTION_AUDIT_SUCC);
            break;
        case SET_AUDIT_FAILURE:
            DEBUG_INFO("[%d] grfAccessMode %s", i, ACL_ACTION_AUDIT_FAIL);
            break;
        default:
            DEBUG_INFO("[%d] grfAccessMode [0x%lx]", i, pcuracc->grfAccessMode);
        }
        DEBUG_INFO("[%d] grfInheritance [0x%lx]", i, pcuracc->grfInheritance);
        DEBUG_INFO("[%d] pMultipleTrustee [%p]", i, pcuracc->Trustee.pMultipleTrustee);
        DEBUG_INFO("[%d] MultipleTrusteeOperation [0x%x]", i, pcuracc->Trustee.MultipleTrusteeOperation);
        DEBUG_INFO("[%d] TrusteeForm [0x%x]", i, pcuracc->Trustee.TrusteeForm);
        DEBUG_INFO("[%d] TrusteeType [0x%x]", i, pcuracc->Trustee.TrusteeType);
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

    return;
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
        retlen = 0;
        if (ppstr && *ppstr) {
            *ppstr = '\0';
        }
        goto succ;
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

succ:
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

int __get_sacl_from_descriptor(PSECURITY_DESCRIPTOR psdp,PACL *ppacl)
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
        retlen = 0;
        if (ppuser && *ppuser) {
            *ppuser = '\0';
        }
        goto succ;
    }

    ret = __get_sacl_from_descriptor(pacl->m_saclsdp,&sacl);
    if (ret == 0 || sacl == NULL) {
        retlen = 0;
        if (ppuser && *ppuser) {
            *ppuser = '\0';
        }
        goto succ;
    }

    ret = __handle_acl_idx_callback(sacl, idx, ppuser, pusersize, __get_acl_user_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
succ:
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
        retlen = 0;
        if (ppuser && *ppuser) {
            *ppuser = '\0';
        }
        goto succ;
    }

    ret = __get_dacl_from_descriptor(pacl->m_daclsdp,&dacl);
    if (ret == 0 || dacl == NULL) {
        retlen = 0;
        if (ppuser && *ppuser) {
            *ppuser = '\0';
        }
        goto succ;
    }

    ret = __handle_acl_idx_callback(dacl, idx, ppuser, pusersize, __get_acl_user_inner);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = ret;
succ:
    return retlen;

fail:
    SETERRNO(ret);
    return ret;
}