#pragma warning(disable:4820)
#pragma warning(disable:4668)

#include "set_acl.h"
#include "vssetup.h"
#include <win_output_debug.h>
#include <win_strop.h>
#include <win_priv.h>

#include <aclapi.h>


int get_security_safe(HANDLE hproc, SECURITY_INFORMATION inform, PSECURITY_DESCRIPTOR* ppsec, int*psize)
{
    NTSTATUS status;
    int ret;
    int retlen = 0;
    PSECURITY_DESCRIPTOR pretsec = NULL;
    int retsize = 0;
    ULONG retl = 0;

    if (hproc == NULL) {
        if (ppsec && *ppsec) {
            free(*ppsec);
            *ppsec = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }
    if (ppsec == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretsec = *ppsec;
    retsize = *psize;

try_again:
    status = NtQuerySecurityObjectFake(hproc, inform, pretsec, (ULONG)retsize, &retl);
    if (status != NTSTATUS_SUCCESS) {
        if (status != NTSTATUS_BUFFER_TOO_SMALL) {
            GETERRNO(ret);
            ERROR_INFO("get proc [%p] [0x%x] error[0x%lx][%d]", hproc, inform, status, ret);
            goto fail;
        }

        if (pretsec != NULL && pretsec != *ppsec) {
            free(pretsec);
        }
        pretsec = NULL;
        retsize <<= 1;
        if (retsize == 0) {
            retsize = 32;
        }
        pretsec = (PSECURITY_DESCRIPTOR)malloc((size_t)retsize);
        if (pretsec == NULL) {
            GETERRNO(ret);
            goto fail;
        }
        memset(pretsec, 0, (size_t)retsize);
        goto try_again;
    }

    retlen = (int)retl;

    if (*ppsec && *ppsec != pretsec) {
        free(*ppsec);
    }
    *ppsec = pretsec;
    *psize = retsize;

    return retlen;
fail:
    if (pretsec && pretsec != *ppsec) {
        free(pretsec);
    }
    pretsec = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

int get_security_string(PSECURITY_DESCRIPTOR psec, SECURITY_INFORMATION  inform, char** ppstr, int *psize)
{
    char* pretstr = NULL;
    int retsize = 0;
    int retlen = 0;
    BOOL bret;
    int ret;
    if (psec == NULL) {
        if (ppstr && *ppstr) {
            free(*ppstr);
            *ppstr = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppstr == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    bret = ConvertSecurityDescriptorToStringSecurityDescriptorA(psec, SDDL_REVISION_1,
            inform, &pretstr, (PULONG)&retsize);
    if (!bret) {
        GETERRNO(ret);
        goto fail;
    }
    retlen = retsize;
    if (retsize > 0) {
        if (*psize <= retsize) {
            if (*ppstr) {
                free(*ppstr);
            }
            *ppstr = NULL;
            *psize = retsize + 1;
            *ppstr = (char*)malloc((size_t)(*psize));
            if ((*ppstr) == NULL) {
                GETERRNO(ret);
                goto fail;
            }
        }
        memset(*ppstr, 0 , (size_t)(*psize));
        memcpy(*ppstr, pretstr, (size_t)retsize);
    }

    if (pretstr) {
        LocalFree(pretstr);
    }
    pretstr = NULL;
    return retlen;
fail:
    if (pretstr) {
        LocalFree(pretstr);
    }
    pretstr = NULL;
    SETERRNO(ret);
    return ret;
}


#define OUTPUT_TABS(fp,tabs)                                                                      \
do{                                                                                               \
    int __i;                                                                                      \
    for (__i=0;__i<tabs;__i++) {                                                                  \
        fprintf(fp,"    ");                                                                       \
    }                                                                                             \
}while(0)

char* get_trustee_type(TRUSTEE_TYPE type)
{
    switch (type) {
    case TRUSTEE_IS_UNKNOWN:
        return "unknown";
    case TRUSTEE_IS_USER:
        return "user";
    case TRUSTEE_IS_GROUP:
        return "group";
    case TRUSTEE_IS_DOMAIN:
        return "domain";
    case TRUSTEE_IS_ALIAS:
        return "alias";
    case TRUSTEE_IS_WELL_KNOWN_GROUP:
        return "wellknowngroup";
    case TRUSTEE_IS_DELETED:
        return "deleted";
    case TRUSTEE_IS_INVALID:
        return "invalid";
    case TRUSTEE_IS_COMPUTER:
        return "computer";
    }
    return "not known";
}

void dump_trustee(FILE* fp , PTRUSTEE_A pcur, int tabs)
{
    PTRUSTEE_A pnext = NULL;
    LPSTR pstr = NULL;
    BOOL bret;
    OBJECTS_AND_SID* posid = NULL;
    OBJECTS_AND_NAME_A* pnamea = NULL;
    OUTPUT_TABS(fp, tabs);
    fprintf(fp, "MultipleTrusteeOperation=0x%x[%d]\n", pcur->MultipleTrusteeOperation, pcur->MultipleTrusteeOperation);
    OUTPUT_TABS(fp, tabs);
    fprintf(fp, "TrusteeForm=0x%x[%d]\n", pcur->TrusteeForm, pcur->TrusteeForm);
    OUTPUT_TABS(fp, tabs);
    fprintf(fp, "TrusteeType=0x%x[%d]\n", pcur->TrusteeType, pcur->TrusteeType);
    OUTPUT_TABS(fp, tabs);
    fprintf(fp, "[%s]", get_trustee_type(pcur->TrusteeType));
    if (pcur->TrusteeForm == TRUSTEE_IS_SID) {
        bret = ConvertSidToStringSidA((PSID)pcur->ptstrName, &pstr);
        if (bret) {
            fprintf(fp, "ptstrName=%s\n", pstr);
            LocalFree(pstr);
            pstr = NULL;
        } else {
            fprintf(fp, "ptstrName=notsucc\n");
        }
    } else if (pcur->TrusteeForm == TRUSTEE_IS_NAME) {
        fprintf(fp, "ptstrName=%s\n", pcur->ptstrName);
    } else if (pcur->TrusteeForm == TRUSTEE_BAD_FORM) {
        fprintf(fp, "ptstrName=BadForm\n");
    } else if (pcur->TrusteeForm == TRUSTEE_IS_OBJECTS_AND_SID) {
        posid = (OBJECTS_AND_SID*) pcur->ptstrName;
        bret = ConvertSidToStringSidA(posid->pSid, &pstr);
        if (bret) {
            fprintf(fp, "ptstrName=%s\n", pstr);
            LocalFree(pstr);
            pstr = NULL;
        } else {
            fprintf(fp, "ptstrName=notsucc\n");
        }
    } else if (pcur->TrusteeForm == TRUSTEE_IS_OBJECTS_AND_NAME) {
        pnamea = (OBJECTS_AND_NAME_A*)pcur->ptstrName;
        fprintf(fp, "ptstrName=%s:%s\n", pnamea->ObjectTypeName, pnamea->ptstrName);
    } else {
        fprintf(fp, "ptstrName=%d\n", pcur->TrusteeForm);
    }
    pnext = pcur->pMultipleTrustee;
    if (pnext != NULL) {
        dump_trustee(fp, pnext, tabs + 1);
    } else {
        OUTPUT_TABS(fp, tabs);
        fprintf(fp, "pMultipleTrustee=NULL\n");
    }
    return;
}


typedef struct __access_mask_match {
    char* m_maskstr;
    ACCESS_MASK m_maskval;
    char m_reserve1[4];
} access_mask_match_t, *paccess_mask_match_t;

static access_mask_match_t st_accessmask[] = {
    {"terminate", PROCESS_TERMINATE},
    {"create_thread", PROCESS_CREATE_THREAD},
    {"vm_operation", PROCESS_VM_OPERATION},
    {"vm_read", PROCESS_VM_READ},
    {"vm_write", PROCESS_VM_WRITE},
    {"dup_handle", PROCESS_DUP_HANDLE},
    {"create_process", PROCESS_CREATE_PROCESS},
    {"set_quota", PROCESS_SET_QUOTA},
    {"set_information", PROCESS_SET_INFORMATION},
    {"query_information", PROCESS_QUERY_INFORMATION},
    {"query_limited_information", PROCESS_QUERY_LIMITED_INFORMATION},
    {"synchronize", SYNCHRONIZE},
    {"read_control", READ_CONTROL},
    {"write_dac", WRITE_DAC},
    {"write_owner", WRITE_OWNER},
    {"delete", DELETE},
    {NULL, 0}
};

char* get_access_permissions(ACCESS_MASK mask)
{
    static char* st_permstr = NULL;
    static int st_permsize = 0;
    int ret;
    int i;

    ret = snprintf_safe(&st_permstr, &st_permsize, "");
    for (i = 0; st_accessmask[i].m_maskstr != NULL; i++) {
        if (ret >= 0) {
            if (mask & st_accessmask[i].m_maskval) {
                size_t rlen = strlen(st_permstr);
                if (rlen > 0) {
                    ret = append_snprintf_safe(&st_permstr, &st_permsize, "|%s", st_accessmask[i].m_maskstr);
                } else {
                    ret = append_snprintf_safe(&st_permstr, &st_permsize, "%s", st_accessmask[i].m_maskstr);
                }
            }
        }
    }

    if (st_permstr == NULL) {
        return "error";
    }
    return st_permstr;
}


typedef struct __access_mode_match {
    char* m_modestr;
    ACCESS_MODE m_modeval;
    char m_reserve1[4];
} access_mode_match_t, *paccess_mode_match_t;

static access_mode_match_t st_accessmode[] = {
    {"not_used", NOT_USED_ACCESS},
    {"grant", GRANT_ACCESS},
    {"set", SET_ACCESS},
    {"deny", DENY_ACCESS},
    {"revoke", REVOKE_ACCESS},
    {"audit_succ", SET_AUDIT_SUCCESS},
    {"audit_fail", SET_AUDIT_FAILURE},
    {NULL, NOT_USED_ACCESS}
};

char* get_access_mode(ACCESS_MODE mode)
{
    static char* st_modestr = NULL;
    static int st_modesize = 0;
    int ret;
    int valid = 0;
    int i;

    ret = snprintf_safe(&st_modestr, &st_modesize, "");
    for (i = 0; st_accessmode[i].m_modestr != NULL ; i++) {
        if (st_accessmode[i].m_modeval == mode) {
            ret = append_snprintf_safe(&st_modestr, &st_modesize, "%s", st_accessmode[i].m_modestr);
            if (ret >= 0) {
                valid = 1;
            }
            break;
        }
    }

    if (valid == 0) {
        ret = append_snprintf_safe(&st_modestr, &st_modesize, "unknown mode[0x%lx]", mode);
    }

    if (st_modestr == NULL) {
        return "error mode";
    }

    return st_modestr;
}

typedef struct __access_inherit_match {
    char* m_inheritstr;
    DWORD m_inheritval;
    char m_reserve1[4];
} access_inherit_match_t, *paccess_inherit_match_t;

static access_inherit_match_t st_accessinherit[] = {
    {"container_inherit_ace", CONTAINER_INHERIT_ACE},
    {"inherit_no_propagate", INHERIT_NO_PROPAGATE},
    {"inherit_only", INHERIT_ONLY},
    {"no_inheritance", NO_INHERITANCE},
    {"object_inherit_ace", OBJECT_INHERIT_ACE},
    {"sub_containers_and_objects_inherit", SUB_CONTAINERS_AND_OBJECTS_INHERIT},
    {NULL, NO_INHERITANCE}
};

char* get_access_inherit(DWORD inherit)
{
    static char* st_inheritstr = NULL;
    static int st_inheritsize = 0;
    int ret;
    int valid = 0;
    int i;

    ret = snprintf_safe(&st_inheritstr, &st_inheritsize, "");
    for (i = 0; st_accessinherit[i].m_inheritstr != NULL ; i ++) {
        if (inherit == st_accessinherit[i].m_inheritval) {
            ret = append_snprintf_safe(&st_inheritstr, &st_inheritsize, "%s", st_accessinherit[i].m_inheritstr);
            if (ret >= 0) {
                valid = 1;
            }
            break;
        }
    }

    if (valid == 0) {
        ret = append_snprintf_safe(&st_inheritstr, &st_inheritsize, "unknown inherit [0x%lx]", inherit);
    }

    if (st_inheritstr == NULL) {
        return "error inherit";
    }
    return st_inheritstr;
}

void dump_aces(FILE* fp, PEXPLICIT_ACCESS_A pace, int tabs, const char* fmt, ...)
{
    PTRUSTEE_A pcur = NULL;

    if (fmt != NULL) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        fprintf(fp, "\n");
    }
    OUTPUT_TABS(fp, tabs);
    fprintf(fp, "grfAccessPermissions=%s[0x%lx]\n", get_access_permissions(pace->grfAccessPermissions), pace->grfAccessPermissions);
    OUTPUT_TABS(fp, tabs);
    fprintf(fp, "grfAccessMode=%s[0x%x]\n", get_access_mode(pace->grfAccessMode), pace->grfAccessMode);
    OUTPUT_TABS(fp, tabs);
    fprintf(fp, "grfInheritance=%s[0x%lx]\n", get_access_inherit(pace->grfInheritance), pace->grfInheritance);
    pcur = &(pace->Trustee);
    dump_trustee(fp, pcur, tabs);
    return;
}

int get_sec_aces_safe(PACL pacl, PEXPLICIT_ACCESS_A* ppaces, ULONG* psize)
{
    int ret;
    DWORD dret;
    if (pacl == NULL) {
        if (ppaces && *ppaces) {
            LocalFree(*ppaces);
            *ppaces = NULL;
        }
        if (psize) {
            *psize = 0;
        }
    }

    if (ppaces == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (*ppaces) {
        LocalFree(*ppaces);
        *ppaces = NULL;
    }
    *psize = 0;

    dret = GetExplicitEntriesFromAclA(pacl, psize, ppaces);
    if (dret != ERROR_SUCCESS) {
        GETERRNO(ret);
        ERROR_INFO("get ace error [%ld] [%d]", dret, ret);
        goto fail;
    }
    ret = (int) * psize;

    return ret;

fail:
    if (*ppaces) {
        LocalFree(*ppaces);
        *ppaces = NULL;
    }
    *psize = 0;
    SETERRNO(ret);
    return ret;
}

int dump_process_security(int pid)
{
    HANDLE hproc = NULL;
    int ret, res;
    PSECURITY_DESCRIPTOR pownersec = NULL, pgrpsec = NULL, psaclsec = NULL, pdaclsec = NULL;
    int ownersize = 0, grpsize = 0, saclsize = 0, daclsize = 0;
    char* pdesc = NULL;
    int descsize = 0;
    int enabled = 0;
    int saclenabled = 0;
    PEXPLICIT_ACCESS_A paces = NULL;
    ULONG acesize = 0;
    int i;
    PACL pacl = NULL;
    BOOL bpresent = FALSE;
    BOOL bdefault = FALSE;
    BOOL bret;

    ret = enable_security_priv();
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not make enabled[%d]", ret);
        goto fail;
    }
    enabled = 1;
    DEBUG_INFO("enable security [%d]" , enabled);

    hproc = OpenProcess(READ_CONTROL | ACCESS_SYSTEM_SECURITY, FALSE, (DWORD)pid);

    //hproc = OpenProcess(PROCESS_ALL_ACCESS,FALSE,(DWORD)pid);
    if (hproc == NULL) {
        hproc = OpenProcess(READ_CONTROL, FALSE, (DWORD)pid);
        if (hproc == NULL) {
            GETERRNO(ret);
            ERROR_INFO("open [%d] error[%d]", pid, ret);
            goto fail;
        }
    } else {
        saclenabled = 1;
    }

    ret = get_security_safe(hproc, OWNER_SECURITY_INFORMATION, &pownersec, &ownersize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get owner for [%d] error[%d]", pid, ret);
        goto fail;
    }

    ret = get_security_safe(hproc, GROUP_SECURITY_INFORMATION, &pgrpsec, &grpsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get group for [%d] error[%d]", pid, ret);
        goto fail;
    }

    if (saclenabled) {
        ret = get_security_safe(hproc, SACL_SECURITY_INFORMATION, &psaclsec, &saclsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("get sacl for [%d] error[%d]", pid, ret);
            goto fail;
        }
    }

    ret = get_security_safe(hproc, DACL_SECURITY_INFORMATION, &pdaclsec, &daclsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get dacl for [%d] error[%d]", pid, ret);
        goto fail;
    }

    ret = get_security_string(pownersec, OWNER_SECURITY_INFORMATION, &pdesc, &descsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get owner string error[%d]", ret);
        goto fail;
    }
    fprintf(stdout, "owner------------\n%s\n", pdesc);





    ret = get_security_string(pgrpsec, GROUP_SECURITY_INFORMATION, &pdesc, &descsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get group string error[%d]", ret);
        goto fail;
    }
    fprintf(stdout, "group------------\n%s\n", pdesc);

    if (saclenabled) {
        ret = get_security_string(psaclsec, SACL_SECURITY_INFORMATION, &pdesc, &descsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("get sacl string error[%d]", ret);
            goto fail;
        }
        fprintf(stdout, "sacl------------\n%s\n", pdesc);

        bpresent = FALSE;
        bdefault = FALSE;
        bret = GetSecurityDescriptorSacl(psaclsec, &bpresent, &pacl, &bdefault);
        if (bret && bpresent) {
            ret = get_sec_aces_safe(pacl, &paces, &acesize);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            for (i = 0; i < (int)acesize; i++) {
                dump_aces(stdout, &(paces[i]), 1, "sacl [%d] ace", i);
            }
        } else {
            fprintf(stdout, "no sacl\n");
        }
    }


    ret = get_security_string(pdaclsec, DACL_SECURITY_INFORMATION, &pdesc, &descsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get dacl string error[%d]", ret);
        goto fail;
    }
    fprintf(stdout, "dacl------------\n%s\n", pdesc);


    bpresent = FALSE;
    bdefault = FALSE;
    bret = GetSecurityDescriptorDacl(pdaclsec, &bpresent, &pacl, &bdefault);
    if (bret && bpresent) {
        ret = get_sec_aces_safe(pacl, &paces, &acesize);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        for (i = 0; i < (int)acesize; i++) {
            dump_aces(stdout, &(paces[i]), 1, "dacl [%d] ace", i);
        }
    } else {
        fprintf(stdout, "no dacl\n");
    }


    get_sec_aces_safe(NULL, &paces, &acesize);

    get_security_string(NULL, DACL_SECURITY_INFORMATION, &pdesc, &descsize);

    get_security_safe(NULL, DACL_SECURITY_INFORMATION, &pdaclsec, &daclsize);
    get_security_safe(NULL, SACL_SECURITY_INFORMATION, &psaclsec, &saclsize);
    get_security_safe(NULL, GROUP_SECURITY_INFORMATION, &pgrpsec, &grpsize);
    get_security_safe(NULL, OWNER_SECURITY_INFORMATION, &pownersec, &ownersize);
    if (hproc != NULL &&
            hproc != INVALID_HANDLE_VALUE) {
        CloseHandle(hproc);
    }
    hproc = NULL;

    if (enabled) {
        res = disable_security_priv();
        if (res < 0) {
            GETERRNO(res);
            ERROR_INFO("disable priv error[%d]", res);
        }
    }
    enabled = 0;

    return 0;
fail:
    get_sec_aces_safe(NULL, &paces, &acesize);
    get_security_string(NULL, DACL_SECURITY_INFORMATION, &pdesc, &descsize);
    get_security_safe(NULL, DACL_SECURITY_INFORMATION, &pdaclsec, &daclsize);
    get_security_safe(NULL, SACL_SECURITY_INFORMATION, &psaclsec, &saclsize);
    get_security_safe(NULL, GROUP_SECURITY_INFORMATION, &pgrpsec, &grpsize);
    get_security_safe(NULL, OWNER_SECURITY_INFORMATION, &pownersec, &ownersize);
    if (hproc != NULL &&
            hproc != INVALID_HANDLE_VALUE) {
        CloseHandle(hproc);
    }
    hproc = NULL;
    if (enabled) {
        res = disable_security_priv();
        if (res < 0) {
            GETERRNO(res);
            ERROR_INFO("disable priv error[%d]" , res);
        }
    }

    SETERRNO(ret);
    return ret;
}


int get_mask_from_str(FILE* fp,char* maskstr, ACCESS_MASK* pmask)
{
    ACCESS_MASK mask = 0;
    char* pcurptr = NULL;
    int valid;
    int ret;
    int i;

    pcurptr = maskstr;

    while (*pcurptr != '\0') {
        valid = 0;
        for (i = 0; st_accessmask[i].m_maskstr != NULL; i++) {
            size_t rlen = strlen(st_accessmask[i].m_maskstr);
            if (_strnicmp(pcurptr, st_accessmask[i].m_maskstr, rlen) == 0) {
                mask |= st_accessmask[i].m_maskval;
                valid = 1;
                pcurptr += rlen;
                if (*pcurptr == '|') {
                    pcurptr ++;
                }
                break;
            }
        }
        if (valid == 0) {
            fprintf(fp, "not valid [%s] valid [", pcurptr);
            for (i = 0; st_accessmask[i].m_maskstr != NULL; i++) {
                if (i > 0) {
                    fprintf(fp, "|");
                }
                fprintf(fp, "%s", st_accessmask[i].m_maskstr);
            }
            fprintf(fp, "]\n");
            ret = -ERROR_INVALID_PARAMETER;
            SETERRNO(ret);
            return ret;
        }
    }
    *pmask = mask;
    return 0;
}

int get_mode_from_str(FILE* fp,char* modestr, ACCESS_MODE* pmode)
{
    ACCESS_MODE mode=NOT_USED_ACCESS;
    int i;
    int valid = 0;
    int ret;

    for (i = 0; st_accessmode[i].m_modestr != NULL; i++) {
        if (_stricmp(modestr, st_accessmode[i].m_modestr) == 0) {
            mode = st_accessmode[i].m_modeval;
            valid = 1;
            break;
        }
    }

    if (valid == 0) {
        fprintf(fp, "not valid mode [%s] valid are[", modestr);
        for (i = 0; st_accessmode[i].m_modestr; i++) {
            if (i > 0) {
                fprintf(fp, "|");
            }
            fprintf(fp, "%s", st_accessmode[i].m_modestr);
        }
        fprintf(fp, "]\n");
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    *pmode = mode;
    return 0;
}

int get_inherit_from_str(FILE* fp,char* inheritstr, DWORD *pinherit)
{
    DWORD inherit = 0;
    int i;
    int valid = 0;
    int ret;

    for (i = 0;st_accessinherit[i].m_inheritstr != NULL; i++) {
        if (_stricmp(inheritstr, st_accessinherit[i].m_inheritstr) == 0) {
            inherit = st_accessinherit[i].m_inheritval;
            valid = 1;
            break;
        }
    }

    if (valid == 0) {
        fprintf(fp, "not valid [%s] valid are[", inheritstr);
        for (i = 0; st_accessinherit[i].m_inheritstr; i++) {
            if (i > 0) {
                fprintf(fp, "|");
            }
            fprintf(fp, "%s", st_accessinherit[i].m_inheritstr);
        }
        fprintf(fp, "]\n");
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    *pinherit = inherit;
    return 0;
}

int proc_dacl_set(int pid,ACCESS_MASK mask, ACCESS_MODE mode,DWORD inherit,char* username)
{
    EXPLICIT_ACCESS_A ea;
    PSECURITY_DESCRIPTOR pdaclsec=NULL;
    int daclsize=0;
    HANDLE hproc=NULL;
    PACL poacl=NULL,pnacl=NULL;
    BOOL bpresent,bdefault,bret;
    DWORD dret;
    SECURITY_DESCRIPTOR sd;
    NTSTATUS status;
    int ret;

    hproc = OpenProcess(READ_CONTROL | WRITE_DAC,FALSE,(DWORD)pid);
    if (hproc == NULL || hproc == INVALID_HANDLE_VALUE) {
        hproc = NULL;
        GETERRNO(ret);
        goto fail;
    }

    ret = get_security_safe(hproc,DACL_SECURITY_INFORMATION,&pdaclsec,&daclsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("get [%d] dacl error[%d]", pid, ret);
        goto fail;
    }

    memset(&ea,0,sizeof(ea));
    bpresent = FALSE;
    bdefault = FALSE;
    bret = GetSecurityDescriptorDacl(pdaclsec,&bpresent,&poacl,&bdefault);
    if (!bret || !bpresent) {
        GETERRNO(ret);
        ERROR_INFO("can not get dacl [%d]" ,ret);
        goto fail;
    }

    BuildExplicitAccessWithNameA(&ea,username,mask,mode,inherit);

    dret = SetEntriesInAclA(1,&ea,poacl,&pnacl);
    if (dret != ERROR_SUCCESS) {
        GETERRNO(ret);
        ERROR_INFO("SetEntriesInAcl [%ld][%d]",dret,ret);
        goto fail;
    }

    bret = InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("initialize security descriptor error[%d]",ret);
        goto fail;
    }

    bret = SetSecurityDescriptorDacl(&sd,TRUE,pnacl,FALSE);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("SetSecurityDescriptorDacl error[%d]", ret);
        goto fail;
    }

    status = NtSetSecurityObjectFake(hproc,DACL_SECURITY_INFORMATION,&sd);
    if (status != NTSTATUS_SUCCESS) {
        GETERRNO(ret);
        ERROR_INFO("NtSetSecurityObjectFake error[0x%lx][%d]", status,ret);
        goto fail;
    }


    if (pnacl) {
        LocalFree(pnacl);
    }
    pnacl = NULL;

    get_security_safe(NULL,DACL_SECURITY_INFORMATION,&pdaclsec,&daclsize);
    if (hproc != NULL) {
        CloseHandle(hproc);
    }
    hproc = NULL;


    return 0;
fail:
    if (pnacl) {
        LocalFree(pnacl);
    }
    pnacl = NULL;

    get_security_safe(NULL,DACL_SECURITY_INFORMATION,&pdaclsec,&daclsize);
    if (hproc != NULL) {
        CloseHandle(hproc);
    }
    hproc = NULL;
    SETERRNO(ret);
    return ret;
}
