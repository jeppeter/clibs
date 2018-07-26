#include <win_envop.h>
#include <win_err.h>
#include <win_uniansi.h>

#pragma warning(disable:4996)

int get_env_variable(char* envvar, char** ppenvval, int* pvalsize)
{
    char* penv = NULL;
    char* pretval = NULL;
    int retsize = 0;
    int vallen = 0, ret = 0;
    size_t slen = 0;


    if (envvar == NULL) {
        if (ppenvval && *ppenvval) {
            free(*ppenvval);
        }
        if (ppenvval) {
            *ppenvval = NULL;
        }
        if (pvalsize) {
            *pvalsize = 0;
        }
        return 0;
    }

    if (ppenvval == NULL || pvalsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    pretval = *ppenvval;
    retsize = *pvalsize;
    penv = getenv(envvar);
    if (penv == NULL) {
        ret = -ERROR_NOT_FOUND;
        goto fail;
    }
    slen = strlen(penv) + 1;
    if ((int)slen > retsize || pretval == NULL) {
        retsize = (int)slen;
        pretval = (char*)malloc((size_t)retsize);
        if (pretval == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not alloc[%d] error[%d]", retsize, ret);
            goto fail;
        }
    }

    strncpy(pretval, penv, (size_t)retsize);

    if (*ppenvval && *ppenvval != pretval) {
        free(*ppenvval);
    }
    *ppenvval = pretval;
    *pvalsize = retsize;
    return vallen;
fail:
    if (pretval && pretval != *ppenvval) {
        free(pretval);
    }
    pretval = NULL;
    SETERRNO(-ret);
    return ret;
}

int get_computer_name(int type, char** ppname, int *pnamesize)
{
    TCHAR *ptname = NULL;
    DWORD tnamesize = 0;
    DWORD dret;
    char* pretname = NULL;
    int retnamesize = 0;
    int ret;
    BOOL bret;
    int retlen = 0;
    char* ptmpname = NULL;
    int tmpnamesize = 0;
    COMPUTER_NAME_FORMAT  format = ComputerNamePhysicalDnsDomain;

    if (type == COMPUTER_NAME_NONE) {
        if (ppname && *ppname != NULL) {
            free(*ppname);
            *ppname = NULL;
        }
        if (pnamesize != NULL) {
            *pnamesize = 0;
        }
        return 0;
    }

    if (ppname == NULL || pnamesize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    switch (type) {
    case COMPUTER_NAME_DNS:
        format = ComputerNamePhysicalDnsDomain;
        break;
    case COMPUTER_NAME_NETBIOS:
        format = ComputerNamePhysicalNetBIOS;
        break;
    case COMPUTER_NAME_PHYS:
        format = ComputerNamePhysicalDnsHostname;
        break;
    default:
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretname = *ppname;
    retnamesize = *pnamesize;

    tnamesize = 256;
try_again:
    if (ptname) {
        free(ptname);
    }
    ptname = NULL;
    ptname = (TCHAR*) malloc((tnamesize * sizeof(TCHAR)));
    if (ptname == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    dret = tnamesize;
    bret = GetComputerNameEx(format, ptname, &dret);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_BUFFER_OVERFLOW) {
            tnamesize <<= 1;
            goto try_again;
        }
        ERROR_INFO("can not get computer name error[%d]", ret);
        goto fail;
    }

    ret = TcharToAnsi(ptname, &ptmpname, &tmpnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    retlen = (int)strlen(ptmpname);
    if (retlen >= retnamesize || pretname == NULL) {
        if (retlen >= retnamesize) {
            retnamesize = retlen + 3;
        }
        pretname = (char*) malloc((size_t)retnamesize);
    }
    memset(pretname, 0 , (size_t)retnamesize);
    strncpy_s(pretname, (size_t)retnamesize, ptmpname, (size_t)retnamesize);

    TcharToAnsi(NULL, &ptmpname, &tmpnamesize);
    if (ptname != NULL) {
        free(ptname);
    }
    ptname = NULL;
    tnamesize = 0;

    if (*ppname && *ppname != pretname) {
        free(*ppname);
    }
    *ppname = pretname;
    *pnamesize = retnamesize;

    return retlen;
fail:
    TcharToAnsi(NULL, &ptmpname, &tmpnamesize);
    if (ptname != NULL) {
        free(ptname);
    }
    ptname = NULL;
    tnamesize = 0;

    if (pretname != NULL && pretname != *ppname) {
        free(pretname);
    }
    pretname = NULL;
    retnamesize = 0;
    SETERRNO(ret);
    return ret;
}

int set_computer_name(int type, char* pname)
{
    TCHAR* ptname = NULL;
    int tnamesize = 0;
    int ret;
    BOOL bret;
    COMPUTER_NAME_FORMAT format = ComputerNamePhysicalDnsDomain;

    switch (type) {
    case COMPUTER_NAME_DNS:
        format = ComputerNamePhysicalDnsDomain;
        break;
    case COMPUTER_NAME_NETBIOS:
        format = ComputerNamePhysicalNetBIOS;
        break;
    case COMPUTER_NAME_PHYS:
        format = ComputerNamePhysicalDnsHostname;
        break;
    default:
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    ret = AnsiToTchar(pname, &ptname, &tnamesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = SetComputerNameEx(format, ptname);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("set [%s] computer name error[%d]",  pname, ret);
        goto fail;
    }

    AnsiToTchar(NULL, &ptname, &tnamesize);
    return 0;
fail:
    AnsiToTchar(NULL, &ptname, &tnamesize);
    SETERRNO(ret);
    return ret;
}


int get_codepage(void)
{
    UINT cp=0;
    int ret = 0;

    cp = GetConsoleCP();
    if (cp == 0) {
        GETERRNO(ret);
        ERROR_INFO("can not get cp error[%d]",ret);
        goto fail;
    }

    return (int)cp;
fail:
    SETERRNO(ret);
    return ret;
}

int set_codepage(int cp)
{
    BOOL bret;
    int ret;

    bret = SetConsoleCP((UINT)cp);
    if (!bret){
        GETERRNO(ret);
        ERROR_INFO("can not set [%d] error[%d]", cp, ret);
        goto fail;
    }
    return 0;
fail:
    SETERRNO(ret);
    return ret;
}