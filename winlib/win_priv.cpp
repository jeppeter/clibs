#include <win_priv.h>
#include <win_err.h>
#include <win_types.h>
#include <win_uniansi.h>

#include <Windows.h>

int __handle_priv(const char* privstr, int enabled)
{
    TCHAR* ptpriv = NULL;
    int tprivsize = 0;
    int ret;
    BOOL bret;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE htoken=NULL;

    bret = OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&htoken);
    if (!bret) {
    	GETERRNO(ret);
    	ERROR_INFO("open process token error[%d]", ret);
    	goto fail;
    }

    ret = AnsiToTchar(privstr,&ptpriv,&tprivsize);
    if (ret < 0) {
    	GETERRNO(ret);
    	goto fail;
    }

    bret = LookupPrivilegeValue(NULL,ptpriv,&luid);
    if (!bret) {
    	GETERRNO(ret);
    	ERROR_INFO("lookup [%s] error[%d]", privstr, ret);
    	goto fail;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid =luid;
    if (enabled) {
    	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
    	tp.Privileges[0].Attributes = 0;
    }

    bret = AdjustTokenPrivileges(htoken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES), NULL,NULL);
    if (!bret) {
    	GETERRNO(ret);
    	ERROR_INFO("adjust %s [%s] error[%d]", privstr, enabled ? "enable" : "disable", ret);
    	goto fail;
    }

    if (htoken != NULL) {
    	CloseHandle(htoken);
    }
    htoken = NULL;

    return 0;
fail:
    if (htoken != NULL) {
    	CloseHandle(htoken);
    }
    htoken = NULL;
	AnsiToTchar(NULL,&ptpriv,&tprivsize);
    SETERRNO(ret);
    return ret;
}


int enable_security_priv(void)
{
	return __handle_priv("SeSecurityPrivilege",1);
}

int disable_security_priv(void)
{
	return __handle_priv("SeSecurityPrivilege",0);
}