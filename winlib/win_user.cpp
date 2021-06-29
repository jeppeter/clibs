#include <win_user.h>
#include <win_output_debug.h>
#include <win_uniansi.h>

#pragma warning(push)
#pragma warning(disable:4820)

#include <Lm.h>

#pragma warning(pop)

#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif

#pragma comment(lib, "netapi32.lib")


int user_change_password(char* user, char* oldpassword,char* newpassword)
{
	wchar_t* puuser=NULL, *puoldpass=NULL,*punewpass=NULL,*pudomain=NULL;
	int usersize=0, oldsize=0,newsize=0,domainsize=0;
	int ret;
	NET_API_STATUS  status;

	if (user == NULL || oldpassword == NULL || newpassword == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	ret = AnsiToUnicode("\\\\.",&pudomain,&domainsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = AnsiToUnicode(user,&puuser,&usersize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = AnsiToUnicode(oldpassword,&puoldpass,&oldsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = AnsiToUnicode(newpassword,&punewpass,&newsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	status = NetUserChangePassword(pudomain, puuser,puoldpass,punewpass);
	if (status != NERR_Success) {
		GETERRNO(ret);
		ERROR_INFO("can not change user[%s] from old [%s] =>  new[%s] error[%ld]", user, oldpassword,newpassword, status);
		goto fail;
	}

	AnsiToUnicode(NULL,&pudomain,&domainsize);
	AnsiToUnicode(NULL,&puuser,&usersize);
	AnsiToUnicode(NULL,&puoldpass,&oldsize);
	AnsiToUnicode(NULL,&punewpass,&newsize);
	return 0;

fail:
	AnsiToUnicode(NULL,&pudomain,&domainsize);
	AnsiToUnicode(NULL,&puuser,&usersize);
	AnsiToUnicode(NULL,&puoldpass,&oldsize);
	AnsiToUnicode(NULL,&punewpass,&newsize);
	SETERRNO(ret);
	return ret;
}