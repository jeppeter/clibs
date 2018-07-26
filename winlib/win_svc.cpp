#include <win_svc.h>
#include <win_err.h>
#include <win_uniansi.h>

#pragma comment(lib,"Advapi32.lib")

void __close_scm(SC_HANDLE* pschd)
{
	BOOL bret;
	int ret;
	if (pschd != NULL && *pschd != NULL) {
		bret = CloseServiceHandle(*pschd);
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO("close %p error[%d]", *pschd, ret);
		}
		*pschd = NULL;
	}
}

void __close_svc(SC_HANDLE* pshsv)
{
	__close_scm(pshsv);
}

SC_HANDLE __open_svc_scm(const char* name, DWORD accmode)
{
	SC_HANDLE schd=NULL;
	int ret;
	TCHAR* ptname=NULL;
	int tnamesize=0;

	if (name != NULL) {
		ret = AnsiToTchar(name,&ptname,&tnamesize);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	schd = OpenSCManager(ptname,NULL,accmode);
	if (schd == NULL) {
		GETERRNO(ret);
		ERROR_INFO("open %s err[%d]", name != NULL ? name : "local", ret);
		goto fail;
	}

	AnsiToTchar(NULL,&ptname,&tnamesize);

	return schd;
fail:
	__close_scm(&schd);
	AnsiToTchar(NULL,&ptname,&tnamesize);
	SETERRNO(ret);
	return NULL;
}

SC_HANDLE __open_svc(SC_HANDLE schd, const char* name,DWORD accmode)
{
	SC_HANDLE shsv=NULL;
	int ret;
	TCHAR* ptname= NULL;
	int tnamesize=0;
	if (schd == NULL || name == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	ret = AnsiToTchar(name, &ptname,&tnamesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	shsv = OpenService(schd, ptname, accmode);
	if (shsv == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not open [%s] error[%d]", name, ret);
		goto fail;
	}

	AnsiToTchar(NULL,&ptname,&tnamesize);
	return shsv;
fail:
	__close_svc(&shsv);
	AnsiToTchar(NULL,&ptname,&tnamesize);	
	SETERRNO(ret);
	return NULL;
}

int is_service_exist(const char* name)
{
	SC_HANDLE schd = NULL;
	SC_HANDLE shsv = NULL;
	int exist = 0;
	int ret;

	schd = __open_svc_scm(NULL,GENERIC_READ);
	if (schd == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	shsv = __open_svc(schd,name,GENERIC_READ);
	if (shsv == NULL) {
		GETERRNO(ret);
		if (ret != -ERROR_SERVICE_DOES_NOT_EXIST) {
			goto fail;	
		}
		exist = 0;
	} else {
		exist = 1;
	}

	__close_svc(&shsv);
	__close_scm(&schd);

	return exist;
fail:
	__close_svc(&shsv);
	__close_scm(&schd);
	SETERRNO(ret);
	return ret;
}

int is_service_running(const char* name)
{
	SC_HANDLE schd = NULL;
	SC_HANDLE shsv = NULL;
	int isrunning = 0;
	int ret;

	schd = __open_svc_scm(NULL,GENERIC_READ);
	if (schd == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	shsv = __open_svc(schd,name,GENERIC_READ);
	if (shsv == NULL) {
		GETERRNO(ret);
		goto fail;
	} 

	__close_svc(&shsv);
	__close_scm(&schd);

	return isrunning;
fail:
	__close_svc(&shsv);
	__close_scm(&schd);
	SETERRNO(ret);
	return ret;	
}