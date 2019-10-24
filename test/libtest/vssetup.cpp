
#pragma warning(push)

#pragma warning(disable:4820)
#pragma warning(disable:4668)

#include <win_types.h>
#include <win_err.h>
#include <win_uniansi.h>

#include <Objbase.h>

#include "vssetup.h"
#include "Setup.Configuration.h"

#pragma warning(pop)

#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"OleAut32.lib")


static int st_vs_cominitialized=0;

const IID IID_ISetupConfiguration = {
  0x42843719, 0xDB4C, 0x46C2,
  { 0x8E, 0x7C, 0x64, 0xF1, 0x81, 0x6E, 0xFD, 0x5B }
};

const IID IID_ISetupConfiguration2 = {
  0x26AAB78C, 0x4A60, 0x49D6,
  { 0xAF, 0x3B, 0x3C, 0x35, 0xBC, 0x93, 0x36, 0x5D }
};

const IID IID_ISetupHelper = {
  0x42b21b78, 0x6192, 0x463e,
  { 0x87, 0xbf, 0xd5, 0x77, 0x83, 0x8f, 0x1d, 0x5c }
};

const IID IID_ISetupInstance2 = {
  0x89143C9A, 0x05AF, 0x49B0,
  { 0xB7, 0x17, 0x72, 0xE2, 0x18, 0xA2, 0x18, 0x5C }
};

const CLSID CLSID_SetupConfiguration = {
  0x177F0C4A, 0x1CD3, 0x4DE7,
  { 0xA3, 0x2C, 0x71, 0xDB, 0xBB, 0x9F, 0xA3, 0x6D }
};


int __vs_init_com()
{
	HRESULT hres;
	int ret;
	if (st_vs_cominitialized) {
		return 0;
	}

	hres = CoInitializeEx(NULL,0);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("CoInitializeEx error[%d]", ret);
		return ret;
	}
	st_vs_cominitialized = 1;
	return 0;
}


void __free_interface(IUnknown** pptr)
{
	if (pptr && *pptr) {
		(*pptr)->Release();
		*pptr = NULL;
	}
	return ;	
}



int __get_setup_configuration(ISetupConfiguration** pptr)
{
	int ret;
	HRESULT hres;
	if (pptr==NULL || *pptr != NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	hres = ::CoCreateInstance(CLSID_SetupConfiguration,NULL,CLSCTX_INPROC_SERVER,IID_ISetupConfiguration,(LPVOID*)pptr);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("create CLSID_SetupConfiguration IID_ISetupConfiguration error [%ld] [%d]", hres, ret);
		goto fail;
	}

	return 0;
fail:
	__free_interface((IUnknown**)pptr);
	SETERRNO(ret);
	return ret;
}

int __query_get_setup_configuration2(ISetupConfiguration* ptr, ISetupConfiguration2**pptr)
{
	int ret;
	HRESULT hres;
	if (ptr == NULL || pptr == NULL || *pptr != NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	hres = ptr->QueryInterface(IID_ISetupConfiguration2,(LPVOID*)pptr);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("query IID_ISetupConfiguration2 error [%ld] [%d]", hres,ret);
		goto fail;
	}

	return 0;
fail:
	__free_interface((IUnknown**)pptr);
	SETERRNO(ret);
	return ret;
}

int __query_get_setup_helper(ISetupConfiguration* ptr,ISetupHelper** pptr)
{
	int ret;
	HRESULT hres;
	if (ptr == NULL || pptr == NULL || *pptr != NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	hres = ptr->QueryInterface(IID_ISetupHelper,(LPVOID*)pptr);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("query IID_ISetupHelper error [%ld] [%d]", hres,ret);
		goto fail;
	}

	return 0;
fail:
	__free_interface((IUnknown**)pptr);
	SETERRNO(ret);
	return ret;
}


int __enum_get_enum_instances(ISetupConfiguration2* ptr, IEnumSetupInstances** pptr)
{
	int ret;
	HRESULT hres;
	if (ptr == NULL || pptr == NULL || *pptr != NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	hres = ptr->EnumInstances(pptr);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("EnumInstances error [%ld] [%d]", hres,ret);
		goto fail;
	}

	return 0;
fail:
	__free_interface((IUnknown**)pptr);
	SETERRNO(ret);
	return ret;
}

int __get_instance2(ISetupInstance* ptr, ISetupInstance2** pptr)
{
	int ret;
	HRESULT hres;
	if (ptr == NULL || pptr == NULL || *pptr != NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	hres = ptr->QueryInterface(IID_ISetupInstance2,(LPVOID*)pptr);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("query IID_ISetupInstance2 error [%ld] [%d]", hres,ret);
		goto fail;
	}

	return 0;
fail:
	__free_interface((IUnknown**)pptr);
	SETERRNO(ret);
	return ret;
}

void __free_bstr(BSTR* ppstr)
{
	if (ppstr && *ppstr) {
		::SysFreeString(*ppstr);
		*ppstr = NULL;
	}
	return ;
}

int __check_match_version(ISetupInstance2* pinst2,const char* version)
{
	int ret;
	HRESULT hres;
	BSTR pstr=NULL;
	char* nstr=NULL;
	int nsize=0;
	InstanceState state;
	REFERENCE_ARG(version);
	hres = pinst2->GetInstanceId(&pstr);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("can not get instance id [%ld] [%d]", hres,ret);
		goto fail;
	}

	ret = UnicodeToAnsi((wchar_t*)pstr,&nstr,&nsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	DEBUG_INFO("get instance id [%s]", nstr);
	__free_bstr(&pstr);

	hres = pinst2->GetState(&state);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("get state error [%ld] [%d]", hres,ret);
		goto fail;
	}

	DEBUG_INFO("state [%ld]", state);

	hres = pinst2->GetInstallationVersion(&pstr);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("can not get installation version error[%ld] [%d]", hres,ret);
		goto fail;
	}

	ret = UnicodeToAnsi((wchar_t*)pstr, &nstr,&nsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	DEBUG_INFO("installation version [%s]", nstr);
	__free_bstr(&pstr);

	hres = pinst2->GetInstallationPath(&pstr);
	if (hres != S_OK) {
		GETERRNO(ret);
		ERROR_INFO("get installation path error[%ld] [%d]", hres, ret);
		goto fail;
	}

	ret = UnicodeToAnsi((wchar_t*)pstr,&nstr, &nsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	DEBUG_INFO("installation path [%s]" , nstr);
	__free_bstr(&pstr);


	UnicodeToAnsi(NULL,&nstr,&nsize);
	__free_bstr(&pstr);
	return 1;
fail:
	UnicodeToAnsi(NULL,&nstr,&nsize);
	__free_bstr(&pstr);
	SETERRNO(ret);
	return ret;
}


int __check_inst_instance(IEnumSetupInstances* penum, const char* version)
{
	ISetupInstance* pinst=NULL;
	ISetupInstance2* pinst2=NULL;
	int ret;
	int matched = 0;
	HRESULT hres;
	int cnt = 0;

	REFERENCE_ARG(version);

	while(1) {
		__free_interface((IUnknown**)&pinst2);
		__free_interface((IUnknown**)&pinst);
		hres = penum->Next(1, &pinst,NULL);
		if (hres != S_OK) {
			GETERRNO(ret);
			ERROR_INFO("can not get instance [%d] return [%ld] [%d]", cnt, hres, ret);
			break;
		}
		cnt ++;

		ret = __get_instance2(pinst,&pinst2);
		if (ret < 0) {
			continue;
		}

		ret = __check_match_version(pinst2, version);
		if (ret > 0) {
			matched = 1;
			break;
		}
	}


	__free_interface((IUnknown**)&pinst2);
	__free_interface((IUnknown**)&pinst);
	return matched;
//fail:
//	__free_interface((IUnknown**)&pinst);
//	SETERRNO(ret);
//	return ret;
}



int is_visual_studio_installed(const char* version)
{
	int ret;
	ISetupConfiguration* psetupconfig=NULL;
	ISetupConfiguration2* psetupconfig2=NULL;
	ISetupHelper* phelper=NULL;
	IEnumSetupInstances* penum=NULL;
	REFERENCE_ARG(version);
	ret = __vs_init_com();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __get_setup_configuration(&psetupconfig);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __query_get_setup_configuration2(psetupconfig,&psetupconfig2);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __query_get_setup_helper(psetupconfig,&phelper);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret =__enum_get_enum_instances(psetupconfig2,&penum);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = __check_inst_instance(penum,version);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	__free_interface((IUnknown**)&penum);
	__free_interface((IUnknown**)&phelper);
	__free_interface((IUnknown**)&psetupconfig2);
	__free_interface((IUnknown**)&psetupconfig);
	return 0;
fail:
	__free_interface((IUnknown**)&penum);
	__free_interface((IUnknown**)&phelper);
	__free_interface((IUnknown**)&psetupconfig2);
	__free_interface((IUnknown**)&psetupconfig);
	SETERRNO(ret);
	return ret;
}

