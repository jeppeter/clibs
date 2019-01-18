#include <win_types.h>
#include <win_dbg.h>
#include <win_output_debug.h>
#include <win_uniansi.h>

#include <Windows.h>
#include <dbgeng.h>
#include <atlcomcli.h>

#define WIN_DBG_MAGIC           0x31dcae09

#define WIN_DBG_CHECK           1

#if  WIN_DBG_CHECK
#define   CHECK_WINDBG_MAGIC(pdbg)            ( (pdbg) != NULL && ((pdbg)->m_magic == WIN_DBG_MAGIC))
#define   SET_WINDBG_MAGIC(pdbg)              do{ (pdbg)->m_magic = WIN_DBG_MAGIC; }while(0)
#else
#define   CHECK_WINDBG_MAGIC(pdbg)            ( (pdbg) != NULL )
#define   SET_WINDBG_MAGIC(pdbg)              
#endif


#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"dbgeng.lib")

typedef struct __win_debug_t {
#if WIN_DBG_CHECK
	uint32_t m_magic;
#endif
	CComPtr<IDebugClient4>            m_client;
    CComPtr<IDebugControl4>           m_control;
    CComPtr<IDebugSystemObjects4>     m_system;
} win_debug_t,*pwin_debug_t;

void __release_win_debug(pwin_debug_t* ppdbg)
{
	if (ppdbg && *ppdbg) {
		pwin_debug_t pdbg = *ppdbg;
		if (CHECK_WINDBG_MAGIC(pdbg)){
			if (pdbg->m_client) {
				pdbg->m_client->SetEventCallbacks(NULL);
				pdbg->m_client->SetOutputCallbacks(NULL);
			}
		}
		free(pdbg);
		*ppdbg=  NULL;
	}
	return;
}

pwin_debug_t __alloc_win_debug(void)
{
	pwin_debug_t pdbg=NULL;
	int ret;

	pdbg = (pwin_debug_t)malloc(sizeof(*pdbg));
	if (pdbg == NULL) {
		GETERRNO(ret);		
		ERROR_INFO("alloc [%d] error[%d]", sizeof(*pdbg), ret);
		goto fail;
	}
	memset(pdbg, 0, sizeof(*pdbg));
	SET_WINDBG_MAGIC(pdbg);
	pdbg->m_client = NULL;
	pdbg->m_control = NULL;
	pdbg->m_system = NULL;

	return pdbg;
fail:
	__release_win_debug(&pdbg);
	SETERRNO(ret);
	return NULL;
}


int create_client(char* option, void** ppclient)
{
	wchar_t* pwoption=NULL;
	int woptsize=0;
	int ret;
	HRESULT hr;
	int len=0;


	pwin_debug_t pretdbg=NULL;
	if (option == NULL) {
		__release_win_debug((pwin_debug_t*) ppclient);
		return 0;
	}
	if (ppclient == NULL || *ppclient != NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	len = (int)strlen(option);

	ret = AnsiToUnicode(option,&pwoption,&woptsize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	pretdbg = __alloc_win_debug();
	if (pretdbg == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	if (len == 0) {
		hr = DebugCreate(__uuidof(IDebugClient4), (void**) &(pretdbg->m_client));
	} else {
		hr = DebugConnectWide(pwoption,__uuidof(IDebugClient4),(void**)&(pretdbg->m_client));
	}

	if (hr != S_OK) {
		ret = (hr & 0xffffff);
		ret = -ret;
		ERROR_INFO("connect [%s] options error [0x%lx:%d]", option, hr, hr);
		goto fail;
	}

	pretdbg->m_control = CComQIPtr<IDebugControl4>(pretdbg->m_client);
	pretdbg->m_system = CComQIPtr<IDebugSystemObjects4>(pretdbg->m_client);

	*ppclient = (void*) pretdbg;
	AnsiToUnicode(NULL,&pwoption,&woptsize);

	return 0;
fail:
	__release_win_debug(&pretdbg);
	AnsiToUnicode(NULL,&pwoption,&woptsize);
	SETERRNO(ret);
	return ret;
}