#include <win_types.h>
#include <win_dbg.h>
#include <win_output_debug.h>
#include <win_uniansi.h>

#include <Windows.h>
#include <dbgeng.h>
#include <atlcomcli.h>


class windbgcallBackOutput : public IDebugOutputCallbacksWide
{
public:
	HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface) { 
		if (InterfaceId == IID_IUnknown) {
			Interface = Interface;	
		}		
		return E_NOINTERFACE; 
	}
	ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
	ULONG	STDMETHODCALLTYPE Release() { return 0; }	
	HRESULT Output(ULONG mask, PCWSTR text);
	windbgcallBackOutput();
	virtual ~windbgcallBackOutput();

	int get_error(char* pbuf,int bufsize);
	int get_info(char* pbuf, int bufsize);


private:
	int add_text(PCWSTR text, char** ppbuf,int *psize, int* plen);
	int get_text(char* pbuf,int bufsize, char* psrc,int* plen);

	char* m_errorbuffer;
	int m_errorsize;
	int m_errorlen;

	char* m_infobuffer;
	int m_infosize;
	int m_infolen;
};

int windbgcallBackOutput::add_text(PCWSTR text, char** ppbuf,int *psize, int* plen)
{
	int ret = 0;
	char* pretbuf=NULL;
	int retsize = 0;
	int retlen=0;
	int wlen=0;
	char* pansi=NULL;
	int ansisize=0;
	int ansilen=0;
	if (text == NULL) {
		if (ppbuf && *ppbuf) {
			free(*ppbuf);
			*ppbuf = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		if (plen) {
			*plen = 0;
		}
		return 0;
	}

	if (ppbuf == NULL || psize == NULL || plen == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	retsize = *psize;
	retlen = *plen;
	pretbuf = *ppbuf;

	ret = UnicodeToAnsi((wchar_t*)text,&pansi,&ansisize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	ansilen = ret;

	wlen = ansilen + retlen;
	if (wlen >= retsize || pretbuf == NULL) {
		if (wlen >= retsize) {
			retsize = wlen + 1;
		}
		pretbuf = (char*)malloc(retsize);
		if (pretbuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(pretbuf, 0 ,retsize);
		if (retlen > 0) {
			memcpy(pretbuf, *ppbuf, retlen);
		}
	}
	memcpy(&(pretbuf[retlen]), pansi, ansilen);
	retlen += ansilen;

	if (*ppbuf && *ppbuf != pretbuf) {
		free(*ppbuf);
	}
	*ppbuf = pretbuf;
	*psize = retsize;
	*plen = retlen;
	UnicodeToAnsi(NULL,&pansi,&ansisize);
	return wlen;
fail:
	UnicodeToAnsi(NULL,&pansi,&ansisize);
	if (pretbuf && pretbuf != *ppbuf) {
		free(pretbuf);
	}
	pretbuf = NULL;
	retsize = 0;
	retlen = 0;
	SETERRNO(ret);
	return ret;
}

int windbgcallBackOutput::get_text(char* pbuf,int bufsize, char* psrc,int* plen)
{
	int ret = 0;
	int i,j;
	if (pbuf == NULL || bufsize == 0) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}
	if (psrc != NULL && *plen != 0) {
		if (*plen <= bufsize) {
			ret = *plen;
			memcpy(pbuf, psrc,ret);
			*plen = 0;
		} else {
			ret = bufsize;
			memcpy(pbuf, psrc, bufsize);
			for (i=bufsize,j=0;i<*plen;i++, j++) {
				psrc[j] = psrc[i];
			}
			*plen -= bufsize;
		}
	}
	return ret;
}

HRESULT windbgcallBackOutput::Output(ULONG mask, PCWSTR text)
{
	int ret;
	HRESULT hr = S_OK;
	if (mask == DEBUG_OUTPUT_ERROR || mask == DEBUG_OUTPUT_WARNING) {
		ret = this->add_text(text, &(this->m_errorbuffer), &(this->m_errorsize), &(this->m_errorlen));
	} else {
		ret = this->add_text(text,&(this->m_infobuffer), &(this->m_infosize), &(this->m_infolen));
	}

	if (ret < 0) {
		hr = 0x80000000 | GetLastError();
	}
	return hr;
}

int windbgcallBackOutput::get_error(char* pbuf,int bufsize)
{
	return this->get_text(pbuf,bufsize,this->m_errorbuffer,  &(this->m_errorlen));
}

int windbgcallBackOutput::get_info(char* pbuf,int bufsize)
{
	return this->get_text(pbuf,bufsize, this->m_infobuffer,&(this->m_infolen));
}

windbgcallBackOutput::~windbgcallBackOutput()
{
	this->add_text(NULL,&(this->m_errorbuffer),&(this->m_errorsize),&(this->m_errorlen));
	this->add_text(NULL,&(this->m_infobuffer),&(this->m_infosize),&(this->m_infolen));
}

windbgcallBackOutput::windbgcallBackOutput()
{
	this->m_errorlen = 0;
	this->m_errorsize = 0;
	this->m_errorbuffer = NULL;
	this->m_infobuffer = NULL;
	this->m_infosize = 0;
	this->m_infolen = 0;
}


class windbgEventCallback : public DebugBaseEventCallbacksWide
{
public:
	ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
	ULONG	STDMETHODCALLTYPE Release() { return 0; }	
    HRESULT STDMETHODCALLTYPE GetInterestMask(PULONG Mask){
        *Mask = 0;
        *Mask |= DEBUG_EVENT_BREAKPOINT;
        *Mask |= DEBUG_EVENT_CHANGE_ENGINE_STATE;
        *Mask |= DEBUG_EVENT_CHANGE_SYMBOL_STATE;
        *Mask |= DEBUG_EVENT_EXCEPTION;
        *Mask |= DEBUG_EVENT_LOAD_MODULE;
        *Mask |= DEBUG_EVENT_UNLOAD_MODULE;
        *Mask |= DEBUG_EVENT_CREATE_PROCESS;
        *Mask |= DEBUG_EVENT_EXIT_PROCESS;
        *Mask |= DEBUG_EVENT_CREATE_THREAD;
        *Mask |= DEBUG_EVENT_EXIT_THREAD;

        return S_OK;
    }
	windbgEventCallback() : DebugBaseEventCallbacksWide()
	{

	}
	virtual ~windbgEventCallback() {}
};

class windbgInputCallBack : public IDebugInputCallbacks
{
public:
	HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface) { 
		if (InterfaceId == IID_IUnknown) {
			Interface = Interface;	
		}		
		return E_NOINTERFACE; 
	}
	ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
	ULONG	STDMETHODCALLTYPE Release() { return 0; }	

	HRESULT  STDMETHODCALLTYPE EndInput() {return S_OK;}
	HRESULT STDMETHODCALLTYPE StartInput(ULONG buffersize) { buffersize = buffersize; return S_OK;}
	windbgInputCallBack() {

	}
	virtual ~windbgInputCallBack() {

	}
};


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
	windbgcallBackOutput*             m_outputcallback;
	windbgEventCallback*              m_evtcallback;
	windbgInputCallBack*              m_inputcallback;
	CComPtr<IDebugClient5>            m_client;
    CComPtr<IDebugControl5>           m_control;
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
				pdbg->m_client->SetInputCallbacks(NULL);
			}
			if (pdbg->m_outputcallback) {
				pdbg->m_outputcallback->Release();
				delete pdbg->m_outputcallback;
				pdbg->m_outputcallback = NULL;
			}
			if (pdbg->m_evtcallback) {
				pdbg->m_evtcallback->Release();
				delete pdbg->m_evtcallback;
				pdbg->m_evtcallback = NULL;
			}

			if (pdbg->m_inputcallback) {
				pdbg->m_inputcallback->Release();
				delete pdbg->m_inputcallback;
				pdbg->m_inputcallback = NULL;
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
	pdbg->m_outputcallback = NULL;
	pdbg->m_evtcallback = NULL;
	pdbg->m_inputcallback = NULL;

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
		hr = DebugCreate(__uuidof(IDebugClient5), (void**) &(pretdbg->m_client));
	} else {
		hr = DebugConnectWide(pwoption,__uuidof(IDebugClient5),(void**)&(pretdbg->m_client));
	}

	if (hr != S_OK) {
		ret = (hr & 0xffffff);
		ret = -ret;
		ERROR_INFO("connect [%s] options error [0x%lx:%d]", option, hr, hr);
		goto fail;
	}

	pretdbg->m_control = CComQIPtr<IDebugControl5>(pretdbg->m_client);
	pretdbg->m_system = CComQIPtr<IDebugSystemObjects4>(pretdbg->m_client);

	pretdbg->m_evtcallback = new windbgEventCallback();
	pretdbg->m_outputcallback = new windbgcallBackOutput();
	pretdbg->m_inputcallback = new windbgInputCallBack();

	pretdbg->m_client->SetEventCallbacksWide(pretdbg->m_evtcallback);
	pretdbg->m_client->SetOutputCallbacksWide(pretdbg->m_outputcallback);
	pretdbg->m_client->SetInputCallbacks(pretdbg->m_inputcallback);
	pretdbg->m_client->SetOutputMask(DEBUG_OUTPUT_NORMAL);

	*ppclient = (void*) pretdbg;
	AnsiToUnicode(NULL,&pwoption,&woptsize);

	return 0;
fail:
	__release_win_debug(&pretdbg);
	AnsiToUnicode(NULL,&pwoption,&woptsize);
	SETERRNO(ret);
	return ret;
}


int start_process_single(void* pclient, char* cmd, int flags)
{
	pclient = pclient;
	cmd = cmd;
	flags = flags;
	return 0;
}