#include <win_types.h>
#include <win_dbg.h>
#include <win_output_debug.h>
#include <win_uniansi.h>

#include <Windows.h>
#include <dbgeng.h>
#include <atlcomcli.h>

#define GET_HR_ERROR(hr)    -((hr) & 0xffffff)
#define DEFAULT_WAIT_FLAG   0

class windbgcallBackOutput : public IDebugOutputCallbacksWide
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface)
    {
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

    int get_error(char* pbuf, int bufsize);
    int get_info(char* pbuf, int bufsize);


private:
    int add_text(PCWSTR text, char** ppbuf, int *psize, int* plen);
    int get_text(char* pbuf, int bufsize, char* psrc, int* plen);

    char* m_errorbuffer;
    int m_errorsize;
    int m_errorlen;

    char* m_infobuffer;
    int m_infosize;
    int m_infolen;
};

int windbgcallBackOutput::add_text(PCWSTR text, char** ppbuf, int *psize, int* plen)
{
    int ret = 0;
    char* pretbuf = NULL;
    int retsize = 0;
    int retlen = 0;
    int wlen = 0;
    char* pansi = NULL;
    int ansisize = 0;
    int ansilen = 0;
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

    ret = UnicodeToAnsi((wchar_t*)text, &pansi, &ansisize);
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
        memset(pretbuf, 0 , retsize);
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
    UnicodeToAnsi(NULL, &pansi, &ansisize);
    return wlen;
fail:
    UnicodeToAnsi(NULL, &pansi, &ansisize);
    if (pretbuf && pretbuf != *ppbuf) {
        free(pretbuf);
    }
    pretbuf = NULL;
    retsize = 0;
    retlen = 0;
    SETERRNO(ret);
    return ret;
}

int windbgcallBackOutput::get_text(char* pbuf, int bufsize, char* psrc, int* plen)
{
    int ret = 0;
    int i, j;
    if (pbuf == NULL || bufsize == 0) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    if (psrc != NULL && *plen != 0) {
        if (*plen <= bufsize) {
            ret = *plen;
            memcpy(pbuf, psrc, ret);
            *plen = 0;
        } else {
            ret = bufsize;
            memcpy(pbuf, psrc, bufsize);
            for (i = bufsize, j = 0; i < *plen; i++, j++) {
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
        ret = this->add_text(text, &(this->m_infobuffer), &(this->m_infosize), &(this->m_infolen));
    }

    if (ret < 0) {
        hr = 0x80000000 | GetLastError();
    }
    return hr;
}

int windbgcallBackOutput::get_error(char* pbuf, int bufsize)
{
    return this->get_text(pbuf, bufsize, this->m_errorbuffer,  &(this->m_errorlen));
}

int windbgcallBackOutput::get_info(char* pbuf, int bufsize)
{
    return this->get_text(pbuf, bufsize, this->m_infobuffer, &(this->m_infolen));
}

windbgcallBackOutput::~windbgcallBackOutput()
{
    this->add_text(NULL, &(this->m_errorbuffer), &(this->m_errorsize), &(this->m_errorlen));
    this->add_text(NULL, &(this->m_infobuffer), &(this->m_infosize), &(this->m_infolen));
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
    HRESULT STDMETHODCALLTYPE GetInterestMask(PULONG Mask)
    {
        *Mask = 0;
        *Mask |= DEBUG_EVENT_BREAKPOINT;
        *Mask |= DEBUG_EVENT_EXCEPTION;
        *Mask |= DEBUG_EVENT_CREATE_THREAD;
        *Mask |= DEBUG_EVENT_EXIT_THREAD;
        *Mask |= DEBUG_EVENT_CREATE_PROCESS;
        *Mask |= DEBUG_EVENT_EXIT_PROCESS;
        *Mask |= DEBUG_EVENT_LOAD_MODULE;
        *Mask |= DEBUG_EVENT_UNLOAD_MODULE;
        *Mask |= DEBUG_EVENT_SYSTEM_ERROR;
        *Mask |= DEBUG_EVENT_SESSION_STATUS;
        *Mask |= DEBUG_EVENT_CHANGE_DEBUGGEE_STATE;
        *Mask |= DEBUG_EVENT_CHANGE_ENGINE_STATE;
        *Mask |= DEBUG_EVENT_CHANGE_SYMBOL_STATE;

        return S_OK;
    }
    windbgEventCallback() : DebugBaseEventCallbacksWide()
    {

    }
    virtual ~windbgEventCallback() {}
    HRESULT STDMETHODCALLTYPE Breakpoint( PDEBUG_BREAKPOINT2 Bp) {Bp = Bp ;DEBUG_INFO("get Breakpoint") ;return S_OK; }
    HRESULT STDMETHODCALLTYPE ChangeDebuggeeState(ULONG   Flags,ULONG64 Argument) { 
    	Flags = Flags ; 
    	Argument = Argument; 
    	DEBUG_INFO("get ChangeDebuggeeState Flags [0x%lx:%ld] Argument [0x%llx:%lld]", Flags, Flags,Argument,Argument); 
    	return S_OK;}
    HRESULT STDMETHODCALLTYPE ChangeEngineState( ULONG   Flags, ULONG64 Argument) { 
    	Flags = Flags ; 
    	Argument = Argument; 
    	DEBUG_INFO("get ChangeEngineState Flags [0x%lx:%ld] Argument [0x%llx:%lld]", Flags, Flags, Argument,Argument); 
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateThread( ULONG64 Handle, ULONG64 DataOffset, ULONG64 StartOffset) {
    	Handle = Handle;
    	DataOffset = DataOffset;
    	StartOffset = StartOffset;
    	DEBUG_INFO("get CreateThread");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ExitThread(ULONG ExitCode) {
    	ExitCode = ExitCode;
    	DEBUG_INFO("get ExitThread");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SessionStatus(ULONG Status){
    	Status = Status;
    	DEBUG_INFO("get SessionStatus");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SystemError(ULONG Error,ULONG Level){
    	Error = Error;
    	Level = Level;
    	DEBUG_INFO("get SystemError");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ChangeSymbolState(ULONG   Flags,ULONG64 Argument){
    	Flags = Flags;
    	Argument = Argument;
    	DEBUG_INFO("get ChangeSymbolState");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Exception(PEXCEPTION_RECORD64 Exception,ULONG               FirstChance) {
    	Exception = Exception;
    	FirstChance = FirstChance;
    	DEBUG_INFO("get Exception");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateProcess(ULONG64 ImageFileHandle,ULONG64 Handle,ULONG64 BaseOffset,
    		ULONG   ModuleSize,PCWSTR  ModuleName,PCWSTR  ImageName,ULONG   CheckSum,
    		ULONG   TimeDateStamp,ULONG64 InitialThreadHandle,ULONG64 ThreadDataOffset,ULONG64 StartOffset){
    	ImageFileHandle = ImageFileHandle;
    	Handle = Handle;
    	BaseOffset = BaseOffset;
    	ModuleSize = ModuleSize;
    	ModuleName = ModuleName;
    	ImageName = ImageName;
    	CheckSum = CheckSum;
    	TimeDateStamp = TimeDateStamp;
    	InitialThreadHandle = InitialThreadHandle;
    	ThreadDataOffset = ThreadDataOffset;
    	StartOffset = StartOffset;
    	DEBUG_INFO("get CreateProcess");
    	return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ExitProcess(ULONG ExitCode) {
    	ExitCode = ExitCode;
    	DEBUG_INFO("get ExitProcess");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE LoadModule(ULONG64 ImageFileHandle,ULONG64 BaseOffset,ULONG   ModuleSize,
    		PCWSTR  ModuleName,PCWSTR  ImageName,ULONG   CheckSum,ULONG   TimeDateStamp){
    	ImageFileHandle = ImageFileHandle;
    	BaseOffset = BaseOffset;
    	ModuleSize = ModuleSize;
    	ModuleName = ModuleName;
    	ImageName = ImageName;
    	CheckSum = CheckSum;
    	TimeDateStamp = TimeDateStamp;
    	DEBUG_INFO("get LoadModule");
    	return S_OK;
    }

    HRESULT STDMETHODCALLTYPE UnloadModule(PCWSTR  ImageBaseName,ULONG64 BaseOffset){
    	ImageBaseName = ImageBaseName;
    	BaseOffset = BaseOffset;
    	DEBUG_INFO("get UnloadModule");
    	return S_OK;
    }
};

class windbgInputCallBack : public IDebugInputCallbacks
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface)
    {
        if (InterfaceId == IID_IUnknown) {
            Interface = Interface;
        }
        return E_NOINTERFACE;
    }
    ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG	STDMETHODCALLTYPE Release() { return 0; }

    HRESULT  STDMETHODCALLTYPE EndInput() {return S_OK;}
    HRESULT STDMETHODCALLTYPE StartInput(ULONG buffersize) { buffersize = buffersize; return S_OK;}
    windbgInputCallBack()
    {

    }
    virtual ~windbgInputCallBack()
    {

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
    CComPtr<IDebugControl4>           m_control;
    CComPtr<IDebugSystemObjects4>     m_system;
    int                               m_created;
    int                               m_procid;
} win_debug_t, *pwin_debug_t;

int __detach_process(pwin_debug_t pdbg)
{
    int ret;
    HRESULT hr;
    if (pdbg->m_procid < 0) {
        return 0;
    }
    hr = pdbg->m_client->DetachProcesses();
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("detach process error [0x%x:%d]", hr, hr);
        goto fail;
    }
    pdbg->m_procid = -1;
    pdbg->m_created = 0;

    return 1;
fail:
    SETERRNO(ret);
    return ret;
}

int __stop_process(pwin_debug_t pdbg)
{
    HANDLE hproc = NULL;
    int ret;
    int trycnt = 0;
    BOOL bret;
    int maxcnt = 5;
    ULONG status;
    HRESULT hr;
    if (pdbg->m_procid < 0) {
        return 0;
    }

    hproc = OpenProcess(PROCESS_TERMINATE , TRUE, pdbg->m_procid);
    if (hproc == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open process %d error[%d]", pdbg->m_procid, ret);
        goto fail;
    }

    do {
        bret = TerminateProcess(hproc, 32);
        if (!bret) {
            GETERRNO(ret);
            ERROR_INFO("can not terminate proc[%d] error[%d]", pdbg->m_procid, ret);
        }

        hr = pdbg->m_control->GetExecutionStatus(&status);
        if (hr == S_OK) {
            DEBUG_INFO("status [0x%lx:%d]", status, status);
        } else {
            hr = pdbg->m_control->WaitForEvent(DEFAULT_WAIT_FLAG, 1);
        }
        if (trycnt >= maxcnt) {
            ret = -ERROR_INTERNAL_ERROR;
            ERROR_INFO("over maxcnt [%d]", maxcnt);
            goto fail;
        }
        trycnt ++;
    } while (1);

    if (hproc != NULL) {
        CloseHandle(hproc);
    }
    hproc = NULL;
    ret = __detach_process(pdbg);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return 1;
fail:
    if (hproc != NULL) {
        CloseHandle(hproc);
    }
    hproc = NULL;
    SETERRNO(ret);
    return ret;
}


void __release_win_debug(pwin_debug_t* ppdbg)
{
    if (ppdbg && *ppdbg) {
        pwin_debug_t pdbg = *ppdbg;
        if (CHECK_WINDBG_MAGIC(pdbg)) {
            if (pdbg->m_procid >= 0) {
                if (pdbg->m_created) {
                    __stop_process(pdbg);
                } else {
                    __detach_process(pdbg);
                }
                pdbg->m_procid = -1;
                pdbg->m_created = 0;
            }
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
        *ppdbg =  NULL;
    }
    return;
}

pwin_debug_t __alloc_win_debug(void)
{
    pwin_debug_t pdbg = NULL;
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
    pdbg->m_procid = -1;
    pdbg->m_created = 0;

    return pdbg;
fail:
    __release_win_debug(&pdbg);
    SETERRNO(ret);
    return NULL;
}


int windbg_create_client(char* option, void** ppclient)
{
    wchar_t* pwoption = NULL;
    int woptsize = 0;
    int ret;
    HRESULT hr;
    int len = 0;


    pwin_debug_t pretdbg = NULL;
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

    ret = AnsiToUnicode(option, &pwoption, &woptsize);
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
        hr = DebugCreate(__uuidof(IDebugClient4), (void**) & (pretdbg->m_client));
    } else {
        hr = DebugConnectWide(pwoption, __uuidof(IDebugClient4), (void**) & (pretdbg->m_client));
    }

    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("connect [%s] options error [0x%lx:%d]", option, hr, hr);
        goto fail;
    }

    pretdbg->m_control = CComQIPtr<IDebugControl4>(pretdbg->m_client);
    pretdbg->m_system = CComQIPtr<IDebugSystemObjects4>(pretdbg->m_client);
    DEBUG_INFO("control %p", pretdbg->m_control);
    DEBUG_INFO("system %p", pretdbg->m_system);

    pretdbg->m_evtcallback = new windbgEventCallback();
    pretdbg->m_outputcallback = new windbgcallBackOutput();
    pretdbg->m_inputcallback = new windbgInputCallBack();

    pretdbg->m_client->SetEventCallbacksWide(pretdbg->m_evtcallback);
    pretdbg->m_client->SetOutputCallbacksWide(pretdbg->m_outputcallback);
    pretdbg->m_client->SetInputCallbacks(pretdbg->m_inputcallback);
    pretdbg->m_client->SetOutputMask(DEBUG_OUTPUT_NORMAL);

    *ppclient = (void*) pretdbg;
    AnsiToUnicode(NULL, &pwoption, &woptsize);

    return 0;
fail:
    __release_win_debug(&pretdbg);
    AnsiToUnicode(NULL, &pwoption, &woptsize);
    SETERRNO(ret);
    return ret;
}


ULONG  _create_process_flag(int flags)
{
    ULONG cflags = 0;
    if (!(flags & WIN_DBG_FLAGS_CHILDREN)) {
        cflags |= DEBUG_ONLY_THIS_PROCESS;
    } else {
        cflags |= DEBUG_PROCESS;
    }

    if (!(flags & WIN_DBG_FLAGS_HEAP)) {
        cflags |= DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP;
    }

    return cflags;
}


int windbg_start_process_single(void* pclient, char* cmd, int flags)
{
    wchar_t * pwcmd = NULL;
    int wcmdsize = 0;
    int ret;
    ULONG cflags = 0;
    ULONG status;
    ULONG pid;
    HRESULT hr;
    int matchcnt = 0;
    pwin_debug_t pdbg = (pwin_debug_t) pclient;
    if (!CHECK_WINDBG_MAGIC(pdbg) || cmd == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pdbg->m_procid >= 0) {
        ret = -ERROR_ALREADY_EXISTS;
        SETERRNO(ret);
        return ret;
    }

    ret = AnsiToUnicode(cmd, &pwcmd, &wcmdsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    cflags = _create_process_flag(flags);

    hr = pdbg->m_client->CreateProcessAndAttachWide(0,
            pwcmd, cflags, 0, DEBUG_ATTACH_DEFAULT);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("create process [%s] error[0x%lx:%d]", cmd, hr, hr);
        goto fail;
    }

    /*now wait for the process running*/
    while (1) {

    	DEBUG_INFO("control [%p]" , pdbg->m_control);
        hr = pdbg->m_control->GetExecutionStatus(&status);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            ERROR_INFO("get status error [0x%lx:%d]", hr, hr);
            goto fail;
        }
        DEBUG_INFO("status [0x%lx:%d]", status, status);

        hr = pdbg->m_control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);

#if 0        
        if (hr != S_OK)	{
            ret = GET_HR_ERROR(hr);
            ERROR_INFO("wait event error[0x%lx:%d]", hr, hr);
            goto fail;
        }
#else
        DEBUG_INFO("hr [0x%lx:%d]", hr, hr);
        if (hr == E_UNEXPECTED) {
        	ret = GET_HR_ERROR(hr);
        	goto fail;
        }
#endif

        hr = pdbg->m_control->GetExecutionStatus(&status);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            ERROR_INFO("get status error [0x%lx:%d]", hr, hr);
            goto fail;
        }
        DEBUG_INFO("status [0x%lx:%d]", status, status);
        if (status == DEBUG_STATUS_BREAK) {
        	matchcnt ++;
        } else {
        	matchcnt = 0;
        }
        if (matchcnt >= 10) {
        	DEBUG_INFO("BREAK already");
        	break;
        }
    }

    hr = pdbg->m_system->GetCurrentProcessId(&pid);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("getpid error [0x%lx:%d]", hr, hr);
        goto fail;
    }
    pdbg->m_procid = (int) pid;
    pdbg->m_created = 1;

    DEBUG_INFO("procid %d", pdbg->m_procid);
    AnsiToUnicode(NULL, &pwcmd, &wcmdsize);
    return 1;
fail:
    if (pdbg->m_procid >= 0) {
        __stop_process(pdbg);
    }
    AnsiToUnicode(NULL, &pwcmd, &wcmdsize);
    SETERRNO(ret);
    return ret;
}

int windbg_stop_process(void* pclient)
{
    pwin_debug_t pdbg = (pwin_debug_t) pclient;
    int ret = -ERROR_INVALID_PARAMETER;
    if (!CHECK_WINDBG_MAGIC(pdbg)) {
    	ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    return __stop_process(pdbg);
}