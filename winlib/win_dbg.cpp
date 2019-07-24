#include <win_types.h>
#include <win_dbg.h>
#include <win_output_debug.h>
#include <win_uniansi.h>
#include <win_priv.h>

#include <Windows.h>
#include <dbgeng.h>
#include <atlcomcli.h>

#ifdef  _M_X64

#define GET_HR_ERROR(hr)    -((hr) & 0xffffff)
#define DEFAULT_WAIT_FLAG   0

typedef struct __win_debug_t win_debug_t,*pwin_debug_t;


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
    windbgcallBackOutput(pwin_debug_t pdbg);
    virtual ~windbgcallBackOutput();

    int get_info(char* pbuf, int bufsize);


private:
    int add_text(PCWSTR text, char** ppbuf, int *psize, int* plen);
    int get_text(char* pbuf, int bufsize, char* psrc, int* plen);

    char* m_infobuffer;
    int m_infosize;
    int m_infolen;

    pwin_debug_t m_pdbg;
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
    mask = mask;
    ret = this->add_text(text, &(this->m_infobuffer), &(this->m_infosize), &(this->m_infolen));

    if (ret < 0) {
        hr = 0x80000000 | GetLastError();
    }
    return hr;
}


int windbgcallBackOutput::get_info(char* pbuf, int bufsize)
{
    return this->get_text(pbuf, bufsize, this->m_infobuffer, &(this->m_infolen));
}

windbgcallBackOutput::~windbgcallBackOutput()
{
    this->add_text(NULL, &(this->m_infobuffer), &(this->m_infosize), &(this->m_infolen));
}

windbgcallBackOutput::windbgcallBackOutput(pwin_debug_t pdbg)
{
    this->m_infobuffer = NULL;
    this->m_infosize = 0;
    this->m_infolen = 0;
    this->m_pdbg = pdbg;
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

    windbgEventCallback(pwin_debug_t pdbg) : DebugBaseEventCallbacksWide()
    {
        this->m_pdbg = pdbg;
    }
    virtual ~windbgEventCallback() {}
    HRESULT STDMETHODCALLTYPE Breakpoint( PDEBUG_BREAKPOINT2 Bp) {Bp = Bp ;DEBUG_INFO("get Breakpoint") ;return DEBUG_STATUS_BREAK; }
    HRESULT STDMETHODCALLTYPE ChangeDebuggeeState(ULONG   Flags,ULONG64 Argument) { 
    	Flags = Flags ; 
    	Argument = Argument; 
    	DEBUG_INFO(">>>get ChangeDebuggeeState Flags [0x%lx:%ld] Argument [0x%llx:%lld]", Flags, Flags,Argument,Argument); 
    	return S_OK;}
    HRESULT STDMETHODCALLTYPE ChangeEngineState( ULONG   Flags, ULONG64 Argument) { 
    	Flags = Flags ; 
    	Argument = Argument; 
    	DEBUG_INFO(">>>get ChangeEngineState Flags [0x%lx:%ld] Argument [0x%llx:%lld]", Flags, Flags, Argument,Argument); 
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateThread( ULONG64 Handle, ULONG64 DataOffset, ULONG64 StartOffset) {
    	Handle = Handle;
    	DataOffset = DataOffset;
    	StartOffset = StartOffset;
    	DEBUG_INFO(">>>get CreateThread");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ExitThread(ULONG ExitCode) {
    	ExitCode = ExitCode;
    	DEBUG_INFO(">>>get ExitThread");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SessionStatus(ULONG Status){
    	Status = Status;
    	DEBUG_INFO(">>>get SessionStatus");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SystemError(ULONG Error,ULONG Level){
    	Error = Error;
    	Level = Level;
    	DEBUG_INFO(">>>get SystemError");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ChangeSymbolState(ULONG   Flags,ULONG64 Argument){
    	Flags = Flags;
    	Argument = Argument;
    	DEBUG_INFO(">>>get ChangeSymbolState");
    	return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Exception(PEXCEPTION_RECORD64 Exception,ULONG               FirstChance) {
    	Exception = Exception;
    	FirstChance = FirstChance;
    	DEBUG_INFO(">>>get Exception");
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
    	DEBUG_INFO(">>>get CreateProcess");
    	return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ExitProcess(ULONG ExitCode) {
    	ExitCode = ExitCode;
    	DEBUG_INFO(">>>get ExitProcess");
    	return DEBUG_STATUS_BREAK;
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
    	DEBUG_INFO(">>>get LoadModule");
    	return S_OK;
    }

    HRESULT STDMETHODCALLTYPE UnloadModule(PCWSTR  ImageBaseName,ULONG64 BaseOffset){
    	ImageBaseName = ImageBaseName;
    	BaseOffset = BaseOffset;
    	DEBUG_INFO(">>>get UnloadModule");
    	return S_OK;
    }
private:
    pwin_debug_t m_pdbg;
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
    windbgInputCallBack(pwin_debug_t pdbg)
    {
        this->m_pdbg = pdbg;
    }
    virtual ~windbgInputCallBack()
    {

    }
private:
    pwin_debug_t m_pdbg;
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
    IDebugClient5*                    m_client;
    IDebugControl4*                   m_control;
    IDebugSystemObjects4*             m_system;
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
    int maxcnt=5;
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
            if (status == DEBUG_STATUS_BREAK) {
                break;
            }
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

            if (pdbg->m_system) {
                pdbg->m_system->Release();
                pdbg->m_system = NULL;
            }

            if (pdbg->m_control) {
                pdbg->m_control->Release();
                pdbg->m_control = NULL;
            }

            if (pdbg->m_client) {
                pdbg->m_client->Release();
                pdbg->m_client = NULL;
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

    hr = pretdbg->m_client->QueryInterface(__uuidof(IDebugControl4),(void**)&(pretdbg->m_control));
    if (hr != S_OK) {
        ret= GET_HR_ERROR(hr);
        ERROR_INFO("query control error [0x%lx:%d]", hr, hr);
        goto fail;
    }

    hr = pretdbg->m_client->QueryInterface(__uuidof(IDebugSystemObjects4),(void**)&(pretdbg->m_system));
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("query system error [0x%lx:%d]", hr ,hr);
        goto fail;
    }
    DEBUG_INFO("control %p", pretdbg->m_control);
    DEBUG_INFO("system %p", pretdbg->m_system);

    pretdbg->m_outputcallback = new windbgcallBackOutput(pretdbg);
    pretdbg->m_inputcallback = new windbgInputCallBack(pretdbg);
    pretdbg->m_evtcallback = new windbgEventCallback(pretdbg);

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

    cflags |= CREATE_SUSPENDED;

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
    BOOL bret;
    int enbled=0;
    int validhd=0;
    pwin_debug_t pdbg = (pwin_debug_t) pclient;
    STARTUPINFOW startinfo = {0};
    PROCESS_INFORMATION infoproc = {0};
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

    ret = enable_debug_priv();
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    enbled = 1;

    ret = AnsiToUnicode(cmd, &pwcmd, &wcmdsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    cflags = _create_process_flag(flags);

    memset(&startinfo,0, sizeof(startinfo));
    memset(&infoproc, 0, sizeof(infoproc));
    startinfo.cb = sizeof(startinfo);
    bret = CreateProcessW(NULL,pwcmd,NULL,NULL,FALSE,cflags,NULL,NULL,&startinfo,&infoproc);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not create [%s] error[%d]", cmd, ret);
        goto fail;
    }
    validhd = 1;
    pid = GetProcessId(infoproc.hProcess);

    hr = pdbg->m_client->AttachProcess(0,pid,DEBUG_ATTACH_EXISTING);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("attach proc [%ld] error[0x%lx:%d]", pid, hr,hr);
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
        DEBUG_INFO("hr [0x%lx:%d]", hr, hr);
        if (FAILED(hr)) {
        	ret = GET_HR_ERROR(hr);
        	goto fail;
        }

        hr = pdbg->m_control->GetExecutionStatus(&status);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            ERROR_INFO("get status error [0x%lx:%d]", hr, hr);
            goto fail;
        }
        DEBUG_INFO("status [0x%lx:%d]", status, status);
        if (status == DEBUG_STATUS_BREAK) {
        	break;
        }
    }

    pdbg->m_procid = (int) pid;
    pdbg->m_created = 1;
    disable_debug_priv();
    enbled = 0;
    DEBUG_INFO("procid %d", pdbg->m_procid);
    bret = ResumeThread(infoproc.hThread);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("resume thread error[%d]", ret);
        goto fail;
    }

    CloseHandle(infoproc.hThread);
    CloseHandle(infoproc.hProcess);
    validhd = 0;    


    AnsiToUnicode(NULL, &pwcmd, &wcmdsize);
    return 1;
fail:
    if (validhd) {
        CloseHandle(infoproc.hThread);
        CloseHandle(infoproc.hProcess);
    }
    validhd = 0;

    if (pdbg->m_procid >= 0) {
        __stop_process(pdbg);
    }
    AnsiToUnicode(NULL, &pwcmd, &wcmdsize);
    if (enbled) {
        disable_debug_priv();
    }
    enbled = 0;

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

int windbg_go(void* pclient)
{
    pwin_debug_t pdbg = (pwin_debug_t) pclient;
    int ret = -ERROR_INVALID_PARAMETER;
    HRESULT hr;
    ULONG status;
    if (!CHECK_WINDBG_MAGIC(pdbg)) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    while (1) {
        hr = pdbg->m_control->WaitForEvent(DEBUG_WAIT_DEFAULT,INFINITE);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            ERROR_INFO("wait error [0x%lx:%d]", hr ,hr);
            return ret;
        }
        hr = pdbg->m_control->GetExecutionStatus(&status);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            ERROR_INFO("get status error [0x%lx:%d]", hr ,hr);
            return ret;
        }
        DEBUG_INFO("status [0x%d:%d]", status,status);
        break;
    }
    return 0;
}

int windbg_exec(void* pclient, const char* cmd)
{
    int ret;
    pwin_debug_t pdbg = (pwin_debug_t) pclient;
    wchar_t* pwcmd=NULL;
    int wcmdsize=0;
    HRESULT hr;
    if (!CHECK_WINDBG_MAGIC(pdbg) || cmd == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    ret= AnsiToUnicode((char*)cmd,&pwcmd,&wcmdsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    hr = pdbg->m_control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT,pwcmd,DEBUG_EXECUTE_NOT_LOGGED);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("exec[%s] error[0x%lx:%d]", cmd, hr, hr);
        goto fail;
    }
    AnsiToUnicode(NULL,&pwcmd,&wcmdsize);
    return 1;
fail:
    AnsiToUnicode(NULL,&pwcmd,&wcmdsize);
    SETERRNO(ret);
    return ret;
}

int windbg_interrupt(void* pclient)
{
    pwin_debug_t pdbg = (pwin_debug_t) pclient;
    int ret;
    HRESULT hr;
    if (!CHECK_WINDBG_MAGIC(pdbg)) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    hr = pdbg->m_control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("interrupt error [0x%lx:%d]", hr, hr);
        goto fail;
    }

    return 1;
fail:
    SETERRNO(ret);
    return ret;
}

#define MIN_BUF_SIZE            512

int windbg_get_out(void* pclient,int flags, char** ppout, int *psize)
{
    int ret;
    pwin_debug_t pdbg = (pwin_debug_t) pclient;
    int outlen=0;
    char* pretout=NULL;
    char* ptmpout=NULL;
    int retsize=0;
    if (flags == WIN_DBG_FLAGS_FREE) {
        if (ppout && *ppout) {
            free(*ppout);
            *ppout = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (!CHECK_WINDBG_MAGIC(pdbg) || 
        (flags != WIN_DBG_OUTPUT_OUT) || 
        ppout == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }
    pretout = *ppout;
    retsize = *psize;

    if (pdbg->m_outputcallback == NULL) {
        ret = -ERROR_NOT_READY;
        goto fail;
    }

    if (retsize < MIN_BUF_SIZE || pretout == NULL) {
        if (retsize < MIN_BUF_SIZE) {
            retsize = MIN_BUF_SIZE;
        }
        pretout = (char*) malloc(retsize);
        if (pretout == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc [%d] error[%d]", retsize, ret);
            goto fail;
        }
        memset(pretout, 0 ,retsize);
    }

try_again:
    ret = pdbg->m_outputcallback->get_info(&(pretout[outlen]), (retsize - outlen));
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    outlen += ret;
    if (outlen == retsize) {
        retsize <<= 1;
        ptmpout = (char*) malloc(retsize);
        if (ptmpout == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc [%d] error[%d]", retsize, ret);
            goto fail;
        }
        memset(ptmpout, 0, retsize);
        if (outlen > 0) {
            memcpy(ptmpout, pretout, outlen);
        }
        if (pretout && pretout != *ppout) {
            free(pretout);
        }
        pretout = ptmpout;
        goto try_again;
    }

    if (*ppout && *ppout != pretout) {
        free(*ppout);
    }

    *ppout = pretout;
    *psize = retsize;
    return outlen;
fail:
    if (pretout != NULL && pretout != *ppout) {
        free(pretout);
    }
    pretout = NULL;
    SETERRNO(ret);
    return ret;
}

#endif /* _M_X64*/