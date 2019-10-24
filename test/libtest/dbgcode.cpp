

#ifdef _M_X64

#pragma warning(push)

#pragma warning(disable:4820)
#pragma warning(disable:4365)
#pragma warning(disable:4191)
#pragma warning(disable:4917)

#if _MSC_VER >= 1910
#pragma warning(disable:4514)
#endif

#include <Windows.h>
#include <dbgeng.h>
#include <atlcomcli.h>

#pragma warning(pop)


#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"dbgeng.lib")


#define GET_HR_ERROR(hr)    -((hr) & 0xffffff)

class EventCallbacks : public IDebugEventCallbacks
{
private:
	int m_started;
    int m_dummy;

public:
	EventCallbacks()
	{
		m_started = 0;
        m_dummy = 0;
	}
	virtual ~EventCallbacks()
	{

	}
    HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface)
    {
    	if (InterfaceId == IID_IUnknown){
    		REFERENCE_ARG(Interface);	
    	}
        return E_NOINTERFACE;
    }

    ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG	STDMETHODCALLTYPE Release() { return 0; }

    HRESULT Breakpoint(PDEBUG_BREAKPOINT p) 
    {
    	DEBUG_INFO("BreakPoint p[%p]", p);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT ChangeDebuggeeState(ULONG flags,ULONG64 arg)
    {
    	DEBUG_INFO("ChangeDebuggeeState flags[0x%lx] arg[0x%llx]", flags, arg);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT ChangeEngineState(ULONG flags,ULONG64 arg)
    {
    	DEBUG_INFO("ChangeEngineState flags [0x%lx] arg[0x%llx]", flags, arg);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT ChangeSymbolState(ULONG flags, ULONG64 arg)
    {
    	DEBUG_INFO("ChangeSymbolState flags [0x%lx] arg[0x%llx]", flags, arg);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT CreateProcess(ULONG64 imghdl,ULONG64 hdl,ULONG64 baseoff,ULONG modsize,
    	PCSTR modname,PCSTR imgname,ULONG chksum,ULONG timestamp,ULONG64 initthrhdl,ULONG64 thrdataoff,
    	ULONG64 startoff)
    {
    	DEBUG_INFO("CreateProcess imghdl [0x%llx] hdl [0x%llx] baseoff [0x%llx] modsize [0x%lx] modname [%s] imgname [%s] chksum [0x%lx] timestamp [0x%lx] initthrhdl [0x%llx] thrdataoff [0x%llx] startoff [0x%llx]", imghdl, hdl,baseoff,modsize, modname,
    		imgname, chksum, timestamp,initthrhdl,thrdataoff,startoff);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT CreateThread(ULONG64 hdl,ULONG64 dataoff,ULONG64 startoff)
    {
    	DEBUG_INFO("CreateThread hdl[0x%llx] dataoff[0x%llx] startoff[0x%llx]",
    		hdl, dataoff, startoff);
    	this->m_started = 1;
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT Exception(PEXCEPTION_RECORD64 pexp, ULONG firstchance)
    {
    	DEBUG_INFO("Exception pexp[%p] firstchance [0x%lx]", pexp, firstchance);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT ExitProcess(ULONG exitcode)
    {
    	DEBUG_INFO("ExitProcess exitcode [0x%lx]", exitcode);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT ExitThread(ULONG exitcode)
    {
    	DEBUG_INFO("ExitThread exitcode [0x%lx]", exitcode);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT GetInterestMask(ULONG* pmask)
    {
    	*pmask = (DEBUG_EVENT_BREAKPOINT | 
    		DEBUG_EVENT_EXCEPTION |
    		DEBUG_EVENT_CREATE_THREAD | 
    		DEBUG_EVENT_EXIT_THREAD |
    		DEBUG_EVENT_CREATE_PROCESS | 
    		DEBUG_EVENT_EXIT_PROCESS |
    		DEBUG_EVENT_LOAD_MODULE | 
    		DEBUG_EVENT_UNLOAD_MODULE | 
    		DEBUG_EVENT_SYSTEM_ERROR |
    		DEBUG_EVENT_SESSION_STATUS | 
    		DEBUG_EVENT_CHANGE_DEBUGGEE_STATE | 
    		DEBUG_EVENT_CHANGE_ENGINE_STATE |
    		DEBUG_EVENT_CHANGE_SYMBOL_STATE);
    	return S_OK;
    }

    HRESULT LoadModule(ULONG64 imghdl,ULONG64 baseoff,ULONG modsize,PCSTR modname,PCSTR imgname,ULONG chksum,ULONG timestamp)
    {
    	DEBUG_INFO("LoadModule imghdl[0x%llx] baseoff[0x%llx] modsize [0x%lx] modname[%s] imgname[%s] chksum [0x%lx] timestamp [0x%lx]",
    		imghdl,baseoff, modsize, modname, imgname, chksum, timestamp);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT SessionStatus(ULONG status)
    {
    	DEBUG_INFO("SessionStatus status[0x%lx]", status);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT SystemError(ULONG error,ULONG level)
    {
    	DEBUG_INFO("SystemError error[0x%lx] level[0x%lx]", error, level);
    	return DEBUG_STATUS_BREAK;
    }

    HRESULT UnloadModule(PCSTR imgname,ULONG64 baseoff)
    {
    	DEBUG_INFO("UnloadModule imgname[%s] baseoff[0x%llx]", imgname, baseoff);
    	return DEBUG_STATUS_BREAK;
    }

    int is_started()
    {
    	return this->m_started;
    }
};

class OutputCallback : public IDebugOutputCallbacks
{
public:
	OutputCallback(){}
	virtual ~OutputCallback(){}
    HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface)
    {
    	if (InterfaceId == IID_IUnknown){
    		REFERENCE_ARG(Interface);	
    	}
        return E_NOINTERFACE;
    }

    ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG	STDMETHODCALLTYPE Release() { return 0; }
	HRESULT Output(ULONG mask,PCSTR text)
	{
		fprintf(stdout,"Output[0x%lx]%s", mask,text);
		return S_OK;
	}
};

class InputCallback : public IDebugInputCallbacks
{
public:
	InputCallback() {}
	virtual ~InputCallback(){}
    HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface)
    {
    	if (InterfaceId == IID_IUnknown){
    		REFERENCE_ARG(Interface);	
    	}
        return E_NOINTERFACE;
    }

    ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG	STDMETHODCALLTYPE Release() { return 0; }
	HRESULT EndInput()	
	{
		DEBUG_INFO("EndInput");
		return S_OK;
	}
	HRESULT StartInput(ULONG bufsize)
	{
		DEBUG_INFO("StartInput bufsize[0x%lx]", bufsize);
		return S_OK;
	}
};


int dbgcode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    HRESULT hr;
    IDebugClient* pclient = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;
    int ret;
    char* pcmd = NULL;
    int cmdsize = 0;
    int i;
    IDebugControl3* pctrl = NULL;
    EventCallbacks* pevtcallback=NULL;
    int setevt = 0;
    int cnt=0;
    char readbuf[256];
    int readsize=256;
    char* pptr=NULL;
    int readlen;
    InputCallback* inputcallback=NULL;
    OutputCallback* outputcallback=NULL;
    int setinput=0,setoutput=0;
    ULONG outmask=0;


    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    init_log_level(pargs);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i] ; i ++) {
        if (i > 0) {
            ret = append_snprintf_safe(&pcmd, &cmdsize, " %s", parsestate->leftargs[i]);
        } else {
            ret = append_snprintf_safe(&pcmd, &cmdsize, "%s", parsestate->leftargs[i]);
        }
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("append [%d] [%s] error[%d]", i, parsestate->leftargs[i], ret);
            goto out;
        }
    }


    hr = DebugCreate(__uuidof(IDebugClient), (void**)&pclient);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("debug create error[%d]", ret);
        goto out;
    }

    DEBUG_INFO("get client ok");
    hr = pclient->CreateProcessAndAttach(NULL, pcmd, DEBUG_PROCESS, NULL, NULL);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("could not create [%s] error[%d] [0x%lx]", pcmd, ret, hr);
        goto out;
    }

    DEBUG_INFO("create [%s] succ", pcmd);

    hr = pclient->QueryInterface(__uuidof(IDebugControl3), (void**)&pctrl);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("can not query interface control3 error[%d] [0x%lx]", ret, hr);
        goto out;
    }

    DEBUG_INFO("get IDebugControl succ");

    pevtcallback = new EventCallbacks();
    hr = pclient->SetEventCallbacks(pevtcallback);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        ERROR_INFO("can not set event callback error[%d] [0x%lx]", ret, hr);
        goto out;
    }
    setevt = 1;

    inputcallback= new InputCallback();
    hr = pclient->SetInputCallbacks(inputcallback);
    if (hr != S_OK) {
    	ret = GET_HR_ERROR(hr);
    	ERROR_INFO("can not set input callback error[%d] [0x%lx]", ret, hr);
    	goto out;
    }
    setinput = 1;

    outputcallback = new OutputCallback();
    hr = pclient->SetOutputCallbacks(outputcallback);
    if (hr != S_OK) {
    	ret = GET_HR_ERROR(hr);
    	ERROR_INFO("can not set output callback error[%d] [0x%lx]", ret , hr);
    	goto out;
    }
    setoutput = 1;

    outmask = DEBUG_OUTPUT_NORMAL | 
    	DEBUG_OUTPUT_ERROR |
    	DEBUG_OUTPUT_WARNING |
    	DEBUG_OUTPUT_VERBOSE | 
    	DEBUG_OUTPUT_PROMPT |
    	DEBUG_OUTPUT_PROMPT_REGISTERS |
    	DEBUG_OUTPUT_EXTENSION_WARNING |
    	DEBUG_OUTPUT_DEBUGGEE |
    	DEBUG_OUTPUT_DEBUGGEE_PROMPT |
    	DEBUG_OUTPUT_SYMBOLS |
    	DEBUG_OUTPUT_STATUS;
    hr = pclient->SetOutputMask(outmask);
    if (hr != S_OK) {
    	ret = GET_HR_ERROR(hr);
    	ERROR_INFO("can not set output mask error[%d] [0x%lx]", ret, hr);
    	goto out;
    }

    while(1){
	    hr = pctrl->WaitForEvent(0, INFINITE);
	    if (hr != S_OK) {
	        ret = GET_HR_ERROR(hr);
	        ERROR_INFO("wait for [%s] error[%d] [0x%lx]", pcmd, ret , hr);
	        goto out;
	    }

	    if (pevtcallback->is_started()){
	    	break;
	    }

	    DEBUG_INFO("WaitForEvent [%d] succ",cnt);
	    cnt ++;
    }

    while(1) {
        hr = pctrl->GetExecutionStatus(&outmask);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            ERROR_INFO("GetExecutionStatus error[%d] [0x%lx]", ret ,hr);
            goto out;
        }
        DEBUG_INFO("before status [0x%lx]", outmask);
        if (outmask != DEBUG_STATUS_BREAK) {
            SleepEx(500,TRUE);
            continue;
        }

    	fprintf(stdout,"dbg>");
    	fflush(stdout);
    	pptr = fgets(readbuf,readsize,stdin);
    	if (pptr == NULL) {
    		break;
    	}

    	readlen = (int)strlen(readbuf);
    	while(readlen > 0  ) {
    		if (readbuf[(readlen - 1)] != '\r' &&
    			readbuf[(readlen - 1)] != '\n') {
    			break;
    		}
    		readbuf[(readlen-1)] = 0x0;
    		readlen --;
    	}
    	if (readlen == 0) {
    		fprintf(stdout,"\n");
    		fflush(stdout);
    		continue;
    	}

        hr = pctrl->GetExecutionStatus(&outmask);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            ERROR_INFO("GetExecutionStatus error[%d] [0x%lx]", ret ,hr);
            goto out;
        }
        DEBUG_INFO("after status [0x%lx]", outmask);

    	hr = pctrl->Execute(DEBUG_OUTCTL_IGNORE,readbuf,DEBUG_EXECUTE_NOT_LOGGED);
    	if (hr != S_OK) {
    		ret = GET_HR_ERROR(hr);
    		ERROR_INFO("execute [%s] error[%d] [0x%lx]", readbuf, ret, hr);
    		goto out;
    	}
    }


    ret = 0;
out:
	if (setoutput) {
		pclient->SetOutputCallbacks(NULL);
	}
	setoutput = 0;
	if (outputcallback) {
		delete outputcallback;
	}
	outputcallback = NULL;

	if (setinput) {
		pclient->SetInputCallbacks(NULL);
	}
	setinput = 0;

	if (inputcallback) {
		delete inputcallback;
	}
	inputcallback = NULL;

	if (setevt) {
		pclient->SetEventCallbacks(NULL);
	}
	if (pevtcallback) {
		delete pevtcallback;
	}
	pevtcallback = NULL;

    if (pctrl) {
        pctrl->Release();
    }
    pctrl = NULL;
    if (pclient) {
        pclient->Release();
    }
    pclient = NULL;
    append_snprintf_safe(&pcmd, &cmdsize, NULL);
    SETERRNO(ret);
    return ret;
}

#else

int dbgcode_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;

    ret = -ERROR_NOT_SUPPORTED;
    SETERRNO(ret);
    return ret;
}

#endif