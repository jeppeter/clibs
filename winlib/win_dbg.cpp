#include <win_types.h>
#include <win_dbg.h>
#include <win_output_debug.h>
#include <win_uniansi.h>

typedef struct __win_debug {
	CComPtr<IDebugClient5>            m_client;
    CComPtr<IDebugControl4>           m_control;
    CComPtr<IDebugSystemObjects4>     m_system;
} win_debug_t,*pwin_debug_t;

void __release_win_debug(pwin_debug_t* ppdbg)
{
	if (ppdbg && *ppdbg) {
		pwin_debug_t pdbg = *ppdbg;
		if (pdbg->m_)
	}
}


int create_client(char* option, void** ppclient)
{
	if (option == NULL) {

	}
}