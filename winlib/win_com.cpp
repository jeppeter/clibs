#include <win_err.h>
#include <win_com.h>
#include <win_output_debug.h>


int initialize_com(void)
{
	HRESULT hr;
	int ret =0;

	hr = CoInitialize(NULL);
	if (hr != S_OK) {
		switch(hr) {
		case E_INVALIDARG:
			ret = -ERROR_INVALID_PARAMETER;
			break;
		case E_OUTOFMEMORY:
			ret = -ERROR_OUTOFMEMORY;
			break;
		case E_UNEXPECTED:
			ret = -ERROR_UNEXP_NET_ERR;
			break;
		case S_FALSE:
			ret = -PEERDIST_ERROR_ALREADY_INITIALIZED;
			break;
		case RPC_E_CHANGED_MODE:
			ret = -RPC_S_INVALID_BINDING;
			break;
		default:
			ERROR_INFO("initialize error [0x%x:%d]", hr,hr);
			ret = -ERROR_INTERNAL_ERROR;
			break;
		}
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

void uninitialize_com(void)
{
	CoUninitialize();
	return ;
}