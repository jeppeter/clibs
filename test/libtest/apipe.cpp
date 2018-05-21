#include <apipe.h>


void __free_async_evt(pasync_evt_t* ppevt)
{
	BOOL bret;
	int res;
	if (ppevt != NULL && *ppevt != NULL) {
		pasync_evt_t pevt = *ppevt;
		CHECK_CLOSE_HANDLE_FMT(pevt->m_evt,"close %p error[%d]", pevt->m_evt, res);
		pevt->m_cbret = 0;
		pevt->m_errorcode = 0;
		free(pevt);
		*ppevt = NULL;
	}
	return;
}

pasync_evt_t __alloc_async_evt()
{
	pasync_evt_t pevt=NULL;
	int ret;
	
	ALLOC_PTR_TYPEOF(pevt);
	memset(pevt,0, sizeof(*pevt));
	pevt->m_evt = CreateEvent(NULL,TRUE,TRUE,NULL);
	CHECK_NULL_FAIL(pevt->m_evt,"can not create event error[%d]",ret);
	
	return pevt;
fail:
	__free_async_evt(&pevt);
	return NULL;
}


int __create_pipe_async(char* name , int wr, HANDLE *ppipe)
{
	TCHAR* ptname=NULL;
	int tnamesize=0;
	BOOL bret;
	if (name == NULL || ppipe == NULL || *ppipe != NULL || pov == NULL || pstate == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (pov->hEvent != NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	/*now we should make the */


	return 0;
fail:

	SETERRNO(ret);
	return ret;       
}
