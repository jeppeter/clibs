#include <win_thread.h>
#include <vector>

typedef struct __output_buf {
	CRITICAL_SECTION m_cs;
	std::vector<pdbwin_buffer_t> *m_pbufs;
	std::vector<pdbwin_buffer_t> *m_freebufs;
	int m_global;
	HANDLE m_notifyevt;
	void* m_thread;
} output_buf_t,*poutput_buf_t;


int __pick_buf(poutput_buf_t pof,pdbwin_buffer_t *ppdbwin)
{
	int ret = 0;
	ASSERT_IF(pof);
	EnterCriticalSection(&(pof->m_cs));
	if (pof->m_pbufs->size() > 0) {
		*ppdbwin = pof->m_pbufs->at(0);
		pof->m_pbufs->erase(pof->m_pbufs->begin());
		ret = 1;
	}
	LeaveCriticalSection(&(pof->m_cs));
	return ret;
}

int __insert_buf(poutput_buf_t pof,pdbwin_buffer_t pdbwin)
{
	int ret=-1;
	EnterCriticalSection(&(pof->m_cs));
	pof->m_pbufs->push_back(pdbwin);
	ret = 1;
	LeaveCriticalSection(&(pof->m_cs));
	return ret;
}

int __insert_free(poutput_buf_t pof,pdbwin_buffer_t pdbwin)
{
	int ret = 0;
	EnterCriticalSection(&(pof->m_cs));
	pof->m_freebufs->push_back(pdbwin);
	ret = 1;
	LeaveCriticalSection(&(pof->m_cs));
	return ret;
}

void free_output_memory(void* pof1,pdbwin_buffer_t *ppdbwin)
{
	poutput_buf_t pof = (poutput_buf_t) pof1;
	if (pof != NULL) {
		if (ppdbwin && *ppdbwin) {
			__insert_free(pof, *ppdbwin);	
			*ppdbwin = NULL;
		}		
	}
	return;
}

void __free_output_buf(poutput_buf_t* ppof)
{
	if (ppof && *ppof) {
		poutput_buf_t pof = *ppof;
		int ret;
		pdbwin_buffer_t pdbwin=NULL;
		free_thread(&(pof->m_thread));
		if (pof->m_pbufs != NULL) {
			while(pof->m_pbufs->size() != 0) {
				pdbwin = pof->m_pbufs->at(0);
				pof->m_pbufs->erase(pof->m_pbufs->begin());
				free(pdbwin);
			}
			delete pof->m_pbufs;
			pof->m_pbufs = NULL;
		}
		if (pof->m_freebufs) {
			while(pof->m_freebufs->size() != 0) {
				pdbwin = pof->m_freebufs->at(0);
				pof->m_freebufs->erase(pof->m_freebufs->begin());
				free(pdbwin);
			}
			delete pof->m_freebufs;
			pof->m_freebufs = NULL;
		}
		if (pof->m_notifyevt) {
			CloseEvent(pof->m_notifyevt);
			pof->m_notifyevt=  NULL;
		}

		free(pof);
		*ppof = NULL;
	}
	return ;
}

typedef struct __dbwin_wait {
	HANDLE m_readyevt;

} dbwin_wait_t, *pdbwin_wait_t;


HANDLE get_mutex_dbwin(char* name, int global)
{
	int ret;
	char* sname=NULL;
	int ssize=0;
	HANDLE mux=NULL;

	if(global) {
		ret = snprintf_safe(&sname,&ssize,"Global\\%s",name);
	} else {
		ret=  snprintf_safe(&sname,&ssize,"%s", name);
	}
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	mux = get_or_create_mutex(sname);
	if (mux == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	snprintf_safe(&sname,&ssize,NULL);
	return mux;
fail:
	if (mux) {
		CloseHandle(mux);
	}
	mux = NULL;
	snprintf_safe(&sname,&ssize,NULL);
	SETERRNO(ret);
	return NULL;
}

HANDLE get_event_dbwin(char* name, int global)
{
	int ret;
	char* sname=NULL;
	int ssize=0;
	HANDLE evt=NULL;

	if(global) {
		ret = snprintf_safe(&sname,&ssize,"Global\\%s",name);
	} else {
		ret=  snprintf_safe(&sname,&ssize,"%s", name);
	}
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	evt = get_or_create_event(sname);
	if (evt == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	snprintf_safe(&sname,&ssize,NULL);
	return evt;
fail:
	if (evt) {
		CloseHandle(evt);
	}
	evt = NULL;
	snprintf_safe(&sname,&ssize,NULL);
	SETERRNO(ret);
	return NULL;
}



int __handle_buffer_thread(void* param, HANDLE exitevt)
{
	int ret;
	HANDLE hdbready=NULL;

	ret = 0;
out:
	

}

poutput_buf_t __alloc_output_buf(int global, int maxcnt)
{
	poutput_buf_t pof=NULL;
	int putcnt=4096;
	pdbwin_buffer_t pdbwin=NULL;

	pof = malloc(sizeof(*pof));
	if (pof == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pof, 0 , sizeof(*pof));
	InitializeCriticalSection(&(pof->m_cs));
	pof->m_pbufs = new std::vector<pdbwin_buffer_t>();
	pof->m_freebufs = new std::vector<pdbwin_buffer_t>();

	if (maxcnt != 0){
		putcnt = maxcnt;
	}

	for (i=0;i<putcnt ;i++) {
		pdbwin = malloc(sizeof(*pdbwin));
		if (pdbwin == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		pof->m_freebufs->push_back(pdbwin);
		pdbwin = NULL;
	}

	pof->m_notifyevt = CreateEvent(NULL,FALSE,FALSE,NULL);
	if (pof->m_notifyevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not create notify event error[%d]", ret);
		goto fail;
	}

	pof->m_global = global;

	ret = create_thread(__handle_buffer_thread,pof,1,&(pof->m_thread));
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	SETERRNO(0);
	return pof;
fail:
	__free_output_buf(&pof);
	SETERRNO(ret);
	return NULL;
}

void* create_output_buf(int global,int maxcnt)
{
	return __alloc_output_buf(global,maxcnt);
}

HANDLE get_output_evt(void* pof1)
{
	poutput_buf_t pof = (poutput_buf_t) pof1;
	if (pof !=NULL) {
		return pof->m_notifyevt;
	}
	return NULL;
}

int get_output_buf(void* pof1,pdbwin_buffer_t *ppdbwin)
{
	poutput_buf_t pof = (poutput_buf_t) pof1;
	int ret;
	if (pof == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	return __pick_buf(pof,ppdbwin);
fail:
	SETERRNO(ret);
	return ret;
}

void free_output_buf(void**ppof)
{
	poutput_buf_t pof=NULL;
	if (ppof && *ppof) {
		pof = (poutput_buf_t) *ppof;
		__free_output_buf(&pof);
		*ppof = NULL;
	}
	return ;
}