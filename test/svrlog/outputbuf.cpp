#include <win_thread.h>
#include <vector>

typedef struct __output_buf {
	CRITICAL_SECTION m_cs;
	std::vector<char*> *m_pbufs;
	std::vector<int> *m_cnts;
	int m_maxcnt;
	int m_global;
	HANDLE m_notifyevt;
	void* m_thread;
} output_buf_t,*poutput_buf_t;


int __pick_buf(poutput_buf_t pof,char** ppbuf,int *plen)
{
	int ret = 0;
	ASSERT_IF(pof);
	EnterCriticalSection(&(pof->m_cs));
	if (pof->m_pbufs->size() > 0) {
		ASSERT_IF(pof->m_pbufs->size() == pof->m_cnts->size());
		*ppbuf = pof->m_pbufs->at(0);
		*plen = pof->m_cnts->at(0);
		pof->m_pbufs->erase(pof->m_pbufs->begin());
		pof->m_cnts->erase(pof->m_cnts->begin());
		ret = 1;
	}
	LeaveCriticalSection(&(pof->m_cs));
	return ret;
}

int __insert_buf(poutput_buf_t pof,char* pbuf,int len)
{
	int ret=-1;
	EnterCriticalSection(&(pof->m_cs));
	if (pof->m_maxcnt == 0 || 
		pof->m_maxcnt > pof->m_cnts->size()) {
		pof->m_pbufs->push_back(pbuf);
		pof->m_cnts->push_back(len);
		ret = 1;
	}
	LeaveCriticalSection(&(pof->m_cs));
	return ret;
}

void free_output_memory(char** ppbuf,int * bufsize)
{
	if (ppbuf && *ppbuf) {
		free(*ppbuf);
		*ppbuf = NULL;
	}
	if (bufsize) {
		*bufsize = 0;
	}
	return;
}

void __free_output_buf(poutput_buf_t* ppof)
{
	if (ppof && *ppof) {
		poutput_buf_t pof = *ppof;
		int ret;
		char* buf=NULL;
		int len=0;
		free_thread(&(pof->m_thread));
		while(1) {
			ret = __pick_buf(pof, &buf,&len);
			if (ret == 0) {
				break;
			}
			free_output_memory(&buf,&len);
		}
		if (pof->m_pbufs) {
			delete pof->m_pbufs;
			pof->m_pbufs = NULL;
		}
		if (pof->m_cnts) {
			delete pof->m_cnts;
			pof->m_cnts = NULL;
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

int handle_buffer_thread(void* param, HANDLE exitevt)
{

}

poutput_buf_t __alloc_output_buf(int global, int maxcnt)
{
	poutput_buf_t pof=NULL;

	pof = malloc(sizeof(*pof));
	if (pof == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pof, 0 , sizeof(*pof));
	InitializeCriticalSection(&(pof->m_cs));
	pof->m_pbufs = new std::vector<char*>();
	pof->m_cnts = new std::vector<int>();
	pof->m_notifyevt = CreateEvent(NULL,FALSE,FALSE,NULL);
	if (pof->m_notifyevt == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not create notify event error[%d]", ret);
		goto fail;
	}

	pof->m_global = global;
	pof->m_maxcnt = maxcnt;

	ret = create_thread(handle_buffer_thread,pof,1,&(pof->m_thread));
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

int get_output_buf(void* pof,char** ppbuf,int* bufsize)
{
	
}