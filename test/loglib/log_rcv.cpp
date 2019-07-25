#include <log_rcv.h>
#include <win_err.h>
#include <win_strop.h>


typedef struct __dbwin_buffer {
	DWORD procid;
	char data[4096- sizeof(DWORD)];
} dbwin_buffer_t,*pdbwin_buffer_t;


LogMonitor::LogMonitor(void* pevmain,int global)
{
	this->m_pevmain = pevmain;
	this->m_global = global;
	this->m_pcallback = NULL;
	this->m_buffready = NULL;
	this->m_dataready = NULL;
	this->m_hmutex = NULL;
	this->m_mapbuf = NULL;
	this->m_inserted = 0;
	this->m_pcurdata = NULL;
	this->m_cursize = 0;
	this->m_curlen = 0;
}

void LogMonitor::__remove_all_callbacks()
{

	if (this->m_pcallback) {
		while(this->m_pcallback->size() > 0) {
			this->m_pcallback->erase(this->m_pcallback->begin());
		}
		delete this->m_pcallback;
		this->m_pcallback = NULL;
	}
	return;
}

void LogMonitor::__unmap_buf(void)
{
	unmap_buffer(&(this->m_mapbuf));
}

void LogMonitor::__remove_data_ready_evt(void)
{
	int ret;
	if (this->m_inserted) {
		ret = libev_remove_handle(this->m_pevmain,this->m_dataready);
		ASSERT_IF(ret > 0);
		this->m_inserted = 0;
	}
	return;
}

int LogMonitor::__insert_data_ready_evt(void)
{
	int ret;
	ASSERT_IF(this->m_inserted == 0);
	DEBUG_INFO("insert dataready event");
	ret = libev_insert_handle(this->m_pevmain,this->m_dataready,LogMonitor::handle_data_ready,this,INFINIT_TIME);
	ASSERT_IF(ret > 0);
	this->m_inserted = 1;
	return 0;
}


void LogMonitor::__close_event(void)
{
	this->__remove_data_ready_evt();
	if (this->m_dataready != NULL) {
		CloseHandle(this->m_dataready);
		this->m_dataready = NULL;
	}

	if (this->m_buffready != NULL) {
		CloseHandle(this->m_buffready);
		this->m_buffready = NULL;
	}

	if (this->m_hmutex != NULL) {
		CloseHandle(this->m_hmutex);
		this->m_hmutex = NULL;
	}

	return ;
}

void LogMonitor::__free_buf(void)
{
	if (this->m_pcurdata) {
		free(this->m_pcurdata);
	}
	this->m_pcurdata = NULL;
	this->m_curlen = 0;
	this->m_cursize = 0;
}

int LogMonitor::__alloc_buf(void)
{
	int ret;
	this->__free_buf();
	this->m_cursize = (sizeof(dbwin_buffer_t) - sizeof(DWORD));
	this->m_pcurdata = (char*)malloc((size_t)this->m_cursize);
	if (this->m_pcurdata == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	this->m_curlen = 0;

	return 0;
fail:
	this->__free_buf();
	SETERRNO(ret);
	return ret;
}

LogMonitor::~LogMonitor()
{
	this->__remove_all_callbacks();
	this->__unmap_buf();
	this->__close_event();
	this->__free_buf();

	this->m_pevmain = NULL;
	this->m_global = 0;
}

int LogMonitor::add_log_callback(LogCallback* pcallback)
{
	int ret;
	int findidx=-1;
	DWORD i;
	if(this->m_pcallback == NULL) {
		this->m_pcallback = new std::vector<LogCallback*>();
	}

	if (this->m_pcallback == NULL) {
		ret = -ERROR_APP_INIT_FAILURE;
		SETERRNO(ret);
		return ret;
	}
	for (i=0;i<this->m_pcallback->size();i++) {
		if (this->m_pcallback->at(i) == pcallback) {
			findidx = (int) i;
			break;
		}
	}

	if (findidx >= 0) {
		ret = -ERROR_ALREADY_EXISTS;
		SETERRNO(ret);
		return ret;
	}
	this->m_pcallback->push_back(pcallback);
	return (int) this->m_pcallback->size() - 1;
}

int LogMonitor::remove_log_callback(LogCallback* pcallback)
{
	int ret = 0;
	int findidx=-1;
	DWORD i;
	if (this->m_pcallback != NULL) {
		for (i=0;i<this->m_pcallback->size();i++) {
			if (this->m_pcallback->at(i) == pcallback){
				findidx = (int) i;
				break;
			}
		}

		if (findidx >= 0) {
			this->m_pcallback->erase( this->m_pcallback->begin() + findidx);
			ret = 1;
		}
	}
	return ret;
}

HANDLE LogMonitor::__create_event_name(char* name)
{
	int ret;
	char* sname = NULL;
	int snamesize=0;
	HANDLE evt=NULL;

	if (this->m_global) {
		ret = snprintf_safe(&sname,&snamesize,"Global\\%s", name);
	} else {
		ret = snprintf_safe(&sname,&snamesize,"%s", name);
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

	snprintf_safe(&sname,&snamesize,NULL);
	return evt;
fail:
	if (evt != NULL) {
		CloseHandle(evt);
	}
	evt = NULL;
	snprintf_safe(&sname,&snamesize,NULL);
	SETERRNO(ret);
	return NULL;
}

HANDLE LogMonitor::__create_mutex_name(char* name)
{
	int ret;
	char* sname = NULL;
	int snamesize=0;
	HANDLE mux=NULL;

	if (this->m_global) {
		ret = snprintf_safe(&sname,&snamesize,"Global\\%s", name);
	} else {
		ret = snprintf_safe(&sname,&snamesize,"%s", name);
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

	snprintf_safe(&sname,&snamesize,NULL);
	return  mux;
fail:
	if (mux != NULL) {
		CloseHandle(mux);
	}
	mux = NULL;
	snprintf_safe(&sname,&snamesize,NULL);
	SETERRNO(ret);
	return NULL;
}


int LogMonitor::__alloc_event()
{
	int ret;

	this->__close_event();

	this->m_hmutex = this->__create_mutex_name("DBWinMutex");
	if (this->m_hmutex == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	this->m_dataready = this->__create_event_name("DBWIN_DATA_READY");
	if (this->m_dataready == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	this->m_buffready = this->__create_event_name("DBWIN_BUFFER_READY");
	if (this->m_buffready == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	this->__close_event();
	SETERRNO(ret);
	return ret;
}

int LogMonitor::__map_buff()
{
	int ret;
	char* sname=NULL;
	int snamesize=0;

	if (this->m_global) {
		ret = snprintf_safe(&sname,&snamesize,"Global\\DBWIN_BUFFER");
	} else {
		ret = snprintf_safe(&sname,&snamesize,"DBWIN_BUFFER");
	}
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = map_buffer(sname, WINLIB_MAP_FILE_READ,sizeof(dbwin_buffer_t),&(this->m_mapbuf));
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	snprintf_safe(&sname,&snamesize,NULL);
	return 0;
fail:
	this->__unmap_buf();
	snprintf_safe(&sname,&snamesize,NULL);
	SETERRNO(ret);
	return ret;
}


int LogMonitor::start(void)
{
	int ret;

	/*to remove */
	this->__close_event();
	this->__unmap_buf();
	this->__free_buf();

	ret = this->__alloc_event();
	if (ret < 0){
		GETERRNO(ret);
		goto fail;
	}

	ret = this->__map_buff();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = this->__alloc_buf();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	/*now insert the handle*/
	ret = this->__insert_data_ready_evt();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	/*this would be buffer ready*/
	SetEvent(this->m_buffready);

	return 0;
fail:
	this->__close_event();
	this->__unmap_buf();
	this->__free_buf();
	SETERRNO(ret);
	return ret;
}


int LogMonitor::__data_ready_impl(void)
{
	int ret;
	LogCallback* pcallback;
	ASSERT_IF(this->m_mapbuf != NULL);
	DEBUG_INFO("data ready in");

	ret = read_buffer(this->m_mapbuf,sizeof(DWORD), this->m_pcurdata,this->m_cursize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (this->m_pcallback) {
		DWORD i;
		this->m_curlen = (int)strlen(this->m_pcurdata);
		for (i=0;i<this->m_pcallback->size();i++) {
			pcallback = this->m_pcallback->at(i);
			ret = pcallback->handle_log_buffer(this->m_pcurdata, this->m_curlen);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}
	}

	/*now to notify the buff ready*/
	ASSERT_IF(this->m_buffready != NULL);
	DEBUG_INFO("set buff ready");
	SetEvent(this->m_buffready);

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

void LogMonitor::handle_data_ready(HANDLE hd,libev_enum_event_t evt,void* pevmain, void* args)
{
	LogMonitor* pThis = (LogMonitor*) args;
	int ret;
	hd = hd;
	if (evt == normal_event) {
		ret = pThis->__data_ready_impl();
		if (ret < 0) {
			ret = pThis->start();
			if (ret < 0) {
				libev_break_winev_loop(pevmain);
			}
		}
	} else {
		ret = pThis->start();
		if (ret < 0) {
			libev_break_winev_loop(pevmain);
		}
	}
	return;
}