#include <log_file.h>


LogFileCallback::LogFileCallback(void* pevmain,char* filename,int appendmode) 
{
	this->m_pemain = pevmain;
	this->m_pwritebufs = NULL;
	this->m_pwritelen = NULL;
	this->m_name = NULL;
	if (filename) {
		this->m_name  = strdup(filename);	
	}
	this->m_curbuf = NULL;
	this->m_curlen = 0;
	this->m_hfile = NULL;
	memset(&(this->m_ov),0, sizeof(this->m_ov));
	this->m_inserted = 0;
	this->m_appended = appendmode;
	this->m_isoverlapped = 0;
}

void LogFileCallback::__remove_write_handle(void)
{
	int ret;
	if (this->m_inserted) {
		ret = libev_remove_handle(this->m_pemain,this->m_ov.hEvent);
		ASSERT_IF(ret > 0);
		this->m_inserted = 0;
	}
}

void LogFileCallback::__free_write_buf(void)
{
	if(this->m_curbuf) {
		free(this->m_curbuf);
		this->m_curbuf = NULL;
	}
	this->m_curlen = 0;
	this->m_cursize = 0;
	return ;
}

int LogFileCallback::__pick_write_buf()
{
	int ret = 0;
	this->__free_write_buf();

	if (this->m_pwritebufs != NULL &&
		this->m_pwritelen != NULL) {
		ASSERT_IF(this->m_pwritebufs->size() == 
				this->m_pwritelen->size());
		if (this->m_pwritebufs->size() > 0) {
			this->m_curbuf = this->m_pwritebufs->at(0);
			this->m_cursize = this->m_pwritelen->at(0);
			this->m_curlen = 0;
			this->m_pwritebufs->erase(this->m_pwritebufs->begin());
			this->m_pwritelen->erase(this->m_pwritelen->begin());
			ret = 1;
		}
	}
	return ret;
}


LogFileCallback::~LogFileCallback()
{
	int ret;
	this->__remove_write_handle();

	while(1) {
		ret = this->__pick_write_buf();
		if (ret == 0) {
			break;
		}
	}
	this->__free_write_buf();
	if (this->m_pwritebufs) {
		delete this->m_pwritebufs;
		this->m_pwritebufs = NULL;
	}

	if (this->m_pwritelen) {
		delete this->m_pwritelen;
		this->m_pwritelen = NULL;
	}

	this->__close_file();

	if (this->m_name) {
		free(this->m_name);
		this->m_name = NULL;
	}

	this->m_pemain = NULL;
}

void LogFileCallback::__close_file()
{
	if (this->m_isoverlapped) {
		ASSERT_IF(this->m_hfile != NULL);
		ASSERT_IF(this->m_ov.hEvent != NULL);
		bret = CancelIoEx(this->m_hfile,&(this->m_ov));
		if (!bret) {
			GETERRNO(ret);
			ERROR_INFO_FILE("can not cancel file handle");
		}
		this->m_isoverlapped = 0;
	}

	if (this->m_ov.hEvent != NULL) {
		CloseHandle(this->m_ov.hEvent);
		this->m_ov.hEvent = NULL;
	}
	memset(&(this->m_ov),0, sizeof(this->m_ov));


	if (this->m_hfile) {
		CloseHandle(this->m_hfile);
		this->m_hfile = NULL;
	}
	return;
}

int LogFileCallback::__reopen_file()
{
	int ret;
	DWORD rwflag = 0;
	TCHAR* ptname=NULL;
	int tnamesize=0;


	/*to make start*/
	this->m_curlen = 0;

	if (this->m_name == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	if (this->m_appended) {
		rwflag = FILE_APPEND_DATA;
	} else {
		rwflag = GENERIC_WRITE;
	}

	ret = AnsiToTchar(this->m_name, &ptname,&tnamesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	this->m_hfile = CreateFile(ptname,rwflag,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_FLAG_OVERLAPPED,NULL);
	if (this->m_hfile == INVALID_HANDLE_VALUE) {
		GETERRNO(ret);
		this->m_hfile = NULL;
		ERROR_INFO_FILE("can not open [%s] file error[%d]", this->m_name, ret);
		goto fail;
	}
	memset(&(this->m_ov),0 ,sizeof(this->m_ov));
	this->m_ov.hEvent = CreateEvent(NULL,TRUE,TRUE,NULL);
	if (this->m_ov.hEvent == NULL) {
		GETERRNO(ret);
		ERROR_INFO_FILE("can not create event for [%s] error[%d]", this->m_name, ret);
		goto fail;
	}

	AnsiToTchar(NULL,&ptname,&tnamesize);
	return 0;
fail:
	this->__close_file();
	AnsiToTchar(NULL,&ptname,&tnamesize);
	SETERRNO(ret);
	return ret;
}

int LogFileCallback::__insert_write_handle()
{
	int ret;
	ASSERT_IF(this->m_inserted == 0);
	ret = libev_insert_handle(this->m_pemain,this->m_ov.hEvent,LogFileCallback::__log_file_write,this,1000);
	ASSERT_IF(ret > 0);
	this->m_inserted = 1;
	return 0;
}

int LogFileCallback::__write_buffer()
{
	BOOL bret;
	int ret;
	DWORD cbret;
	int curlen = this->m_curlen;

	while(curlen < this->m_cursize) {
		bret = WriteFile(this->m_hfile,&(this->m_curbuf[curlen]),this->m_cursize,&cbret,&(this->m_ov));
		if (!bret) {
			GETERRNO(ret);
			if (ret != -ERROR_IO_PENDING) {
				ERROR_INFO_FILE("can not write [%s] for [%s] error[%d]", this->m_name,this->m_curbuf, ret);
				goto fail;
			}
			this->m_curlen = curlen;
			return 0;
		} 
		curlen += cbret;
	}
	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int LogFileCallback::__start_write()
{
	int ret;
	/*to not start handle*/
	this->__remove_write_handle();
	if (this->m_curbuf == NULL) {
		this->__pick_write_buf();
	}
	/*now to give the write*/
	if (this->m_curbuf == NULL) {
		return 0;
	}

write_again:
	ret = this->__write_buffer();
	if (ret > 0) {
		ret = this->__pick_write_buf();
		if (ret > 0) {
			goto write_again;
		}
		return 0;
	} else if (ret < 0) {
		return ret;
	}
	/*now this is in io pending */
	this->m_isoverlapped = 1;
	return this->__insert_write_handle();
}

int LogFileCallback::__log_file_impl()
{
	BOOL bret;
	DWORD cbret;
	bret =GetOverlappedResult(this->m_hfile,&(this->m_ov),&cbret,FALSE);
	if (!bret) {
		GETERRNO(ret);
		if (ret != -ERROR_IO_PENDING) {
			ERROR_INFO_FILE("can not get [%s] result error[%d]", this->m_name, ret);
			goto fail;
		}
		return 0;
	}

	this->m_curlen += cbret;
	if (this->m_cursize == this->m_curlen) {
		/*this is ok */
		this->m_isoverlapped = 0;
		this->__free_write_buf();
		return this->__start_write();
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}


void LogFileCallback::__log_file_write(HANDLE hd,libev_enum_event_t evt,void* pevmain, void* args)
{
	int ret;
	LogFileCallback* pThis = (LogFileCallback*) args;
	if (evt == normal_event) {
		ret = pThis->__log_file_impl();
		if (ret < 0) {
		re_open:
			ret = pThis->__reopen_file();
			if (ret < 0) {
				libev_break_winev_loop(pevmain);
			} else {
				ret= pThis->__start_write();
				if (ret < 0) {
					libev_break_winev_loop(pevmain);
				}
			}
		} else {
			ret = pThis->__start_write();
			if (ret < 0) {
				goto re_open;
			}
		}
	} else if (evt == timeout_event) {
		/*this reopen it */
		goto re_open;
	} else {
		libev_break_winev_loop(pevmain);
	}
	return ;
}

int LogFileCallback::__alloc_vecs()
{
	if (this->m_pwritebufs == NULL)  {
		this->m_pwritebufs = new std::vector<char*>();
	}

	if (this->m_pwritelen == NULL) {
		this->m_pwritelen = new std::vector<int>();
	}
	return 0;
}

int LogFileCallback::start()
{
	int ret;

	ret = this->__alloc_vecs();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = this->__reopen_file();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = this->__start_write();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;

fail:
	this->__close_file();
	SETERRNO(ret);
	return ret;
}

int LogFileCallback::handle_log_buffer(char* pbuf,int buflen)
{
	char* pnewbuf=NULL;
	int newlen =0;
	int ret;

	if (this->m_hfile == NULL || this->m_pwritebufs == NULL ||
		this->m_pwritelen == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	pnewbuf = (char*)malloc(buflen);
	if (pnewbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	newlen = buflen;
	memcpy(pnewbuf, pbuf,buflen);
	if (this->m_curbuf == NULL) {
		/*nothing wait to write ,so just start write*/
		this->m_curbuf = pnewbuf;
		this->m_cursize = newlen;
		this->m_curlen = 0;
		return this->__start_write();
	}

	this->m_pwritebufs->push_back(pnewbuf);
	this->m_pwritelen->push_back(newlen);

	return 0;
fail:
	if (pnewbuf) {
		free(pnewbuf);
	}
	pnewbuf = NULL;
	SETERRNO(ret);
	return ret;
}