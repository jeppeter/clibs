#include "pipe_svr_comm.h"
#include <win_namedpipe.h>

#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(push)
#pragma warning(disable:5045)
#pragma warning(disable:4530)
#endif
#endif /* _MSC_VER*/

pipe_svr_comm::pipe_svr_comm(char* pipename)
{
	this->m_pipename = _strdup(pipename);
	this->m_inited = 0;
	this->m_pipe = NULL;
	this->m_realpipe = NULL;
}

void pipe_svr_comm::__uninit()
{
	if (this->m_pipe != NULL) {
		DEBUG_INFO("close [%s] pipe", this->m_pipename);
	}
	if (this->m_realpipe) {
		DEBUG_INFO("close realpipe [%s]", this->m_pipename);
	}
	close_namedpipe(&(this->m_realpipe));
	if (this->m_pipe) {
		delete this->m_pipe;
	}
	this->m_pipe = NULL;
	return ;	
}

pipe_svr_comm::~pipe_svr_comm()
{
	if (this->m_inited) {
		this->__uninit();
		this->m_inited = 0;
	}
	if (this->m_pipename) {
		free(this->m_pipename);
	}
	this->m_pipename = NULL;	
}

int pipe_svr_comm::is_accept_mode()
{
	int ret =0;
	if (this->m_inited && this->m_realpipe) {
		ret = get_namedpipe_connstate(this->m_realpipe);
	}
	return ret;
}

int pipe_svr_comm::complete_accept()
{
	int ret;
	if (this->m_inited == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	if (this->is_accept_mode() == 0) {
		return 1;
	}
	ret = complete_namedpipe_connpending(this->m_realpipe);
	if (ret < 0 ){
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	} else if (ret == 0) {
		return 0;
	}
	this->m_pipe = new pipe_comm(this->m_realpipe, this->m_pipename);
	this->m_realpipe = NULL;
	ret = this->m_pipe->init();
	if (ret < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	}
	return 1;
}


int pipe_svr_comm::init()
{
	int ret = 0;
	if (this->m_pipename == NULL) {
		ret = -ERROR_NOT_ENOUGH_MEMORY;
		SETERRNO(ret);
		return ret;
	}

	if (this->m_inited == 0) {
		this->m_realpipe = bind_namedpipe(this->m_pipename);
		if (this->m_realpipe == NULL) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
		ret = get_namedpipe_connstate(this->m_realpipe);
		if (ret == 0) {
			this->m_pipe = new pipe_comm(this->m_realpipe,this->m_pipename);
			this->m_realpipe = NULL;
			ret = this->m_pipe->init();
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO(" ");
				goto fail;
			}
		}

		this->m_inited = 1;
		ret = 1;
	}
	return ret;
fail:
	this->__uninit();
	SETERRNO(ret);
	return ret;
}

int pipe_svr_comm::is_read_mode()
{
	int ret = 0;
	if (this->m_inited && this->m_pipe) {
		ret = this->m_pipe->is_read_mode();
	}
	return ret;
}

int pipe_svr_comm::is_write_mode()
{
	int ret = 0;
	if (this->m_inited && this->m_pipe) {
		ret = this->m_pipe->is_write_mode();
	}
	return ret;
}

int pipe_svr_comm::complete_read()
{
	int ret;
	if (this->m_inited == 0 || this->m_pipe == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_pipe->complete_read();
}

int pipe_svr_comm::complete_write()
{
	int ret;
	if (this->m_inited == 0 || this->m_pipe == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_pipe->complete_write();
}

int pipe_svr_comm::read_json(jvalue** ppj)
{
	int ret;
	if (this->m_inited == 0 || this->m_pipe == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_pipe->read_json(ppj);
}


int pipe_svr_comm::write_json(jvalue* pj)
{
	int ret;
	if (this->m_inited == 0 || this->m_pipe == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_pipe->write_json(pj);
}

HANDLE pipe_svr_comm::get_read_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited && this->m_pipe) {
		hret = this->m_pipe->get_read_evt();
	}
	return hret;
}

HANDLE pipe_svr_comm::get_write_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited && this->m_pipe) {
		hret = this->m_pipe->get_write_evt();
	}
	return hret;
}

HANDLE pipe_svr_comm::get_accept_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited && this->m_realpipe) {
		hret = get_namedpipe_connevt(this->m_realpipe);
	}
	return hret;
}

#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(pop)
#endif
#endif /* _MSC_VER*/