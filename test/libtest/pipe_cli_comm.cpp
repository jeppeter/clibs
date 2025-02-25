#include "pipe_cli_comm.h"
#include <win_namedpipe.h>

#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(push)
#pragma warning(disable:5045)
#pragma warning(disable:4530)
#endif
#endif /* _MSC_VER*/

pipe_cli_comm::pipe_cli_comm(char* pipename,int timeout)
{
	this->m_pipename = _strdup(pipename);
	this->m_timeout = timeout;
	this->m_inited = 0;
	this->m_pipe = NULL;
}

void pipe_cli_comm::__uninit()
{
	if (this->m_pipe) {
		delete this->m_pipe;
	}
	this->m_pipe = NULL;
	return ;	
}

pipe_cli_comm::~pipe_cli_comm()
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



int pipe_cli_comm::init()
{
	int ret = 0;
	if (this->m_pipename == NULL) {
		ret = -ERROR_NOT_ENOUGH_MEMORY;
		SETERRNO(ret);
		return ret;
	}

	if (this->m_inited == 0) {
		void* pipe = connect_namedpipe_timeout(this->m_pipename,this->m_timeout);
		if (pipe == NULL) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
		}
		this->m_pipe = new pipe_comm(pipe,this->m_pipename);
		pipe = NULL;
		ret = this->m_pipe->init();
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO(" ");
			goto fail;
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

int pipe_cli_comm::is_read_mode()
{
	int ret = 0;
	if (this->m_inited && this->m_pipe) {
		ret = this->m_pipe->is_read_mode();
	}
	return ret;
}

int pipe_cli_comm::is_write_mode()
{
	int ret = 0;
	if (this->m_inited && this->m_pipe) {
		ret = this->m_pipe->is_write_mode();
	}
	return ret;
}

int pipe_cli_comm::complete_read()
{
	int ret;
	if (this->m_inited == 0 || this->m_pipe == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_pipe->complete_read();
}

int pipe_cli_comm::complete_write()
{
	int ret;
	if (this->m_inited == 0 || this->m_pipe == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_pipe->complete_write();
}

int pipe_cli_comm::read_json(jvalue** ppj)
{
	int ret;
	if (this->m_inited == 0 || this->m_pipe == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_pipe->read_json(ppj);
}


int pipe_cli_comm::write_json(jvalue* pj)
{
	int ret;
	if (this->m_inited == 0 || this->m_pipe == NULL) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	return this->m_pipe->write_json(pj);
}

HANDLE pipe_cli_comm::get_read_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited && this->m_pipe) {
		hret = this->m_pipe->get_read_evt();
	}
	return hret;
}

HANDLE pipe_cli_comm::get_write_evt()
{
	HANDLE hret =NULL;
	if (this->m_inited && this->m_pipe) {
		hret = this->m_pipe->get_write_evt();
	}
	return hret;
}


#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(pop)
#endif
#endif /* _MSC_VER*/