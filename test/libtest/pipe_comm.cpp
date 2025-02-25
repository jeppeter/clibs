#include "pipe_comm.h"


pipe_comm::pipe_comm(void* ppipe,char* pipename)
{
	this->m_pipe = ppipe;
	this->m_pipename = _strdup(pipename);	
}

void pipe_comm::__uninit()
{
	return;
}

pipe_comm::~pipe_comm()
{
	if (this->m_inited != 0) {
		this->__uninit();
		this->m_inited = 0;
	}
	close_namedpipe(&(this->m_pipe));
	if (this->m_pipename) {
		free(this->m_pipename);
	}
	this->m_pipename = NULL;
}

int pipe_comm::init()
{
	int ret=0;
	if (this->m_pipename == NULL) {
		ret = -ERROR_NOT_ENOUGH_MEMORY;
		SETERRNO(ret);
		return ret;
	}
	if (this->m_inited == 0) {
		this->m_inited = 1;
		ret = 1;
	}
	return ret;
fail:
	this->__uninit();
	SETERRNO(ret);
	return ret;
}

int pipe_comm::is_read_mode()
{
	int ret =0;
	if (this->m_inited != 0) {
		ret = get_namedpipe_rdstate(this->m_pipe);
	}
	return ret;
}

int pipe_comm::is_write_mode()
{
	int ret =0;
	if (this->m_inited != 0) {
		ret = get_namedpipe_wrstate(this->m_pipe);
	}
	return ret;
}

HANDLE pipe_comm::get_read_evt()
{
	HANDLE hret = NULL;
	if (this->m_inited != 0) {
		hret = get_namedpipe_rdevt(this->m_pipe);
	}
	return hret;
}

HANDLE pipe_comm::get_write_evt()
{
	HANDLE hret = NULL;
	if (this->m_inited != 0) {
		hret = get_namedpipe_wrevt(this->m_pipe);
	}
	return hret;
}

int pipe_comm::read_json(jvalue** ppj)
{
	int ret;
	if (ppj == NULL || *ppj != NULL) {
		ret  =-ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}
	if (this->m_inited == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	if (this->is_read_mode()) {
		ret = this->complete_read();
		if (ret < 0) {
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;
		} else if (ret == 0) {
			return 0;
		}
		rdlen = this->__get_json_size();
		if (this->m_rdlen == rdlen) {
			
		}
	}
}