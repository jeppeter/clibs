#include "pipe_comm.h"
#include <win_namedpipe.h>

#define  PROTO_HDR_SIZE          4
#define  MINI_BUF_SIZE           512

#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(push)
#pragma warning(disable:5045)
#pragma warning(disable:4530)
#endif
#endif /* _MSC_VER*/


pipe_comm::pipe_comm(void* ppipe,char* pipename)
{
	this->m_pipe = ppipe;
	this->m_pipename = _strdup(pipename);	
	this->m_prdbuf = NULL;
	this->m_rdlen = 0;
	this->m_rdsize = 0;
	this->m_needlen = 0;

	this->m_pbufs= NULL;
	this->m_pbuflens = NULL;
	this->m_pwrbuf = NULL;
	this->m_wrlen = 0;

	this->m_inited = 0;
}

void pipe_comm::__uninit()
{
	if (this->m_prdbuf) {
		free(this->m_prdbuf);
	}
	this->m_prdbuf = NULL;
	this->m_rdlen = 0;
	this->m_needlen = 0;
	this->m_rdsize = 0;

	if (this->m_pbufs && this->m_pbuflens) {
		ASSERT_IF(this->m_pbufs->size() == this->m_pbuflens->size());
		while(this->m_pbufs->size() > 0) {
			char* pbuf = this->m_pbufs->at(0);
			int buflen = this->m_pbuflens->at(0);
			this->m_pbufs->erase(this->m_pbufs->begin());
			this->m_pbuflens->erase(this->m_pbuflens->begin());
			free(pbuf);
			pbuf = NULL;
			buflen = 0;
		}
	}

	if (this->m_pbufs) {
		delete this->m_pbufs;
	}
	this->m_pbufs = NULL;

	if (this->m_pbuflens) {
		delete this->m_pbuflens;
	}
	this->m_pbuflens = NULL;

	if (this->m_pwrbuf) {
		free(this->m_pwrbuf);
	}
	this->m_pwrbuf = NULL;
	this->m_wrlen = 0;
	return;
}

pipe_comm::~pipe_comm()
{
	close_namedpipe(&(this->m_pipe));
	if (this->m_inited != 0) {
		this->__uninit();
		this->m_inited = 0;
	}
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
		this->m_rdsize = MINI_BUF_SIZE;
		this->m_prdbuf = (char*)malloc((size_t)this->m_rdsize);
		if (this->m_prdbuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		this->m_rdlen = 0;
		this->m_needlen = 0;

		this->m_pbufs = new std::vector<char*>();
		this->m_pbuflens = new std::vector<int>();

		this->m_pwrbuf = NULL;
		this->m_wrlen = 0;

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

int pipe_comm::__get_json_size()
{
	uint32_t retval = 0;
	int i;
	for(i=0;i<4;i++) {
		retval |= ((uint32_t)this->m_prdbuf[i] << (i*8));
	}
	return (int) retval;
}

int pipe_comm::__inner_read()
{
	int ret;
	char* ptmp=NULL;
	if (this->m_rdlen < PROTO_HDR_SIZE) {
		this->m_needlen = PROTO_HDR_SIZE;
		DEBUG_INFO("m_prdbuf %p read %p",this->m_prdbuf,&(this->m_prdbuf[this->m_rdlen]));
		ret = read_namedpipe(this->m_pipe,&(this->m_prdbuf[this->m_rdlen]),(this->m_needlen - this->m_rdlen));
		if (ret < 0) {
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;
		} else if (ret == 0) {
			return 0;
		}
		this->m_rdlen = this->m_needlen;
	}
	this->m_needlen = this->__get_json_size();
	if (this->m_needlen >= this->m_rdsize) {
		this->m_rdsize = this->m_needlen + 1;
		ptmp = (char*)malloc((size_t)this->m_rdsize);
		if (ptmp == NULL) {
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;
		}
		if (this->m_rdlen > 0) {
			memcpy(ptmp,this->m_prdbuf,(size_t)this->m_rdlen);
		}
		if (this->m_prdbuf) {
			free(this->m_prdbuf);
		}
		this->m_prdbuf = ptmp;
		ptmp = NULL;		
	}

	if (this->m_rdlen < this->m_needlen) {
		DEBUG_INFO("m_prdbuf %p read %p",this->m_prdbuf,&(this->m_prdbuf[this->m_rdlen]));
		ret = read_namedpipe(this->m_pipe,&(this->m_prdbuf[this->m_rdlen]), (this->m_needlen - this->m_rdlen));
		if (ret < 0) {
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;
		} else if (ret == 0) {
			return 0;
		}
		this->m_rdlen = this->m_needlen;
		this->m_prdbuf[this->m_rdlen] = '\0';
		DEBUG_BUFFER_FMT(this->m_prdbuf,this->m_rdlen,"rdlen %d",this->m_rdlen);
	}
	return 1;
}

int pipe_comm::complete_read()
{
	int ret;
	if (this->m_inited == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	if (this->is_read_mode() == 0) {
		return 1;
	}
	ret = complete_namedpipe_rdpending(this->m_pipe);
	if (ret < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	} else if (ret > 0) {
		this->m_rdlen = this->m_needlen;
	}
	return ret;

}


int pipe_comm::read_json(jvalue** ppj)
{
	int ret;
	int rdlen;
	unsigned int jsonsize=0;
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
		ASSERT_IF(this->m_rdlen >= PROTO_HDR_SIZE);
		rdlen = this->__get_json_size();
		if (this->m_rdlen < rdlen) {
			/*ok this is we try*/
			this->m_needlen = rdlen;
			ret=  this->__inner_read();
			if (ret < 0) {
				GETERRNO(ret);
				SETERRNO(ret);
				return ret;				
			} else if (ret == 0) {
				return 0;
			}
		}
		DEBUG_BUFFER_FMT(this->m_prdbuf,this->m_rdlen,"read buffer");
	} else {
		ret = this->__inner_read();
		if (ret < 0) {
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;				
		} else if (ret == 0) {
			return 0;
		}
		DEBUG_BUFFER_FMT(this->m_prdbuf,this->m_rdlen,"read buffer");
	}

	*ppj = jvalue_read(&(this->m_prdbuf[PROTO_HDR_SIZE]),&jsonsize);
	if (*ppj == NULL) {
		GETERRNO(ret);
		DEBUG_BUFFER_FMT(this->m_prdbuf,this->m_rdlen+1,"error buffer");
		SETERRNO(ret);
		return ret;
	}
	/*now we change the buffer*/
	this->m_rdlen = 0;
	this->m_needlen = 0;
	return 1;
}

int pipe_comm::__inner_write()
{
	int ret;
	ASSERT_IF(this->is_write_mode() == 0);
write_again:
	if (this->m_pwrbuf == NULL) {
		return 1;
	}
	ret = write_namedpipe(this->m_pipe,this->m_pwrbuf,this->m_wrlen);
	if (ret < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	} else if (ret == 0){
		return 0;
	}
	/*free this*/
	free(this->m_pwrbuf);
	this->m_pwrbuf = NULL;
	this->m_wrlen = 0;
	if (this->m_pbufs->size() > 0) {
		this->m_pwrbuf = this->m_pbufs->at(0);
		this->m_wrlen = this->m_pbuflens->at(0);
		this->m_pbufs->erase(this->m_pbufs->begin());
		this->m_pbuflens->erase(this->m_pbuflens->begin());
	}
	goto write_again;
}

int pipe_comm::write_json(jvalue* pj)
{
	int ret;
	char* jsonstr=NULL;
	unsigned int jsonsize=0;
	char* pwrbuf=NULL;
	int wrlen=0;
	int i;
	if (this->m_inited == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}

	jsonstr = jvalue_write(pj,&jsonsize);
	if (jsonstr == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	wrlen = (int)(jsonsize + PROTO_HDR_SIZE + 1);
	pwrbuf = (char*)malloc((size_t)wrlen);
	if (pwrbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	memset(pwrbuf,0,(size_t)wrlen);
	for(i=0;i<4;i++) {
		pwrbuf[i] = (char)((wrlen >> (i*8)) & 0xff);
	}
	memcpy(&(pwrbuf[4]),jsonstr,jsonsize);
	/*to free the buffer*/
	free(jsonstr);
	jsonstr = NULL;
	jsonsize = 0;

	if (this->m_pwrbuf == NULL) {
		this->m_pwrbuf = pwrbuf;
		this->m_wrlen = wrlen;
		pwrbuf = NULL;
		wrlen = 0;
		ret = this->__inner_write();
		if (ret < 0) {
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;
		} else if (ret == 0) {
			return 0;
		}
	} else {
		this->m_pbufs->push_back(pwrbuf);
		this->m_pbuflens->push_back(wrlen);
		pwrbuf = NULL;
		wrlen = 0;
		return 0;
	}


	return 1;
fail:
	if (jsonstr) {
		free(jsonstr);
	}
	jsonstr = NULL;
	if (pwrbuf) {
		free(pwrbuf);
	}
	pwrbuf = NULL;
	SETERRNO(ret);
	return ret;
}

int pipe_comm::complete_write()
{
	int ret;
	if (this->m_inited == 0) {
		ret = -ERROR_NOT_READY;
		SETERRNO(ret);
		return ret;
	}
	if (this->is_write_mode() == 0) {
		return 1;
	}
	ret = complete_namedpipe_wrpending(this->m_pipe);
	if (ret < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	} else if (ret == 0) {
		return 0;
	}
	ASSERT_IF(this->m_pwrbuf != NULL);
	free(this->m_pwrbuf);
	this->m_pwrbuf = NULL;
	this->m_wrlen = 0;
	if (this->m_pbufs->size() > 0) {
		this->m_pwrbuf = this->m_pbufs->at(0);
		this->m_wrlen = this->m_pbuflens->at(0);
		this->m_pbufs->erase(this->m_pbufs->begin());
		this->m_pbuflens->erase(this->m_pbuflens->begin());
	}
	/*we to give the write*/
	return this->__inner_write();
}

#ifdef  _MSC_VER
#if  _MSC_VER >= 1929
#pragma warning(pop)
#endif
#endif /* _MSC_VER*/
