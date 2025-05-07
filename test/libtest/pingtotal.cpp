#include <win_err.h>

#include "pingtotal.h"


#pragma warning(push)
#pragma warning(disable:5045)

PingTotal::PingTotal(int timeout,int nexttime,int times,int verbose)
{
	this->m_verbose = verbose;
	this->m_timeout = timeout;
	this->m_nexttime = nexttime;
	this->m_times = times;
	this->m_vec = NULL;
	this->m_ipvec = NULL;
}

PingTotal::~PingTotal()
{
	if (this->m_ipvec) {
		while(this->m_ipvec->size() > 0) {
			char* ip = this->m_ipvec->at(0);
			this->m_ipvec->erase(this->m_ipvec->begin());
			free(ip);
		}
		delete this->m_ipvec;
	}
	this->m_ipvec = NULL;

	if (this->m_vec) {
		while(this->m_vec->size() > 0) {
			PingCap* p = this->m_vec->at(0);
			this->m_vec->erase(this->m_vec->begin());
			delete p;
			p = NULL;
		}
		delete this->m_vec;
	}
	this->m_vec = NULL;
}


int PingTotal::add_host(const char* ip)
{
	PingCap* pv=NULL;
	int ret;
	char* newip=NULL;
	if (this->m_vec == NULL) {
		this->m_vec = new std::vector<PingCap*>();
	}

	if (this->m_ipvec == NULL) {
		this->m_ipvec = new std::vector<char*>();
	}

	ASSERT_IF(this->m_ipvec->size() == this->m_vec->size());

	newip = _strdup(ip);
	if (newip == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	pv = new PingCap(ip,this->m_timeout,this->m_nexttime,this->m_times);
	ret = pv->set_verbose(this->m_verbose);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ret = pv->start();
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	this->m_vec->push_back(pv);
	this->m_ipvec->push_back(newip);
	pv = NULL;
	newip = NULL;
	return 1;
fail:
	if (newip) {
		free(newip);
	}
	newip = NULL;

	if (pv) {
		delete pv;
	}
	pv = NULL;
	SETERRNO(ret);
	return ret;
}

int PingTotal::get_mean(int idx, char** ppipstr,uint64_t* pval)
{
	int ret;
	PingCap* pv=NULL;
	uint64_t cval;
	char* newstr=NULL;

	if (idx < 0) {
		if (ppipstr && *ppipstr) {
			free(*ppipstr);
			*ppipstr = NULL;
		}
		if (pval) {
			*pval = 0;
		}
		return 0;
	}

	if (ppipstr == NULL || pval == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (this->m_ipvec == NULL || (int)this->m_ipvec->size() <= idx) {
		return 0;
	}
	pv = this->m_vec->at((uint64_t)idx);
	newstr = this->m_ipvec->at((uint64_t)idx);
	ret = pv->get_mean_result(cval);

	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (ppipstr && *ppipstr) {
		free(*ppipstr);
		*ppipstr = NULL;
	}

	*ppipstr = _strdup(newstr);
	if (*ppipstr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	*pval = cval;
	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

int PingTotal::__min2(int a, int b)
{
	int retval = a;
	if (b < a) {
		retval = b;
	}
	return retval;
}


int PingTotal::loop(HANDLE exithd)
{
	int ret;
	HANDLE *hdls= NULL;
	DWORD waitnum=0;
	int maxsize=0;
	DWORD maxtime;
	PingCap* pv;
	int nextones=0;
	uint64_t i;
	int mode;
	int timeval;
	DWORD dret;
	HANDLE curhd;
	int timeout=0;
	maxsize = 1;
	if (this->m_vec) {
		maxsize += (int)(this->m_vec->size() * 2);
	}

	hdls = (HANDLE*)malloc(sizeof(*hdls) * maxsize);
	if (hdls == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	while(1) {
		maxtime = (DWORD)this->m_timeout;
		nextones = 0;
		waitnum = 0;
		hdls[waitnum] = exithd;
		waitnum += 1;

		for(i=0;i < this->m_vec->size();i ++) {
			pv = this->m_vec->at(i);
	get_next_mode:
			timeout = 0;
			mode = pv->get_mode();
			if ((mode & START_MODE) != 0 || (mode & EXPIRE_MODE) != 0) {
				if ((mode & EXPIRE_MODE) != 0) {
					timeout = 1;
				}
				ret = pv->restart(timeout);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				goto get_next_mode;
			}

			if ((mode & READ_MODE) != 0) {
				hdls[waitnum] = pv->get_read_evt();
				if (hdls[waitnum] != NULL) {
					waitnum += 1;
					timeval = pv->get_expire();
					maxtime = (DWORD)this->__min2(timeval,(int)maxtime);	
				}

			}

			if ((mode & WRITE_MODE) != 0) {
				hdls[waitnum] = pv->get_write_evt();
				if (hdls[waitnum] != NULL) {
					waitnum += 1;
					timeval = pv->get_expire();
					maxtime = (DWORD)this->__min2(timeval,(int)maxtime);	
				}
			}


			if ((mode & NEXT_MODE) != 0) {
				nextones += 1;
				timeval = pv->get_next_expire();
				maxtime =(DWORD) this->__min2(timeval,(int)maxtime);
			}
		}

		if (waitnum == 1) {
			if (nextones == 0) {
				break;
			}
		}

		DEBUG_INFO("waitnum %d maxtime %d", waitnum, maxtime);
		dret = WaitForMultipleObjectsEx(waitnum,hdls,FALSE,(DWORD)maxtime,FALSE);
		if (dret < (WAIT_OBJECT_0 + waitnum)) {
			curhd = hdls[(dret - WAIT_OBJECT_0)];
			if (curhd == exithd) {
				DEBUG_INFO(" ");
				break;
			} else {
				if (this->m_vec) {
					for(i=0;i<this->m_vec->size();i++) {
						pv = this->m_vec->at(i);
						if (pv->get_read_evt() == curhd) {
							ret = pv->complete_read_evt();
							if (ret < 0) {
								GETERRNO(ret);
								DEBUG_INFO(" ");
								goto fail;
							} 
						} else if (pv->get_write_evt() == curhd) {
							ret = pv->complete_write_evt();
							if (ret < 0) {
								GETERRNO(ret);
								DEBUG_INFO(" ");
								goto fail;
							}
						}
					}
				}
			}

		} else if (dret == WAIT_TIMEOUT) {
			continue;
		} else {
			GETERRNO(ret);
			ERROR_INFO("wait error %ld %d", dret,ret);
			goto fail;
		}
	}

	if (hdls) {
		free(hdls);
	}
	hdls = NULL;
	return 1;
fail:
	if (hdls) {
		free(hdls);
	}
	hdls = NULL;
	SETERRNO(ret);
	return ret;
}

int PingTotal::get_succ_ratio(int idx, char** ppipstr,double* pratio)
{
	int ret;
	double rd;
	PingCap* pv=NULL;
	char* newstr=NULL;
	if (idx < 0) {
		if (ppipstr && *ppipstr) {
			free(*ppipstr);
			*ppipstr = NULL;
		}
		if (pratio) {
			*pratio = 0.0;
		}
		return 0;
	}

	if (ppipstr == NULL || pratio == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	if (this->m_ipvec == NULL || (int)this->m_ipvec->size() <= idx) {
		return 0;
	}
	pv = this->m_vec->at((uint64_t)idx);
	newstr = this->m_ipvec->at((uint64_t)idx);
	rd = pv->get_succ_ratio();

	if (ppipstr && *ppipstr) {
		free(*ppipstr);
		*ppipstr = NULL;
	}

	*ppipstr = _strdup(newstr);
	if (*ppipstr == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	*pratio = rd;
	return 1;
fail:
	SETERRNO(ret);
	return ret;
}

#pragma warning(pop)