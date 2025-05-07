#include <ux_output_debug.h>
#include <ux_err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "pingtotal.h"


PingTotal::PingTotal(int timeout,int nexttime,int times,int verbose)
{
	this->m_verbose = verbose;
	this->m_timeout = timeout;
	this->m_nexttime = nexttime;
	this->m_times = times;
	this->m_vec = NULL;
	this->m_ipvec = NULL;
	this->m_findmap = NULL;
}

PingTotal::~PingTotal()
{
	if (this->m_findmap) {
		this->m_findmap->clear();
		delete this->m_findmap;
	}
	this->m_findmap = NULL;
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

	newip = strdup(ip);
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

PingCap* PingTotal::__find_pingcap(int fd)
{	
	PingCap* retv= NULL;
	if (this->m_findmap) {
		std::map<int,PingCap*>::iterator res;
		res= this->m_findmap->find(fd);
		if (res != this->m_findmap->end()) {
			retv = res->second;
		}
	}
	return retv;
}

int PingTotal::__insert_pingcap(int fd,PingCap* pv)
{
	if (this->m_findmap == NULL) {
		this->m_findmap = new std::map<int,PingCap*>();
	}
	this->m_findmap->insert({fd,pv});
	return 0;
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
		ret = -EINVAL;
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

	*ppipstr = strdup(newstr);
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


#define REMOVE_EVT(epollfd, fd)                                                                   \
do{                                                                                               \
	struct epoll_event _evt;                                                                      \
	int __ret;                                                                                    \
	memset(&_evt,0,sizeof(_evt));                                                                 \
	_evt.events = 0;                                                                              \
	_evt.events |= EPOLLIN;                                                                       \
	_evt.events |= EPOLLOUT;                                                                      \
	_evt.events |= EPOLLERR;                                                                      \
	__ret = epoll_ctl(epollfd,EPOLL_CTL_DEL,fd,&_evt);                                            \
	if (__ret < 0) {                                                                              \
		GETERRNO(__ret);                                                                          \
		DEBUG_INFO("remove [%d] error %d", fd, __ret);                                            \
	}                                                                                             \
}while(0)

#define  ADD_EVT(epollfd, fd,mode)                                                                \
do{                                                                                               \
	struct epoll_event _evt;                                                                      \
	int __ret;                                                                                    \
	memset(&_evt,0,sizeof(_evt));                                                                 \
	_evt.events = 0;                                                                              \
	if ((mode & READ_MODE) != 0) {                                                                \
		_evt.events |= EPOLLIN;                                                                   \
	}                                                                                             \
	if ((mode & WRITE_MODE) != 0) {                                                               \
		_evt.events |= EPOLLOUT;                                                                  \
	}                                                                                             \
	__ret = epoll_ctl(epollfd,EPOLL_CTL_ADD,fd,&_evt);                                            \
	if (__ret < 0) {                                                                              \
		GETERRNO(__ret);                                                                          \
		DEBUG_INFO("remove [%d] error %d", fd, __ret);                                            \
		ret = __ret;                                                                              \
		goto fail;                                                                                \
	}                                                                                             \
} while(0)

int PingTotal::loop(int exithd)
{
	int ret;
	int maxtime;
	PingCap* pv,*newpv;
	int nextones=0;
	int i;
	int mode;
	int timeval;
	int timeout=0;
	int epollfd = -1;
	struct epoll_event* waitevt=NULL;
	int maxevt=5;
	int retevt;
	int waitnum;
	int fd;
	epollfd = epoll_create1(0);
	if (epollfd < 0) {
		GETERRNO(ret);
		goto fail;
	}

	ADD_EVT(epollfd,exithd,READ_MODE);

	waitevt = (struct epoll_event*) malloc(sizeof(*waitevt) * maxevt);
	if (waitevt == NULL) {
		GETERRNO(ret);
		goto fail;
	}


	while(1) {
		maxtime = this->m_timeout;
		nextones = 0;
		waitnum = 1;



		for(i=0;i < (int)this->m_vec->size();i ++) {
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

			if ((mode & READ_MODE) != 0 || (mode & WRITE_MODE) != 0) {
				fd = pv->get_sock_evt();
				if (fd < 0) {
					REMOVE_EVT(epollfd,fd);
				} else {
					REMOVE_EVT(epollfd,fd);
					ADD_EVT(epollfd,fd,mode);
					newpv=  this->__find_pingcap(fd);
					waitnum += 1;
					if (newpv == NULL) {
						this->__insert_pingcap(fd,pv);
					}
				}
				
			}



			if ((mode & NEXT_MODE) != 0) {
				nextones += 1;
				timeval = pv->get_next_expire();
				maxtime = this->__min2(timeval,maxtime);
			}
		}

		if (waitnum == 1) {
			if (nextones == 0) {
				break;
			}
		}

		DEBUG_INFO("waitnum %d maxtime %d", waitnum, maxtime);
		memset(waitevt,0, sizeof(*waitevt) * maxevt);
		ret= epoll_wait(epollfd,waitevt,maxevt,maxtime);
		if (ret > 0) {
			retevt = ret;
			for(i=0;i<retevt;i++) {
				pv = this->__find_pingcap(waitevt[i].data.fd);
				if (pv != NULL) {
					if ((waitevt[i].events & EPOLLIN) != 0) {
						ret = pv->complete_read_evt();
						if (ret < 0) {
							GETERRNO(ret);
							ERROR_INFO(" ");
							goto fail;
						}
					}

					if ((waitevt[i].events & EPOLLOUT) != 0) {
						ret = pv->complete_write_evt();
						if (ret < 0) {
							GETERRNO(ret);
							ERROR_INFO(" ");
							goto fail;
						}
					}
				} else if (waitevt[i].data.fd == exithd) {
					break;
				}
			}
		} else if (ret == 0) {
			continue;
		} else {
			GETERRNO(ret);
			ERROR_INFO("epoll_wait error %d", ret);
			goto fail;
		}


	}

	if (epollfd >= 0) {
		close(epollfd);
	}
	epollfd = -1;
	if (waitevt) {
		free(waitevt);
	}
	waitevt = NULL;

	return 1;
fail:
	if (epollfd >= 0) {
		close(epollfd);
	}
	epollfd = -1;
	if (waitevt) {
		free(waitevt);
	}
	waitevt = NULL;
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
		ret = -EINVAL;
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

	*ppipstr = strdup(newstr);
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

