class DebugOutIO
{
public:
	virtual ~DebugOutIO() {};
	virtual int write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr) = 0;
	virtual int write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen) = 0;
	virtual int write_buffer(char* pbuf, int buflen) = 0;
	virtual void flush() = 0;
	virtual int set_cfg(OutfileCfg* pcfg) = 0;
	virtual int set_level(int level) = 0;
};

class DebugOutBuffer : public DebugOutIO
{
public:
	DebugOutBuffer();
	virtual ~DebugOutBuffer();
	virtual int write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual int write_buffer(char* pbuf, int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
	virtual int set_level(int level);	
protected:
	int m_level;
	int m_fmtflag;
};


int str_append_vsnprintf_safe(char** ppbuf, int *pbufsize, const char* fmt, va_list ap)
{
	char* pRetBuf = *ppbuf;
	char* pTmpBuf = NULL;
	char* pcurptr = NULL;
	size_t tmpsize;
	size_t retsize = (size_t)(*pbufsize);
	int nret, ret;
	size_t leftsize = retsize;
	size_t cntsize = 0;
	va_list origap;

	if (fmt == NULL) {
		if (*ppbuf) {
			free(*ppbuf);
		}
		*ppbuf = NULL;
		*pbufsize = 0;
		return 0;
	}

	if (pRetBuf == NULL || retsize < 32) {
		if (retsize < 32) {
			retsize = 32;
		}
		pRetBuf = (char*)malloc(retsize);
		if (pRetBuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	if (*ppbuf) {
		cntsize = strlen(*ppbuf);
	}

	if (cntsize > 0  ) {
		if (pRetBuf != *ppbuf) {
			memcpy(pRetBuf, *ppbuf, cntsize);
		}
		pRetBuf[cntsize] = 0x0;
		pcurptr = &(pRetBuf[cntsize]);
		leftsize = retsize - cntsize;
	} else {
		pcurptr = pRetBuf;
		leftsize = retsize;
	}

	va_copy(origap, ap);
try_again:
	va_copy(ap, origap);
	ret = vsnprintf(pcurptr, leftsize - 1, fmt, ap);
	if (ret == -1 || ret >= (int)(leftsize - 1)) {
		tmpsize = retsize << 1;
		pTmpBuf = (char*)malloc(tmpsize);
		if (pTmpBuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}

		if (cntsize > 0 && *ppbuf != NULL) {
			memcpy(pTmpBuf, *ppbuf, cntsize);
			pTmpBuf[cntsize] = 0x0;
			pcurptr = &(pTmpBuf[cntsize]);
			leftsize = tmpsize - cntsize;
		} else {
			pTmpBuf[0] = 0;
			pcurptr = pTmpBuf;
			leftsize = tmpsize;
		}

		if (pRetBuf && pRetBuf != *ppbuf) {
			free(pRetBuf);
		}
		pRetBuf = NULL;
		pRetBuf = pTmpBuf;
		pTmpBuf = NULL;
		retsize = tmpsize;
		tmpsize = 0;
		goto try_again;
	}

	nret = ret + 1;
	nret += (int)cntsize;

	if (*ppbuf && *ppbuf != pRetBuf) {
		free(*ppbuf);
	}
	*ppbuf = pRetBuf;
	*pbufsize = (int)retsize;
	return nret;
fail:
	if (pRetBuf && pRetBuf != *ppbuf) {
		free(pRetBuf);
	}
	pRetBuf = NULL;
	SETERRNO(-ret);
	return ret;
}

int str_append_snprintf_safe(char**ppbuf, int*pbufsize, const char* fmt, ...)
{
	va_list ap;
	if (fmt == NULL) {
		if (*ppbuf) {
			free(*ppbuf);
		}
		*ppbuf = NULL;
		*pbufsize = 0;
		return 0;
	}
	va_start(ap, fmt);
	return str_append_vsnprintf_safe(ppbuf, pbufsize, fmt, ap);
}


int format_out_string(int fmtflag, int addline, char** ppoutstr, int* psize, char* locstr, char* timestr, const char* tagstr, char* msgstr)
{
	int ret;
	int retlen = 0;
	int cnt = 0;
	if (fmtflag < 0) {
		return str_append_snprintf_safe(ppoutstr, psize, NULL);
	}

	if (fmtflag & UXLIB_OUTPUT_LOCATION) {
		ret = str_append_snprintf_safe(ppoutstr, psize, "%s", locstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		cnt ++;
	}

	if (fmtflag & UXLIB_OUTPUT_TIMESTAMP) {
		if (cnt > 0) {
			ret = str_append_snprintf_safe(ppoutstr, psize, " ");
		}
		ret = str_append_snprintf_safe(ppoutstr, psize, "%s", timestr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		cnt ++;
	}

	if (fmtflag & UXLIB_OUTPUT_LEVEL) {
		if (cnt > 0) {
			ret = str_append_snprintf_safe(ppoutstr, psize, " ");
		}
		ret = str_append_snprintf_safe(ppoutstr, psize, "%s", tagstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		cnt ++;
	}

	if (fmtflag & UXLIB_OUTPUT_MSG) {
		if (cnt > 0) {
			ret = str_append_snprintf_safe(ppoutstr, psize, " ");
		}
		ret = str_append_snprintf_safe(ppoutstr, psize, "%s", msgstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		cnt ++;
	}

	if (cnt > 0) {
		if (addline > 0) {
			ret = str_append_snprintf_safe(ppoutstr, psize, "\n");
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}

		retlen = (int)strlen(*ppoutstr);
	}

	return retlen;

fail:
	str_append_snprintf_safe(ppoutstr, psize, NULL);
	SETERRNO(ret);
	return ret;
}

int DebugOutBuffer::write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr)
{
	int retlen = 0;
	int ret;
	char* outstr = NULL;
	int outsize = 0;
	if (this->m_level >=  level) {
		ret = format_out_string(this->m_fmtflag, 1, &outstr, &outsize, locstr, timestr, tagstr, msgstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		retlen = ret;
		if (retlen > 0) {
			ret = this->write_buffer(outstr, retlen);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}
		format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
	}
	this->flush();
	return retlen;
fail:
	format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
	SETERRNO(ret);
	return ret;
}

int DebugOutBuffer::write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen)
{
	int retlen = 0;
	int ret;
	char* outstr = NULL;
	int outsize = 0;
	char* bufstr = NULL;
	int bufsize = 0;
	int outlen = 0;
	int i, lasti;

	uint8_t* pcurptr;
	if (this->m_level >= level) {
		ret = format_out_string(this->m_fmtflag, 0, &outstr, &outsize, locstr, timestr, tagstr, msgstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		retlen = ret;
		if (retlen > 0) {
			ret = this->write_buffer(outstr, retlen);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}
		format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
		if ((this->m_fmtflag & UXLIB_OUTPUT_MSG ) != 0) {
			pcurptr = (uint8_t*)pbuffer;
			lasti = 0;
			for (i = 0; i < buflen; i++) {

				if (outlen > 2000) {
					ret = this->write_buffer(bufstr, outlen);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
					retlen += ret;
					outlen = 0;
					str_append_snprintf_safe(&bufstr, &bufsize, NULL);
				}

				if ((i % 16) == 0) {
					if (i > 0) {
						ret = str_append_snprintf_safe(&bufstr, &bufsize, "    ");
						if (ret < 0) {
							GETERRNO(ret);
							goto fail;
						}

						while (lasti != i) {
							if (pcurptr[lasti] >= ' ' && pcurptr[lasti] <= '~') {
								ret = str_append_snprintf_safe(&bufstr, &bufsize, "%c", pcurptr[lasti]);
							} else {
								ret = str_append_snprintf_safe(&bufstr, &bufsize, ".");
							}
							if (ret < 0) {
								GETERRNO(ret);
								goto fail;
							}
							lasti ++;
						}
					}
					ret = str_append_snprintf_safe(&bufstr, &bufsize, "\n0x%08x:", i);
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
				}

				ret = str_append_snprintf_safe(&bufstr, &bufsize, " 0x%02x", pcurptr[i]);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				outlen = (int)strlen(bufstr);
			}

			if (lasti != buflen) {
				while ((i % 16) != 0) {
					ret =  str_append_snprintf_safe(&bufstr, &bufsize, "     ");
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
					i ++;
				}
				ret = str_append_snprintf_safe(&bufstr, &bufsize, "    ");
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				while (lasti < buflen) {
					if (pcurptr[lasti] >= ' ' && pcurptr[lasti] <= '~') {
						ret = str_append_snprintf_safe(&bufstr, &bufsize, "%c", pcurptr[lasti]);
					} else {
						ret = str_append_snprintf_safe(&bufstr, &bufsize, ".");
					}
					if (ret < 0) {
						GETERRNO(ret);
						goto fail;
					}
					lasti ++;
				}
				outlen = (int)strlen(bufstr);
				ret = this->write_buffer(bufstr, outlen);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				retlen += ret;
			}

		}
		if (retlen > 0) {
			str_append_snprintf_safe(&outstr, &outsize, NULL);
			ret = str_append_snprintf_safe(&outstr, &outsize, "\n");
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			outlen = (int) strlen(outstr);
			ret = this->write_buffer(outstr, outlen);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			retlen += outlen;
		}
	}
	this->flush();

	str_append_snprintf_safe(&bufstr, &bufsize, NULL);
	format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
	return retlen;
fail:
	str_append_snprintf_safe(&bufstr, &bufsize, NULL);
	format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
	SETERRNO(ret);
	return ret;
}


DebugOutBuffer::DebugOutBuffer()
{
	this->m_level = BASE_LOG_ERROR;
	this->m_fmtflag = UXLIB_OUTPUT_ALL_MASK;
}

DebugOutBuffer::~DebugOutBuffer()
{
}



void DebugOutBuffer::flush()
{
	return;
}

int DebugOutBuffer::write_buffer(char* pbuffer, int buflen)
{
	if (pbuffer) {
		pbuffer = pbuffer;
	}
	return buflen;
}


int DebugOutBuffer::set_cfg(OutfileCfg* pcfg)
{
	int ret;
	this->m_level = pcfg->get_level();
	if (this->m_level < 0) {
		ret = -EINVAL;
		goto fail;
	}
	this->m_fmtflag = pcfg->get_format();
	if (this->m_fmtflag < 0) {
		ret = -EINVAL;
		goto fail;
	}
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int DebugOutBuffer::set_level(int level)
{
	int retval = this->m_level;
	this->m_level = level;
	return  retval;
}

class DebugOutStderr : public DebugOutBuffer
{
public:
	DebugOutStderr();
	virtual ~DebugOutStderr();
	virtual int write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual int write_buffer(char* pbuffer , int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
};



DebugOutStderr::DebugOutStderr()
{
	this->m_level = BASE_LOG_ERROR;
	this->m_fmtflag = UXLIB_OUTPUT_ALL_MASK;
}

DebugOutStderr::~DebugOutStderr()
{
	fflush(stderr);
}

void DebugOutStderr::flush()
{
	fflush(stderr);
	return;
}

int DebugOutStderr::set_cfg(OutfileCfg* pcfg)
{
	const char* fname = NULL;
	int maxfiles = 0;
	int type = 0;
	uint64_t size = 0;
	int ret;

	ret = pcfg->get_file_type(fname, type, size, maxfiles);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (fname != NULL || (type & UXLIB_DEBUGOUT_FILE_MASK ) != UXLIB_DEBUGOUT_FILE_STDERR || size != 0 || maxfiles != 0) {
		ret = -EINVAL;
		goto fail;
	}

	ret = this->DebugOutBuffer::set_cfg(pcfg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int DebugOutStderr::write_buffer(char* pbuffer, int buflen)
{
	fprintf(stderr, "%s", pbuffer);
	return buflen;
}

int DebugOutStderr::write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr)
{
	return this->DebugOutBuffer::write_log(level, locstr, timestr, tagstr, msgstr);
}

int DebugOutStderr::write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen)
{
	return this->DebugOutBuffer::write_buffer_log(level, locstr, timestr, tagstr, msgstr, pbuffer, buflen);
}

class DebugOutBackground : public DebugOutBuffer
{
public:
	DebugOutBackground();
	virtual ~DebugOutBackground();
	virtual int write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual int write_buffer(char* pbuffer , int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
private:
	int m_opened;
};

DebugOutBackground::DebugOutBackground()
{
	this->m_level = BASE_LOG_ERROR;
	this->m_fmtflag = UXLIB_OUTPUT_ALL_MASK;
	this->m_opened = 0;
}

DebugOutBackground::~DebugOutBackground()
{
	if (this->m_opened != 0) {
		closelog();
		this->m_opened = 0;
	}
}

void DebugOutBackground::flush()
{
	return;
}

int DebugOutBackground::write_buffer(char* pbuffer, int buflen)
{
    int priority = LOG_ERR;
    if (this->m_opened == 0) {
    	openlog(NULL,LOG_PID,LOG_USER);
    	this->m_opened = 1;
    }

    if (this->m_opened == 0) {
    	return 0;
    }

    switch (this->m_level) {
    case BASE_LOG_FATAL:
        priority = LOG_EMERG;
        break;
    case BASE_LOG_ERROR:
        priority = LOG_ERR;
        break;
    case BASE_LOG_WARN:
        priority = LOG_WARNING;
        break;
    case BASE_LOG_INFO:
        priority = LOG_NOTICE;
        break;
    case BASE_LOG_DEBUG:
        priority = LOG_INFO;
        break;
    case BASE_LOG_TRACE:
        priority = LOG_DEBUG;
        break;
    }

    syslog(priority, "%s", pbuffer);
    return buflen;
}

int DebugOutBackground::write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr)
{
	return this->DebugOutBuffer::write_log(level, locstr, timestr, tagstr, msgstr);
}

int DebugOutBackground::write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen)
{
	return this->DebugOutBuffer::write_buffer_log(level, locstr, timestr, tagstr, msgstr, pbuffer, buflen);
}

int DebugOutBackground::set_cfg(OutfileCfg* pcfg)
{
	const char* fname = NULL;
	int maxfiles = 0;
	int type = 0;
	uint64_t size = 0;
	int ret;

	ret = pcfg->get_file_type(fname, type, size, maxfiles);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (fname != NULL || (type & UXLIB_DEBUGOUT_FILE_MASK) != UXLIB_DEBUGOUT_FILE_BACKGROUND || size != 0 || maxfiles != 0) {
		ret = -EINVAL;
		goto fail;
	}

	ret = this->DebugOutBuffer::set_cfg(pcfg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}


	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

class DebugOutFileTrunc : public DebugOutBuffer
{
public:
	DebugOutFileTrunc();
	virtual ~DebugOutFileTrunc();
	virtual int write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual int write_buffer(char* pbuffer , int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
protected:
	int copy_to_file(char* nfile,char* ofile);
	int open_file_trunc(char* fname);
	int m_fd;
	char* m_name;
	uint64_t m_size;
	uint64_t m_filesize;
};

int DebugOutFileTrunc::copy_to_file(char* nfile,char* ofile)
{
	int ret;
	struct stat statbuf;

	if (nfile == NULL || ofile == NULL) {
		return 0;
	}

	ret = stat(nfile,&statbuf);
	if (ret < 0) {
		GETERRNO(ret);
		if (ret != -ENOENT) {
			/*this not */
			GETERRNO(ret);
			UX_OUTPUT_DEBUG("STATE [%s] error %d", nfile,ret);
			SETERRNO(ret);
			return ret;
		}
	} else {
		/*unlink file*/
		ret = unlink(nfile);
		if (ret < 0) {
			GETERRNO(ret);
			UX_OUTPUT_DEBUG("unlink [%s] error %d", nfile, ret);
			SETERRNO(ret);
			return ret;
		}
	}

	/*to test for old file exists*/
	ret = stat(ofile,&statbuf);
	if (ret < 0) {
		GETERRNO(ret);
		if (ret != -ENOENT) {
			/*this not */
			GETERRNO(ret);
			UX_OUTPUT_DEBUG("ofile [%s] error [%d]", ofile, ret);
			SETERRNO(ret);
			return ret;
		}
		return 0;
	}

	ret = rename(ofile,nfile);
	if (ret < 0) {
		GETERRNO(ret);
		UX_OUTPUT_DEBUG("[%s] => [%s] error %d", ofile, nfile, ret);
		SETERRNO(ret);
		return ret;
	}
	return 1;
}

int DebugOutFileTrunc::open_file_trunc(char* fname)
{
	int ret;
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;

	this->m_fd = open(fname,O_CREAT|O_TRUNC|O_WRONLY);
	if (this->m_fd < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	}
	UX_OUTPUT_DEBUG("[%s] trunc [%d]", this->m_name, this->m_fd);
	this->m_filesize = 0;
	return 0;
}

DebugOutFileTrunc::DebugOutFileTrunc()
{
	this->m_fd = -1;
	this->m_name = NULL;
	this->m_size = 0;
	this->m_filesize = 0;
}

DebugOutFileTrunc::~DebugOutFileTrunc()
{
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	if (this->m_name != NULL) {
		free(this->m_name);
	}
	this->m_name = NULL;
	this->m_size = 0;
	this->m_filesize = 0;
}

int DebugOutFileTrunc::write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr)
{
	return this->DebugOutBuffer::write_log(level, locstr, timestr, tagstr, msgstr);
}

int DebugOutFileTrunc::write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen)
{
	return this->DebugOutBuffer::write_buffer_log(level, locstr, timestr, tagstr, msgstr, pbuffer, buflen);
}

int DebugOutFileTrunc::write_buffer(char* pbuffer , int buflen)
{
	int ret = -1;
	int wlen = 0;
	char* pptr=NULL;
	if (this->m_fd < 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	pptr = pbuffer;
	while(wlen < buflen) {
		ret = write(this->m_fd, pptr, (buflen-wlen));
		if (ret < 0) {
			GETERRNO(ret);
			UX_OUTPUT_DEBUG("[%s].[%d] error [%d]", this->m_name, this->m_fd, ret);
			SETERRNO(ret);
			return ret;
		}
		wlen += ret;
		pptr += ret;
	}

	this->m_filesize += buflen;
	//UX_OUTPUT_DEBUG("write [%s] size 0x%lx", this->m_name, this->m_filesize);
	return buflen;
}

void DebugOutFileTrunc::flush()
{
	if (this->m_size > 0 && this->m_filesize >= this->m_size) {
		char* nname = NULL;
		int nsize = 0;
		int ret;
		/*this means we exceed the file limited size, so we should change */
		if (this->m_fd >= 0)  {
			close(this->m_fd);
		}
		this->m_fd = -1;
		/*now to give the name copy*/
		if (this->m_name != NULL) {
			ret = str_append_snprintf_safe(&nname, &nsize, "%s.1", this->m_name);
			if (ret >= 0)	 {
				UX_OUTPUT_DEBUG("copy [%s] => [%s]", nname, this->m_name);
				ret = this->copy_to_file(nname,this->m_name);
				if (ret >= 0) {
					ret = this->open_file_trunc(this->m_name);
				}
			}
			str_append_snprintf_safe(&nname, &nsize, NULL);
		}
	}
	return;
}

int DebugOutFileTrunc::set_cfg(OutfileCfg* pcfg)
{
	const char* fname = NULL;
	int maxfiles = 0;
	int type = 0;
	uint64_t size = 0;
	int ret;

	ret = pcfg->get_file_type(fname, type, size, maxfiles);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (fname == NULL || (type & UXLIB_DEBUGOUT_FILE_MASK) != UXLIB_DEBUGOUT_FILE_TRUNC ||  maxfiles != 0) {
		ret = -EINVAL;
		goto fail;
	}

	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	if (this->m_name != NULL ) {
		free(this->m_name);
	}
	this->m_name = NULL;

	ret = this->DebugOutBuffer::set_cfg(pcfg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	this->m_name = strdup(fname);
	this->m_size = size;
	if (this->m_name == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	ret = this->open_file_trunc(this->m_name);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	return 0;
fail:
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	if (this->m_name) {
		free(this->m_name);
	}
	this->m_name = NULL;
	SETERRNO(ret);
	return ret;
}

class DebugOutFileAppend : public DebugOutFileTrunc
{
public:
	DebugOutFileAppend();
	virtual ~DebugOutFileAppend();
	virtual int write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual int write_buffer(char* pbuffer , int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
protected:
	int open_file_append(char* name);
};

int DebugOutFileAppend::open_file_append(char* name)
{
	int ret;
	struct stat statbuf;
	int flags= O_APPEND|O_WRONLY;
	loff_t loff;
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	ret = stat(name, &statbuf);
	if (ret < 0) {
		GETERRNO(ret);
		if (ret != -ENOENT) {
			GETERRNO(ret);
			SETERRNO(ret);
			return ret;
		}
		flags = O_CREAT|O_WRONLY;
	}

	this->m_fd = open(name, flags,0644);
	if (this->m_fd < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	}
	UX_OUTPUT_DEBUG("[%s] append [%d]", name, this->m_fd);

	loff = lseek64(this->m_fd,0,SEEK_CUR);
	if (loff == -1) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	}
	/*
	ret = _llseek(this->m_fd,0,0,&loff,SEEK_CUR);
	if (ret < 0) {
		GETERRNO(ret);
		SETERRNO(ret);
		return ret;
	}*/
	this->m_filesize = loff;
	return 0;
}

DebugOutFileAppend::DebugOutFileAppend()
{
	this->m_fd = -1;
	this->m_name = NULL;
	this->m_size = 0;
	this->m_filesize = 0;
}

DebugOutFileAppend::~DebugOutFileAppend()
{
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	if (this->m_name != NULL) {
		free(this->m_name);
	}
	this->m_name = NULL;
	this->m_size = 0;
	this->m_filesize = 0;
}


int DebugOutFileAppend::write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr)
{
	return this->DebugOutFileTrunc::write_log(level, locstr, timestr, tagstr, msgstr);
}

int DebugOutFileAppend::write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen)
{
	return this->DebugOutFileTrunc::write_buffer_log(level, locstr, timestr, tagstr, msgstr, pbuffer, buflen);
}

int DebugOutFileAppend::write_buffer(char* pbuffer , int buflen)
{
	return this->DebugOutFileTrunc::write_buffer(pbuffer, buflen);
}

void DebugOutFileAppend::flush()
{
	this->DebugOutFileTrunc::flush();
	return;
}

int DebugOutFileAppend::set_cfg(OutfileCfg* pcfg)
{
	const char* fname = NULL;
	int maxfiles = 0;
	int type = 0;
	uint64_t size = 0;
	int ret;

	ret = pcfg->get_file_type(fname, type, size, maxfiles);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (fname == NULL || (type & UXLIB_DEBUGOUT_FILE_MASK ) != UXLIB_DEBUGOUT_FILE_APPEND ||  maxfiles != 0) {
		ret = -EINVAL;
		goto fail;
	}

	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	if (this->m_name != NULL ) {
		free(this->m_name);
	}
	this->m_name = NULL;

	ret = this->DebugOutBuffer::set_cfg(pcfg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	this->m_name = strdup(fname);
	this->m_size = size;
	if (this->m_name == NULL) {
		GETERRNO(ret);
		goto fail;
	}


	ret = this->open_file_append(this->m_name);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	if (this->m_name) {
		free(this->m_name);
	}
	this->m_name = NULL;
	SETERRNO(ret);
	return ret;
}


class DebugOutFileRotate : public DebugOutFileAppend
{
public:
	DebugOutFileRotate();
	virtual ~DebugOutFileRotate();
	virtual int write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual int write_buffer(char* pbuffer, int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
protected:
	int rotate_file(int appmode);
	int m_maxfiles;
};


DebugOutFileRotate::DebugOutFileRotate()
{
	this->m_fd = -1;
	this->m_name = NULL;
	this->m_filesize = 0;
	this->m_size = 0;
	this->m_maxfiles = 0;
}

DebugOutFileRotate::~DebugOutFileRotate()
{
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd=-1;
	if (this->m_name != NULL) {
		free(this->m_name);
	}
	this->m_name = NULL;
	this->m_size = 0;
	this->m_filesize = 0;
	this->m_maxfiles = 0;
}

int DebugOutFileRotate::write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr)
{
	return this->DebugOutBuffer::write_log(level, locstr, timestr, tagstr, msgstr);
}

int DebugOutFileRotate::write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen)
{
	return this->DebugOutBuffer::write_buffer_log(level, locstr, timestr, tagstr, msgstr, pbuffer, buflen);
}

int DebugOutFileRotate::write_buffer(char* pbuffer , int buflen)
{
	return this->DebugOutFileTrunc::write_buffer(pbuffer, buflen);
}

int DebugOutFileRotate::rotate_file(int appmode)
{
	char* nname = NULL;
	int nsize = 0;
	char* oname = NULL;
	int osize = 0;
	int i;
	int ret;
	struct stat statbuf;

	/*now to make sure */
	if (this->m_maxfiles > 0) {
		for (i = (this->m_maxfiles - 1); i > 0; i--) {
			/*now to make sure it is exist*/
			str_append_snprintf_safe(&nname, &nsize, NULL);
			ret = str_append_snprintf_safe(&nname, &nsize, "%s.%d", this->m_name, i + 1);
			if (ret < 0) {
				goto fail;
			}
			str_append_snprintf_safe(&oname, &osize, NULL);
			ret =  str_append_snprintf_safe(&oname, &osize, "%s.%d", this->m_name, i);
			if (ret < 0) {
				goto fail;
			}
			UX_OUTPUT_DEBUG("[%s] => [%s]", oname, nname);
			ret = this->copy_to_file(nname,oname);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
		}
		/*now copy file*/
		str_append_snprintf_safe(&nname, &nsize, NULL);
		str_append_snprintf_safe(&oname, &osize, NULL);
		ret = str_append_snprintf_safe(&nname, &nsize, "%s.1", this->m_name);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = str_append_snprintf_safe(&oname, &osize, "%s", this->m_name);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		UX_OUTPUT_DEBUG("[%s] => [%s]", oname, nname);
		ret= this->copy_to_file(nname,oname);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	} else {
		int maxfiles = 1;

		for (maxfiles = 1;; maxfiles++) {
			str_append_snprintf_safe(&nname, &nsize, NULL);
			ret = str_append_snprintf_safe(&nname, &nsize, "%s.%d", this->m_name, maxfiles);
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			ret = stat(nname,&statbuf);
			if (ret < 0) {
				break;
			}
		}
		if (maxfiles > 1) {
			for (i = (maxfiles); i > 1; i--) {
				str_append_snprintf_safe(&nname, &nsize, NULL);
				str_append_snprintf_safe(&oname, &osize, NULL);
				ret = str_append_snprintf_safe(&nname, &nsize, "%s.%d", this->m_name, i);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				ret = str_append_snprintf_safe(&oname, &osize, "%s.%d", this->m_name, i - 1);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}

				UX_OUTPUT_DEBUG("[%s] => [%s]", oname, nname);
				ret = this->copy_to_file(nname,oname);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
			}
		}

		str_append_snprintf_safe(&nname, &nsize, NULL);
		str_append_snprintf_safe(&oname, &osize, NULL);
		ret = str_append_snprintf_safe(&nname, &nsize, "%s.1", this->m_name);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = str_append_snprintf_safe(&oname, &osize, "%s", this->m_name);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		ret = this->copy_to_file(nname,oname);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
	}

	ASSERT_IF(this->m_fd  < 0);
	/*now to open the truncation file*/
	if (appmode) {
		ret = this->open_file_append(this->m_name);
	} else {
		ret = this->open_file_trunc(this->m_name);
	}

	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	str_append_snprintf_safe(&nname, &nsize, NULL);
	str_append_snprintf_safe(&oname, &osize, NULL);

	return 0;
fail:
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	str_append_snprintf_safe(&nname, &nsize, NULL);
	str_append_snprintf_safe(&oname, &osize, NULL);
	SETERRNO(ret);
	return ret;
}

void DebugOutFileRotate::flush()
{
	if (this->m_size > 0 && this->m_filesize >= this->m_size) {
		if (this->m_fd >= 0) {
			close(this->m_fd);
		}
		this->m_fd = -1;
		this->rotate_file(0);
	}
	return;
}

int DebugOutFileRotate::set_cfg(OutfileCfg* pcfg)
{
	const char* fname = NULL;
	int maxfiles = 0;
	int type = 0;
	uint64_t size = 0;
	int ret;

	ret = pcfg->get_file_type(fname, type, size, maxfiles);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	if (fname == NULL || (type & UXLIB_DEBUGOUT_FILE_MASK ) != UXLIB_DEBUGOUT_FILE_ROTATE ) {
		ret = -EINVAL;
		goto fail;
	}

	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	if (this->m_name != NULL ) {
		free(this->m_name);
	}
	this->m_name = NULL;

	ret = this->DebugOutBuffer::set_cfg(pcfg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	this->m_name = strdup(fname);
	this->m_size = size;
	if (this->m_name == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	this->m_maxfiles = maxfiles;

	ret = this->rotate_file(1);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	return 0;
fail:
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	this->m_fd = -1;
	if (this->m_name) {
		free(this->m_name);
	}
	this->m_name = NULL;
	SETERRNO(ret);
	return ret;
}



DebugOutIO* get_cfg_out(OutfileCfg* pcfg)
{
	const char* fname = NULL;
	int type = 0;
	int maxfiles = 0;
	uint64_t size;
	int ret;
	DebugOutIO* pout = NULL;

	ret = pcfg->get_file_type(fname, type, size, maxfiles);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	switch (type & UXLIB_DEBUGOUT_FILE_MASK) {
	case UXLIB_DEBUGOUT_FILE_STDERR:
		pout =  new DebugOutStderr();
		break;
	case UXLIB_DEBUGOUT_FILE_APPEND:
		pout =  new DebugOutFileAppend();
		break;
	case UXLIB_DEBUGOUT_FILE_TRUNC:
		pout = new DebugOutFileTrunc();
		break;
	case UXLIB_DEBUGOUT_FILE_BACKGROUND:
		pout = new DebugOutBackground();
		break;
	case UXLIB_DEBUGOUT_FILE_ROTATE:
		pout = new DebugOutFileRotate();
		break;
	default:
		ret =  -ENOTSUP;
		goto fail;
	}

	ret = pout->set_cfg(pcfg);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}
	return pout;
fail:
	if (pout) {
		delete pout;
	}
	pout = NULL;
	SETERRNO(ret);
	return NULL;
}