
class DebugOutIO
{
public:
	virtual ~DebugOutIO() {};
	virtual int write_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr) = 0;
	virtual int write_buffer_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr, void* pbuffer, int buflen) = 0;
	virtual void flush() = 0;
	virtual int set_cfg(OutfileCfg* pcfg) = 0;
};


class DebugOutStderr : public DebugOutIO
{
public:
	DebugOutStderr();
	virtual ~DebugOutStderr();
	virtual int write_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
private:
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


int format_out_string(int fmtflag, int addline, char** ppoutstr, int* psize, char* locstr, char* timestr, char* tagstr, char* msgstr)
{
	int ret;
	int retlen = 0;
	int cnt = 0;
	if (fmtflag < 0) {
		return str_append_snprintf_safe(ppoutstr, psize, NULL);
	}

	if (fmtflag & WINLIB_OUTPUT_LOCATION) {
		ret = str_append_snprintf_safe(ppoutstr, psize, "%s", locstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		cnt ++;
	}

	if (fmtflag & WINLIB_OUTPUT_TIMESTAMP) {
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

	if (fmtflag & WINLIB_OUTPUT_LEVEL) {
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

	if (fmtflag & WINLIB_OUTPUT_LEVEL) {
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

	if (fmtflag & WINLIB_OUTPUT_MSG) {
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

DebugOutStderr::DebugOutStderr()
{
	this->m_level = BASE_LOG_ERROR;
	this->m_fmtflag = WINLIB_OUTPUT_ALL_MASK;
}

DebugOutStderr::~DebugOutStderr()
{
	fflush(stderr);
}

int DebugOutStderr::write_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr)
{
	int retlen = 0;
	int ret;
	char* outstr = NULL;
	int outsize = 0;
	if (this->m_level <= level) {
		ret = format_out_string(this->m_fmtflag, 1, &outstr, &outsize, locstr, timestr, tagstr, msgstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		retlen = ret;
		fprintf(stderr, "%s", outstr);
		format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
	}
	return retlen;
fail:
	format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
	SETERRNO(ret);
	return ret;
}

int DebugOutStderr::write_buffer_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr, void* pbuffer, int buflen)
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
	if (this->m_level <= level) {
		ret = format_out_string(this->m_fmtflag, 0, &outstr, &outsize, locstr, timestr, tagstr, msgstr);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		retlen = ret;
		fprintf(stderr, "%s", outstr);
		format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
		pcurptr = (uint8_t*)pbuffer;
		lasti = 0;
		for (i = 0; i < buflen; i++) {

			if (outlen > 2000) {
				fprintf(stderr, "%s", bufstr);
				retlen += outlen;
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
				ret =  str_append_snprintf_safe(&bufstr, &buflen, "     ");
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				i ++;
			}
			ret = str_append_snprintf_safe(&bufstr, &buflen, "    ");
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
			ret = str_append_snprintf_safe(&bufstr, &buflen, "\n");
			if (ret < 0) {
				GETERRNO(ret);
				goto fail;
			}
			outlen = (int)strlen(bufstr);
			fprintf(stderr, "%s", bufstr);
			retlen += outlen;
		}
	}

	str_append_snprintf_safe(&bufstr, &bufsize, NULL);
	format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
	return retlen;
fail:
	str_append_snprintf_safe(&bufstr, &bufsize, NULL);
	format_out_string(-1, 0, &outstr, &outsize, NULL, NULL, NULL, NULL);
	SETERRNO(ret);
	return ret;
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

	if (fname != NULL || type != WINLIB_FILE_STDERR || size != 0 || maxfiles != 0) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}

	this->m_level = pcfg->get_level();
	this->m_fmtflag = pcfg->get_format();

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}



class DebugOutBackground : public DebugOutIO
{
public:
	DebugOutBackground();
	virtual ~DebugOutBackground();
	virtual int write_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
};


class DebugOutFileTrunc : public DebugOutIO
{
public:
	DebugOutFileTrunc();
	virtual ~DebugOutFileTrunc();
	virtual int write_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
private:
	HANDLE m_hfile;
	char* m_name;
	uint64_t m_size;
	uint64_t m_filesize;
};


class DebugOutFileAppend : public DebugOutIO
{
public:
	DebugOutFileAppend();
	virtual ~DebugOutFileAppend();
	virtual int write_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
private:
	HANDLE m_hfile;
	char* m_name;
	uint64_t m_size;
	uint64_t m_filesize;
};


class DebugOutFileRotate : public DebugOutIO
{
public:
	DebugOutFileRotate();
	virtual ~DebugOutFileRotate();
	virtual int write_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr, char* timestr, char* tagstr, char* msgstr, void* pbuffer, int buflen);
	virtual void flush();
	virtual int set_cfg(OutfileCfg* pcfg);
private:
	HANDLE m_hfile;
	char* m_name;
	uint64_t m_size;
	uint64_t m_filesize;
	int m_maxfiles;
	int m_rsv1;
};
