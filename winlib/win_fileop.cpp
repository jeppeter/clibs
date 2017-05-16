#include <win_fileop.h>
#include <win_err.h>
#include <win_output_debug.h>
#include <io.h>
#include <win_uniansi.h>
#include <win_envop.h>

#define TEMP_XSIZE      6

#pragma warning(disable:4996)

int mktempfile_safe(char* inputtemplate,char**ppoutput,int* bufsize)
{
	int ret=0;
	char* pretout=NULL;
	int retlen=0;
	int templen=0;
	size_t sz=0;
	errno_t err;
	char* plastpart=NULL;
	char* ptemppath=NULL;
	int temppathlen = 0;
	int i;

	if (inputtemplate == NULL) {
		if (ppoutput != NULL && *ppoutput != NULL) {
			free(*ppoutput);
		}
		if (ppoutput != NULL) {
			*ppoutput = NULL;
		}
		if (bufsize != NULL) {
			*bufsize = 0;
		}
		return 0;
	}

	if (ppoutput == NULL || bufsize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;		
		goto fail;
	}
	retlen = *bufsize;
	pretout = *ppoutput;
	plastpart = strrchr(inputtemplate,'\\');
	if (plastpart == NULL) {
		plastpart = inputtemplate;
	} else {
		plastpart ++;
	}
	ret = get_env_variable("TEMP",&ptemppath,&temppathlen);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not get TEMP env error[%d]",ret);
		goto fail;
	}
	templen = (int)strlen(plastpart) + 1;
	templen += (int)strlen(ptemppath);
	templen += TEMP_XSIZE;

	if (templen > retlen || pretout == NULL){
		retlen = templen;
		pretout = (char*)malloc((size_t)retlen);
		if (pretout == NULL) {
			GETERRNO(ret);
			ERROR_INFO("can not malloc[%d] error[%d]",templen,ret);
			goto fail;
		}
	}
	memset(pretout,0,(size_t)retlen);
	strncpy(pretout,ptemppath,(size_t)templen);
	strncat(pretout,"\\",(size_t)templen);
	strncat(pretout,plastpart,(size_t)templen);
	for (i=0;i<TEMP_XSIZE;i++) {
		strncat(pretout,"X",(size_t)templen);
	}
	sz = strlen(pretout) + 1;
	err = _mktemp_s(pretout,sz);
	if (err != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not mktemp [%s] error[%d]",pretout,ret);
		goto fail;
	}
	if (*ppoutput != NULL && pretout != *ppoutput) {
		free(*ppoutput);
	}
	*ppoutput = pretout;
	*bufsize = templen;
	get_env_variable(NULL,&ptemppath,&temppathlen);
	return templen ;
fail:
	if (pretout && pretout != *ppoutput) {
		free(pretout);
	}
	pretout = NULL;
	get_env_variable(NULL,&ptemppath,&temppathlen);
	SETERRNO(-ret);
	return ret;
}

int read_file_encoded(char* infile,char** ppoutbuf,int *bufsize)
{
	int ret=0;
	char* pretbuf=NULL;
	int retsize=0;
	unsigned char* preadbuf=NULL;	
	char* curbuf=NULL;
	wchar_t *pwbuf=NULL;
	int filelen=0;
	int readlen=0;
	char *transbuf=NULL;
	int transsize=0;
	FILE* fp=NULL;
	__int64 offset;
	int retlen;

	if (infile == NULL) {
		if (ppoutbuf && *ppoutbuf) {
			free(*ppoutbuf);
		}
		if (ppoutbuf) {
			*ppoutbuf = NULL;
		}
		if (bufsize) {
			*bufsize = 0;
		}
		return 0;
	}

	if (ppoutbuf == NULL || bufsize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		goto fail;
	}
	pretbuf = *ppoutbuf;
	retsize = *bufsize;

	fp = fopen(infile,"rb");
	if (fp == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not open[%s] error[%d]",infile,ret);
		goto fail;
	}

	ret = _fseeki64(fp,0,SEEK_END);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not seek end [%s] error[%d]",infile,ret);
		goto fail;
	}

	SETERRNO(0);
	offset = _ftelli64(fp);
	if (offset == (__int64) -1) {
		GETERRNO_DIRECT(ret);
		if (ret != 0) {
			ERROR_INFO("can not tell [%s] error[%d]",infile,ret);
			goto fail;
		}
	}

	filelen = (int)offset;
	if (filelen < offset) {
		ret = -ERROR_ARITHMETIC_OVERFLOW;
		ERROR_INFO("[%s] overflow 32bit %lld %d",infile,offset,filelen);
		goto fail;
	}

	preadbuf = (unsigned char*)malloc((size_t)filelen + 4);
	if (preadbuf == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not malloc[%d]",filelen);
		goto fail;
	}
	memset(preadbuf,0,(size_t)(filelen + 4));

	ret = _fseeki64(fp,0,SEEK_SET);
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not rewind file[%s] error[%d]",infile,ret);
		goto fail;
	}

	readlen = 0;
	while (readlen < filelen) {
		curbuf = (char*)(preadbuf + readlen);
		ret = (int)fread(curbuf,1,(size_t)(filelen-readlen),fp);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("can not read at[%d][%s] error[%d]",readlen,infile,ret);
			goto fail;
		} else if (ret > 0) {
			readlen += ret;
		} else {
			GETERRNO(ret);
			ERROR_INFO("can not read [%d][%s] zero",readlen,infile);
			goto fail;
		}
	}


	if (filelen > 2 && preadbuf[0] == 0xff && preadbuf[1] == 0xfe) {
		curbuf = (char*)(&(preadbuf[2]));
	} else {
		curbuf = (char*)preadbuf;
	}
	pwbuf = (wchar_t*)curbuf;

	ret = UnicodeToAnsi(pwbuf,&transbuf,&transsize);
	if (ret < 0) {
		goto fail;
	}
	retlen = ret;

	if (retlen > retsize || pretbuf == NULL) {
		retsize = retlen;
		pretbuf = (char*)malloc((size_t)retsize);
		if (pretbuf == NULL) {
			GETERRNO(ret);
			ERROR_INFO("can not malloc [%d]",retsize);
			goto fail;
		}
	}

	if (retlen > 0) {
		memcpy(pretbuf,transbuf,(size_t)retlen);
	}

	if (*ppoutbuf && *ppoutbuf != pretbuf) {
		free(*ppoutbuf);
	}

	*ppoutbuf = pretbuf;
	*bufsize = retsize;

	UnicodeToAnsi(NULL,&transbuf,&transsize);
	if (preadbuf) {
		free(preadbuf);
	}
	preadbuf = NULL;

	if (fp != NULL) {
		fclose(fp);
	}
	fp = NULL;
	return retlen;
fail:
	UnicodeToAnsi(NULL,&transbuf,&transsize);
	if (preadbuf) {
		free(preadbuf);
	}
	preadbuf = NULL;

	if (fp != NULL) {
		fclose(fp);
	}
	fp = NULL;

	if (pretbuf && pretbuf != *ppoutbuf) {
		free(pretbuf);
	}
	pretbuf = NULL;
	SETERRNO(-ret);
	return ret;
}

int delete_file(const char* infile)
{
	int ret;
	BOOL bret;
	TCHAR* ptfile=NULL;
	int tfilesize=0;

	if (infile == NULL) {
		ret =-ERROR_INVALID_PARAMETER;
		SETERRNO(-ret);
		return ret;
	}

	ret = AnsiToTchar(infile,&ptfile,&tfilesize);
	if (ret < 0) {
		GETERRNO(ret);
		goto fail;
	}

	bret = DeleteFile(ptfile);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("can not delete [%s] error[%d]",infile,ret);
		goto fail;
	}

	AnsiToTchar(NULL,&ptfile,&tfilesize);
	return 0;
fail:
	AnsiToTchar(NULL,&ptfile,&tfilesize);
	SETERRNO(ret);
	return ret;
}