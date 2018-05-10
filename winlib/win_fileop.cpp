#include <win_fileop.h>
#include <win_err.h>
#include <win_output_debug.h>
#include <io.h>
#include <win_uniansi.h>
#include <win_envop.h>

#define TEMP_XSIZE      6

#pragma warning(disable:4996)

int mktempfile_safe(char* inputtemplate, char**ppoutput, int* bufsize)
{
    int ret = 0;
    char* pretout = NULL;
    int retlen = 0;
    int templen = 0;
    size_t sz = 0;
    errno_t err;
    char* plastpart = NULL;
    char* ptemppath = NULL;
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
    plastpart = strrchr(inputtemplate, '\\');
    if (plastpart == NULL) {
        plastpart = inputtemplate;
    } else {
        plastpart ++;
    }
    ret = get_env_variable("TEMP", &ptemppath, &temppathlen);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not get TEMP env error[%d]", ret);
        goto fail;
    }
    templen = (int)strlen(plastpart) + 1;
    templen += (int)strlen(ptemppath);
    templen += TEMP_XSIZE;

    if (templen > retlen || pretout == NULL) {
        retlen = templen;
        pretout = (char*)malloc((size_t)retlen);
        if (pretout == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not malloc[%d] error[%d]", templen, ret);
            goto fail;
        }
    }
    memset(pretout, 0, (size_t)retlen);
    strncpy(pretout, ptemppath, (size_t)templen);
    strncat(pretout, "\\", (size_t)templen);
    strncat(pretout, plastpart, (size_t)templen);
    for (i = 0; i < TEMP_XSIZE; i++) {
        strncat(pretout, "X", (size_t)templen);
    }
    sz = strlen(pretout) + 1;
    err = _mktemp_s(pretout, sz);
    if (err != 0) {
        GETERRNO(ret);
        ERROR_INFO("can not mktemp [%s] error[%d]", pretout, ret);
        goto fail;
    }
    if (*ppoutput != NULL && pretout != *ppoutput) {
        free(*ppoutput);
    }
    *ppoutput = pretout;
    *bufsize = templen;
    get_env_variable(NULL, &ptemppath, &temppathlen);
    return templen ;
fail:
    if (pretout && pretout != *ppoutput) {
        free(pretout);
    }
    pretout = NULL;
    get_env_variable(NULL, &ptemppath, &temppathlen);
    SETERRNO(-ret);
    return ret;
}

#define MIN_BUF_SIZE   0x10000

int __read_fp_buffer(FILE* fp, char** ppoutbuf, int *pbufsize)
{
    size_t retlen = 0;
    size_t curlen;
    char* pretbuf = NULL;
    size_t retsize = 0;
    char* ptmpbuf = NULL;
    int ret;

    if (fp == NULL) {
        if (ppoutbuf != NULL) {
            if (*ppoutbuf != NULL) {
                free(*ppoutbuf);
            }
            *ppoutbuf = NULL;
        }
        if (pbufsize != NULL) {
            *pbufsize = 0;
        }
        return 0;
    }

    if (ppoutbuf == NULL || pbufsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretbuf = *ppoutbuf;
    retsize = (size_t)*pbufsize;

    if (retsize < MIN_BUF_SIZE || pretbuf == NULL) {
        if (retsize < MIN_BUF_SIZE) {
            retsize = MIN_BUF_SIZE;
        }
        pretbuf = (char*) malloc(retsize);
        if (pretbuf == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", retsize, ret);
            goto fail;
        }
        memset(pretbuf, 0 , retsize);
    }


    while (1) {
        while (retlen >= retsize) {
            retsize += MIN_BUF_SIZE;
            if (retsize > retlen) {
                ptmpbuf = (char*) malloc(retsize);
                if (ptmpbuf == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", retsize, ret);
                    goto fail;
                }
                memset(ptmpbuf, 0 , retsize);
                if (retlen > 0) {
                    memcpy(ptmpbuf, pretbuf, retlen);
                }
                if (pretbuf != NULL && pretbuf != *ppoutbuf) {
                    free(pretbuf);
                }
                pretbuf = ptmpbuf;
                ptmpbuf = NULL;
            }
        }

        curlen = retsize - retlen;
        ret = (int)fread(&(pretbuf[retlen]), (size_t)1, curlen, fp);
        if (ret < 0) {
            if (feof(fp)) {
                break;
            }
            GETERRNO(ret);
            ERROR_INFO("read [%d] error[%d]", retlen, ret);
            goto fail;
        }
        retlen += ret;
        if (ret < (int)curlen) {
            break;
        }
    }

    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;

    if (*ppoutbuf != NULL && *ppoutbuf != pretbuf) {
        free(*ppoutbuf);
    }
    *ppoutbuf = pretbuf;
    *pbufsize = (int)retsize;
    return (int)retlen;

fail:
    if (ptmpbuf != NULL) {
        free(ptmpbuf);
    }
    ptmpbuf = NULL;
    if (pretbuf != NULL && pretbuf != *ppoutbuf) {
        free(pretbuf);
    }
    pretbuf = NULL;
    SETERRNO(ret);
    return ret;
}


int read_file_encoded(char* infile, char** ppoutbuf, int *bufsize)
{
    int ret;
    FILE* fp = NULL;
    int filelen;
    int retlen;
    char* preadbuf=NULL;
    int readsize=0;
    char* curbuf;
    wchar_t *pwbuf;

    if (infile == NULL) {
        return UnicodeToAnsi(NULL,ppoutbuf,bufsize);
    }

    if (ppoutbuf == NULL || bufsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        goto fail;
    }

    fp = fopen(infile, "rb");
    if (fp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open[%s] error[%d]", infile, ret);
        goto fail;
    }


    ret = __read_fp_buffer(fp,&preadbuf,&readsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    filelen = ret;


    if (filelen > 2 && preadbuf[0] == 0xff && preadbuf[1] == 0xfe) {
        curbuf = (char*)(&(preadbuf[2]));
    } else {
        curbuf = (char*)preadbuf;
    }
    pwbuf = (wchar_t*)curbuf;

    ret = UnicodeToAnsi(pwbuf, ppoutbuf, bufsize);
    if (ret < 0) {
        goto fail;
    }
    retlen = ret;

    __read_fp_buffer(NULL,&preadbuf,&readsize);
    if (fp != NULL) {
        fclose(fp);
    }
    fp = NULL;
    return retlen;
fail:
    __read_fp_buffer(NULL,&preadbuf,&readsize);

    if (fp != NULL) {
        fclose(fp);
    }
    fp = NULL;
    SETERRNO(-ret);
    return ret;
}


int read_file_whole(char* infile,char** ppoutbuf,int *bufsize)
{
    int ret=0;
    FILE* fp=NULL;
    if (infile == NULL) {
        return __read_fp_buffer(NULL,ppoutbuf,bufsize);
    }

    if (ppoutbuf == NULL || bufsize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    fp = fopen(infile, "rb");
    if (fp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open[%s] error[%d]", infile, ret);
        goto fail;
    }

    ret = __read_fp_buffer(fp,ppoutbuf,bufsize);
    if (ret < 0) {
        goto fail;
    }

    if (fp != NULL) {
        fclose(fp);
    }
    fp = NULL;
    return ret;
fail:
    if (fp != NULL) {
        fclose(fp);
    }
    fp = NULL;
    SETERRNO(-ret);
    return ret;
}
int delete_file(const char* infile)
{
    int ret;
    BOOL bret;
    TCHAR* ptfile = NULL;
    int tfilesize = 0;

    if (infile == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(-ret);
        return ret;
    }

    ret = AnsiToTchar(infile, &ptfile, &tfilesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = DeleteFile(ptfile);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("can not delete [%s] error[%d]", infile, ret);
        goto fail;
    }

    AnsiToTchar(NULL, &ptfile, &tfilesize);
    return 0;
fail:
    AnsiToTchar(NULL, &ptfile, &tfilesize);
    SETERRNO(ret);
    return ret;
}

int read_stdin_whole(int freed,char** ppoutbuf,int *bufsize)
{
    if (freed) {
        return __read_fp_buffer(NULL,ppoutbuf,bufsize);
    }

    return __read_fp_buffer(stdin,ppoutbuf,bufsize);
}

int get_full_path(char* pinfile, char** ppfullpath, int *pfullsize)
{
    int ret;
    TCHAR* ptinfile = NULL;
    int tinsize = 0;
    TCHAR* ptfullpath = NULL;
    DWORD tfullsize = 0;
    TCHAR* ptlongpath=NULL;
    DWORD tlongsize=0;
    int retlen=0;
    DWORD dret;
    TCHAR* pfilepart=NULL;

    if (ppfullpath == NULL || pfullsize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    if (pinfile == NULL) {
        TcharToAnsi(NULL, ppfullpath, pfullsize);
        return 0;
    }

    ret = AnsiToTchar(pinfile, &ptinfile, &tinsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    tfullsize = 1024;

try_again:
    if (ptfullpath) {
        free(ptfullpath);
    }
    ptfullpath = NULL;

    ptfullpath = (TCHAR*) malloc(tfullsize * sizeof(TCHAR));
    if (ptfullpath == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc [%d] error[%d]", tfullsize * sizeof(TCHAR), ret);
        goto fail;
    }

    dret = GetFullPathName(ptinfile,tfullsize,ptfullpath,&pfilepart);
    if (dret == 0) {
    	GETERRNO(ret);
    	ERROR_INFO("[%s] fullname error[%d]",pinfile,ret);
    	goto fail;
    } else if (dret >= (tfullsize - 1)) {
    	tfullsize <<= 1;
    	goto try_again;
    }

    tlongsize = 1024;
get_long_again:
	if (ptlongpath) {
		free(ptlongpath);
	}
	ptlongpath = NULL;
	ptlongpath = (TCHAR*) malloc(tlongsize*sizeof(TCHAR));
	if (ptlongpath == NULL) {
		GETERRNO(ret);
		ERROR_INFO("alloc [%d] error[%d]",tlongsize*sizeof(TCHAR),ret);
		goto fail;
	}

	dret = GetLongPathName(ptfullpath,ptlongpath,tlongsize);
	if (dret == 0) {
		GETERRNO(ret);
		ERROR_INFO("[%s] longname error[%d]",pinfile,ret);
		goto fail;
	} else if (dret >= (tlongsize - 1)) {
		tlongsize <<= 1;
		goto get_long_again;
	}

    ret = TcharToAnsi(ptlongpath,ppfullpath,pfullsize);
    if (ret < 0) {
    	GETERRNO(ret);
    	goto fail;
    }
    retlen = ret;

    if (ptlongpath != NULL)  {
    	free(ptlongpath);
    }
    ptlongpath = NULL;

	if (ptfullpath != NULL) {
		free(ptfullpath);
	}
	ptfullpath = NULL;
	tfullsize = 0;
	AnsiToTchar(NULL,&ptinfile,&tinsize);

    return retlen;
fail:
    if (ptlongpath != NULL)  {
    	free(ptlongpath);
    }
    ptlongpath = NULL;

	if (ptfullpath != NULL) {
		free(ptfullpath);
	}
	ptfullpath = NULL;
	tfullsize = 0;
	AnsiToTchar(NULL,&ptinfile,&tinsize);
    SETERRNO(ret);
    return ret;
}