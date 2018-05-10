#include <ux_err.h>
#include <ux_fileop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ux_output_debug.h>


#define MIN_BUF_SIZE   0x10000

int __read_fp_buffer(FILE* fp, char** ppoutbuf, int *pbufsize)
{
    int retlen = 0;
    int curlen;
    char* pretbuf = NULL;
    int retsize = 0;
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
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pretbuf = *ppoutbuf;
    retsize = *pbufsize;

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
        ret = fread(&(pretbuf[retlen]), 1, curlen, fp);
        if (ret < 0) {
            if (feof(fp)) {
                break;
            }
            GETERRNO(ret);
            ERROR_INFO("read [%d] error[%d]", retlen, ret);
            goto fail;
        }
        retlen += ret;
        if (ret != curlen) {
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
    *pbufsize = retsize;
    return retlen;

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

int read_stdin_whole(int freed,char** ppoutbuf,int *bufsize)
{
    if (freed) {
        return __read_fp_buffer(NULL,ppoutbuf,bufsize);
    }

    return __read_fp_buffer(stdin,ppoutbuf,bufsize);
}


int __write_fp_out(FILE* fp,char* poutbuf,int outsize)
{
    size_t outlen=0;
    size_t curlen=0;
    int ret;

    if (fp == NULL || poutbuf == NULL || outsize < 0) {
        ret  = -EINVAL;
        goto fail;
    }

    while( (int)outlen < outsize) {
        curlen = (outsize - outlen);
        ret = (int) fwrite(&(poutbuf[outlen]), 1, curlen,fp);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("write [%d] error[%d]", outlen, ret);
            goto fail;
        }
        outlen += ret;
        if (ret == 0) {
            /*it means we have something wrong*/
            break;
        }
    }

    return (int) outlen;
fail:
    SETERRNO(ret);
    return ret;
}

int write_file_whole(char* outfile,char* poutbuf,int outsize)
{
    FILE* fp=NULL;
    int ret=0;

    if (outfile == NULL) {
        ret = -EINVAL;
        goto fail;
    }

    fp = fopen(outfile,"wb");
    if (fp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("open [%s] error[%d]", outfile,ret);
        goto fail;
    }

    ret = __write_fp_out(fp,poutbuf,outsize);
    if (ret < 0) {
        GETERRNO(ret);
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
    SETERRNO(ret);
    return ret;
}

int write_out_whole(int flag,char* poutbuf,int outsize)
{
    FILE* fp=NULL;
    int ret;

    if (flag == STDOUT_FILE_FLAG) {
        fp = stdout;
    } else if (flag == STDERR_FILE_FLAG) {
        fp = stderr;
    }

    if (fp == NULL) {
        ret = -EINVAL;
        goto fail;
    }

    ret = __write_fp_out(fp,poutbuf,outsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return ret;
fail:
    SETERRNO(ret);
    return ret;
}

