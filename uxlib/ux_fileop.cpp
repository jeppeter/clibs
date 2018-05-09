#include <ux_err.h>
#include <ux_fileop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ux_output_debug.h>


int read_file_whole(char* infile,char** ppoutbuf,int *bufsize)
{
    int ret = 0;
    char* pretbuf = NULL;
    int retsize = 0;
    unsigned char* preadbuf = NULL;
    char* curbuf=NULL;
    int filelen = 0;
    int readlen = 0;
    FILE* fp = NULL;
    off_t offset;
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
        ret = -EINVAL;
        goto fail;
    }
    pretbuf = *ppoutbuf;
    retsize = *bufsize;

    fp = fopen(infile, "rb");
    if (fp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not open[%s] error[%d]", infile, ret);
        goto fail;
    }

    ret = fseeko(fp, 0, SEEK_END);
    if (ret != 0) {
        GETERRNO(ret);
        ERROR_INFO("can not seek end [%s] error[%d]", infile, ret);
        goto fail;
    }

    SETERRNO(0);
    offset = ftello(fp);
    if (offset == (off_t) - 1) {
        GETERRNO_DIRECT(ret);
        if (ret != 0) {
            ERROR_INFO("can not tell [%s] error[%d]", infile, ret);
            goto fail;
        }
    }

    filelen = (int)offset;
    if (filelen < offset) {
        ret = -ERANGE;
        ERROR_INFO("[%s] overflow 32bit %lld %d", infile, offset, filelen);
        goto fail;
    }

    preadbuf = (unsigned char*)malloc((size_t)filelen + 4);
    if (preadbuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not malloc[%d]", filelen);
        goto fail;
    }
    memset(preadbuf, 0, (size_t)(filelen + 4));

    ret = fseeko(fp, 0, SEEK_SET);
    if (ret != 0) {
        GETERRNO(ret);
        ERROR_INFO("can not rewind file[%s] error[%d]", infile, ret);
        goto fail;
    }

    readlen = 0;
    while (readlen < filelen) {
        curbuf = (char*)(preadbuf + readlen);
        ret = (int)fread(curbuf, 1, (size_t)(filelen - readlen), fp);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("can not read at[%d][%s] error[%d]", readlen, infile, ret);
            goto fail;
        } else if (ret > 0) {
            readlen += ret;
        } else {
            GETERRNO(ret);
            ERROR_INFO("can not read [%d][%s] zero", readlen, infile);
            goto fail;
        }
    }


    retlen = readlen;

    if (retlen > retsize || pretbuf == NULL) {
        retsize = retlen;
        pretbuf = (char*)malloc((size_t)retsize);
        if (pretbuf == NULL) {
            GETERRNO(ret);
            ERROR_INFO("can not malloc [%d]", retsize);
            goto fail;
        }
    }

    if (retlen > 0) {
        memcpy(pretbuf, preadbuf, (size_t)retlen);
    }

    if (*ppoutbuf && *ppoutbuf != pretbuf) {
        free(*ppoutbuf);
    }

    *ppoutbuf = pretbuf;
    *bufsize = retsize;

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