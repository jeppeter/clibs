#include <ux_err.h>
#include <ux_fileop.h>
#include <ux_output_debug.h>
#include <ux_strop.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


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

#define  MIN_PATH_SIZE   0x100

int realpath_safe(char* path, char** pprealpath, int *psize)
{
    char* pretstr=NULL;
    int retsize=0;
    int retlen=0;
    int ret;
    char* ptr;
    int maxsize=0;
    if (path == NULL) {
        if (pprealpath && *pprealpath) {
            free(*pprealpath);
            *pprealpath = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }
    if (pprealpath == NULL || psize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pretstr = *pprealpath;
    retsize = *psize;

    maxsize = pathconf(path,_PC_PATH_MAX);
    if (maxsize < 0) {
        GETERRNO(ret);
        ERROR_INFO("get [%s] path max error[%d]", path, ret);
        goto fail;
    }

    if (pretstr == NULL || retsize < maxsize) {
        if (retsize < maxsize) {
            retsize = maxsize;
        }
        pretstr = (char*) malloc(retsize);
        if (pretstr == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", retsize,ret);
            goto fail;
        }
    }


    memset(pretstr, 0, retsize);
    ptr = realpath(path, pretstr);
    if (ptr == NULL) {
        GETERRNO(ret);
        ERROR_INFO("realpath [%s] error[%d]",  path, ret);
        goto fail;
    }

    if (*pprealpath && *pprealpath != pretstr) {
        free(*pprealpath);
    }
    *pprealpath = pretstr;
    *psize = retsize;
    return retlen;
fail:
    if (pretstr && pretstr != *pprealpath) {
        free(pretstr);
    }
    pretstr = NULL;
    SETERRNO(ret);
    return ret;
}

#define  MTAB_FILE    "/etc/mtab"

int __get_mtab_lines(int freed, char*** ppplines,int *plinesize)
{
    char* mtabcont=NULL;
    int mtabsize=0;
    int ret;
    int llen=0;
    if (freed) {
        split_lines(NULL,ppplines,plinesize);
        return 0;
    }
    ret= read_file_whole((char*)MTAB_FILE,&mtabcont,&mtabsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = split_lines(mtabcont,ppplines,plinesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    llen = ret;

    read_file_whole(NULL,&mtabcont,&mtabsize);
    return llen;
fail:
    split_lines(NULL,ppplines,plinesize);
    read_file_whole(NULL,&mtabcont,&mtabsize);
    SETERRNO(ret);
    return ret;
}

char* __get_line_item(char* ptr, int *plen)
{
    int len=0;
    char* pcurptr = ptr;
    while(*pcurptr == ' ') {
        pcurptr ++;
    }
    ptr = pcurptr;
    while(*pcurptr != '\0' && *pcurptr != ' ') {
        pcurptr ++;
    }

    len = pcurptr - ptr;
    if (plen) {
        *plen = len;
    }
    return pcurptr;
}

int dev_get_mntdir(const char* dev, char** ppmntdir,int *pmntsize)
{
    char** pplines=NULL;
    int linesize=0;
    int linenum=0;
    int retlen= 0;
    int ret;
    int i;
    char* comparestr = NULL;
    int comparesize=0;
    char* pcurptr=NULL;
    char* plastptr=NULL;
    char* pretstr=NULL;
    int retsize=0;
    int curlen=0;


    if (dev == NULL) {
        if (ppmntdir && *ppmntdir) {
            free(*ppmntdir);
            *ppmntdir = NULL;
        }
        if (pmntsize) {
            *pmntsize = 0;
        }
        return 0;
    }

    if (ppmntdir == NULL || pmntsize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    ret = __get_mtab_lines(0,&pplines,&linesize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not split lines [%d]",ret);
        goto fail;
    }
    linenum = ret;
    comparesize = strlen(dev);
    /*added the compare space*/
    comparestr = (char*) malloc(comparesize + 2);
    if (comparestr == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", comparesize + 2, ret);
        goto fail;
    }
    memset(comparestr, 0 ,comparesize + 2);
    memcpy(comparestr, dev, comparesize);
    strcat(comparestr, " ");


    for (i=0;i<linenum;i++) {
        if (strncmp(comparestr, pplines[i], comparesize+1) == 0) {
            /*ok this is the lines ,so we found it*/
            pcurptr = pplines[i];
            plastptr = __get_line_item(pcurptr, &curlen);
            pcurptr = plastptr;
            plastptr = __get_line_item(pcurptr, &retlen);
            plastptr -= retlen;
            if (retsize < (retlen + 1) || pretstr == NULL) {
                if (retsize < (retlen + 1)) {
                    retsize = retlen + 1;
                }
                pretstr = (char*) malloc(retsize);
                if (pretstr == NULL) {
                    GETERRNO(ret);
                    ERROR_INFO("alloc %d error[%d]", retsize, ret);
                    goto fail;
                }
            }
            memset(pretstr, 0 ,retsize);
            memcpy(pretstr, plastptr, retlen);
            break;
        }
    }

    if (comparestr) {
        free(comparestr);
    }
    comparestr = NULL;
    comparesize = 0;
    __get_mtab_lines(1,&pplines,&linesize);

    if (*ppmntdir && *ppmntdir != pretstr) {
        free(*ppmntdir);
    }
    *ppmntdir = pretstr;
    *pmntsize = retsize;

    return retlen;
fail:
    if (pretstr && pretstr != *ppmntdir) {
        free(pretstr);
    }
    pretstr = NULL;
    if (comparestr) {
        free(comparestr);
    }
    comparestr = NULL;
    comparesize = 0;
    __get_mtab_lines(1,&pplines,&linesize);
    SETERRNO(ret);
    return ret;
}

int path_get_mntdir(const char* path, char** ppmntdir,int *pmntsize)
{
    char** pplines=NULL;
    int lsize=0,llen=0;
    int i;
    char* pmatch=NULL;
    int matchlen=0;
    char* pcurptr,*plastptr;
    int curlen;
    char* pretstr=NULL;
    int retsize=0;
    int ret;

    if (path == NULL) {
        if (ppmntdir && *ppmntdir) {
            free(*ppmntdir);
            *ppmntdir = NULL;
        }
        if (pmntsize) {
            *pmntsize = 0;
        }
        return 0;
    }
    if (*path != '/') {
        ret= -EINVAL;
        ERROR_INFO("path [%s] not absolute path", path);
        SETERRNO(ret);
        return ret;
    }

    if (ppmntdir == NULL || pmntsize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pretstr = *ppmntdir;
    retsize = *pmntsize;

    ret = __get_mtab_lines(0,&pplines,&lsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    llen = ret;

    for (i=0;i < llen;i++) {
        /*first to get the device*/
        pcurptr = pplines[i];
        /*second item*/
        plastptr = __get_line_item(pcurptr,&curlen);
        pcurptr = plastptr;
        plastptr = __get_line_item(pcurptr,&curlen);
        plastptr -= curlen;
        if (matchlen < curlen) {
            if (strncmp(path, plastptr, curlen) == 0) {
                matchlen = curlen;
                pmatch = plastptr;
            }
        }
    }

    if (matchlen > 0) {
        if (pretstr == NULL || retsize < (matchlen + 1)) {
            if (retsize < (matchlen + 1)) {
                retsize = matchlen + 1;
            }
            pretstr = (char*) malloc(retsize);
            if (pretstr == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", retsize,ret);
                goto fail;
            }
        }
        memset(pretstr, 0 ,retsize);
        memcpy(pretstr, pmatch, matchlen);
    } else {
        /*to give the null*/
        if (pretstr != NULL) {
            memset(pretstr, 0 ,retsize);
        }
    }

    __get_mtab_lines(1,&pplines,&lsize);

    if (*ppmntdir && *ppmntdir != pretstr) {
        free(*ppmntdir);
    }
    *ppmntdir = pretstr;
    *pmntsize = retsize;

    return matchlen;
fail:
    if (pretstr && pretstr != *ppmntdir) {
        free(pretstr);
    }
    pretstr = NULL;
    retsize = 0;
    __get_mtab_lines(1,&pplines,&lsize);
    SETERRNO(ret);
    return ret;
}

int __validate_len(const char* path)
{
    int pathlen ;
    int origlen = 0;
    /*we omit the path last / */
    pathlen = (int)strlen(path);    
    origlen = pathlen;
    /*we more than 0 for / simple one*/
    while( pathlen > 0 && (path[pathlen] == '\0' ||
        path[pathlen] == '/')) {
        pathlen --;
    }

    if (pathlen != origlen) {
        /*to give the more a byte*/
        pathlen ++;
    }
    return pathlen;
}

int mntdir_get_dev(const char* path,char** ppdev,int *pdevsize)
{
    char** pplines=NULL;
    int lsize=0,llen=0;
    int i;
    int matchlen=0;
    int pathlen=0;
    char* pcurptr,*plastptr;
    int curlen;
    int mlen=0;
    char* pdev=NULL;
    char* pretstr=NULL;
    int retsize=0;
    int ret;

    if (path == NULL) {
        if (ppdev && *ppdev) {
            free(*ppdev);
            *ppdev = NULL;
        }
        if (pdevsize) {
            *pdevsize = 0;
        }
        return 0;
    }
    if (*path != '/') {
        ret= -EINVAL;
        ERROR_INFO("path [%s] not absolute path", path);
        SETERRNO(ret);
        return ret;
    }

    if (ppdev == NULL || pdevsize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pretstr = *ppdev;
    retsize = *pdevsize;

    pathlen = __validate_len(path);

    ret = __get_mtab_lines(0,&pplines,&lsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    llen = ret;

    for (i=0;i < llen;i++) {
        /*first to get the device*/
        pdev = pplines[i];
        pcurptr = __get_line_item(pdev,&mlen);
        plastptr = __get_line_item(pcurptr,&curlen);
        plastptr -= curlen;
        if (curlen == pathlen && 
            strncmp(path, plastptr,curlen) == 0) {
            matchlen = mlen;
            break;
        }
    }

    if (matchlen > 0) {
        if (pretstr == NULL || retsize < (matchlen + 1)) {
            if (retsize < (matchlen + 1)) {
                retsize = matchlen + 1;
            }
            pretstr = (char*) malloc(retsize);
            if (pretstr == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", retsize,ret);
                goto fail;
            }
        }
        memset(pretstr, 0 ,retsize);
        memcpy(pretstr, pdev, matchlen);
    } else {
        /*to give the null*/
        if (pretstr != NULL) {
            memset(pretstr, 0 ,retsize);
        }
    }

    __get_mtab_lines(1,&pplines,&lsize);

    if (*ppdev && *ppdev != pretstr) {
        free(*ppdev);
    }
    *ppdev = pretstr;
    *pdevsize = retsize;

    return matchlen;
fail:
    if (pretstr && pretstr != *ppdev) {
        free(pretstr);
    }
    pretstr = NULL;
    retsize = 0;
    __get_mtab_lines(1,&pplines,&lsize);
    SETERRNO(ret);
    return ret;    
}

int mntdir_get_fstype(const char* path,char** ppfstype,int *pfssize)
{
    char** pplines=NULL;
    int lsize=0,llen=0;
    int i;
    char* pmatch=NULL;
    int matchlen=0;
    int pathlen=0;
    char* pcurptr,*plastptr;
    int curlen;
    char* pretstr=NULL;
    int retsize=0;
    int ret;

    if (path == NULL) {
        if (ppfstype && *ppfstype) {
            free(*ppfstype);
            *ppfstype = NULL;
        }
        if (pfssize) {
            *pfssize = 0;
        }
        return 0;
    }
    if (*path != '/') {
        ret= -EINVAL;
        ERROR_INFO("path [%s] not absolute path", path);
        SETERRNO(ret);
        return ret;
    }
    /*we omit the path last / */
    pathlen = __validate_len(path);

    if (ppfstype == NULL || pfssize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pretstr = *ppfstype;
    retsize = *pfssize;

    ret = __get_mtab_lines(0,&pplines,&lsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    llen = ret;

    for (i=0;i < llen;i++) {
        /*first to get the device*/
        pcurptr = pplines[i];
        plastptr = __get_line_item(pcurptr,&curlen);
        pcurptr = plastptr;
        plastptr = __get_line_item(pcurptr,&curlen);
        plastptr -= curlen;
        if (curlen == pathlen && 
            strncmp(path, plastptr,curlen) == 0) {
            pcurptr = plastptr;
            plastptr = __get_line_item(pcurptr,&curlen);
            pcurptr = plastptr ;
            plastptr = __get_line_item(pcurptr,&curlen);
            plastptr -= curlen;
            pmatch = plastptr;
            matchlen = curlen;
            break;
        }
    }

    if (matchlen > 0) {
        if (pretstr == NULL || retsize < (matchlen + 1)) {
            if (retsize < (matchlen + 1)) {
                retsize = matchlen + 1;
            }
            pretstr = (char*) malloc(retsize);
            if (pretstr == NULL) {
                GETERRNO(ret);
                ERROR_INFO("alloc %d error[%d]", retsize,ret);
                goto fail;
            }
        }
        memset(pretstr, 0 ,retsize);
        memcpy(pretstr, pmatch, matchlen);
    } else {
        /*to give the null*/
        if (pretstr != NULL) {
            memset(pretstr, 0 ,retsize);
        }
    }

    __get_mtab_lines(1,&pplines,&lsize);

    if (*ppfstype && *ppfstype != pretstr) {
        free(*ppfstype);
    }
    *ppfstype = pretstr;
    *pfssize = retsize;

    return matchlen;
fail:
    if (pretstr && pretstr != *ppfstype) {
        free(pretstr);
    }
    pretstr = NULL;
    retsize = 0;
    __get_mtab_lines(1,&pplines,&lsize);
    SETERRNO(ret);
    return ret;
}