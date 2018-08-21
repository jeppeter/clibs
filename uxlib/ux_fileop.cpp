#include <ux_err.h>
#include <ux_fileop.h>
#include <ux_output_debug.h>
#include <ux_strop.h>
#include <ux_regex.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>


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


int read_file_whole(char* infile, char** ppoutbuf, int *bufsize)
{
    int ret = 0;
    FILE* fp = NULL;
    if (infile == NULL) {
        return __read_fp_buffer(NULL, ppoutbuf, bufsize);
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

    ret = __read_fp_buffer(fp, ppoutbuf, bufsize);
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

int read_stdin_whole(int freed, char** ppoutbuf, int *bufsize)
{
    if (freed) {
        return __read_fp_buffer(NULL, ppoutbuf, bufsize);
    }

    return __read_fp_buffer(stdin, ppoutbuf, bufsize);
}


int __write_fp_out(FILE* fp, char* poutbuf, int outsize)
{
    size_t outlen = 0;
    size_t curlen = 0;
    int ret;

    if (fp == NULL || poutbuf == NULL || outsize < 0) {
        ret  = -EINVAL;
        goto fail;
    }

    while ( (int)outlen < outsize) {
        curlen = (outsize - outlen);
        ret = (int) fwrite(&(poutbuf[outlen]), 1, curlen, fp);
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

int write_file_whole(char* outfile, char* poutbuf, int outsize)
{
    FILE* fp = NULL;
    int ret = 0;

    if (outfile == NULL) {
        ret = -EINVAL;
        goto fail;
    }

    fp = fopen(outfile, "wb");
    if (fp == NULL) {
        GETERRNO(ret);
        ERROR_INFO("open [%s] error[%d]", outfile, ret);
        goto fail;
    }

    ret = __write_fp_out(fp, poutbuf, outsize);
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

int write_out_whole(int flag, char* poutbuf, int outsize)
{
    FILE* fp = NULL;
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

    ret = __write_fp_out(fp, poutbuf, outsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    return ret;
fail:
    SETERRNO(ret);
    return ret;
}

int __get_dot_dot_path(char* path,char** pppath, int *psize)
{
    int ret;
    char** pparrs= NULL;
    int arrsize=0,arrlen=0;
    char* pretpath=*pppath;
    int retsize=*psize;
    int retlen=0;
    char* pcurpath=NULL;
    int curpathsize=0;
    int i;
    if (path == NULL) {
        if(pppath && *pppath) {
            free(*pppath);
            *pppath = NULL;
        }
        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (*path != '/' || pppath == NULL || psize == NULL) {
        ret = -EINVAL;
        SETERRNO(ret);
        return ret;
    }

    pretpath = *pppath;
    retsize = *psize;

    ret = split_chars_re(path,"[/]+", REGEX_NONE,&pparrs,&arrsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    arrlen = ret;

    while (arrlen > 0 && pparrs[arrlen-1] != NULL
         && strlen(pparrs[arrlen-1]) == 0) {
        arrlen --;
    }

    ret = snprintf_safe(&pcurpath,&curpathsize,"/");
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    for (i=0;i<(arrlen);i++) {
        if (strlen(pparrs[i]) == 0) {
            continue;
        }
        ret = append_snprintf_safe(&pcurpath,&curpathsize,"%s/", pparrs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    retlen = strlen(pcurpath);

    if (retlen > (retsize -1) || pretpath == NULL) {
        if (retlen > (retsize - 1)) {
            retsize = retlen + 1;
        }
        pretpath = (char*) malloc(retsize);
        if (pretpath == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", retsize, ret);
            goto fail;
        }
    }
    memset(pretpath, 0, retsize);
    memcpy(pretpath, pcurpath, retlen);


    snprintf_safe(&pcurpath,&curpathsize,NULL);
    split_chars_re(NULL,NULL,REGEX_NONE,&pparrs,&arrsize);

    if (*pppath && *pppath != pretpath) {
        free(*pppath);
    }
    *pppath = pretpath;
    *psize = retsize;
    return retlen;
fail:
    if (pretpath && pretpath != *pppath) {
        free(pretpath);
    }
    pretpath = NULL;
    retsize = 0;
    snprintf_safe(&pcurpath,&curpathsize,NULL);
    split_chars_re(NULL,NULL,REGEX_NONE,&pparrs,&arrsize);
    SETERRNO(ret);
    return ret;

}

int realpath_safe(char* path, char** pprealpath, int *psize)
{
    char* pretstr = NULL;
    int retsize = 0;
    int retlen = 0;
    int ret;
    int isabs=0;
    char** pparrs = NULL;
    int arrsize= 0;
    int arrlen = 0;
    char* cwd=NULL;
    int cwdsize=0;
    char* prealpath = NULL;
    int realsize=0;
    char* pdotdotpath=NULL;
    int dotdotsize=0;
    int ishome = 0;
    int i;
    int startidx=0;
    char* ptr=NULL;
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

    retlen = 1;
    while(path[retlen] != '\0') {
        if (path[retlen] == '~') {
            /*we can not get stridle in the middle */
            ret = -EINVAL;
            SETERRNO(ret);
            return ret;
        }
        retlen ++;
    }

    if (*path == '/') {
        isabs = 1;
    } else if (*path == '~') {
        ishome = 1;
    }

    ret = split_chars_re(path,"[/]+", REGEX_NONE, &pparrs,&arrsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    arrlen = ret;

    if (isabs) {
        ret = snprintf_safe(&prealpath, &realsize, "/");
    } else if (ishome) {
        if (path[1] != '/' && path[1] != '\0') {
            ret = -EINVAL;
            ERROR_INFO("[%s] not valid path",path);
            goto fail;
        }
        ptr = getenv("HOME");
        if (ptr == NULL) {
            ret = -ENOENT;
            ERROR_INFO("can not get HOME env");
            goto fail;
        }
        startidx = 1;
        ret = snprintf_safe(&prealpath,&realsize,"%s/",ptr);
    } else {
        cwdsize = 0x100;
    cwd_again:
        if (cwd != NULL) {
            free(cwd);
        }
        cwd = NULL;
        cwd = (char*) malloc(cwdsize);
        if (cwd == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]",cwdsize, ret);
            goto fail;
        }
        ptr = getcwd(cwd , cwdsize);
        if (ptr == NULL) {
            GETERRNO(ret);
            if (ret == -ERANGE) {
                cwdsize <<= 1;
                goto cwd_again;
            }
            ERROR_INFO("get cwd error[%d]", ret);
            goto fail;
        }
        ret = snprintf_safe(&prealpath,&realsize,"%s/",cwd);
    }

    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    for (i=startidx;i<arrlen;i++) {
        if (strlen(pparrs[i]) == 0) {
            continue;
        }
        if (strcmp(pparrs[i],".") == 0) {
            continue;
        } else if (strcmp(pparrs[i],"..") == 0) {
            ret = __get_dot_dot_path(prealpath,&pdotdotpath,&dotdotsize);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            ret= snprintf_safe(&prealpath,&realsize,"%s/",pdotdotpath);
            if (ret < 0) {
                GETERRNO(ret);
                goto fail;
            }
            continue;
        }
        ret=  append_snprintf_safe(&prealpath,&realsize,"%s/", pparrs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
    }

    retlen = strlen(prealpath);


    if (pretstr == NULL || retsize <= (retlen)) {
        if (retsize <= retlen) {
            retsize = retlen + 1;
        }
        pretstr = (char*) malloc(retsize);
        if (pretstr == NULL) {
            GETERRNO(ret);
            ERROR_INFO("alloc %d error[%d]", retsize, ret);
            goto fail;
        }
    }

    memset(pretstr, 0, retsize);
    memcpy(pretstr, prealpath, retlen);

    snprintf_safe(&prealpath,&realsize, NULL);
    if (cwd) {
        free(cwd);
    }
    cwd = NULL;
    cwdsize = 0;
    __get_dot_dot_path(NULL,&pdotdotpath,&dotdotsize);
    if (*pprealpath && *pprealpath != pretstr) {
        free(*pprealpath);
    }
    *pprealpath = pretstr;
    *psize = retsize;
    return retlen;
fail:
    snprintf_safe(&prealpath,&realsize, NULL);
    if (cwd) {
        free(cwd);
    }
    cwd = NULL;
    cwdsize = 0;
    __get_dot_dot_path(NULL,&pdotdotpath,&dotdotsize);
    if (pretstr && pretstr != *pprealpath) {
        free(pretstr);
    }
    pretstr = NULL;
    SETERRNO(ret);
    return ret;
}

int read_file_offset(char* infile,unsigned long long offset,char* pbuf,int bufsize)
{
    int rfd=-1;
    int ret;
    int retlen=0;
    off64_t retoff;

    if (infile == NULL || pbuf == NULL || bufsize <= 0) {
        ret =-EINVAL;
        SETERRNO(ret);
        return ret;
    }

    rfd = open(infile,O_RDONLY);
    if (rfd < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not open[%s] error[%d]", infile, ret);
        goto fail;
    }

    if (offset != 0) {
        SETERRNO(0);
        retoff = lseek64(rfd, offset, SEEK_SET);
        if (retoff == (off64_t) -1) {
            GETERRNO_DIRECT(ret);
            if (ret != 0) {
                ERROR_INFO("seek [%s] offset [%lld:0x%llx] error[%d]",
                    infile,offset,offset, ret);
                goto fail;
            }
        }
    }

    while(retlen < bufsize) {
        ret = read(rfd,&(pbuf[retlen]), (bufsize - retlen));
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("read [%s] offset[%lld:0x%llx] error[%d]",
                infile, (offset + retlen),(offset + retlen), ret);
            goto fail;
        } else if (ret == 0){
            break;
        }
        retlen += ret;
    }

    if (rfd>=0) {
        close(rfd);
    }
    rfd = -1;

    return retlen;
fail:
    if (rfd>=0) {
        close(rfd);
    }
    rfd = -1;
    SETERRNO(ret);
    return ret;
}

int write_file_offset(char* outfile,unsigned long long offset,char* pbuf,int bufsize)
{
    int wfd=-1;
    int ret;
    int retlen=0;
    off64_t retoff;

    if (outfile == NULL || pbuf == NULL || bufsize <= 0) {
        ret =-EINVAL;
        SETERRNO(ret);
        return ret;
    }

    wfd = open(outfile,O_RDWR | O_CREAT,0660);
    if (wfd < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not open[%s] error[%d]", outfile, ret);
        goto fail;
    }

    if (offset != 0) {
        SETERRNO(0);
        retoff = lseek64(wfd, offset, SEEK_SET);
        if (retoff == (off64_t) -1) {
            GETERRNO_DIRECT(ret);
            if (ret != 0) {
                ERROR_INFO("seek [%s] offset [%lld:0x%llx] error[%d]",
                    outfile,offset,offset, ret);
                goto fail;
            }
        }
    }

    while(retlen < bufsize) {
        ret = write(wfd,&(pbuf[retlen]), (bufsize - retlen));
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("write [%s] offset[%lld:0x%llx] error[%d]",
                outfile, (offset + retlen),(offset + retlen), ret);
            goto fail;
        } 
        retlen += ret;
    }

    if (wfd>=0) {
        close(wfd);
    }
    wfd = -1;

    return retlen;
fail:
    if (wfd>=0) {
        close(wfd);
    }
    wfd = -1;
    SETERRNO(ret);
    return ret;
}


#define  MTAB_FILE    "/etc/mtab"

int __get_mtab_lines(int freed, char*** ppplines, int *plinesize)
{
    char* mtabcont = NULL;
    int mtabsize = 0;
    int ret;
    int llen = 0;
    if (freed) {
        split_lines(NULL, ppplines, plinesize);
        return 0;
    }
    ret = read_file_whole((char*)MTAB_FILE, &mtabcont, &mtabsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = split_lines(mtabcont, ppplines, plinesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    llen = ret;

    read_file_whole(NULL, &mtabcont, &mtabsize);
    return llen;
fail:
    split_lines(NULL, ppplines, plinesize);
    read_file_whole(NULL, &mtabcont, &mtabsize);
    SETERRNO(ret);
    return ret;
}

char* __get_line_item(char* ptr, int *plen)
{
    int len = 0;
    char* pcurptr = ptr;
    while (*pcurptr == ' ') {
        pcurptr ++;
    }
    ptr = pcurptr;
    while (*pcurptr != '\0' && *pcurptr != ' ') {
        pcurptr ++;
    }

    len = pcurptr - ptr;
    if (plen) {
        *plen = len;
    }
    return pcurptr;
}

int dev_get_mntdir(const char* dev, char** ppmntdir, int *pmntsize)
{
    char** pplines = NULL;
    int linesize = 0;
    int linenum = 0;
    int retlen = 0;
    int ret;
    int i;
    char* comparestr = NULL;
    int comparesize = 0;
    char* pcurptr = NULL;
    char* plastptr = NULL;
    char* pretstr = NULL;
    int retsize = 0;
    int curlen = 0;


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

    ret = __get_mtab_lines(0, &pplines, &linesize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not split lines [%d]", ret);
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
    memset(comparestr, 0 , comparesize + 2);
    memcpy(comparestr, dev, comparesize);
    strcat(comparestr, " ");


    for (i = 0; i < linenum; i++) {
        if (strncmp(comparestr, pplines[i], comparesize + 1) == 0) {
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
            memset(pretstr, 0 , retsize);
            memcpy(pretstr, plastptr, retlen);
            break;
        }
    }

    if (comparestr) {
        free(comparestr);
    }
    comparestr = NULL;
    comparesize = 0;
    __get_mtab_lines(1, &pplines, &linesize);

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
    __get_mtab_lines(1, &pplines, &linesize);
    SETERRNO(ret);
    return ret;
}

int path_get_mntdir(const char* path, char** ppmntdir, int *pmntsize)
{
    char** pplines = NULL;
    int lsize = 0, llen = 0;
    int i;
    char* pmatch = NULL;
    int matchlen = 0;
    char* pcurptr, *plastptr;
    int curlen;
    char* pretstr = NULL;
    int retsize = 0;
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
        ret = -EINVAL;
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

    ret = __get_mtab_lines(0, &pplines, &lsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    llen = ret;

    for (i = 0; i < llen; i++) {
        /*first to get the device*/
        pcurptr = pplines[i];
        /*second item*/
        plastptr = __get_line_item(pcurptr, &curlen);
        pcurptr = plastptr;
        plastptr = __get_line_item(pcurptr, &curlen);
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
                ERROR_INFO("alloc %d error[%d]", retsize, ret);
                goto fail;
            }
        }
        memset(pretstr, 0 , retsize);
        memcpy(pretstr, pmatch, matchlen);
    } else {
        /*to give the null*/
        if (pretstr != NULL) {
            memset(pretstr, 0 , retsize);
        }
    }

    __get_mtab_lines(1, &pplines, &lsize);

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
    __get_mtab_lines(1, &pplines, &lsize);
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
    while ( pathlen > 0 && (path[pathlen] == '\0' ||
                            path[pathlen] == '/')) {
        pathlen --;
    }

    if (pathlen != origlen) {
        /*to give the more a byte*/
        pathlen ++;
    }
    return pathlen;
}

int mntdir_get_dev(const char* path, char** ppdev, int *pdevsize)
{
    char** pplines = NULL;
    int lsize = 0, llen = 0;
    int i;
    int matchlen = 0;
    int pathlen = 0;
    char* pcurptr, *plastptr;
    int curlen;
    int mlen = 0;
    char* pdev = NULL;
    char* pretstr = NULL;
    int retsize = 0;
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
        ret = -EINVAL;
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

    ret = __get_mtab_lines(0, &pplines, &lsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    llen = ret;

    for (i = 0; i < llen; i++) {
        /*first to get the device*/
        pdev = pplines[i];
        pcurptr = __get_line_item(pdev, &mlen);
        plastptr = __get_line_item(pcurptr, &curlen);
        plastptr -= curlen;
        if (curlen == pathlen &&
                strncmp(path, plastptr, curlen) == 0) {
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
                ERROR_INFO("alloc %d error[%d]", retsize, ret);
                goto fail;
            }
        }
        memset(pretstr, 0 , retsize);
        memcpy(pretstr, pdev, matchlen);
    } else {
        /*to give the null*/
        if (pretstr != NULL) {
            memset(pretstr, 0 , retsize);
        }
    }

    __get_mtab_lines(1, &pplines, &lsize);

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
    __get_mtab_lines(1, &pplines, &lsize);
    SETERRNO(ret);
    return ret;
}

int mntdir_get_fstype(const char* path, char** ppfstype, int *pfssize)
{
    char** pplines = NULL;
    int lsize = 0, llen = 0;
    int i;
    char* pmatch = NULL;
    int matchlen = 0;
    int pathlen = 0;
    char* pcurptr, *plastptr;
    int curlen;
    char* pretstr = NULL;
    int retsize = 0;
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
        ret = -EINVAL;
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

    ret = __get_mtab_lines(0, &pplines, &lsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    llen = ret;

    for (i = 0; i < llen; i++) {
        /*first to get the device*/
        pcurptr = pplines[i];
        plastptr = __get_line_item(pcurptr, &curlen);
        pcurptr = plastptr;
        plastptr = __get_line_item(pcurptr, &curlen);
        plastptr -= curlen;
        if (curlen == pathlen &&
                strncmp(path, plastptr, curlen) == 0) {
            pcurptr = plastptr;
            plastptr = __get_line_item(pcurptr, &curlen);
            pcurptr = plastptr ;
            plastptr = __get_line_item(pcurptr, &curlen);
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
                ERROR_INFO("alloc %d error[%d]", retsize, ret);
                goto fail;
            }
        }
        memset(pretstr, 0 , retsize);
        memcpy(pretstr, pmatch, matchlen);
    } else {
        /*to give the null*/
        if (pretstr != NULL) {
            memset(pretstr, 0 , retsize);
        }
    }

    __get_mtab_lines(1, &pplines, &lsize);

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
    __get_mtab_lines(1, &pplines, &lsize);
    SETERRNO(ret);
    return ret;
}

int __mkdir_inner(const char* dname, int mask)
{
    int ret;
    ret = mkdir(dname,(mode_t) mask);
    if (ret < 0) {
        GETERRNO(ret);
        if (ret == -EEXIST) {
            return 0;
        }
        ERROR_INFO("mkdir [%s] with mask [%o] error [%d]", dname, mask, ret);
        SETERRNO(ret);
        return ret;
    }
    return 1;
}

int mkdir_p(const char* dname, int mask)
{
    char** pparrs = NULL;
    int arrsize = 0;
    int arrlen = 0;
    int ret;
    int i;
    char* pcurdir = NULL;
    int curdirsize = 0;
    char* realdname = NULL;
    int realsize = 0;
    int created = 0;

    ret = realpath_safe((char*)dname, &realdname, &realsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    ret = split_chars_re(realdname, "[/]+", REGEX_NONE, &pparrs, &arrsize);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not split [%s]", dname);
        goto fail;
    }
    arrlen = ret;

    ret = snprintf_safe(&pcurdir, &curdirsize, "/");
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /**/
    for (i = 0; i < arrlen; i++) {
        if (strlen(pparrs[i]) == 0) {
            continue;
        }
        ret = append_snprintf_safe(&pcurdir, &curdirsize, "%s/", pparrs[i]);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        ret = __mkdir_inner(pcurdir, mask);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        created += ret;
    }



    snprintf_safe(&pcurdir, &curdirsize, NULL);
    split_chars_re(NULL, NULL, REGEX_NONE, &pparrs, &arrsize);
    realpath_safe(NULL, &realdname, &realsize);
    return created;
fail:
    snprintf_safe(&pcurdir, &curdirsize, NULL);
    split_chars_re(NULL, NULL, REGEX_NONE, &pparrs, &arrsize);
    realpath_safe(NULL, &realdname, &realsize);
    SETERRNO(ret);
    return ret;
}

int __cp_file_inner(const char* srcfile, const char* dstfile)
{
    int rfd = -1, wfd = -1;
    char* preadbuf = NULL;
    int readsize = 0;
    int bufsize = 0;
    int readlen = 0;
    int wlen = 0;
    int ret;

    rfd = open(srcfile, O_RDONLY);
    if (rfd < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not open[%s] read error[%d]", srcfile, ret);
        goto fail;
    }

    wfd = open(dstfile, O_WRONLY | O_CREAT| O_TRUNC);
    if (wfd < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not open[%s] write error[%d]", dstfile, ret);
        goto fail;
    }
    bufsize = (1 << 20);

    preadbuf = (char*)malloc(bufsize);
    if (preadbuf == NULL) {
        GETERRNO(ret);
        ERROR_INFO("alloc %d error[%d]", bufsize, ret);
        goto fail;
    }

    while (1) {
        ret = read(rfd, preadbuf, bufsize);
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("read [%s] [%d] error[%d]", srcfile, readsize, ret);
            goto fail;
        } else if (ret == 0) {
            break;
        }
        readlen = ret;
        wlen = 0;
        while (wlen < readlen) {
            ret = write(wfd, &(preadbuf[wlen]), readlen - wlen);
            if (ret < 0) {
                GETERRNO(ret);
                ERROR_INFO("[%s] [%d] write error[%d]", dstfile, readsize + wlen,ret);
                goto fail;
            }
            wlen += ret;
        }
        readsize += readlen;
    }

    if (preadbuf) {
        free(preadbuf);
    }
    preadbuf = NULL;

    if (rfd >= 0) {
        close(rfd);
    }
    rfd = -1;
    if (wfd >= 0) {
        close(wfd);
    }
    wfd = -1;

    return readsize;
fail:
    if (preadbuf) {
        free(preadbuf);
    }
    preadbuf = NULL;

    if (rfd >= 0) {
        close(rfd);
    }
    rfd = -1;
    if (wfd >= 0) {
        close(wfd);
    }
    wfd = -1;
    SETERRNO(ret);
    return ret;
}

int cp_file(char* srcfile, char* dstfile)
{
    char* dfiledup = NULL;
    struct stat srcstat;
    int ret;
    int cplen = 0;
    char* dname = NULL;

    ret = stat(srcfile, &srcstat);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("[%s] stat error[%d]", srcfile, ret);
        goto fail;
    }

    if (!S_ISREG(srcstat.st_mode)) {
        ret = -EINVAL;
        ERROR_INFO("[%s] not regular file", srcfile);
        goto fail;
    }

    dfiledup = strdup(dstfile);
    if (dfiledup == NULL) {
        GETERRNO(ret);
        ERROR_INFO("strdup [%s] error[%d]", dstfile, ret);
        goto fail;
    }

    dname = dirname(dfiledup);
    if (dname == NULL) {
        GETERRNO(ret);
        ERROR_INFO("dirname [%s] error[%d]", dstfile, ret);
        goto fail;
    }

    ret = mkdir_p(dname,0761);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    /*now open */
    ret = __cp_file_inner(srcfile, dstfile);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    cplen = ret;

    if (dfiledup) {
        free(dfiledup);
    }
    dfiledup = NULL;

    return cplen;
fail:
    if (dfiledup) {
        free(dfiledup);
    }
    dfiledup = NULL;
    SETERRNO(ret);
    return ret;

}