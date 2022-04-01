
int mkdir_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* dir = NULL;
    int i;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i] != NULL; i++) {
        dir = parsestate->leftargs[i];
        ret = mkdir_p(dir, pargs->m_mask);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "can not mkdir [%s] error[%d]\n", dir, ret);
            goto out;
        }

        fprintf(stdout, "[%d][%s] [%s]\n", i, dir, ret > 0 ? "created" : "exists");
    }

    ret  = 0;
out:
    SETERRNO(ret);
    return ret;
}

int cpfile_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* srcfile = NULL;
    char* dstfile = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    argc = argc;
    argv = argv;


    srcfile = parsestate->leftargs[0];
    dstfile = parsestate->leftargs[1];
    ret = cp_file(srcfile, dstfile);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "cp [%s] => [%s] error[%d]\n", srcfile, dstfile, ret);
        goto out;
    }

    fprintf(stdout, "cp [%s] => [%s] size[%d]\n", srcfile, dstfile, ret);
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int readoffset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* infile = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;
    uint64_t offset = 0;
    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    GET_OPT_NUM64(offset, "offset");
    GET_OPT_INT(bufsize, "buffer size");

    if (pargs->m_input == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the input by --input|-i\n");
        goto out;
    }
    infile = pargs->m_input;

    pbuf = (char*)malloc(bufsize);
    if (pbuf == NULL) {
        GETERRNO(ret);
        fprintf(stderr, "alloc %d error[%d]\n", bufsize, ret);
        goto out;
    }

    ret = read_offset_file(infile, offset, pbuf, bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read [%s] error[%d]\n", infile, ret );
        goto  out;
    }
    buflen = ret;
    fprintf(stdout, "read [%s] ret[%d]\n", infile, buflen);
    __debug_buf(stdout, pbuf, buflen);
    ret = 0;
out:
    if (pbuf) {
        free(pbuf);
    }
    pbuf = NULL;
    SETERRNO(ret);
    return ret;
}


int writeoffset_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    char* infile = NULL;
    char* outfile = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;
    uint64_t offset = 0;
    init_log_verbose(pargs);
    argc = argc;
    argv = argv;

    GET_OPT_NUM64(offset, "offset");

    if (pargs->m_input == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the input by --input|-i\n");
        goto out;
    }
    infile = pargs->m_input;
    if (pargs->m_output == NULL) {
        ret = -EINVAL;
        fprintf(stderr, "need specified the output by --output|-o\n");
        goto out;
    }
    outfile = pargs->m_output;

    ret = read_file_whole(infile, &pbuf, &bufsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read [%s] error[%d]\n", infile, ret );
        goto out;
    }
    buflen = ret;

    ret = write_offset_file(outfile, offset, pbuf, buflen);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "write [%s] error[%d]\n", outfile, ret);
        goto out;
    }

    fprintf(stdout, "read [%s] => [%s] offset[%ld:0x%lx] len[%d]\n", infile, outfile, offset, offset, buflen);
    __debug_buf(stdout, pbuf, buflen);
    ret = 0;
out:
    read_file_whole(NULL, &pbuf, &bufsize);
    SETERRNO(ret);
    return ret;
}

int readlines_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char** pplines = NULL;
    int lsize = 0, llen = 0;
    int i, j;
    pargs_options_t pargs = (pargs_options_t) popt;
    char* infile = NULL;
    int ret;
    int maxlen = 0;
    int maxi;

    init_log_verbose(pargs);

    for (i = 0; parsestate->leftargs != NULL && parsestate->leftargs[i] != NULL ; i++) {
        infile = parsestate->leftargs[i];
        ret = read_file_lines(infile, &pplines, &lsize);
        if (ret < 0) {
            GETERRNO(ret);
            fprintf(stderr, "read [%s] error[%d]\n", infile, ret);
            goto out;
        }
        llen = ret;

        maxi = 1;
        maxlen = 1;
        while (maxi < llen) {
            maxi *= 10;
            maxlen ++;
        }

        fprintf(stdout, "[%d] [%s] lines[%d]\n", i, infile, llen);
        for (j = 0; j < llen; j++) {
            fprintf(stdout, "    [%*d][%s]\n", maxlen, j, pplines[j]);
        }
    }

    ret = 0;
out:
    read_file_lines(NULL, &pplines, &lsize);
    SETERRNO(ret);
    return ret;
}

int exists_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret;
    pargs_options_t pargs = (pargs_options_t) popt;
    int i;
    const char* fname;
    init_log_verbose(pargs);

    for (i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        fname = parsestate->leftargs[i];
        ret = is_path_exist(fname);
        fprintf(stdout,"[%d][%s] %s\n",i,fname,ret > 0 ? "exist" : "not exist");
    }
    ret = 0;

    SETERRNO(ret);
    return ret;
}

int format_md5_digest(pmd5_state_t p, char* fmt, int size)
{
    char* pcur = fmt;
    int leftlen = size;
    int ret;
    int i;
    unsigned char* pc;

    for (i = 0; i < 4; i++) {
        pc = (unsigned char*) & (p->state[i]);
        ret = snprintf(pcur, (size_t)leftlen, "%02x%02x%02x%02x", pc[0], pc[1], pc[2], pc[3]);
        if (ret < 0 || ret >= (leftlen - 1)) {
            return -1;
        }
        pcur += ret;
        leftlen -= ret;
    }
    return 0;
}

int md5sum_file(char* fname, uint64_t size,char* digest,int digsize)
{
    char* pbuf = NULL;
    int bufsize = 0, buflen=0;
    int overed = 0;
    uint64_t cursize;
    md5_state_t s;
    unsigned char bufdig[70];
    int ret;

    bufsize = 1024 * 1024;
    pbuf = (char*)malloc((size_t)bufsize);
    if (pbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    cursize = 0;
    init_md5_state(&s);
    while (1) {
        buflen = bufsize;
        ret = read_offset_file(fname,cursize,pbuf,buflen);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }
        DEBUG_BUFFER_FMT(pbuf, (buflen > 0x20 ? 0x20 : buflen), "[%s] at [0x%llx]", fname, cursize);
        buflen = ret;
        if (buflen > 0) {
            md5sum((unsigned char*)pbuf, (unsigned int) buflen, bufdig, &s);    
        }        
        cursize += buflen;
        if (buflen < bufsize) {
            overed = 1;
            break;
        }
    }

    if ((buflen & 0x3f) == 0) {
        md5sum((unsigned char*)pbuf, (unsigned int)0, bufdig, &s);
    }
    
    format_md5_digest(&s, digest, digsize);

    if (pbuf) {
        free(pbuf);
    }

    return overed;
fail:
    if (pbuf) {
        free(pbuf);
    }
    SETERRNO(ret);
    return ret;
}

int md5_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    char* fname;
    char digest[64];
    int i;
    int ret;

    init_log_verbose(pargs);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        fname = parsestate->leftargs[i];
        ret = md5sum_file(fname,0, digest, sizeof(digest));
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("calc [%s] error[%d]", fname, ret);
            goto out;
        }
        fprintf(stdout, "[%s] => [%s]\n",fname, digest);
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}
