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

int md5sum_file(char* fname, uint64_t size, char* digest, int digsize)
{
    void* pf = NULL;
    char* pbuf = NULL;
    int bufsize = 0, buflen = 0;
    uint64_t fsize = 0;
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


    pf = open_file(fname, READ_MODE);
    if (pf == NULL) {
        GETERRNO(ret);
        goto fail;
    }

    fsize = get_file_size(pf);
    cursize = 0;
    init_md5_state(&s);
    while (cursize < size || size == 0) {
        buflen = bufsize;
        if ((uint64_t)buflen > (fsize - cursize)) {
            buflen = (int) (fsize - cursize);
        }
        DEBUG_BUFFER_FMT(pbuf, (buflen > 0x20 ? 0x20 : buflen), "[%s] at [0x%llx]", fname, cursize);
        ret = read_file(pf, cursize, pbuf, (uint32_t)buflen);
        if (ret < 0) {
            GETERRNO(ret);
            goto fail;
        }

        md5sum((unsigned char*)pbuf, (unsigned int) buflen, bufdig, &s);
        cursize += buflen;
        if (cursize == fsize) {
            overed = 1;
            break;
        }
    }

    if (overed == 0 || (buflen & 0x3f) == 0) {
        md5sum((unsigned char*)pbuf, (unsigned int)0, bufdig, &s);
    }

    format_md5_digest(&s, digest, digsize);

    if (pbuf) {
        free(pbuf);
    }
    close_file(&pf);

    return overed;
fail:
    if (pbuf) {
        free(pbuf);
    }
    close_file(&pf);
    SETERRNO(ret);
    return ret;
}

int md5sum_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    pargs_options_t pargs = (pargs_options_t) popt;
    char* fname;
    char digest[64];
    int i;
    int ret;


    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

    for (i = 0; parsestate->leftargs && parsestate->leftargs[i]; i++) {
        fname = parsestate->leftargs[i];
        ret = md5sum_file(fname, 0, digest, sizeof(digest));
        if (ret < 0) {
            GETERRNO(ret);
            ERROR_INFO("calc [%s] error[%d]", fname, ret);
            goto out;
        }
        fprintf(stdout, "[%s] => [%s]\n", fname, digest);
    }
    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}

int rsaenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    char* pout = NULL;
    int outsize = 0;
    int outlen = 0;
    rsa_context ctx = {0};
    int bitsize = 2048;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;
    int blksize = 0;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);
    GET_OPT_INT(bitsize, "bitsize");
    ret = rsa_init_nums(&ctx, bitsize, pargs->m_rsan, pargs->m_rsae, NULL, 16);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not init rsa");
        goto out;
    }

    ret = read_file_whole_stdin(0, pargs->m_input, &pin, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    inlen = ret;
    blksize = bitsize / 8;

    outsize = ((inlen + blksize - 1) / blksize ) * blksize * 2;
    pout = (char*) malloc((size_t)outsize);
    if (pout == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = rsa_encrypt((unsigned char*)pout, outsize, (unsigned char*)pin, inlen, &ctx, printf);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    outlen = ret;
    DEBUG_BUFFER_FMT(pin, inlen, "input len");
    DEBUG_BUFFER_FMT(pout, outlen, "output len");
    ret = write_file_whole_stdout(pargs->m_output, pout, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    if (pout) {
        free(pout);
    }
    pout = NULL;
    read_file_whole_stdin(1, NULL, &pout, &outsize);
    rsa_free(&ctx);
    SETERRNO(ret);
    return ret;
}

int rsadec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    char* pout = NULL;
    int outsize = 0;
    int outlen = 0;
    rsa_context ctx = {0};
    int bitsize = 2048;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);
    GET_OPT_INT(bitsize, "bitsize");
    ret = rsa_init_nums(&ctx, bitsize, pargs->m_rsan, NULL, pargs->m_rsad, 16);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not init rsa");
        goto out;
    }

    ret = read_file_whole_stdin(0, pargs->m_input, &pin, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    inlen = ret;

    outsize = inlen;
    pout = (char*) malloc((size_t)outsize);
    if (pout == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = rsa_decrypt((unsigned char*)pout, outsize, (unsigned char*)pin, inlen, &ctx, printf);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    outlen = ret;
    DEBUG_BUFFER_FMT(pin, inlen, "input len");
    DEBUG_BUFFER_FMT(pout, outlen, "output len");
    ret = write_file_whole_stdout(pargs->m_output, pout, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    if (pout) {
        free(pout);
    }
    pout = NULL;
    read_file_whole_stdin(1, NULL, &pout, &outsize);
    rsa_free(&ctx);
    SETERRNO(ret);
    return ret;
}

int rsaverify_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    char* pout = NULL;
    int outsize = 0;
    int outlen = 0;
    rsa_context ctx = {0};
    int bitsize = 2048;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);
    GET_OPT_INT(bitsize, "bitsize");
    ret = rsa_init_nums(&ctx, bitsize, pargs->m_rsan, pargs->m_rsae, NULL, 16);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not init rsa");
        goto out;
    }

    ret = read_file_whole_stdin(0, pargs->m_input, &pin, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    inlen = ret;

    outsize = inlen;
    pout = (char*) malloc((size_t)outsize);
    if (pout == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = rsa_verify((unsigned char*)pout, outsize, (unsigned char*)pin, inlen, &ctx, printf);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("verify [%s] error[%s]", pargs->m_input ? pargs->m_input : "stdin", ret);
        goto out;
    }
    outlen = ret;
    DEBUG_BUFFER_FMT(pin, inlen, "input len");
    DEBUG_BUFFER_FMT(pout, outlen, "output len");
    ret = write_file_whole_stdout(pargs->m_output, pout, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    if (pout) {
        free(pout);
    }
    pout = NULL;
    read_file_whole_stdin(1, NULL, &pout, &outsize);
    rsa_free(&ctx);
    SETERRNO(ret);
    return ret;
}

int rsasign_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    char* pout = NULL;
    int outsize = 0;
    int outlen = 0;
    rsa_context ctx = {0};
    int bitsize = 2048;
    pargs_options_t pargs = (pargs_options_t) popt;
    int idx = 0;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);

    init_log_level(pargs);
    ERROR_INFO(" ");
    GET_OPT_INT(bitsize, "bitsize");
    ret = rsa_init_nums(&ctx, bitsize, pargs->m_rsan, NULL, pargs->m_rsad, 16);
    if (ret < 0) {
        GETERRNO(ret);
        ERROR_INFO("can not init rsa");
        goto out;
    }

    ERROR_INFO(" ");
    ret = read_file_whole_stdin(0, pargs->m_input, &pin, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    inlen = ret;
    ERROR_INFO(" ");

    outsize = inlen * 2;
    pout = (char*) malloc((size_t)outsize);
    if (pout == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ERROR_INFO(" ");
    ret = rsa_sign((unsigned char*)pout, outsize, (unsigned char*)pin, inlen, &ctx, printf);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    outlen = ret;
    DEBUG_BUFFER_FMT(pin, inlen, "input len");
    DEBUG_BUFFER_FMT(pout, outlen, "output len");
    ret = write_file_whole_stdout(pargs->m_output, pout, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    if (pout) {
        free(pout);
    }
    pout = NULL;
    read_file_whole_stdin(1, NULL, &pout, &outsize);
    rsa_free(&ctx);
    SETERRNO(ret);
    return ret;
}

int get_value_hex_string(const char* str, uint8_t**ppval, int *psize)
{
    int retlen = 0;
    int ret;
    uint8_t* pretval = NULL;
    int retsize = 0;
    int codelen = 0;
    int i = 0, j;
    if (str == NULL) {
        if (ppval && *ppval) {
            free(*ppval);
            *ppval = NULL;
        }

        if (psize) {
            *psize = 0;
        }
        return 0;
    }

    if (ppval == NULL || psize == NULL) {
        ret = -ERROR_INVALID_PARAMETER;
        SETERRNO(ret);
        return ret;
    }

    pretval = *ppval;
    retsize = *psize;

    codelen = (int) strlen(str);
    retlen = ((codelen + 1) / 2 );
    i = 0;
    j = 0;

    if (retsize < retlen || pretval == NULL) {
        if (retsize < retlen) {
            retsize = retlen;
        }
        pretval = (uint8_t*)malloc((size_t)retsize);
        if (pretval == NULL) {
            GETERRNO(ret);
            goto fail;
        }
    }
    if (retlen * 2 !=  codelen) {
        pretval[j] = (uint8_t)parse_get_hex_val((uint8_t)str[i]);
        j ++;
        i ++;
    }

    while (i < codelen) {
        pretval[j] = (uint8_t)((parse_get_hex_val((uint8_t)str[i]) << 4) | (parse_get_hex_val((uint8_t)str[i + 1])));
        i += 2;
        j ++;
    }

    if (*ppval && *ppval != pretval) {
        free(*ppval);
    }
    *ppval = pretval;
    *psize = retsize;

    return retlen;
fail:
    if (pretval && pretval != *ppval) {
        free(pretval);
    }
    pretval = NULL;
    retsize = 0;
    SETERRNO(ret);
    return ret;
}

int aesenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    char* pout = NULL;
    int outsize = 0;
    int outlen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    uint8_t* aeskey = NULL, *aesiv = NULL;
    int keysize = 0, ivsize = 0;
    int keylen = 0, ivlen = 0;
    AES_ctx ctx = {0};
    int leftlen = 0;
    int i;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(parsestate);

    init_log_level(pargs);

    ret = get_value_hex_string(pargs->m_aeskey, &aeskey, &keysize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    keylen = ret;

    ret = get_value_hex_string(pargs->m_aesiv, &aesiv, &ivsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    ivlen = ret;
    if (ivlen != AES_BLOCKLEN || keylen != AES_KEYLEN) {
        ERROR_INFO("ivlen [%d] != [%d] or keylen [%d] != [%d]",
                   ivlen, AES_BLOCKLEN, keylen, AES_KEYLEN);
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    ret = read_file_whole_stdin(0, pargs->m_input, &pin, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    inlen = ret;

    outsize = inlen * 2;
    outlen = inlen;
    outlen = ((outlen + AES_BLOCKLEN - 1) / AES_BLOCKLEN) * AES_BLOCKLEN;
    if (outlen > outsize) {
        outsize = outlen;
    }
    pout = (char*) malloc((size_t)outsize);
    if (pout == NULL) {
        GETERRNO(ret);
        goto out;
    }

    memset(pout, 0, (size_t)outsize);
    memcpy(pout, pin, (size_t)inlen);

    leftlen = (outlen - inlen);
    ERROR_INFO("leftlen [%d] outlen [%d] inlen[%d]", leftlen, outlen, inlen);
    if (leftlen > 0) {
        for (i = inlen; i < outlen; i++) {
            pout[i] = (char) leftlen;
        }
    }

    AES_init_ctx_iv(&ctx, aeskey, aesiv);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t*)pout, (size_t)outlen);

    ret = write_file_whole_stdout(pargs->m_output, pout, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    if (pout) {
        free(pout);
    }
    pout = NULL;
    read_file_whole_stdin(1, NULL, &pout, &outsize);
    get_value_hex_string(NULL, &aeskey, &keysize);
    get_value_hex_string(NULL, &aesiv, &ivsize);
    SETERRNO(ret);
    return ret;
}

int aesdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int ret = 0;
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    char* pout = NULL;
    int outsize = 0;
    int outlen = 0;
    pargs_options_t pargs = (pargs_options_t) popt;
    uint8_t* aeskey = NULL, *aesiv = NULL;
    int keysize = 0, ivsize = 0;
    int keylen = 0, ivlen = 0;
    AES_ctx ctx = {0};
    int leftlen = 0;
    int valid = 0;
    int i;

    REFERENCE_ARG(argv);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(parsestate);

    init_log_level(pargs);

    ret = get_value_hex_string(pargs->m_aeskey, &aeskey, &keysize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    keylen = ret;

    ret = get_value_hex_string(pargs->m_aesiv, &aesiv, &ivsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    ivlen = ret;

    if (ivlen != AES_BLOCKLEN || keylen != AES_KEYLEN) {
        ERROR_INFO("ivlen [%d] != [%d] or keylen [%d] != [%d]",
                   ivlen, AES_BLOCKLEN, keylen, AES_KEYLEN);
        ret = -ERROR_INVALID_PARAMETER;
        goto out;
    }

    ret = read_file_whole_stdin(0, pargs->m_input, &pin, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    inlen = ret;

    if (inlen % AES_BLOCKLEN) {
        ret = -ERROR_INVALID_PARAMETER;
        ERROR_INFO("inlen [%d] not align [%d]", inlen, AES_BLOCKLEN);
        goto out;
    }

    outsize = inlen;
    pout = (char*) malloc((size_t)outsize);
    if (pout == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memcpy(pout, pin, (size_t)inlen);
    outlen = inlen;

    AES_init_ctx_iv(&ctx, aeskey, aesiv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t*)pout, (size_t)outlen);
    leftlen = pout[outlen - 1];
    if (leftlen < AES_BLOCKLEN) {
        valid = 1;
        for (i = 0; i < leftlen; i++) {
            if (pout[outlen - i - 1] != leftlen) {
                valid = 0;
                break;
            }
        }
        if (valid) {
            outlen -= leftlen;
        }
    }
    ERROR_INFO("leftlen [%d] inlen [%d] outlen[%d]", leftlen, inlen, outlen);


    ret = write_file_whole_stdout(pargs->m_output, pout, outlen);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    if (pout) {
        free(pout);
    }
    pout = NULL;
    read_file_whole_stdin(1, NULL, &pout, &outsize);
    get_value_hex_string(NULL, &aeskey, &keysize);
    get_value_hex_string(NULL, &aesiv, &ivsize);
    SETERRNO(ret);
    return ret;
}

int debug_sha256_hash(char* fname)
{
    char* pin = NULL;
    int insize = 0;
    int inlen = 0;
    uint8_t hash[32];
    int ret;
    SHA256_CTX ctx;
    int i;

    ret = read_file_whole_stdin(0, fname, &pin, &insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }
    inlen = ret;
    DEBUG_BUFFER_FMT(pin,inlen,"%s ",fname ? fname : "<STDIN>");
    fflush(stderr);
    sha256_init(&ctx);
    sha256_update(&ctx, (const unsigned char*)pin, (size_t)inlen);
    sha256_final(&ctx, hash);

    fprintf(stdout,"%s ", fname ? fname : "<STDIN>");
    for (i=0;i<32;i++) {
        fprintf(stdout,"%02x",hash[i]);
    }
    fprintf(stdout,"\n");

    read_file_whole_stdin(1,NULL,&pin,&insize);
    return 0;
fail:
    read_file_whole_stdin(1,NULL,&pin,&insize);
    SETERRNO(ret);
    return ret;
}

int sha256sum_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    int argcnt = 0;
    int i;
    int ret;
    pargs_options_t pargs = (pargs_options_t)popt;

    init_log_level(pargs);
    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);
    for (argcnt = 0; parsestate->leftargs && parsestate->leftargs[argcnt]; argcnt++) {
    }

    if (argcnt == 0) {
        ret = debug_sha256_hash(NULL);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    } else {
        for (i = 0; i < argcnt; i++) {
            ret = debug_sha256_hash(parsestate->leftargs[i]);
            if (ret < 0) {
                GETERRNO(ret);
                goto out;
            }
        }
    }

    ret = 0;
out:
    SETERRNO(ret);
    return ret;
}