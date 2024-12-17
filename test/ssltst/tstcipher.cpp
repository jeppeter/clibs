
int cipherenc_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char* ciphername = NULL, *keyfile=NULL, *initfile=NULL, *outfile=NULL, *origfile=NULL;
    char *initdata=NULL, *keydata=NULL,*origdata=NULL, *outdata=NULL;
    int initlen=0,keylen=0,origlen=0,outlen=0;
    int initsize=0,keysize=0,origsize=0,outsize=0;
    int i=0;
    pargs_options_t pargs = (pargs_options_t) popt;
    const EVP_CIPHER* evp=NULL;
    EVP_CIPHER_CTX *ctx=NULL;
    int curlen = 0;
    int ret;

    init_log_verbose(pargs);

    for(i=0;parsestate->leftargs && parsestate->leftargs[i];i++) {
        switch(i) {
            case 0:
                ciphername = parsestate->leftargs[i];
                break;
            case 1:
                keyfile = parsestate->leftargs[i];
                break;
            case 2:
                initfile = parsestate->leftargs[i];
                break;
            case 3:
                origfile = parsestate->leftargs[i];
                break;
            case 4:
                outfile = parsestate->leftargs[i];
                break;
            default:
                break;
        }
    }

    if (i <= 4) {
        ret = -EINVAL;
        goto out;
    }

    evp = EVP_CIPHER_fetch(NULL,ciphername,NULL);
    if (evp == NULL) {
        ret = -EINVAL;
        fprintf(stderr,"[%s] cipher not found\n",ciphername);
        goto out;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = read_file_whole(initfile,&initdata,&initsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read init data file [%s] error[%d]\n", initfile,ret);
        goto out;
    }
    initlen = ret;
    initlen = initlen;

    ret = read_file_whole(keyfile,&keydata,&keysize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read key data file [%s] error[%d]\n", keyfile,ret);
        goto out;
    }
    keylen = ret;
    keylen = keylen;

    ret = read_file_whole(origfile,&origdata,&origsize);
    if (ret < 0) {
        GETERRNO(ret);
        fprintf(stderr, "read orig data file [%s] error[%d]\n", origfile,ret);
        goto out;
    }
    origlen = ret;

    outsize = origlen + (1<<20);
    outdata = (char*)malloc(outsize);
    if (outdata == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = EVP_EncryptInit_ex(ctx,evp,NULL,(const unsigned char*)keydata,(const unsigned char*)initdata);
    if (ret == 0) {
        GETERRNO(ret);
        fprintf(stderr, "init [%s] error [%d]\n", ciphername, ret);
        goto out;
    }

    curlen = 0;
    ret = EVP_EncryptUpdate(ctx,(unsigned char*)outdata,&curlen,(const unsigned char*)origdata,origlen);
    if (ret == 0) {
        GETERRNO(ret);
        fprintf(stderr, "enc [%s] error[%d]\n", ciphername,ret);
        goto out;
    }
    outlen = curlen;
    curlen = 0;
    ret = EVP_EncryptFinal(ctx,(unsigned char*)(outdata + outlen), &curlen);
    if (ret != 0) {
        GETERRNO(ret);
        fprintf(stderr, "final [%s] error [%d]\n", ciphername,ret);
        goto out;
    }

    if (outfile != NULL) {
        ret = write_file_whole(outfile,outdata,outlen);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    } else {
        dump_buffer_out(stdout,(uint8_t*)origdata,origlen,"orig data");
        dump_buffer_out(stdout,(uint8_t*)outdata,outlen,"encrypt data");
    }

    ret = 0;

out:
    if (outdata) {
        free(outdata);
    }
    outdata = NULL;
    outsize = 0;
    outlen = 0;
    read_file_whole(NULL,&origdata,&origsize);
    origlen = 0;
    read_file_whole(NULL,&initdata,&initsize);
    initlen=0;
    read_file_whole(NULL,&keydata,&keysize);
    keylen = 0;
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    ctx = NULL;
    if(evp) {
        EVP_CIPHER_free((EVP_CIPHER*)evp);
    }
    evp = NULL;

    SETERRNO(ret);
    return ret;
}