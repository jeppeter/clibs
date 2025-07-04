
OSSL_LIB_CTX* app_get0_libctx()
{
    return NULL;
}


/**********************************************
* if can not load des or bf evp
* just specified --provider legacy --providerpath openssl_path/providers to load
* 
**********************************************/
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
    OSSL_PROVIDER *prov=NULL;

    init_log_verbose(pargs);
    DEBUG_INFO(" ");

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

    if (i < 4) {
        ret = -EINVAL;
        fprintf(stderr,"[i %d] <= 4", i);
        goto out;
    }

    if (pargs->m_providerpath != NULL) {
        ret = OSSL_PROVIDER_set_default_search_path(app_get0_libctx(),pargs->m_providerpath);
        if (ret <= 0) {
            GETERRNO(ret);
            fprintf(stderr, "set m_providerpath [%s] error[%d]\n", pargs->m_providerpath, ret);
            goto out;
        }
    }

    for(i=0;pargs->m_provider && pargs->m_provider[i];i++) {
        prov =  OSSL_PROVIDER_load(app_get0_libctx(),pargs->m_provider[i]);
        if (prov == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "load [%s] error [%d]\n", pargs->m_provider[i], ret);
            goto out;
        }
        
    }

    evp = EVP_CIPHER_fetch(app_get0_libctx(),ciphername,NULL);
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
    curlen = (outsize - outlen);
    ret = EVP_EncryptFinal_ex(ctx,(unsigned char*)(outdata + outlen), &curlen);
    if (ret <= 0) {
        GETERRNO(ret);
        fprintf(stderr, "final [%s] error [%d]\n", ciphername,ret);
        goto out;
    }
    outlen += curlen;

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


int cipherdec_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
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
    int ret,iret;
    OSSL_PROVIDER *prov=NULL;

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

    if (i < 4) {
        ret = -EINVAL;
        fprintf(stderr,"[i %d] <= 4", i);
        goto out;
    }

    if (pargs->m_providerpath != NULL) {
        ret = OSSL_PROVIDER_set_default_search_path(app_get0_libctx(),pargs->m_providerpath);
        if (ret <= 0) {
            GETERRNO(ret);
            fprintf(stderr, "set m_providerpath [%s] error[%d]\n", pargs->m_providerpath, ret);
            goto out;
        }
    }

    for(i=0;pargs->m_provider && pargs->m_provider[i];i++) {
        prov =  OSSL_PROVIDER_load(app_get0_libctx(),pargs->m_provider[i]);
        if (prov == NULL) {
            GETERRNO(ret);
            fprintf(stderr, "load [%s] error [%d]\n", pargs->m_provider[i], ret);
            goto out;
        }
        
    }

    evp = EVP_CIPHER_fetch(app_get0_libctx(),ciphername,NULL);
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

    if (origsize > origlen) {
        memset(origdata+origlen,0, (origsize - origlen));
    } else {
        char* ptmp = NULL;
        origsize = origlen + 16;
        ptmp = (char*)malloc(origsize);
        if (ptmp == NULL) {
            GETERRNO(ret);
            goto out;
        }
        memset(ptmp,0,origsize);
        if (origlen > 0) {
            memcpy(ptmp,origdata,origlen);
        }
        if(origdata) {
            free(origdata);
        }
        origdata = ptmp;
        ptmp = NULL;

    }

    outsize = origlen + (1<<20);
    outdata = (char*)malloc(outsize);
    if (outdata == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(outdata,0,outsize);

    iret = EVP_DecryptInit_ex(ctx,evp,NULL,(const unsigned char*)keydata,(const unsigned char*)initdata);
    if (iret <= 0) {
        GETERRNO(ret);
        fprintf(stderr, "init [%s] error [%d] %d\n", ciphername, ret, iret);
        goto out;
    }

    curlen = 0;
    ret = EVP_DecryptUpdate(ctx,(unsigned char*)outdata,&curlen,(const unsigned char*)origdata,origlen);
    if (ret == 0) {
        GETERRNO(ret);
        fprintf(stderr, "enc [%s] error[%d]\n", ciphername,ret);
        goto out;
    }
    outlen = curlen;
    curlen = (outsize - outlen);
    iret = EVP_DecryptFinal_ex(ctx,(unsigned char*)(outdata + outlen), &curlen);
    if (iret <= 0) {
        GETERRNO(ret);
        fprintf(stderr, "final [%s] error [%d] %d\n", ciphername,ret,iret);
        goto out;
    }
    outlen += curlen;

    if (outfile != NULL) {
        ret = write_file_whole(outfile,outdata,outlen);
        if (ret < 0) {
            GETERRNO(ret);
            goto out;
        }
    } else {
        dump_buffer_out(stdout,(uint8_t*)origdata,origlen,"enc data");
        dump_buffer_out(stdout,(uint8_t*)outdata,outlen,"decrypt data");
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

int rsasign_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char *privkeyfile=NULL,*inputfile=NULL, *signfile=NULL;
    char *keydata=NULL, *indata=NULL,*signdata=NULL;
    char *pkeydata=NULL;
    int keydatalen=0;
    int keysize=0,insize=0,signsize=0;
    int keylen=0,inlen=0,signlen=0;
    int ret;
    BIO* keybio=NULL;
    EVP_PKEY* pkey=NULL;
    EVP_MD_CTX* ctx=NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    if (parsestate->leftargs && parsestate->leftargs[0]) {
        privkeyfile = parsestate->leftargs[0];
        if (parsestate->leftargs && parsestate->leftargs[1]) {
            inputfile = parsestate->leftargs[1];
            if (parsestate->leftargs && parsestate->leftargs[2]) {
                signfile = parsestate->leftargs[2];
            }
        }
    }

    if (privkeyfile == NULL || inputfile == NULL || signfile == NULL) {
        fprintf(stderr,"need privkey inputfile signfile\n");
        ret = -EINVAL;
        goto out;
    }

    ret = read_file_whole(privkeyfile,&keydata,&keysize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    keylen = ret;

    ret = read_file_whole(inputfile,&indata,&insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    inlen = ret;

    keybio = BIO_new_mem_buf(keydata,keylen);
    if (keybio == NULL) {
        GETERRNO(ret);
        ERROR_INFO("mem buf error [%d]", ret);
        goto out;
    }

    pkey = d2i_PrivateKey_bio(keybio,NULL);
    if (pkey == NULL) {
        GETERRNO(ret);
        ERROR_INFO("from [%s] key error %d", privkeyfile,ret);
        goto out;
    }

    ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (ret <= 0) {
        GETERRNO(ret);
        ERROR_INFO("Digest init error %d", ret);
        goto out;
    }

    ret = EVP_DigestSignUpdate(ctx,indata,inlen);
    if (ret <= 0) {
        GETERRNO(ret);
        ERROR_INFO("update digest error %d", ret);
        goto out;
    }

    signsize = 0;
    ret = EVP_DigestSignFinal(ctx,NULL,(size_t*)&signsize);
    if (ret <= 0) {
        GETERRNO(ret);
        ERROR_INFO("final error %d", ret);
        goto out;
    }

    signdata = (char*) malloc(signsize);
    if (signdata == NULL) {
        GETERRNO(ret);
        goto out;
    }
    memset(signdata,0,signsize);

    signlen = signsize;
    ret = EVP_DigestSignFinal(ctx,(unsigned char*)signdata,(size_t*)&signlen);
    if (ret <= 0) {
        GETERRNO(ret);
        ERROR_INFO("final error %d", ret);
        goto out;
    }

    ret = write_file_whole(signfile,signdata,signsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }

    ret = 0;
out:
    if (signdata) {
        free(signdata);
    }
    signdata = NULL;
    signsize = 0;
    signlen = 0;

    if (ctx) {
        EVP_MD_CTX_destroy(ctx);
    }
    ctx = NULL;

    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    pkey = NULL;

    if (keybio) {
        BIO_free(keybio);
    }
    keybio = NULL;
    read_file_whole(NULL,&keydata,&keysize);
    read_file_whole(NULL,&indata,&insize);
    SETERRNO(ret);
    return ret;
}

int rsavfy_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
    char *certfile=NULL,*inputfile=NULL, *signfile=NULL;
    char *certdata=NULL, *indata=NULL,*signdata=NULL;
    int certsize=0,insize=0,signsize=0;
    int certlen=0,inlen=0,signlen=0;
    int ret;
    BIO* certbio=NULL;
    X509* cert=NULL;
    EVP_PKEY* pubkey=NULL;
    EVP_MD_CTX* ctx=NULL;
    X509_PUBKEY* x509pubkey = NULL;
    pargs_options_t pargs = (pargs_options_t) popt;

    init_log_verbose(pargs);
    if (parsestate->leftargs && parsestate->leftargs[0]) {
        certfile = parsestate->leftargs[0];
        if (parsestate->leftargs && parsestate->leftargs[1]) {
            inputfile = parsestate->leftargs[1];
            if (parsestate->leftargs && parsestate->leftargs[2]) {
                signfile = parsestate->leftargs[2];
            }
        }
    }

    if (certfile == NULL || inputfile == NULL || signfile == NULL) {
        fprintf(stderr,"need certfile inputfile signfile\n");
        ret = -EINVAL;
        goto out;
    }

    ret = read_file_whole(certfile,&certdata,&certsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    certlen = ret;

    ret = read_file_whole(inputfile,&indata,&insize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    inlen = ret;

    ret = read_file_whole(signfile,&signdata,&signsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto out;
    }
    signlen = ret;

    certbio = BIO_new_mem_buf(certdata,certlen);
    if (certbio == NULL) {
        GETERRNO(ret);
        ERROR_INFO("mem buf error [%d]", ret);
        goto out;
    }

    cert = d2i_X509_bio(certbio,NULL);
    if (cert == NULL) {
        GETERRNO(ret);
        ERROR_INFO("from [%s] key error %d", certfile,ret);
        goto out;
    }

    x509pubkey =  X509_get_X509_PUBKEY(cert);
    if (x509pubkey == NULL) {
        GETERRNO(ret);
        ERROR_INFO("can not get x509pubkey %d",ret);
        goto out;
    }

    pubkey = X509_PUBKEY_get(x509pubkey);
    if (pubkey == NULL) {
        GETERRNO(ret);
        ERROR_INFO("get pubkey error %d", ret);
        goto out;
    }


    ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        GETERRNO(ret);
        goto out;
    }

    ret = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey);
    if (ret <= 0) {
        GETERRNO(ret);
        ERROR_INFO("Digest init error %d", ret);
        goto out;
    }

    ret = EVP_DigestVerifyUpdate(ctx,indata,inlen);
    if (ret <= 0) {
        GETERRNO(ret);
        ERROR_INFO("update digest error %d", ret);
        goto out;
    }

    ret = EVP_DigestVerifyFinal(ctx,(unsigned char*)signdata,signlen);
    if (ret <= 0) {
        GETERRNO(ret);
        ERROR_INFO("final error %d", ret);
        goto out;
    }


    fprintf(stdout,"verify [%s] with certfile [%s] with sign [%s] ok\n",inputfile,certfile,signfile);
    ret = 0;
out:

    if (ctx) {
        EVP_MD_CTX_destroy(ctx);
    }
    ctx = NULL;

    if (cert) {
        X509_free(cert);
    }
    cert = NULL;


    if (certbio) {
        BIO_free(certbio);
    }
    certbio = NULL;
    read_file_whole(NULL,&signdata,&signsize);
    read_file_whole(NULL,&certdata,&certsize);
    read_file_whole(NULL,&indata,&insize);
    SETERRNO(ret);
    return ret;

}