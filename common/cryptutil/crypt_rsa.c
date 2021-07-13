/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#include <crypt_rsa.h>
#include <stdint.h>
#include <stdlib.h>

#if 0
#define RSA_DEBUG(...)
#define RSA_ERROR(...)   do { if(printfunc != NULL) { printfunc(__VA_ARGS__); printfunc("\n");}} while(0)
#else
#define RSA_DEBUG(...)   do { if(printfunc != NULL) { printfunc("[%s:%d] ",__FILE__,__LINE__); printfunc(__VA_ARGS__); printfunc("\n");}} while(0)
#define RSA_ERROR(...)   do { if(printfunc != NULL) { printfunc("[%s:%d] ",__FILE__,__LINE__); printfunc(__VA_ARGS__); printfunc("\n");}} while(0)
#endif

/*
 * Initialize an RSA context
 */
void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id )
{
    hash_id = hash_id;
    memset( ctx, 0, sizeof( rsa_context ) );
    ctx->padding = padding;
    mpz_init(ctx->N);
    mpz_init(ctx->E);
    mpz_init(ctx->D);
    return ;
}

int rsa_init_nums(rsa_context* ctx,int bitsize,char* nstr,char* estr,
                  char* dstr,int radix)
{
    ctx->len = bitsize;
    ctx->ver = 0;

    if (nstr)
    {
        mpz_set_str(ctx->N,nstr,radix);
    }
    if (estr)
    {
        mpz_set_str(ctx->E,estr,radix);
    }

    if (dstr)
    {
        mpz_set_str(ctx->D,dstr,radix);
    }
    return 0;
}

int rsa_init_func(rsa_context * ctx,randfunc_t randfunc,void* arg)
{
    ctx->m_rand = randfunc;
    ctx->m_randarg = arg;
    return 0;
}


/*
 * Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx )
{
    mpz_clear(ctx->N);
    mpz_clear(ctx->E);
    mpz_clear(ctx->D);
    return ;
}


int get_hex_val(unsigned char ch)
{
    int val=0;
    if (ch >= '0' && ch<='9')
    {
        val = ch - '0';
    }
    else if (ch >= 'a' && ch<='f')
    {
        val = ch - 'a' + 10;
    }
    else if (ch >= 'A' && ch<='F')
    {
        val = ch - 'A' + 10;
    }
    return val;
}

int hex_str_buffer(const char* hexstr,uint8_t *pbuf,uint32_t buflen,printf_func_t printfunc)
{
    uint32_t i,j;
    uint32_t len=(uint32_t) strlen(hexstr);

    if (len > (buflen*2))
    {
        RSA_ERROR("len [%d][%s] buflen[%d]", len, hexstr,buflen);
        return -1;
    }

    i = 0;
    if (len < (buflen *2 ))
    {
        while(i<((buflen*2-len)/2))
        {
            pbuf[i] = 0;
            i ++;
        }
    }

    j = 0;
    if (len % 2)
    {
        pbuf[i] = (uint8_t)get_hex_val(hexstr[j]);
        j ++;
        i ++;
    }

    while ( i < buflen)
    {
        pbuf[i] = (uint8_t)((get_hex_val(hexstr[j])<<4)|(get_hex_val(hexstr[j+1])));
        j += 2;
        i ++;
    }

    return buflen;
}


void block_encrypt(mpz_t C, mpz_t M, rsa_context* rsa)
{
    /* C = M^e mod n */
    mpz_powm(C, M, rsa->E, rsa->N);
    return;
}


int __rsa_encrypt(char* cipher,int cipherlen, char* message, int length, rsa_context* rsa,int blocksize,printf_func_t printfunc)
{
    char *expbuf=NULL;
    char *filledbuf=NULL;
    int leftlen=length;
    int leftcipherlen=cipherlen;
    int filledlen=0;
    int curlen;
    char* pptr;
    uint8_t *ppcipherptr;
    int i;
    mpz_t m;
    mpz_t c;
    int ret;

    expbuf = malloc(blocksize*4);
    if (expbuf == NULL)
    {
        goto fail;
    }
    if (rsa->padding == 0) {
        rsa->padding = 3;
    }

    filledbuf = malloc(blocksize* 2);
    if (filledbuf == NULL)
    {
        goto fail;
    }

    leftlen = length;
    pptr = message;
    ppcipherptr =(uint8_t*) cipher;
    filledlen = 0;

    while(leftlen > 0)
    {
        curlen  = (blocksize - rsa->padding);
        if (leftlen < curlen)
        {
            curlen = leftlen;
        }

        filledbuf[0] = 0x0;
        filledbuf[1] = 0x2;

        for (i=2; i<(blocksize - curlen-1); i++)
        {
            if (rsa->m_rand)
            {
fill_again:
                filledbuf[i] =(uint8_t) rsa->m_rand(rsa->m_randarg);
                if (filledbuf[i] == 0)
                {
                    goto fill_again;
                }
            }
            else
            {
                filledbuf[i] = 0x11;
            }
        }

        filledbuf[i] = 0x0;
        i ++;

        memcpy(&(filledbuf[i]),pptr,curlen);

        /*now to filled m c */
        mpz_init(m);
        mpz_init(c);

        mpz_import(m,blocksize,1,sizeof(char),0,0,filledbuf);
        block_encrypt(c,m,rsa);

        if (leftcipherlen < blocksize)
        {
            RSA_ERROR(" ");
            goto fail;
        }

        ret = hex_str_buffer(mpz_get_str(expbuf,16,c),ppcipherptr,blocksize,printfunc);
        if (ret < 0)
        {
            RSA_ERROR(" ");
            goto fail;
        }

        mpz_clear(m);
        mpz_clear(c);
        leftcipherlen -= blocksize;
        ppcipherptr += blocksize;
        pptr += curlen;
        leftlen -= curlen;
        filledlen += blocksize;
    }

    if (filledbuf)
    {
        free(filledbuf);
    }
    filledbuf = NULL;
    if (expbuf)
    {
        free(expbuf);
    }
    expbuf = NULL;
    return filledlen;

fail:
    if (filledbuf)
    {
        free(filledbuf);
    }
    filledbuf = NULL;
    if (expbuf)
    {
        free(expbuf);
    }
    expbuf = NULL;
    return -1;
}


int rsa_encrypt(unsigned char* cipher,int cipherlen,unsigned char* message, int messlen, rsa_context* prsa,printf_func_t printfunc)
{
    return __rsa_encrypt((char*)cipher,cipherlen,(char*)message,messlen,prsa,(prsa->len >> 3), printfunc);
}

void block_decrypt(mpz_t M, mpz_t C, rsa_context* prsa,printf_func_t printfunc)
{
    if (printfunc) {
        printfunc = printfunc;
    }
    mpz_powm(M, C, prsa->D, prsa->N);
    return;
}


int __rsa_decrypt(char* message,int messlen, char* cipher, int length,rsa_context* prsa,int blocksize,printf_func_t printfunc)
{
    char *expbuf=NULL;
    uint8_t *filledbuf=NULL;
    int curlen;
    char* pcurmess=NULL;
    int leftmesslen=0;
    int filledlen = 0;
    int i,j;
    mpz_t m;
    mpz_t c;
    int ret;
    if (length & (blocksize - 1))
    {
        RSA_ERROR("length %d blocksize (%d)", length, blocksize);
        goto fail;
    }

    RSA_DEBUG(" ");
    expbuf = malloc(blocksize*4);
    if (expbuf == NULL)
    {
        goto fail;
    }

    RSA_DEBUG(" ");
    filledbuf = malloc(blocksize* 2);
    if (filledbuf == NULL)
    {
        goto fail;
    }

    RSA_DEBUG(" ");
    pcurmess = message;
    leftmesslen = messlen;
    filledlen = 0;

    for (i=0; i<(length /blocksize); i++)
    {
        RSA_DEBUG(" ");
        mpz_init(m);
        RSA_DEBUG(" ");
        mpz_init(c);
        RSA_DEBUG(" ");
        mpz_import(c,blocksize,1,sizeof(char),0,0,cipher+i*blocksize);
        RSA_DEBUG(" ");

        block_decrypt(m,c,prsa, printfunc);
        RSA_DEBUG(" ");
        ret = hex_str_buffer(mpz_get_str(expbuf,16,m),(uint8_t*)filledbuf,blocksize,printfunc);
        if (ret < 0)
        {
            goto fail;
        }
        RSA_DEBUG(" ");
        mpz_clear(m);
        RSA_DEBUG(" ");
        mpz_clear(c);
        RSA_DEBUG(" ");

        for (j=2; j<blocksize; j++)
        {
            if (filledbuf[j] == 0x0)
            {
                break;
            }
        }
        RSA_DEBUG(" ");

        if (j >= (blocksize-1))
        {
            /*this is invalid ,so failed to decrypt*/
            goto fail;
        }
        RSA_DEBUG(" ");
        j ++;
        /*current len to copy*/
        curlen = blocksize - j;
        if (leftmesslen < curlen)
        {
            goto fail;
        }
        RSA_DEBUG(" ");

        memcpy(pcurmess,&(filledbuf[j]),curlen);
        pcurmess += curlen;
        leftmesslen -= curlen;
        filledlen += curlen;
    }

    if (filledbuf)
    {
        free(filledbuf);
    }
    filledbuf = NULL;
    RSA_DEBUG(" ");
    if (expbuf)
    {
        free(expbuf);
    }
    expbuf = NULL;
    RSA_DEBUG(" ");
    return filledlen;

fail:
    if (filledbuf)
    {
        free(filledbuf);
    }
    filledbuf = NULL;
    if (expbuf)
    {
        free(expbuf);
    }
    expbuf = NULL;
    return -1;
}


int rsa_decrypt(unsigned char* message,int messlen,unsigned char* cipher, int cipherlen, rsa_context* prsa,printf_func_t printfunc)
{
    RSA_DEBUG(" ");
    return __rsa_decrypt((char*)message,messlen,(char*)cipher,cipherlen,prsa,(prsa->len >> 3), printfunc);
}

int __rsa_sign(unsigned char* signedmess ,int signedlen,unsigned char *mess,int messlen,rsa_context* prsa,int blocksize,printf_func_t printfunc)
{
    int ret;
    int leftmesslen=messlen,leftsignedmess=signedlen;
    unsigned char* pcursignedmess=NULL;
    char* pcurmess=NULL;
    int curlen;
    int filledlen=0;
    char* expbuf=NULL;
    char* filledbuf=NULL;
    mpz_t m;
    mpz_t c;
    int i;

    if (prsa->padding == 0) {
        prsa->padding = 3;
    }

    expbuf = malloc(blocksize* 4);
    if (expbuf == NULL)
    {
        RSA_ERROR(" ");
        goto fail;
    }

    filledbuf = malloc(blocksize*4);
    if (filledbuf == NULL)
    {
        RSA_ERROR(" ");
        goto fail;
    }


    pcursignedmess = signedmess;
    pcurmess = (char*)mess;
    leftmesslen = messlen;
    filledlen = 0;
    leftsignedmess = signedlen;
    while(leftmesslen > 0)
    {
        curlen = (blocksize - prsa->padding);
        if (curlen > leftmesslen)
        {
            curlen = leftmesslen;
        }

        filledbuf[0] = 0x0;
        filledbuf[1] = 0x1;
        for (i=2; i<(blocksize - curlen - 1); i++)
        {
            if (prsa->m_rand)
            {
fill_again:
                filledbuf[i] = (uint8_t) prsa->m_rand(prsa->m_randarg);
                if (filledbuf[i] == 0)
                {
                    goto fill_again;
                }
            }
            else
            {
                filledbuf[i] = 0x12;
            }
        }

        filledbuf[i] = 0x0;
        i ++;
        memcpy(&(filledbuf[i]),pcurmess,curlen);

        mpz_init(m);
        mpz_init(c);

        /*now filled buffer*/
        mpz_import(m,blocksize,1,sizeof(char),0,0,filledbuf);
        block_decrypt(c,m,prsa, printfunc);
        if (leftsignedmess < blocksize)
        {
            RSA_ERROR(" ");
            goto fail;
        }

        ret = hex_str_buffer(mpz_get_str(expbuf,16,c),pcursignedmess,blocksize,printfunc);
        if (ret < 0)
        {
            RSA_ERROR(" ");
            goto fail;
        }


        mpz_clear(m);
        mpz_clear(c);

        pcurmess += curlen;
        pcursignedmess += blocksize;
        leftmesslen -= curlen;
        leftsignedmess -= blocksize;
        filledlen += blocksize;
    }

    if (filledbuf)
    {
        free(filledbuf);
    }
    filledbuf = NULL;
    if (expbuf)
    {
        free(expbuf);
    }
    expbuf = NULL;
    return filledlen;
fail:
    if (filledbuf)
    {
        free(filledbuf);
    }
    filledbuf = NULL;
    if (expbuf)
    {
        free(expbuf);
    }
    expbuf = NULL;
    return -1;
}

int rsa_sign(unsigned char* signedmess ,int signedlen,unsigned char *mess,int messlen,rsa_context* prsa,printf_func_t printfunc)
{
    return __rsa_sign(signedmess,signedlen,mess,messlen,prsa,(prsa->len >> 3),printfunc);
}


int __rsa_verify(unsigned char * verimess,int verilen,unsigned char * mess,int messlen,rsa_context * prsa,int blocksize
        ,printf_func_t printfunc)
{
    int ret;
    int leftmesslen=messlen,leftverimesslen=verilen;
    unsigned char* pcurverimess=NULL;
    char* pcurmess=NULL;
    int curlen;
    int filledlen=0;
    char* expbuf=NULL;
    char* filledbuf=NULL;
    mpz_t m;
    mpz_t c;
    int j;
    RSA_DEBUG(" ");

    expbuf = malloc(blocksize* 4);
    if (expbuf == NULL)
    {
        goto fail;
    }

    filledbuf = malloc(blocksize*4);
    if (filledbuf == NULL)
    {
        goto fail;
    }

    if (messlen % (blocksize))
    {
        goto fail;
    }


    pcurverimess = verimess;
    pcurmess = (char*)mess;
    leftmesslen = messlen;
    filledlen = 0;
    leftverimesslen = verilen;

    while(leftmesslen > 0)
    {
        mpz_init(m);
        mpz_init(c);
        mpz_import(c,blocksize,1,sizeof(char),0,0,pcurmess);

        block_encrypt(m,c,prsa);
        ret = hex_str_buffer(mpz_get_str(expbuf,16,m),(uint8_t*)filledbuf,blocksize,printfunc);
        if (ret < 0)
        {
            goto fail;
        }
        mpz_clear(m);
        mpz_clear(c);

        for (j=2; j<blocksize; j++)
        {
            if (filledbuf[j] == 0x0)
            {
                break;
            }
        }

        if (j >= (blocksize-1))
        {
            /*this is invalid ,so failed to decrypt*/
            goto fail;
        }
        j ++;
        /*current len to copy*/
        curlen = blocksize - j;
        if (leftverimesslen < curlen)
        {
            goto fail;
        }

        memcpy(pcurverimess,&(filledbuf[j]),curlen);
        pcurmess += blocksize;
        leftmesslen -= blocksize;
        filledlen += curlen;
        pcurverimess += curlen;
        leftverimesslen -= curlen;
    }

    if (filledbuf)
    {
        free(filledbuf);
    }
    filledbuf = NULL;
    if (expbuf)
    {
        free(expbuf);
    }
    expbuf = NULL;
    return filledlen;
fail:
    if (filledbuf)
    {
        free(filledbuf);
    }
    filledbuf = NULL;
    if (expbuf)
    {
        free(expbuf);
    }
    expbuf = NULL;
    return -1;
}

int rsa_verify(unsigned char * verimess,int verilen,unsigned char * mess,int messlen,rsa_context * prsa,printf_func_t printfunc)
{
    return __rsa_verify(verimess,verilen,mess,messlen,prsa,(prsa->len >> 3),printfunc);
}


