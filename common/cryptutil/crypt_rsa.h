#ifndef __CRYPT_RSA_H__
#define __CRYPT_RSA_H__

#include <cmn_err.h>
#include <crypt_mpn.h>

/*
 * RSA Error codes
 */
#define ERR_RSA_BAD_INPUT_DATA                    -0x0400
#define ERR_RSA_INVALID_PADDING                   -0x0410
#define ERR_RSA_KEY_GEN_FAILED                    -0x0420
#define ERR_RSA_KEY_CHECK_FAILED                  -0x0430
#define ERR_RSA_PUBLIC_FAILED                     -0x0440
#define ERR_RSA_PRIVATE_FAILED                    -0x0450
#define ERR_RSA_VERIFY_FAILED                     -0x0460
#define ERR_RSA_OUTPUT_TOO_LARGE                  -0x0470
#define ERR_RSA_RNG_FAILED                        -0x0480

/*
 * PKCS#1 constants
 */
#define SIG_RSA_RAW     0
#define SIG_RSA_MD2     2
#define SIG_RSA_MD4     3
#define SIG_RSA_MD5     4
#define SIG_RSA_SHA1	5
#define SIG_RSA_SHA224	14
#define SIG_RSA_SHA256	11
#define	SIG_RSA_SHA384	12
#define SIG_RSA_SHA512	13

#define RSA_PUBLIC      0
#define RSA_PRIVATE     1

#define RSA_PKCS_V15    0
#define RSA_PKCS_V21    1

#define RSA_SIGN        1
#define RSA_CRYPT       2

#define ASN1_STR_CONSTRUCTED_SEQUENCE	"\x30"
#define ASN1_STR_NULL			        "\x05"
#define ASN1_STR_OID			        "\x06"
#define ASN1_STR_OCTET_STRING		    "\x04"

#define OID_DIGEST_ALG_MDX	        "\x2A\x86\x48\x86\xF7\x0D\x02\x00"
#define OID_HASH_ALG_SHA1	        "\x2b\x0e\x03\x02\x1a"
#define OID_HASH_ALG_SHA2X	        "\x60\x86\x48\x01\x65\x03\x04\x02\x00"

#define OID_ISO_MEMBER_BODIES	    "\x2a"
#define OID_ISO_IDENTIFIED_ORG	    "\x2b"

/*
 * ISO Member bodies OID parts
 */
#define OID_COUNTRY_US		        "\x86\x48"
#define OID_RSA_DATA_SECURITY	    "\x86\xf7\x0d"

/*
 * ISO Identified organization OID parts
 */
#define OID_OIW_SECSIG_SHA1	        "\x0e\x03\x02\x1a"

/*
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   digest Digest }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * Digest ::= OCTET STRING
 */
#define ASN1_HASH_MDX					        \
(							                    \
    ASN1_STR_CONSTRUCTED_SEQUENCE "\x20"		\
      ASN1_STR_CONSTRUCTED_SEQUENCE "\x0C"		\
        ASN1_STR_OID "\x08"				        \
	  OID_DIGEST_ALG_MDX				        \
	ASN1_STR_NULL "\x00"				        \
      ASN1_STR_OCTET_STRING "\x10"			    \
)

#define ASN1_HASH_SHA1					        \
    ASN1_STR_CONSTRUCTED_SEQUENCE "\x21"		\
      ASN1_STR_CONSTRUCTED_SEQUENCE "\x09"		\
        ASN1_STR_OID "\x05"				        \
	  OID_HASH_ALG_SHA1				            \
        ASN1_STR_NULL "\x00"				    \
      ASN1_STR_OCTET_STRING "\x14"

#define ASN1_HASH_SHA2X					        \
    ASN1_STR_CONSTRUCTED_SEQUENCE "\x11"		\
      ASN1_STR_CONSTRUCTED_SEQUENCE "\x0d"		\
        ASN1_STR_OID "\x09"				        \
	  OID_HASH_ALG_SHA2X				        \
        ASN1_STR_NULL "\x00"				    \
      ASN1_STR_OCTET_STRING "\x00"

typedef unsigned int (*randfunc_t)(void* arg);
typedef int (*printf_func_t)(const char* fmt, ...);

/**
 * \brief          RSA context structure
 */
typedef struct
{
    int ver;                    /*!<  always 0          */
    int len;                    /*!<  size(N) in chars  */   

    mpz_t N;                      /*!<  public modulus    */
    mpz_t E;                      /*!<  public exponent   */
    mpz_t D;                      /*!<  private exponent  */
	randfunc_t m_rand;
	void* m_randarg;
    int padding;
}
rsa_context;


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Initialize an RSA context
 *
 * \param ctx      RSA context to be initialized
 * \param padding  RSA_PKCS_V15 or RSA_PKCS_V21
 * \param hash_id  RSA_PKCS_V21 hash identifier
 *
 * \note           The hash_id parameter is actually ignored
 *                 when using RSA_PKCS_V15 padding.
 *
 * \note           Currently, RSA_PKCS_V21 padding
 *                 is not supported.
 */
WINLIB_API void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id);


/**
 * \brief          Initialize an RSA nums
 *
 * \param ctx      RSA context to be initialized
 * \param bitsize  bitsize to set for rsa
 * \param nstr    for N in rsa
 * \param estr    for E in rsa
 * \param dstr    for D in rsa
 * \param radix  for radix as the string will convert
 *
 */
WINLIB_API int rsa_init_nums(rsa_context* ctx,int bitsize,char* nstr,char* estr,
                  char* dstr,int radix);

WINLIB_API int rsa_init_func(rsa_context* ctx,randfunc_t randfunc,void* arg);

WINLIB_API int rsa_encrypt(unsigned char* cipher,int cipherlen,unsigned char* message, int messlen, rsa_context* prsa,printf_func_t printfunc);
WINLIB_API int rsa_decrypt(unsigned char* message,int messlen,unsigned char* cipher, int cipherlen, rsa_context* prsa,printf_func_t printfunc);
WINLIB_API int rsa_sign(unsigned char* signedmess ,int signedlen,unsigned char *mess,int messlen,rsa_context* prsa,printf_func_t printfunc);
WINLIB_API int rsa_verify(unsigned char* verimess ,int verilen,unsigned char *mess,int messlen,rsa_context* prsa,printf_func_t printfunc);




/**
 * \brief          Free the components of an RSA key
 *
 * \param ctx      RSA Context to free
 */
WINLIB_API void rsa_free( rsa_context *ctx );


#ifdef __cplusplus
}
#endif

#endif /* __CRYPT_RSA_H__ */
