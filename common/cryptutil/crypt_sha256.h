/*********************************************************************
* Filename:   crypt_sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef __CRYPT_SHA256_H__
#define __CRYPT_SHA256_H__


/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/

typedef struct {
	unsigned char data[64];
	unsigned int datalen;
	unsigned char rsv1[4];
	unsigned long long bitlen;
	unsigned int state[8];
} SHA256_CTX;

#ifdef __cplusplus
extern "C" {
#endif


/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const unsigned char* data, size_t len);
void sha256_final(SHA256_CTX *ctx, unsigned char* hash);

#ifdef __cplusplus
}
#endif


#endif   // __CRYPT_SHA256_H__