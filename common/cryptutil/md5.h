#ifndef __MD5_H_F959FF2A39A35DAEA96B82BC1E0F818C__
#define __MD5_H_F959FF2A39A35DAEA96B82BC1E0F818C__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/


typedef struct __md5_state
{
	unsigned int len;
	unsigned int state[4];
} md5_state_t,*pmd5_state_t;


WINLIB_API void init_md5_state(pmd5_state_t s);
WINLIB_API pmd5_state_t md5sum(unsigned char* p, unsigned int len, unsigned char* digest, pmd5_state_t s);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __MD5_H_F959FF2A39A35DAEA96B82BC1E0F818C__ */
