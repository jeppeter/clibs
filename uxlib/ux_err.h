#ifndef __UX_ERR_H_73A8C598A0218E3860A02C1628B7A768__
#define __UX_ERR_H_73A8C598A0218E3860A02C1628B7A768__

#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define  SETERRNO(ret) do{int __ret=(ret); if (__ret < 0) { __ret = - __ret;} errno = __ret;} while(0)
#define  GETERRNO(ret) do{int __ret=errno; if (__ret > 0) { __ret = - __ret;} if (__ret == 0) { __ret = -1;} ret = __ret;} while(0)
#define  GETERRNO_DIRECT(ret) do {int __ret = errno; if (__ret > 0) { __ret = -__ret;} ret = __ret;} while(0)


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_ERR_H_73A8C598A0218E3860A02C1628B7A768__ */
