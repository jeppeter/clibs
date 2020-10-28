#ifndef __VSSETUP_H_BE73D584F245CD106FD5BC8A2FA5117E__
#define __VSSETUP_H_BE73D584F245CD106FD5BC8A2FA5117E__

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

int is_visual_studio_installed(const char* version);
void fini_nt_funcs(void);
int init_nt_funcs(void);

#define  NTSTATUS_SUCCESS            0
#define  NTSTATUS_BUFFER_TOO_SMALL   0xC0000023

#define  NTSTATUS_FLT_NOT_INITIALIZED 0xC01C0007


NTSTATUS
NTAPI
NtSetSecurityObjectFake(
    _In_ HANDLE Handle,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

NTSTATUS
NTAPI
NtQuerySecurityObjectFake(
    _In_ HANDLE Handle,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Length,
    _Out_ PULONG LengthNeeded
    );


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __VSSETUP_H_BE73D584F245CD106FD5BC8A2FA5117E__ */
