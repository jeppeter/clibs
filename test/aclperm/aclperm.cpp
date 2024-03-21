/*++
THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (C) 1996 - 2000.  Microsoft Corporation.  All rights reserved.

Module Name:

    aclapi.c

Abstract:

    This module illustrates new Acl management API for Windows NT 4.0.

    Developers of new software which is to run on Windows NT version 4.0
    and above are encouraged to utilize these security API rather than
    implementing code which uses lower level security API.  The development
    and test time can be drastically reduced by utilizing these new API.

    This sample illustrates this point by implementing code which modifies
    the security on an existing file using the new Windows NT 4.0
    Acl management API.


    The following new API functions are illustrated in this sample:

    GetNamedSecurityInfo()
    BuildExplicitAccessWithName()
    SetEntriesInAcl()
    SetNamedSecurityInfo()

    The following lower-level security API would have been used to achieve
    the same result:

    LookupAccountName()
    InitializeSecurityDescriptor()
    InitializeAcl()
    GetSecurityDescriptorDacl()
    GetAclInformation()
    GetAce()
    SetSecurityDescriptorDacl()
    AddAce()
    AddAccessAllowedAce() / AddAccessDeniedAce()
    GetFileSecurity()
    SetFileSecurity()

    Less code and less complex code is required to achieve this task using
    the new Windows NT 4.0 Acl management API.

--*/

#include <windows.h>
#include <aclapi.h>
#include <lmerr.h>

#include <stdio.h>
#include <assert.h>

#define RTN_OK 0
#define RTN_USAGE 1
#define RTN_ERROR 13

#pragma comment(lib,"Advapi32.lib")

#define GETERRNO(ret) do{ret = -(int)GetLastError(); if (ret == 0) {ret = -1;}} while(0)
#define SETERRNO(ret) do{if(ret>0) {SetLastError(ret);} else {SetLastError(-ret);}}while(0)

#define  DEBUG_INFO(...) do{}while(0)
#define  ERROR_INFO(...) do{}while(0)


int AnsiToUnicode(char* pChar, wchar_t **ppWideChar, int*pWideCharSize)
{
    wchar_t *pRetWideChar = *ppWideChar;
    int retwidecharsize = *pWideCharSize;
    int ret, len, needlen;

    if (pChar == NULL) {
        if (*ppWideChar) {
            delete [] pRetWideChar;
        }
        *ppWideChar = NULL;
        *pWideCharSize = 0;
        return 0;
    }

    len = (int) strlen(pChar);
    needlen = MultiByteToWideChar(CP_ACP, 0, pChar, len, NULL, 0);
    if (retwidecharsize <= needlen) {
        retwidecharsize = needlen + 1;
        pRetWideChar = new wchar_t[(size_t)retwidecharsize];
        assert(pRetWideChar != NULL);
    }

    ret = MultiByteToWideChar(CP_ACP, 0, pChar, len, pRetWideChar, retwidecharsize);
    if (ret != needlen) {
        ret = ERROR_INVALID_BLOCK;
        goto fail;
    }
    pRetWideChar[needlen] = '\0';

    if ( (*ppWideChar) && (*ppWideChar) != pRetWideChar) {
        wchar_t *pTmpWideChar = *ppWideChar;
        delete [] pTmpWideChar;
    }
    *ppWideChar = pRetWideChar;
    *pWideCharSize = retwidecharsize;
    return ret;
fail:
    if (pRetWideChar && pRetWideChar != (*ppWideChar)) {
        delete [] pRetWideChar;
    }
    pRetWideChar = NULL;
    retwidecharsize = 0;
    SetLastError((DWORD)ret);
    return -ret;
}


int AnsiToTchar(const char *pChar, TCHAR **pptchar, int *ptcharsize)
{
    int ret;
#ifdef _UNICODE
    ret = AnsiToUnicode((char*)pChar, pptchar, ptcharsize);
#else
    ret = _chartoansi(pChar, pptchar, ptcharsize);
#endif
    return ret;
}


int __handle_priv_token(HANDLE htoken, const char* privstr, int enabled)
{
    TCHAR* ptpriv = NULL;
    int tprivsize = 0;
    int ret;
    BOOL bret;
    TOKEN_PRIVILEGES tp;
    LUID luid;


    ret = AnsiToTchar(privstr, &ptpriv, &tprivsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = LookupPrivilegeValue(NULL, ptpriv, &luid);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("lookup [%s] error[%d]", privstr, ret);
        goto fail;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (enabled) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        tp.Privileges[0].Attributes = 0;
    }

    bret = AdjustTokenPrivileges(htoken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("adjust %s [%s] error[%d]", privstr, enabled ? "enable" : "disable", ret);
        goto fail;
    }
    DEBUG_INFO("%s [%s] succ",  enabled ? "enable" : "disable", privstr);


    return 0;
fail:
    AnsiToTchar(NULL, &ptpriv, &tprivsize);
    SETERRNO(ret);
    return ret;
}



int __handle_priv(const char* privstr, int enabled)
{
    TCHAR* ptpriv = NULL;
    int tprivsize = 0;
    int ret;
    BOOL bret;
    HANDLE htoken = NULL;

    bret = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &htoken);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("open process token error[%d]", ret);
        goto fail;
    }

    ret = __handle_priv_token(htoken, privstr, enabled);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    if (htoken != NULL) {
        CloseHandle(htoken);
    }
    htoken = NULL;

    return 0;
fail:
    if (htoken != NULL) {
        CloseHandle(htoken);
    }
    htoken = NULL;
    AnsiToTchar(NULL, &ptpriv, &tprivsize);
    SETERRNO(ret);
    return ret;
}

int __get_priv_value_inner(HANDLE htoken,const char* privstr)
{
    TCHAR* ptpriv = NULL;
    int tprivsize = 0;
    int ret;
    BOOL bret;
    LUID luid;
    int value = 0;
    PVOID ptokenbuf=NULL;
    DWORD tokenbufsize=32;
    DWORD dret;
    TOKEN_PRIVILEGES* ptp=NULL;
    DWORD i;


    ret = AnsiToTchar(privstr, &ptpriv, &tprivsize);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    bret = LookupPrivilegeValue(NULL, ptpriv, &luid);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("lookup [%s] error[%d]", privstr, ret);
        goto fail;
    }

try_again:
    if (ptokenbuf) {
        HeapFree(GetProcessHeap(), 0, ptokenbuf);
    }
    ptokenbuf = NULL;
    ptokenbuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tokenbufsize);
    if (ptokenbuf == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    bret = GetTokenInformation(htoken,TokenPrivileges,ptokenbuf,tokenbufsize,&dret);
    if (!bret) {
        GETERRNO(ret);
        if (ret == -ERROR_INSUFFICIENT_BUFFER) {
            tokenbufsize <<= 1;
            goto try_again;
        }
        ERROR_INFO("get token buffer error[%d]", ret);
        goto fail;
    }

    ptp = (TOKEN_PRIVILEGES*) ptokenbuf;
    for (i=0;i<ptp->PrivilegeCount ;i ++) {
        if (ptp->Privileges[i].Luid.LowPart == luid.LowPart && 
            ptp->Privileges[i].Luid.HighPart == luid.HighPart) {
            if (ptp->Privileges[i].Attributes  & SE_PRIVILEGE_ENABLED) {
                value = 1;
            } else {
                value = 0;
            }
        }
    }
    DEBUG_INFO("[%d] value [%d]", privstr,value);

    if (ptokenbuf) {
        HeapFree(GetProcessHeap(), 0, ptokenbuf);
    }
    ptokenbuf = NULL;
    AnsiToTchar(NULL, &ptpriv, &tprivsize);
    return value;
fail:
    if (ptokenbuf) {
        HeapFree(GetProcessHeap(), 0, ptokenbuf);
    }
    ptokenbuf = NULL;
    AnsiToTchar(NULL, &ptpriv, &tprivsize);
    SETERRNO(ret);
    return ret;
}


int __get_priv_value(const char* privstr)
{
    int ret;
    int val=0;
    HANDLE htoken=NULL;
    BOOL bret;

    bret = OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&htoken);
    if (!bret) {
        GETERRNO(ret);
        ERROR_INFO("open token query error[%d]", ret);
        goto fail;
    }

    ret = __get_priv_value_inner(htoken,privstr);
    if (ret < 0) {
        GETERRNO(ret);
        goto fail;
    }

    val = ret;

    if (htoken != NULL && htoken != INVALID_HANDLE_VALUE) {
        CloseHandle(htoken);
    }
    htoken = NULL;
    return val;
fail:
    if (htoken != NULL && htoken != INVALID_HANDLE_VALUE) {
        CloseHandle(htoken);
    }
    htoken = NULL;
    SETERRNO(ret);
    return ret;
}


int enable_security_priv(void)
{
    return __handle_priv("SeSecurityPrivilege", 1);
}

int disable_security_priv(void)
{
    return __handle_priv("SeSecurityPrivilege", 0);
}

void
DisplayLastError(
    LPSTR szAPI
    );

int
__cdecl
main(
    int argc,
    char *argv[]
    )
{
    LPTSTR FileName;
    LPTSTR TrusteeName;

    DWORD AccessMask = GENERIC_ALL;
    DWORD InheritFlag = NO_INHERITANCE;
    ACCESS_MODE option;
    EXPLICIT_ACCESS explicitaccess;

    PACL ExistingDacl;
    PACL NewAcl = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;

    DWORD dwError;
    BOOL bSuccess = FALSE; // assume failure
    int ret;

    if(argc < 4) {
        printf("Usage: %s <filename> {/Deny | /Grant | /Revoke | /Set} [<trustee>] [<permissions>] [<InheritFlag>]\n", argv[0]);
        return RTN_USAGE;
    }

    FileName = (LPTSTR)argv[1];
    TrusteeName = (LPTSTR)argv[3];

    if ( (0 == _stricmp(argv[2], "/Deny") ) ||
        (0 == _stricmp(argv[2], "/D") ) )
    {
      option = DENY_ACCESS;
    } else if ( ( (0 == _stricmp(argv[2], "/Revoke") ) ||
                 (0 == _stricmp(argv[2], "/R") ) ) )
    {
      option = REVOKE_ACCESS;
    } else if ( (0 == _stricmp(argv[2], "/Set") ) ||
               (0 == _stricmp(argv[2], "/S") ) )
    {
      option = SET_ACCESS;
    } else if ( (0 == _stricmp(argv[2], "/Grant") ) ||
               (0 == _stricmp(argv[2], "/G") ) )
    {
      option = GRANT_ACCESS;
    } else {
        printf("Invalid action specified\n");
        return RTN_ERROR;
    }

    if (argc > 4)
    {
        AccessMask = atol( argv[4] );
    }

    if (argc > 5)
    {
       InheritFlag = atol( argv[5] );
    }

    ret = enable_security_priv();
    if (ret < 0) {
        fprintf(stderr,"enable_security_priv error\n");
        return -1;
    }
    //
    // get current Dacl on specified file
    //

    dwError = GetNamedSecurityInfo(
                        FileName,
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        NULL,
                        NULL,
                        &ExistingDacl,
                        NULL,
                        &psd
                        );

    if(dwError != ERROR_SUCCESS) {
        //DisplayLastError("GetNamedSecurityInfo");
        fprintf(stderr,"GetNamedSecurityInfo [%ld] dwError  [%ld]\n",GetLastError(),dwError);
        return RTN_ERROR;
    }

    BuildExplicitAccessWithName(
            &explicitaccess,
            TrusteeName,
            AccessMask,
            option,
            InheritFlag
            );

    //
    // add specified access to the object
    //

    dwError = SetEntriesInAcl(
            1,
            &explicitaccess,
            ExistingDacl,
            &NewAcl
            );

    if(dwError != ERROR_SUCCESS) {
        DisplayLastError("SetEntriesInAcl");
        goto cleanup;
    }

    //
    // apply new security to file
    //

    dwError = SetNamedSecurityInfo(
                    FileName,
                    SE_FILE_OBJECT, // object type
                    DACL_SECURITY_INFORMATION,
                    NULL,
                    NULL,
                    NewAcl,
                    NULL
                    );

    if(dwError != ERROR_SUCCESS) {
        DisplayLastError("SetNamedSecurityInfo");
        goto cleanup;
    }

    bSuccess = TRUE; // indicate success

cleanup:

    if( NewAcl != NULL ) AccFree( NewAcl );
    if( psd != NULL) AccFree( psd );


    if(!bSuccess)
        return RTN_ERROR;

    return RTN_OK;
}

void
DisplayLastError(
    LPSTR szAPI
    )
{
    HMODULE hModule = NULL; // default to system source
    DWORD dwLastError = GetLastError();
    LPSTR MessageBuffer;
    DWORD dwBufferLength;

    DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_IGNORE_INSERTS |
        FORMAT_MESSAGE_FROM_SYSTEM ;

    //
    // if dwLastError is in the network range, load the message source
    //

    if(dwLastError >= NERR_BASE && dwLastError <= MAX_NERR) {
        hModule = LoadLibraryEx(
            TEXT("netmsg.dll"),
            NULL,
            LOAD_LIBRARY_AS_DATAFILE
            );

        if(hModule != NULL)
            dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;
    }

    printf("%s error! (rc=%lu)\n", szAPI, dwLastError);

    //
    // call FormatMessage() to allow for message text to be acquired
    // from the system or the supplied module handle
    //

    if(dwBufferLength = FormatMessageA(
        dwFormatFlags,
        hModule, // module to get message from (NULL == system)
        dwLastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
        (LPSTR) &MessageBuffer,
        0,
        NULL
        ))
    {
        DWORD dwBytesWritten;

        //
        // Output message string on stderr
        //
        WriteFile(
            GetStdHandle(STD_ERROR_HANDLE),
            MessageBuffer,
            dwBufferLength,
            &dwBytesWritten,
            NULL
            );

        //
        // free the buffer allocated by the system
        //
        LocalFree(MessageBuffer);
    }

    //
    // if we loaded a message source, unload it
    //
    if(hModule != NULL)
        FreeLibrary(hModule);
}