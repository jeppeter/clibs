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
#if 0
#pragma warning(push)

#pragma warning(disable:4668)
#pragma warning(disable:4820)

#include <aclapi.h>
#pragma warning(pop)
#include <lmerr.h>

#pragma warning(push)
#pragma warning(disable:4514)
#include <stdio.h>
#pragma warning(pop)

//#include <assert.h>
#include <win_priv.h>
#include <win_output_debug.h>
#include <win_uniansi.h>

#define RTN_OK 0
#define RTN_USAGE 1
#define RTN_ERROR 13


#pragma comment(lib,"Advapi32.lib")

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
    TCHAR* FileName=NULL;
    int filesize=0;
    TCHAR* TrusteeName=NULL;
    int trustsize=0;

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
    PEXPLICIT_ACCESS pacc=NULL;
    ULONG lcnt;
    ULONG i;

    if(argc < 4) {
        printf("Usage: %s <filename> {/Deny | /Grant | /Revoke | /Set} [<trustee>] [<permissions>] [<InheritFlag>]\n", argv[0]);
        goto cleanup;
    }

    ret = AnsiToTchar(argv[1],&FileName,&filesize);
    if (ret < 0) {
        GETERRNO(ret);
        goto cleanup;
    }

    ret = AnsiToTchar(argv[3],&TrusteeName,&trustsize);
    if (ret < 0 ){
        GETERRNO(ret);
        goto cleanup;
    }

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

    if (argc > 4) {
        AccessMask = (DWORD)atol( argv[4] );
    }

    if (argc > 5) {
       InheritFlag = (DWORD)atol( argv[5] );
    }

    ret = enable_security_priv();
    if (ret < 0) {
        fprintf(stderr,"enable_security_priv error\n");
        goto cleanup;
    }
    //enpriv = 1;
    fprintf(stdout, "AccessMask 0x%lx InheritFlag 0x%lx\n", AccessMask,InheritFlag);
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

    dwError = GetExplicitEntriesFromAcl(ExistingDacl,&lcnt,&pacc);
    if (dwError != ERROR_SUCCESS) {
        DisplayLastError("GetExplicitEntriesFromAcl");
        goto cleanup;
    }

    fprintf(stderr,"get [%ld]\n",lcnt);
    for (i=0;i<lcnt;i++) {
        fprintf(stdout,"exist[%ld] access [0x%lx] perm [0x%x]\n",i,pacc[i].grfAccessPermissions, pacc[i].grfAccessMode);
    }

    if (pacc) {
        LocalFree(pacc);
    }
    pacc =NULL;


    dwError = GetExplicitEntriesFromAcl(NewAcl,&lcnt,&pacc);
    if (dwError != ERROR_SUCCESS) {
        DisplayLastError("GetExplicitEntriesFromAcl");
        goto cleanup;
    }

    fprintf(stderr,"get [%ld]\n",lcnt);
    for (i=0;i<lcnt;i++) {
        fprintf(stdout,"new[%ld] access [0x%lx] perm [0x%x]\n",i,pacc[i].grfAccessPermissions, pacc[i].grfAccessMode);
    }


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
        fprintf(stderr,"dwError [%ld]", dwError);
        goto cleanup;
    }




    bSuccess = TRUE; // indicate success


cleanup:

    if (pacc) {
        LocalFree(pacc);
    }
    pacc =NULL;

    if( NewAcl != NULL ) AccFree( NewAcl );
    if( psd != NULL) AccFree( psd );

    AnsiToTchar(NULL,&FileName,&filesize);
    AnsiToTchar(NULL,&TrusteeName,&trustsize);

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

    dwBufferLength = FormatMessageA(
        dwFormatFlags,
        hModule, // module to get message from (NULL == system)
        dwLastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
        (LPSTR) &MessageBuffer,
        0,
        NULL
        );
    if(dwBufferLength != 0)
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
#else
#pragma warning(push)

#pragma warning(disable:4668)
#include <windows.h>

#include <stdio.h>
#pragma warning(pop)

#include <Sddl.h>

#pragma comment(lib,"Advapi32.lib")

SECURITY_DESCRIPTOR *get_security_descriptor(char *filename) {
  /* First find out the amount of memory needed for the security descriptor */
  SECURITY_DESCRIPTOR *sd;
  unsigned long size = 0;

  GetFileSecurityA(filename, DACL_SECURITY_INFORMATION, 0, 0, &size);

  /* We should have failed GetFileSecurity with an out of memory error */
  int ret = (int)GetLastError();
  if (ret != ERROR_INSUFFICIENT_BUFFER) {
    fprintf(stderr, "Error getting file security DACL: %d\n", ret);
    return 0;
  }

  /* Allocate memory for security descriptor */
  sd = (SECURITY_DESCRIPTOR *) HeapAlloc(GetProcessHeap(), 0, size);
  if (! sd) {
    fprintf(stderr, "Out of memory for security descriptor!\n");
    return 0;
  }

  /* Now perform the actual GetFileSecurity() call */
  if (! GetFileSecurityA(filename, DACL_SECURITY_INFORMATION, sd, size, &size)) {
    fprintf(stderr, "Error getting file security DACL: %ld\n", GetLastError());
    HeapFree(GetProcessHeap(), 0, sd);
    return 0;
  }

  return sd;
}

/* Security descriptor needs to have DACL_SECURITY_INFORMATION */
ACL *get_dacl(SECURITY_DESCRIPTOR *sd) {
  if (! sd) return 0;

  /* Get DACL from the security descriptor */
  ACL *acl;
  int defaulted, present;
  if (! GetSecurityDescriptorDacl(sd, &present, &acl, &defaulted)) {
    fprintf(stderr, "Error getting DACL from security descriptor: %ld\n", GetLastError());
    return 0;
  }

  /* If there is one */
  if (! present) {
    fprintf(stderr, "Security descriptor has no DACL present\n");
    HeapFree(GetProcessHeap(), 0, acl);
    return 0;
  }

  return acl;
}

void display_ace(void *ace) {
  if (! ace) return;

  SID *sid;
  char *stringsid;
  int mask;
  char *type;

  /* Check type of ACE and whether it's inherited or not */
  if (((ACCESS_ALLOWED_ACE *) ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
    ACCESS_ALLOWED_ACE *access = (ACCESS_ALLOWED_ACE *) ace;
    sid = (SID *) &access->SidStart;
    mask = (int)access->Mask;
    type = "Allow";
  }
  else if (((ACCESS_DENIED_ACE *) ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
    ACCESS_DENIED_ACE *access = (ACCESS_DENIED_ACE *) ace;
    sid = (SID *) &access->SidStart;
    mask = (int)access->Mask;
    type = "Deny";
  }
  else return;

  /* Check SID to which this ACE applies */
  if (! IsValidSid(sid)) {
    printf(" invalid SID!\n");
    return;
  }

  /* Get size of buffers for account name */
  SID_NAME_USE snu;
  char *name = 0;
  char *domain = 0;
  unsigned long namesize = 0;
  unsigned long domainsize = 0;

  LookupAccountSidA(0, sid, name, &namesize, domain, &domainsize, &snu);
  int ret = (int)GetLastError();
  if (ret != ERROR_INSUFFICIENT_BUFFER) {
    fprintf(stderr, "Error getting size of name and domain: %d\n", ret);
    printf("\n");
    return;
  }

  /* Allocate memory for them */
  name = (char *) HeapAlloc(GetProcessHeap(), 0, namesize);
  if (! name) {
    fprintf(stderr, "Out of memory for account name!\n");
    printf("\n");
    return;
  }

  domain = (char *) HeapAlloc(GetProcessHeap(), 0, domainsize);
  if (! domain) {
    fprintf(stderr, "Out of memory for domain name!\n");
    printf("\n");
    return;
  }

  /* Perform the actual lookup */
  if (! LookupAccountSidA(0, sid, name, &namesize, domain, &domainsize, &snu)) {
    fprintf(stderr, "Error looking up account name: %ld\n", GetLastError());
    printf("\n");
    HeapFree(GetProcessHeap(), 0, name);
    HeapFree(GetProcessHeap(), 0, domain);
  }

  /* Get the sid as a string */
  if (! ConvertSidToStringSidA(sid, &stringsid)) {
    fprintf(stderr, "Error converting SID to string : %ld\n", GetLastError());
    printf("\n");
    HeapFree(GetProcessHeap(), 0, name);
    HeapFree(GetProcessHeap(), 0, domain);
  }

  /* Print 'em */
  if (*domain) printf("%s\\", domain);
  printf("%s\n%s\n", name, stringsid);

  /* Cleanup */
  HeapFree(GetProcessHeap(), 0, stringsid);
  HeapFree(GetProcessHeap(), 0, name);
  HeapFree(GetProcessHeap(), 0, domain);

  /* Print permissions as a string */
  if (mask & FILE_READ_DATA) printf("\t%s\tFILE_READ_DATA\n", type);
  if (mask & FILE_WRITE_DATA) printf("\t%s\tFILE_WRITE_DATA\n", type);
  if (mask & FILE_APPEND_DATA) printf("\t%s\tFILE_APPEND_DATA\n", type);
  if (mask & FILE_READ_EA) printf("\t%s\tFILE_READ_EA\n", type);
  if (mask & FILE_WRITE_EA) printf("\t%s\tFILE_WRITE_EA\n", type);
  if (mask & FILE_EXECUTE) printf("\t%s\tFILE_EXECUTE\n", type);
  if (mask & FILE_READ_ATTRIBUTES) printf("\t%s\tFILE_READ_ATTRIBUTES\n", type);
  if (mask & FILE_WRITE_ATTRIBUTES) printf("\t%s\tFILE_WRITE_ATTRIBUTES\n", type);
  if (mask & FILE_DELETE_CHILD) printf("\t%s\tFILE_DELETE\n", type);
  if (mask & DELETE) printf("\t%s\tDELETE\n", type);
  if (mask & READ_CONTROL) printf("\t%s\tREAD_CONTROL\n", type);
  if (mask & WRITE_DAC) printf("\t%s\tWRITE_DAC\n", type);
  if (mask & WRITE_OWNER) printf("\t%s\tWRITE_OWNER\n", type);
  if (mask & SYNCHRONIZE) printf("\t%s\tSYNCHRONIZE\n", type);
}

int main(int argc, char **argv) {
  if (argc == 1) {
    fprintf(stderr, "Usage: %s pathspec\n", argv[0]);
    fprintf(stderr, "Example: %s c:\\winnt\n", argv[0]);
    return 1;
  }

  /* Get security descriptor for the file */
  SECURITY_DESCRIPTOR *sd = get_security_descriptor(argv[1]);
  if (! sd) return 2;

  /* Get ACL */
  ACL *dacl = get_dacl(sd);
  if (! dacl) {
    HeapFree(GetProcessHeap(), 0, sd);
    return 3;
  }

  /* Get information about the ACL (ie number of ACEs) */
  ACL_SIZE_INFORMATION acl_size_info;
  if (! GetAclInformation(dacl, (void *) &acl_size_info, sizeof(acl_size_info), AclSizeInformation)) {
    fprintf(stderr, "Error getting DACL size information: %ld\n", GetLastError());
    HeapFree(GetProcessHeap(), 0, dacl);
    HeapFree(GetProcessHeap(), 0, sd);
    return 4;
  }

  /* Process ACEs */
  for (int i = 0; i < (int)acl_size_info.AceCount; i++) {
    void *ace;

    if (! GetAce(dacl, (DWORD)i, &ace)) {
      fprintf(stderr, "Can't get ACE %d: %ld\n", i, GetLastError());
      HeapFree(GetProcessHeap(), 0, dacl);
      HeapFree(GetProcessHeap(), 0, sd);
      return 4;
    }

    display_ace(ace);
  }

  /* Cleanup */
  HeapFree(GetProcessHeap(), 0, dacl);
  HeapFree(GetProcessHeap(), 0, sd);

  return 0;
}
#endif