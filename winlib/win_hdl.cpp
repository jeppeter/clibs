#include <win_hdl.h>
#include <win_output_debug.h>
#include <win_ntapi.h>
#include <win_uniansi.h>
#include <win_strop.h>

#define MAX_QUERY_BUF_SIZE   (2UL << 20)

int get_handle_infos(int freed, phandle_info_t* pphdls, int *psize)
{
	int retsize = 0;
	phandle_info_t prethdl = NULL;
	int retlen = 0;
	int ret;
	NTSTATUS status;
	ULONG uret;
	ULONG bufsize = 32;
	PVOID pbuffer = NULL;
	unsigned int i;
	PSYSTEM_HANDLE_INFORMATION_EX pinfoex = NULL;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX ptblex = NULL;
	NtQuerySystemInformation_fn_t pNtQuerySystemInformation = NULL;
	NtDuplicateObject_fn_t pNtDuplicateObject = NULL;
	NtQueryObject_fn_t pNtQueryObject = NULL;
	void* pqrybuf = NULL;
	ULONG qrysize = 4;
	ULONG qrylen = 0;
	void* pnamebuf = NULL;
	ULONG namesize = 4;
	ULONG namelen = 0;
	void* pbasicbuf = NULL;
	ULONG basicsize = 4;
	ULONG basiclen = 0;
	HMODULE hmod = NULL;
	HANDLE prochdl = NULL;
	HANDLE duphdl = NULL;
	int lastpid = -1;
	int lasterrpid = -1;
	int curpid = -1;
	POBJECT_TYPE_INFORMATION ptypeinfo = NULL;
	POBJECT_NAME_INFORMATION pnameinfo = NULL;
	POBJECT_BASIC_INFORMATION pbasicinfo = NULL;
	char* pstype = NULL;
	int stypesize = 0;
	char* psname = NULL;
	int snamesize = 0;



	if (freed > 0) {
		if (pphdls && *pphdls) {
			free(*pphdls);
			*pphdls = NULL;
		}

		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (pphdls == NULL || psize == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(ret);
		return ret;
	}

	prethdl = *pphdls;
	retsize = *psize;

	hmod = LoadLibraryA("ntdll.dll");
	if (hmod == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	curpid = (int) GetCurrentProcessId();

	pNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_fn_t>(reinterpret_cast<void*>(GetProcAddress(hmod, "NtQuerySystemInformation")));
	if (pNtQuerySystemInformation == NULL) {
		GETERRNO(ret);
		ERROR_INFO("no NtQuerySystemInformation error[%d]", ret);
		goto fail;
	}

	pNtDuplicateObject = reinterpret_cast<NtDuplicateObject_fn_t>(reinterpret_cast<void*>(GetProcAddress(hmod, "NtDuplicateObject")));
	if (pNtDuplicateObject == NULL) {
		GETERRNO(ret);
		ERROR_INFO("no NtDuplicateObject error[%d]", ret);
		goto fail;
	}

	pNtQueryObject = reinterpret_cast<NtQueryObject_fn_t>(reinterpret_cast<void*>(GetProcAddress(hmod, "NtQueryObject")));
	if (pNtQueryObject == NULL) {
		GETERRNO(ret);
		ERROR_INFO("no NtQueryObject error[%d]", ret);
		goto fail;
	}

get_info_again:
	if (pbuffer) {
		free(pbuffer);
	}
	pbuffer = NULL;
	pbuffer = malloc(bufsize);
	if (pbuffer == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	status = pNtQuerySystemInformation(SystemExtendedHandleInformation, pbuffer, bufsize, &uret);
	if (!NT_SUCCESS(status)) {
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			if (bufsize < uret) {
				bufsize = uret;
			} else {
				bufsize <<= 1;
			}
			goto get_info_again;
		}
		GETERRNO(ret);
		ERROR_INFO("can not get SystemExtendedHandleInformation error[%ld] [%d]", status, ret);
		goto fail;
	}

	pinfoex = (PSYSTEM_HANDLE_INFORMATION_EX) pbuffer;
	for (i = 0; i < pinfoex->NumberOfHandles; i++) {
		ptblex = &(pinfoex->Handles[i]);
		if ((int)ptblex->UniqueProcessId == curpid) {
			continue;
		}

		if (lastpid < 0 || lastpid != (int)ptblex->UniqueProcessId) {
			if (prochdl != NULL) {
				CloseHandle(prochdl);
				prochdl = NULL;
			}
			prochdl = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)ptblex->UniqueProcessId);
			if (prochdl == NULL) {
				GETERRNO(ret);
				if (lasterrpid != (int) ptblex->UniqueProcessId) {
					ERROR_INFO("can not open [%d] error[%d]", ptblex->UniqueProcessId, ret);
					lasterrpid = (int)	 ptblex->UniqueProcessId;
				}
				continue;
			}
			lastpid = (int)ptblex->UniqueProcessId;
		}

		if (duphdl != NULL) {
			CloseHandle(duphdl);
			duphdl = NULL;
		}


		status = pNtDuplicateObject(prochdl, (HANDLE)ptblex->HandleValue, NtCurrentProcess(), &duphdl, 0, 0, 0);
		if (!NT_SUCCESS(status)) {
			GETERRNO(ret);
			duphdl = NULL;
			ERROR_INFO("can not open [%d] handle [0x%x] error[0x%lx] [%d]", lastpid, ptblex->HandleValue, status, ret);
			continue;
		}

		//DEBUG_INFO("dup [%d].[0x%x] value [0x%x]", lastpid, ptblex->HandleValue, duphdl);



get_query_type_again:
		if (pqrybuf) {
			free(pqrybuf);
		}
		pqrybuf = NULL;

		pqrybuf = malloc((size_t)qrysize);
		if (pqrybuf == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		memset(pqrybuf, 0 , (size_t)qrysize);

		status = pNtQueryObject(duphdl, ObjectTypeInformation, pqrybuf, qrysize, &uret);
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_INFO_LENGTH_MISMATCH) {
				if (qrysize < MAX_QUERY_BUF_SIZE) {
					if (qrysize < uret) {
						qrysize = uret;
					} else {
						qrysize <<= 1;
					}
					goto get_query_type_again;
				}
			}
			GETERRNO(ret);
			ERROR_INFO("query [%d].[0x%x] duphdl [0x%x] error[0x%x] [%d]", lastpid, ptblex->HandleValue, duphdl, status, ret);
			continue;
		}
		qrylen = uret;
		ptypeinfo = (POBJECT_TYPE_INFORMATION) pqrybuf;

		ret = UnicodeToAnsi(ptypeinfo->TypeName.Buffer, &pstype, &stypesize);
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_BUFFER_FMT(ptypeinfo->TypeName.Buffer, ptypeinfo->TypeName.Length, "trans [%d].[0x%x] duphdl [0x%x] error[%d]", lastpid, ptblex->HandleValue, duphdl, ret);
			goto fail;
		}

		//DEBUG_INFO("[%d].[0x%x] duphdl [0x%x] type [%s]", lastpid, ptblex->HandleValue, duphdl, pstype);
		if (str_nocase_cmp(pstype, "file") == 0 || str_nocase_cmp(pstype, "directory") == 0 ) {

get_basic_again:
			basicsize = sizeof(*pbasicinfo);
			if (pbasicbuf) {
				free(pbasicbuf);
			}
			pbasicbuf = NULL;
			pbasicbuf = malloc(basicsize);
			if (pbasicbuf == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			memset(pbasicbuf , 0, basicsize);
			status = pNtQueryObject(duphdl, ObjectBasicInformation, pbasicbuf, basicsize, &uret);
			if (!NT_SUCCESS(status)) {
				if (status == STATUS_INFO_LENGTH_MISMATCH) {
					if (basicsize < MAX_QUERY_BUF_SIZE) {
						basiclen = basicsize;
						if (basicsize == 0) {
							basicsize = 4;
						} else {
							basicsize <<= 1;
						}

						DEBUG_INFO("query basic [%d].[0x%x] duphdl [0x%x] basicsize [0x%lx] basiclen [0x%lx]", lastpid, ptblex->HandleValue, duphdl, basicsize, basiclen);
						goto get_basic_again;
					}
				}
				GETERRNO(ret);
				ERROR_INFO("query basic [%d].[0x%x] duphdl [0x%x] error[0x%x] [%d]", lastpid, ptblex->HandleValue, duphdl, status, ret);
				continue;
			}

			pbasicinfo = (POBJECT_BASIC_INFORMATION) pbasicbuf;


get_name_again:
			if (pnamebuf) {
				free(pnamebuf);
			}
			pnamebuf = NULL;
			pnamebuf = malloc(namesize);
			if (pnamebuf == NULL) {
				GETERRNO(ret);
				goto fail;
			}
			memset(pnamebuf, 0, namesize);
			DEBUG_INFO("[%d].[0x%x] duphdl [0x%x] type [%s] get name size [%d] Attributes [0x%lx] GrantedAccess [0x%lx]", lastpid, ptblex->HandleValue, duphdl, pstype, pbasicinfo->NameInfoSize,pbasicinfo->Attributes,ptblex->GrantedAccess);
			if ( pbasicinfo->NameInfoSize > 0 ||  
				//(ptblex->GrantedAccess != 0x1a0089 && ptblex->GrantedAccess != 0x1a019f && ptblex->GrantedAccess != 0x120189 && ptblex->GrantedAccess != 0x16019f && ptblex->GrantedAccess != 0x12019f) 
				((ptblex->GrantedAccess & 0x120089) != 0x120089)) {
				DEBUG_INFO("query [%d] [0x%x] duphdl [0x%x]", lastpid,ptblex->HandleValue, duphdl);
				status = pNtQueryObject(duphdl, ObjectNameInformation, pnamebuf, namesize, &uret);
				if (!NT_SUCCESS(status)) {
					if (status == STATUS_INFO_LENGTH_MISMATCH) {
						if (namesize < MAX_QUERY_BUF_SIZE) {
							if (namesize < uret) {
								namesize = uret;
							} else {
								namesize <<= 1;
							}
							DEBUG_INFO("[%d].[0x%x] duphdl [0x%x] type [%s] get name size [%d]", lastpid, ptblex->HandleValue, duphdl, pstype, namesize);
							goto get_name_again;
						}
					}
					GETERRNO(ret);
					ERROR_INFO("[%d].[0x%x] duphdl [0x%x] type [%s] get name error[0x%x] [%d]", lastpid, ptblex->HandleValue, duphdl, pstype, status, ret);
					continue;
				}
				pnameinfo = (POBJECT_NAME_INFORMATION) pnamebuf;

				ret = UnicodeToAnsi(pnameinfo->Name.Buffer, &psname, &snamesize);
				if (ret < 0) {
					GETERRNO(ret);
					goto fail;
				}
				DEBUG_INFO("[%d].[0x%x] duphdl [0x%x] type [%s] name [%s]", lastpid, ptblex->HandleValue, duphdl, pstype, psname);
			}
		}

	}

	if (pbuffer) {
		free(pbuffer);
	}
	pbuffer = NULL;

	UnicodeToAnsi(NULL, &psname, &snamesize);
	UnicodeToAnsi(NULL, &pstype, &stypesize);

	if (pbasicbuf) {
		free(pbasicbuf);
	}
	pbasicbuf = NULL;
	basicsize = 0;
	basiclen = 0;

	if (pnamebuf) {
		free(pnamebuf);
	}
	pnamebuf = NULL;
	namesize = 0;
	namelen = 0;

	if (pqrybuf) {
		free(pqrybuf);
	}
	pqrybuf = NULL;
	qrysize = 0;
	qrylen = 0;

	if (duphdl != NULL) {
		CloseHandle(duphdl);
	}
	duphdl = NULL;

	if (prochdl != NULL) {
		CloseHandle(prochdl);
	}
	prochdl = NULL;

	if (hmod != NULL) {
		FreeLibrary(hmod);
	}
	hmod = NULL;

	return retlen;
fail:
	if (pbuffer) {
		free(pbuffer);
	}
	pbuffer = NULL;

	if (prethdl && prethdl != *pphdls) {
		free(prethdl);
	}
	prethdl = NULL;
	retsize = 0;

	UnicodeToAnsi(NULL, &psname, &snamesize);
	UnicodeToAnsi(NULL, &pstype, &stypesize);

	if (pbasicbuf) {
		free(pbasicbuf);
	}
	pbasicbuf = NULL;
	basicsize = 0;
	basiclen = 0;

	if (pnamebuf) {
		free(pnamebuf);
	}
	pnamebuf = NULL;
	namesize = 0;
	namelen = 0;

	if (pqrybuf) {
		free(pqrybuf);
	}
	pqrybuf = NULL;
	qrysize = 0;
	qrylen = 0;

	if (duphdl != NULL) {
		CloseHandle(duphdl);
	}
	duphdl = NULL;

	if (prochdl != NULL) {
		CloseHandle(prochdl);
	}
	prochdl = NULL;

	if (hmod != NULL) {
		FreeLibrary(hmod);
	}
	hmod = NULL;
	SETERRNO(ret);
	return ret;
}

