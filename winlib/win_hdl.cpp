#include <win_hdl.h>
#include <win_output_debug.h>
#include <win_ntapi.h>
#include <win_uniansi.h>
#include <win_strop.h>
#include <vector>

#define MAX_QUERY_BUF_SIZE   (2UL << 20)

typedef struct __info_variables {
	char* m_ptypename;
	int m_typesize;
	char* m_pname;
	int m_namesize;
	HANDLE m_duphdl;
	HANDLE m_prochdl;
	phandle_info_t m_phdlinfo;
	HMODULE m_ntmod;
	int m_lastpid;	
} info_variables_t,*pinfo_variables_t;

typedef struct __input_handls_t {
	CRITICAL_SECTION m_cs;
	std::vector<PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>* m_pvec;
}input_handles_t,*pinput_handles_t;

typedef struct __output_infos_t {
	CRITICAL_SECTION m_cs;
	std::vector<phandle_info_t>* m_pvec;
} output_infos_t,*poutput_infos_t;

typedef struct __thread_vars {
	HANDLE m_notievt;
	HANDLE m_exitevt;
	HANDLE m_thrhdl;
	pinfo_variables_t m_pvars;
	pinput_handles_t m_pinput;
	poutput_infos_t m_poutput;
	int m_exited;
	int m_exitcode;
} thread_vars_t,*pthread_vars_t;

void free_info_variables(pinfo_variables_t* ppvars)
{
	if (ppvars && *ppvars) {
		pinfo_variables_t pvars = *ppvars;
		if (pvars->m_ptypename) {
			free(pvars->m_ptypename);
		}
		pvars->m_ptypename = NULL;
		pvars->m_typesize = 0;

		if (pvars->m_pname) {
			free(pvars->m_pname);
		}
		pvars->m_pname = NULL;
		pvars->m_namesize = 0;

		if (pvars->m_duphdl != NULL) {
			CloseHandle(pvars->m_duphdl);
		}
		pvars->m_duphdl = NULL;

		if (pvars->m_prochdl != NULL) {
			CloseHandle(pvars->m_prochdl);
		}
		pvars->m_prochdl = NULL;

		if (pvars->m_phdlinfo != NULL) {
			free(pvars->m_phdlinfo);
		}
		pvars->m_phdlinfo = NULL;

		if (pvars->m_ntmod != NULL) {
			CloseHandle(pvars->m_ntmod);
		}
		pvars->m_ntmod = NULL;

		pvars->m_lastpid = -1;

		free(pvars);
		*ppvars = NULL;
	}
	return ;
}


pinfo_variables_t alloc_info_variables(void)
{
	pinfo_variables_t pvars = NULL;
	int ret;
	pvars = malloc(sizeof(*pvars));
	if (pvars == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pvars,0,sizeof(*pvars));
	pvars->m_lastpid = -1;

	pvars->m_typesize = 4;
	pvars->m_namesize = 4;

	return pvars;
fail:
	free_info_variables(&pvars);
	SETERRNO(ret);
	return NULL;
}

void free_input_handles(pinput_handles_t* pphdls)
{
	if (pphdls && *pphdls) {
		pinput_handles_t phdls = *pphdls;
		if (phdls->m_pvec) {
			while(phdls->m_pvec->size() > 0) {
				PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX phdl = phdls->m_pvec->at(0);
				phdls->m_pvec->erase(phdls->m_pvec->begin());
				free(phdl);
				phdl = NULL;
			}

			delete phdls->m_pvec;
			phdls->m_pvec = NULL;
		}
		free(phdls);
		*pphdls = NULL;
	}
	return;
}


int peek_input_handles(pinput_handles_t phdls,PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX pinput)
{
	int ret = 0;
	EnterCriticalSection(&(phdls->m_cs));
	if (phdls->m_pvec->size() > 0) {
		PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX pget = phdls->m_pvec->at(0);
		memcpy(pinput,pget,sizeof(*pget));
		ret = 1;
	}
	LeaveCriticalSection(&(phdls->m_cs));
	return ret;
}

int remove_input_handles(pinput_handles_t phdls)
{
	int ret = 0;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX pget = NULL;
	EnterCriticalSection(&(phdls->m_cs));
	if (phdls->m_pvec->size() > 0) {
		pget = phdls->m_pvec->at(0);
		phdls->m_pvec->erase(phdls->m_pvec->begin());
		ret = 1;
	}
	LeaveCriticalSection(&(phdls->m_cs));
	if (pget != NULL) {
		free(pget);
	}
	pget = NULL;
	return ret;
}

int push_input_handles(pinput_handles_t phdls, PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX ptable)
{
	int ret = 0;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX pinsert= NULL;
	pinsert = malloc(sizeof(*pinsert));
	if (pinsert == NULL) {
		GETERRNO(ret);
		return ret;
	}

	memcpy(pinsert,ptable,sizeof(*pinsert));

	EnterCriticalSection(&(phdls->m_cs));
	phdls->m_pvec->push_back(pinsert);
	ret = phdls->m_pvec->size();
	LeaveCriticalSection(&(phdls->m_cs));
	return ret;
}

pinput_handles_t alloc_input_handles(void)
{
	pinput_handles_t phdls=NULL;
	int ret;

	phdls = malloc(sizeof(*phdls));
	if (phdls == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(phdls,0,sizeof(*phdls));
	InitializeCriticalSection(&(phdls->m_cs));
	phdls->m_pvec = new std::vector<PSYSTEM_HANDLE_INFORMATION_EX>();
	return phdls;
fail:
	free_input_handles(&phdls);
	SETERRNO(ret);
	return NULL;
}

void free_output_info(poutput_infos_t *ppinfos)
{
	if (ppinfos && *ppinfos) {
		poutput_infos_t pinfos = *ppinfos;
		if (pinfos->m_pvec != NULL) {
			while(pinfos->m_pvec->size() > 0) {
				phandle_info_t pinfo = pinfos->m_pvec->at(0);
				pinfos->m_pvec->erase(pinfos->m_pvec->begin());
				free(pinfo);
				pinfo = NULL;
			}
			delete pinfos->m_pvec;
			pinfos->m_pvec = NULL;
		}
		free(pinfos);
		*ppinfos = NULL;
	}
	return;
}

poutput_infos_t alloc_output_infos(void)
{
	poutput_infos_t pinfos = NULL;
	int ret;

	pinfos = malloc(sizeof(*pinfos));
	if (pinfos == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pinfos,0,sizeof(*pinfos));
	InitializeCriticalSection(&(pinfos->m_cs));
	pinfos->m_pvec = new std::vector<phandle_info_t>();
	return pinfos;
fail:
	free_output_info(&pinfos);
	SETERRNO(ret);
	return NULL;
}

int push_output_info(poutput_infos_t pinfos, phandle_info_t *ppinfo)
{
	int ret=0;
	EnterCriticalSection(&(pinfos->m_cs));
	pinfos->m_pvec->push_back(*ppinfo);
	*ppinfo = NULL;
	ret = pinfos->m_pvec->size();
	LeaveCriticalSection(&(pinfos->m_cs));
	return ret;
}

phandle_info_t get_output_info(poutput_infos_t pinfos)
{
	phandle_info_t poutput=NULL;
	EnterCriticalSection(&(pinfos->m_cs));
	if (pinfos->m_pvec->size() > 0) {
		poutput = pinfos->m_pvec->at(0);
		pinfos->m_pvec->erase(pinfos->m_pvec->begin());
	}
	LeaveCriticalSection(&(pinfos->m_cs));
	return poutput;
}

DWORD WINAPI get_handle_info_thread(void* args)
{
	pthread_vars_t pthrvars = (pthread_vars_t) args;
	int ret;
	pinfo_variables_t pvars = pthrvars->m_pvars;
	pinput_handles_t pinput = pthrvars->m_pinput;
	poutput_infos_t poutput = pthrvars->m_poutput;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX ptable;
	int curpid = (int)GetCurrentProcessId();
	int curthrid = (int)GetCurrentThreadId();
	int lasterrpid = -1;
	int i;

	if (pvars->m_typesize == 0) {
		pvars->m_typesize = 4;
	}

	if (pvars->m_namesize == 0) {
		pvars->m_namesize = 4;
	}

	if (pvars->m_phdlinfo == NULL) {
		pvars->m_phdlinfo = malloc(sizeof(*(pvars->m_phdlinfo)));
		if (pvars->m_phdlinfo == NULL) {
			GETERRNO(ret);
			goto out;
		}
	}

	ptable = pvars->m_phdlinfo;


	while(1) {
		ret = peek_input_handles(pinput,ptable);
		if (ret == 0) {
			dret = WaitForSingleObject(pthrvars->m_exitevt,1);
			if (dret == WAIT_OBJECT_0) {
				/*that exited*/
				break;
			}
			/*we notified*/
			SetEvent(pthrvars->m_notievt);
			continue;
		}


		if (ptable->UniqueProcessId == curpid) {
			DEBUG_INFO("[%d].[%d] skip same process", curpid,curthrid);
			goto next_cycle;
		}

		/*ok this is the */
		if (pvars->m_lastpid < 0 || pvars->m_lastpid != (int)ptable->UniqueProcessId) {
			if (pvars->m_prochdl != NULL) {
				CloseHandle(pvars->m_prochdl);
			}
			pvars->m_prochdl = NULL;
			pvars->m_prochdl = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)ptable->UniqueProcessId);
			if (pvars->m_prochdl == NULL) {
				if (lasterrpid != (int)ptable->UniqueProcessId) {
					GETERRNO(ret);
					ERROR_INFO("[%d].[%d] can not open [%d] process error[%d]", curpid,curthrid, (int)(ptable->UniqueProcessId), ret);	
					lasterrpid = (int) ptable->UniqueProcessId;
				}
				goto next_cycle;
			}
		}



	next_cycle:
		/*we handle next one*/
		remove_input_handles(pinput);
	}


out:
	pthrvars->m_exitcode = ret;
	SETERRNO(ret);
	pthrvars->m_exited = 1;
	return (DWORD)ret;
}


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

