/***************************************
*  command line for run as
*
***************************************/
#define WINVER 0x600

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <win_err.h>
#include <win_args.h>
#include <win_strop.h>
#include <win_uniansi.h>
#include <win_output_debug.h>
#include <extargs.h>
#include <Windows.h>

#define  __LSRUNAS_VERSION__             "0.1.2"

#if defined(_WIN64)
#define  _USE_UMS_MODE      1
#else
#undef   _USE_UMS_MODE
#endif

#ifndef STARTF_UNTRUSTEDSOURCE
#define STARTF_UNTRUSTEDSOURCE  0x00008000
#endif

#if _MSC_VER >= 1929
#pragma warning(disable:5045)
#endif

typedef struct __args_options {
	int m_verbose;
	int m_version;
	char* m_username;
	char* m_password;
	char* m_domainname;
	char* m_curdir;
	char** m_ppenvs;

	/*desktop name*/
	char* m_desktopname;
	char* m_title;
	int m_xpos;
	int m_ypos;
	int m_xsize;
	int m_ysize;
	int m_xcountchars;
	int m_ycountchars;

	int m_foreblue;
	int m_foregreen;
	int m_forered;
	int m_foreintensity;
	int m_backblue;
	int m_backgreen;
	int m_backred;
	int m_backintensity;

	/*startinfo flags*/
	int m_siforceonfeedback;
	int m_siforceofffeedback;
	int m_sipreventpinning;
	int m_sirunfullscreen;
	int m_sititleisappid;
	int m_sititleisalinkname;
	int m_siuntrustedsource;
	int m_siusehotkey;

	/*
		window show cmd
		forceminimize             SW_FORCEMINIMIZE
		hide                      SW_HIDE
		maximize                  SW_MAXIMIZE
		minimize                  SW_MINIMIZE
		restore                   SW_RESTORE
		show                      SW_SHOW
		showdefault               SW_SHOWDEFAULT
		showmaximized             SW_SHOWMAXIMIZED
		showminimized             SW_SHOWMINIMIZED
		showminnoactive           SW_SHOWMINNOACTIVE
		showna                    SW_SHOWNA
		shownoactive              SW_SHOWNOACTIVATE
		shownormal                SW_SHOWNORMAL
	*/
	char* m_xwindowcmd;

	char* m_stdinfile;
	char* m_stdouutfile;
	char* m_stderrfile;

	/*append mode*/
	char* m_appendstdoutfile;
	char* m_appendstderrfile;

	/*logon flags*/
	int m_withprofile;
	int m_netcredential;
	/*create flags*/
	int m_createdefaulterrormode;
	int m_createnewconsole;
	int m_createnewprocessgroup;
	int m_createseperatewowvdm;
	int m_createsuspended;
	int m_createunicodeenvironment;

	/*this is the thread attribute */
	char* m_thrattrgroupaff;
	char* m_thrattridealprocess;
	char* m_thrattrmitigationpolicy;
	char* m_thrattrparentprocess;
	char* m_thrattrpreferrednode;
#if defined(_USE_UMS_MODE)
	char* m_thrattrumsthread;
#endif	
	char* m_thrattrproctionlevel;
	char* m_thrattrchildprocesspolicy;
} args_options_t, *pargs_options_t;

#define DEBUG_START(...)   \
	do{\
		if (popt->m_verbose >= 3) {\
			fprintf(stderr, "[%s:%d] ",__FILE__,__LINE__ );\
		} \
		if (popt->m_verbose >= 1) {\
			fprintf(stderr, __VA_ARGS__);\
		}\
	} while(0)
#define DEBUG_STRAIGHT(...) do{if (popt->m_verbose >= 1) {fprintf(stderr, __VA_ARGS__);}}while(0)
#define DEBUG_END()  do{if (popt->m_verbose >= 1) {fprintf(stderr, "\n"); fflush(stderr);}} while(0)




#if defined(_WIN64)
#include "args_options64.cpp"
#elif defined(_WIN32)
#include "args_options32.cpp"
#else
#error "not defined _WIN32 or _WIN64"
#endif

#define SPLIT_ENV_CHAR     0x3
#define SW_ERROR_CODE      0xffffUL

struct __show_window {
	WORD m_showflags;
	const char* m_showcmd;
};

typedef struct __show_window show_window_t;

static show_window_t st_showcmd [] = {
	{SW_FORCEMINIMIZE             , "forceminimize"            } ,
	{SW_HIDE                      , "hide"                     } ,
	{SW_MAXIMIZE                  , "maximize"                 } ,
	{SW_MINIMIZE                  , "minimize"                 } ,
	{SW_RESTORE                   , "restore"                  } ,
	{SW_SHOW                      , "show"                     } ,
	{SW_SHOWDEFAULT               , "showdefault"              } ,
	{SW_SHOWMAXIMIZED             , "showmaximized"            } ,
	{SW_SHOWMINIMIZED             , "showminimized"            } ,
	{SW_SHOWMINNOACTIVE           , "showminnoactive"          } ,
	{SW_SHOWNA                    , "showna"                   } ,
	{SW_SHOWNOACTIVATE            , "shownoactive"             } ,
	{SW_SHOWNORMAL                , "shownormal"               } ,
	{SW_ERROR_CODE                , NULL}
};

typedef struct __thread_attribute {
#if defined(_USE_UMS_MODE)	
	PUMS_CONTEXT m_pumscontext;
	PUMS_COMPLETION_LIST m_pumscompletion;
#endif	
	HANDLE m_hparentproc;
} thread_attribute_t, *pthread_attribute_t;

WORD get_show_window(const char* showwindow)
{
	WORD dret = SW_ERROR_CODE;
	int i;
	for (i = 0; st_showcmd[i].m_showcmd != NULL ; i++) {
		if (strcmp(showwindow, st_showcmd[i].m_showcmd) == 0) {
			dret = st_showcmd[i].m_showflags;
			break;
		}
	}
	return dret;
}

pthread_attribute_t __alloc_thread_attribute()
{
	pthread_attribute_t pattr = NULL;
	pattr = (pthread_attribute_t) malloc(sizeof(*pattr));
	if (pattr) {
		memset(pattr, 0, sizeof(*pattr));
		pattr->m_hparentproc = INVALID_HANDLE_VALUE;
	}
	return pattr;
}

void __dealloc_thread_attribute(pthread_attribute_t* ppattr)
{
	pthread_attribute_t pattr = NULL;
	BOOL bret;
	int res;
	if (ppattr && *ppattr) {
		pattr = *ppattr;
#if defined(_USE_UMS_MODE)		
		if (pattr->m_pumscontext) {
			bret = DeleteUmsThreadContext(pattr->m_pumscontext);
			if (!bret) {
				GETERRNO(res);
				error_out("can not delete ums context error(%d)", res);
			}
		}
		pattr->m_pumscontext = NULL;
		if (pattr->m_pumscompletion) {
			bret = DeleteUmsCompletionList(pattr->m_pumscompletion);
			if (!bret) {
				GETERRNO(res);
				error_out("can not delete usm completion error(%d)", res);
			}
		}
		pattr->m_pumscompletion = NULL;
#endif

		if (pattr->m_hparentproc != INVALID_HANDLE_VALUE) {
			bret = CloseHandle(pattr->m_hparentproc);
			if (!bret) {
				GETERRNO(res);
				error_out("close %p error(%d)", pattr->m_hparentproc, res);
			}
		}
		pattr->m_hparentproc = INVALID_HANDLE_VALUE;
		free(pattr);
		pattr = NULL;
		*ppattr = NULL;
	}
	return ;
}

#if defined(_USE_UMS_MODE)
int __update_ums(args_options_t* popt, LPPROC_THREAD_ATTRIBUTE_LIST pthreadattr, const char* umscommand, pthread_attribute_t pattr)
{
	int ret = 0;
	UMS_CREATE_THREAD_ATTRIBUTES umsattr;
	BOOL bret;

	REFERENCE_ARG(popt);

	if (umscommand != NULL) {
		if (pthreadattr == NULL || pattr == NULL) {
			ret = -ERROR_INVALID_PARAMETER;
			goto fail;
		}
		ret = 0;
		if (strcmp(umscommand, "version") == 0) {
			bret = CreateUmsThreadContext(&(pattr->m_pumscontext));
			if (!bret) {
				GETERRNO(ret);
				error_out("can not create ums thread context error(%d)", ret);
				goto fail;
			}

			bret = CreateUmsCompletionList(&(pattr->m_pumscompletion));
			if (!bret) {
				GETERRNO(ret);
				error_out("can not create ums completion error(%d)", ret);
				goto fail;
			}

			DEBUG_INFO("umscontext %p usmcompletion %p", pattr->m_pumscontext, pattr->m_pumscompletion);

			memset(&umsattr, 0, sizeof(umsattr));
			umsattr.UmsVersion = UMS_VERSION;
			umsattr.UmsContext = pattr->m_pumscontext;
			umsattr.UmsCompletionList = pattr->m_pumscompletion;

			bret = UpdateProcThreadAttribute(pthreadattr, 0, PROC_THREAD_ATTRIBUTE_UMS_THREAD, &umsattr, sizeof(umsattr), NULL, NULL);
			if (!bret) {
				GETERRNO(ret);
				error_out("update ums thread error(%d)", ret);
				goto fail;
			}
			ret = 1;

		} else {
			ret =  -ERROR_INVALID_PARAMETER;
			goto fail;
		}
	}

	return ret;
fail:
	SETERRNO(-ret);
	return ret;
}
#endif

int __update_group_aff(args_options_t* popt, LPPROC_THREAD_ATTRIBUTE_LIST pthreadattr, const char* grpaff, pthread_attribute_t pattr)
{
	int ret = 0;
	BOOL bret;
	char* pcurptr;
	GROUP_AFFINITY groupaff;
	int setmask = 0;
	int setgroup = 0;
	char* pendptr;
	uint64_t num64;
	if (popt != NULL) {
		popt = popt;	
	}	
	if (grpaff != NULL) {
		pattr = pattr;
		memset(&groupaff, 0, sizeof(groupaff));
		pcurptr = (char*)grpaff;
		while (*pcurptr != 0) {
			if (strncmp(pcurptr, "mask=", 5) == 0 ) {
				pcurptr += 5;
				ret = parse_number(pcurptr, &num64, &pendptr);
				if (ret < 0 || pcurptr == pendptr) {
					GETERRNO(ret);
					goto fail;
				}
				groupaff.Mask = (KAFFINITY)num64;
				setmask = 1;
				pcurptr = pendptr;
			} else if (strncmp(pcurptr, "group=", 6) == 0) {
				pcurptr += 6;
				ret = parse_number(pcurptr, &num64, &pendptr);
				if (ret < 0 || pcurptr == pendptr) {
					GETERRNO(ret);
					goto fail;
				}
				groupaff.Group = (WORD)num64;
				setgroup = 1;
				pcurptr = pendptr;
			} else {
				if (setmask == 0) {
					ret = parse_number(pcurptr, &num64, &pendptr);
					if (ret < 0 || pcurptr == pendptr) {
						GETERRNO(ret);
						goto fail;
					}
					groupaff.Mask = (KAFFINITY)num64;
					setmask = 1;
					pcurptr = pendptr;
				} else if (setgroup == 0) {
					ret = parse_number(pcurptr, &num64, &pendptr);
					if (ret < 0 || pcurptr == pendptr) {
						GETERRNO(ret);
						goto fail;
					}
					groupaff.Group = (WORD)num64;
					setgroup = 1;
					pcurptr = pendptr;
				} else {
					ret = parse_number(pcurptr, &num64, &pendptr);
					if (ret < 0 || pcurptr == pendptr) {
						GETERRNO(ret);
						goto fail;
					}
					pcurptr = pendptr;
				}
			}
			while (*pcurptr == ',' ||
			        *pcurptr == ' ' ||
			        *pcurptr == '\t') {
				pcurptr ++;
			}
		}

		DEBUG_INFO("(%s) Group %d Mask %d", grpaff, groupaff.Group, groupaff.Mask);
		bret = UpdateProcThreadAttribute(pthreadattr, 0, PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY, &groupaff, sizeof(groupaff), NULL, NULL);
		if (!bret) {
			GETERRNO(ret);
			error_out("can not update group aff (%s) error(%d)", grpaff, ret);
			goto fail;
		}
		ret = 1;
	}
	return ret;
fail:
	SETERRNO(-ret);
	return ret;
}

int __update_ideal_process(args_options_t* popt, LPPROC_THREAD_ATTRIBUTE_LIST pthreadattr, const char* idealprocess, pthread_attribute_t pattr)
{
	int ret = 0;
	BOOL bret;
	PROCESSOR_NUMBER procnumber;
	char* pcurptr = NULL;
	char* pendptr;
	uint64_t num64;
	int setgroup = 0;
	int setnumber = 0;
	if (popt != NULL) {
		popt = popt;
	}
	if (idealprocess != NULL) {
		pattr = pattr;
		pcurptr = (char*)idealprocess;
		memset(&procnumber, 0, sizeof(procnumber));
		while (*pcurptr != 0) {
			if (strncmp(pcurptr, "group=", 6) == 0) {
				pcurptr += 6;
				ret = parse_number(pcurptr, &num64, &pendptr);
				if (ret < 0 || pcurptr == pendptr) {
					GETERRNO(ret);
					error_out("(%s) not valid", pcurptr);
					goto fail;
				}
				procnumber.Group = (WORD)num64;
				pcurptr = pendptr;
				setgroup = 1;
			} else if (strncmp(pcurptr, "number=", 6) == 0) {
				pcurptr += 6;
				ret = parse_number(pcurptr, &num64, &pendptr);
				if (ret < 0 || pcurptr == pendptr) {
					GETERRNO(ret);
					error_out("(%s) not valid", pcurptr);
					goto fail;
				}
				procnumber.Number = (BYTE)num64;
				pcurptr = pendptr;
				setnumber = 1;
			} else {
				if (setgroup == 0) {
					pcurptr += 6;
					ret = parse_number(pcurptr, &num64, &pendptr);
					if (ret < 0 || pcurptr == pendptr) {
						GETERRNO(ret);
						error_out("(%s) not valid", pcurptr);
						goto fail;
					}
					procnumber.Group = (WORD)num64;
					pcurptr = pendptr;
					setgroup = 1;
				} else if (setnumber == 0) {
					pcurptr += 6;
					ret = parse_number(pcurptr, &num64, &pendptr);
					if (ret < 0 || pcurptr == pendptr) {
						GETERRNO(ret);
						error_out("(%s) not valid", pcurptr);
						goto fail;
					}
					procnumber.Number = (BYTE)num64;
					pcurptr = pendptr;
					setnumber = 1;
				} else {
					ret = parse_number(pcurptr, &num64, &pendptr);
					if (ret < 0 || pcurptr == pendptr) {
						GETERRNO(ret);
						error_out("(%s) not valid", pcurptr);
						goto fail;
					}
					pcurptr = pendptr;
				}
			}
			while (*pcurptr == ',' ||
			        *pcurptr == ' ' ||
			        *pcurptr == '\t') {
				pcurptr ++;
			}
		}
		DEBUG_INFO("(%s) Group %d Number %d", idealprocess, procnumber.Group, procnumber.Number);
		bret = UpdateProcThreadAttribute(pthreadattr, 0, PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR, &procnumber, sizeof(procnumber), NULL, NULL);
		if (!bret) {
			GETERRNO(ret);
			error_out("can not update ideal process (%s) error(%d)", idealprocess, ret);
			goto fail;
		}
		ret =  1;
	}
	return ret;
fail:
	SETERRNO(-ret);
	return ret;
}

typedef struct __mitigation_policy_cmd {
	DWORD64 m_policy;
	const char* m_cmd;
} mitigation_policy_t, *pmitigation_policy_t;

static mitigation_policy_t st_policies [] = {
	{PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE                                                                     , "depenable"                        },
	{PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE                                                           , "depaltthunkenable"                },
	{PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE                                                                   , "sehopenable"                      },
	{PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON                                                , "relimgalwayson"                   },
	{PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF                                               , "relimgalwaysoff"                  },
	{PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS                                     , "relimgalwaysreqrelocs"            },
	{PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON                                                       , "heaptermalwayson"                 },
	{PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_OFF                                                      , "heaptermalwaysoff"                },
	{PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON                                                       , "aslralwayson"                     },
	{PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF                                                      , "aslralwaysoff"                    },
	{PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON                                                    , "highaslron"                       },
	{PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF                                                   , "highaslroff"                      },
	{PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON                                                 , "handlecheckon"                    },
	{PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_OFF                                                , "handlecheckoff"                   },
	{PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON                                           , "win32callon"                      },
	{PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_OFF                                          , "win32calloff"                     },
	{PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON                                              , "extdison"                         },
	{PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_OFF                                             , "extdisoff"                        },
	{PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_MASK                                                     , "dyncodemask"                      },
	{PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_DEFER                                                    , "dyncodedefer"                     },
	{(0x1ui64 << 36) /*PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON*/                            , "dyncodeon"                        },
	{PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_OFF                                               , "dyncodeoff"                       },
	{(0x3ui64 << 36) /*PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON_ALLOW_OPT_OUT*/              , "dyncodeoptouut"                   },
	{(0x3ui64 << 48) /*PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_MASK*/                                          , "fontdismask"                      },
	{(0x0ui64 << 48) /*PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_DEFER*/                                         , "fontdisdefer"                     },
	{(0x1ui64 << 48) /*PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON*/                                     , "fontdison"                        },
	{(0x2ui64 << 48) /*PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_OFF*/                                    , "fontdisoff"                       },
	{(0x3ui64 << 48) /*PROCESS_CREATION_MITIGATION_POLICY_AUDIT_NONSYSTEM_FONTS*/                                      , "auditnonsysfont"                  },
	{(0x3ui64 << 52) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_MASK*/                                  , "imgldmask"                        },
	{(0x0ui64 << 52) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_DEFER*/                                 , "imglddefer"                       },
	{(0x1ui64 << 52) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON*/                             , "imgldon"                          },
	{(0x2ui64 << 52) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_OFF*/                            , "imgldoff"                         },
	{(0x3ui64 << 52) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_RESERVED*/                              , "imgldreserve"                     },
	{(0x3ui64 << 56) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_MASK*/                               , "imgldlowmask"                     },
	{(0x0ui64 << 56) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_DEFER*/                              , "imgldlowdefer"                    },
	{(0x1ui64 << 56) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON*/                          , "imgldlowon"                       },
	{(0x2ui64 << 56) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_OFF*/                         , "imgldlowoff"                      },
	{(0x3ui64 << 56) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_RESERVED*/                           , "imgldlowreserve"                  },
	{(0x3ui64 << 60) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_MASK*/                            , "imgldsys32mask"                   },
	{(0x0ui64 << 60) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_DEFER*/                           , "imgldsys32defer"                  },
	{(0x1ui64 << 60) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON*/                       , "imgldsys32on"                     },
	{(0x2ui64 << 60) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_OFF*/                      , "imgldsys32off"                    },
	{(0x3ui64 << 60) /*PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_RESERVED*/                        , "imgldsys32reserve"                },
	{0                                                                                                                 , NULL                               }
};

int __get_mitigation_policy(const char* policy, DWORD64* pdret64)
{
	int i = 0;
	size_t len = 0;

	for (i = 0; st_policies[i].m_cmd != NULL ; i ++) {
		len = strlen(st_policies[i].m_cmd);
		if (strncmp(policy, st_policies[i].m_cmd, len) == 0) {
			*pdret64 = st_policies[i].m_policy;
			return (int)len;
		}
	}
	return -1;
}

int __update_mitigation_policy(args_options_t* popt, LPPROC_THREAD_ATTRIBUTE_LIST  pthreadattr, const char* mitigationpolicy, pthread_attribute_t pattr)
{
	int ret = 0;
	char* pcurptr;
	DWORD64 policy = 0, dret64;
	BOOL bret;

	if (popt != NULL) {
		popt = popt;
	}

	if (mitigationpolicy != NULL) {
		pattr = pattr;
		pcurptr = (char*)mitigationpolicy;
		while (*pcurptr != 0) {
			ret = __get_mitigation_policy(pcurptr, &dret64);
			if (ret < 0) {
				ret = -ERROR_INVALID_PARAMETER;
				error_out("(%s) not valid", pcurptr);
				goto fail;
			}
			policy |= dret64;
			pcurptr += ret;
			while ( *pcurptr == ',' ||
			        *pcurptr == '|' ||
			        *pcurptr == ' ' ||
			        *pcurptr == '\t') {
				pcurptr ++;
			}
		}

		DEBUG_INFO("(%s) policy 0x%llx", mitigationpolicy, policy);
		bret = UpdateProcThreadAttribute(pthreadattr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);
		if (!bret) {
			GETERRNO(ret);
			error_out("(%s) update policy error(%d)", mitigationpolicy, ret);
			goto fail;
		}
		ret = 1;
	}

	return ret;
fail:
	SETERRNO(-ret);
	return ret;
}

int __update_parent_process(args_options_t* popt, LPPROC_THREAD_ATTRIBUTE_LIST pthreadattr, const char* parentproc, pthread_attribute_t pattr)
{
	int ret = 0;
	uint64_t num64;
	char* pendptr;
	BOOL bret;

	if (popt != NULL) {
		popt = popt;
	}

	if (parentproc != NULL) {
		if (pattr == NULL || pattr->m_hparentproc != INVALID_HANDLE_VALUE) {
			ret = -ERROR_INVALID_PARAMETER;
			goto fail;
		}
		ret = parse_number((char*)parentproc, &num64, &pendptr);
		if (ret < 0 || parentproc == pendptr || *pendptr != '\0') {
			GETERRNO(ret);
			error_out("(%s) not valid parent process", parentproc, ret);
			goto fail;
		}

		pattr->m_hparentproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)num64);
		if (pattr->m_hparentproc == INVALID_HANDLE_VALUE) {
			GETERRNO(ret);
			error_out("can not open(%lld) error(%d)", num64, ret);
			goto fail;
		}
		DEBUG_INFO("(%s) %lld", parentproc, num64);
		bret = UpdateProcThreadAttribute(pthreadattr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &(pattr->m_hparentproc), sizeof(pattr->m_hparentproc), NULL, NULL);
		if (!bret) {
			GETERRNO(ret);
			error_out("can not update parent process(%s) error(%d)", parentproc, ret);
			goto fail;
		}
		ret =  1;
	}
	return ret;
fail:
	SETERRNO(-ret);
	return ret;
}

int __update_prefer_node(args_options_t* popt, LPPROC_THREAD_ATTRIBUTE_LIST pthreadattr, const char* prefernode, pthread_attribute_t pattr)
{
	int ret = 0;
	char* pendptr;
	uint64_t num64;
	DWORD dret;
	BOOL bret;
	if (popt != NULL) {
		popt = popt;
	}

	if (prefernode != NULL) {
		pattr = pattr;
		ret = parse_number((char*)prefernode, &num64, &pendptr);
		if (ret < 0 || pendptr == prefernode || *pendptr != 0x0) {
			GETERRNO(ret);
			error_out("(%s) not valid prefernode", prefernode);
			goto fail;
		}

		dret = (DWORD)num64;
		DEBUG_INFO("(%s) prefernode %d", prefernode, dret);
		bret = UpdateProcThreadAttribute(pthreadattr, 0, PROC_THREAD_ATTRIBUTE_PREFERRED_NODE , &dret, sizeof(dret), NULL, NULL);
		if (!bret) {
			GETERRNO(ret);
			error_out("update (%s) prefernode error(%d)", prefernode, ret);
			goto fail;
		}
		ret = 1;
	}
	return ret;
fail:
	SETERRNO(-ret);
	return ret;
}

int __update_protection_level(args_options_t* popt, LPPROC_THREAD_ATTRIBUTE_LIST pthreadattr, const char* protectionlevel, pthread_attribute_t pattr)
{
	int ret = 0;
	DWORD dret;
	BOOL bret;
	if (popt != NULL) {
		popt = popt;
	}

	if (protectionlevel != NULL) {
		pattr = pattr;
		if (strcmp(protectionlevel, "same") == 0) {
			dret = PROTECTION_LEVEL_SAME;
		} else {
			ret = -ERROR_INVALID_PARAMETER;
			error_out("(%s) not valid protection level", protectionlevel);
			goto fail;
		}
		DEBUG_INFO("(%s) protectionlevel %ld", protectionlevel, dret);
		bret = UpdateProcThreadAttribute(pthreadattr, 0, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, &dret, sizeof(dret), NULL, NULL);
		if (!bret) {
			GETERRNO(ret);
			error_out("update protection level(%s) error(%d)", protectionlevel, ret);
			goto fail;
		}
		ret = 1;
	}
	return ret;
fail:
	SETERRNO(-ret);
	return ret;
}

int __update_thread_attribute(args_options_t *popt, LPPROC_THREAD_ATTRIBUTE_LIST *ppthreadattr, pthread_attribute_t* ppattr)
{
	LPPROC_THREAD_ATTRIBUTE_LIST pthreadattr = NULL;
	pthread_attribute_t pattr = NULL;
	DWORD maxattrs = 0;
	SIZE_T attrsize = 0;
	int ret;
	BOOL bret;
	if (popt->m_thrattrgroupaff != NULL || popt->m_thrattridealprocess != NULL ||
	        popt->m_thrattrmitigationpolicy != NULL || popt->m_thrattrparentprocess != NULL ||
	        popt->m_thrattrpreferrednode != NULL || 
#if defined(_USE_UMS_MODE)
	        popt->m_thrattrumsthread != NULL ||
#endif
	        popt->m_thrattrproctionlevel != NULL || popt->m_thrattrchildprocesspolicy != NULL) {
		pattr = __alloc_thread_attribute();
		if (pthreadattr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		if (popt->m_thrattrgroupaff) {
			maxattrs ++;
		}
		if (popt->m_thrattridealprocess) {
			maxattrs ++;
		}
		if (popt->m_thrattrmitigationpolicy) {
			maxattrs ++;
		}
		if (popt->m_thrattrparentprocess) {
			maxattrs ++;
		}
		if (popt->m_thrattrpreferrednode) {
			maxattrs ++;
		}
#if defined(_USE_UMS_MODE)		
		if (popt->m_thrattrumsthread) {
			maxattrs ++;
		}
#endif
		if (popt->m_thrattrproctionlevel) {
			maxattrs ++;
		}
		if (popt->m_thrattrchildprocesspolicy) {
			maxattrs ++;
		}

		SETERRNO(0);
		InitializeProcThreadAttributeList(NULL, maxattrs, 0, &attrsize);
		GETERRNO_DIRECT(ret);
		if (ret != -ERROR_INSUFFICIENT_BUFFER) {
			GETERRNO(ret);
			goto fail;
		}
		pthreadattr = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrsize);
		if (pthreadattr == NULL) {
			GETERRNO(ret);
			goto fail;
		}
		bret = InitializeProcThreadAttributeList(pthreadattr, maxattrs, 0, &attrsize);
		if (!bret) {
			GETERRNO(ret);
			goto fail;
		}

#if defined(_USE_UMS_MODE)
		ret = __update_ums(popt, pthreadattr, popt->m_thrattrumsthread, pattr);
		if (ret < 0) {
			goto fail;
		}
#endif
		ret = __update_protection_level(popt, pthreadattr, popt->m_thrattrproctionlevel, pattr);
		if (ret < 0) {
			goto fail;
		}

		ret = __update_prefer_node(popt, pthreadattr, popt->m_thrattrpreferrednode, pattr);
		if (ret < 0) {
			goto fail;
		}

		ret = __update_parent_process(popt, pthreadattr, popt->m_thrattrparentprocess, pattr);
		if (ret < 0) {
			goto fail;
		}

		ret = __update_mitigation_policy(popt, pthreadattr, popt->m_thrattrmitigationpolicy, pattr);
		if (ret < 0) {
			goto fail;
		}

		ret = __update_group_aff(popt, pthreadattr, popt->m_thrattrgroupaff, pattr);
		if (ret < 0) {
			goto fail;
		}
	}
	*ppthreadattr = pthreadattr;
	*ppattr = pattr;
	return (int) maxattrs;
fail:
	if (pthreadattr != NULL) {
		DeleteProcThreadAttributeList(pthreadattr);
	}
	__dealloc_thread_attribute(&pattr);
	return ret;

}



int login_user_create_process(int argc, char* argv[], pextargs_state_t pextstate, args_options_t* popt)
{
	wchar_t *pwusername = NULL, *pwpassword = NULL, *pwdomain = NULL, *pwexename = NULL, *pwcmdline = NULL, *pwcurdir = NULL, *pwenvs = NULL;
	int usernamesize = 0, passwordsize = 0, domainsize = 0, exenamesize = 0, wcmdlinesize = 0, curdirsize = 0, wenvsize = 0;
	wchar_t *pwfname = NULL;
	int wfnamesize = 0;
	int ret, res;
	int pid = -1;
	int i;
	char* pcmdline = NULL, *penvs = NULL;
	int cmdlinesize = 0, envsize = 0;
	LPSTARTUPINFOW psiw = NULL;
	LPSTARTUPINFOEXW psixw = NULL;
	size_t siwsize = 0;
	LPPROCESS_INFORMATION ppi = NULL;
	DWORD logonflags = 0;
	DWORD createflags = 0;
	BOOL bret;
	LPPROC_THREAD_ATTRIBUTE_LIST pthreadattr = NULL;
	pthread_attribute_t pattr = NULL;
	argc = argc;
	argv = argv;

	if (popt->m_username) {
		DEBUG_INFO("m_username %s", popt->m_username);
		ret = AnsiToUnicode(popt->m_username, &pwusername, &usernamesize);
		if (ret < 0) {
			goto fail;
		}
	}

	if (popt->m_password) {
		DEBUG_INFO("m_password %s", popt->m_password);
		ret = AnsiToUnicode(popt->m_password, &pwpassword, &passwordsize);
		if (ret < 0) {
			goto fail;
		}
	}

	if (popt->m_domainname) {
		DEBUG_INFO("m_domainname %s", popt->m_domainname);
		ret = AnsiToUnicode(popt->m_domainname, &pwdomain, &domainsize);
		if (ret < 0) {
			goto fail;
		}
	}

	if (popt->m_curdir) {
		DEBUG_INFO("m_curdir %s", popt->m_curdir);
		ret = AnsiToUnicode(popt->m_curdir, &pwcurdir, &curdirsize);
		if (ret < 0) {
			goto fail;
		}
	}

	if (pextstate->leftargs != NULL) {
		for (i=0;;i++) {
			if (pextstate->leftargs[i] == NULL) {
				break;
			}
			if (i == 0) {
				ret = snprintf_safe(&pcmdline,&cmdlinesize,"\"%s\"",pextstate->leftargs[i]);
			} else {
				ret = append_snprintf_safe(&pcmdline,&cmdlinesize," \"%s\"",pextstate->leftargs[i]);
			}
			if (ret < 0) {
				goto fail;
			}
		}
		/*if it is */
		if (i == 0) {			
			ret = snprintf_safe(&pcmdline, &cmdlinesize, "cmd.exe");
			if (ret < 0) {
				goto fail;
			}
		}
	} else {
		ret = snprintf_safe(&pcmdline, &cmdlinesize, "cmd.exe");
		if (ret < 0) {
			goto fail;
		}
	}
	if (popt->m_ppenvs) {
		for (i = 0; popt->m_ppenvs[i]; i++) {
			if (i == 0) {
				ret = append_snprintf_safe(&penvs, &envsize, "%s", popt->m_ppenvs[i]);
			} else {
				ret = append_snprintf_safe(&penvs, &envsize, "%c%s", SPLIT_ENV_CHAR, popt->m_ppenvs[i]);
			}
			if (ret < 0) {
				goto fail;
			}
		}
		ret = append_snprintf_safe(&penvs, &envsize, "%c", SPLIT_ENV_CHAR);
		if (ret < 0) {
			goto fail;
		}
		DEBUG_BUFFER_FMT(penvs, (int)(strlen(penvs) + 1), "penvs [%s]", penvs);

		ret = AnsiToUnicode(penvs, &pwenvs, &wenvsize);
		if (ret < 0) {
			goto fail;
		}
		for (i = 0; pwenvs[i] != 0x0; i++) {
			if (pwenvs[i] == (wchar_t) SPLIT_ENV_CHAR) {
				pwenvs[i] = (wchar_t)0x0;
			}
		}
	}

	DEBUG_INFO("pcmdline [%s]", pcmdline);
	ret = AnsiToUnicode(pcmdline, &pwcmdline, &wcmdlinesize);
	if (ret < 0) {
		goto fail;
	}

	if (popt->m_withprofile) {
		DEBUG_INFO("m_withprofile");
		logonflags |= LOGON_WITH_PROFILE;
	}

	if (popt->m_netcredential) {
		DEBUG_INFO("m_netcredential");
		logonflags |= LOGON_NETCREDENTIALS_ONLY;
	}

	if (popt->m_createdefaulterrormode) {
		DEBUG_INFO("m_createdefaulterrormode");
		createflags  |= CREATE_DEFAULT_ERROR_MODE;
	}
	if (popt->m_createnewconsole) {
		DEBUG_INFO("m_createnewconsole");
		createflags |= CREATE_NEW_CONSOLE;
	}
	if (popt->m_createnewprocessgroup) {
		DEBUG_INFO("m_createnewprocessgroup");
		createflags |= CREATE_NEW_PROCESS_GROUP;
	}

	if (popt->m_createseperatewowvdm) {
		DEBUG_INFO("m_createseperatewowvdm");
		createflags |= CREATE_SEPARATE_WOW_VDM;
	}

	if (popt->m_createsuspended) {
		DEBUG_INFO("m_createsuspended");
		createflags |= CREATE_SUSPENDED;
	}

	if (popt->m_createunicodeenvironment) {
		DEBUG_INFO("m_createunicodeenvironment");
		createflags |= CREATE_UNICODE_ENVIRONMENT;
	}
	ret = __update_thread_attribute(popt, &pthreadattr, &pattr);
	if (ret < 0) {
		goto fail;
	} else if (ret > 0) {
		siwsize = sizeof(STARTUPINFOEXW);
		DEBUG_INFO("extended startupinfo");
		createflags |= EXTENDED_STARTUPINFO_PRESENT;
	} else {
		siwsize = sizeof(STARTUPINFOW);
	}

	psiw = (LPSTARTUPINFOW) malloc(siwsize);
	if (psiw == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(psiw, 0, siwsize);
	psiw->cb = (DWORD)siwsize;
	psiw->lpReserved = NULL;
	psiw->lpDesktop = NULL;
	psiw->lpTitle = NULL;
	psiw->dwX = 0;
	psiw->dwY = 0;
	psiw->dwXSize = 0;
	psiw->dwYSize = 0;
	psiw->dwXCountChars = 0;
	psiw->dwYCountChars = 0;
	psiw->dwFillAttribute = 0;
	psiw->dwFlags = 0;
	psiw->wShowWindow = 0;
	psiw->cbReserved2 = 0;
	psiw->lpReserved2 = NULL;
	psiw->hStdInput = INVALID_HANDLE_VALUE;
	psiw->hStdOutput = INVALID_HANDLE_VALUE;
	psiw->hStdError = INVALID_HANDLE_VALUE;

	if (pthreadattr != NULL) {
		psixw = (LPSTARTUPINFOEXW) psiw;
		psixw->lpAttributeList = pthreadattr;
	}

	if (popt->m_desktopname) {
		i = 0;
		DEBUG_INFO("desktop %s", popt->m_desktopname);
		ret = AnsiToUnicode(popt->m_desktopname, &(psiw->lpDesktop), &i);
		if (ret < 0) {
			goto fail;
		}
	}

	if (popt->m_title) {
		i = 0;
		DEBUG_INFO("title %s", popt->m_title);
		ret = AnsiToUnicode(popt->m_title, &(psiw->lpTitle), &i);
		if (ret < 0) {
			goto fail;
		}
	}

	if (popt->m_stdinfile != NULL  && psiw->hStdInput == INVALID_HANDLE_VALUE) {
		DEBUG_INFO("m_stdinfile [%s]", popt->m_stdinfile);
		ret = AnsiToUnicode(popt->m_stdinfile, &pwfname, &wfnamesize);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		psiw->hStdInput = CreateFileW(pwfname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (psiw->hStdInput == INVALID_HANDLE_VALUE) {
			GETERRNO(ret);
			error_out("open (%s) error(%d)", popt->m_stdinfile, ret);
			goto fail;
		}
		psiw->dwFlags |= STARTF_USESTDHANDLES;
	}

	if (popt->m_appendstdoutfile != NULL) {
		DEBUG_INFO("m_appendstderrfile [%s]", popt->m_appendstdoutfile);
		ret =  AnsiToUnicode(popt->m_appendstdoutfile, &pwfname, &wfnamesize);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		psiw->hStdOutput = CreateFileW(pwfname, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (psiw->hStdOutput == INVALID_HANDLE_VALUE) {
			GETERRNO(ret);
			error_out("open (%s) error(%d)", popt->m_appendstdoutfile, ret);
			goto fail;
		}

		psiw->dwFlags |= STARTF_USESTDHANDLES;
	}

	if (popt->m_stdouutfile != NULL && psiw->hStdOutput == INVALID_HANDLE_VALUE) {
		DEBUG_INFO("m_stdouutfile [%s]", popt->m_stdouutfile);
		ret = AnsiToUnicode(popt->m_stdouutfile, &pwfname, &wfnamesize);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		psiw->hStdOutput = CreateFileW(pwfname, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
		if (psiw->hStdOutput == INVALID_HANDLE_VALUE) {
			GETERRNO(ret);
			error_out("opne (%s) error(%d)", popt->m_stdouutfile, ret);
			goto fail;
		}

		psiw->dwFlags |= STARTF_USESTDHANDLES;
	}

	if (popt->m_appendstderrfile != NULL) {
		DEBUG_INFO("m_appendstderrfile [%s]", popt->m_appendstderrfile);
		ret = AnsiToUnicode(popt->m_appendstderrfile, &pwfname, &wfnamesize);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		psiw->hStdError = CreateFileW(pwfname, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
		if (psiw->hStdError == INVALID_HANDLE_VALUE) {
			GETERRNO(ret);
			error_out("open (%s) error(%d)", popt->m_appendstderrfile, ret);
			goto fail;
		}
	}

	if (popt->m_stderrfile != NULL && psiw->hStdError == INVALID_HANDLE_VALUE) {
		DEBUG_INFO("m_stderrfile [%s]", popt->m_stderrfile);
		ret = AnsiToUnicode(popt->m_stderrfile, &pwfname, &wfnamesize);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}

		psiw->hStdError = CreateFileW(pwfname, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
		if (psiw->hStdError == INVALID_HANDLE_VALUE) {
			GETERRNO(ret);
			error_out("opne (%s) error(%d)", popt->m_stderrfile, ret);
			goto fail;
			goto fail;
		}

		psiw->dwFlags |= STARTF_USESTDHANDLES;
	}

	if (popt->m_siforceonfeedback) {
		DEBUG_INFO("m_siforceonfeedback");
		psiw->dwFlags |= STARTF_FORCEONFEEDBACK;
	}

	if (popt->m_siforceofffeedback) {
		DEBUG_INFO("m_siforceofffeedback");
		psiw->dwFlags |= STARTF_FORCEOFFFEEDBACK;
	}

	if (popt->m_sipreventpinning) {
		DEBUG_INFO("m_sipreventpinning");
		psiw->dwFlags |= STARTF_PREVENTPINNING;
	}

	if (popt->m_sirunfullscreen) {
		DEBUG_INFO("m_sirunfullscreen");
		psiw->dwFlags |= STARTF_RUNFULLSCREEN;
	}

	if (popt->m_sititleisappid) {
		DEBUG_INFO("m_sititleisappid");
		psiw->dwFlags |= STARTF_TITLEISAPPID;
	}

	if (popt->m_sititleisalinkname) {
		DEBUG_INFO("m_sititleisalinkname");
		psiw->dwFlags |= STARTF_TITLEISLINKNAME;
	}

	if (popt->m_siuntrustedsource) {
		DEBUG_INFO("m_siuntrustedsource");
		psiw->dwFlags |= STARTF_UNTRUSTEDSOURCE;
	}

	if (popt->m_xcountchars != 0 ||
	        popt->m_ycountchars != 0) {
		DEBUG_INFO("m_xcountchars [%d] m_ycountchars [%d]",
		             popt->m_xcountchars, popt->m_ycountchars);
		psiw->dwFlags |= STARTF_USECOUNTCHARS;
		psiw->dwXCountChars = (DWORD)popt->m_xcountchars;
		psiw->dwYCountChars = (DWORD)popt->m_ycountchars;
	}

	if (popt->m_forered || popt->m_foreblue || popt->m_foregreen || popt->m_foreintensity
	        || popt->m_backred || popt->m_backblue || popt->m_foregreen || popt->m_foreintensity) {
		int attradded=0;

		psiw->dwFlags |= STARTF_USEFILLATTRIBUTE;
		psiw->dwFillAttribute = 0;
		DEBUG_START("fillattributes ");
		if (popt->m_forered) {
			DEBUG_STRAIGHT("FOREGROUND_RED");
			attradded ++;
			psiw->dwFillAttribute |= FOREGROUND_RED;
		}
		if (popt->m_foreblue) {
			if (attradded > 0) {
				DEBUG_STRAIGHT("|");
			}
			DEBUG_STRAIGHT("FOREGROUND_BLUE");
			attradded ++;
			psiw->dwFillAttribute |= FOREGROUND_BLUE;
		}
		if (popt->m_foregreen) {
			if (attradded > 0) {
				DEBUG_STRAIGHT("|");
			}		
			DEBUG_STRAIGHT("FOREGROUND_GREEN");
			attradded ++;
			psiw->dwFillAttribute |= FOREGROUND_GREEN;
		}
		if (popt->m_foreintensity) {
			if (attradded > 0) {
				DEBUG_STRAIGHT("|");
			}
			DEBUG_STRAIGHT("FOREGROUND_INTENSITY");
			attradded ++;
			psiw->dwFillAttribute |= FOREGROUND_INTENSITY;
		}
		if (popt->m_backred) {
			if (attradded > 0) {
				DEBUG_STRAIGHT("|");
			}
			DEBUG_STRAIGHT("BACKGROUND_RED");
			attradded ++;
			psiw->dwFillAttribute |= BACKGROUND_RED;
		}
		if (popt->m_backblue) {
			if (attradded > 0) {
				DEBUG_STRAIGHT("|");
			}
			DEBUG_STRAIGHT("BACKGROUND_BLUE");
			attradded ++;
			psiw->dwFillAttribute |= BACKGROUND_BLUE;
		}
		if (popt->m_backgreen) {
			if (attradded > 0) {
				DEBUG_STRAIGHT("|");
			}
			DEBUG_STRAIGHT("BACKGROUND_GREEN");
			attradded ++;
			psiw->dwFillAttribute |= BACKGROUND_GREEN;
		}
		if (popt->m_backintensity) {
			if (attradded > 0) {
				DEBUG_STRAIGHT("|");
			}
			DEBUG_STRAIGHT("BACKGROUND_INTENSITY");
			attradded ++;
			psiw->dwFillAttribute |= BACKGROUND_INTENSITY;
		}
		DEBUG_END();
	}

	if (popt->m_siusehotkey) {
		DEBUG_INFO("m_siusehotkey");
		psiw->dwFlags |= STARTF_USEHOTKEY;
	}

	if (popt->m_xpos != 0 || popt->m_ypos != 0) {
		DEBUG_INFO("m_xpos [%d] m_ypos [%d]",popt->m_xpos,popt->m_ypos);
		psiw->dwFlags |= STARTF_USEPOSITION;
		psiw->dwX = (DWORD)popt->m_xpos;
		psiw->dwY = (DWORD)popt->m_ypos;
	}

	if (popt->m_xwindowcmd != NULL) {
		psiw->dwFlags |= STARTF_USESHOWWINDOW;
		psiw->wShowWindow = get_show_window(popt->m_xwindowcmd);
		DEBUG_INFO("(%s) 0x%lx",popt->m_xwindowcmd,psiw->wShowWindow);
		if (psiw->wShowWindow == SW_ERROR_CODE) {
			ret = -ERROR_INVALID_PARAMETER;
			error_out("(%s) not valid show window", popt->m_xwindowcmd);
			goto fail;
		}
	}

	if (popt->m_xsize != 0 || popt->m_ysize != 0) {
		DEBUG_INFO("m_xsize [%d] m_ysize [%d]",popt->m_xsize,popt->m_ysize);
		psiw->dwFlags |= STARTF_USESIZE;
		psiw->dwXSize = (DWORD)popt->m_xsize;
		psiw->dwYSize = (DWORD)popt->m_ysize;
	}



	ppi = (LPPROCESS_INFORMATION)malloc(sizeof(PROCESS_INFORMATION));
	if (ppi == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(ppi, 0, sizeof(*ppi));

	DEBUG_INFO("logonflags 0x%08x createflags 0x%08x", logonflags, createflags);
	DEBUG_BUFFER_FMT(psiw, (int)siwsize, "startupinfo");

	bret = CreateProcessWithLogonW(pwusername,
	                               pwdomain,
	                               pwpassword,
	                               logonflags,
	                               pwexename,
	                               pwcmdline,
	                               createflags,
	                               pwenvs,
	                               pwcurdir,
	                               psiw,
	                               ppi);
	if (!bret) {
		GETERRNO(ret);
		error_out("create error(%d)", ret);
		goto fail;
	}

	pid = (int) ppi->dwProcessId;

	if (pthreadattr) {
		DeleteProcThreadAttributeList(pthreadattr);
	}
	pthreadattr = NULL;
	__dealloc_thread_attribute(&pattr);
	if (psiw) {
		i = 1;
		AnsiToUnicode(NULL, &(psiw->lpTitle), &i);
		i = 1;
		AnsiToUnicode(NULL, &(psiw->lpDesktop), &i);

		if (psiw->hStdInput != INVALID_HANDLE_VALUE) {
			bret = CloseHandle(psiw->hStdInput);
			if (!bret) {
				GETERRNO(res);
				error_out("close input error(%d)", res);
			}
		}
		psiw->hStdInput = INVALID_HANDLE_VALUE;

		if (psiw->hStdOutput != INVALID_HANDLE_VALUE) {
			bret = CloseHandle(psiw->hStdOutput);
			if (!bret) {
				GETERRNO(res);
				error_out("close output error(%d)", res);
			}
		}
		psiw->hStdOutput = INVALID_HANDLE_VALUE;

		if (psiw->hStdError != INVALID_HANDLE_VALUE) {
			bret = CloseHandle(psiw->hStdError);
			if (!bret) {
				GETERRNO(res);
				error_out("close stderr error(%d)", res);
			}
		}
		psiw->hStdError = INVALID_HANDLE_VALUE;

		free(psiw);
	}
	psiw = NULL;
	if (ppi) {
		free(ppi);
	}
	ppi = NULL;
	snprintf_safe(&pcmdline, &cmdlinesize, NULL);
	AnsiToUnicode(NULL, &pwfname, &wfnamesize);
	AnsiToUnicode(NULL, &pwcmdline, &wcmdlinesize);
	AnsiToUnicode(NULL, &pwcurdir, &curdirsize);
	AnsiToUnicode(NULL, &pwexename, &exenamesize);
	AnsiToUnicode(NULL, &pwusername, &usernamesize);
	AnsiToUnicode(NULL, &pwpassword, &passwordsize);
	AnsiToUnicode(NULL, &pwdomain, &domainsize);
	return pid;
fail:
	if (pthreadattr) {
		DeleteProcThreadAttributeList(pthreadattr);
	}
	pthreadattr = NULL;
	__dealloc_thread_attribute(&pattr);
	if (psiw) {
		i = 1;
		AnsiToUnicode(NULL, &(psiw->lpTitle), &i);
		i = 1;
		AnsiToUnicode(NULL, &(psiw->lpDesktop), &i);

		if (psiw->hStdInput != INVALID_HANDLE_VALUE) {
			bret = CloseHandle(psiw->hStdInput);
			if (!bret) {
				GETERRNO(res);
				error_out("close input error(%d)", res);
			}
		}
		psiw->hStdInput = INVALID_HANDLE_VALUE;

		if (psiw->hStdOutput != INVALID_HANDLE_VALUE) {
			bret = CloseHandle(psiw->hStdOutput);
			if (!bret) {
				GETERRNO(res);
				error_out("close output error(%d)", res);
			}
		}
		psiw->hStdOutput = INVALID_HANDLE_VALUE;

		if (psiw->hStdError != INVALID_HANDLE_VALUE) {
			bret = CloseHandle(psiw->hStdError);
			if (!bret) {
				GETERRNO(res);
				error_out("close stderr error(%d)", res);
			}
		}
		psiw->hStdError = INVALID_HANDLE_VALUE;

		free(psiw);
	}
	psiw = NULL;
	if (ppi) {
		free(ppi);
	}
	ppi = NULL;
	snprintf_safe(&pcmdline, &cmdlinesize, NULL);
	AnsiToUnicode(NULL, &pwfname, &wfnamesize);
	AnsiToUnicode(NULL, &pwcmdline, &wcmdlinesize);
	AnsiToUnicode(NULL, &pwcurdir, &curdirsize);
	AnsiToUnicode(NULL, &pwexename, &exenamesize);
	AnsiToUnicode(NULL, &pwusername, &usernamesize);
	AnsiToUnicode(NULL, &pwpassword, &passwordsize);
	AnsiToUnicode(NULL, &pwdomain, &domainsize);
	return ret;

}


int _tmain(int argc, TCHAR* argv[])
{
	char** args = NULL;
	int ret;
	int loglvl = BASE_LOG_ERROR;
	args_options_t argsoption;
	pextargs_state_t pextstate = NULL;

	memset(&argsoption, 0, sizeof(argsoption));

	args = copy_args(argc, argv);
	if (args == NULL) {
		GETERRNO(ret);
		error_out("can not get args %d", ret);
		goto out;
	}
	ret = EXTARGS_PARSE(argc, args, &argsoption, pextstate);
	//ret = parse_param_smart(argc, args, st_main_cmds, &argsoption, &pextstate, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "could not parse error(%d)", ret);
		goto out;
	}

	if (argsoption.m_version != 0) {
		fprintf(stdout,"lsrunas version %s\n",__LSRUNAS_VERSION__);
		ret = 0;
		goto out;
	}

	if (argsoption.m_verbose <= 0) {
		loglvl = BASE_LOG_ERROR;
	} else if (argsoption.m_verbose == 1) {
		loglvl = BASE_LOG_WARN;
	} else if (argsoption.m_verbose == 2) {
		loglvl = BASE_LOG_INFO;
	} else if (argsoption.m_verbose == 3) {
		loglvl = BASE_LOG_DEBUG;
	} else if (argsoption.m_verbose >= 4) {
		loglvl = BASE_LOG_TRACE;
	}

	ret = INIT_LOG(loglvl);
	if (ret < 0) {
		GETERRNO(ret);
		goto out;
	}


	ret = login_user_create_process(argc, args, pextstate, &argsoption);
	if (ret < 0) {
		goto out;
	}
	fprintf(stdout, "create (%d)\n", ret);
	ret = 0;
out:
	free_args(&args);
	free_extargs_state(&pextstate);
	release_extargs_output(&argsoption);
	extargs_deinit();
	FINI_LOG();
	return ret;
}