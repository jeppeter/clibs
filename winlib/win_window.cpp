#include <win_window.h>


typedef struct __win_enum_callback {
	win_enum_func_t m_func;
	void* m_param;
} win_enum_callback_t,*pwin_enum_callback_t;

BOOL CALLBACK __inner_get_win_callback(HWND hwnd,LPARAM param)
{
	int ret;
	pwin_enum_callback_t pcallback = (pwin_enum_callback_t) param;
	if (pcallback == NULL || pcallback->m_func == NULL) {
		return FALSE;
	}
	ret = pcallback->m_func(hwnd,pcallback->m_param);
	if (ret < 0) {
		return FALSE;
	}
	return TRUE;
}

int get_win_handle(win_enum_func_t pcallback,void* param)
{
	int ret;
	BOOL bret;
	pwin_enum_callback_t pcallarg=NULL;

	if (pcallback == NULL) {
		ret = -ERROR_INVALID_PARAMETER;
		SETERRNO(-ret);
		return ret;
	}

	pcallarg = (pwin_enum_callback_t) malloc(sizeof(*pcallarg));
	if (pcallarg == NULL) {
		GETERRNO(ret);
		ERROR_INFO("can not malloc[%d] error[%d]",sizeof(*pcallarg),ret);
		goto out;
	}
	memset(pcallarg,0,sizeof(*pcallarg));
	pcallarg->m_func = pcallback;
	pcallarg->m_param = param;

	bret = EnumWindows(__inner_get_win_callback,pcallarg);
	if (!bret) {
		GETERRNO(ret);
		ERROR_INFO("enum window error[%d]",ret);
		goto out;
	}

	ret = 0;
out:
	if (pcallarg) {
		free(pcallarg);
	}
	pcallarg = NULL;
	SETERRNO(-ret);
	return ret;
}

typedef struct __win_class {
	char* m_classname;
	int m_hwndsize;
	int m_hwndnum;
	HWND *m_phwnd;
} win_class_t,*pwin_class_t;

int __get_window_type(HWND hwnd,void* param)
{
	pwin_class_t pwinclass = (pwin_class_t) param;
	int ok=0;
	int ret;
	TCHAR* tclassname=NULL;
	int tclasnamesize=0;
	int tclasslen=0;
	char* clsname=NULL;
	int clsnamesize=0;
	HWND* pwndtmp=NULL;
	int wndsize=0;
	if (pwinclass == NULL ) {
		return -1;
	}

	if (pwinclass->m_classname == NULL || 
		strlen(pwinclass->m_classname) == 0 ) {
		ok = 1;
	} else {
		while(1) {
			if (tclassname == NULL) {
				if (tclasslen == 0) {
					tclasslen = 1;
				}
				tclasnamesize = tclasslen * sizeof(TCHAR);
				tclassname = (TCHAR*) malloc((size_t)tclasnamesize);
				if (tclassname == NULL) {
					GETERRNO(ret);
					ERROR_INFO("can not malloc[%d] error[%d]",tclasnamesize,ret);
					goto out;
				}
			}
			ret = GetClassName(hwnd,tclassname,tclasslen - 1);
			if (ret < 0) {
				GETERRNO(ret);
				ERROR_INFO("get [0x%x] return value %d",hwnd,ret);
				goto out;
			}
			break;
		}

		/*now get the class*/
		ret = TcharToAnsi(tclassname,&clsname,&clsnamesize);
		if (ret < 0) {
			GETERRNO(ret);
			goto out;
		}

		if (_strnicmp(clsname,pwinclass->m_classname) == 0) {
			ok = 1;
		}
	}

	if (ok) {

		if (pwinclass->m_hwndnum >= pwinclass->m_hwndsize) {
			wndsize = pwinclass->m_hwndsize;
			wndsize <<= 1;
			if (wndsize == 0) {
				wndsize = 4;
			}

			pwndtmp = (HWND*)malloc(sizeof(HWND)*wndsize);
			if (pwndtmp == NULL) {
				GETERRNO(ret);
				ERROR_INFO("can not malloc[%d] error[%d]",sizeof(HWND)*wndsize,ret);
				goto out;
			}

		}

		ret = 1;
	} else {
		ret = 0;
	}


out:
	TcharToAnsi(NULL,&clsname,&clsnamesize);
	if (tclassname) {
		free(tclassname);
	}
	tclassname = NULL;
	SETERRNO(-ret);
	return ret;
}

int get_window_handle(const char* typeclass,HWND *ppwnd[],int *pwinsize)
{

}