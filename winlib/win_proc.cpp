#include <win_proc.h>


int get_pid_name(int pid,char** ppname,int *namesize)
{
	char* tempfile=NULL;
	int tempsize=0;
	int ret = 0;
	int namelen = 0;

	if (pid < 0) {
		if (ppname && *ppname != NULL) {
			free(*ppname);
		}
		if (ppname) {
			*ppname = NULL;
		}
		if (namesize) {
			*namesize = 0;
		}
		return 0;
	}

	ret = mktempfile_safe()

	return namelen;
fail:
	mktempfile_safe(NULL,&tempfile,&tempsize);
	SETERRNO(-ret);
	return ret;
}