#include <log_console.h>
#include <win_err.h>

LogConsole::LogConsole(void* pevmain,int stderrmode)
{
	this->m_pevmain = pevmain;
	this->m_fp = stderr;
	if (stderrmode == 0) {
		this->m_fp = stdout;
	}
}

LogConsole::~LogConsole()
{
	this->m_pevmain = NULL;
	this->m_fp = NULL;
}

int LogConsole::start()
{
	return 0;
}

int LogConsole::handle_log_buffer(char* pbuf,int buflen)
{
	int ret;
	char* pwbuf=NULL;
	if (this->m_fp == NULL) {
		return 0;
	}

	pwbuf = (char*)malloc((size_t)(buflen + 1));
	if (pwbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(pwbuf, 0, (size_t)(buflen + 1));
	memcpy(pwbuf , pbuf, (size_t)buflen);
	fprintf(this->m_fp, "%s", pwbuf);

	if (pwbuf) {
		free(pwbuf);
	}
	pwbuf = NULL;
	return 0;
fail:
	if (pwbuf) {
		free(pwbuf);
	}
	pwbuf = NULL;
	SETERRNO(ret);
	return ret;
}