#ifndef __LOG_FILE_H_AFCC08925663B65130F44137986A5251__
#define __LOG_FILE_H_AFCC08925663B65130F44137986A5251__


#include <log_inter.h>
#pragma warning(push)
#pragma warning(disable:4514)
#include <vector>
#pragma warning(pop)


class LogFileCallback : public LogCallback
{
public:
	LogFileCallback(void* pevmain,char* filename,int appendmode=0);
	virtual ~LogFileCallback();
	virtual int handle_log_buffer(char* pbuf,int buflen);
	virtual int start();

private:
	int __insert_write_handle();
	void __remove_write_handle();
	void __free_write_buf();
	int __pick_write_buf();
	int __write_buffer();
	static void __log_file_write(HANDLE hd,libev_enum_event_t evt,void* pevmain, void* args);
	int __log_file_impl();
	int __reopen_file();
	int __start_write();
	int __alloc_vecs();
	void __free_vecs();
	void __close_file();
private:
	void* m_pevmain;
	char* m_name;
	std::vector<char*> *m_pwritebufs;
	std::vector<int> *m_pwritelen;
	char* m_curbuf;
	int m_curlen;
	int m_cursize;
	HANDLE m_hfile;
	OVERLAPPED m_ov;
	int m_inserted;
	int m_appended;
	int m_isoverlapped;
};


#endif /* __LOG_FILE_H_AFCC08925663B65130F44137986A5251__ */
