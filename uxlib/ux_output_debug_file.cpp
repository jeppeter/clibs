class DebugOutIO
{
public:
	virtual ~DebugOutIO() {};
	virtual int write_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr) = 0;
	virtual int write_buffer_log(int level, char* locstr, char* timestr, const char* tagstr, char* msgstr, void* pbuffer, int buflen) = 0;
	virtual int write_buffer(char* pbuf, int buflen) = 0;
	virtual void flush() = 0;
	virtual int set_cfg(OutfileCfg* pcfg) = 0;
	virtual int set_level(int level) = 0;
};
