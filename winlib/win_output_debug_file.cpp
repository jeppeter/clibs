
class DebugOutIO
{
public:
	DebugOutIO();
	virtual ~DebugOutIO()=0;
	virtual int write_log(int level,char* locstr,char* timestr,char* tagstr, char* msgstr)=0;
	virtual int write_buffer_log(int level, char* locstr,char* timestr,char* tagstr,char* msgstr, void* pbuffer,int buflen)=0;
	virtual void flush()=0;
};

class DebugOutStderr : public DebugOutIO
{
public:
	DebugOutStderr();
	virtual ~DebugOutStderr();
	virtual int write_log(int level,char* locstr,char* timestr,char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr,char* timestr,char* tagstr,char* msgstr, void* pbuffer,int buflen);
	virtual void flush();
};




class DebugOutBackground : public DebugOutIO
{
public:
	DebugOutBackground();
	virtual ~DebugOutBackground();
	virtual int write_log(int level,char* locstr,char* timestr,char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr,char* timestr,char* tagstr,char* msgstr, void* pbuffer,int buflen);
	virtual void flush();
};


class DebugOutFileTrunc : public DebugOutIO
{
public:
	DebugOutFileTrunc();
	virtual ~DebugOutFileTrunc();
	virtual int write_log(int level,char* locstr,char* timestr,char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr,char* timestr,char* tagstr,char* msgstr, void* pbuffer,int buflen);
	virtual void flush();
};


class DebugOutFileAppend : public DebugOutIO
{
public:
	DebugOutFileAppend();
	virtual ~DebugOutFileAppend();
	virtual int write_log(int level,char* locstr,char* timestr,char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr,char* timestr,char* tagstr,char* msgstr, void* pbuffer,int buflen);
	virtual void flush();
};


class DebugOutFileRotate : public DebugOutIO
{
public:
	DebugOutFileRotate();
	virtual ~DebugOutFileRotate();
	virtual int write_log(int level,char* locstr,char* timestr,char* tagstr, char* msgstr);
	virtual int write_buffer_log(int level, char* locstr,char* timestr,char* tagstr,char* msgstr, void* pbuffer,int buflen);
	virtual void flush();
};
