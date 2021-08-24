#ifndef __WIN_OUTPUT_DEBUG_CFG_H_34271879EF5F24AB1FD4CF1BDFD9DC92__
#define __WIN_OUTPUT_DEBUG_CFG_H_34271879EF5F24AB1FD4CF1BDFD9DC92__

#include <win_types.h>

#define  WINLIB_OUTPUT_LOCATION             0x1
#define  WINLIB_OUTPUT_TIMESTAMP            0x2
#define  WINLIB_OUTPUT_LEVEL                0x4
#define  WINLIB_OUTPUT_MSG                  0x8

#define  WINLIB_FILE_STDERR                 0x1
#define  WINLIB_FILE_APPEND                 0x2
#define  WINLIB_FILE_TRUNC                  0x3
#define  WINLIB_FILE_BACKGROUND             0x4
#define  WINLIB_FILE_MASK                   0xff
#define  WINLIB_FILE_ROTATE                 0x100

#define  WINLIB_OUTPUT_ALL_MASK             (WINLIB_OUTPUT_LOCATION | WINLIB_OUTPUT_TIMESTAMP |WINLIB_OUTPUT_LEVEL |WINLIB_OUTPUT_MSG)

class OutfileCfg
{
public:
	OutfileCfg();
	~OutfileCfg();
	int set_file_type(const char* fname,int type,uint64_t size,int maxfiles);
	int set_level(int level);
	int set_format(int fmtflag);
private:
	char* m_fname;
	int m_level;
	int m_fmtflag;
	int m_maxfiles;
	uint64_t m_size;
	int m_type;
};

#endif /* __WIN_OUTPUT_DEBUG_CFG_H_34271879EF5F24AB1FD4CF1BDFD9DC92__ */
