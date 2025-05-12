#ifndef __UX_OUTPUT_DEBUG_CFG_H_34271879EF5F24AB1FD4CF1BDFD9DC92__
#define __UX_OUTPUT_DEBUG_CFG_H_34271879EF5F24AB1FD4CF1BDFD9DC92__

#include <ux_err.h>


#define  UXLIB_OUTPUT_LOCATION             0x1
#define  UXLIB_OUTPUT_TIMESTAMP            0x2
#define  UXLIB_OUTPUT_LEVEL                0x4
#define  UXLIB_OUTPUT_MSG                  0x8

#define  UXLIB_DEBUGOUT_FILE_STDERR                 0x1
#define  UXLIB_DEBUGOUT_FILE_APPEND                 0x2
#define  UXLIB_DEBUGOUT_FILE_TRUNC                  0x3
#define  UXLIB_DEBUGOUT_FILE_BACKGROUND             0x4
#define  UXLIB_DEBUGOUT_FILE_ROTATE                 0x5
#define  UXLIB_DEBUGOUT_FILE_MASK                   0xff

#define  UXLIB_OUTPUT_ALL_MASK             (UXLIB_OUTPUT_LOCATION | UXLIB_OUTPUT_TIMESTAMP |UXLIB_OUTPUT_LEVEL |UXLIB_OUTPUT_MSG)


#include <vector>


class OutfileCfg
{
public:
	OutfileCfg();
	~OutfileCfg();
	int set_file_type(const char* fname,int type,uint64_t size,int maxfiles);
	int set_level(int level);
	int set_format(int fmtflag);
	int get_file_type(const char*& fname, int& type, uint64_t& size, int& maxfiles);
	int get_level();
	int get_format();
	OutfileCfg* clone();
private:
	char* m_fname;
	int m_level;
	int m_fmtflag;
	int m_maxfiles;
	uint64_t m_size;
	int m_type;
};

class OutputCfg
{
public:
	OutputCfg();
	~OutputCfg();
	int insert_config(OutfileCfg& cfg);
	OutfileCfg* get_config(int idx);
	void clear_configs();
private:
	std::vector<OutfileCfg*> *m_cfgs;
};



#ifdef __cplusplus
extern "C" {
#endif


int init_log_ex(OutputCfg* pcfgs);

#ifdef __cplusplus
};
#endif


#endif /* __UX_OUTPUT_DEBUG_CFG_H_34271879EF5F24AB1FD4CF1BDFD9DC92__ */
