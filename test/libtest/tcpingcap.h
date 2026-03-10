#ifndef __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__
#define __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__

#include <vector>

class TcpingCap 
{
public:
	TcpingCap(const char* ipportstr,int timeout,int nextout,int times);
	virtual ~TcpingCap();
	int set_verbose(int verbose);
	int get_expire();
	int get_next_expire();
	int start();
	int send_ping();
	int get_result(int idx,uint64_t& val);
	int get_mean_result(uint64_t& val);
	double get_succ_ratio();

private:
	void _print_result(const char* file, int lineno,uint64_t val);
	int _get_tcping_type();
	void __release_resource();
	int __start_alloc();
	int __parse_ipstr();
	void __free_ipstr();

private:
	void* m_sock;
	char* m_ip;
	int m_port;
	char* m_ipstr;
	int m_verbose;
	int m_tcpingtype;
	uint64_t m_expire;
	uint64_t m_nextstart;
	int m_times;
	int m_timeout;
	int m_nexttime;
	std::vector<uint64_t> *m_tcpingval;
};


#endif /* __TCPINGCAP_H_9B11C11FCC12148352947EB3C132CE86__ */
