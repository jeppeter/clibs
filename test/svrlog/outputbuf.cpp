#include <win_thread.h>
#include <vector>

typedef struct __output_buf {
	CRITICAL_SECTION m_cs;
	std::vector<char*> *m_pbufs;
	std::vector<int> *m_cnts;
	int m_global;
	void* m_thread;
} output_buf_t,*poutput_buf_t;



void __free_output_buf(poutput_buf_t* ppbuf)
{
	
}

void* create_output_buf(int global)
{
	poutput_buf_t pbuf = NULL;

}