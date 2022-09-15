#ifndef __UX_TTY_H_00AFC500DF1329098E65B69D3F096D67__
#define __UX_TTY_H_00AFC500DF1329098E65B69D3F096D67__


#include <ux_err.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define  TTY_SET_SPEED     1   /*void* is int* */
#define  TTY_SET_SIZE      2   /*void* is int* */
#define  TTY_SET_IFLAGS    3   /*to set IFLAGS unsigned int* */
#define  TTY_CLEAR_IFLAGS  4   /*to clear IFLAGS unsigned int* */
#define  TTY_SET_OFLAGS    5   /*to set OFLAGS unsigned int* */
#define  TTY_CLEAR_OFLAGS  6   /*to clear OFLAGS unsigned int* */
#define  TTY_SET_CFLAGS    7   //
#define  TTY_CLEAR_CFLAGS  8
#define  TTY_SET_LFLAGS    9
#define  TTY_CLEAR_LFLAGS  10
#define  TTY_SET_CLINE     11  /*value unsigned char*/
#define  TTY_SET_CC        12  /*to set ctrl[2] ctrl[0] == offset ctrl[1] == value */

#define  TTY_SET_RAW       13  /*set raw mode*/



void free_tty(void** pptty);
void* open_tty(const char* ttyname,int maxflush);
int prepare_tty_config(void* ptty,int flag,void* value);
int commit_tty_config(void* ptty);
int read_tty_nonblock(void* ptty,uint8_t* pbuf, int bufsize);
int write_tty_nonblock(void* ptty,uint8_t* pbuf, int bufsize);
int get_tty_read_handle(void* ptty);
int get_tty_write_handle(void* ptty);
int complete_tty_read(void* ptty);
int complete_tty_write(void* ptty);
int get_tty_config_direct(void* ptty, void** ppcfg,int* psize);
int set_tty_config_direct(void* ptty, void* pcfg,int size);


#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_TTY_H_00AFC500DF1329098E65B69D3F096D67__ */
