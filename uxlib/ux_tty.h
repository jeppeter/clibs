#ifndef __UX_TTY_H_00AFC500DF1329098E65B69D3F096D67__
#define __UX_TTY_H_00AFC500DF1329098E65B69D3F096D67__


#include <ux_err.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define  TTY_SET_SPEED     1   /*void* is int* */
#define  TTY_SET_XONXOFF   2   /*void* is int* */
#define  TTY_SET_SIZE      3   /*void* is int* */

void free_tty(void** pptty);
void* open_tty(const char* ttyname);
int set_tty_config(void* ptty,int flag,void* value);
int read_tty_nonblock(void* ptty,uint8_t* pbuf, int bufsize);
int write_tty_nonblock(void* ptty,uint8_t* pbuf, int bufsize);
int get_tty_read_handle(void* ptty);
int get_tty_write_handle(void* ptty);
int complete_tty_read(void* ptty);
int complete_tty_write(void* ptty);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_TTY_H_00AFC500DF1329098E65B69D3F096D67__ */
