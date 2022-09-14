#include <ux_tty.h>
#include <ux_output_debug.h>

#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



#define  TTY_DATA_MAGIC   0x430129de

typedef struct __tty_data_priv {
	uint32_t m_magic;
	int m_ttyfd;
	char* m_ttyname;
	int m_inrd;
	int m_inwr;
	struct termios m_ttycfg;
	int m_bauderate;
	uint8_t* m_prdptr;
	int m_rdleft;
	uint8_t* m_pwrptr;
	int m_wrleft;
} tty_data_priv_t, *ptty_data_priv_t;

void free_tty(void** pptty)
{
	ptty_data_priv_t ptty = NULL;
	if (pptty && *pptty) {
		ptty = (ptty_data_priv_t) * pptty;
		ASSERT_IF(ptty->m_magic == TTY_DATA_MAGIC);
		if (ptty->m_ttyfd >= 0) {
			close(ptty->m_ttyfd);
		}
		ptty->m_ttyfd = -1;
		if (ptty->m_ttyname) {
			free(ptty->m_ttyname);
		}
		ptty->m_ttyname = NULL;
		ptty->m_bauderate = 0;
		memset(&(ptty->m_ttycfg), 0, sizeof(ptty->m_ttycfg));
		ptty->m_inrd = 0;
		ptty->m_inwr = 0;
		ptty->m_prdptr = NULL;
		ptty->m_rdleft = 0;
		ptty->m_pwrptr = NULL;
		ptty->m_wrleft = 0;
		free(ptty);
		*pptty = NULL;
	}
}

void* open_tty(const char* ttyname)
{
	ptty_data_priv_t ptty = NULL;
	int ret;
	int flags;


	ptty = (ptty_data_priv_t)malloc(sizeof(*ptty));
	if (ptty == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	memset(ptty, 0, sizeof(*ptty));
	ptty->m_magic = TTY_DATA_MAGIC;
	ptty->m_ttyfd = -1;

	ptty->m_ttyname = strdup(ttyname);
	if (ptty->m_ttyname == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	/*now open the fd*/
	ptty->m_ttyfd = open(ptty->m_ttyname, O_RDWR);
	if (ptty->m_ttyfd < 0) {
		GETERRNO(ret);
		ERROR_INFO("can not open [%s] error[%d]", ptty->m_ttyname, ret);
		goto fail;
	}

	SETERRNO(0);
	flags = fcntl(ptty->m_ttyfd, F_GETFL);
	if (flags == -1) {
		GETERRNO_DIRECT(ret);
		if (ret != 0) {
			ERROR_INFO("get fcntl [%s] error[%d]", ptty->m_ttyname, ret);
			goto fail;
		}
	}

	ret = fcntl(ptty->m_ttyfd, F_SETFL, O_NONBLOCK | flags);
	if (ret < 0) {
		GETERRNO(ret);
		ERROR_INFO("set nonblock [%s] error[%d]", ptty->m_ttyname, ret);
		goto fail;
	}

	ptty->m_inrd = 0;
	ptty->m_inwr = 0;

	ptty->m_bauderate = 115200;

	ret = tcgetattr(ptty->m_ttyfd, &(ptty->m_ttycfg));
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not TCGETS2 [%s] error[%d]", ptty->m_ttyname, ret);
		goto fail;
	}

	ptty->m_ttycfg.c_cflag &= ~CSTOPB;

	ptty->m_ttycfg.c_cflag &= ~CSIZE;
	ptty->m_ttycfg.c_cflag |= CS8;

	ptty->m_ttycfg.c_cflag &= ~CRTSCTS;

	ptty->m_ttycfg.c_iflag &= ~(IXON | IXOFF | IXANY);
	ptty->m_ttycfg.c_iflag |= (IXOFF | IXON);

	cfsetspeed(&(ptty->m_ttycfg), B115200);

	ret = tcsetattr(ptty->m_ttyfd, TCSANOW, &(ptty->m_ttycfg));
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not TCSETS2 [%s] error[%d]", ptty->m_ttyname, ret);
		goto fail;
	}

	return (void*) ptty;
fail:
	free_tty((void**)&ptty);
	SETERRNO(ret);
	return NULL;
}

int set_tty_config(void* ptty1, int flag, void* value)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	int ret;
	int *iptr, ival;
	struct termios tycfg;
	int setbauderate = 0;
	int bauderate = 0;
	if (ptty->m_magic != TTY_DATA_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	switch (flag) {
	case TTY_SET_SPEED:
		if (value == NULL) {
			ret = -EINVAL;
			goto fail;
		}
		iptr = (int*) value;
		ival = *iptr;
		memcpy(&tycfg, &(ptty->m_ttycfg), sizeof(tycfg));
		switch (ival) {
		case 0:
			cfsetspeed(&tycfg, B0);
			break;
		case 50:
			cfsetspeed(&tycfg, B50);
			break;
		case 75:
			cfsetspeed(&tycfg, B75);
			break;
		case 110:
			cfsetspeed(&tycfg, B110);
			break;
		case 134:
			cfsetspeed(&tycfg, B134);
			break;
		case 150:
			cfsetspeed(&tycfg, B150);
			break;
		case 200:
			cfsetspeed(&tycfg, B200);
			break;
		case 300:
			cfsetspeed(&tycfg, B300);
			break;
		case 600:
			cfsetspeed(&tycfg, B600);
			break;
		case 1200:
			cfsetspeed(&tycfg, B1200);
			break;
		case 1800:
			cfsetspeed(&tycfg, B1800);
			break;
		case 2400:
			cfsetspeed(&tycfg, B2400);
			break;
		case 4800:
			cfsetspeed(&tycfg, B4800);
			break;
		case 9600:
			cfsetspeed(&tycfg, B9600);
			break;
		case 19200:
			cfsetspeed(&tycfg, B19200);
			break;
		case 38400:
			cfsetspeed(&tycfg, B38400);
			break;
		case 57600:
			cfsetspeed(&tycfg, B57600);
			break;
		case 115200:
			cfsetspeed(&tycfg, B115200);
			break;
		case 230400:
			cfsetspeed(&tycfg, B230400);
			break;
		case 460800:
			cfsetspeed(&tycfg, B460800);
			break;
		default:
			ret = -EINVAL;
			ERROR_INFO("set speed for [%s] not valid [%d]", ptty->m_ttyname, ival);
			goto fail;
		}
		setbauderate = 1;
		bauderate = ival;
		break;
	case TTY_SET_XONXOFF:
		iptr = (int*) value;
		ival = *iptr;
		memcpy(&tycfg, &(ptty->m_ttycfg), sizeof(tycfg));
		tycfg.c_iflag &= ~(IXON | IXOFF | IXANY);
		if (ival != 0) {
			tycfg.c_iflag |= (IXON | IXOFF);
		}
		break;
	case TTY_SET_SIZE:
		iptr = (int*) value;
		ival = *iptr;
		memcpy(&tycfg, &(ptty->m_ttycfg), sizeof(tycfg));
		tycfg.c_cflag &= ~CSIZE;
		switch (ival) {
		case 5:
			tycfg.c_cflag |= CS5;
			break;
		case 6:
			tycfg.c_cflag |= CS6;
			break;
		case 7:
			tycfg.c_cflag |= CS7;
			break;
		case 8:
			tycfg.c_cflag |= CS8;
			break;
		default:
			ret = -EINVAL;
			ERROR_INFO("set [%s] CSIZE [%d] not valid", ptty->m_ttyname, ival);
			goto fail;
		}
		break;
	default:
		ret = -EINVAL;
		ERROR_INFO("[%d] not valid ctrl code", flag);
		goto fail;;
	}

	ret = tcsetattr(ptty->m_ttyfd, TCSANOW, &(tycfg));
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("set TCSETS2 [%s]  error[%d]", ptty->m_ttyname, ret);
		goto fail;
	}

	memcpy(&(ptty->m_ttycfg), &tycfg, sizeof(tycfg));
	if (setbauderate) {
		ptty->m_bauderate = bauderate;
	}

	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int read_tty_nonblock(void* ptty1, uint8_t* pbuf, int bufsize)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t)ptty1;
	int ret;
	int completed = 0;
	if (ptty->m_magic != TTY_DATA_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_inrd > 0) {
		ret = -EBUSY;
		SETERRNO(ret);
		return ret;
	}

	ptty->m_inrd = 1;
	ptty->m_prdptr = pbuf;
	ptty->m_rdleft = bufsize;

	ret = read(ptty->m_ttyfd, ptty->m_prdptr, ptty->m_rdleft);
	if (ret < 0) {
		GETERRNO(ret);
		if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
			ERROR_INFO("read [%s] error[%d]", ptty->m_ttyname, ret);
			goto fail;
		}
		/*now handle*/
		ret = 0;
	}

	ptty->m_prdptr += ret;
	ptty->m_rdleft -= ret;
	if (ptty->m_rdleft == 0) {
		ptty->m_prdptr = NULL;
		ptty->m_inrd = 0;
		completed = 1;
	}
	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int write_tty_nonblock(void* ptty1, uint8_t* pbuf, int bufsize)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t)ptty1;
	int ret;
	int completed = 0;
	if (ptty->m_magic != TTY_DATA_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_inwr > 0) {
		ret = -EBUSY;
		SETERRNO(ret);
		return ret;
	}

	ptty->m_inwr = 1;
	ptty->m_pwrptr = pbuf;
	ptty->m_wrleft = bufsize;

	ret = write(ptty->m_ttyfd, ptty->m_pwrptr, ptty->m_wrleft);
	if (ret < 0) {
		GETERRNO(ret);
		if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
			ERROR_INFO("write [%s] error[%d]", ptty->m_ttyname, ret);
			goto fail;			
		}
		ret = 0;
	}

	ptty->m_pwrptr += ret;
	ptty->m_wrleft -= ret;
	if (ptty->m_wrleft == 0) {
		ptty->m_pwrptr = NULL;
		ptty->m_inwr = 0;
		completed = 1;
	}
	return completed;
fail:
	SETERRNO(ret);
	return ret;
}

int get_tty_read_handle(void* ptty1)
{
	int rethd = -1;
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	if (ptty && ptty->m_magic == TTY_DATA_MAGIC && ptty->m_inrd > 0) {
		rethd = ptty->m_ttyfd;
	}
	return rethd;
}

int get_tty_write_handle(void* ptty1)
{
	int rethd = -1;
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	if (ptty && ptty->m_magic == TTY_DATA_MAGIC && ptty->m_inwr > 0) {
		rethd = ptty->m_ttyfd;
	}
	return rethd;
}

int complete_tty_read(void* ptty1)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	int ret;
	int completed = 0;
	if (ptty->m_magic != TTY_DATA_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_inrd == 0) {
		completed = 1;
	} else {
		ASSERT_IF(ptty->m_prdptr != NULL);
		ASSERT_IF(ptty->m_rdleft > 0);
		ret = read(ptty->m_ttyfd, ptty->m_prdptr, ptty->m_rdleft);
		if (ret < 0) {
			GETERRNO(ret);
			if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
				ERROR_INFO("read [%s] error[%d]", ptty->m_ttyname, ret);
				goto fail;	
			}
			ret = 0;
		}

		ptty->m_prdptr += ret;
		ptty->m_rdleft -= ret;
		if (ptty->m_rdleft == 0) {
			ptty->m_prdptr = NULL;
			ptty->m_inrd = 0;
			completed = 1;
		}
	}

	return completed;

fail:
	SETERRNO(ret);
	return ret;
}


int complete_tty_write(void* ptty1)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	int ret;
	int completed = 0;
	if (ptty->m_magic != TTY_DATA_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_inwr == 0) {
		completed = 1;
	} else {
		ASSERT_IF(ptty->m_pwrptr != NULL);
		ASSERT_IF(ptty->m_wrleft > 0);
		ret = write(ptty->m_ttyfd, ptty->m_pwrptr, ptty->m_wrleft);
		if (ret < 0) {
			GETERRNO(ret);
			if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
				ERROR_INFO("write [%s] error[%d]", ptty->m_ttyname, ret);
				goto fail;	
			}
			ret = 0;
		}

		ptty->m_pwrptr += ret;
		ptty->m_wrleft -= ret;
		if (ptty->m_wrleft == 0) {
			ptty->m_pwrptr = NULL;
			ptty->m_inwr = 0;
			completed = 1;
		}
	}

	return completed;

fail:
	SETERRNO(ret);
	return ret;
}