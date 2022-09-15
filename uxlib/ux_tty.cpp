#include <ux_tty.h>
#include <ux_output_debug.h>

#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



#define  TTY_DATA_MAGIC   0x430129de

#define  TTY_NONE_FLUSH   0
#define  TTY_FLUSHING     1
#define  TTY_FLUSH_STORED 2
#define  TTY_FLUSHED      3

typedef struct __tty_data_priv {
	uint32_t m_magic;
	int m_flushed;
	uint8_t *m_flushbuf;
	int m_flushlen;
	int m_flushrlen;
	int m_flushsize;
	int m_ttyfd;
	char* m_ttyname;
	int m_inrd;
	int m_inwr;
	struct termios m_ttycfg;
	struct termios m_preparecfg;
	int m_cfgcached;
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
		memset(&(ptty->m_ttycfg), 0, sizeof(ptty->m_ttycfg));

		if (ptty->m_flushbuf) {
			free(ptty->m_flushbuf);
		}
		ptty->m_flushbuf = NULL;
		ptty->m_flushsize = 0;
		ptty->m_flushlen = 0;
		ptty->m_flushrlen = 0;


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

void* open_tty(const char* ttyname,int maxflush)
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
	ptty->m_flushed = TTY_NONE_FLUSH;
	ptty->m_cfgcached = 0;
	if (maxflush <= 0) {
		ptty->m_flushsize = (512 << 10);
	} else {
		ptty->m_flushsize = maxflush;
	}

	ptty->m_flushbuf = (uint8_t*)malloc(ptty->m_flushsize);
	if (ptty->m_flushbuf == NULL) {
		GETERRNO(ret);
		goto fail;
	}
	ptty->m_flushrlen = 0;
	ptty->m_flushlen = 0;

	ptty->m_ttyname = strdup(ttyname);
	if (ptty->m_ttyname == NULL) {
		GETERRNO(ret);
		goto fail;
	}

	/*now open the fd*/
	ptty->m_ttyfd = open(ptty->m_ttyname, O_RDWR,O_TRUNC);
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


	ret = tcgetattr(ptty->m_ttyfd, &(ptty->m_ttycfg));
	if (ret != 0) {
		GETERRNO(ret);
		ERROR_INFO("can not TCGETS2 [%s] error[%d]", ptty->m_ttyname, ret);
		goto fail;
	}

	return (void*) ptty;
fail:
	free_tty((void**)&ptty);
	SETERRNO(ret);
	return NULL;
}

int _flush_tty_read_buffer(ptty_data_priv_t ptty)
{
	int ret;
	int cnt = 0;
	int completed = 0;
	int curlen = 0;
	if (ptty->m_ttyfd < 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_flushed == TTY_FLUSHED || ptty->m_flushed == TTY_FLUSH_STORED) {
		completed = 1;
	} else {
		if (ptty->m_flushed == TTY_NONE_FLUSH) {
			/*now we should read every left buffer in the ttyname*/
			while (1) {
				ret = read(ptty->m_ttyfd, ptty->m_flushbuf, ptty->m_flushsize);
				if (ret < 0) {
					GETERRNO(ret);
					if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
						ERROR_INFO("flush buffer for [%s] error[%d]", ptty->m_ttyname, ret);
						goto fail;
					}
					ptty->m_inrd = 1;
					ptty->m_flushed = TTY_FLUSHING;
					break;
				} else if (ret == 0) {
					WARN_INFO("read [%s][%d] ret == 0", ptty->m_ttyname, cnt);
					ptty->m_inrd = 0;
					ptty->m_flushed = TTY_FLUSHED;
					completed = 1;
					break;
				}

				curlen = ret;
				if (curlen > 0x200) {
					curlen = 0x200;
				}
				DEBUG_BUFFER_FMT(ptty->m_flushbuf, curlen, "read[%s][%d] len [%d]", ptty->m_ttyname, cnt,ret);
				cnt += ret;
			}
		}
	}

	return completed;
fail:
	SETERRNO(ret);
	return ret;
}


int prepare_tty_config(void* ptty1, int flag, void* value)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	int ret;
	int *iptr, ival;
	unsigned int *uptr, uval;
	unsigned char* ucptr, uch,ucoff;
	struct termios* ptycfg=NULL;
	if (ptty->m_magic != TTY_DATA_MAGIC || ptty->m_ttyfd < 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_cfgcached == 0) {
		memcpy(&(ptty->m_preparecfg), &(ptty->m_ttycfg),sizeof(ptty->m_preparecfg));
		ptty->m_cfgcached = 1;
	}
	ptycfg = &(ptty->m_preparecfg);

	switch (flag) {
	case TTY_SET_SPEED:
		if (value == NULL) {
			ret = -EINVAL;
			goto fail;
		}
		iptr = (int*) value;
		ival = *iptr;
		switch (ival) {
		case 0:
			cfsetspeed(ptycfg, B0);
			break;
		case 50:
			cfsetspeed(ptycfg, B50);
			break;
		case 75:
			cfsetspeed(ptycfg, B75);
			break;
		case 110:
			cfsetspeed(ptycfg, B110);
			break;
		case 134:
			cfsetspeed(ptycfg, B134);
			break;
		case 150:
			cfsetspeed(ptycfg, B150);
			break;
		case 200:
			cfsetspeed(ptycfg, B200);
			break;
		case 300:
			cfsetspeed(ptycfg, B300);
			break;
		case 600:
			cfsetspeed(ptycfg, B600);
			break;
		case 1200:
			cfsetspeed(ptycfg, B1200);
			break;
		case 1800:
			cfsetspeed(ptycfg, B1800);
			break;
		case 2400:
			cfsetspeed(ptycfg, B2400);
			break;
		case 4800:
			cfsetspeed(ptycfg, B4800);
			break;
		case 9600:
			cfsetspeed(ptycfg, B9600);
			break;
		case 19200:
			cfsetspeed(ptycfg, B19200);
			break;
		case 38400:
			cfsetspeed(ptycfg, B38400);
			break;
		case 57600:
			cfsetspeed(ptycfg, B57600);
			break;
		case 115200:
			cfsetspeed(ptycfg, B115200);
			break;
		case 230400:
			cfsetspeed(ptycfg, B230400);
			break;
		case 460800:
			cfsetspeed(ptycfg, B460800);
			break;
		default:
			ret = -EINVAL;
			ERROR_INFO("set speed for [%s] not valid [%d]", ptty->m_ttyname, ival);
			goto fail;
		}
		break;
	case TTY_SET_SIZE:
		iptr = (int*) value;
		ival = *iptr;
		ptycfg->c_cflag &= ~CSIZE;
		switch (ival) {
		case 5:
			ptycfg->c_cflag |= CS5;
			break;
		case 6:
			ptycfg->c_cflag |= CS6;
			break;
		case 7:
			ptycfg->c_cflag |= CS7;
			break;
		case 8:
			ptycfg->c_cflag |= CS8;
			break;
		default:
			ret = -EINVAL;
			ERROR_INFO("set [%s] CSIZE [%d] not valid", ptty->m_ttyname, ival);
			goto fail;
		}
		break;
	case TTY_SET_IFLAGS:
		uptr = (unsigned int*) value;
		uval = *uptr;
		ptycfg->c_iflag |= uval;
		break;

	case TTY_CLEAR_IFLAGS:
		uptr = (unsigned int*) value;
		uval = *uptr;
		ptycfg->c_iflag &= ~uval;
		break;	

	case TTY_SET_OFLAGS:
		uptr = (unsigned int*) value;
		uval = *uptr;
		ptycfg->c_oflag |= uval;
		break;

	case TTY_CLEAR_OFLAGS:
		uptr = (unsigned int*) value;
		uval = *uptr;
		ptycfg->c_oflag &= ~uval;
		break;	

	case TTY_SET_CFLAGS:
		uptr = (unsigned int*) value;
		uval = *uptr;
		ptycfg->c_cflag |= uval;
		break;

	case TTY_CLEAR_CFLAGS:
		uptr = (unsigned int*) value;
		uval = *uptr;
		ptycfg->c_cflag &= ~uval;
		break;

	case TTY_SET_LFLAGS:
		uptr = (unsigned int*) value;
		uval = *uptr;
		ptycfg->c_lflag |= uval;
		break;

	case TTY_CLEAR_LFLAGS:
		uptr = (unsigned int*) value;
		uval = *uptr;
		ptycfg->c_lflag &= ~uval;
		break;	

	case TTY_SET_CLINE:
		ucptr = (unsigned char*) value;
		uch = *ucptr;
		ptycfg->c_line = uch;
		break;

	case TTY_SET_CC:
		ucptr = (unsigned char*) value;
		ucoff = ucptr[0];
		uch = ucptr[1];
		if (ucoff >= NCCS) {
			ret = -EINVAL;
			goto fail;
		}
		ptycfg->c_cc[ucoff] = uch;
		break;

	case TTY_SET_RAW:
		ptycfg->c_iflag = 0;
		ptycfg->c_oflag &= ~OPOST;
		ptycfg->c_lflag &= ~(ISIG | ICANON | XCASE);
		ptycfg->c_cc[VMIN] = 1;
		ptycfg->c_cc[VTIME] = 0;
		break;

	default:
		ret = -EINVAL;
		ERROR_INFO("[%d] not valid ctrl code", flag);
		goto fail;;
	}


	return 0;
fail:
	SETERRNO(ret);
	return ret;
}

int commit_tty_config(void* ptty1)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	int setted = 0;
	int ret;

	if (ptty->m_magic != TTY_DATA_MAGIC || ptty->m_ttyfd < 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_cfgcached > 0) {
		ret = tcsetattr(ptty->m_ttyfd, TCSANOW,&(ptty->m_preparecfg));
		if (ret < 0) {
			GETERRNO(ret);
			ERROR_INFO("can not set [%s] error[%d]", ptty->m_ttyname, ret);
			goto fail;
			goto fail;
		}
		memcpy(&(ptty->m_ttycfg),&(ptty->m_preparecfg),sizeof(ptty->m_preparecfg));
		ptty->m_cfgcached = 0;
		setted = 1;
	}

	return setted;
fail:
	SETERRNO(ret);
	return ret;
}

int read_tty_nonblock(void* ptty1, uint8_t* pbuf, int bufsize)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t)ptty1;
	int ret;
	int completed = 0;
	int curlen;
	if (ptty->m_magic != TTY_DATA_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_prdptr != NULL) {
		ret = -EBUSY;
		SETERRNO(ret);
		return ret;
	}

	ptty->m_prdptr = pbuf;
	ptty->m_rdleft = bufsize;

	if (ptty->m_flushed == TTY_FLUSH_STORED) {
		if (ptty->m_rdleft > 0) {
			curlen = ptty->m_flushlen - ptty->m_flushrlen;
			if (curlen > ptty->m_rdleft) {
				curlen = ptty->m_rdleft;
			}
			if (curlen > 0) {
				memcpy(ptty->m_prdptr, &(ptty->m_flushbuf[ptty->m_flushrlen]), curlen);	
			}			
			ptty->m_rdleft -= curlen;
			ptty->m_prdptr += curlen;
			ptty->m_flushrlen += curlen;
			if (ptty->m_flushrlen == ptty->m_flushlen) {
				ptty->m_flushed = TTY_FLUSHED;
			}
		}

		if (ptty->m_rdleft == 0) {
			ptty->m_prdptr = NULL;
			ptty->m_rdleft = 0;
			ptty->m_inrd = 0;
			completed = 1;
			goto succ;
		}
	}


	if (ptty->m_flushed == TTY_FLUSHED) {
read_real_buffer:
		/*this is handle read mode*/
		ptty->m_inrd = 1;
		DEBUG_INFO("will read [%s] [%p] [0x%x:%d]", ptty->m_ttyname, ptty->m_prdptr, ptty->m_rdleft, ptty->m_rdleft);
		while (1) {
			ret = read(ptty->m_ttyfd, ptty->m_prdptr, ptty->m_rdleft);
			if (ret < 0) {
				GETERRNO(ret);
				DEBUG_INFO("read [%s] [%d] error[%d]", ptty->m_ttyname, ptty->m_rdleft, ret);
				if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
					ERROR_INFO("read [%s] error[%d]", ptty->m_ttyname, ret);
					goto fail;
				}
				/*now handle*/
				break;
			}
			DEBUG_INFO("read [%s] ret [%d]", ptty->m_ttyname, ret);

			ptty->m_prdptr += ret;
			ptty->m_rdleft -= ret;
			if (ptty->m_rdleft == 0) {
				ptty->m_prdptr = NULL;
				ptty->m_inrd = 0;
				completed = 1;
				break;
			}
		}
	} else if (ptty->m_flushed == TTY_NONE_FLUSH) {
		ret = _flush_tty_read_buffer(ptty);
		if (ret < 0) {
			GETERRNO(ret);
			goto fail;
		}
		if (ret > 0) {
			goto read_real_buffer;
		}
	}

succ:
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

	while (1) {
		ret = write(ptty->m_ttyfd, ptty->m_pwrptr, ptty->m_wrleft);
		if (ret < 0) {
			GETERRNO(ret);
			if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
				ERROR_INFO("write [%s] error[%d]", ptty->m_ttyname, ret);
				goto fail;
			}
			ret = 0;
			break;
		}
		DEBUG_INFO("write [%s] size [%d]", ptty->m_ttyname, ret);
		//DEBUG_BUFFER_FMT(ptty->m_pwrptr, ret, "write [%s] ", ptty->m_ttyname);
		ptty->m_pwrptr += ret;
		ptty->m_wrleft -= ret;
		if (ptty->m_wrleft == 0) {
			ptty->m_pwrptr = NULL;
			ptty->m_inwr = 0;
			completed = 1;
			break;
		}
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
	int curlen;
	int completed = 0;
	if (ptty->m_magic != TTY_DATA_MAGIC) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_inrd == 0) {
		completed = 1;
	} else {
		if (ptty->m_flushed == TTY_FLUSHING) {
			ret = read(ptty->m_ttyfd, ptty->m_flushbuf, ptty->m_flushsize);
			if (ret < 0) {
				GETERRNO(ret);
				if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
					ERROR_INFO("read flush buffer [%s] error[%d]", ptty->m_ttyname , ret);
					goto fail;
				}
			} else if (ret > 0) {
				ptty->m_flushed = TTY_FLUSH_STORED;
				ptty->m_flushlen += ret;
				if (ptty->m_prdptr != NULL) {
					if (ptty->m_rdleft > 0) {
						curlen = ptty->m_flushlen - ptty->m_flushrlen;
						if (curlen > ptty->m_rdleft) {
							curlen = ptty->m_rdleft;
						}
						if (curlen > 0) {
							memcpy(ptty->m_prdptr, &(ptty->m_flushbuf[ptty->m_flushrlen]), curlen);	
						}						
						ptty->m_rdleft -= curlen;
						ptty->m_prdptr += curlen;
						ptty->m_flushrlen += curlen;
						if (ptty->m_flushrlen == ptty->m_flushlen) {
							ptty->m_flushed = TTY_FLUSHED;
						}
					}

					if (ptty->m_rdleft == 0) {
						ptty->m_prdptr = NULL;
						ptty->m_rdleft = 0;
						ptty->m_inrd = 0;
						completed = 1;
					}

					if (ptty->m_prdptr != NULL) {
						goto read_again;
					}
				} else {
					ptty->m_inrd = 0;
					completed = 1;
				}
			}
		} else if (ptty->m_flushed == TTY_FLUSHED) {
read_again:
			ASSERT_IF(ptty->m_prdptr != NULL);
			ASSERT_IF(ptty->m_rdleft > 0);
			DEBUG_INFO("will read [%s] [%p] [0x%x:%d]", ptty->m_ttyname, ptty->m_prdptr, ptty->m_rdleft, ptty->m_rdleft);
			while (1) {
				ret = read(ptty->m_ttyfd, ptty->m_prdptr, ptty->m_rdleft);
				if (ret < 0) {
					GETERRNO(ret);
					DEBUG_INFO("read [%s] [%d] error[%d]", ptty->m_ttyname, ptty->m_rdleft, ret);
					if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
						ERROR_INFO("read [%s] error[%d]", ptty->m_ttyname, ret);
						goto fail;
					}
					ret = 0;
					break;
				}
				curlen = ret;
				if (curlen > 0x200) {
					curlen = 0x200;
				}
				DEBUG_BUFFER_FMT(ptty->m_prdptr, curlen, "read [%s] ret [%d]", ptty->m_ttyname, ret);

				ptty->m_prdptr += ret;
				ptty->m_rdleft -= ret;
				if (ptty->m_rdleft == 0) {
					ptty->m_prdptr = NULL;
					ptty->m_inrd = 0;
					completed = 1;
					break;
				}
			}
		} else if (ptty->m_flushed == TTY_FLUSH_STORED) {
			WARN_INFO("TTY_FLUSH_STORED met again");
			completed = 1;
		} else {
			ERROR_INFO("not valid state in complete_tty_read [%d]", ptty->m_flushed);
			ret = -EINVAL;
			goto fail;
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
		while(1) {
			ret = write(ptty->m_ttyfd, ptty->m_pwrptr, ptty->m_wrleft);
			if (ret < 0) {
				GETERRNO(ret);
				if (ret != -EAGAIN && ret != -EWOULDBLOCK) {
					ERROR_INFO("write [%s] error[%d]", ptty->m_ttyname, ret);
					goto fail;
				}
				ret = 0;
				break;
			}
			DEBUG_INFO("write [%s] size [%d]", ptty->m_ttyname, ret);
			//DEBUG_BUFFER_FMT(ptty->m_pwrptr, ret, "write [%s] ", ptty->m_ttyname);
			ptty->m_pwrptr += ret;
			ptty->m_wrleft -= ret;
			if (ptty->m_wrleft == 0) {
				ptty->m_pwrptr = NULL;
				ptty->m_inwr = 0;
				completed = 1;
				break;
			}
		}
	}

	return completed;

fail:
	SETERRNO(ret);
	return ret;
}



int get_tty_config_direct(void* ptty1, void** ppcfg, int* psize)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	int ret;
	struct termios *pretcfg = NULL;
	int retsize = 0;
	int retlen = sizeof(*pretcfg);
	if (ptty == NULL) {
		if (ppcfg && *ppcfg) {
			free(*ppcfg);
			*ppcfg = NULL;
		}
		if (psize) {
			*psize = 0;
		}
		return 0;
	}

	if (ppcfg == NULL || psize == NULL) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	if (ptty->m_magic != TTY_DATA_MAGIC || ptty->m_ttyfd < 0) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	pretcfg = (struct termios*) (*ppcfg);
	retsize = *psize;

	if (retsize < retlen || pretcfg == NULL) {
		retsize = retlen;
		pretcfg = (struct termios*) malloc(retsize);
		if (pretcfg == NULL) {
			GETERRNO(ret);
			goto fail;
		}
	}

	memcpy(pretcfg, &(ptty->m_ttycfg), retlen);
	if (*ppcfg && *ppcfg != pretcfg) {
		free(*ppcfg);
	}

	*ppcfg = pretcfg;
	*psize = retsize;

	return retlen;
fail:
	if (pretcfg != NULL && pretcfg != *ppcfg) {
		free(pretcfg);
	}
	pretcfg = NULL;
	SETERRNO(ret);
	return ret;
}

int set_tty_config_direct(void* ptty1, void* pcfg, int size)
{
	ptty_data_priv_t ptty = (ptty_data_priv_t) ptty1;
	int ret;
	struct termios *pretcfg = (struct termios*) pcfg;

	if (ptty == NULL || ptty->m_magic != TTY_DATA_MAGIC || ptty->m_ttyfd < 0 ||
	        pretcfg == NULL || size < (int)sizeof(*pretcfg)) {
		ret = -EINVAL;
		SETERRNO(ret);
		return ret;
	}

	ret = tcsetattr(ptty->m_ttyfd, TCSANOW, pretcfg);
	if (ret != 0) {
		GETERRNO(ret);
		goto fail;
	}
	memcpy(&(ptty->m_ttycfg), pretcfg, sizeof(*pretcfg));
	return 0;
fail:
	SETERRNO(ret);
	return ret;
}