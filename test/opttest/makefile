
TOPDIR:=$(shell readlink -f ../../)
CURDIR:=$(shell pwd)

ifdef MAKEVERBOSE
QUIET:=
VERBOSE_CFLAGS:=-D__EXTARGS_VERBOSE__
VERBOSE_GFLAGS:= -g
else
QUIET:=@
VERBOSE_CFLAGS:=
VERBOSE_GFLAGS:=
endif


SRCS:=main.c
OBJS:=main.o
CC:=$(shell /usr/bin/which gcc)
LDFLAGS:= -Wall ${VERBOSE_GFLAGS} -L${TOPDIR}/src/
LIBFLAGS:= -lextargs
CFLAGS:= ${VERBOSE_CFLAGS} ${VERBOSE_GFLAGS}  -I${TOPDIR}/src/ -Wall
PYTHON:=$(shell /usr/bin/which python)
RM:=$(shell /usr/bin/which rm)
MAKE:=$(shell /usr/bin/which make)

ifdef EXTARGSLIB_STATICLIB
export EXTARGSLIB_STATICLIB
endif

all:opttest array

ifdef EXTARGSLIB_STATICLIB
opttest:${OBJS} ${TOPDIR}/src/libextargs.a
	${QUIET}${CC} ${LDFLAGS}  -o $@ ${OBJS} ${LIBFLAGS}
else
opttest:${OBJS} ${TOPDIR}/src/libextargs.so
	${QUIET}${CC} ${LDFLAGS}  -o $@ ${OBJS} ${LIBFLAGS}
endif

array:array.o
	${QUIET}${CC} ${LDFLAGS}  -o $@ $<


${TOPDIR}/src/libextargs.so:
	${QUIET}${MAKE} -C ${TOPDIR}/src all

${TOPDIR}/src/libextargs.a:
	${QUIET}${MAKE} -C ${TOPDIR}/src all


%.o:%.c
	${QUIET}${CC} ${CFLAGS} -c $< -o $@

main.c:main.c.tmpl ${TOPDIR}/coutput.py
	${QUIET}${PYTHON} ${TOPDIR}/coutput.py -j ${CURDIR}/test.json -i $< -o $@ all

clean:
	${QUIET}${RM} -f ${OBJS} array array.o opttest main.c
	${QUIET}${MAKE} -C ${TOPDIR}/src clean