
include ../../../../baseop.mak

ifdef MAKEVERBOSE
VERBOSE_CFLAGS:=-D__EXTARGS_VERBOSE__
else
VERBOSE_CFLAGS:=
endif

CURDIR:=$(shell readlink -f .)

SRCS:=main.c
OBJS:=main.o
LDFLAGS:= -Wall -L${TOPDIR}/src/
ifeq (${STATICLIB},)
LIBFLAGS:= -L${TOPDIR} -lextargs -ljson -luxlib
else
LIBFLAGS:= -L${TOPDIR} -luxlib
endif
CFLAGS:= ${VERBOSE_CFLAGS} -I${TOPDIR}/common/extargslib -I${TOPDIR}/common -I${TOPDIR}/uxlib -Wall

ifdef STATICLIB
export STATICLIB
endif

all:opttest

ifdef STATICLIB
opttest:${OBJS} ${TOPDIR}/uxlib/libuxlib.a
	$(call call_exec,${CC} ${LDFLAGS}  -o $@ ${OBJS} ${LIBFLAGS},"LINK    opttest(static)")
else
opttest:${OBJS} ${TOPDIR}/uxlib/libuxlib.so
	$(call call_exec,${CC} ${LDFLAGS}  -o $@ ${OBJS} ${LIBFLAGS},"LINK    opttest(dynamic)")
endif



${TOPDIR}/uxlib/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"LINK    uxlib(dynamic)")

${TOPDIR}/uxlib/libuxlib.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"LINK    uxlib(static)")


%.o:%.c
	$(call call_exec,${CC} ${CFLAGS} -c $< -o $@,"CC      $<")

main.c:main.c.tmpl ${TOPDIR}/coutput.py
	$(call call_exec,${PYTHON} ${TOPDIR}/coutput.py -j ${CURDIR}/test.json -i $< -o $@ all,"GEN     $@")

clean:
	$(call call_exec,${RM} -f ${OBJS} opttest main.c, "RM     opttest main.c")
	$(call call_exec,${MAKE} -C ${TOPDIR}/uxlib clean,"CLEAN   uxlib")