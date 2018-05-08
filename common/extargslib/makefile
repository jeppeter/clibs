
include ../../baseop.mak


ifdef MAKEVERBOSE
VERBOSE_SOURCES:=debug_jvalue.c
VERBOSE_CFLAGS:=-D__EXTARGS_VERBOSE__
VERBOSE_GFLAGS:= -g
else
VERBOSE_SOURCES:=
VERBOSE_CFLAGS:=
VERBOSE_GFLAGS:=
endif

TARGET:=libextargs
CURDIR:=$(shell pwd)


EXTARGS_SRCS:=extargs.c ${VERBOSE_SOURCES}
EXTARGS_OBJS:=$(patsubst %.c,${CURDIR}/%.o,${EXTARGS_SRCS})
LIB_OBJS:= ${EXTARGS_OBJS}
EXTARGS_HEADS:= $(wildcard ${CURDIR}/*.h)
JSONLIB_HEADS:= $(wildcard ${CURDIR}/../jsonlib/*.h)
HEADERS:=${EXTARGS_HEADS}



ifeq (${STATICLIB},)
LDFLAGS:= ${VERBOSE_GFLAGS} -Wall -shared -Wl,-soname,$(TARGET).so
CFLAGS:= ${VERBOSE_CFLAGS} ${VERBOSE_GFLAGS} -Wall -I${CURDIR}/ -I${TOPDIR}/common/jsonlib -I${TOPDIR}/common -I${TOPDIR}/uxlib  -fPIC 
else
LDFLAGS:= ${VERBOSE_GFLAGS} -Wall
CFLAGS:= ${VERBOSE_CFLAGS} ${VERBOSE_GFLAGS} -Wall -I${CURDIR}/ -I${TOPDIR}/common/jsonlib -I${TOPDIR}/common -I${TOPDIR}/uxlib
endif


ifeq (${STATICLIB},)
all: ${TARGET}.so
else
all: ${TARGET}.a
endif

${TARGET}.a:${LIB_OBJS}
	$(call ${AR} -rcs $@ $^,"AR      $@")
	$(call ${CP} ${TARGET}.a ${TOPDIR}/${TARGET}.a,"CP      ${TOPDIR}/${TARGET}.a")

${TARGET}.so:${LIB_OBJS}
	$(call ${CC} $(LDFLAGS) $^ -o $@,"LD      $@")
	$(call ${CP} ${TARGET}.so ${TOPDIR}/${TARGET}.so,"CP      ${TOPDIR}/${TARGET}.so")

%.o:%.c ${HEADERS}
	$(call ${CC} ${CFLAGS} -o $@ -c $<,"CC      $<")

extargs.o:extargs.c ${HEADERS}

debug_jvalue.o:debug_jvalue.c ${HEADERS}

clean:
	$(call ${RM} -f ${LIB_OBJS} *.o *.so *.a ${TARGET}.a ${TARGET}.so,"RM      ${LIB_OBJS}")
	$(call ${RM} -f ${TOPDIR}/${TARGET}.so ${TOPDIR}/${TARGET}.a,"RM      ${TARGET}.so ${TARGET}.a")
