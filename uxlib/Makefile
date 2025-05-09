EXTRA_CFLAGS=
EXTRA_CXXFLAGS=

ifeq (${STATICLIB},)
EXTRA_LDFLAGS= -shared
else
EXTRA_LDFLAGS=
endif

include ../baseop.mak

TARGET:=libuxlib

LIBUX_SRCS=ux_output_debug.cpp ux_strop.cpp ux_args.cpp ux_time_op.cpp ux_fileop.cpp ux_proc.cpp ux_regex.cpp ux_sock.cpp ux_tty.cpp ux_libev.cpp ux_ping.cpp
LIBUX_OFILES=$(patsubst %.cpp,%.o,${LIBUX_SRCS})

ifeq (${STATICLIB},)
COMMON_LDFLAGS:= -lpthread
else
COMMON_LDFLAGS:= -lpthread
endif

INCLUDE_BASE_CFLAGS = -I${TOPDIR}/uxlib
INCLUDE_BASE_CXXFLAGS = -I${TOPDIR}/uxlib
INCLUDE_BASE_LDFLAGS= -L${TOPDIR}/uxlib
INCLUDE_BASE_LIBFLAGS= -luxlib

CFLAGS= ${INCLUDE_BASE_CFLAGS} ${EXTRA_CFLAGS} ${SHARED_CFLAGS} -Wall
CXXFLAGS = ${INCLUDE_BASE_CXXFLAGS} ${EXTRA_CXXFLAGS} ${SHARED_CFLAGS} -Wall
LDFLAGS= ${INCLUDE_BASE_LDFLAGS} ${EXTRA_LDFLAGS} -Wall
LIBFLAGS= ${INCLUDE_BASE_LIBFLAGS} ${EXTRA_LIBFLAGS}


ifeq (${STATICLIB},)
unexport STATICLIB
else
export STATICLIB
endif

ifeq (${STATICLIB},)
all:${DYNAMICDIR}/${TARGET}.so

${DYNAMICDIR}/${TARGET}.so:${TARGET}.so ${DYNAMICDIR}
	$(call call_exec,${CP} -f $< ${DYNAMICDIR}/${TARGET}.so,"CP      ${DYNAMICDIR}/${TARGET}.so")

${DYNAMICDIR}:
	$(call call_exec,${MKDIR} -p $@,"MKDIR   $@")

${TARGET}.so:${LIBUX_OFILES}
	$(call call_exec,${LINK} ${LDFLAGS} -Wall -o $@ ${LIBUX_OFILES} ${COMMON_LDFLAGS},"LINK    $@")


else

all:${STATICDIR}/${TARGET}.a

${STATICDIR}/${TARGET}.a:${TARGET}.a ${STATICDIR}
	$(call call_exec,${CP} -f $< ${STATICDIR}/$<,"CP      ${STATICDIR}/$<")

${STATICDIR}:
	$(call call_exec,${MKDIR} -p $@,"MKDIR   $@")


${TARGET}.a:${LIBUX_OFILES}
	$(call call_exec,${AR} -rcs $@ $^ ${COMMON_LIBS},"AR      $@")

endif

ux_output_deubg.o:ux_output_deubg.cpp

ux_strop.o:ux_strop.cpp


include ../rules.mak



clean:
	$(call call_exec,${RM} -f ${TARGET}.so ${TARGET}.a,"RM      ${TARGET}")
	$(call call_exec,${RM} -f ${STATICDIR}/${TARGET}.a ${DYNAMICDIR}/${TARGET}.so,"RM      ${TOPDIR}/${TARGET}")
	$(call call_exec,${RM} -f ${LIBUX_OFILES},"RM      *.o")
