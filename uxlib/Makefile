EXTRA_CFLAGS=
EXTRA_CXXFLAGS=
EXTRA_LDFLAGS= -shared

include ../baseop.mak

LIBUX_SRCS=ux_output_debug.cpp ux_strop.cpp ux_args.cpp ux_time_op.cpp
LIBUX_OFILES=$(patsubst %.cpp,%.o,${LIBUX_SRCS})

ifeq (${STATICLIB},)
COMMON_LIBS:= ${TOPDIR}/libextargs.a ${TOPDIR}/libjson.a
COMMON_LDFLAGS:= -L${TOPDIR} -lextargs -ljson
else
COMMON_LIBS:= ${TOPDIR}/libextargs.so ${TOPDIR}/libjson.so
COMMON_LDFLAGS:= -L${TOPDIR} -lextargs -ljson
endif

ifeq (${STATICLIB},)
all:libuxlib.so

libuxlib.so:${LIBUX_OFILES} ${COMMON_LIBS}
	$(call call_exec,${LINK} ${LDFLAGS} -Wall -o $@ ${LIBUX_OFILES} ${COMMON_LDFLAGS},"LINK    $@")
	$(call call_exec,${CP} -f $@ ${TOPDIR}/$@,"CP      ${TOPDIR}/$@")

else

all:libuxlib.a

libuxlib.a:${LIBUX_OFILES}
	$(call call_exec,${AR} -rcs $@ $^ ${COMMON_LIBS},"AR      $@")
	$(call call_exec,${CP} -f $@ ${TOPDIR}/$@,"CP      ${TOPDIR}/$@")

endif


ux_output_deubg.o:ux_output_deubg.cpp

ux_strop.o:ux_strop.cpp


include ../rules.mak

clean:
	$(call call_exec,${RM} -f libuxlib.so libuxlib.a,"RM      libuxlib")
	$(call call_exec,${RM} -f ${LIBUX_OFILES},"RM      *.o")
	$(call call_exec,${RM} -f ${TOPDIR}/libuxlib.a ${TOPDIR}/libuxlib.so,"RM      ${TOPDIR}/libuxlib.so ${TOPDIR}/libuxlib.a")