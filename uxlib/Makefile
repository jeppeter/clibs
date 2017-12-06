EXTRA_CFLAGS=
EXTRA_CXXFLAGS=
EXTRA_LDFLAGS= -shared

include ../baseop.mak

LIBUX_SRCS=ux_output_debug.cpp ux_strop.cpp ux_args.cpp ux_time_op.cpp
LIBUX_OFILES=$(patsubst %.cpp,%.o,${LIBUX_SRCS})

ifeq (${STATICLIB},)
all:libuxlib.so

libuxlib.so:${LIBUX_OFILES}
	$(call call_exec,${LINK} ${LDFLAGS} -Wall -o $@ ${LIBUX_OFILES},"LINK    $@")

else

all:libuxlib.a

libuxlib.a:${LIBUX_OFILES}
	$(call call_exec,${AR} -rcs $@ $^,"AR      $@")


endif


ux_output_deubg.o:ux_output_deubg.cpp

ux_strop.o:ux_strop.cpp


include ../rules.mak

clean:
	$(call call_exec,${RM} -f libuxlib.so libuxlib.a,"RM      libuxlib")
	$(call call_exec,${RM} -f ${LIBUX_OFILES},"RM      *.o")