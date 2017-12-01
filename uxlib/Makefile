EXTRA_CFLAGS=
EXTRA_CXXFLAGS=
EXTRA_LDFLAGS=

include ../baseop.mak

LIBUX_SRCS=ux_output_debug.cpp ux_strop.cpp ux_args.cpp
LIBUX_OFILES=$(patsubst %.cpp,%.o,${LIBUX_SRCS})

ifeq (${STATICLIB},)
all:libuxlib.so

libuxlib.so:${LIBUX_OFILES}
	$(call call_exec,${LINK} -shared -Wall -o $@ ${LIBUX_OFILES},"LINK    $@")

ux_output_deubg.o:ux_output_deubg.cpp

ux_strop.o:ux_strop.cpp

else

all:libuxlib.lib

libuxlib.lib:${LIBUX_OFILES}
	$(call call_exec,${AR} -rcs $@ $^,"AR $@")

ux_output_deubg.o:ux_output_deubg.cpp

ux_strop.o:ux_strop.cpp

endif

include ../rules.mak

clean:
	$(call call_exec,${RM} -f libuxlib.so libuxlib.lib,"RM      libuxlib")
	$(call call_exec,${RM} -f ${LIBUX_OFILES},"RM      *.o")