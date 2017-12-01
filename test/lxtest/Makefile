
include ../../baseop.mak

SRCDIR= $(shell dirname $(lastword $(MAKEFILE_LIST)))

LXTEST_SRCS= main.cpp
LXTEST_OFILES=$(patsubst %.cpp,%.o,${LXTEST_SRCS})

all:lxtest

ifeq (${STATICLIB},)
lxtest:${LXTEST_OFILES} ${TOPDIR}/uxlib/libuxlib.so
	$(call call_exec,${LINK} ${LDFLAGS} -o $@ ${LXTEST_OFILES} ${LIBFLAGS},"LINK    $@")

${TOPDIR}/uxlib/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"GEN     libuxlib.so")

else
lxtest:${LXTEST_OFILES} ${TOPDIR}/uxlib/libuxlib.lib
	$(call call_exec,${LINK} ${LDFLAGS} -o $@ ${LXTEST_OFILES} ${LIBFLAGS},"LINK    $@")


${TOPDIR}/uxlib/libuxlib.lib:
	$(call call_exec,${MAKE} STATICLIB=1 -C ${TOPDIR}/uxlib all,"GEN     libuxlib.lib")

endif

main.o:main.cpp

main.cpp:args_options.cpp

args_options.cpp:args_options.cpp.tmpl
	$(call call_exec,${PYTHON} ${TOPDIR}/extargslib/coutput.py -j ${SRCDIR}/cmd.json -i $< cmdstruct | \
		${PYTHON} ${TOPDIR}/extargslib/coutput.py -j ${SRCDIR}/cmd.json -i - -o $@ freefunc,"GEN     $@")

include ../../rules.mak

clean:
	$(call call_exec,${MAKE} -C ${TOPDIR}/uxlib ${MAKE_PRINT_FLAG} clean,"CLEAN   uxlib")
	$(call call_exec,${RM} -f lxtest, "RM      lxtest")
	$(call call_exec,${RM} -f ${LXTEST_OFILES}, "RM      *.o")