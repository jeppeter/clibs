
SRCDIR:=$(shell dirname $(lastword $(MAKEFILE_LIST)))

ifeq ($(MAKECMDGOALS),static)
STATICLIB=1
endif

include ../../baseop.mak

EXTARGSLIB_GITHUB=https://github.com/jeppeter/extargslib.git

LXTEST_SRCS= main.cpp
LXTEST_OFILES=$(patsubst %.cpp,%.o,${LXTEST_SRCS})

#$(info "SRCDIR ${SRCDIR} $(MAKEFILE_LIST)")

ifeq (${STATICLIB},)


all:dynamic

dynamic:lxtest

lxtest:${LXTEST_OFILES} ${TOPDIR}/uxlib/libuxlib.so ${TOPDIR}/extargslib/src/libextargs.so
	$(call call_exec,${LINK} ${LDFLAGS} -o $@ ${LXTEST_OFILES} ${LIBFLAGS} -L${TOPDIR}/extargslib/src -lextargs,"LINK    $@")

${TOPDIR}/uxlib/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} STATICLIB= -C ${TOPDIR}/uxlib all,"GEN     libuxlib.so")

${TOPDIR}/extargslib/src/libextargs.so:${TOPDIR}/extargslib
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} EXTARGSLIB_STATICLIB= -C ${TOPDIR}/extargslib/src all,"GEN     libextargslib.so")

else

all:static

static:lxtest_static


lxtest_static:${LXTEST_OFILES} ${TOPDIR}/uxlib/libuxlib.a ${TOPDIR}/extargslib/src/libextargs.a
	$(call call_exec,${LINK} ${LDFLAGS} -o $@ ${LXTEST_OFILES} ${LIBFLAGS} -L${TOPDIR}/extargslib/src -lextargs,"LINK    $@")


${TOPDIR}/uxlib/libuxlib.a:
	$(call call_exec,${MAKE} STATICLIB=1 ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"GEN     libuxlib.a")

${TOPDIR}/extargslib/src/libextargs.a:${TOPDIR}/extargslib
	$(call call_exec,${MAKE} EXTARGSLIB_STATICLIB=1 ${MAKE_PRINT_FLAG} -C ${TOPDIR}/extargslib/src all,"GEN     libuxlib.a")

endif

${TOPDIR}/extargslib:
	$(call call_exec, ${GIT} clone --quiet ${EXTARGSLIB_GITHUB} $@,"CLONE   extargslib")


main.o:main.cpp

main.cpp:args_options.cpp

args_options.cpp:args_options.cpp.tmpl ${TOPDIR}/extargslib
	$(call call_exec,${PYTHON} ${TOPDIR}/extargslib/coutput.py -j ${SRCDIR}/cmd.json -i $< cmdstruct | \
		${PYTHON} ${TOPDIR}/extargslib/coutput.py -j ${SRCDIR}/cmd.json -i - -o $@ freefunc,"GEN     $@")

include ../../rules.mak

clean_extargslib:
	$(call call_exec,if [ -f ${TOPDIR}/extargslib/src/makefile ] ; then ${MAKE} -C ${TOPDIR}/uxlib ${MAKE_PRINT_FLAG} clean; fi,"CLEAN   extargslib")

clean:clean_extargslib
	$(call call_exec,${MAKE} -C ${TOPDIR}/uxlib ${MAKE_PRINT_FLAG} clean,"CLEAN   uxlib")
	$(call call_exec,${RM} -f lxtest lxtest_static, "RM      lxtest")
	$(call call_exec,${RM} -f args_options.cpp,"RM      args_options.cpp")
	$(call call_exec,${RM} -f ${LXTEST_OFILES}, "RM      *.o")