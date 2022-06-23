
SRCDIR:=$(shell dirname $(lastword $(MAKEFILE_LIST)))

ifeq ($(MAKECMDGOALS),static)
STATICLIB=1
endif

include ../../baseop.mak


LXTEST_SRCS= main.cpp authenticode.cpp auth_certificate.cpp auth_countersignature.cpp auth_structs.cpp auth_helper.cpp
LXTEST_OFILES=$(patsubst %.cpp,%.o,${LXTEST_SRCS})

INCLUDE_CFLAGS= -I${TOPDIR}/uxlib -I${TOPDIR}/common -I${TOPDIR}/common/jsonlib -I${TOPDIR}/common/extargslib -I${TOPDIR}/common/cryptutil -I${SRCDIR}

#$(info "SRCDIR ${SRCDIR} $(MAKEFILE_LIST)")
ifeq (${STATICLIB},)
unexport STATICLIB
else
export STATICLIB
endif

ifeq (${STATICLIB},)


all:dynamic

dynamic:ssltst

ssltst:${LXTEST_OFILES} ${DYNAMICDIR}/libuxlib.so ${DYNAMICDIR}/libextargs.so ${DYNAMICDIR}/libjson.so ${DYNAMICDIR}/libcryptutil.so
	$(call call_exec,${LINK} ${LDFLAGS} -o $@ ${LXTEST_OFILES} -L${DYNAMICDIR} -lextargs -ljson -luxlib -lcryptutil -lssl -lcrypto,"LINK    $@")

${DYNAMICDIR}/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"GEN     libuxlib.so")

${DYNAMICDIR}/libextargs.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib all,"GEN     libextargslib.so")

${DYNAMICDIR}/libjson.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"GEN     libjson.so")

${DYNAMICDIR}/libcryptutil.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/cryptutil all,"GEN     libcryptutil.so")

else

all:static

static:ssltst_static


ssltst_static:${LXTEST_OFILES} ${STATICDIR}/libuxlib.a ${STATICDIR}/libextargs.a ${STATICDIR}/libjson.a ${STATICDIR}/libcryptutil.a
	$(call call_exec,${LINK} ${LDFLAGS} -o $@ ${LXTEST_OFILES}  -L${STATICDIR} -lextargs -ljson -luxlib -lcryptutil -lssl -lcrypto,"LINK    $@")


${STATICDIR}/libuxlib.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"GEN     libuxlib.a")

${STATICDIR}/libextargs.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib all,"GEN     libextargs.a")

${STATICDIR}/libjson.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"GEN     libjson.a")

${STATICDIR}/libcryptutil.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/cryptutil all,"GEN     libcryptutil.a")


endif


main.o:main.cpp

main.cpp:args_options.cpp peauth.cpp

args_options.cpp:args_options.cpp.tmpl ${TOPDIR}/common/extargslib
	$(call call_exec,${PYTHON} ${TOPDIR}/coutput.py -j ${SRCDIR}/cmd.json -i $< cmdstruct | \
		${PYTHON} ${TOPDIR}/coutput.py -j ${SRCDIR}/cmd.json -i - -o $@ freefunc,"GEN     $@")

%.o:%.cpp
	$(call call_exec,${CXX} -Wall ${INCLUDE_CFLAGS} -c $< -o $@,"CXX     $<")

clean_extargslib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib clean,"CLEAN   extargslib")

clean_json:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib clean,"CLEAN   jsonlib")

clean_uxlib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib clean,"CLEAN   uxlib")

clean_cryptutil:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/cryptutil clean,"CLEAN   cryptutil")


clean:clean_extargslib clean_uxlib clean_json clean_cryptutil
	$(call call_exec,${RM} -f ssltst ssltst_static, "RM      ssltst")
	$(call call_exec,${RM} -f args_options.cpp,"RM      args_options.cpp")
	$(call call_exec,${RM} -f ${LXTEST_OFILES}, "RM      *.o")

