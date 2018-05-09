
include ../../../../baseop.mak

ifdef MAKEVERBOSE
VERBOSE_CFLAGS:=-D__EXTARGS_VERBOSE__
else
VERBOSE_CFLAGS:=
endif

CURDIR:=$(shell readlink -f .)

SRCS:=main.c
OBJS:=main.o
LDFLAGS:= -Wall 
ifeq (${STATICLIB},)
LIBFLAGS += -L${DYNAMICDIR} -lextargs -ljson -luxlib
else
LIBFLAGS += -L${STATICDIR} -lextargs -ljson -luxlib
endif
CFLAGS:= ${VERBOSE_CFLAGS} -I${TOPDIR}/common/extargslib -I${TOPDIR}/common -I${TOPDIR}/uxlib -Wall

ifdef STATICLIB
export STATICLIB
else
unexport STATICLIB
endif

all:opttest

ifdef STATICLIB
opttest:${OBJS} ${STATICDIR}/libuxlib.a ${STATICDIR}/libextargs.a ${STATICDIR}/libjson.a
	$(call call_exec,${CC} ${LDFLAGS}  -o $@ ${OBJS} ${LIBFLAGS},"LINK    opttest(static)")

else
opttest:${OBJS} ${DYNAMICDIR}/libuxlib.so ${DYNAMICDIR}/libextargs.so ${DYNAMICDIR}/libjson.so
	$(call call_exec,${CC} ${LDFLAGS}  -o $@ ${OBJS} ${LIBFLAGS},"LINK    opttest(dynamic)")
endif



${DYNAMICDIR}/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"LINK    uxlib(dynamic)")

${DYNAMICDIR}/libextargs.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib all,"LINK    extargslib(dynamic)")

${DYNAMICDIR}/libjson.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"LINK    jsonlib(dynamic)")


${STATICDIR}/libuxlib.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG}  -C ${TOPDIR}/uxlib all,"LINK    uxlib(static)")

${STATICDIR}/libjson.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"LINK    libjson(static)")

${STATICDIR}/libextargs.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib all,"LINK    extargslib(static)")

%.o:%.c
	$(call call_exec,${CC} ${CFLAGS} -c $< -o $@,"CC      $<")

main.c:main.c.tmpl ${TOPDIR}/coutput.py
	$(call call_exec,${PYTHON} ${TOPDIR}/coutput.py -j ${CURDIR}/test.json -i $< -o $@ all,"GEN     $@")

clean_extargslib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib clean,"CLEAN   extargslib")

clean_json:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib clean,"CLEAN   jsonlib")


clean_uxlib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib clean,"CLEAN   uxlib")


clean:clean_extargslib clean_json clean_uxlib
	$(call call_exec,${RM} -f ${OBJS} opttest main.c, "RM     opttest main.c")
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib clean,"CLEAN   uxlib")