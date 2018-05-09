
include ../../baseop.mak

CURDIR:=$(shell pwd)

ifdef MAKEVERBOSE
VERBOSE_CFLAGS:=-D__EXTARGS_VERBOSE__
VERBOSE_GFLAGS:= -g
else
VERBOSE_CFLAGS:=
VERBOSE_GFLAGS:=
endif


SRCS:=main.c
OBJS:=main.o


ifdef STATICLIB
LDFLAGS:= -Wall ${VERBOSE_GFLAGS} -L$(STATICDIR)

export STATICLIB
else
LDFLAGS:= -Wall ${VERBOSE_GFLAGS} -L$(DYNAMICDIR)

unexport STATICLIB
endif

LIBFLAGS:= -lextargs -ljson -luxlib
CFLAGS:= ${VERBOSE_CFLAGS} ${VERBOSE_GFLAGS}  -I${TOPDIR}/uxlib -I${TOPDIR}/common/extargslib -I${TOPDIR}/common -I${TOPDIR}/common/jsonlib -Wall 

all:opttest array

ifdef STATICLIB
opttest:${OBJS} ${STATICDIR}/libextargs.a $(STATICDIR)/libjson.a $(STATICDIR)/libuxlib.a
	$(call call_exec,${CC} ${LDFLAGS}  -o $@ ${OBJS} ${LIBFLAGS},"LD      opttest(static)")
else
opttest:${OBJS} $(DYNAMICDIR)/libextargs.so $(DYNAMICDIR)/libjson.so $(DYNAMICDIR)/libuxlib.so
	$(call call_exec,${CC} ${LDFLAGS}  -o $@ ${OBJS} ${LIBFLAGS},"LD      opttest(dynamic)")
endif

array:array.o
	${QUIET}${CC} ${LDFLAGS}  -o $@ $<


$(DYNAMICDIR)/libextargs.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib all,"MAKE    extargslib(dynamic)")

$(DYNAMICDIR)/libjson.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"MAKE    jsonlib(dynamic)")

$(DYNAMICDIR)/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"MAKE    uxlib(dynamic)")


$(STATICDIR)/libextargs.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib all,"MAKE    extargslib(static)")

$(STATICDIR)/libjson.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"MAKE    jsonlib(static)")

$(STATICDIR)/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"MAKE    uxlib(static)")


%.o:%.c
	$(call call_exec,${CC} ${CFLAGS} -c $< -o $@,"CC      $<")

main.c:main.c.tmpl ${TOPDIR}/coutput.py
	$(call call_exec,${PYTHON} ${TOPDIR}/coutput.py -j ${CURDIR}/test.json -i $< -o $@ all,"GEN     $@")

clean_extargslib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib clean,"CLEAN   extargslib")

clean_json:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib clean,"CLEAN   json")

clean_uxlib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib clean,"CLEAN   uxlib")


clean:clean_extargslib clean_json clean_uxlib
	$(call call_exec,${RM} -f ${OBJS} array array.o opttest main.c,"RM     main.c")
