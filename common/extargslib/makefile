
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
all: ${DYNAMICDIR}/${TARGET}.so
else
all: ${STATICDIR}/${TARGET}.a
endif

${STATICDIR}/${TARGET}.a:${TARGET}.a ${STATICDIR}
	$(call call_exec,${CP} ${TARGET}.a ${STATICDIR}/${TARGET}.a,"CP      ${STATICDIR}/${TARGET}.a")

${DYNAMICDIR}/${TARGET}.so:${TARGET}.so ${DYNAMICDIR}
	$(call call_exec,${CP} ${TARGET}.so ${DYNAMICDIR}/${TARGET}.so,"CP      ${DYNAMICDIR}/${TARGET}.so")

${TARGET}.a:${LIB_OBJS}  $(STATICDIR)/libuxlib.a $(STATICDIR)/libjson.a
	$(call call_exec,${AR} -rcs $@ $^,"AR      $@")

${TARGET}.so:${LIB_OBJS} $(DYNAMICDIR)/libuxlib.so $(DYNAMICDIR)/libjson.so
	$(call call_exec,${CC} $(LDFLAGS) $^ -o $@,"LD      $@")

${DYNAMICDIR}:
	$(call call_exec,${MKDIR} -p $@,"MKDIR   $@")

${STATICDIR}:
	$(call call_exec,${MKDIR} -p $@,"MKDIR   $@")

$(STATICDIR)/libuxlib.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"MAKE    uxlib(static)")

$(STATICDIR)/libjson.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"MAKE    jsonlib(static)")

$(DYNAMICDIR)/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"MAKE    uxlib(dynamic)")

$(DYNAMICDIR)/libjson.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"MAKE    jsonlib(dynamic)")


%.o:%.c ${HEADERS}
	$(call call_exec,${CC} ${CFLAGS} -o $@ -c $<,"CC      $<")

extargs.o:extargs.c ${HEADERS}

debug_jvalue.o:debug_jvalue.c ${HEADERS}

clean_uxlib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib clean,"CLEAN   uxlib")
clean_json:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib clean,"CLEAN   jsonlib")

clean:clean_uxlib clean_json
	$(call call_exec,${RM} -f ${LIB_OBJS} *.o *.so *.a ${TARGET}.a ${TARGET}.so,"RM      ${LIB_OBJS}")
	$(call call_exec,${RM} -f ${DYNAMICDIR}/${TARGET}.so ${STATICDIR}/${TARGET}.a,"RM      ${TARGET}.so ${TARGET}.a")
