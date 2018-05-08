EXTRA_CFLAGS=
EXTRA_CXXFLAGS=
EXTRA_LDFLAGS= -shared

include ../baseop.mak

TARGET:=libuxlib

LIBUX_SRCS=ux_output_debug.cpp ux_strop.cpp ux_args.cpp ux_time_op.cpp
LIBUX_OFILES=$(patsubst %.cpp,%.o,${LIBUX_SRCS})

ifeq (${STATICLIB},)
COMMON_LIBS:= ${TOPDIR}/libextargs.so ${TOPDIR}/libjson.so
COMMON_LDFLAGS:= -L${TOPDIR} -lextargs -ljson
else
COMMON_LIBS:= ${TOPDIR}/libextargs.a ${TOPDIR}/libjson.a
COMMON_LDFLAGS:= -L${TOPDIR} -lextargs -ljson
endif

ifeq (${STATICLIB},)
unexport STATICLIB
else
export STATICLIB
endif

ifeq (${STATICLIB},)
all:${TOPDIR}/${TARGET}.so

${TOPDIR}/${TARGET}.so:${TARGET}.so
	$(call call_exec,${CP} -f $< ${TOPDIR}/${TARGET}.so,"CP      ${TOPDIR}/${TARGET}.so")

${TARGET}.so:${LIBUX_OFILES} ${COMMON_LIBS}
	$(call call_exec,${LINK} ${LDFLAGS} -Wall -o $@ ${LIBUX_OFILES} ${COMMON_LDFLAGS},"LINK    $@")

${TOPDIR}/libextargs.so:${TOPDIR}/common/extargslib
	$(call call_exec,${MAKE} -C ${TOPDIR}/common/extargslib all, "MAKE    extargslib")

${TOPDIR}/libjson.so:${TOPDIR}/common/jsonlib
	$(call call_exec,${MAKE} -C ${TOPDIR}/common/jsonlib all,"MAKE    jsonlib")

else

all:${TOPDIR}/${TARGET}.a

${TOPDIR}/${TARGET}.a:${TARGET}.a
	$(call call_exec,${CP} -f $< ${TOPDIR}/$<,"CP      ${TOPDIR}/$<")

${TARGET}.a:${LIBUX_OFILES} ${COMMON_LIBS}
	$(call call_exec,${AR} -rcs $@ $^ ${COMMON_LIBS},"AR      $@")

${TOPDIR}/libextargs.a:${TOPDIR}/common/extargslib
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib all,"MAKE    extargslib")

${TOPDIR}/libjson.a:${TOPDIR}/common/jsonlib
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib all,"MAKE    jsonlib")

endif


ux_output_deubg.o:ux_output_deubg.cpp

ux_strop.o:ux_strop.cpp


include ../rules.mak

clean_extargslib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/extargslib clean,"CLEAN   extargslib")

clean_jsonlib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/common/jsonlib clean,"CLEAN   jsonlib")

clean:clean_extargslib clean_jsonlib
	$(call call_exec,${RM} -f ${TARGET}.so ${TARGET}.a,"RM      ${TARGET}")
	$(call call_exec,${RM} -f ${LIBUX_OFILES},"RM      *.o")
