

include ../../baseop.mak

SYSTEM_NAME:=$(shell uname)


TARGET  = libjson

HEADERS = jvalue.h jstring.h util.h hashtable.h arraylist.h
SOURCES = jvalue.c json.c jstring.c util.c hashtable.c arraylist.c
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

CFLAGS  = $(COMMON_CFLAGS)
CFLAGS += -I${TOPDIR}/uxlib -I${TOPDIR}/common -I${TOPDIR}/common/jsonlib -Wall
ifeq (${STATICLIB},)
CFLAGS += -fPIC 
endif
LDFLAGS = 

ifeq ($(SYSTEM_NAME), Linux)
LDFLAGS += -shared -Wl,-soname,$(TARGET).so
endif

ifeq ($(SYSTEM_NAME), Darwin)
LDFLAGS += -dynamiclib -install_name @rpath/$(TARGET).so
endif

all : build

build: CFLAGS += $(BUILD_CFLAGS)
debug: CFLAGS += $(DEBUG_CFLAGS)


ifeq (${STATICLIB},)
build: ${DYNAMICDIR}/$(TARGET).so
debug: ${DYNAMICDIR}/$(TARGET).so
else
build: ${STATICDIR}/$(TARGET).a
debug: ${STATICDIR}/$(TARGET).a
endif



${DYNAMICDIR}/$(TARGET).so:$(TARGET).so ${DYNAMICDIR}
	$(call call_exec,${CP} $(TARGET).so ${DYNAMICDIR}/$(TARGET).so,"CP      ${DYNAMICDIR}/$(TARGET).so")

${DYNAMICDIR}:
	$(call call_exec,${MKDIR} -p $@,"MKDIR   $@")

$(TARGET).so: $(OBJECTS) $(DYNAMICDIR)/libuxlib.so
	$(call call_exec,${CC} $(LDFLAGS)  -o $@  $^, "LD      $@")
	


${STATICDIR}/$(TARGET).a:$(TARGET).a ${STATICDIR}
	$(call call_exec,${CP} $(TARGET).a ${STATICDIR}/$(TARGET).a,"CP      ${STATICDIR}/$(TARGET).a")

${STATICDIR}:
	$(call call_exec,${MKDIR} -p $@,"MKDIR   $@")

$(TARGET).a: $(OBJECTS) $(STATICDIR)/libuxlib.a
	$(call call_exec,${AR} -rcs $@ $^,"AR      $@")

$(DYNAMICDIR)/libuxlib.so:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib all,"MAKE    uxlib(dynamic)")

$(STATICDIR)/libuxlib.a:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}uxlib all,"MAKE    uxlib(static)")

%.o:%.c ${HEADERS}
	$(call call_exec,${CC} ${CFLAGS} -c $< -o $@,"CC      $<")


jvalue.o:jvalue.c ${HEADERS}

json.o:json.c ${HEADERS}

jstring.o:jstring.c ${HEADERS}

util.o:util.c ${HEADERS}

hashtable.o:hashtable.c ${HEADERS}

arraylist.o:arraylist.c ${HEADERS}

clean_uxlib:
	$(call call_exec,${MAKE} ${MAKE_PRINT_FLAG} -C ${TOPDIR}/uxlib clean,"CLEAN   uxlib")

clean : clean_uxlib
	$(call call_exec,${RM} -rf $(OBJECTS) $(TARGET).so $(TARGET).a core libjson.so.dSYM,"RM      $(OBJECTS)")
	$(call call_exec,${RM} -f ${DYNAMICDIR}/$(TARGET).so ${STATICDIR}/$(TARGET).a,"RM      $(TARGET).so $(TARGET).a")
