

include ../../baseop.mak

SYSTEM_NAME:=$(shell uname)


TARGET  = libjson

HEADERS = jvalue.h jstring.h util.h hashtable.h arraylist.h
SOURCES = jvalue.c json.c jstring.c util.c hashtable.c arraylist.c
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

CFLAGS  = $(COMMON_CFLAGS)
CFLAGS += -I${TOPDIR}/uxlib -I${TOPDIR}/common -I${TOPDIR}/common/jsonlib
CFLAGS += -fPIC -Wall
LDFLAGS = 

ifeq ($(SYSTEM_NAME), Linux)
LDFLAGS += -shared -Wl,-soname,$(TARGET).so
endif

ifeq ($(SYSTEM_NAME), Darwin)
LDFLAGS += -dynamiclib -install_name @rpath/$(TARGET).so
endif

all : build

build: CFLAGS += $(BUILD_CFLAGS)
build: ${TOPDIR}/$(TARGET).so ${TOPDIR}/$(TARGET).a

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: ${TOPDIR}/$(TARGET).so ${TOPDIR}/$(TARGET).a

${TOPDIR}/$(TARGET).so:$(TARGET).so
	$(call call_exec,${CP} $(TARGET).so ${TOPDIR}/$(TARGET).so,"CP      ${TOPDIR}/$(TARGET).so")

$(TARGET).so: $(OBJECTS)
	$(call call_exec,${CC} $(LDFLAGS)  -o $@  $^, "LD      $@")
	

$(TARGET): $(OBJECTS)
	$(call call_exec,${CC} ${OBJECTS} -o $@ ${LDFLAGS} ${RPATH},"LD      $@")

${TOPDIR}/$(TARGET).a:$(TARGET).a
	$(call call_exec,${CP} $(TARGET).a ${TOPDIR}/$(TARGET).a,"CP      ${TOPDIR}/$(TARGET).a")

$(TARGET).a: $(OBJECTS)
	$(call call_exec,${AR} -rcs $@ $^,"AR      $@")

%.o:%.c ${HEADERS}
	$(call call_exec,${CC} ${CFLAGS} -c $< -o $@,"CC      $<")


jvalue.o:jvalue.c ${HEADERS}

json.o:json.c ${HEADERS}

jstring.o:jstring.c ${HEADERS}

util.o:util.c ${HEADERS}

hashtable.o:hashtable.c ${HEADERS}

arraylist.o:arraylist.c ${HEADERS}

clean :
	$(call call_exec,${RM} -rf $(OBJECTS) $(TARGET).so $(TARGET).a core libjson.so.dSYM,"RM      $(OBJECTS)")
	$(call call_exec,${RM} -f ${TOPDIR}/$(TARGET).so ${TOPDIR}/$(TARGET).a,"RM     $(TARGET).so $(TARGET).a")
