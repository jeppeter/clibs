
TOPDIR:=$(shell readlink -f ../..)
SYSTEM_NAME:=$(shell uname)

CC = gcc

TARGET  = libjson

HEADERS = jvalue.h jstring.h util.h hashtable.h arraylist.h
SOURCES = jvalue.c json.c jstring.c util.c hashtable.c arraylist.c
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

CFLAGS  = $(COMMON_CFLAGS)
CFLAGS += -I${TOPDIR}/uxlib -I${TOPDIR}/common -I${TOPDIR}/common/jsonlib
CFLAGS += -fPIC -Wall

ifeq ($(SYSTEM_NAME), Linux)
LDFLAGS += -shared -Wl,-soname,$(TARGET).so
endif

ifeq ($(SYSTEM_NAME), Darwin)
LDFLAGS += -dynamiclib -install_name @rpath/$(TARGET).so
endif

all : build

build: CFLAGS += $(BUILD_CFLAGS)
build: $(TARGET).so $(TARGET).a

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: $(TARGET).so $(TARGET).a

$(TARGET).so: $(OBJECTS)
	${CC} $(LDFLAGS)  -o $@  $^

$(TARGET): $(OBJECTS)
	${CC} ${OBJECTS} -o $@ ${LDFLAGS} ${RPATH}

$(TARGET).a: $(OBJECTS)
	${AR} -rcs $@ $^

%.o:%.c ${HEADERS}
	${CC} ${CFLAGS} -c $< -o $@


jvalue.o:jvalue.c ${HEADERS}

json.o:json.c ${HEADERS}

jstring.o:jstring.c ${HEADERS}

util.o:util.c ${HEADERS}

hashtable.o:hashtable.c ${HEADERS}

arraylist.o:arraylist.c ${HEADERS}

clean :
	rm -rf $(OBJECTS) $(TARGET).so $(TARGET).a core libjson.so.dSYM
