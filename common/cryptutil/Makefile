

include ../../baseop.mak

SYSTEM_NAME:=$(shell uname)


TARGET  = libcryptutil

HEADERS = crypt_md5.h crypt_aes.h crypt_mulmpi.h crypt_mpi.h crypt_mpn.h crypt_rsa.h crypt_sha256.h base64_code.h
SOURCES = crypt_md5.c crypt_aes.c crypt_mpi.c crypt_mpn.c crypt_rsa.c crypt_sha256.c  base64_code.c
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

CFLAGS  = $(COMMON_CFLAGS)
CFLAGS += -I${TOPDIR}/common  -I${TOPDIR}/common/cryptutil -I${TOPDIR}/uxlib -Wall
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

$(TARGET).so: $(OBJECTS)
	$(call call_exec,${CC} $(LDFLAGS)  -o $@  $^, "LD      $@")
	


${STATICDIR}/$(TARGET).a:$(TARGET).a ${STATICDIR}
	$(call call_exec,${CP} $(TARGET).a ${STATICDIR}/$(TARGET).a,"CP      ${STATICDIR}/$(TARGET).a")

${STATICDIR}:
	$(call call_exec,${MKDIR} -p $@,"MKDIR   $@")

$(TARGET).a: $(OBJECTS)
	$(call call_exec,${AR} -rcs $@ $^,"AR      $@")


%.o:%.c ${HEADERS}
	$(call call_exec,${CC}  ${CFLAGS} ${CPU_CFLAGS} -c $< -o $@,"CC      $<")


md5.o:md5.c ${HEADERS}


clean:
	$(call call_exec,${RM} -rf $(OBJECTS) $(TARGET).so $(TARGET).a core libcryptutil.so.dSYM,"RM      $(OBJECTS)")
	$(call call_exec,${RM} -f ${DYNAMICDIR}/$(TARGET).so ${STATICDIR}/$(TARGET).a,"RM      $(TARGET).so $(TARGET).a")
