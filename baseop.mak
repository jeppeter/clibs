ifndef __BASEDEF_MAK__
__BASEDEF_MAK__ := 1


TOPDIR = $(shell dirname $(lastword $(MAKEFILE_LIST)))
STATICDIR = ${TOPDIR}/staticlib
DYNAMICDIR = ${TOPDIR}/dynmaiclib

PRINTF:=$(shell which printf)
OSNAME:=$(shell uname -s | tr [:upper:] [:lower:])
ECHO:=$(shell which echo)
MAKE:=$(shell which make)
PYTHON:=$(shell which python)
PERL:=$(shell which perl)
RM:=$(shell which rm)
BASH:=$(shell which bash)
DIFF:=$(shell which diff)
CHX:=$(shell which chmod) +x
GIT:=$(shell which git)
CP:=$(shell which cp)
MKDIR:=$(shell which mkdir)


ifeq (${CROSS_COMPILE},)
CC            = gcc
CXX           = g++
LINK          = g++
AR            = ar
STRIP         = strip
else
CC            = ${CROSS_COMPILE}-gcc
CXX           = ${CROSS_COMPILE}-g++
LINK          = ${CROSS_COMPILE}-g++
AR            = ${CROSS_COMPILE}-ar
STRIP         = ${CROSS_COMPILE}-strip
endif


ifeq (${MAKEVERBOSE},)
Q=@
MAKE_PRINT_FLAG= --no-print-directory
GIT_QUIET_FLAG= --quiet
else
Q=
MAKE_PRINT_FLAG=
GIT_QUIET_FLAG=
endif

ifeq (${STATICLIB},)
SHARED_CFLAGS= -fPIC
SHARED_CXXFLAGS= -fPIC
SHARED_LDFLAGS= -shared
else
SHARED_CFLAGS=
SHARED_CXXFLAGS=
SHARED_LDFLAGS=
endif


define call_exec_echo
${PRINTF} "    %-9s %s\n" $(1) $(2);
endef

define call_run_command
$(1)
endef

ifeq (${Q},)
define call_exec_directly
$(call call_run_command,$(1))
endef
else
define call_exec_directly
$(call call_exec_echo,$(2),$(3)) $(call call_run_command,$(1))
endef
endif

define call_exec
${Q}$(call call_exec_directly,$(1),$(2),$(3))
endef


ECHO          = $(shell which echo)



## __BASEDEF_MAK__
endif 