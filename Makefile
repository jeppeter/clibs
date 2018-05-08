include baseop.mak

subdirs=uxlib common/extargslib common/jsonlib

all:
	@ for _i in $(subdirs) ; do ${MAKE} -C $$_i $@ ; if [ $$? -ne 0 ] ; then  ${ECHO} "can not run $$_i [all] error[$$?]" ; exit 4 ; fi ; done

clean:
	@ for _i in $(subdirs) ; do ${MAKE} -C $$_i $@ ; if [ $$? -ne 0 ] ; then  ${ECHO} "can not run $$_i [clean] error[$$?]" ; fi ; done