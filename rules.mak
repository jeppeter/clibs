

%.o : %.cpp
	$(call call_exec,${CXX} ${CXXFLAGS} ${CPU_CFLAGS} -o $@ -c $<,"CXX     $@")

%.o : %.c
	$(call call_exec,${CC} ${CFLAGS} ${CPU_CFLAGS} -o $@ -c $<,"CC      $@")