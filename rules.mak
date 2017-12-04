

%.o : %.cpp
	$(call call_exec,${CXX} ${CXXFLAGS}  -o $@ -c $<,"CXX     $@")

%.o : %.c
	$(call call_exec,${CC} ${CFLAGS} -o $@ -c $<,"CC      $@")