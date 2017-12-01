

%.o : %.cpp
	$(call call_exec,${CXX} ${CXXFLAGS} -c $< -o $@,"CXX     $@")

%.o : %.c
	$(call call_exec,${CC} ${CFLAGS} -c $< -o $@,"CC      $@")