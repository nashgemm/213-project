#CC := nvcc -arch sm_20

#CFLAGS := -g $(shell sdl2-config --cflags)
#LINKFLAGS := $(shell sdl2-config --libs)

##clean:
##	@rm -f cracker

#cracker: cracker.cu
#	$(CC) $(CFLAGS) -o cracker cracker.cu $(LINKFLAGS)

TARGETS = cracker.cu
LIBS = crypto
ROOT = ..
include $(ROOT)/common.mk
