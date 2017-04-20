CC := nvcc -arch sm_20

CFLAGS := -g $(shell sdl2-config --cflags)
LINKFLAGS := $(shell sdl2-config --libs)

all: cracker

clean:
	@rm -f cracker

cracker: cracker.cu
	$(CC) $(CFLAGS) -o cracker cracker.cu $(LINKFLAGS)
