CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

CFLAGS	:= $(CFLAGS) -O0 
CFLAGS  := $(CFLAGS) -masm=intel -Wall -Wno-pointer-arith -w

all: clean
	$(CC_x64) $(CFLAGS) -c src/elusiveMice.c -o bin/elusiveMice.x64.o 
	$(CC_x86) $(CFLAGS) -c src/elusiveMice.c -o bin/elusiveMice.x86.o 
	cp elusiveMice.cna bin

clean:
	rm -f bin/*.o
