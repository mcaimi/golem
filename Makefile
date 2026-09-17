CC = clang
CFLAGS = -O3 -Wall
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    LDFLAGS = --static
else
    LDFLAGS =
endif

OBJECTS = build/utils-obj.o build/platform-obj.o build/packetforge-obj.o build/arpoison-obj.o

default: $(OBJECTS)
	$(CC) $(LDFLAGS) -o bin/arpoison.bin $(OBJECTS)

build/utils-obj.o: src/utils.c src/utils.h src/color_codes.h
	$(CC) $(CFLAGS) -o $@ -c src/utils.c

build/platform-obj.o: src/platform.c src/platform.h src/ether-def.h
	$(CC) $(CFLAGS) -o $@ -c src/platform.c

build/packetforge-obj.o: src/packet_forge.c src/packet_forge.h src/arp.h src/ether-def.h src/platform.h
	$(CC) $(CFLAGS) -o $@ -c src/packet_forge.c -Wno-pointer-sign

build/arpoison-obj.o: src/arpoison.c src/packet_forge.h src/utils.h src/platform.h
	$(CC) $(CFLAGS) -o $@ -c src/arpoison.c

clean:
	rm -f build/*.o bin/arpoison.bin
