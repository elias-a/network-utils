CC=gcc
CFLAGS=-lpcap

objects=ping arp

all: $(objects)

$(objects): %: %.c
	$(CC) -o $@.o $< $(CFLAGS)

clean:
	rm $(objects).o
