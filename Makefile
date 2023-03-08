CC=gcc
CFLAGS=-lpcap

objects=ping

all: $(objects)

$(objects): %: %.c
	$(CC) -o $@.o $< $(CFLAGS)

clean:
	rm $(objects).o
