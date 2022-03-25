CC=gcc
CFLAGS=-lpcap

objects=ping

all: $(objects)

$(objects): %: %.c
	$(CC) $(CFLAGS) -o $@.o $<

clean:
	rm $(objects).o
