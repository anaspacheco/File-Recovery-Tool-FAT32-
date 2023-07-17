CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra
LDLIBS = -lcrypto

.PHONY: all
all: file_rec

nyufile: file_rec.o 


.PHONY: clean
clean:
	rm -f *.o file_rec
