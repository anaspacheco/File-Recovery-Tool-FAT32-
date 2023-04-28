CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra

.PHONY: all
all: nyufile

nyufile: nyufile.o 


.PHONY: clean
clean:
	rm -f *.o nyufile
