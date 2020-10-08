CC = gcc
CFLAGS = -Wall -O3 -fomit-frame-pointer

all: pep1_test

clean:
	rm -f -v *.o *~

distclean: clean
	rm -f -v pep1_test

pep1_test: pep1_test.o twofish_symmcrypt.o crc32.o

pep1_test.o: pep1.c
	$(CC) $(CFLAGS) -DPEP1_TEST -c $^ -o $@
