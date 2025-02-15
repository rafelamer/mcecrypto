CFLAGS = -I. -O3 -lmceintegers -lmceutils -lmcersa -lz -largon2
CC = gcc

PROGRAMS = test01 test02 test03

all: $(PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROGRAMS)