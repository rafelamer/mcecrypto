CFLAGS = -I. -O3 -lmceintegers -lmceutils -lmceecc -lz -largon2
CC = gcc

PROGRAMS = test01 test02 test03 test04 test05 test06 test07

all: $(PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROGRAMS)