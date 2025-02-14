CFLAGS = -I. -O3 -lmceintegers -lmceutils -lz -largon2
CC = gcc

PROGRAMS = test01 test02 test03 test04 test05 test06 test07 test08 test09 test10 \
test11 test12 test13

all: $(PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROGRAMS)