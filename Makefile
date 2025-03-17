CFLAGS = -fPIC -I. -Imceutils -Imceintegers -Imcersa -Imceecc -O3
CC = gcc
LIBS = -L/usr/local/lib -L. -lmcecrypto -largon2 -lz

FOLDERS = mceintegers mceutils mceecc mcersa
OBJECTS = mceintegers/utils.o mceintegers/addition.o mceintegers/multiplication.o mceintegers/karatsuba.o \
		  mceintegers/toomcook.o mceintegers/division.o mceintegers/modular.o mceintegers/gcd.o mceintegers/ec.o \
		  mceintegers/ecpoints.o mceintegers/slidingwindow.o mceintegers/primes.o mceutils/aes.o mceutils/base64.o \
		  mceutils/mceutils.o mceutils/hmac-sha1.o mceutils/hmac-sha256.o mceutils/hmac-sha512.o mceutils/memxor.o \
		  mceutils/sha1.o mceutils/sha256.o mceutils/sha512.o mceutils/sha3.o mcersa/sboxes.o mcersa/oaep.o mcersa/tiger.o mcersa/rsa.o \
		  mcersa/rsafiles.o mcersa/signature.o mcersa/encryption.o mceecc/ecc.o mceecc/eccfiles.o mceecc/signature.o \
		  mceecc/encryption.o
INCLUDES = mcecrypto.h
TARGET = libmcecrypto.so.1.0.0
NAME1 = libmcecrypto.so.1
NAME2 = libmcecrypto.so

all: $(FOLDERS) $(TARGET) mcecrypto

$(FOLDERS):
	make -C $@

$(TARGET): $(FOLDERS)
	ln -sf libmcecrypto.so.1.0.0 libmcecrypto.so
	$(CC) -shared -fPIC -Wl,-soname,libmcecrypto.so.1 -o $(TARGET) $(OBJECTS)

mcecrypto: cmdline.o cmdline.c mcecrypto.o
	$(CC) -o mcecrypto mcecrypto.o cmdline.o -O3 $(LIBS)

cmdline.c: cmdline.ggo
	gengetopt --input=cmdline.ggo

install: $(TARGET)
	for folder in $(FOLDERS); do \
	make install -C $$folder ; \
	done
	cp $(INCLUDES) /usr/local/include/
	cp $(TARGET) /usr/local/lib/
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME1)
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME2)
	cp mcecrypto /usr/local/bin/
	ldconfig

clean:
	for folder in $(FOLDERS); do \
	make clean -C $$folder ; \
	done
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all $(FOLDERS)
