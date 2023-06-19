OS = $(shell sh -c 'uname -s 2>/dev/null || echo not')
CFLAGS = -g -fPIC -I. -O3
ifeq ($(OS),Minix)
CC = clang
else
CC = gcc
endif

OBJECTS = aes.o base64.o compress.o der.o hmac-sha1.o hmac-sha256.o \
		  hmac-sha512.o memxor.o sha1.o sha256.o  sha512.o

INCLUDES = der.h aes.h hmac.h sha1.h sha256.h sha512.h
TARGET = libmceutils.so.1.0.0
NAME1 = libmceutils.so.1
NAME2 = libmceutils.so

$(TARGET): $(OBJECTS)
	$(CC) -shared -fPIC -Wl,-soname,libmceutils.so.1 -o $(TARGET) $(OBJECTS)

install: $(TARGET)
	cp $(INCLUDES) /usr/local/include/
	cp $(TARGET) /usr/local/lib/
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME1) 
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME2)

clean:
	rm -f $(OBJECTS) $(TARGET)
