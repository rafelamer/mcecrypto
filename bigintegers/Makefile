OS = $(shell sh -c 'uname -s 2>/dev/null || echo not')
CFLAGS = -g -fPIC -I. -O3
ifeq ($(OS),Minix)
CC = clang
else
CC = gcc
endif

OBJECTS = utils.o addition.o multiplication.o karatsuba.o toomcook.o division.o \
		  modular.o gcd.o ec.o ecpoints.o slidingwindow.o primes.o

INCLUDES = bigintegers.h
TARGET = libbigintegers.so.1.0.0
NAME1 = libbigintegers.so.1
NAME2 = libbigintegers.so

$(TARGET): $(OBJECTS)
	$(CC) -shared -fPIC -Wl,-soname,libbigintegers.so.1 -o $(TARGET) $(OBJECTS)

install: $(TARGET)
	cp $(INCLUDES) /usr/local/include/
	cp $(TARGET) /usr/local/lib/
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME1) 
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME2)

clean:
	rm -f $(OBJECTS) $(TARGET)
