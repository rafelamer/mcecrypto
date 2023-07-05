CFLAGS = -g -fPIC -I. -O3
CC = gcc

OBJECTS = oaep.o tiger.o rsa.o rsafiles.o signature.o encryption.o

INCLUDES = mcersa.h
TARGET = libmcersa.so.1.0.0
NAME1 = libmcersa.so.1
NAME2 = libmcersa.so

$(TARGET): $(OBJECTS)
	$(CC) -shared -fPIC -Wl,-soname,libmcersa.so.1 -o $(TARGET) $(OBJECTS)

install: $(TARGET)
	cp $(INCLUDES) /usr/local/include/
	cp $(TARGET) /usr/local/lib/
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME1) 
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME2)

clean:
	rm -f $(OBJECTS) $(TARGET)
