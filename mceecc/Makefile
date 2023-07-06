CFLAGS = -g -fPIC -I. -O3
CC = gcc

OBJECTS = ecc.o eccfiles.o

INCLUDES = mceecc.h
TARGET = libmceecc.so.1.0.0
NAME1 = libmceecc.so.1
NAME2 = libmceecc.so

$(TARGET): $(OBJECTS)
	$(CC) -shared -fPIC -Wl,-soname,libmceecc.so.1 -o $(TARGET) $(OBJECTS)

install: $(TARGET)
	cp $(INCLUDES) /usr/local/include/
	cp $(TARGET) /usr/local/lib/
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME1) 
	ln -sf /usr/local/lib/$(TARGET) /usr/local/lib/$(NAME2)

clean:
	rm -f $(OBJECTS) $(TARGET)
