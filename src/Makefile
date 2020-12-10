CC = gcc
CFLAGS = -Wall `pkg-config fuse --cflags --libs` 
LDFLAGS = 
OBJFILES = wormholefs.o uidmap.o
TARGET = ../install/wormholefs

all: $(TARGET)

$(TARGET): $(OBJFILES)
	mkdir -p ../install
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *~