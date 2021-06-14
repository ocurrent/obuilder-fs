CC = gcc
CFLAGS = -Wall `pkg-config fuse --cflags --libs` -D_FILE_OFFSET_BITS=64 
LDFLAGS = 
OBJFILES = obuilderfs.o uidmap.o
TARGET = ../install/obuilderfs

all: $(TARGET)

$(TARGET): $(OBJFILES)
	mkdir -p ../install
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *~
