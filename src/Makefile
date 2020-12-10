CC = gcc
CFLAGS = -Wall `pkg-config fuse --cflags --libs` 
LDFLAGS = 
OBJFILES = obuilderfs.o uidmap.o
TARGET = ../install/obuilderfs

all: $(TARGET)

$(TARGET): $(OBJFILES)
	mkdir -p ../install
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *~