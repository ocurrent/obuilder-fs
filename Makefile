homebrew := $(shell brew --prefix)

all:
	$(MAKE) -C src 

install:
	cp ./install/obuilderfs $(homebrew)/bin/obuilderfs

clean: 
	$(MAKE) -C src clean

.PHONY: all install clean
