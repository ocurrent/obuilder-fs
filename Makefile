all:
	$(MAKE) -C src 

install:
	cp ./install/obuilderfs /usr/local/bin/obuilderfs

clean: 
	$(MAKE) -C src clean

.PHONY: all install clean
