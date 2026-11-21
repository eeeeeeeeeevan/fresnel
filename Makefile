# make - old build will be nuked soon
# make full - runs the shitty setup.sh from the setup guide and lets you start debugging etc and look at your tarball idk
# make rebuild - rebuilds and spits out a tarball
# make fresh - fresh VM on the configured/free SSH port, nothing installed
# make clean - cleanup

.PHONY: all full rebuild fresh clean

all: rebuild

full:
	bash fullrun.sh

rebuild:
	perl vmbuild.pl rebuild

clean:
	rm -f rootkit.tar
