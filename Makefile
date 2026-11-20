# make - old build will be nuked soon
# make full - runs the shitty setup.sh from the setup guide and lets you start debugging etc and look at your tarball idk
# make rebuild - rebuilds and spits out a tarball
# make fresh - fresh VM on the configured/free SSH port, nothing installed
# make clean - cleanup

.PHONY: all full rebuild fresh clean

all:
	cd src/tools && sh buildprivesc.sh
	@echo "+ built"

full:
	bash fullrun.sh

rebuild:
	perl vmbuild.pl rebuild

fresh:
	bash lab/lab.sh reset
	@echo "+ fresh vm, nothing installed"

clean:
	rm -f rootkit.tar
