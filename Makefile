# Bosch ICCom Driver Makefile

KVER ?= `uname -r`
KDIR ?= /lib/modules/${KVER}/build

.PHONY: test install uninstall docker-image

# Build on current machine with given (current kernel by default) kernel
default:
	$(MAKE) -C $(KDIR) M=$$PWD \
		CONFIG_BOSCH_ICCOM=m

# Install to current machine
install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
	cp $$PWD/include/linux/iccom.h \
		/usr/src/linux-headers-${KVER}/include/linux/iccom.h

# Try to remove the installed driver from current machine
uninstall:
	rm -f /usr/src/linux-headers-${KVER}/include/linux/iccom.h
	rm -f /lib/modules/${KVER}/extra/src/iccom.ko

# Build Docker deployed image (Docker image with built and installed ICCom)
docker-image:
	cd $$PWD && sudo -u `whoami` docker build -t linux-iccom \
		-f ./Dockerfile.docker-image . \
		&& echo "docker-image: \033[0;32mOK\033[0m"

# Test ourselves in Docker environment (similar to docker-image, but
# usually builds various build configurations and if all fine, just removes
# the build artifacts)
test:
	cd $$PWD && sudo -u `whoami` docker build . \
		&& echo "test: \033[0;32mOK\033[0m"

# combines both: `test` and `docker-image` target
base: docker-image test
	echo "base: \033[0;32mOK\033[0m"
