# To make the build reproducible, we fix the kernel headers
# version, but leave opportunity to update it.
KVER_DOCKER ?= v5.4

KVER_LOCAL?= $(shell uname -r)
KDIR_LOCAL ?= /lib/modules/$(KVER_LOCAL)/build

# NOTE: don't change this unless you're sure what you're doing
#	cause by this tag the dependent components refer to the current
#	component
DOCKER_OUT_IMAGE_TAG = iccom
DOCKER_OUT_TEST_IMAGE_TAG = iccom-test

.PHONY: test docker-image

# Creates the ICCom & Full Duplex Test Transport Test Build
default:
	$(MAKE) -C ${KDIR_LOCAL} M=$$PWD \
		CONFIG_BOSCH_ICCOM=m \
		CONFIG_ICCOM_VERSION=$(git rev-parse HEAD) \
		CONFIG_BOSCH_FD_TEST_TRANSPORT=m \
		CONFIG_BOSCH_ICCOM_SOCKETS=m

# Cleans ICCom & Full Duplex Test Transport Test Build
clean:
	$(MAKE) -C ${KDIR_LOCAL} M=$$PWD clean

# Install to current machine
install:
	$(MAKE) -C $(KDIR_LOCAL) M=$$PWD modules_install
	cp $$PWD/include/linux/iccom.h \
		/usr/src/linux-headers-${KVER_LOCAL}/include/linux/iccom.h

# Try to remove the installed driver from current machine
uninstall:
	rm -f /usr/src/linux-headers-${KVER_LOCAL}/include/linux/iccom.h
	rm -f /lib/modules/${KVER_LOCAL}/extra/src/iccom.ko
	rm -f /lib/modules/${KVER_LOCAL}/extra/src/fd_test_transport.ko

# Build Docker deployed image (Docker image with built and installed ICCom)

# This will build the reusable Docker Stage for
# other components to build the external kernel modules
docker-image:
	cd $$PWD && scripts/docker_build_wrapper.sh				\
					--progress=plain			\
					--build-arg kernel_version=${KVER_DOCKER}\
					--tag ${DOCKER_OUT_IMAGE_TAG}		\
					--target ${DOCKER_OUT_IMAGE_TAG}	\
					.					\
		&& echo "docker-image: \033[0;32mOK\033[0m"

# test if the image is really working
test: docker-image
	cd $$PWD && scripts/docker_build_wrapper.sh				\
					--build-arg kernel_version=${KVER_DOCKER}\
					--tag ${DOCKER_OUT_TEST_IMAGE_TAG}	\
					--tag ${DOCKER_OUT_TEST_IMAGE_TAG}	\
					--progress=plain			\
					.					\
		&& echo "test: \033[0;32mOK\033[0m"

# Will remove the docker image generated by the build
# and all dangling images as well
clean-docker-images:
	docker rmi ${DOCKER_OUT_IMAGE_TAG} || true
	docker rmi ${DOCKER_OUT_TEST_IMAGE_TAG} || true
	docker image prune
	docker system prune

print-output-docker-image-tag:
	@echo "${DOCKER_OUT_IMAGE_TAG}"