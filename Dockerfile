# NOTE: Docker Server to fetch docker images
ARG DOCKER_SERVER

# defines the tag of the image we should base on
ARG DOCKER_IN_TAG

# NOTE: Default build for the iccom modules
#       with its different variants
FROM ${DOCKER_SERVER}/bosch-linux-full-duplex-interface:${DOCKER_IN_TAG} AS iccom

# Base (default) version
ARG kernel_source_dir_x86=/repos/linux_x86/
ARG kernel_source_dir_arm=/repos/linux_arm/

ENV repo_path=/repos/linux-iccom
RUN rm -rf ${repo_path} && mkdir -p ${repo_path}

# allow python find extra modules
RUN echo 'export PYTHONPATH=${PYTHONPATH}:/py_mods' \
            >> ${INITRAMFS_CHROOT_X86}/root/.tests_profile
# this is needed for ICCom TTY driver testing
RUN mkdir -p ${INITRAMFS_CHROOT_X86}/py_mods \
      && pip install "Pyserial==3.4" --target "${INITRAMFS_CHROOT_X86}/py_mods"
# for independent CRC computation check
RUN mkdir -p ${INITRAMFS_CHROOT_X86}/py_mods \
      && pip install "crc==7.1.0" --target "${INITRAMFS_CHROOT_X86}/py_mods"

# add only for the container, not for an image
WORKDIR ${repo_path}
COPY . .

##  ICCom Variants Builds

# Workqueue - use the system WQ
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM \
        CONFIG_CHECK_SIGNATURE=n \
        && rm -rf ${repo_path}/*
COPY . .

# Workqueue - use the system high prio WQ
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM_HIGHPRI \
        CONFIG_CHECK_SIGNATURE=n \
        && rm -rf ${repo_path}/*
COPY . .

# Workqueue - use the private highprio WQ
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=PRIVATE \
        CONFIG_CHECK_SIGNATURE=n \
        && rm -rf ${repo_path}/*
COPY . .

# Debug with embedded defaults
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_DEBUG=y \
        CONFIG_CHECK_SIGNATURE=n  \
        && rm -rf ${repo_path}/*
COPY . .

##  ICCom & Full Duplex Test Transport Test Build
# x86
RUN make -C ${kernel_source_dir_x86} M=${repo_path}     \
        CONFIG_BOSCH_ICCOM=m                            \
        CONFIG_CHECK_SIGNATURE=n                        \
        CONFIG_ICCOM_VERSION=$(git rev-parse HEAD)      \
        CONFIG_BOSCH_FD_TEST_TRANSPORT=m                \
        CONFIG_BOSCH_ICCOM_SOCKETS=m                    \
        CONFIG_BOSCH_ICCOM_TTY=m

RUN mkdir -p ${INITRAMFS_CHROOT_X86}/modules            \
    && cp ${repo_path}/src/fd_test_transport.ko         \
          ${INITRAMFS_CHROOT_X86}/modules/              \
    && cp ${repo_path}/src/iccom.ko                     \
          ${INITRAMFS_CHROOT_X86}/modules/              \
    && cp ${repo_path}/src/iccom_socket_if.ko           \
          ${INITRAMFS_CHROOT_X86}/modules/              \
    && cp ${repo_path}/src/iccom_tty.ko                 \
          ${INITRAMFS_CHROOT_X86}/modules/

# ARM
RUN make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi-      \
        -C ${kernel_source_dir_arm} M=${repo_path}      \
            CONFIG_BOSCH_ICCOM=m                        \
            CONFIG_CHECK_SIGNATURE=n                    \
            CONFIG_ICCOM_VERSION=$(git rev-parse HEAD)  \
            CONFIG_BOSCH_FD_TEST_TRANSPORT=m            \
            CONFIG_BOSCH_ICCOM_SOCKETS=m                \
            CONFIG_BOSCH_ICCOM_TTY=m

RUN mkdir -p ${INITRAMFS_CHROOT_ARM}/modules            \
    && cp ${repo_path}/src/fd_test_transport.ko         \
          ${INITRAMFS_CHROOT_ARM}/modules/              \
    && cp ${repo_path}/src/iccom.ko                     \
          ${INITRAMFS_CHROOT_ARM}/modules/              \
    && cp ${repo_path}/src/iccom_socket_if.ko           \
          ${INITRAMFS_CHROOT_ARM}/modules/              \
    && cp ${repo_path}/src/iccom_tty.ko                 \
          ${INITRAMFS_CHROOT_ARM}/modules/

# those scripts may be used by dependendant modules, so we keep them
# in the iccom image (instead of iccom-test)
COPY test/sysfs.py                  \
      test/general_test.py          \
      test/iccom.py                 \
      test/iccom_skif.py            \
      test/iccom_testenv.py         \
      test/iccom_test.py            \
      test/iccom_skif_test.py       \
      test/iccom_tty_test.py        \
      test/iccom_main.py            \
      /builds/python-test/
RUN python-to-initramfs-x86 /builds/python-test/sysfs.py \
      && python-to-initramfs-x86 /builds/python-test/general_test.py \
      && python-to-initramfs-x86 /builds/python-test/iccom.py \
      && python-to-initramfs-x86 /builds/python-test/iccom_skif.py \
      && python-to-initramfs-x86 /builds/python-test/iccom_testenv.py \
      && python-to-initramfs-x86 /builds/python-test/iccom_test.py \
      && python-to-initramfs-x86 /builds/python-test/iccom_skif_test.py \
      && python-to-initramfs-x86 /builds/python-test/iccom_tty_test.py \
      && python-to-initramfs-x86 /builds/python-test/iccom_main.py

# NOTE: Run the qemu tests with the main
#       iccom variant
FROM iccom AS iccom-test

####### TEST BLOCK #######
#
# Taking our test module and building it
#

RUN run-qemu-tests-x86

# Check the expected results

# ICCOM
RUN grep "iccom_skif: PASS" /qemu_run_x86.log \
      && grep "iccom: PASS" /qemu_run_x86.log \
      && grep "iccom_tty: PASS" /qemu_run_x86.log

# ARM

# Create the dtb file
RUN mkdir -p /builds/linux_arm/device_tree
COPY ./device_tree/ast2500.dts /builds/linux_arm/device_tree
RUN dtc -I dts -O dtb /builds/linux_arm/device_tree/ast2500.dts > /builds/linux_arm/device_tree/ast2500.dtb

# Add shell Test
RUN mkdir -p /builds/shell-tests
COPY test/iccom_main.sh /builds/shell-tests
RUN shell-to-initramfs-arm /builds/shell-tests/iccom_main.sh

# Add shell Test
RUN mkdir -p /builds/shell-tests
COPY test/iccom_test.sh \
            test/iccom_tty_test.sh \
     /builds/shell-tests
RUN shell-to-initramfs-arm /builds/shell-tests/iccom_test.sh      \
      && shell-to-initramfs-arm /builds/shell-tests/iccom_tty_test.sh

RUN run-qemu-tests-arm /builds/linux_arm/device_tree/ast2500.dtb

# Check the expected results
RUN grep "iccom_test_0.shell.tests: PASS" /qemu_run_arm.log \
      && grep "iccom_tty_test_tty_creation.shell.tests: PASS" /qemu_run_arm.log \
      && grep "iccom_tty_test_basic_io.shell.tests: PASS" /qemu_run_arm.log
