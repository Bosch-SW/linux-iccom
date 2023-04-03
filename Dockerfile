# syntax=docker/dockerfile:1.3-labs

# NOTE: Default build for the iccom modules
#       with its different variants
FROM bosch-linux-full-duplex-interface:latest AS iccom

# Base (default) version
ARG kernel_source_dir_x86=/repos/linux_x86/
ARG kernel_source_dir_arm=/repos/linux_arm/

RUN cd /repos/linux && ./scripts/config --set-val CONFIG_NET y
RUN cd /repos/linux && make -j16
ARG QEMU_KERNEL_IMAGE_PATH="/builds/linux/linuz.bzImage"
RUN ls -la /builds/linux/
RUN cp /repos/linux/arch/x86/boot/bzImage    \
          ${QEMU_KERNEL_IMAGE_PATH}

ENV repo_path=/repos/linux-iccom
RUN rm -rf ${repo_path} && mkdir -p ${repo_path}

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
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        CONFIG_BOSCH_ICCOM=m \
        CONFIG_CHECK_SIGNATURE=n \
        CONFIG_ICCOM_VERSION=$(git rev-parse HEAD) \
        CONFIG_BOSCH_FD_TEST_TRANSPORT=m \
        CONFIG_BOSCH_ICCOM_SOCKETS=m

RUN mkdir -p ${INITRAMFS_CHROOT_X86}/modules              \
    && cp ${repo_path}/src/fd_test_transport.ko         \
        ${INITRAMFS_CHROOT_X86}/modules/      \
    && cp ${repo_path}/src/iccom.ko         \
    ${INITRAMFS_CHROOT_X86}/modules/ \
    && cp ${repo_path}/src/iccom_socket_if.ko         \
    ${INITRAMFS_CHROOT_X86}/modules/

# ARM
RUN make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -C ${kernel_source_dir_arm} M=${repo_path} \
        CONFIG_BOSCH_ICCOM=m \
        CONFIG_CHECK_SIGNATURE=n \
        CONFIG_ICCOM_VERSION=$(git rev-parse HEAD) \
        CONFIG_BOSCH_FD_TEST_TRANSPORT=m \
        CONFIG_BOSCH_ICCOM_SOCKETS=m

RUN mkdir -p ${INITRAMFS_CHROOT_ARM}/modules              \
    && cp ${repo_path}/src/fd_test_transport.ko         \
        ${INITRAMFS_CHROOT_ARM}/modules/      \
    && cp ${repo_path}/src/iccom.ko         \
    ${INITRAMFS_CHROOT_ARM}/modules/ \
    && cp ${repo_path}/src/iccom_socket_if.ko         \
    ${INITRAMFS_CHROOT_ARM}/modules/

# NOTE: Run the qemu tests with the main
#       iccom variant
FROM iccom AS iccom-test

####### TEST BLOCK #######
#
# Taking our test module and building it
#

ARG TEST_NAME="iccom_test"

# x86

# Add Python Test
COPY test/iccom_test.py /builds/python-test/
# Binarization and blobing of the test script into initramfs
RUN python-to-initramfs-x86 /builds/python-test/iccom_test.py

RUN run-qemu-tests-x86

# Check the expected results

RUN grep "${TEST_NAME}_0.python: PASS" /qemu_run_x86.log
RUN grep "${TEST_NAME}_1.python: PASS" /qemu_run_x86.log
RUN grep "${TEST_NAME}_2.python: PASS" /qemu_run_x86.log
RUN grep "${TEST_NAME}_3.python: PASS" /qemu_run_x86.log
RUN grep "${TEST_NAME}_4.python: PASS" /qemu_run_x86.log
RUN grep "${TEST_NAME}_5.python: PASS" /qemu_run_x86.log
RUN grep "${TEST_NAME}_6.python: PASS" /qemu_run_x86.log
RUN grep "${TEST_NAME}_final_1.python: PASS" /qemu_run_x86.log
RUN grep "${TEST_NAME}_final_2.python: PASS" /qemu_run_x86.log
RUN grep "iccom_sk_test_1: PASS" /qemu_run_x86.log

# ARM

# Create the dtb file
RUN mkdir -p /builds/linux_arm/device_tree
COPY ./device_tree/versatile-pb_iccom.dts /builds/linux_arm/device_tree
RUN dtc -I dts -O dtb /builds/linux_arm/device_tree/versatile-pb_iccom.dts > /builds/linux_arm/device_tree/versatile-pb_iccom.dtb

# Add shell Test
RUN mkdir -p /builds/shell-tests
COPY test/iccom_test.sh /builds/shell-tests
RUN shell-to-initramfs-arm /builds/shell-tests/iccom_test.sh

RUN run-qemu-tests-arm /builds/linux_arm/device_tree/versatile-pb_iccom.dtb

# Check the expected results
RUN grep "${TEST_NAME}_0.shell.tests: PASS" /qemu_run_arm.log

RUN cat /qemu_run_arm.log
