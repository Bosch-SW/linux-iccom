# syntax=docker/dockerfile:1.3-labs

# NOTE: Default build for the iccom modules
#       with its different variants
FROM bosch-linux-full-duplex-interface:latest AS iccom

# Base (default) version
ARG kernel_source_dir=/repos/linux/

ENV repo_path=/repos/linux-iccom
RUN rm -rf ${repo_path} && mkdir -p ${repo_path}

# add only for the container, not for an image
WORKDIR ${repo_path}
COPY . .

# Workqueue - use the system WQ
RUN make -C ${kernel_source_dir} M=${repo_path} \
                CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM \
        CONFIG_CHECK_SIGNATURE=n

# Default build
RUN make -C ${kernel_source_dir} M=${repo_path} \
                CONFIG_BOSCH_ICCOM=m \
        CONFIG_CHECK_SIGNATURE=n

# Copy Default build ko to initramfs for qemu test run
RUN mkdir -p /builds/initramfs/content/modules/ && \
    cp ${repo_path}/src/iccom.ko \
    /builds/initramfs/content/modules/

# NOTE: Run the qemu tests with the main
#       iccom variant
FROM iccom AS iccom-test

####### TEST BLOCK #######
#
# Taking our test module and building it
#

# Add Python Test
COPY test/iccom_test.py /builds/python-test/
# Binarization and blobing of the test script into initramfs
RUN python-to-initramfs /builds/python-test/iccom_test.py

RUN run-qemu-tests

# Check the expected results
RUN <<EOF
        grep "iccom_test_0.python: PASS" /qemu_run.log && \
        grep "iccom_test_1.python: PASS" /qemu_run.log && \
        grep "iccom_test_2.python: PASS" /qemu_run.log && \
        grep "iccom_test_3.python: PASS" /qemu_run.log && \
        grep "iccom_test_4.python: PASS" /qemu_run.log
EOF
