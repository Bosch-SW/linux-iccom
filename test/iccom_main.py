import subprocess
import zlib
import time
import errno
import os
import string
import random

import iccom_common as iccom_common
import iccom_test as iccom
import iccom_sk_test as iccom_sk

if __name__ == '__main__':

    # Total number of devices for iccom and iccom sk
    iccom_sk_dev_num_for_iccom_test = 0
    iccom_dev_num_for_iccom_test = 7
    fd_tt_dev_num_for_iccom_test = 7

    iccom_sk_dev_num_for_iccom_sk_test = 3
    iccom_dev_num_for_iccom_sk_test = 3
    fd_tt_dev_num_for_iccom_sk_test = 3

    # Total number of devices
    iccom_sk_dev_num = iccom_sk_dev_num_for_iccom_test + iccom_sk_dev_num_for_iccom_sk_test
    iccom_dev_num = iccom_dev_num_for_iccom_test + iccom_dev_num_for_iccom_sk_test
    fd_tt_dev_num = fd_tt_dev_num_for_iccom_test + fd_tt_dev_num_for_iccom_sk_test

    iccom_sk_dev = []
    iccom_dev = []
    fd_tt_dev = []

    # Setup
    print("#### Inserting iccom.ko ...")
    iccom_common.execute_command("insmod /modules/iccom.ko")

    print("#### Inserting fd_test_transport.ko ...")
    iccom_common.execute_command("insmod /modules/fd_test_transport.ko")

    print("#### Inserting iccom_socket_if.ko ...")
    iccom_common.execute_command("insmod /modules/iccom_socket_if.ko")

    try:
        # Create iccom socket devices
        for i in range(iccom_sk_dev_num):
            iccom_sk_dev.append("iccom_socket_if." + str(i))
            iccom_sk.create_iccom_sockets_device(None)

        # Create iccom devices
        for i in range(iccom_dev_num):
            iccom_dev.append("iccom." + str(i))
            iccom.create_iccom_device(None)

        # Create full duplex test transport devices
        for i in range(fd_tt_dev_num):
            fd_tt_dev.append("fd_test_transport." + str(i))
            iccom.create_fd_test_transport_device(None)

    except Exception as e:
        print("[Aborting!] Main Setup failed!")
        print(str(e))
        os._exit(os.EX_IOERR)

    # Run tests
    iccom.run_tests(iccom_dev[:iccom_dev_num_for_iccom_test], fd_tt_dev[:fd_tt_dev_num_for_iccom_test])
    iccom_sk.run_tests(iccom_sk_dev, iccom_dev[iccom_dev_num_for_iccom_test:], fd_tt_dev[fd_tt_dev_num_for_iccom_test:])

    # Tear Down
    print("Removing iccom.ko ..")
    iccom_common.execute_command("rmmod iccom.ko")
    print("Removing fd_test_transport.ko ..")
    iccom_common.execute_command("rmmod fd_test_transport.ko")