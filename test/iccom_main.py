import subprocess
import zlib
import time
import errno
import os
import string
import random

from iccom import iccom_version

import iccom_test
import iccom_skif_test

def execute_command(command):
    subprocess.run(command, shell=True)

if __name__ == '__main__':

    # Setup
    print("#### Inserting iccom.ko ...")
    execute_command("insmod /modules/iccom.ko")

    print("#### Inserting fd_test_transport.ko ...")
    execute_command("insmod /modules/fd_test_transport.ko")

    print("#### Inserting iccom_socket_if.ko ...")
    execute_command("insmod /modules/iccom_socket_if.ko")

    print("ICCom repository revision: %s" % (iccom_version(None),))

    # Run tests
    iccom_results = iccom_test.run_tests()
    iccom_skif_results = iccom_skif_test.run_tests()

    # Tear Down
    print("Removing iccom.ko ..")
    execute_command("rmmod iccom.ko")
    print("Removing fd_test_transport.ko ..")
    execute_command("rmmod fd_test_transport.ko")

    iccom_results.print()
    iccom_skif_results.print()