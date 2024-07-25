#!/bin/sh
set -e

source /tests/iccom_test.sh
source /tests/iccom_tty_test.sh

# Insert Modules
insmod /modules/fd_test_transport.ko
insmod /modules/iccom.ko
insmod /modules/iccom_socket_if.ko
insmod /modules/iccom_tty.ko

# NOTE: for now test order matters (due to the package ID being
# changed by the previous interactions)

# Main Execution
iccom_data_exchange_to_transport_with_iccom_data_with_transport_data

# Main ICComTty test execution
check_iccom_tty_created
check_iccom_tty_basic_io

# Remove Modules
rmmod iccom_socket_if
rmmod iccom
rmmod fd_test_transport
dmesg