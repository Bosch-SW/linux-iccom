#!/bin/sh
set -e

source /tests/iccom_test.sh

# Insert Modules
insmod /modules/fd_test_transport.ko
insmod /modules/iccom.ko
insmod /modules/iccom_socket_if.ko

# Main Execution
iccom_data_exchange_to_transport_with_iccom_data_with_transport_data

# Remove Modules
rmmod iccom_socket_if
rmmod iccom
rmmod fd_test_transport
dmesg