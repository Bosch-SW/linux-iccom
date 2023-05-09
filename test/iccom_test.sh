#!/bin/sh
set -e

create_iccom_sysfs_channel() {
    local iccom_dev=$1
    local channel=$2
    sh -c "echo -n c${channel} > /sys/devices/platform/${iccom_dev}/channels_ctl"
}

create_transport_device_RW_files() {
    local transport_dev=$1
    sh -c "echo -n c > /sys/devices/platform/${transport_dev}/transport_ctl"
}

set_iccom_sysfs_channel() {
    local iccom_dev=$1
    local channel=$2
    sh -c "echo -n s${channel} > /sys/devices/platform/${iccom_dev}/channels_ctl"
}

iccom_send() {
    local iccom_dev=$1
    local channel=$2
    local message=$3
    set_iccom_sysfs_channel ${iccom_dev} ${channel}
    sh -c "echo -n ${message} > /sys/devices/platform/${iccom_dev}/channels_RW"
}

check_wire_xfer () {
    local iccom_dev=$1
    local transport_dev=$2
    local channel=$3
    local send_data=$4
    local exp_rcv_data=$5

    # Set operating Sysfs Channel
    set_iccom_sysfs_channel ${iccom_dev} ${channel}

    # Set the data
    sh -c "echo ${send_data} > /sys/devices/platform/${transport_dev}/transport_RW"

    # Read exchanged data
    local rcv_data=$(cat "/sys/devices/platform/${transport_dev}/transport_RW")

    if [ ${rcv_data} != ${exp_rcv_data} ]
    then
        echo "Expectation failed!"
        echo "Expected: " ${exp_rcv_data}
        echo "Received: " ${rcv_data}
        exit
    fi

}

iccom_data_exchange_to_transport_with_iccom_data_with_transport_data() {
    local iccom_dev="iccom0"
    local transport_dev="fd_test_transport0"
    local channel="1"

    create_iccom_sysfs_channel ${iccom_dev} ${channel}
    create_transport_device_RW_files ${transport_dev}
    iccom_send ${iccom_dev} ${channel} "Who are you?"
    
    local send_data=000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb8c8b346
    local exp_data=000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb8c8b346
    check_wire_xfer ${iccom_dev} ${transport_dev} ${channel} ${send_data} ${exp_data}

    send_data=d0
    exp_data=d0
    check_wire_xfer ${iccom_dev} ${transport_dev} ${channel} ${send_data} ${exp_data}
    
    send_data=000d02000900814920616d204c756973ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff513d7dd4
    exp_data=001002000c008157686f2061726520796f753fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff788d44db
    check_wire_xfer ${iccom_dev} ${transport_dev} ${channel} ${send_data} ${exp_data}

    send_data=d0
    exp_data=d0
    check_wire_xfer ${iccom_dev} ${transport_dev} ${channel} ${send_data} ${exp_data}

    echo "iccom_test_0.shell.tests: PASS"
}

# Main Execution

insmod /modules/fd_test_transport.ko
insmod /modules/iccom.ko

iccom_data_exchange_to_transport_with_iccom_data_with_transport_data

rmmod iccom
rmmod fd_test_transport
dmesg