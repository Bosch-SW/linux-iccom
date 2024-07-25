#!/bin/sh
set -e

# checks if the IccomTty device is created according to the
# description in the Device Tree
check_iccom_tty_created() {
    # this comes from DT configuration, feel free to check it
    # at the REPOSITORY_ROOT/device_tree/...
    local tty_number="4"

    echo "------- list of tty's ------"
    ls -al /sys/class/tty/
    echo "--- end of list of tty's ---"
    if [ -L "/sys/class/tty/ttyICCOM${tty_number}" ]; then true; else {
        echo "Failed to find the /sys/class/tty/ttyICCOM${tty_number}  device."
        false;
    } fi

    major_minor=`cat /sys/class/tty/ttyICCOM${tty_number}/dev | sed 's/:/ /g'`
    echo "ICCom TTY ${tty_number} major and minor numbers: ${major_minor}"

    # OK, simulating udev work here
    mknod "/dev/ttyICCOM${tty_number}" c ${major_minor}

    if [ -c "/dev/ttyICCOM${tty_number}" ]; then true; else {
        echo "Failed to find the /dev/ttyICCOM${tty_number}  device."
        false;
    } fi

    echo "------- tty's in dev ------"
    ls -al /dev/tty*
    echo "--- end of tty's in dev ------"

    echo "iccom_tty_test_tty_creation.shell.tests: PASS"
}

check_iccom_tty_basic_io() {
    # this comes from DT configuration, feel free to check it
    # at the REPOSITORY_ROOT/device_tree/...
    local iccom_dev="iccom0"
    local transport_dev="fd_test_transport0"
    local channel="17435"
    local tty_number="4"

    # sending the data via serial
    echo "hello from tty" > "/dev/ttyICCOM${tty_number}"

    # empty
    local send_data=000003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9ed73dd3
    local exp_data=000002ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0dd8fa99
    check_wire_xfer ${iccom_dev} ${transport_dev} ${channel} ${send_data} ${exp_data}

    send_data=d0
    exp_data=d0
    check_wire_xfer ${iccom_dev} ${transport_dev} ${channel} ${send_data} ${exp_data}

    local expected_from_wire="hello from wire\n"
    {
      # NOTE: read will remove the final \n so we append \n on the next line
      read from_wire < "/dev/ttyICCOM${tty_number}"
      echo "${from_wire}\n" > /iccom_tty_out.txt
    } &

    # actual data
    send_data=0014040010889b68656c6c6f2066726f6d20776972650affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc4382b65
    exp_data=001303000f889b68656c6c6f2066726f6d207474790affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97cc8b97
    check_wire_xfer ${iccom_dev} ${transport_dev} ${channel} ${send_data} ${exp_data}

    send_data=d0
    exp_data=d0
    check_wire_xfer ${iccom_dev} ${transport_dev} ${channel} ${send_data} ${exp_data}

    # time is not a friend in testing, but for now we go this way
    sleep 1
    from_wire=`cat /iccom_tty_out.txt`
    rm /iccom_tty_out.txt

    if [ "${from_wire}" != "${expected_from_wire}" ]; then
        echo "TTY rcv. in user space expectation failed!"
        echo "Expected: " ${expected_from_wire}
        echo "Received: " ${from_wire}
        false
    fi

    echo "iccom_tty_test_basic_io.shell.tests: PASS"
}