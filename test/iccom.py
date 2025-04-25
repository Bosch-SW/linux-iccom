from crc import Calculator, Crc32
from time import time

from sysfs import *

# Create an iccom devices and propagate
# the error expectations
#
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_iccom_device(err_expectation):
    print("Creating ICCom device.")
    file = "/sys/class/iccom/create_iccom"
    command = " "
    write_sysfs_file(file, command, err_expectation)

# Delete an iccom devices and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_iccom_device(iccom_dev, err_expectation):
    print("Deleting ICCom device: ", iccom_dev)
    file = "/sys/class/iccom/delete_iccom"
    command = "%s" % (iccom_dev)
    write_sysfs_file(file, command, err_expectation)

# Create an full duplex test transport device and propagate
# the error expectations
#
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_fd_test_transport_device(err_expectation):
    print("Creating FD test transport device.")
    file = "/sys/class/fd_test_transport/create_transport"
    command = " "
    write_sysfs_file(file, command, err_expectation)

# Delete an full duplex test transport device and propagate
# the error expectations
#
# @transport_dev {string} full duplex test device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_fd_test_transport_device(transport_dev, err_expectation):
    print("Deleting FD test transport device: ", transport_dev)
    file = "/sys/class/fd_test_transport/delete_transport"
    command = "%s" % (transport_dev)
    write_sysfs_file(file, command, err_expectation)

# Link an iccom to a full duplex test transport device
# and propagate the error expectations
#
# @transport_dev {string} full duplex test device name
# @iccom_dev {string} iccom device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def link_fd_test_transport_device_to_iccom_device(
          transport_dev, iccom_dev, err_expectation):
    file = "/sys/devices/platform/%s/transport" % (iccom_dev)
    command = transport_dev
    write_sysfs_file(file, command, err_expectation)

# Configure if the iccom should replace idle package on
# transport layer or not.
#
# @iccom_dev {string} iccom device name
# @replace {bool} to replace or not
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def set_idle_package_replace_policy(iccom_dev, replace, err_expectation):
    file = "/sys/devices/platform/%s/replace_empty_tx_package" % (iccom_dev)
    command = "1" if replace else "0"
    write_sysfs_file(file, command, err_expectation)

# Get idle package replacement policy.
#
# @iccom_dev {string} iccom device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
#
# RETURNS: bool if policy is set or not
def get_idle_package_replace_policy(iccom_dev, err_expectation):
    file = "/sys/devices/platform/%s/replace_empty_tx_package" % (iccom_dev)
    return (read_sysfs_file(file, err_expectation) == "1")

# Create an iccom sysfs channel and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_iccom_sysfs_channel(iccom_dev, channel, err_expectation):
    file = "/sys/devices/platform/%s/channels_ctl" % (iccom_dev)
    command = "c%d" % (channel)
    write_sysfs_file(file, command, err_expectation)

# Delete an iccom sysfs channel and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_iccom_sysfs_channel(iccom_dev, channel, err_expectation):
    file = "/sys/devices/platform/%s/channels_ctl" % (iccom_dev)
    command = "d%d" % (channel)
    write_sysfs_file(file, command, err_expectation)

# Set the iccom sysfs channel to read or write and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def set_iccom_sysfs_channel(iccom_dev, channel, err_expectation):
    file = "/sys/devices/platform/%s/channels_ctl" % (iccom_dev)
    command = "s%d" % (channel)
    write_sysfs_file(file, command, err_expectation)

# Retrieves the iccom git revision and propagate
# the error expectations
#
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# Returns:
# Empty String
# String with data read
def iccom_version(err_expectation):
    file = "/sys/class/iccom/version"
    output = read_sysfs_file(file, err_expectation)
    return output

# Writes message to the given iccom sysfs channel
#
# @iccom_dev {string} id of the iccom device
# @channel {number} the destination channel id
# @message {string} message to send
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def iccom_sysfs_send(iccom_dev, channel, message, err_expectation):
    # Set sysfs channel to work with
    set_iccom_sysfs_channel(iccom_dev, channel, None)
    # Write to the working sysfs channel
    file = "/sys/devices/platform/%s/channels_io" % (iccom_dev)
    command = message
    write_sysfs_file(file, command, err_expectation)

# Reads message from the given iccom sysfs channel and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# @timeout_ms {>=0} the timeout to wait for the data to come in ms.
#
# Returns:
# Empty String
# String with data read
def iccom_sysfs_read(iccom_dev, channel, err_expectation, timeout_ms=1000):
    # Set sysfs channel to work with
    set_iccom_sysfs_channel(iccom_dev, channel, None)
    # Read from the working sysfs channel
    file = "/sys/devices/platform/%s/channels_io" % (iccom_dev)

    start = time()
    while True:
        output = read_sysfs_file(file, err_expectation)
        if len(output) > 0:
            break
        if ((time() - start) * 1000 > timeout_ms):
            break

    return output

# Write in the full duplext test transport device the wire
# message that shall be sent later on
#
# @transport_dev {string} full duplex test device name
# @data bytearray to write to wire
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# @com_log {None or the dict with entry "log"} here the log of the
#   op shall be written if provided
def write_to_wire(transport_dev, data, err_expectation, com_log=None):
    if com_log is not None:
        if "log" not in com_log:
            com_log["log"] = ""
        com_log["log"] += ("iccom_test: simulated wire data: %s" % (data.hex(),)) + "\n"
    file = "/sys/devices/platform/%s/transport_RW" % (transport_dev)
    command = data.hex()
    write_sysfs_file(file, command, err_expectation)

# Reads the data that iccom sent to the wire and propagate
# the error expectations
#
# @transport_dev {string} full duplex test device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# @com_log {None or the dict with entry "log"} here the log of the
#   op shall be written if provided
# @timeout_ms {>=0} time to wait for non-empty result on wire.
#
# RETURNS: the bytarray of wire data sent by ICCom to the wire
def read_from_wire(transport_dev, err_expectation, com_log=None
                   , timeout_ms=1000):
    file = "/sys/devices/platform/%s/transport_RW" % (transport_dev)

    start = time()
    while True:
        output = read_sysfs_file(file, err_expectation)
        if len(output) != 0:
            break
        if ((time() - start) * 1000 > timeout_ms):
            break

    result = bytearray.fromhex(output)
    if com_log is not None:
        if "log" not in com_log:
            com_log["log"] = ""
        com_log["log"] += ("iccom_test: received wire data: %s" % (result.hex(),)) + "\n"
    return result

# Performs the full duplex xfer on wire
#
# @transport_dev {string} full duplex test device name
# @send_data the bytearray of the data to send
# @error_R_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# @error_W_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# @com_log {None or the dict with entry "log"} here the log of the
#   op shall be written if provided
#
# RETURNS: the received data as bytearray
def wire_xfer(transport_dev, send_data, error_R_expectation, error_W_expectation
              , com_log=None):
    write_to_wire(transport_dev, send_data, error_W_expectation, com_log)
    return read_from_wire(transport_dev, error_R_expectation, com_log)

# Does the wire full duplex xfer and checks if the
# received data matches expected
#
# @transport_dev {string} full duplex test device name
# @send_data the bytearray of the data to send
# @expected_rcv_data bytearray we expect to receive on wire from iccom.
#   OPTIONAL: can be a list of acceptable arrays we expect to receive
# @error_R_expectation {number} the errno which is expected
#                           to be caught on read. Example: None, errno.EIO, ...
# @error_W_expectation {number} the errno which is expected
#                           to be caught on write. Example: None, errno.EIO, ...
# @log_msg the extra message to the log in case of failure
#
# Throws an exception if the received data doesn't match expected
#
# RETURNS: the index of matched option
def check_wire_xfer(transport_dev, send_data, expected_rcv_data
                    , error_R_expectation, error_W_expectation
                    , log_msg=""):
    com_log = {}
    rcv_data = wire_xfer(transport_dev, send_data, error_R_expectation
                         , error_W_expectation, com_log)

    expected_rcv_data_list = (expected_rcv_data
                              if isinstance(expected_rcv_data, list)
                              else [expected_rcv_data,])
    match = False
    idx = 0
    for expected_data in expected_rcv_data_list:
        if (rcv_data == expected_data):
            match = True
            break
        idx += 1

    if not match:
        expected_str = ""
        i = 0

        print("*** failed sequence ***")
        if "log" in com_log:
            print(com_log["log"])
        print("*** failed sequence end ***")

        for expected_data in expected_rcv_data_list:
            expected_str += ("    expected (v%d): %s\n"
                            % (i, expected_data.hex(),))
            i += 1

        raise RuntimeError(
                ("Unexpected data on wire%s!\n"
                 % (" (" + log_msg + ")" if len(log_msg) else "",))
                + expected_str
                + ("    received: %s\n" % (rcv_data.hex(),))
            )

    return idx

# Does the wire full duplex ack xfer and checks if the other side
# acks as well.
#
# @transport_dev {string} full duplex test device name
# @error_R_expectation {number} the errno which is expected
#                           to be caught on read. Example: None, errno.EIO, ...
# @error_W_expectation {number} the errno which is expected
#                           to be caught on write. Example: None, errno.EIO, ...
#  @log_msg the extra message to the log in case of failure
#
# Throws an exception if the other side doesn't ack
def check_wire_xfer_ack(transport_dev, error_R_expectation
                        , error_W_expectation, log_msg=""):
        check_wire_xfer(transport_dev, iccom_ack_package()
                                     , iccom_ack_package()
                        , error_R_expectation, error_W_expectation, log_msg)

# Reads the data from the given channel of given device and checks
# if it matches the expected data.
#
# @iccom_dev {string} iccom device name
# @channel the channel id number
# @expected_ch_data the string which is expected to be received from
#   the channel
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
#
# Throws an exception if the read data doesn't match expected
def check_ch_data(iccom_device, channel, expected_ch_data, expected_error):
    output = iccom_sysfs_read(iccom_device, channel, expected_error)

    if (expected_error == None):
        if (output != expected_ch_data):
            raise RuntimeError("Unexpected data mismatch in channel!\n"
                               "    %s (expected)\n"
                               "    %s (received)\n"
                               % (expected_ch_data, output))

# Create the RW sysfs files for a full duplex test device and propagate
# the error expectations
#
# @transport_dev {string} full duplex test device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_transport_device_RW_files(transport_dev, err_expectation):
    file = "/sys/devices/platform/%s/transport_ctl" % (transport_dev)
    command = "c"
    write_sysfs_file(file, command, err_expectation)

# Deletes the RW sysfs files for a full duplex test device and propagate
# the error expectations
#
# @transport_dev {string} full duplex test device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_transport_device_RW_files(transport_dev, err_expectation):
    file = "/sys/devices/platform/%s/transport_ctl" % (transport_dev)
    command = "d"
    write_sysfs_file(file, command, err_expectation)

# Provides package on the basis of the package payload
# NOTE: by package payload is meant
#   * packets
# NOTE: NOT included
#   * package header
#   * padding
#   * CRC32
#
# @package_sequential_number the sequential number of the package
#   (unsigned byte in size)
# @package_payload the bytearray of the package payload part
#   (packets data)
# @package_size_bytes the TOTAL size of the package to generate.
#
# RETURNS: the new bytearray - a complete package ready to sent
def iccom_package(package_sequential_number, package_payload
                  , package_size_bytes = 64):
    CRC32_SIZE_BYTES = 4

    if (package_sequential_number > 0xff) or (package_sequential_number < 0):
        raise ValueError("The package_sequential_number must fit the unsigned"
                         " byte in size, but now given: %s"
                         % (str(package_sequential_number)))
    if (len(package_payload) > package_size_bytes - CRC32_SIZE_BYTES):
        raise RuntimeError("The package payload is too big: %d."
                           " It can me max %d bytes size."
                           % (len(package_payload), package_size_bytes - CRC32_SIZE_BYTES))

    package_header = bytearray((len(package_payload)).to_bytes(2, "big")
                               + package_sequential_number.to_bytes(1, "little"))

    padding_size = (package_size_bytes - len(package_header)
                    - len(package_payload) - CRC32_SIZE_BYTES)

    padded_package = package_header + package_payload + bytearray(padding_size * b"\xff")

    crc32 = Calculator(Crc32.CRC32).checksum(padded_package)

    full_package = padded_package + bytearray(crc32.to_bytes(CRC32_SIZE_BYTES, "little"))

    return full_package

# RETURNS: the bytearray of the ACK iccom package
def iccom_ack_package():
    return bytearray(b"\xd0")

# RETURNS: the bytearray of the NACK iccom package
def iccom_nack_package():
    return bytearray(b"\xe1")

# Renders the ICCom packet raw data.
# @channel an integer, the ICCom channel number (15 bits, unsigned)
# @payload a bytearray with payload to carry
# @complete bool - if set to True, then the packet is marked as the
#   final packet in packet sequence (last packet needed to assemble the
#   final message on the recevier side).
#
# RETURNS: the bytearray for the packet for given @channel
#   with given @payload and completeness flag
def iccom_packet(channel, payload, complete):
    return (len(payload).to_bytes(2, "big")
            + ((channel & 0x7F80) >> 7).to_bytes(1, "big")
            + ((channel & 0x007F) | (0x80 if complete else 0x00)).to_bytes(1, "big")
            + payload )

