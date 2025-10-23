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

# RETURNS: the size of the package header
def iccom_packet_header_size():
    return 4

# Simplified parsing of the ICCom package into a dict struct.
#
# NOTE: this function is directly exposed to external world via
#       iccom-package-parser.py utility, so don't rename the
#       JSON export fields unless absolutely necessary.
#
# Example of the resulting parse result JSON:
# {
#   "type": "broken" / "data" / "ack" / "nack",
#   "error-info": error message,
#   "package_payload_size": package_payload_size,
#   "package_sequence_id": package_sequence_id,
#   "package_free_size": package_payload_free_size,
#   "free_space_offset": free_off,
#   "packets": [
#       {"ch": channel,
#        "data": <bytearray>,
#        "complete": true | false},
#       ...
#   ]
# }
#
# It can be used in the testing sequences which involve talking to the iccom
# from the wire side.
#
# @data_pkg_bytes the full sequence of package bytes from the transport layer.
# @pedantic if set to True, then will also check that the padding is properly
#   set to pad value.
def iccom_package_parse(data_pkg_bytes, pedantic=False):
    if (data_pkg_bytes == iccom_ack_package()):
        return {"type": "ack"}
    if (data_pkg_bytes == iccom_nack_package()):
        return {"type": "nack"}

    PKG_HEADER_SIZE = 3
    PKG_CRC_SIZE = 4
    if (len(data_pkg_bytes) <= PKG_HEADER_SIZE):
        return {"type": "broken", "error-info": "too small to be data package"}

    pkg_pl_size = iccom_package_get_data_size(data_pkg_bytes)
    if (len(data_pkg_bytes) < PKG_HEADER_SIZE + pkg_pl_size
                              + PKG_CRC_SIZE):
        max_avail = len(data_pkg_bytes) - PKG_HEADER_SIZE - PKG_CRC_SIZE
        return {"type": "broken"
                , "error-info": ("declared payload size (%d)"
                                 "can not fit into the package"
                                 " (max data: %d)"
                                 % (pkg_pl_size, max_avail))}

    # crc check
    computed_crc = Calculator(Crc32.CRC32).checksum(
                                data_pkg_bytes[:-PKG_CRC_SIZE])
    stated_crc = int.from_bytes(data_pkg_bytes[-PKG_CRC_SIZE:]
                                , "little", signed=False)
    if (computed_crc != stated_crc):
        computed_str = computed_crc.to_bytes(PKG_CRC_SIZE, "little").hex()
        stated_str = stated_crc.to_bytes(PKG_CRC_SIZE, "little").hex()
        return {"type": "broken"
                , "error-info": ("crc failure, computed crc is: %s"
                                 ", stamped crc is: %s"
                                 % (computed_str, stated_str))}

    # packets parsing now
    package_seq_id = int.from_bytes(data_pkg_bytes[2:3], 'little', signed=False)
    ppb = data_pkg_bytes[PKG_HEADER_SIZE : PKG_HEADER_SIZE + pkg_pl_size]
    free_space = len(data_pkg_bytes) - PKG_HEADER_SIZE - PKG_CRC_SIZE - pkg_pl_size
    free_off = PKG_HEADER_SIZE + pkg_pl_size

    res = {
        "type": "data"
        , "package_payload_size": pkg_pl_size
        , "package_sequence_id": package_seq_id
        , "package_free_size": free_space
        , "free_space_offset": free_off
        , "packets": []
    }

    PKT_HEADER_SIZE = 4

    while (len(ppb) > PKT_HEADER_SIZE):

        p_size = int.from_bytes(ppb[0:2], 'big', signed=False)
        if (len(ppb) < p_size + PKT_HEADER_SIZE):
            return {"type": "broken"
                    , "error-info": ("package claimed bigger data size (%d)"
                                    " than available (%d)"
                                    % (p_size, len(ppb) - PKT_HEADER_SIZE))}

        hi_ch = int.from_bytes(ppb[2:3], 'big', signed=False)
        lo_ch = int.from_bytes(ppb[3:4], 'big', signed=False) & 0x7F
        ch = (hi_ch << 7) | lo_ch
        complete = ((int.from_bytes(ppb[3:4], 'big', signed=False) & 0x80) == 0x80)

        pkt = {
            "ch": ch
            , "complete": complete
            , "data": ppb[PKT_HEADER_SIZE: PKT_HEADER_SIZE + p_size]
        }
        res["packets"].append(pkt)

        ppb = ppb[PKT_HEADER_SIZE + p_size:]
    
    if (len(ppb) != 0):
        return {"type": "broken"
                , "error-info": ("not all package payload used,"
                                 " leftover payload data: %s"
                                 % (ppb.hex(),))}

    if (pedantic):
        # default padding
        pad_value = 0xff
        pad_data = data_pkg_bytes[PKG_HEADER_SIZE + pkg_pl_size : -PKG_CRC_SIZE]
        for c in pad_data:
            if (c != pad_value):
                return {"type": "broken"
                        , "error-info": ("wrong payload used, value: %d"
                                         % (int(c),))}

    return res 

def iccom_package_get_data_size(data_pkg_bytes):
    return int.from_bytes(data_pkg_bytes[0:2], 'big', signed=False)

def iccom_package_set_data_size(data_pkg_bytes, data_size):
    data_pkg_bytes[0:2] = data_size.to_bytes(2, "big")[:]

def iccom_package_inc_data_size(data_pkg_bytes, increment):
    orig = iccom_package_get_data_size(data_pkg_bytes)
    res = orig + increment
    if (res < 0):
        raise RuntimeError("Asked to change the package "
                           "payload size to negative value: %d"
                           % (res,))
    if (res >= 0xffff):
        raise RuntimeError("Asked to change the package "
                           "payload size to the value which"
                           " doesn't fit the 2-byte field: %d"
                           % (res, ))
    iccom_package_set_data_size(data_pkg_bytes, res)


# Updates the package data by adding new message to it.
# NOTE: assumes that the original @package_data describes a valid package.
#
# @channel the msg channel
# @msg the data to be added to the package (full message left to be written)
# @force_max if True, we will use all possible bytes of the package
#
# RETURNS: how many msg bytes were appended to the package data
def package_append_msg(package_data, channel, msg, force_max=True):
    CRC_SIZE = 4

    p_pr = iccom_package_parse(package_data, pedantic=True)

    free = p_pr["package_free_size"]
    # if we can not append the data efficiently (at least 50% of useful data)
    # then just tell, we can't 
    if (not force_max and (free < iccom_packet_header_size() * 2)):
        return 0

    # no payload possible at all for the package
    if (free <= iccom_packet_header_size()):
        return 0

    offset = p_pr["free_space_offset"]
    use_bytes = min(free - iccom_packet_header_size(), len(msg))
    total_use_bytes = iccom_packet_header_size() + use_bytes
    end = offset + total_use_bytes
    complete = (use_bytes == len(msg))

    package_data[offset:end] = iccom_packet(channel, msg[:use_bytes], complete)[:]

    iccom_package_inc_data_size(package_data, total_use_bytes)

    crc32 = Calculator(Crc32.CRC32).checksum(package_data[:-CRC_SIZE])

    package_data[-CRC_SIZE:] = bytearray(crc32.to_bytes(CRC_SIZE, "little"))

    return use_bytes

# Serves as a simplified message delivery facility
# to deliver the completed messages to the customer. 
#
# Shall be used for the tests to communicate with real ICCom driver.
#
# Usage example:
#   ic = IccomProc(pedantic=True)
#   ic.set_ch_handler(123, my_handler_for_ch_123)
#
#   ic.send_msg(channel=42, msg=my_nice_msg)
#   to_send_out = ic.get_curr_out()
#
#   while (!got_proper_msg_on_ch_123):
#       # actual wire xfer
#       send_to_wire(to_send_out)
#       incoming_data = get_from_wire()
#   
#       to_send_out = ic.process_xfer(incoming_data)
#
class IccomProc:

    # @pedantic tells IccomProc to check the package padding for correctness.
    def __init__(self, pedantic=True):
        # channel -> handler function
        self.handlers = {}
        self.def_handler = None
        # channel -> message-under-construction (bytearray)
        self.msgs = {}
        # if to check msgs pedantically
        self.pedantic = pedantic
        # the initial state - wait for the data
        self.FRAME_DATA = 0
        self.FRAME_ACK = 1
        # current frame (how we interpret incoming data and which data we send)
        self.frame = self.FRAME_DATA
        # relevant for the ack frames - which exact ack or nack package to use
        self.ack_pkg = iccom_ack_package()
        # last-processed incoming package id
        self.last_rcv_pkg_id = -1
        # configured package size
        self.package_size = 64
        # the outgoing package to be sent on the next data frame
        # NOTE: never empty, first package is to be sent upon xfer
        self.outgoing_pkgs = [ iccom_package(0, bytearray()), ]

    # @channel the channel to assign the handler to
    # @handler the method with (int channel, bytearray msg) arguments
    #   to handle the incoming messages, the handler will be called every time
    #   when a message on the given channel is completed.
    def set_ch_handler(self, channel, handler):
        self.handlers[channel] = handler

    # Sets the default handler for all messages.
    # @handler the method with (int channel, bytearray msg) arguments
    #   to handle the incoming messages, the handler will be called every time
    #   when a message is completed and corresponding channel doesn't have
    #   channel-dedicated handler
    def set_def_ch_handler(self, handler):
        self.def_handler = handler

    # appends next empty package with proper ID to the outgoing package list
    def __append_next_empty_package(self):
        pr = iccom_package_parse(self.outgoing_pkgs[-1], self.pedantic)
        next_id = (pr["package_sequence_id"] + 1) & 0xFF
        self.outgoing_pkgs.append(iccom_package(next_id, bytearray()))

    # enqueue the message to be sent
    # NOTE: it is not really completely optimized in comparison to the real driver
    # @channel the channel number (int)
    # @msg the actual message data to send (bytearray)
    #
    # RETURN: 0 if all fine, <0 error;
    def send_msg(self, channel, msg):
        # if we're already on the ack frame we can not update the first
        # package in line (it was just sent already)
        if self.frame == self.FRAME_ACK and len(self.outgoing_pkgs) == 1:
            self.__append_next_empty_package()

        # NOTE: important: m is a deep copy of msg
        m = bytearray(msg)
        while (len(m) > 0):
            used = package_append_msg(self.outgoing_pkgs[-1], channel, m)
            m = m[used:]
            if (len(m) > 0):
                self.__append_next_empty_package()

    # RETURNS: the currently outgoing wire data, can be: ack / nack / data
    def get_curr_out(self):
        if self.frame == self.FRAME_DATA:
            return self.outgoing_pkgs[0]
        else:
            return self.ack_pkg

    # Tells what type is current outgoing data and what is expectation
    # of the incoming data.
    # RETURNS: "data" or "ack"
    def get_curr_frame_type(self):
        return "data" if self.frame == self.FRAME_DATA else "ack"

    # RETURNS: if has the package data to be sent
    def has_data_to_send(self):
        pr = iccom_package_parse(self.outgoing_pkgs[0], self.pedantic)
        return pr["package_payload_size"] > 0

    # handles the frame of the data from the other side
    # NOTE: assumes that the CURRENT XFER OUR DATA WAS ALREADY SENT OUT
    # @data_package_bytes the incoming to us wire data.
    #
    # RETURNS: what needs to be send to the wire FOR THE NEXT FRAME
    def process_xfer(self, data_package_bytes):
        pr = iccom_package_parse(data_package_bytes, self.pedantic)

        if pr["type"] == "broken":
            self.frame = self.FRAME_ACK
            self.ack_pkg = iccom_nack_package()
            return self.ack_pkg

        if self.frame == self.FRAME_DATA:
            # unexpected data from other side
            if (pr["type"] == "ack" or pr["type"] == "nack"):
                self.frame = self.FRAME_ACK
                self.ack_pkg = iccom_nack_package()
                return self.ack_pkg
            
            # already processed
            if self.last_rcv_pkg_id == pr["package_sequence_id"]:
                self.frame = self.FRAME_ACK
                self.ack_pkg = iccom_ack_package()
                return self.ack_pkg

            # all fine, process and deliver
            for pkt in pr["packets"]:
                ch = pkt["ch"]
                if ch not in self.msgs:
                    self.msgs[ch] = bytearray()

                self.msgs[ch] += pkt["data"]

                if pkt["complete"]:
                    if ch in self.handlers:
                        self.handlers[ch](ch, self.msgs[ch])
                    elif self.def_handler is not None:
                        self.def_handler(ch, self.msgs[ch])
                    else:
                        print("dropping msg to ch %d, no one listens\n" % (ch,))

                    del(self.msgs[ch])

            self.last_rcv_pkg_id = pr["package_sequence_id"]
            self.frame = self.FRAME_ACK
            self.ack_pkg = iccom_ack_package()
            return self.ack_pkg

        # expecting ack/nack frame

        if pr["type"] == "data":
            self.frame = self.FRAME_ACK
            self.ack_pkg = iccom_nack_package()
            return self.ack_pkg

        if pr["type"] == "nack":
            self.frame = self.FRAME_DATA
            self.ack_pkg = None
            return self.get_curr_out()

        self.frame = self.FRAME_DATA
        self.ack_pkg = None
        if (len(self.outgoing_pkgs) == 1):
            self.__append_next_empty_package()
        del(self.outgoing_pkgs[0])

        return self.get_curr_out()