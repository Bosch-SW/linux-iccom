import subprocess
import zlib
from time import sleep
import errno
import os

def execute_shell_command(command):
    subprocess.run(command, shell=True)

def read_sysfs_file(file_to_read):
    try:
        # Initialize Data
        data_read = ""
        error = None
        
        # Open file & read
        with open(file_to_read, 'r') as file:
            data_read = file.read()
    except OSError as e:
        # Catch the error if any
        data_read = ""
        error = e.errno

    return str(data_read), error

def write_sysfs_file(file_to_write, content_to_write):
    try:
        # Initialize Data
        error = None
        
        # Open file & write
        with open(file_to_write, 'w') as file:
            file.write(content_to_write)
    except OSError as e:
        # Catch the error if any
        if (error != None):
            raise RuntimeError("Unexpected error trying to write\n"
                               "    (data to write:) %s \n"
                               "    (file) %s \n"
                               "    (error) %s \n"
                               % (content_to_write, file_to_write, str(e)))

def create_iccom_device():
    file = "/sys/class/iccom/create_iccom"
    command = " "
    write_sysfs_file(file, command)

def delete_iccom_device(iccom_dev):
    file = "/sys/class/iccom/delete_iccom"
    command = "%s" % (iccom_dev)
    write_sysfs_file(file, command)

def create_iccom_test_transport_device():
    file = "/sys/class/iccom_test_transport/create_transport"
    command = " "
    write_sysfs_file(file, command)

def delete_iccom_test_transport_device(transport_dev):
    file = "/sys/class/iccom_test_transport/delete_transport"
    command = "%s" % (transport_dev)
    write_sysfs_file(file, command)

def link_iccom_test_transport_device_to_iccom_device(transport_dev, iccom_dev):
    file = "/sys/devices/platform/%s/transport" % (iccom_dev)
    command = transport_dev
    write_sysfs_file(file, command)

def create_iccom_channel(iccom_dev, channel):
    file = "/sys/devices/platform/%s/channels_ctl" % (iccom_dev)
    command = "c%d" % (channel)
    write_sysfs_file(file, command)

def delete_channel(iccom_dev, channel):
    file = "/sys/devices/platform/%s/channels_ctl" % (iccom_dev)
    command = "d%d" % (channel)
    write_sysfs_file(file, command)

# Writes message to the given iccom channel
# @iccom_dev {string} id of the iccom device
# @channel {number} the destination channel id
def iccom_write(iccom_dev, channel, message):
    file = "/sys/devices/platform/%s/channels/%d" % (iccom_dev, channel)
    command = message
    write_sysfs_file(file, command)

def iccom_read(iccom_dev, channel):
    file = "/sys/devices/platform/%s/channels/%d" % (iccom_dev, channel)
    output, errorCode = read_sysfs_file(file)
    return output, errorCode

# @data bytearray to write to wire
def write_to_wire(transport_dev, data):
    print("iccom_test: simulated wire data: %s" % (data.hex(),))
    file = "/sys/devices/platform/%s/W" % (transport_dev)
    command = data.hex()
    write_sysfs_file(file, command)

# Does the full duplex exfer on wire
# @transport_dev the transport to work with
# @send_data the bytearray of the data to send
#
# RETURNS: the received data as bytearray
def wire_xfer(transport_dev, send_data):
    write_to_wire(transport_dev, send_data)
    sleep(0.1)
    return read_from_wire(transport_dev)

# Does the wire full duplex xfer and checks if the
# received data matches expected
# @transport_dev the transport to work with
# @send_data the bytearray of the data to send
# @expected_rcv_data bytearray we expect to receive
# @log_msg the extra message to the log in case of failure
#
# Throws an exception if the received data doesn't match expected
def check_wire_xfer(transport_dev, send_data, expected_rcv_data, log_msg=""):
    rcv_data = wire_xfer(transport_dev, send_data)
    if (rcv_data != expected_rcv_data):
        raise RuntimeError("Unexpected data on wire%s!\n"
                           "    %s (expected)\n"
                           "    %s (received)\n"
                           % (" (" + log_msg + ")" if len(log_msg) else ""
                              , expected_rcv_data.hex(), rcv_data.hex()))

# Does the wire full duplex ack xfer and checks if the other side
# acks as well.
# @transport_dev the transport to work with
# @log_msg the extra message to the log in case of failure
#
# Throws an exception if the other side doesn't ack
def check_wire_xfer_ack(transport_dev, log_msg=""):
        check_wire_xfer(transport_dev, iccom_ack_package()
                                     , iccom_ack_package()
                        , log_msg)

# Reads the data from the given channel of given device and checks
# if it matches the expected data.
# @iccom_device the iccom_dev name str
# @channel the channel id number
# @expected_ch_data the string which is expected to be received from
#   the channel
#
# Throws an exception if the read data doesn't match expected
def check_ch_data(iccom_device, channel, expected_ch_data, expected_error):
    # time is a bad companion, but still we need some time to allow the
    # kernel internals to work all out with 100% guarantee, to allow
    # test stability
    sleep(0.3)
    output, errorCode = iccom_read(iccom_device, channel)
    if(expected_error != None):
        if (errorCode != expected_error):
            raise RuntimeError("Unexpected error mismatch in channel!\n"
                               "    %s (expected)\n"
                               "    %s (received)\n"
                               % (expected_error, errorCode))
    else:
        if (errorCode != None):
            raise RuntimeError("Unexpected error in channel!\n"
                               "    %s (error received)\n"
                               % (errorCode))
        elif (output != expected_ch_data):
            raise RuntimeError("Unexpected data mismatch in channel!\n"
                               "    %s (expected)\n"
                               "    %s (received)\n"
                               % (expected_ch_data, output))

# RETURNS: the bytarray of wire data sent by ICCom to the wire
def read_from_wire(transport_dev):
    file = "/sys/devices/platform/%s/R" % (transport_dev)
    output, errorCode = read_sysfs_file(file)
    result = bytearray.fromhex(output)
    print("iccom_test: received wire data: %s" % (result.hex(),))
    return result

def create_transport_device_RW_files(transport_dev):
    file = "/sys/devices/platform/%s/showRW_ctl" % (transport_dev)
    command = "1"
    write_sysfs_file(file, command)

def delete_transport_device_RW_files(transport_dev):
    file = "/sys/devices/platform/%s/showRW_ctl" % (transport_dev)
    command = "0"
    write_sysfs_file(file, command)

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
#
# RETURNS: the new bytearray - a complete package ready to sent
def iccom_package(package_sequential_number, package_payload):
    PACKAGE_SIZE_BYTES = 64
    CRC32_SIZE_BYTES = 4

    if (package_sequential_number > 0xff) or (package_sequential_number < 0):
        raise ValueError("The package_sequential_number must fit the unsigned"
                         " byte in size, but now given: %s"
                         % (str(package_sequential_number)))
    if (len(package_payload) > PACKAGE_SIZE_BYTES - CRC32_SIZE_BYTES):
        raise RuntimeError("The package payload is too big: %d."
                           " It can me max %d bytes size."
                           % (len(package_payload), PACKAGE_SIZE_BYTES - CRC32_SIZE_BYTES))

    package_header = bytearray((len(package_payload)).to_bytes(2, "big")
                               + package_sequential_number.to_bytes(1, "little"))
                     
    padding_size = (PACKAGE_SIZE_BYTES - len(package_header)
                    - len(package_payload) - CRC32_SIZE_BYTES) 
    
    padded_package = package_header + package_payload + bytearray(padding_size * b"\xff")
    
    crc32 = zlib.crc32(padded_package)

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

# Checks the single package for proper on-wire layout generation
# to ensure the tests themselves are testing against proper data.
# @package_seq_id the package sequential ID
# @package_payload the bytearray of the package payload
# @hex_on_wire the raw hex-string which represents the ground-truth
#   of the on-wire data
# @log_msg the message to test
def iccom_tests_sanity_check_package(package_seq_id, package_payload
                , hex_on_wire, log_msg=""):
        expected_data = bytearray.fromhex(hex_on_wire)
        actual_data = iccom_package(package_seq_id, package_payload)
        if (expected_data != actual_data):
                raise RuntimeError("wrong on-wire package image%s!\n"
                                   "    %s (expected)\n"
                                   "    %s (received)\n"
                                   % ((" (" + log_msg + ")" if len(log_msg) else ""
                                       , expected_data.hex(), actual_data.hex())))

# Launches the test given by the callable @test_sequence
# @test_sequence can run in two modes
#   * provides the test info dict
#   * run the actual test sequence and throw in case of any errors
def iccom_test(test_sequence, params):
        try:
            test_info = test_sequence({}, get_test_info=True)
            test_id = test_info["test_id"]
            test_descr = test_info["test_description"]

            print("======== TEST: %s ========" % (test_id,))

            test_sequence(params)

            print("%s: PASS" % (test_id,))
        except Exception as e:
            print("%s: FAILED: %s (test description: %s)" % (test_id, str(e), test_descr))

# Checks if the package testing fits the on-wire picture.
#
# NOTE: this is critically needed to ensure the on-wire compatibility
#   between systems.
def iccom_tests_sanity_check(params, get_test_info=False):

        if (get_test_info):
            return { "test_description":
                        ("checks the on-wire layout for test-generated packages"
                         " to ensure that the tests themselves are on-wire correct")
                     , "test_id": "iccom_test_0.python" }

        ###### Test sequence ######
        iccom_tests_sanity_check_package(217
                , bytearray()
                , "00 00 d9 ff ff ff ff ff ff ff ff ff ff ff ff ff"
                  "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
                  "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
                  "ff ff ff ff ff ff ff ff ff ff ff ff fe 8f 31 00"
                , log_msg="sanity test msg 0")

        iccom_tests_sanity_check_package(219
                , iccom_packet(140, bytearray.fromhex("cd"), True)
                  + iccom_packet(140, bytearray.fromhex("cd"), True)
                  + iccom_packet(140, bytearray.fromhex("cd"), True)
                , "00 0f db 00 01 01 8c cd 00 01 01 8c cd 00 01 01"
                  "8c cd ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
                  "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
                  "ff ff ff ff ff ff ff ff ff ff ff ff 67 2f ba 10"
                , log_msg="sanity test msg 1")

        iccom_tests_sanity_check_package(219
                , iccom_packet(140, bytearray.fromhex("cd"), True)
                  + iccom_packet(140, bytearray.fromhex("cd"), True)
                  + iccom_packet(140, bytearray.fromhex("cd"), True)
                  + iccom_packet(140, bytearray.fromhex("cd"), True)
                , "00 14 db 00 01 01 8c cd 00 01 01 8c cd 00 01 01"
                  "8c cd 00 01 01 8c cd ff ff ff ff ff ff ff ff ff"
                  "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
                  "ff ff ff ff ff ff ff ff ff ff ff ff 25 78 d6 52"
                , log_msg="sanity test msg 2")

        iccom_tests_sanity_check_package(118
                , iccom_packet(139, bytearray.fromhex("cd"), True)
                  + iccom_packet(143, bytearray.fromhex("ff ff"), True)
                  + iccom_packet(139, bytearray.fromhex("cd"), True)
                  + iccom_packet(139, bytearray.fromhex("cd"), True)
                  + iccom_packet(2560, bytearray.fromhex(
                      "ff ff ff ba be 00 14 00 80 0f 31 03 36 2a 09 00"), True)
                  + iccom_packet(139, bytearray.fromhex("cd"), True)
                  + iccom_packet(143, bytearray.fromhex("ff ff"), True)
                  + iccom_packet(139, bytearray.fromhex("cd"), True)
                , "00 39 76 00 01 01 8b cd 00 02 01 8f ff ff 00 01"
                  "01 8b cd 00 01 01 8b cd 00 10 14 80 ff ff ff ba"
                  "be 00 14 00 80 0f 31 03 36 2a 09 00 00 01 01 8b"
                  "cd 00 02 01 8f ff ff 00 01 01 8b cd ae 7d 1e 35"
                , log_msg="sanity test msg 3")

        iccom_tests_sanity_check_package(121
                , iccom_packet(139, bytearray.fromhex("ce"), True)
                  + iccom_packet(139, bytearray.fromhex("ce"), True)
                  + iccom_packet(2560, bytearray.fromhex(
                      "ff ff ff ba be 00 14 00 80 79 85 03 37 2a 09 00"), True)
                  + iccom_packet(143, bytearray.fromhex("ff ff"), True)
                  + iccom_packet(139, bytearray.fromhex("ce"), True)
                  + iccom_packet(139, bytearray.fromhex("ce"), True)
                  + iccom_packet(139, bytearray.fromhex("ce"), True)
                  + iccom_packet(2560, bytearray.fromhex("ff ff"), False)
                , "00 39 79 00 01 01 8b ce 00 01 01 8b ce 00 10 14"
                  "80 ff ff ff ba be 00 14 00 80 79 85 03 37 2a 09"
                  "00 00 02 01 8f ff ff 00 01 01 8b ce 00 01 01 8b"
                  "ce 00 01 01 8b ce 00 02 14 00 ff ff 95 3a 1a b4"
                , log_msg="sanity test msg 4")

        iccom_tests_sanity_check_package(118
                , iccom_packet(139, bytearray.fromhex("cd"), True)
                  + iccom_packet(143, bytearray.fromhex("ff ff"), True)
                  + iccom_packet(139, bytearray.fromhex("cd"), True)
                  + iccom_packet(139, bytearray.fromhex("cd"), False)
                  + iccom_packet(2560, bytearray.fromhex(
                      "ff ff ff ba be 00 14 00 80 0f 31 03 36 2a 09 00"), False)
                  + iccom_packet(139, bytearray.fromhex("cd"), True)
                  + iccom_packet(143, bytearray.fromhex("ff ff"), True)
                  + iccom_packet(139, bytearray.fromhex("cd"), True)
                , "00 39 76 00 01 01 8b cd 00 02 01 8f ff ff 00 01"
                  "01 8b cd 00 01 01 0b cd 00 10 14 00 ff ff ff ba"
                  "be 00 14 00 80 0f 31 03 36 2a 09 00 00 01 01 8b"
                  "cd 00 02 01 8f ff ff 00 01 01 8b cd d4 f7 33 e0"
                , log_msg="sanity test msg 5")

def iccom_data_exchange_to_transport_with_iccom_data_with_transport_data(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("iccom channel -> wire && wire -> iccom channel")
                     , "test_id": "iccom_test_1.python" }

        transport_dev = params["transport_dev"]
        iccom_device = params["iccom_device "]

        ###### Test sequence ######

        create_iccom_channel(iccom_device, 1)
        create_transport_device_RW_files(transport_dev)

        # Send a message from ICCOM to iccom test transport via channel 1
        iccom_write(iccom_device, 1, "Who are you?")

        # Default xfer
        check_wire_xfer(transport_dev, iccom_package(1, bytearray())
                                     , iccom_package(1, bytearray())
                        , "first data frame")
        check_wire_xfer_ack(transport_dev, "first ack frame")

        # Actual data xfer
        check_wire_xfer(transport_dev
                        , iccom_package(2, iccom_packet(1, bytearray(b"I am Luis"), True))
                        , iccom_package(2, iccom_packet(1, bytearray(b"Who are you?"), True))
                        , "second data frame")
        check_wire_xfer_ack(transport_dev, "second ack frame")

        # Check channel data
        check_ch_data(iccom_device, 1, "I am Luis", None)


def iccom_data_exchange_to_transport_with_iccom_data_without_transport_data(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("idle package exchange with"
                                          " expected no data on the channel")
                     , "test_id": "iccom_test_2.python" }

        transport_dev = params["transport_dev"]
        iccom_device = params["iccom_device "]

        ###### Test sequence ######

        create_iccom_channel(iccom_device, 1)
        create_transport_device_RW_files(transport_dev)

        # Do (Default xfer) Data Exchange + ACK
        check_wire_xfer(transport_dev, iccom_package(1, bytearray())
                                     , iccom_package(1, bytearray())
                        , "first data frame")
        check_wire_xfer_ack(transport_dev, "first ack frame")

        # Do (Default xfer) Data Exchange + ACK
        check_wire_xfer(transport_dev
                        , iccom_package(2, bytearray())
                        , iccom_package(2, bytearray())
                        , "second data frame")
        check_wire_xfer_ack(transport_dev, "second ack frame")

        # Check that there is no channel data
        check_ch_data(iccom_device, 1, "", errno.EIO)

def iccom_data_exchange_to_transport_with_iccom_data_with_transport_data_wrong_payload_size(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": "iccom -> wire && broken wire data package -> iccom"
                     , "test_id": "iccom_test_3.python" }

        transport_dev = params["transport_dev"]
        iccom_device = params["iccom_device "]

        ###### Test sequence ######

        create_iccom_channel(iccom_device, 1)
        create_transport_device_RW_files(transport_dev)

        # Send a message from ICCOM to iccom test transport via channel 1
        iccom_write(iccom_device, 1, "Who are you?")

        # Do (Default xfer) Data Exchange + ACK
        check_wire_xfer(transport_dev, iccom_package(1, bytearray())
                                     , iccom_package(1, bytearray())
                        , "first data frame")
        check_wire_xfer_ack(transport_dev, "first ack frame")

        # Do (Default xfer) Data Exchange without ACK
        broken_package = iccom_package(2, bytearray())
        broken_package[1] = 0x02;
        check_wire_xfer(transport_dev
                        , broken_package
                        , iccom_package(2, iccom_packet(1, bytearray(b"Who are you?"), True))
                        , "second data frame")
        check_wire_xfer(transport_dev
                        , iccom_ack_package()
                        , iccom_nack_package()
                        , "expected nack on wire frame")

        # Check that there is no channel data
        check_ch_data(iccom_device, 1, "", errno.EIO)

def iccom_data_exchange_to_transport_with_iccom_data_with_transport_nack(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("iccom -> wire && wire (with nack) -> iccom"
                                          " && repeated transmission iccom -> wire")
                     , "test_id": "iccom_test_4.python" }

        transport_dev = params["transport_dev"]
        iccom_device = params["iccom_device "]

        ###### Test sequence ######

        create_iccom_channel(iccom_device, 1000)
        create_transport_device_RW_files(transport_dev)

        # Send a message from ICCOM to iccom test transport via channel 1
        iccom_write(iccom_device, 1000, "Is there anybody there?")

        # Do (Default xfer) Data Exchange + NACK
        check_wire_xfer(transport_dev, iccom_package(1, bytearray())
                                     , iccom_package(1, bytearray())
                        , "first data frame")
        check_wire_xfer_ack(transport_dev, "first ack frame")

        # ICCom sends correct data, but we complain that we have not
        # received it properly
        check_wire_xfer(transport_dev
                , iccom_package(2, bytearray())
                , iccom_package(2, iccom_packet(1000, bytearray(b"Is there anybody there?"), True))
                , "second data frame")
        check_wire_xfer(transport_dev
                , iccom_nack_package()
                , iccom_ack_package()
                , "we send nack")

        # ICCom must repeat the transmission of the data
        check_wire_xfer(transport_dev
                , iccom_package(2, bytearray())
                , iccom_package(2, iccom_packet(1000, bytearray(b"Is there anybody there?"), True))
                , "second data frame")
        check_wire_xfer_ack(transport_dev, "final ack")

        # Check that there is no channel data
        check_ch_data(iccom_device, 1000, "", errno.EIO)

def iccom_check_devices_deletion(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("iccom -> check sucessfull removal"
                                          " of all devices")
                     , "test_id": "iccom_final_test.python" }

        device_name = params["device_name"]

        ###### Test sequence ######

        CheckIccomDevicesExistance(device_name)

def iccom_test_transport_check_devices_deletion(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("iccom_test_transport -> check sucessfull removal"
                                          " of all devices")
                     , "test_id": "iccom_test_transport_final_test.python" }

        device_name = params["device_name"]

        ###### Test sequence ######

        CheckIccomDevicesExistance(device_name)

def CheckIccomDevicesExistance(device_regex):
             # Check whether all iccom devices got deleted
        command = "find /sys/devices/platform/ -iname *%s* 2> /dev/null | wc -l | awk '{printf $0}'" % (device_regex)
        devices_num = subprocess.check_output(command, shell=True, text=True)
        if (str(devices_num) != str(0)):
           raise RuntimeError("Some iccom devices were not deleted: " + str(devices_num))

if __name__ == '__main__':

        print("Inserting iccom.ko ..")
        execute_shell_command("insmod /modules/iccom.ko")

        # iccom py start

        iccom_device = []
        iccom_test_transport_device = []

        iccom_device.append("iccom.0")
        iccom_device.append("iccom.1")
        iccom_device.append("iccom.2")
        iccom_device.append("iccom.3")

        iccom_test_transport_device.append("iccom_test_transport.0")
        iccom_test_transport_device.append("iccom_test_transport.1")
        iccom_test_transport_device.append("iccom_test_transport.2")
        iccom_test_transport_device.append("iccom_test_transport.3")

        try:
           # Create iccom device instances
            for x in iccom_device:
                create_iccom_device()

            # Create iccom device instances
            for x in iccom_test_transport_device:
                create_iccom_test_transport_device()
            
            # Link tranport device to iccom
            link_iccom_test_transport_device_to_iccom_device(iccom_test_transport_device[0], iccom_device[0])
            link_iccom_test_transport_device_to_iccom_device(iccom_test_transport_device[1], iccom_device[1])
            link_iccom_test_transport_device_to_iccom_device(iccom_test_transport_device[2], iccom_device[2])
            link_iccom_test_transport_device_to_iccom_device(iccom_test_transport_device[3], iccom_device[3])
        except Exception as e:
            print("[Aborting!] Setup ICCom Tests failed!")
            print(str(e))
            os._exit(os.EX_IOERR)

        # Test #0
        iccom_test(iccom_tests_sanity_check, {})

        # Test #1
        iccom_test(iccom_data_exchange_to_transport_with_iccom_data_with_transport_data
                   , {"transport_dev": iccom_test_transport_device[1]
                      , "iccom_device ": iccom_device[1]})

        # Test #2
        iccom_test(iccom_data_exchange_to_transport_with_iccom_data_without_transport_data
                   , {"transport_dev": iccom_test_transport_device[0]
                      , "iccom_device ": iccom_device[0]})

        # Test #3
        iccom_test(iccom_data_exchange_to_transport_with_iccom_data_with_transport_data_wrong_payload_size
                   , {"transport_dev": iccom_test_transport_device[2]
                      , "iccom_device ": iccom_device[2]})

        #Test #4
        iccom_test(iccom_data_exchange_to_transport_with_iccom_data_with_transport_nack
                   , {"transport_dev": iccom_test_transport_device[3]
                      , "iccom_device ": iccom_device[3]})

       # iccom py end
        print("Removing iccom.ko ..")
        execute_shell_command("rmmod iccom.ko")

        # Final Test #1
        iccom_test(iccom_check_devices_deletion
                   , {"device_name": "iccom."})

        # Final Test #2
        iccom_test(iccom_test_transport_check_devices_deletion
                   , {"device_name": "iccom_test_transport."})