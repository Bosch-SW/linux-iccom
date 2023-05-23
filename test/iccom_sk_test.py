import errno
import socket

import iccom_common as iccom_common
import iccom_test as iccom

# Size of the header within a netlink message
NLMSG_HDR_SIZE_BYTES = 16

# Creates an iccom socket via sysfs interface
#
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_iccom_sockets_device(err_expectation):
        file = "/sys/class/iccom_socket_if/create_device"
        command = " "
        iccom_common.write_sysfs_file(file, command, err_expectation)

# Deletes an iccom socket via sysfs interface
#
# @iccom_sk_id iccom socket interface device id
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_iccom_sockets_device(iccom_sk_id, err_expectation):
        file = "/sys/class/iccom_socket_if/delete_device"
        command = "%s" % (iccom_sk_id)
        iccom_common.write_sysfs_file(file, command, err_expectation)

# Links an iccom socket to iccom device
# via sysfs interface
#
# @iccom_dev iccom device
# @iccom_sk_dev iccom socket interface devices
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def link_iccom_sockets_device_to_iccom_device(iccom_dev, iccom_sk_dev, err_expectation):
        file = "/sys/devices/platform/%s/iccom_dev" % (iccom_sk_dev)
        command = "%s" % (iccom_dev)
        iccom_common.write_sysfs_file(file, command, err_expectation)

# Set a netlink protocol family for an iccom
# socket device via sysfs interface
#
# @protocol_family_number protocol family
# @iccom_sk_dev iccom socket interface devices
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def set_socket_protocol_family(protocol_family_number, iccom_sk_dev, err_expectation):
        file = "/sys/devices/platform/%s/protocol_family" % (iccom_sk_dev)
        command = "%d" % (protocol_family_number)
        iccom_common.write_sysfs_file(file, command, err_expectation)

# Computes aligned netlink message space
#
# @payload_size payload size of netlink message
#
# RETURNS: the netlink message size
def NLMSG_SPACE(payload_size):
        size0 = (NLMSG_HDR_SIZE_BYTES + payload_size)
        return  (int(size0) // 4) * 4 + 4 * min(int(size0) % 4, 1)

# Renders the netlink message, which is compatible with ICCom
# netlink IF.
#
# @payload the message data itself (it will be wrapped into
#   iccom/netlink struct)
#
# RETURNS: the bytes array of the message
def create_netlink_msg(payload, priority):
        psize = len(payload)
        nlsize = NLMSG_SPACE(psize)
        #                           NL HEADER            PAYLOAD
        msg = bytearray(b"\x00" * NLMSG_HDR_SIZE_BYTES + payload
        #                        PADDING
                        + b"\x00" * (nlsize - NLMSG_HDR_SIZE_BYTES - psize))

        print("outgoing payload size: %d, nlsize: %d" % (psize, nlsize))
        # The first 4 bytes contain the **payload + header** size
        msg[0] = (psize + NLMSG_HDR_SIZE_BYTES) % 0x100
        msg[1] = ((psize + NLMSG_HDR_SIZE_BYTES) // 0x100) % 0x100

        # The 2 bytes after the four bytes contain the type of content --> priority
        msg[4] = (priority // 0x100) % 0x100
        msg[5] = (priority % 0x100)

        return bytearray(bytes(msg))

# Extracts the payload from netlink message
#
# @netlink_msg Netlink message to be parsed
#
# RETURNS: The payload message extracted
def extract_netlink_data(netlink_msg):
        netlink_message_length = ((netlink_msg[1] << 8) or netlink_msg[0])
        
        start_payload = NLMSG_HDR_SIZE_BYTES
        payload_length = netlink_message_length - NLMSG_HDR_SIZE_BYTES

        if len(netlink_msg) <= netlink_message_length and payload_length > 0:
            print("Ups start and end of payload in netlink message is wrong!")

        return netlink_msg[start_payload:][:payload_length]

# Test that tries to set a new protocol family to an iccom socket device
# which has already an protocol family associated
#
# @params Test parameters
# @get_test_info Test information request
def test_try_changing_protocol_family_after_initialization(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": "iccom sk -> try setting protocol family after initialization -> iccom sk"
                     , "test_id": "iccom_sk_test_1.python" }

        iccom_sk_dev = params["iccom_sk_dev"]

        # Try to set again the family protocol
        set_socket_protocol_family(28, iccom_sk_dev, errno.EPFNOSUPPORT)

# Test sending data through iccom socket to iccom and transport
# and get back an answer via iccom socket
#
# @params Test parameters
# @get_test_info Test information request
def iccom_sk_data_exchange_to_transport_with_iccom_data_with_transport_data(
                params, get_test_info=False):

        transport_dev = params["transport_dev"]
        iccom_dev = params["iccom_dev"]
        iccom_sk_dev = params["iccom_sk_dev"]
        protocol_family = params["protocol_family"]
        channel = params["channel"]

        if (get_test_info):
            return { "test_description": "iccom sk -> send data to iccom -> iccom sk"
                     , "test_id": "iccom_sk_test_protocol_family_" + str(protocol_family) + "_1.python" }

        ###### Test sequence ######
        iccom.create_iccom_sysfs_channel(iccom_dev, channel, None)
        iccom.create_transport_device_RW_files(transport_dev, None)

        # Send a message from ICCOM to Full Duplex Test Transport via channel
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol_family) as sock:
            sock.bind((channel, 0))
            sock.send(create_netlink_msg(b"Who are you?", 1))

            iccom.check_wire_xfer(transport_dev, iccom.iccom_package(1, bytearray())
                                         , iccom.iccom_package(1, bytearray())
                            , None, None, "first data frame")
            iccom.check_wire_xfer_ack(transport_dev, None, None, "first ack frame")
    
            # Actual data xfer
            iccom.check_wire_xfer(transport_dev
                            , iccom.iccom_package(2, iccom.iccom_packet(channel, bytearray(b"I am Luis"), True))
                            , iccom.iccom_package(2, iccom.iccom_packet(channel, bytearray(b"Who are you?"), True))
                            , None , None, "second data frame")
            iccom.check_wire_xfer_ack(transport_dev, None, None, "second ack frame")

            # Check channel data
            iccom.check_ch_data(iccom_dev, channel, "I am Luis", None)

            # Try to Read 1024 bytes --> We expect way less in fact
            data = sock.recv(1024)
            extracted_data = extract_netlink_data(data)
            if b"I am Luis" != extracted_data:
                 raise RuntimeError("Netlink message received from iccom socket expectation mismatch \n"
                               "    (expected) %s \n"
                               "    (received) %s \n"
                               % (b"I am Luis", extracted_data))

# Launches the test given by the callable @test_sequencescription: iccom sk -> send data to iccom
# @test_sequence can run in two modes
#   * provides the test info dict
#   * run the actual test sequence and throw in case of any errors
def iccom_sk_test(test_sequence, params):
        try:
            test_info = test_sequence(params, get_test_info=True)
            test_id = test_info["test_id"]
            test_descr = test_info["test_description"]

            print("======== TEST: %s ========" % (test_id,))

            test_sequence(params)

            print("%s: PASS" % (test_id,))
        except Exception as e:
            print("%s: FAILED: %s (test description: %s)" % (test_id, str(e), test_descr))

# Runs all the iccom socket tests
#
# @iccom_sk_dev iccom socket interface devices
# @iccom_dev iccom devices
# @fd_tt_dev full duplex transport devices
def run_tests(iccom_sk_dev, iccom_dev, fd_tt_dev):

        if(len(iccom_dev) != len(fd_tt_dev) and len(iccom_sk_dev) != len(fd_tt_dev)):
            print("Aborting! Iccom socket Tests assume that there will be the same amount of iccom sk, iccom and fd test transport devices")
            return

        number_of_devices = len(iccom_dev)

        # NETLINK_ICCOM
        protocol_family = 22 

        try:
           # Create & Link iccom and Full Duplex Test Transport device instances
            for i in range(number_of_devices):
                iccom.link_fd_test_transport_device_to_iccom_device(fd_tt_dev[i], iccom_dev[i], None)
                set_socket_protocol_family(protocol_family + i, iccom_sk_dev[i], None)
                link_iccom_sockets_device_to_iccom_device(iccom_dev[i], iccom_sk_dev[i], None)

        except Exception as e:
            print("[Aborting!] Setup ICCom SK Tests failed!")
            print(str(e))
            os._exit(os.EX_IOERR)

        # Test #1
        iccom_sk_test(test_try_changing_protocol_family_after_initialization
                   , {"iccom_sk_dev": iccom_sk_dev[0]})

        # Test #2
        iccom_sk_test(iccom_sk_data_exchange_to_transport_with_iccom_data_with_transport_data
                   , {"iccom_sk_dev": iccom_sk_dev[0]
                   , "transport_dev": fd_tt_dev[0]
                   , "iccom_dev": iccom_dev[0]
                   , "protocol_family": 22
                   , "channel": 1})

        # Test #3
        iccom_sk_test(iccom_sk_data_exchange_to_transport_with_iccom_data_with_transport_data
                   , {"iccom_sk_dev": iccom_sk_dev[1]
                   , "transport_dev": fd_tt_dev[1]
                   , "iccom_dev": iccom_dev[1]
                   , "protocol_family": 23
                   , "channel": 2})

        # Test #4
        iccom_sk_test(iccom_sk_data_exchange_to_transport_with_iccom_data_with_transport_data
                   , {"iccom_sk_dev": iccom_sk_dev[2]
                   , "transport_dev": fd_tt_dev[2]
                   , "iccom_dev": iccom_dev[2]
                   , "protocol_family": 24
                   , "channel": 2})

        # Delete iccom_sk device
        print("#### Delete iccom sk device ...")
        for i in range(number_of_devices):
                delete_iccom_sockets_device(iccom_sk_dev[i], None)
                #Delete iccom devices