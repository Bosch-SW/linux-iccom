import errno
import socket
import re
from time import sleep
import os

from sysfs import *
from iccom_testenv import *
import iccom_test as iccom
from iccom_skif import *
from general_test import *

# Size of the header within a netlink message
NLMSG_HDR_SIZE_BYTES = 16

# Get current routing table from iccom_skif.
#
# @iccom_sk_dev iccom socket interface devices
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
#
# RETURNS:
#       the string representing the routing table of given iccom_skif dev
def iccom_skif_get_routing_table(iccom_sk_dev, err_expectation):
        file = "/sys/devices/platform/%s/routing_table" % (iccom_sk_dev)
        return read_sysfs_file(file, err_expectation)

# Set routing table for iccom_skif.
#
# @iccom_sk_dev iccom socket interface devices
# @routing_table_str the string descriptor of the routing table.
#       EXAMPLE: "x;"  OR "123ux;123dx;" etc. see iccom_socket_if.c
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def iccom_skif_set_routing_table(iccom_sk_dev, routing_table_str, err_expectation):
        file = "/sys/devices/platform/%s/routing_table" % (iccom_sk_dev)
        return write_sysfs_file(file, routing_table_str, err_expectation)


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
# @netlink_msg Netlink message bytearray to be parsed
#
# RETURNS: The payload message extracted
def extract_netlink_data(netlink_msg):
        # **payload + header** size (without padding)
        stated_msg_len = ((netlink_msg[1] << 8) | netlink_msg[0])
        payload_len = stated_msg_len - NLMSG_HDR_SIZE_BYTES

        # payload and header definitely must fit
        if len(netlink_msg) < stated_msg_len:
            print("ill-formed netlink msg: stated size is not matching"
                  " netlink message size:\n"
                  "* stated hdr+payload size: %d\n"
                  "* real total message size: %d\n"
                  "* resulting payload size: %d\n"
                  % (stated_msg_len, len(netlink_msg)
                     , payload_len))

        return netlink_msg[NLMSG_HDR_SIZE_BYTES:][:payload_len]

# Test that tries to set a new protocol family to an iccom socket device
# which has already an protocol family associated
#
# @params Test parameters
# @get_test_info Test information request
#
# NOTE: only requirement: iccom and td_test_transport modules inserted
def test_try_changing_protocol_family_after_initialization(
              params, get_test_info=False):

        if (get_test_info):
            return { "test_description":
                        "iccom sk -> try setting protocol family"
                        " after initialization"
                     , "test_id":
                        "test_try_changing_protocol_family_after_initialization" }

        with IccomTestEnv() as te:

                updated_pf = 28

                # Try to set again the family protocol
                print("Trying to set protocol family to: %d" % (updated_pf,))
                set_socket_protocol_family(updated_pf, te.iccom_skif_name()
                                        , errno.EPFNOSUPPORT)

# returns dictionary of rules
#       [{"channel" + "direction"}] -> list of actions [{"channel" + "direction"} | "x"]
def routing_table_from_str(rt_string):
        rt_string = "".join(rt_string.split())

        # list of commands
        commands = rt_string.split(";")

        rt_dict = {}

        for cmd in commands:
                compounds = re.findall(r'\d+[ud]{1}|[x]{1}', cmd)

                if (len(compounds) == 0):
                      continue

                # overlapping entries are merged
                if compounds[0] in rt_dict:
                        rt_dict[compounds[0]] += compounds[1:]
                else:
                        rt_dict[compounds[0]] = compounds[1:]

        # remove duplicates for being graceful
        for (filter, actions) in rt_dict.items():
                non_dup_actions = []
                for action in actions:
                        if action == filter:
                                action = "x"
                        if action in non_dup_actions:
                               continue
                        non_dup_actions.append(action)
                rt_dict[filter] = non_dup_actions

        return rt_dict

# @rt is a routing table dict:
#       [{"channel" + "direction"}] -> list of actions [{"channel" + "direction"} | "x"]
# RETURNS: string representing the given routing table
def routing_table_to_str(rt):
        res = ""
        for filter in sorted(rt):
                res += filter
                for action in sorted(rt[filter]):
                        res += action
                res += ";"
        return res

# RETURNS: opmimized representation of the routing table
def routing_table_optimized_str(rt_string):
        return routing_table_to_str(routing_table_from_str(rt_string))

# RETURNS: true, when and only when given routing tables 
#       are semantically identical
def routing_tables_equal(rt_a_str, rt_b_str, a_comment, b_comment):
        rt_a = routing_table_from_str(rt_a_str)
        rt_b = routing_table_from_str(rt_b_str)

        # A in B
        for (filter, actions) in rt_a.items():
                if filter not in rt_b:
                        print("Filter %s not in B." % (filter,))
                        return  False
                for action in actions:
                        if action not in rt_b[filter]:
                                print("Action %s not in B actions: %s"
                                      % (action, str(rt_b[filter])))
                                return False
        # B in A
        for (filter, actions) in rt_b.items():
                if filter not in rt_a:
                        print("Filter %s not in A." % (filter,))
                        return  False
                for action in actions:
                        if action not in rt_a[filter]:
                                print("Action %s not in A actions: %s"
                                      % (action, str(rt_b[filter])))
                                return False
        return True

# @te ICCom test environment, to get the real table from.
# @written_rt_cmd originally written RT command
# @expected_rt what we do expect
def assert_tables_equal(te, written_rt_cmd, expected_rt):
        real_rt = ("".join(iccom_skif_get_routing_table(
                                te.iccom_skif_name(), None).split()))
        expected_rt = ("".join(expected_rt.split()))

        if (not routing_tables_equal(real_rt, expected_rt, "real", "expected")):
                raise RuntimeError(
                        "Real routing table doesn't"
                        " match written routing table (by semantics):\n"
                        " * Written routing table cmd is: %s\n"
                        " * Real routing table is: %s (%s)\n"
                        " * Expected routing table is: %s (%s)\n"
                        % (written_rt_cmd
                           , real_rt, routing_table_optimized_str(real_rt)
                           , expected_rt, routing_table_optimized_str(expected_rt)))

# Test sending data through iccom socket to iccom and transport
# and get back an answer via iccom socket
#
# @params Test parameters
# @get_test_info Test information request
def test_iccom_sk_data_comm_with_transport_level(params, get_test_info=False):

        protocol_family = 22

        ch = params["channel"]
        data_snd = params["data_snd"]
        data_rcv = params["data_rcv"]
        test_tag = params["test_tag"]

        if (get_test_info):
            return { "test_description":
                        "US -> iccom sk -> iccom -> test transport"
                        " -> iccom -> iccom sk -> US"
                     , "test_id":
                        "iccom_sk_data_comm_with_transport_level_"
                        + test_tag + ".python" }

        with IccomTestEnv() as te, socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol_family) as sock:

                # 2s is pretty enough even in testing pythonic env
                sock.settimeout(2.0)

                ###### Test sequence ######
                iccom.create_iccom_sysfs_channel(te.iccom_name(), ch, None)
                iccom.create_transport_device_RW_files(te.test_transport_name(), None)

                sock.bind((ch, 0))
                sock.send(create_netlink_msg(data_snd, 1))

                idx = iccom.check_wire_xfer(te.test_transport_name()
                                        , iccom.iccom_package(0
                                                , iccom.iccom_packet(ch, data_rcv, True), te.curr_dpkg_size())
                                        , [iccom.iccom_package(0, bytearray(), te.curr_dpkg_size())
                                           , iccom.iccom_package(1
                                                , iccom.iccom_packet(ch, data_snd, True), te.curr_dpkg_size())]
                                , None, None, "first data frame")
                iccom.check_wire_xfer_ack(te.test_transport_name()
                                        , None, None, "first ack frame")

                # Actual data xfer
                if idx == 0:
                        iccom.check_wire_xfer(te.test_transport_name()
                                        , iccom.iccom_package(1, bytearray(), te.curr_dpkg_size())
                                        , iccom.iccom_package(1
                                                        , iccom.iccom_packet(ch, data_snd, True), te.curr_dpkg_size())
                                        , None , None, "second data frame")
                        iccom.check_wire_xfer_ack(te.test_transport_name()
                                        , None, None, "second ack frame")

                # Try to Read 1024 bytes --> We expect way less in fact
                extracted_data = extract_netlink_data(sock.recv(1024))
                if data_rcv != extracted_data:
                        raise RuntimeError("Netlink message received from"
                                " iccom socket expectation mismatch \n"
                                "    (expected) %s \n"
                                "    (received) %s \n"
                                % (data_rcv, extracted_data))

# Checks that routing is OFF by default.
# that routing is disabled.
def test_iccom_sk_check_default_routing(
                params, get_test_info=False):

        if (get_test_info):
                return { "test_description":
                                "Checking routing is disabled by default."
                         , "test_id":
                                "test_iccom_sk_check_default_routing"
                        }

        with IccomTestEnv() as te:

                # initially routing must be disabled
                orig_rt = iccom_skif_get_routing_table(te.iccom_skif_name(), None)
                if (orig_rt != "d;"):
                        raise RuntimeError(
                                "Routing configuration is not disabled initially."
                                " The initial routing table is: %s" % (orig_rt,))

# Sets the routing table, checks that it was saved, then resets it, then checks
# that routing is disabled.
def test_iccom_sk_routing_set_check(
                params, get_test_info=False):

        rt = params["routing_table"]
        routing_table_name = params["routing_table_name"]

        if (get_test_info):
                return { "test_description":
                                "Set routing, then check it was saved."
                         , "test_id":
                                "test_iccom_sk_routing_set_check.%s"
                                % (routing_table_name,)
                   }

        # initially routing must be disabled
        with IccomTestEnv() as te:
                print("setting %s routing table: %s" % (routing_table_name, rt,))
                iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)
                assert_tables_equal(te, rt, rt)

# Sets the routing table then appends another one.
# Checks if resulting is a merge of two parts
def test_iccom_sk_routing_append(
                params, get_test_info=False):

        if (get_test_info):
                return { "test_description":
                                "Append to the existing table."
                         , "test_id":
                                "test_iccom_sk_routing_append"
                   }

        with IccomTestEnv() as te:
                rt = "+; 22ux10022u;"
                print("setting routing table: %s" % (rt,))
                iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)
                assert_tables_equal(te, rt, "22ux10022u;")

# Sets the routing table then appends another one.
# Checks if resulting is a merge of two parts
def test_iccom_sk_routing_double_append(
                params, get_test_info=False):

        if (get_test_info):
                return { "test_description":
                                "Double append to the existing table."
                         , "test_id":
                                "test_iccom_sk_routing_double_append"
                   }

        with IccomTestEnv() as te:

                rt = " +; 22u x  10022 u ;"
                print("setting routing table: %s" % (rt,))
                iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)

                assert_tables_equal(te, rt, "22ux10022u;")

                rt = " +; 72u 10072 u;"
                print("setting routing table: %s" % (rt,))
                iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)

                assert_tables_equal(te, rt, "22ux10022u;72u10072u;")

# Sets the routing table with new lines in the command
# Checks if resulting is a merge of two parts
def test_iccom_sk_routing_whitespace_cmd(
                params, get_test_info=False):

        if (get_test_info):
                return { "test_description":
                                "Routing command with a lot of whitespace."
                         , "test_id":
                                "test_iccom_sk_routing_whitespace_cmd"
                   }

        with IccomTestEnv() as te:

                rt = " \n \n \t 22u \t  x \t 10022 \tu ; \n \t\n "
                print("setting routing table: %s" % (rt,))
                iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)

                assert_tables_equal(te, rt, "22ux10022u;")

# Sets the routing table then appends another one with overlapping rules.
# Checks if resulting is a merge of two parts
def test_iccom_sk_routing_double_append_with_overlap(
                params, get_test_info=False):

        if (get_test_info):
                return { "test_description":
                                "Double append to the existing table with overlap."
                         , "test_id":
                                "test_iccom_sk_routing_double_overlap_append"
                   }

        with IccomTestEnv() as te:

                rt = " +; 22u x  10022 u ;"
                print("setting routing table: %s" % (rt,))
                iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)

                assert_tables_equal(te, rt, "22ux10022u;")

                rt = " +; 22u 122 u x 522u; 77u x 177u;"
                print("setting routing table: %s" % (rt,))
                iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)

                assert_tables_equal(te, rt, "22ux10022u122u522u;77ux177u;")

# Executes multiple routing cmds and then checks if the routing table
# is correct.
def test_iccom_sk_routing_multi_cmd(
                params, get_test_info=False):

        sequence_name = params["sequence_name"]
        cmds = params["cmds"]
        expected_rt = params["expected_rt"]

        if (get_test_info):
                return { "test_description":
                                "Multiple routing cmds are executed, then rt checked."
                         , "test_id":
                                "test_iccom_sk_routing_multi_cmd.%s" % (sequence_name)
                   }

        with IccomTestEnv() as te:
                for cmd in cmds:
                        rt = cmd
                        print("setting routing table: %s" % (rt,))
                        iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)

                assert_tables_equal(te, cmds, expected_rt)

# Sets the routing table cyclically many times,
# checks if it was saved properly (implies the test for )
# that routing is disabled.
def test_iccom_sk_routing_set_smoke_test(
                params, get_test_info=False):

        routing_tables = params["routing_tables"]
        routing_tables_name = params["routing_tables_name"]
        count = params["cycles"]

        if (get_test_info):
            return { "test_description":
                        "Multiple set-check cycle over given list or tables."
                     , "test_id":
                        ("test_iccom_sk_routing_set_smoke.%s"
                         % (routing_tables_name,))
                   }

        with IccomTestEnv() as te:

                # initially routing must be disabled
                print("Cycling over following tables list %d times:" % (count,))
                for rt in routing_tables:
                        print("    * table: %s" % (rt,))

                for i in range(count):
                        for rt in routing_tables:
                                iccom_skif_set_routing_table(
                                        te.iccom_skif_name(), rt, None)
                                assert_tables_equal(te, rt, rt)


# Helper for test_iccom_skif_routing_primitive.
# Makes a sinle package send & check for opened and configured device.
#
# @te IccomTestEnv
# @params the test params dictionary, test_iccom_skif_routing_primitive.
# @transport_frame {"tx": NUM, "rx": NUM} transport frame index dict to
#       start from
# @us_sockets dictionary of channel_nr -> socket
# @expected_upcast_ch_list where to expect data to pop in us
# @expected_downcast_ch_list where to expect data to pop at the bottom
#
# RETURNS: the next xfer transport frame
def __routing_primitive_test_helper(
                te, params, transport_frame, us_sockets
                , expected_upcast_ch_list, expected_downcast_ch_list):

        if params["initial_direction"] == "upwards":
                return __routing_primitive_test_helper_in_upwards(
                                te, params, transport_frame, us_sockets
                                , expected_upcast_ch_list, expected_downcast_ch_list)

        # iccom sorts internally the actions, so to make it proper without
        # parsing the packages, let's just sort it as well
        expected_downcast_ch_list = sorted(expected_downcast_ch_list)

        in_direction = params["initial_direction"]
        in_ch = params["msg_inbound_channel"]
        msg_data = params["msg_data"]

        # the optimized version when iccom replaces the idle package
        expected_wire_data_optimized_1 = bytearray()
        expected_wire_data_optimized_2 = bytearray()
        for ch in expected_downcast_ch_list[0:1]:
                expected_wire_data_optimized_1 += iccom.iccom_packet(ch, msg_data, True)
        for ch in expected_downcast_ch_list[1:]:
                expected_wire_data_optimized_2 += iccom.iccom_packet(ch, msg_data, True)

        # send the inbound msg data
        us_sockets[in_ch].send(create_netlink_msg(msg_data, 1))

        # expect all upcast channels read the message data

        for ch in expected_upcast_ch_list:
                sock = us_sockets[ch]
                try:
                        extracted_data = extract_netlink_data(sock.recv(1024))
                except:
                        raise RuntimeError("Failed to read data from"
                                        " iccom socket #%d (timeout)" % ch)

                if msg_data != extracted_data:
                        raise RuntimeError("NL msg from"
                        " iccom socket #%d != expected:\n"
                        "    (expected) %s \n"
                        "    (received) %s \n"
                        % (msg_data, extracted_data))

        if len(expected_downcast_ch_list) == 0:
                return transport_frame

        # Check downward data

        # NOTE: there is no need for now to generate a full-blown
        #       multi-packages interaction, like real iccom does,
        #       so we're limited now here to data which fits into
        #       single data package.

        expected_wire_data = bytearray()

        for ch in expected_downcast_ch_list:
                expected_wire_data += iccom.iccom_packet(ch, msg_data, True)

        # direction downwards also means that we shall start the bottom
        # communication here from scratch
        idx = iccom.check_wire_xfer(te.test_transport_name()
                        , iccom.iccom_package(transport_frame["tx"], bytearray(), te.curr_dpkg_size())
                        , [
                             iccom.iccom_package(transport_frame["rx"], bytearray(), te.curr_dpkg_size())
                             , iccom.iccom_package((transport_frame["rx"] + 1) % 0x100, expected_wire_data, te.curr_dpkg_size())
                             , iccom.iccom_package((transport_frame["rx"] + 1) % 0x100, expected_wire_data_optimized_1, te.curr_dpkg_size())
                          ]
                        , None, None, "idle data frame")
        iccom.check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "idle ack frame")
        transport_frame["rx"] = (transport_frame["rx"] + (1 if idx == 0 else 2)) % 0x100
        transport_frame["tx"] = (transport_frame["tx"] + 1) % 0x100

        # non-optimized sendout
        if idx == 0:
                iccom.check_wire_xfer(te.test_transport_name()
                        , iccom.iccom_package(transport_frame["tx"], bytearray(), te.curr_dpkg_size())
                        , iccom.iccom_package(transport_frame["rx"], expected_wire_data, te.curr_dpkg_size())
                        , None , None, "routed data frame")
                iccom.check_wire_xfer_ack(te.test_transport_name()
                                        , None, None, "routed ack frame")

                transport_frame["rx"] = (transport_frame["rx"] + 1) % 0x100
                transport_frame["tx"] = (transport_frame["tx"] + 1) % 0x100

        # optimized sendout
        if idx == 2:
                iccom.check_wire_xfer(te.test_transport_name()
                        , iccom.iccom_package(transport_frame["tx"], bytearray(), te.curr_dpkg_size())
                        , iccom.iccom_package(transport_frame["rx"], expected_wire_data_optimized_2, te.curr_dpkg_size())
                                        , None , None, "routed data frame")
                iccom.check_wire_xfer_ack(te.test_transport_name()
                                        , None, None, "routed ack frame")

                transport_frame["rx"] = (transport_frame["rx"] + 1) % 0x100
                transport_frame["tx"] = (transport_frame["tx"] + 1) % 0x100

        return transport_frame

def __routing_primitive_test_helper_in_upwards(
                te, params, transport_frame, us_sockets
                , expected_upcast_ch_list, expected_downcast_ch_list):

        # iccom sorts internally the actions, so to make it proper without
        # parsing the packages, let's just sort it as well
        expected_downcast_ch_list = sorted(expected_downcast_ch_list)

        in_ch = params["msg_inbound_channel"]
        msg_data = params["msg_data"]

        # the optimized version when iccom replaces the idle package
        expected_wire_data_optimized_1 = bytearray()
        expected_wire_data_optimized_2 = bytearray()
        for ch in expected_downcast_ch_list[0:1]:
                expected_wire_data_optimized_1 += iccom.iccom_packet(ch, msg_data, True)
        for ch in expected_downcast_ch_list[1:]:
                expected_wire_data_optimized_2 += iccom.iccom_packet(ch, msg_data, True)

        # send the inbound msg data

        # incoming direction upwards
        iccom.check_wire_xfer(te.test_transport_name()
                        , iccom.iccom_package(transport_frame["tx"]
                             , iccom.iccom_packet(in_ch, msg_data, True), te.curr_dpkg_size())
                        , iccom.iccom_package(transport_frame["rx"], bytearray(), te.curr_dpkg_size())
                        , None, None, "initial data/idle frame")
        iccom.check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "idle prerouting ack frame")
        transport_frame["rx"] = (transport_frame["rx"] + 1) % 0x100
        transport_frame["tx"] = (transport_frame["tx"] + 1) % 0x100

        # expect all upcast channels read the message data

        for ch in expected_upcast_ch_list:
                sock = us_sockets[ch]
                try:
                        extracted_data = extract_netlink_data(sock.recv(1024))
                except:
                        raise RuntimeError("Failed to read data from"
                                        " iccom socket #%d (timeout)" % ch)

                if msg_data != extracted_data:
                        raise RuntimeError("NL msg from"
                        " iccom socket #%d != expected:\n"
                        "    (expected) %s \n"
                        "    (received) %s \n"
                        % (msg_data, extracted_data))

        if len(expected_downcast_ch_list) == 0:
                return transport_frame

        # Check downward data

        # NOTE: there is no need for now to generate a full-blown
        #       multi-packages interaction, like real iccom does,
        #       so we're limited now here to data which fits into
        #       single data package.

        expected_wire_data = bytearray()

        for ch in expected_downcast_ch_list:
                expected_wire_data += iccom.iccom_packet(ch, msg_data, True)

        idx = iccom.check_wire_xfer(te.test_transport_name()
                , iccom.iccom_package(transport_frame["tx"], bytearray(), te.curr_dpkg_size())
                , [
                    iccom.iccom_package(transport_frame["rx"], expected_wire_data, te.curr_dpkg_size())
                    , iccom.iccom_package((transport_frame["rx"] + 1) % 0x100, expected_wire_data_optimized_1, te.curr_dpkg_size())
                  ]
                , None , None, "routed data frame")
        iccom.check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "routed ack frame")

        transport_frame["rx"] = (transport_frame["rx"] + (1 if idx == 0 else 2)) % 0x100
        transport_frame["tx"] = (transport_frame["tx"] + 1) % 0x100

        # partial optimized sendout
        if idx == 1:
                iccom.check_wire_xfer(te.test_transport_name()
                        , iccom.iccom_package(transport_frame["tx"], bytearray(), te.curr_dpkg_size())
                        , iccom.iccom_package(transport_frame["rx"], expected_wire_data_optimized_2, te.curr_dpkg_size())
                        , None , None, "routed data frame")
                iccom.check_wire_xfer_ack(te.test_transport_name()
                                        , None, None, "routed ack frame")

                transport_frame["rx"] = (transport_frame["rx"] + 1) % 0x100
                transport_frame["tx"] = (transport_frame["tx"] + 1) % 0x100


        return transport_frame


# * Set routing for THE channel (either incoming from bottom, or from top).
#   NOTE: routing can be to anywhere
# * Send/receive data through ICcom socket (simulate/read
#   data on iccom transport side upon need)
# NOTE: the downward casting is limited to data fitting a single data package.
#
# @params Test parameters
# @get_test_info Test information request
def test_iccom_skif_routing_primitive(params, get_test_info=False):

        if (get_test_info):
            return { "test_description":
                        "Incoming single message routing primitive test."
                        " (test transport -> iccom) | (us) -> iccom sk + routing -> US & down"
                     , "test_id":
                        ("iccom_skif_routing_primitive"
                         + ("." + params["sub_id"]) if "sub_id" in params else "")
            }

        protocol_family = 22

        in_direction = params["initial_direction"]
        in_ch = params["msg_inbound_channel"]
        upcast_ch_list = params["up_cast_channels_list"]
        downcast_ch_list = params["down_cast_channels_list"]
        extra_routes = params["extra_routing_rules"] if "extra_routing_rules" in params else ""
        cycles_count = params["cycles_count"] if "cycles_count" in params else 1
        rt = params["routing_table"] if "routing_table" in params else None

        with IccomTestEnv() as te:

                # setup the transport simulation

                iccom.create_transport_device_RW_files(te.test_transport_name(), None)

                # configure routing

                if rt is None:
                        if in_direction == "upwards":
                                rt = (("%du" % (in_ch,))
                                        + "".join(("%du" % ch) for ch in upcast_ch_list)
                                        + "".join(("%dd" % ch) for ch in downcast_ch_list)
                                        + ";")
                        else:
                                rt = (("%dd" % (in_ch,))
                                        + "".join(("%du" % ch) for ch in upcast_ch_list)
                                        + "".join(("%dd" % ch) for ch in downcast_ch_list)
                                        + ";")
                rt += extra_routes

                print("Routing table: ", rt)
                iccom_skif_set_routing_table(te.iccom_skif_name(), rt, None)
                assert_tables_equal(te, rt, rt)

                # prepare to listen US slots

                us_sockets = {}

                # add write-socket if we start with write-from-us
                us_ch_list = [ ch for ch in upcast_ch_list ]
                if in_direction == "downwards" and in_ch not in us_ch_list:
                        us_ch_list.append(in_ch)

                transport_frame =  {"tx": 0, "rx": 0}

                try:
                        # getting sockets in us
                        for us_ch in us_ch_list:
                                sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW
                                                        , protocol_family)
                                sock.bind((us_ch, 0))
                                # we MUST get and answer within 2s
                                sock.settimeout(2.0)
                                us_sockets[us_ch] = sock

                        for cycle in range(cycles_count):
                                transport_frame = __routing_primitive_test_helper(
                                                        te, params, transport_frame
                                                        , us_sockets
                                                        , upcast_ch_list 
                                                        , downcast_ch_list)

                except Exception as e:
                        for (ch, sock) in us_sockets.items():
                                sock.close()
                        raise e

                for (ch, sock) in us_sockets.items():
                        sock.close()



class IccomSkifTester(GeneralTest):

        def __init__(self, skip_list=None, run_list=None):
                super(IccomSkifTester, self).__init__("iccom_skif", skip_list, run_list)

        # Runs all the iccom socket tests
        def run_tests(self):

                # TRANSPORT SECTION #

                self.test(test_try_changing_protocol_family_after_initialization, {})

                self.test(test_iccom_sk_data_comm_with_transport_level
                        , {"channel": 1
                            , "data_snd": bytearray(b"request")
                            , "data_rcv": bytearray(b"answer")
                            , "test_tag": "simple_small_msg"
                        })

                self.test(test_iccom_sk_data_comm_with_transport_level
                        , {"channel": 2
                            , "data_snd": bytearray(b"r")
                            , "data_rcv": bytearray(b"a")
                            , "test_tag": "single_char_msg"
                        })

                self.test(test_iccom_sk_data_comm_with_transport_level
                        , {"channel": 3
                            , "data_snd": bytearray(b"r" * 50) # limited to 56 to fit
                            , "data_rcv": bytearray(b"a" * 50) # single data frame
                            , "test_tag": "50char_msg"
                        })

                self.test(test_iccom_sk_data_comm_with_transport_level
                        , {"channel": 4
                            , "data_snd": bytearray(b"r" * 10) # limited to 56 to fit
                            , "data_rcv": bytearray(b"a" * 40) # single data frame
                            , "test_tag": "asymetric_msg_10_and_40_chars"
                        })

                # ROUTING SECTION #

                self.test(test_iccom_sk_check_default_routing, {})

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "x;"
                            , "routing_table_name": "default"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "100ux;100dx;"
                            , "routing_table_name": "100_ch_bidirectional"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "1u1u2d3u;"
                            , "routing_table_name": "1u_ch_multicast"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "1ux2d3u;"
                            , "routing_table_name": "1u_ch_multicast_and_default"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "1ux2d3ux;"
                            , "routing_table_name": "1u_ch_multicast_and_2x_default"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "10ux;12ux17u17d;14dx;1ux2d3u;"
                            , "routing_table_name": "mixed_1v"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "10ux;12ux17u17d;14dx;1ux2dx3uxx;"
                            , "routing_table_name": "mixed_2v_multiple_default_actions"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "10ux;12ux17u17d;14dx;14dx;1ux2dx3uxx;"
                            , "routing_table_name": "mixed_3v_multiple_default_actions_double_entries"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "10ux;12ux17u17d;14dx;14dx1u2u;1ux2dx3uxx;"
                            , "routing_table_name": "mixed_3v_multiple_default_actions_overload_entries"
                        })

                self.test(test_iccom_sk_routing_append, {})
                self.test(test_iccom_sk_routing_double_append, {})
                self.test(test_iccom_sk_routing_whitespace_cmd, {})
                self.test(test_iccom_sk_routing_double_append_with_overlap, {})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "append_overlap"
                                , "cmds": ["+;1u2d1u4u;"
                                           , "+;1ux2d5u;22ux44u;"]
                                , "expected_rt": "1ux2d4u5u;22ux44u;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "append_full_overlap"
                                , "cmds": ["+;1u2d1u4u;"
                                           , "+;1ux2d4u;22ux44u;"]
                                , "expected_rt": "1ux2d4u;22ux44u;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "append_no_overlap"
                                , "cmds": ["+;1u2d1u4u;"
                                           , "+;1u10u11u;22ux44u;"]
                                , "expected_rt": "1ux2d4u10u11u;22ux44u;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "append_1_overlap"
                                , "cmds": ["+;1u2d1u4u;"
                                           , "+;1u2d;22ux44u;"]
                                , "expected_rt": "1ux2d4u;22ux44u;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "append_1_no_overlap"
                                , "cmds": ["+;1u2d1u4u;"
                                           , "+;1u10u;22ux44u;"]
                                , "expected_rt": "1ux2d4u10u;22ux44u;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "append_duplicated_overlap"
                                , "cmds": ["+;1u2d1u4u;"
                                           , "+;1u2d4u4u6d;22ux44u;"]
                                , "expected_rt": "1ux2d4u6d;22ux44u;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "append_duplicated_no_overlap"
                                , "cmds": ["+;1u2d1u4u;"
                                           , "+;1u10u10u10d;22ux44u;"]
                                , "expected_rt": "1ux2d4u10u10d;22ux44u;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "append_no_default_change"
                                , "cmds": ["x;1u4u6u;"
                                           , "+;1u10u;"]
                                , "expected_rt": "x;1u4u6u10u;"})

                # subtraction section
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "subtract_simple"
                                , "cmds": ["1ux2u3u4u;"
                                           , "-;1u3u;"]
                                , "expected_rt": "1ux2u4u;" })
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "subtract_rule_removal"
                                , "cmds": ["1ux2u3u4u;2ux;"
                                           , "-;1u1u2u3u4u;"]
                                , "expected_rt": "2ux;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "subtract_more_than_there"
                                , "cmds": ["1ux2u3u4u;2ux;"
                                           , "-;1u1u2u3u4u5u6u;"]
                                , "expected_rt": "2ux;"})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "subtract_all_and_more"
                                , "cmds": ["1ux2u3u4u;2ux;"
                                           , "-;2ux5u8d;1u1u2u3u4u5u6u;"]
                                , "expected_rt": ""})
                self.test(test_iccom_sk_routing_multi_cmd, {
                                "sequence_name": "subtract_no_default_change"
                                , "cmds": ["x;1u4u6u;"
                                           , "-;1u6u10u;"]
                                , "expected_rt": "x;1u4u;"})

                self.test(test_iccom_sk_routing_set_smoke_test
                        , { "routing_tables": [
                                        "10ux;12ux17u17d;14dx;14ux;1ux2dx3uxx;"
                                        , "10ux;14dx;14dx1u2u;1ux2dx3uxx;"
                                        , "1ux2dx3uxx;"
                                        , "x;"
                                ]
                            , "routing_tables_name": "multiple_routing_rules"
                            , "cycles": 100
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table": "10ux; 12ux17u17d  ;14dx;14d  x 1u   2u;1ux2dx3uxx;"
                            , "routing_table_name": "spaced_routing_table"
                        })

                self.test(test_iccom_sk_routing_set_check
                        , { "routing_table":
                                        "1001u x 11001u 21001u;"  # multicast upwards, RO
                                        "1002d x;" #   WO
                                        "1101u x 11101u 21101u;"  # multicast upwards, RO
                                        "1102d x;" #   WO
                                        "1201u x 11201u 21201u;"  # multicast upwards, RO
                                        "1202d x;" #   WO
                                        "1301u x;" # RO
                                        "1302d x;" #   WO
                                        "1401u x;" # RO
                                        "1402d x;" #   WO
                                        "1501u x;" # RO
                                        "1502d x;" #   WO
                                        "1601u x;" # RO
                                        "1602d x;" #   WO
                                        "1701u x;" # RO
                                        "1702d x;" #   WO
                                        "1801u x;" # RO
                                        "1802d x;" #   WO
                                        "1901u x;" # RO
                                        "1902d x;" #   WO
                                        "2001u x;" # RO
                                        "2002d x;" #   WO
                                        "2101u x;" # RO
                                        "2102d x;" #   WO
                                        "2201u x;" # RO
                                        "2202d x;" #   WO
                                        "2301u x;" # RO
                                        "2302d x;" #   WO
                                        "2401u x;" # RO
                                        "2402d x;" #   WO
                                        "2501u x;" # RO
                                        "2502d x;" #   WO
                                        "21202d 1202d;" # WO, aggregation into 1202 channel
                            , "routing_table_name": "realistic_rt"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 2142
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": []
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "1_explicitly_blocked"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 2142
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [2142,]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "1to1_direct"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 2142
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [33,]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "1to1_shifted"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 2142
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [22, 33]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "1to2"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 2142
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [22, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "1to6"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [22, 333, 112]
                            , "down_cast_channels_list": [1,]
                            , "msg_data": bytearray(b"tst")
                            , "sub_id": "1to_3up_1down"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [22, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [1, 2, 3]
                            , "msg_data": bytearray(b"tst")
                            , "sub_id": "1to_6up_3down"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [22, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [1, 2, 3, 4]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "1to_6up_4down"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [21, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [21, 2, 3, 4]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "1to_6up_4down_and_same"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [21, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [21, 2, 3, 4]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "1to_6up_4down_and_same_extra_rule_100_cycles"
                            , "extra_routing_rules": "88u77d88u;12dx;22dx;33ux;103dx;"
                            , "cycles_count": 100
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 22142
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": []
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "downwards_1_explicitly_blocked"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 22142
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": []
                            , "down_cast_channels_list": [22142]
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "downwards_1_1to1_direct"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 2142
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [33,]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "downwards_1to1_shifted"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 2142
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [22, 33]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "downwards_1to2"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 2142
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [22, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"test1")
                            , "sub_id": "downwards_1to6"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [22, 333, 112]
                            , "down_cast_channels_list": [1,]
                            , "msg_data": bytearray(b"tst")
                            , "sub_id": "downwards_1to_3up_1down"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [22, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [1, 2, 3]
                            , "msg_data": bytearray(b"tst")
                            , "sub_id": "downwards_1to_6up_3down"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [22, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [1, 2, 3, 4]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "downwards_1to_6up_4down"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [21, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [21, 2, 3, 4]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "downwards_1to_6up_4down_and_same"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [21, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [21, 2, 3, 4]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "downwards_1to_6up_4down_and_same_extra_rules_1"
                            , "extra_routing_rules": "88u77d88u;"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [21, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [21, 2, 3, 4]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "downwards_1to_6up_4down_and_same_extra_rules_2"
                            , "extra_routing_rules": "88u77d88u;12dx;22dx;33ux;103dx;"
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [21, 33, 103, 122, 333, 112]
                            , "down_cast_channels_list": [21, 2, 3, 4]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "downwards_1to_6up_4down_and_same_extra_rules_2_100_cycles"
                            , "extra_routing_rules": "88u77d88u;12dx;22dx;33ux;103dx;"
                            , "cycles_count": 100
                        })

                # routing with allowed-default

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 21
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [21,]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "upwards_pass_via_allowed_default"
                            , "routing_table": "x;"
                            , "cycles_count": 10
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 210
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": []
                            , "down_cast_channels_list": [210,]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "downwards_pass_via_allowed_default"
                            , "routing_table": "x;"
                            , "cycles_count": 10
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 321
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [321,]
                            , "down_cast_channels_list": []
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "upwards_extra_rules_pass_via_allowed_default"
                            , "routing_table": "x;33u;44u;55ux10u21u;"
                            , "cycles_count": 10
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 3210
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": []
                            , "down_cast_channels_list": [3210,]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "downwards_extra_rules_pass_via_allowed_default"
                            , "routing_table": "x;33u;44u;55ux10u21u;45d;66d21d;"
                            , "cycles_count": 10
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 321
                            , "initial_direction": "upwards"
                            , "up_cast_channels_list": [321, 333]
                            , "down_cast_channels_list": [48]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "upwards_extra_rules_allowed_default_multicast"
                            , "routing_table": "x;33u;321ux333u48d;44u;55ux10u21u;"
                            , "cycles_count": 10
                        })

                self.test(test_iccom_skif_routing_primitive
                        , { "msg_inbound_channel": 3210
                            , "initial_direction": "downwards"
                            , "up_cast_channels_list": [33,]
                            , "down_cast_channels_list": [3210, 66]
                            , "msg_data": bytearray(b"ts")
                            , "sub_id": "downwards_extra_rules_allowed_default_multicast"
                            , "routing_table": "x;33u;44u;3210d3210d33u66d;55ux10u21u;45d;66d21d;"
                            , "cycles_count": 10
                        })


def run_tests():
        #tester = IccomSkifTester(skip_list= [
        # "test_try_changing_protocol_family_after_initialization"
        # , "iccom_sk_data_comm_with_transport_level_simple_small_msg.python"
        # , "iccom_sk_data_comm_with_transport_level_single_char_msg.python"
        # , "iccom_sk_data_comm_with_transport_level_50char_msg.python"
        # , "iccom_sk_data_comm_with_transport_level_asymetric_msg_10_and_40_chars.python"
        # , "test_iccom_sk_check_default_routing"
        # , " test_iccom_sk_check_default_routing"
        # , "test_iccom_sk_routing_set_check.default"
        # , "test_iccom_sk_routing_set_check.100_ch_bidirectional"
        # , "test_iccom_sk_routing_set_check.1u_ch_multicast"
        # , "test_iccom_sk_routing_set_check.1u_ch_multicast_and_default"
        # , "test_iccom_sk_routing_set_check.1u_ch_multicast_and_2x_default"
        # , "test_iccom_sk_routing_set_check.mixed_1v"
        # , "test_iccom_sk_routing_set_check.mixed_2v_multiple_default_actions"
        # , "test_iccom_sk_routing_set_check.mixed_3v_multiple_default_actions_double_entries"
        # , "test_iccom_sk_routing_set_check.mixed_3v_multiple_default_actions_overload_entries"
        # , "test_iccom_sk_routing_append"
        # , "test_iccom_sk_routing_double_append"
        # , "test_iccom_sk_routing_whitespace_cmd"
        # , "test_iccom_sk_routing_double_overlap_append"
        # , "test_iccom_sk_routing_multi_cmd.append_overlap"
        # , "test_iccom_sk_routing_multi_cmd.append_full_overlap"
        # , "test_iccom_sk_routing_multi_cmd.append_no_overlap"
        # , "test_iccom_sk_routing_multi_cmd.append_1_overlap"
        # , "test_iccom_sk_routing_multi_cmd.append_1_no_overlap"
        # , "test_iccom_sk_routing_multi_cmd.append_duplicated_overlap"
        # , "test_iccom_sk_routing_multi_cmd.append_duplicated_no_overlap"
        # , "test_iccom_sk_routing_set_smoke.multiple_routing_rules"
        # , "test_iccom_sk_routing_set_check.spaced_routing_table"
        # , "test_iccom_sk_routing_set_check.realistic_rt"
        # , "iccom_skif_routing_primitive.1_explicitly_blocked"
        # , "iccom_skif_routing_primitive.1to1_direct"
        # , "iccom_skif_routing_primitive.1to1_shifted"
        # , "iccom_skif_routing_primitive.1to2"
        # , "iccom_skif_routing_primitive.1to6"
        # , "iccom_skif_routing_primitive.1to_3up_1down"
        # , "iccom_skif_routing_primitive.1to_6up_3down"
        # , "iccom_skif_routing_primitive.1to_6up_4down"
        # , "iccom_skif_routing_primitive.1to_6up_4down_and_same"
        # , "iccom_skif_routing_primitive.1to_6up_4down_and_same_extra_rule_100_cycles"
        # , "iccom_skif_routing_primitive.downwards_1_explicitly_blocked"
        # , "iccom_skif_routing_primitive.downwards_1_1to1_direct"
        # , "iccom_skif_routing_primitive.downwards_1to1_shifted"
        # , "iccom_skif_routing_primitive.downwards_1to2"
        # , "iccom_skif_routing_primitive.downwards_1to6"
        # , "iccom_skif_routing_primitive.downwards_1to_3up_1down"
        # , "iccom_skif_routing_primitive.downwards_1to_6up_3down"
        # , "iccom_skif_routing_primitive.downwards_1to_6up_4down"
        # , "iccom_skif_routing_primitive.downwards_1to_6up_4down_and_same"
        # , "iccom_skif_routing_primitive.downwards_1to_6up_4down_and_same_extra_rules_1"
        # , "iccom_skif_routing_primitive.downwards_1to_6up_4down_and_same_extra_rules_2"
        # , "iccom_skif_routing_primitive.downwards_1to_6up_4down_and_same_extra_rules_2_100_cycles"
        # , "iccom_skif_routing_primitive.upwards_pass_via_allowed_default"
        # , "iccom_skif_routing_primitive.downwards_pass_via_allowed_default"
        # , "iccom_skif_routing_primitive.upwards_extra_rules_pass_via_allowed_default"
        # , "iccom_skif_routing_primitive.downwards_extra_rules_pass_via_allowed_default"
        # , "iccom_skif_routing_primitive.upwards_extra_rules_allowed_default_multicast"
        # , "iccom_skif_routing_primitive.downwards_extra_rules_allowed_default_multicast"
        #])

        #tester = IccomSkifTester(run_list=[
        #    "iccom_skif_routing_primitive.1to_6up_4down_and_same"
        #    , "iccom_skif_routing_primitive.1to_6up_4down_and_same_extra_rule_100_cycles"
        #])

        tester = IccomSkifTester()

        tester.run_tests()

        tester.print()

        return tester