import subprocess
from time import sleep
import errno
import os
import string
import random

from iccom_testenv import *
from iccom import *
from general_test import *


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
        actual_data = iccom_package(package_seq_id, package_payload, 64)
        if (expected_data != actual_data):
                raise RuntimeError("wrong on-wire package image%s!\n"
                                   "    %s (expected)\n"
                                   "    %s (received)\n"
                                   % ((" (" + log_msg + ")" if len(log_msg) else ""
                                       , expected_data.hex(), actual_data.hex())))

# Checks if the package testing fits the on-wire picture.
#
# NOTE: this is critically needed to ensure the on-wire compatibility
#   between systems.
def iccom_tests_sanity_check(params, get_test_info=False):

        if (get_test_info):
            return { "test_description":
                        ("checks the on-wire layout for test-generated packages"
                         " to ensure that the tests themselves are on-wire correct")
                     , "test_id": "iccom_tests_sanity_check" }

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
                     , "test_id": "simple_channel_to_transport_interaction.short_data" }

        with IccomTestEnv() as te:

            create_iccom_sysfs_channel(te.iccom_name(), 1, None)
            create_transport_device_RW_files(te.test_transport_name(), None)

            # Send a message from ICCOM to Full Duplex Test Transport via channel 1
            iccom_sysfs_send(te.iccom_name(), 1, "Who are you?", None)

            # Default xfer
            check_wire_xfer(te.test_transport_name()
                            , iccom_package(1, bytearray(), te.curr_dpkg_size())
                            , iccom_package(0, bytearray(), te.curr_dpkg_size())
                            , None, None, "first data frame")
            check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "first ack frame")

            # Actual data xfer
            check_wire_xfer(te.test_transport_name()
                            , iccom_package(2, iccom_packet(1, bytearray(b"I am Luis"), True), te.curr_dpkg_size())
                            , iccom_package(1, iccom_packet(1, bytearray(b"Who are you?"), True), te.curr_dpkg_size())
                            , None , None, "second data frame")
            check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "second ack frame")

            # Check channel data
            check_ch_data(te.iccom_name(), 1, "I am Luis", None)

def iccom_data_exchange_to_transport_with_iccom_data_without_transport_data(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("idle package exchange with"
                                          " expected no data on the channel")
                     , "test_id": "simple_channel_to_transport_interaction.no_data" }

        with IccomTestEnv() as te:

            create_iccom_sysfs_channel(te.iccom_name(), 1, None)
            create_transport_device_RW_files(te.test_transport_name(), None)

            # Do (Default xfer) Data Exchange + ACK
            check_wire_xfer(te.test_transport_name()
                            , iccom_package(1, bytearray(), te.curr_dpkg_size())
                            , iccom_package(0, bytearray(), te.curr_dpkg_size())
                            , None, None, "first data frame")
            check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "first ack frame")

            # Do (Default xfer) Data Exchange + ACK
            check_wire_xfer(te.test_transport_name()
                            , iccom_package(2, bytearray(), te.curr_dpkg_size())
                            , iccom_package(1, bytearray(), te.curr_dpkg_size())
                            , None, None, "second data frame")
            check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "second ack frame")

            # Check that there is no channel data
            check_ch_data(te.iccom_name(), 1, "", errno.EIO)

def iccom_data_exchange_to_transport_with_iccom_data_with_transport_data_wrong_payload_size(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": "iccom -> wire && broken wire data package -> iccom"
                     , "test_id": "simple_channel_to_transport_interaction.wrong_payload" }

        with IccomTestEnv() as te:

            create_iccom_sysfs_channel(te.iccom_name(), 1, None)
            create_transport_device_RW_files(te.test_transport_name(), None)

            # Send a message from ICCOM to Full Duplex Test Transport via channel 1
            iccom_sysfs_send(te.iccom_name(), 1, "Who are you?", None)

            # Do (Default xfer) Data Exchange + ACK
            check_wire_xfer(te.test_transport_name()
                            , iccom_package(1, bytearray(), te.curr_dpkg_size())
                            , iccom_package(0, bytearray(), te.curr_dpkg_size())
                            , None, None, "first data frame")
            check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "first ack frame")

            # Do (Default xfer) Data Exchange without ACK
            broken_package = iccom_package(2, bytearray(), te.curr_dpkg_size())
            broken_package[1] = 0x02
            check_wire_xfer(te.test_transport_name()
                            , broken_package
                            , iccom_package(1, iccom_packet(1, bytearray(b"Who are you?"), True), te.curr_dpkg_size())
                            , None , None, "second data frame")
            check_wire_xfer(te.test_transport_name()
                            , iccom_ack_package()
                            , iccom_nack_package()
                            , None , None, "expected nack on wire frame")

            # Check that there is no channel data
            check_ch_data(te.iccom_name(), 1, "", errno.EIO)

def iccom_data_exchange_to_transport_with_iccom_data_with_transport_nack(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("iccom -> wire && wire (with nack) -> iccom"
                                          " && repeated transmission iccom -> wire")
                     , "test_id": "simple_channel_to_transport_interaction.nack" }

        with IccomTestEnv() as te:

            create_iccom_sysfs_channel(te.iccom_name(), 1000, None)
            create_transport_device_RW_files(te.test_transport_name(), None)

            # Send a message from ICCOM to Full Duplex Test Transport via channel 1
            iccom_sysfs_send(te.iccom_name(), 1000, "Is there anybody there?", None)

            # Do (Default xfer) Data Exchange + NACK
            check_wire_xfer(te.test_transport_name()
                            , iccom_package(1, bytearray(), te.curr_dpkg_size())
                            , iccom_package(0, bytearray(), te.curr_dpkg_size())
                            , None, None, "first data frame")
            check_wire_xfer_ack(te.test_transport_name()
                                , None, None, "first ack frame")

            # ICCom sends correct data, but we complain that we have not
            # received it properly
            check_wire_xfer(te.test_transport_name()
                    , iccom_package(2, bytearray(), te.curr_dpkg_size())
                    , iccom_package(1, iccom_packet(1000
                                                    , bytearray(b"Is there anybody there?")
                                                    , True), te.curr_dpkg_size())
                    , None, "second data frame")
            check_wire_xfer(te.test_transport_name()
                    , iccom_nack_package()
                    , iccom_ack_package()
                    , None, "we send nack")

            # ICCom must repeat the transmission of the data
            check_wire_xfer(te.test_transport_name()
                    , iccom_package(2, bytearray(), te.curr_dpkg_size())
                    , iccom_package(1, iccom_packet(1000
                                                    , bytearray(b"Is there anybody there?")
                                                    , True), te.curr_dpkg_size())
                    , None, "second data frame")
            check_wire_xfer_ack(te.test_transport_name(), None, None, "final ack")

            # Check that there is no channel data
            check_ch_data(te.iccom_name(), 1000, "", errno.EIO)

def iccom_check_devices_deletion(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("iccom -> check sucessfull removal"
                                          " of all devices")
                     , "test_id": "iccom_creation_deletion" }

        number_of_devices = params["number_of_devices"]

        ###### Test sequence ######

        for i in range(number_of_devices):
            te = IccomTestEnv()

            create_iccom_device(None)

            check_sysfs_file_presence_expectation(te.get_one_iccom_name(), True)

            delete_iccom_device(te.get_one_iccom_name(), None)

            te.check_no_iccom_devices()

def fd_test_transport_check_devices_deletion(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description":
                        ("fd_test_transport -> check sucessfull removal"
                         " of all devices")
                     , "test_id": "iccom_test_transport_creation_deletion" }

        number_of_devices = params["number_of_devices"]

        ###### Test sequence ######

        for i in range(number_of_devices):
            te = IccomTestEnv()

            create_fd_test_transport_device(None)

            check_sysfs_file_presence_expectation(te.get_one_test_transport_name(), True)

            delete_iccom_device(te.get_one_test_transport_name(), None)

            te.check_no_test_transport_devices()

def iccom_stress_data_communication_with_different_channels(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("iccom channel -> wire && wire -> iccom channel")
                     , "test_id": "random_messages_over_various_channels" }

        with IccomTestEnv() as te:

            gen_char_size = 10
            number_of_msgs = 500
            sequence_number = 0
            number_of_channels = 10

            for ch in range(1, number_of_channels + 1):
                create_iccom_sysfs_channel(te.iccom_name(), ch, None)

            create_transport_device_RW_files(te.test_transport_name(), None)

            for i in range(1, number_of_msgs + 1):

                # NOTE: the channel 0 is not really usable, cause
                #   iccom_skif in general will not propagate it to the
                #   userland, cause kernel itself is bound to 0 address,
                #   so, sending the msg to ch 0 will result in returning
                #   this message back to iccom from the iccom_skif.
                ch = random.randint(1, number_of_channels)
                # Increment the size of question and answer
                # which get's generated from 1 to 50 bytes of
                # message (limited to 50 bytes to fit into one package)
                gen_char_size = 1 + i % 50

                question_str = ''.join(random.choices(string.ascii_uppercase +
                                            string.digits, k=gen_char_size))
                question_b = question_str.encode('utf-8')

                answer_str = ''.join(random.choices(string.ascii_uppercase +
                                        string.digits, k=gen_char_size))
                answer_b = answer_str.encode('utf-8')

                print("Test channel: " + str(ch))
                print("  * iccom->wire msg: " + question_b.hex())
                print("  * wire->iccom msg: " + answer_b.hex())

                # Send a message from ICCOM to Full Duplex Test Transport via the channel
                iccom_sysfs_send(te.iccom_name(), ch, question_str, None)

                # Transfer
                variant = check_wire_xfer(te.test_transport_name()
                                , iccom_package(sequence_number
                                            , iccom_packet(ch, bytearray(answer_b)
                                                        , True), te.curr_dpkg_size())
                                , [iccom_package(sequence_number, bytearray(), te.curr_dpkg_size())
                                   , iccom_package(sequence_number
                                                   , iccom_packet(ch, bytearray(question_b)
                                                                  , True), te.curr_dpkg_size()) ]
                                , None, None, "initial data frame")

                check_wire_xfer_ack(te.test_transport_name(), None, None, "ack frame")

                sequence_number = (sequence_number + 1) % 0x100

                # the first xfer was idle from iccom side, then real data will come now
                if variant == 0:
                    # Data xfer
                    check_wire_xfer(te.test_transport_name()
                                    , iccom_package(sequence_number, bytearray(), te.curr_dpkg_size())
                                    , iccom_package(sequence_number
                                                   , iccom_packet(ch, bytearray(question_b)
                                                                  , True), te.curr_dpkg_size())
                                , None, None, "additional data frame")
                    check_wire_xfer_ack(te.test_transport_name()
                                        , None, None, "ack frame")
                    sequence_number = (sequence_number + 1) % 0x100

                # Check channel data
                check_ch_data(te.iccom_name(), ch, answer_str, None)

def iccom_data_sysfs_fd_test_transport_RW_creation_deletion_checkup(
                params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("iccom -> delete R&W files which do not exist")
                     , "test_id": "iccom_test_channel_io_files_create_delete" }

        with IccomTestEnv() as te:

            transport_RW_file = ("/sys/devices/platform/%s/transport_RW"
                    % (te.test_transport_name()))

            check_sysfs_file_presence_expectation(transport_RW_file , False)

            create_transport_device_RW_files(te.test_transport_name(), None)

            check_sysfs_file_presence_expectation(transport_RW_file , True)

            delete_transport_device_RW_files(te.test_transport_name(), None)

            check_sysfs_file_presence_expectation(transport_RW_file , False)

def iccom_initial_package(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("package on wire -> newly created iccom"
                                          ", allows to ensure that none of packages"
                                          " is lost at the very beginning of comm.")
                     , "test_id": "initial_package" }

        ch = 100

        # checking all initial packages we have for now
        for init_pkg_id in range(0, 256):

            with IccomTestEnv() as te:

                sequence_number = init_pkg_id

                create_iccom_sysfs_channel(te.iccom_name(), 100, None)
                create_transport_device_RW_files(te.test_transport_name(), None)

                question_str = "the fist package"
                question_b = question_str.encode('utf-8')

                answer_str = "really it is"
                answer_b = answer_str.encode('utf-8')

                print("Test channel: " + str(ch))
                print("  * iccom->wire msg: " + question_b.hex())
                print("  * wire->iccom msg: " + answer_b.hex())

                # Send a message from ICCOM to Full Duplex Test Transport via the channel
                iccom_sysfs_send(te.iccom_name(), ch, question_str, None)

                # Transfer
                # NOTE: new ICCom will start with package ID = 0
                check_wire_xfer(te.test_transport_name()
                                , iccom_package(sequence_number
                                                , iccom_packet(ch, bytearray(answer_b)
                                                        , True), te.curr_dpkg_size())
                                , iccom_package(0, bytearray(), te.curr_dpkg_size())
                                , None, None, "initial data frame")

                check_wire_xfer_ack(te.test_transport_name(), None, None, "ack frame")

                sequence_number = (sequence_number + 1) % 0x100

                # NOTE: second ICCom  package ID = 1
                check_wire_xfer(te.test_transport_name()
                                , iccom_package(sequence_number, bytearray(), te.curr_dpkg_size())
                                , iccom_package(1, iccom_packet(ch, bytearray(question_b)
                                                                , True), te.curr_dpkg_size()) 
                                , None, None, "initial data frame")

                check_wire_xfer_ack(te.test_transport_name(), None, None, "ack frame")

                sequence_number = (sequence_number + 1) % 0x100

                # Check channel data
                check_ch_data(te.iccom_name(), ch, answer_str, None)

class IccomTester(GeneralTest):

    def __init__(self, skip_list=None):
        super(IccomTester, self).__init__("iccom", skip_list)

    def run_tests(self):

        self.test(iccom_tests_sanity_check, {})

        self.test(iccom_data_exchange_to_transport_with_iccom_data_with_transport_data, {})

        self.test(iccom_data_exchange_to_transport_with_iccom_data_without_transport_data, {})

        self.test(iccom_data_exchange_to_transport_with_iccom_data_with_transport_data_wrong_payload_size
                  , {})

        self.test(iccom_data_exchange_to_transport_with_iccom_data_with_transport_nack, {})

        self.test(iccom_data_sysfs_fd_test_transport_RW_creation_deletion_checkup, {})

        self.test(iccom_stress_data_communication_with_different_channels, {})

        self.test(iccom_check_devices_deletion, {
            "number_of_devices": 10
        })

        self.test(fd_test_transport_check_devices_deletion, {
            "number_of_devices": 10
        })

        self.test(iccom_initial_package, {})

def run_tests():
     
    # tester = IccomTester(skip_list=[
    #     "iccom_tests_sanity_check"
    #     , "simple_channel_to_transport_interaction.short_data"
    #     , "simple_channel_to_transport_interaction.no_data"
    #     , "simple_channel_to_transport_interaction.wrong_payload"
    #     , "simple_channel_to_transport_interaction.nack"
    #     , "iccom_test_channel_io_files_create_delete"
    #     , "random_messages_over_various_channels"
    #     , "iccom_creation_deletion"
    #     , "iccom_test_transport_creation_deletion"
    #     , "initial_package"
    # ])

    tester = IccomTester()

    tester.run_tests()

    tester.print()

    return tester