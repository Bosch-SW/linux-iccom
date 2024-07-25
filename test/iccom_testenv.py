import subprocess
import zlib
from time import sleep
import errno
import os
import string
import random
import glob

from iccom import *
import iccom_skif

# Just a convenience wrapper to handle the default test environment
# with "with" keyword
class IccomTestEnv:

        def __init__(self, skip_iccom_skif_device=False):
               self.iccom_dev_name = None
               self.iccom_skif_dev_name = None
               self.iccom_transport_dev_name = None

               self.iccom_dev_type = "iccom"
               self.iccom_skif_dev_type = "iccom_socket_if"
               self.iccom_test_transport_dev_type = "fd_test_transport"

               self.skip_iccom_skif_device = skip_iccom_skif_device
        
               # initial indexes of the iccom for internal confirmations
               self.inbound_package_num = 1
               self.outbound_package_num = 0

        def get_one_dev_name(dev_type):

                os.chdir("/sys/devices/platform")
                devices = glob.glob("%s.*" % (dev_type,))

                if len(devices) == 1:
                        return os.path.basename(devices[0])

                raise RuntimeError("Can not return specific %s device. "
                                   " Available list: %s" % (dev_type, str(devices),))

        def check_no_devices(dev_type):

                os.chdir("/sys/devices/platform")
                devices = glob.glob("%s.*" % (dev_type,))

                if len(devices) == 0:
                        return

                raise RuntimeError("The devices of type %s still exist. "
                                   % (dev_type,))

        def check_no_iccom_devices(self):
                return IccomTestEnv.check_no_devices(self.iccom_dev_type)

        def check_no_iccom_skif_devices(self):
                return IccomTestEnv.check_no_devices(self.iccom_skif_dev_type)

        def check_no_test_transport_devices(self):
                return IccomTestEnv.check_no_devices(self.iccom_test_transport_dev_type)

        def get_one_iccom_name(self):
                return IccomTestEnv.get_one_dev_name(self.iccom_dev_type)

        def get_one_iccom_skif_name(self):
                return IccomTestEnv.get_one_dev_name(self.iccom_skif_dev_type)

        def get_one_test_transport_name(self):
                return IccomTestEnv.get_one_dev_name(
                        self.iccom_test_transport_dev_type)

        def iccom_name(self):
               return self.iccom_dev_name

        def iccom_skif_name(self):
               return self.iccom_skif_dev_name

        def test_transport_name(self):
               return self.iccom_transport_dev_name

        # Tests helper.
        # Just creates a set of default devices and binds them together
        #
        # NOTE: used in tests to perform standard single-chain stack of devices.
        def iccom_create_default_stack(self):
                print("Creating default test env.")

                if not self.skip_iccom_skif_device:
                        iccom_skif.create_iccom_sockets_device(None)
                create_iccom_device(None)
                create_fd_test_transport_device(None)

                if not self.skip_iccom_skif_device:
                        self.iccom_skif_dev_name = self.get_one_iccom_skif_name()
                self.iccom_dev_name = self.get_one_iccom_name()
                self.iccom_transport_dev_name = self.get_one_test_transport_name()

                init_pf = 22

                print("Linking the stack.")

                link_fd_test_transport_device_to_iccom_device(
                        self.iccom_transport_dev_name, self.iccom_dev_name, None)
                if not self.skip_iccom_skif_device:
                        iccom_skif.set_socket_protocol_family(
                                init_pf, self.iccom_skif_dev_name, None)
                        iccom_skif.link_iccom_sockets_device_to_iccom_device(
                                self.iccom_dev_name, self.iccom_skif_dev_name, None)

                print("Default test env created.")

        # Tests helper.
        # Unbinds and removes default devices set.
        def iccom_destroy_default_stack(self):
                self.print_iccom_statistics()

                print("Destroying default test env.")

                if not self.skip_iccom_skif_device:
                        iccom_skif.delete_iccom_sockets_device(
                                self.iccom_skif_dev_name, None)
                delete_iccom_device(
                      self.iccom_dev_name, None)
                delete_fd_test_transport_device(
                      self.iccom_transport_dev_name, None)

                print("Default test env destroyed.")

        def __enter__(self):
                self.iccom_create_default_stack()
                return self

        def __exit__(self, exc_type, exc_value, traceback):
                self.iccom_destroy_default_stack()

        # Checks that the given data (fitting into one package) is received via
        # ICCom.
        # @te IccomTestEnv
        def iccom_simulate_incoming(self, channel, data):
                # received it properly
                check_wire_xfer(self.test_transport_name()
                        , iccom_package(self.inbound_package_num
                                        , iccom_packet(channel
                                                , data
                                                , True))
                        , iccom_package(self.outbound_package_num, bytearray())
                        , None, "single data frame")
                check_wire_xfer(self.test_transport_name()
                        , iccom_ack_package()
                        , iccom_ack_package()
                        , None, "ack frame")

                self.inbound_package_num += 1
                self.outbound_package_num += 1
        
        # Checks that the given data (fitting into one package) is sent out via ICCom.
        # @te IccomTestEnv
        def iccom_check_simple_write(self, channel, data):
                # Do (Default xfer) Data Exchange + NACK
                check_wire_xfer(self.test_transport_name()
                                , iccom_package(self.inbound_package_num
                                                , bytearray())
                                , iccom_package(self.outbound_package_num
                                                , bytearray())
                                , None, None, "first data frame")
                check_wire_xfer_ack(self.test_transport_name()
                                        , None, None, "first ack frame")

                self.inbound_package_num += 1
                self.outbound_package_num += 1
        
                # ICCom sends correct data, but we complain that we have not
                # received it properly
                check_wire_xfer(self.test_transport_name()
                        , iccom_package(self.inbound_package_num
                                        , bytearray())
                        , iccom_package(self.outbound_package_num
                                        , iccom_packet(channel
                                                , data
                                                , True))
                        , None, "second data frame")
                check_wire_xfer(self.test_transport_name()
                        , iccom_ack_package()
                        , iccom_ack_package()
                        , None, "ack frame")

        def print_iccom_statistics(self):
                fn = "/sys/devices/platform/" + self.get_one_iccom_name() + "/statistics"

                print("ICCom %s statistics:" % (fn,))
                with open(fn, "r") as statistics:
                        for line in statistics.readlines():
                                print("    | " + line)

