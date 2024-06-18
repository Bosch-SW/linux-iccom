import subprocess
import zlib
from time import sleep
import errno
import os
import string
import random
import glob

import iccom
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
                iccom.create_iccom_device(None)
                iccom.create_fd_test_transport_device(None)

                if not self.skip_iccom_skif_device:
                        self.iccom_skif_dev_name = self.get_one_iccom_skif_name()
                self.iccom_dev_name = self.get_one_iccom_name()
                self.iccom_transport_dev_name = self.get_one_test_transport_name()

                init_pf = 22

                print("Linking the stack.")

                iccom.link_fd_test_transport_device_to_iccom_device(
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
                print("Destroying default test env.")

                if not self.skip_iccom_skif_device:
                        iccom_skif.delete_iccom_sockets_device(
                                self.iccom_skif_dev_name, None)
                iccom.delete_iccom_device(
                      self.iccom_dev_name, None)
                iccom.delete_fd_test_transport_device(
                      self.iccom_transport_dev_name, None)

                print("Default test env destroyed.")

        def __enter__(self):
                self.iccom_create_default_stack()
                return self

        def __exit__(self, exc_type, exc_value, traceback):
                self.iccom_destroy_default_stack()
 