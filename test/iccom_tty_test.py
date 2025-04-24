import re
from time import sleep
import serial
import os
import subprocess

from sysfs import *
from iccom_testenv import *
from iccom_skif import *
from general_test import *
from iccom import *
from iccom_test import *
import stat

# Defines ICCom TTY
class IccomTty:
    def __init__(self, iccom_dev_name, iccom_ch, tty_number, read_timeout_s = 0.5):
        self.iccom_dev_name = iccom_dev_name
        self.iccom_ch = iccom_ch
        self.tty_number = tty_number
        self.read_timeout_s = read_timeout_s

    def get_kernel_version():

        proc = subprocess.Popen(['uname', '-r'], stdin = subprocess.PIPE
                                , stdout = subprocess.PIPE)
        stdout, stderr = proc.communicate()
        kernel_str =  stdout.decode("unicode_escape")

        m = re.match(r"(?P<major>\d+)\.(?P<minor>\d+)\..*", kernel_str)

        kernel_major_ver = int(m.group('major'))
        kernel_minor_ver = int(m.group('minor'))

        return (kernel_major_ver, kernel_minor_ver)

    def dynamic_dt_supported():
        kernel_ver = IccomTty.get_kernel_version()
        kver = 1000 * kernel_ver[0] + kernel_ver[1]
        return False if kver < 6 * 1000 + 6 else True

    def ensure_dynamic_dt():
        if not IccomTty.dynamic_dt_supported():
             raise Exception("NOTE: Dynamic creation of ICCom TTY devices works only with"
                   " kernels >= v6.6")

    def sysfs_dev_dir(self):
        return "/sys/class/tty/ttyICCOM%d" % (self.tty_number)

    def tty_dev_file_name(self):
        return "/dev/ttyICCOM%d" % (self.tty_number,)

    def tty_dev_name(self):
        return "ttyICCOM%d" % (self.tty_number,)

    def __enter__(self):
        file = "/sys/class/iccom_tty/create_iccom_tty"
        command = "%s:%d:%d" % (self.iccom_dev_name
                                , self.iccom_ch
                                , self.tty_number)
        write_sysfs_file(file, command, None)

        total_time_allowed = 2.0
        while (not os.path.exists(self.sysfs_dev_dir())):
            step = 0.050
            sleep(step)
            total_time_allowed -= step
            if (total_time_allowed < 0):
                 raise Exception("failed to wait for '%s' TTY file get created"
                                 % (self.sysfs_dev_dir(),))

        # now simulating udev here =)
        major_num = None
        minor_num = None
        with open("%s/dev" % (self.sysfs_dev_dir())) as f:
            match = re.match(r"\s*(\d+)\s*:\s*(\d+)\s*", f.readline())
            if match is None:
                 raise Exception("failed to read major and minor numbers for %s"
                                 % (self.sysfs_dev_dir(),))
            major_num = int(match[1])
            minor_num = int(match[2])

        os.mknod(self.tty_dev_file_name()
                 , mode=(0o660 | stat.S_IFCHR)
                 , device=os.makedev(major_num, minor_num))

        total_time_allowed = 2.0
        while (not os.path.exists(self.tty_dev_file_name())):
            step = 0.050
            sleep(step)
            total_time_allowed -= step
            if (total_time_allowed < 0):
                 raise Exception("failed to wait for '%s' /dev/*TTY file get created"
                                 % (self.tty_dev_file_name(),))
                        
        os.system("ls -al /dev")
        print("the tty file created: %s" % (self.tty_dev_file_name(),))

        # we also attach ourselves to the TTY file, else incoming
        # messages will be dropped

        self.tty = serial.Serial(timeout=self.read_timeout_s)
        self.tty.port = "/dev/" + self.tty_dev_name() 
        self.tty.open()
        self.tty.flush()

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.tty.close()

        # printing statistics of the device
        with open(self.sysfs_dev_dir() + "/device/statistics") as f:
            print("iccom tty statistics: ")
            for ln in f.readlines():
                print("  " + ln.strip())

        # again, udev simulation first
        os.remove(self.tty_dev_file_name())

        total_time_allowed = 2.0
        while (os.path.exists(self.tty_dev_file_name())):
            step = 0.050
            sleep(step)
            total_time_allowed -= step
            if (total_time_allowed < 0):
                 raise Exception("failed to wait for '%s' /dev/*TTY file get removed"
                                 % (self.tty_dev_file_name(),))
 
        # now the business
        file = "/sys/class/iccom_tty/remove_iccom_tty"
        command = "%s:%d" % (self.iccom_dev_name
                             , self.iccom_ch)
        write_sysfs_file(file, command, None)

    # NOTE: the file must be opened by then by __enter__
    def write(self, msg):
        try:
            self.tty.write(msg)
        except Exception as e:
             print("failed to write to file: %s" % (self.tty_dev_file_name(),))
             raise
        
    # NOTE: the file must be opened by then by __enter__
    def read(self):
        try:
            return self.tty.readline()
        except Exception as e:
             print("failed to read from file: %s" % (self.tty_dev_file_name(),))
             raise

# Test to create the iccom tty device dynamically.
#
# @params Test parameters
# @get_test_info Test information request
#
# NOTE: only requirement: iccom, iccom_tty and fd_test_transport
#       modules are inserted
def test_tty_create(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": "create iccom tty using sysfs request"
                        "note, can be run only on kernel starting v6.6"
                     , "test_id": "tty_create"
                     , "applicable": IccomTty.dynamic_dt_supported() }

        IccomTty.ensure_dynamic_dt()

        with IccomTestEnv() as te:
            with IccomTty(te.get_one_iccom_name()
                          , params["tty_iccom_ch"]
                          , params["tty_number"]) as tty:
                # NOTE: This path needs udevd support to appear
                #target_dev_file = "/dev/ttyICCOM%d" % (params["tty_number"],)
                target_dev_file = "/sys/class/tty/ttyICCOM%d" % (params["tty_number"],)

                if not os.path.exists(target_dev_file):
                     print("Here are available devices:")
                     os.system("ls -al /sys/class/tty")
                     raise Exception("%s does NOT exist, while it should."
                                     % (target_dev_file,))

# Test to create the iccom tty device dynamically and write message there.
#
# @params Test parameters
# @get_test_info Test information request
#
# NOTE: only requirement: iccom, iccom_tty and fd_test_transport
#       modules are inserted
def test_tty_basic_write(params, get_test_info=False):
        if (get_test_info):
            return { "test_description": "create iccom tty and write message"
                     , "test_id": "tty_basic_write" 
                     , "applicable": IccomTty.dynamic_dt_supported() }

        IccomTty.ensure_dynamic_dt()

        with IccomTestEnv() as te:
            with IccomTty(te.get_one_iccom_name()
                          , params["tty_iccom_ch"]
                          , params["tty_number"]) as tty:

                create_transport_device_RW_files(te.test_transport_name(), None)

                tty.write(bytearray(params["data"].encode("UTF-8")))

                te.iccom_check_simple_write(params["tty_iccom_ch"]
                                            , bytearray(params["data"].encode("UTF-8")))

                delete_transport_device_RW_files(te.test_transport_name(), None)

# Test to create the iccom tty device dynamically and read incoming message.
#
# @params Test parameters
# @get_test_info Test information request
#
# NOTE: only requirement: iccom, iccom_tty and fd_test_transport
#       modules are inserted
def test_tty_basic_read(params, get_test_info=False):
        if (get_test_info):
            return { "test_description": "create iccom tty and read message"
                     , "test_id":  (params["test_id"] if "test_id" in params
                                   else "tty_basic_read")
                     , "applicable": IccomTty.dynamic_dt_supported() }

        IccomTty.ensure_dynamic_dt()

        with IccomTestEnv() as te:
            with IccomTty(te.get_one_iccom_name()
                          , params["tty_iccom_ch"]
                          , params["tty_number"]) as tty:

                create_transport_device_RW_files(te.test_transport_name(), None)

                te.iccom_simulate_incoming(params["tty_iccom_ch"]
                                               , params["data"])
                tty_data = tty.read()
                if tty_data != params["data"]:
                    raise Exception("the userland read from TTY differs from expected:\n"
                                    "  * actual  : \"%s\"\n"
                                    "  * expected: \"%s\"\n"
                                    % (tty_data, params["data"]))

                delete_transport_device_RW_files(te.test_transport_name(), None)

# Test to create the iccom tty device dynamically and read multiple incoming
# messages.
#
# @params Test parameters
#      @params["append_nl"] set it to True to enforce last char to be newline.
#           defaults to False
# @get_test_info Test information request
#
# NOTE: only requirement: iccom, iccom_tty and fd_test_transport
#       modules are inserted
def test_tty_multiple_read(params, get_test_info=False):
        if (get_test_info):
            return { "test_description": "create iccom tty and read many messages"
                     , "test_id": (params["test_id"] if "test_id" in params
                                   else "tty_multiple_read")
                     , "applicable": IccomTty.dynamic_dt_supported() }

        IccomTty.ensure_dynamic_dt()

        with IccomTestEnv() as te:
            with IccomTty(te.get_one_iccom_name()
                          , params["tty_iccom_ch"]
                          , params["tty_number"]) as tty:

                create_transport_device_RW_files(te.test_transport_name(), None)

                for i in range(params["msgs_count"]):

                    msg_size = random.randint(1, params["msg_max_size"])

                    base_str = ''.join(random.choices(string.ascii_uppercase +
                                                string.digits, k=msg_size))

                    if "append_nl" and params["append_nl"]:
                        # to let the test go faster due to Serial getting newline instantly
                        # and thus returning from read
                        base_str = base_str[:-1] + "\n"

                    data = base_str.encode('UTF-8')

                    te.iccom_simulate_incoming(params["tty_iccom_ch"]
                                                   , data)
                    tty_data = tty.read()
                    if tty_data != data:
                        raise Exception("the userland read from TTY differs from expected:\n"
                                        "  * actual  : \"%s\"\n"
                                        "  * expected: \"%s\"\n"
                                        % (tty_data, data))

                delete_transport_device_RW_files(te.test_transport_name(), None)

def test_tty_multiple_open_close_same_dev(params, get_test_info=False):
        if (get_test_info):
            return { "test_description": "multiple open&close of the same dev"
                     , "test_id": (params["test_id"] if "test_id" in params
                                   else "tty_multiple_reopen")
                     , "applicable": IccomTty.dynamic_dt_supported() }

        IccomTty.ensure_dynamic_dt()

        with IccomTestEnv() as te:
            with IccomTty(te.get_one_iccom_name()
                          , params["tty_iccom_ch"]
                          , params["tty_number"]) as tty:
                for i in range(params["reopens_count"]):
                    tty.tty.close()
                    tty.tty.open()
                    tty.tty.flush()

def test_tty_multiple_open_read_close_same_dev(params, get_test_info=False):
        if (get_test_info):
            return { "test_description": "multiple open&read&close of the same dev"
                     , "test_id": (params["test_id"] if "test_id" in params
                                   else "tty_multiple_reopen_and_read")
                     , "applicable": IccomTty.dynamic_dt_supported() }

        IccomTty.ensure_dynamic_dt()

        with IccomTestEnv() as te:
            with IccomTty(te.get_one_iccom_name()
                          , params["tty_iccom_ch"]
                          , params["tty_number"]) as tty:

                create_transport_device_RW_files(te.test_transport_name(), None)

                for i in range(params["reopens_count"]):

                    for i in range(params["msgs_count"]):

                        msg_size = random.randint(1, params["msg_max_size"])

                        base_str = ''.join(random.choices(string.ascii_uppercase +
                                                    string.digits, k=msg_size))

                        data = base_str.encode('UTF-8')

                        te.iccom_simulate_incoming(params["tty_iccom_ch"], data)
                        tty_data = tty.read()
                        if tty_data != data:
                            raise Exception("the userland read from TTY differs from expected:\n"
                                            "  * actual  : \"%s\"\n"
                                            "  * expected: \"%s\"\n"
                                            % (tty_data, data))


                    tty.tty.close()
                    tty.tty.open()
                    tty.tty.flush()

                delete_transport_device_RW_files(te.test_transport_name(), None)

class IccomTtyTester(GeneralTest):

        def __init__(self, skip_list=None):
                super(IccomTtyTester, self).__init__("iccom_tty", skip_list)

        # Runs all the iccom socket tests
        def run_tests(self):

                self.test(test_tty_create
                        , { "tty_iccom_ch": 1624
                            , "tty_number": 3
                            , "test_id": "tty_create"
                        })
                self.test(test_tty_basic_write
                        , { "tty_iccom_ch": 1771
                            , "tty_number": 4
                            , "data" : "hello, iccom tty\n"
                            , "test_id": "tty_basic_write"
                        })
                self.test(test_tty_basic_read
                        , { "tty_iccom_ch": 1874
                            , "tty_number": 6
                            , "data": bytearray("hello, user land\n".encode("UTF-8")) 
                            , "test_id": "test_tty_basic_read_normal"
                        })
                self.test(test_tty_basic_read
                        , { "tty_iccom_ch": 1874
                            , "tty_number": 6
                            , "data": bytearray("a".encode("UTF-8")) 
                            , "test_id": "test_tty_basic_read_1ch"
                        })
                self.test(test_tty_basic_read
                        , { "tty_iccom_ch": 1874
                            , "tty_number": 6
                            , "data": bytearray("\n".encode("UTF-8")) 
                            , "test_id": "test_tty_basic_read_nl"
                        })
                self.test(test_tty_basic_read
                        , { "tty_iccom_ch": 1874
                            , "tty_number": 6
                            , "data": bytearray(("1234567890" * 3 + "\n").encode("UTF-8")) 
                            , "test_id": "test_tty_basic_read_30chars_nl"
                        })
                self.test(test_tty_basic_read
                        , { "tty_iccom_ch": 1874
                            , "tty_number": 6
                            , "data": bytearray(("1234567890" * 4 + "\n").encode("UTF-8")) 
                            , "test_id": "test_tty_basic_read_40chars_nl"
                        })
                self.test(test_tty_basic_read
                        , { "tty_iccom_ch": 1874
                            , "tty_number": 6
                            , "data": bytearray(("1234567890" * 3).encode("UTF-8")) 
                            , "test_id": "test_tty_basic_read_30chars"
                        })
                self.test(test_tty_basic_read
                        , { "tty_iccom_ch": 1874
                            , "tty_number": 6
                            , "data": bytearray(("1234567890" * 4).encode("UTF-8")) 
                            , "test_id": "test_tty_basic_read_40chars"
                        })
                self.test(test_tty_multiple_read
                        , { "tty_iccom_ch": 2874
                            , "tty_number": 10
                            , "msgs_count": 100
                            , "msg_max_size": 40
                            , "append_nl": True
                            , "test_id": "test_tty_basic_read_100msgs_up_to_40chars_with_nl"
                        })
                self.test(test_tty_multiple_open_close_same_dev
                        , {
                            "tty_iccom_ch": 2874
                            , "tty_number": 4
                            , "reopens_count": 10
                            , "msgs_count": 10
                            , "msg_max_size": 40
                            , "test_id": "test_tty_reopening"
                        })
                self.test(test_tty_multiple_open_read_close_same_dev
                        , {
                            "tty_iccom_ch": 2874
                            , "tty_number": 4
                            , "reopens_count": 10
                            , "msgs_count": 10
                            , "msg_max_size": 40
                            , "test_id": "test_tty_reopen_and_read"
                        })

def run_tests():

        tester = IccomTtyTester(skip_list=[
        #    "tty_create"
        #    , "tty_basic_write"
        #    , "test_tty_basic_read_normal"
        #    , "test_tty_basic_read_1ch"
        #    , "test_tty_basic_read_nl"
        #    , "test_tty_basic_read_30chars_nl"
        #    , "test_tty_basic_read_40chars_nl"
        #    , "test_tty_basic_read_30chars"
        #    , "test_tty_basic_read_40chars"
        #    , "test_tty_basic_read_100msgs_up_to_40chars_with_nl"
        ])

        tester.run_tests()

        tester.print()

        return tester