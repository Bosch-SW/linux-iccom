import subprocess
import zlib
from time import sleep

def execute_command(command):
    subprocess.run(command, shell=True)

def execute_command_with_result(command):
    return subprocess.check_output(command, shell=True, text=True)

def create_iccom_device():
    command = "echo > /sys/class/iccom/create_device"
    execute_command(command)

def create_dummy_transport_device():
    command = "echo > /sys/class/dummy_transport/create_transport"
    execute_command(command)

def link_dummy_transport_device_to_iccom_device(
        dummy_transport_device, iccom_device):
    command = "echo {} > /sys/devices/platform/{}/transport".format(dummy_transport_device, iccom_device)
    execute_command(command)

def create_iccom_channel(iccom_device, channel):
    command = "echo c%d > /sys/devices/platform/%s/channels_ctl" % (channel, iccom_device)
    execute_command(command)

def delete_channel(iccom_device, channel):
    command = "echo d{} > /sys/devices/platform/{}/channels_ctl".format(channel, iccom_device)
    execute_command(command)

def iccom_write(iccom_device, channel, message):
    command = "echo %s > /sys/devices/platform/%s/channels/%d" % (message, iccom_device, channel)
    execute_command(command)

def iccom_read(iccom_device, channel):
    command = "cat /sys/devices/platform/%s/channels/%d" % (iccom_device, channel)
    return execute_command_with_result(command)

def write_to_wire(dummy_transport_device, data):
    print("iccom_test: incoming other side data: %s" % (data.hex(),))
    command = "echo %s > /sys/devices/platform/%s/W" % (data.hex(), dummy_transport_device)
    execute_command(command)

# Does the full duplex exfer on wire
# @transport_dev the transport to work with
# @send_data the bytearray of the data to send
#
# RETURNS: the received data as bytearray
def wire_xfer(transport_dev, send_data):
    write_to_wire(transport_dev, send_data)
    sleep(0.1)
    return bytearray.fromhex(read_from_wire(transport_dev))

# Does the wire full duplex xfer and checks if the
# received data matches expected
# @transport_dev the transport to work with
# @send_data the bytearray of the data to send
# @expected_rcv_data bytearray we expect to receive
#
# Throws an exception if the received data doesn't match expected
def check_wire_xfer(transport_dev, send_data, expected_rcv_data):
    rcv_data = wire_xfer(transport_dev, send_data)
    if (rcv_data != expected_rcv_data):
        raise RuntimeError("the unexpected data on wire!\n"
                           "    %s (expected)\n"
                           "    %s (received)\n"
                           % (expected_rcv_data.hex(), rcv_data.hex()))

# Does the wire full duplex ack xfer and checks if the other side
# acks as well.
# @transport_dev the transport to work with
#
# Throws an exception if the the other side doesn't ack
def check_wire_xfer_ack(transport_dev):
        check_wire_xfer(transport_dev, iccom_ack_package()
                                     , iccom_ack_package())

def check_ch_data():

def read_from_wire(dummy_transport_device):
    command = "cat /sys/devices/platform/%s/R" % (dummy_transport_device,)
    return execute_command_with_result(command)

def create_transport_device_RW_files(dummy_transport_device):
    command = "echo 1 > /sys/devices/platform/{}/showRW_ctl".format(dummy_transport_device)
    execute_command(command)

def delete_transport_device_RW_files(dummy_transport_device):
    command = "echo 0 > /sys/devices/platform/{}/showRW_ctl".format(dummy_transport_device)
    execute_command(command)

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
                               + package_sequential_number.to_bytes(1, "big"))
                     
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
    return (len(payload).to_bytes(2, "little")
            + ((channel << 1) | complete).to_bytes(2, "little")
            + payload)

def iccom_data_exchange_to_transport_with_iccom_data_with_transport_data(transport_dev, iccom_device):

        try:
            test_name = "Exchange data from iccom to transport and answer from tansport to iccom with default data"

            print("======== TEST: %s ========" % (test_name,))

            create_iccom_channel(iccom_device, 1)
            create_transport_device_RW_files(transport_dev)

            # Send a message from ICCOM to dummy transport via channel 1
            iccom_write(iccom_device, 1, "Who are you?")

            # Do (Default xfer) Data Exchange + ACK
            check_wire_xfer(transport_dev, iccom_package(1, bytearray())
                                         , iccom_package(1, bytearray()))
            check_wire_xfer_ack(transport_dev)

            # Do ("I am Luis" xfer) Data Exchange + ACK
            check_wire_xfer(transport_dev, iccom_package(2, iccom_packet(1, bytearray(b"I am Luis"), True))
                                         , iccom_package(2, iccom_packet(1, bytearray(b"Who are you?"), True)))
            check_wire_xfer_ack(transport_dev)

            # time is a bad companion, but still we need some time to allow the
            # kernel internals to work all out with 100% guarantee, to allow
            # test stability
            sleep(1)

            # Check result
            received_ch = iccom_read(iccom_device, 1)

            print("iccom_test_1.python: PASS")

        except Exception as e:
            print("iccom_test_1.python: FAILED: %s" % (str(e),))

def iccom_data_exchange_to_transport_with_iccom_data_without_transport_data(dummy_transport_device, iccom_device):

        test_name = "Exchange data from iccom to transport and vice versa with valid data"
        string_expected = iccom_package(3, bytearray()).hex();

        # Create Channel 1
        create_iccom_channel(iccom_device, 1)

        # Create Transport RW Files
        create_transport_device_RW_files(dummy_transport_device)

        # Send a message from ICCOM to dummy transport via channel 1
        iccom_write(iccom_device, 1, "Who are you\?")

        # Do (Default xfer) Data Exchange + ACK
        write_to_wire(dummy_transport_device, iccom_package(1, bytearray()));
        write_to_wire(dummy_transport_device, iccom_ack_package())

        # Do (Default xfer) Data Exchange + ACK
        write_to_wire(dummy_transport_device, iccom_package(2, bytearray()));
        write_to_wire(dummy_transport_device, iccom_ack_package())

        # Check result
        string_received = read_from_wire(dummy_transport_device)

        if(string_received == string_expected):
                print("iccom_test_2.python: PASS")
        else:
                print("iccom_test_2.python: FAILED")

def iccom_data_exchange_to_transport_with_iccom_data_with_transport_data_wrong_payload_size(
            dummy_transport_device, iccom_device):

        test_name = ("Exchange data from iccom to transport and answer from"
                    " tansport to iccom with default data with wrong payload")

        string_expected = iccom_nack_package().hex()

        # Create Channel 1
        create_iccom_channel(iccom_device, 1)

        # Create Transport RW Files
        create_transport_device_RW_files(dummy_transport_device)

        # Send a message from ICCOM to dummy transport via channel 1
        iccom_write(iccom_device, 1, "Who are you\?")

        # Do (Default xfer) Data Exchange + ACK
        write_to_wire(dummy_transport_device, iccom_package(1, bytearray()));
        write_to_wire(dummy_transport_device, iccom_ack_package())

        # Do (Default xfer) Data Exchange without ACK
        package = iccom_package(2, bytearray())
        package[1] = 0x02;
        write_to_wire(dummy_transport_device, package)

        # Check result
        string_received = read_from_wire(dummy_transport_device)

        if(string_received == string_expected):
                print("iccom_test_3.python: PASS")
        else:
                print("iccom_test_3.python: FAILED")

def iccom_data_exchange_to_transport_with_iccom_data_with_transport_nack(
            dummy_transport_device, iccom_device):

        test_name = "Exchange data from iccom to transport and answer from tansport to iccom with nack"

        string_expected = iccom_package(1, bytearray()).hex()

        # Create Channel 1
        create_iccom_channel(iccom_device, 1)

        # Create Transport RW Files
        create_transport_device_RW_files(dummy_transport_device)

        # Send a message from ICCOM to dummy transport via channel 1
        iccom_write(iccom_device, 1, "Who are you\?")

        # Do (Default xfer) Data Exchange + NACK
        write_to_wire(dummy_transport_device, iccom_package(1, bytearray()))
        write_to_wire(dummy_transport_device, iccom_nack_package())

        # Check result
        string_received = read_from_wire(dummy_transport_device)

        if(string_received == string_expected):
                print("iccom_test_4.python: PASS")
        else:
                print("iccom_test_4.python: FAILED")

if __name__ == '__main__':

        #print("Mounting sys ..")
        #execute_command("mount sysfs /sys -t sysfs")

        print("Inserting iccom.ko ..")
        execute_command("insmod /modules/iccom.ko")

        # iccom py start

        iccom_device = []
        dummy_transport_device = []

        iccom_device.append("iccom.0")
        iccom_device.append("iccom.1")
        iccom_device.append("iccom.2")
        iccom_device.append("iccom.3")

        dummy_transport_device.append("dummy_transport.0")
        dummy_transport_device.append("dummy_transport.1")
        dummy_transport_device.append("dummy_transport.2")
        dummy_transport_device.append("dummy_transport.3")

        ## Create iccom device instances
        for x in iccom_device:
                create_iccom_device()

        # Create iccom device instances
        for x in dummy_transport_device:
                create_dummy_transport_device()

        # Link tranport device to iccom
        link_dummy_transport_device_to_iccom_device(dummy_transport_device[0], iccom_device[0])
        link_dummy_transport_device_to_iccom_device(dummy_transport_device[1], iccom_device[1])
        link_dummy_transport_device_to_iccom_device(dummy_transport_device[2], iccom_device[2])
        link_dummy_transport_device_to_iccom_device(dummy_transport_device[3], iccom_device[3])

        # Test #1
        iccom_data_exchange_to_transport_with_iccom_data_with_transport_data(dummy_transport_device[1], iccom_device[1])

        # Test #2
        iccom_data_exchange_to_transport_with_iccom_data_without_transport_data(dummy_transport_device[0], iccom_device[0])

        # Test #3
        iccom_data_exchange_to_transport_with_iccom_data_with_transport_data_wrong_payload_size(dummy_transport_device[2], iccom_device[2])

        #Test #4
        iccom_data_exchange_to_transport_with_iccom_data_with_transport_nack(dummy_transport_device[3], iccom_device[3])

        ## iccom py end
        print("Removing iccom.ko ..")
        execute_command("rmmod iccom.ko")
