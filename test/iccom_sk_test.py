import subprocess

import iccom_test as iccom

def execute_command(command):
        subprocess.run(command, shell=True)

def execute_command_with_result(command):
        return subprocess.check_output(command, shell=True, text=True)

def create_iccom_sockets_device():
        command = "echo > /sys/class/iccom_socket_if/create_device"
        execute_command(command)

def delete_iccom_sockets_device(iccom_sk_id):
        command = "echo {} > /sys/class/iccom_socket_if/delete_device".format(iccom_sk_id)
        execute_command(command)

def link_iccom_sockets_device_to_iccom_device(iccom_device, iccom_sockets_device):
        command = "echo {} > /sys/devices/platform/{}/iccom_dev".format(iccom_device, iccom_sockets_device)
        execute_command(command)

def set_socket_protocol_family(protocol_family_number, iccom_sockets_device):
        command = "echo {} > /sys/devices/platform/{}/protocol_family".format(protocol_family_number,iccom_sockets_device)
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        process.wait()
        print(process.returncode)
        return process.returncode
        
def test_set_not_valid_protocol_family(iccom_sockets_device):
        # Try to set a value not valid, less than 22 (NETLINK)
        string_received_result = set_socket_protocol_family(-1, iccom_sockets_device)
        
        if(string_received_result != 0):
                print("iccom_sk_test_1:PASSED")
        else:
                print("iccom_sk_test_1:FAILED")

if __name__ == '__main__':

        print("#### Inserting iccom.ko ...")
        execute_command("insmod /modules/iccom.ko")
        print("#### Inserting iccom_socket_if.ko ...")
        execute_command("insmod /modules/iccom_socket_if.ko")

        iccom_device = []
        iccom_sockets_device = []
        dummy_transport_device = []
        protocol_family = 22 #NETLINK_ICCOM
        aux = 0

        iccom_device.append("iccom.0")
        iccom_device.append("iccom.1")

        iccom_sockets_device.append("iccom_socket_if.0")
        iccom_sockets_device.append("iccom_socket_if.1")

        dummy_transport_device.append("dummy_transport.0")
        dummy_transport_device.append("dummy_transport.1")

        ## Create iccom device instances
        print("#### Creating Iccom devices ...")
        for x in iccom_device:
                iccom.create_iccom_device()

        # Create iccom device instances
        print("#### Creating transport devices ...")
        for x in dummy_transport_device:
                iccom.create_dummy_transport_device()

        ## Create iccom socket device instances
        print("#### Creating Iccom Sk devices with protocol family ...")
        for x in iccom_sockets_device:
                create_iccom_sockets_device()
                set_socket_protocol_family(protocol_family,
						iccom_sockets_device[aux])
                aux += 1
                protocol_family += 1

        # Link tranport device to iccom
        print("#### Link transport to iccom device ...")
        iccom.link_dummy_transport_device_to_iccom_device(dummy_transport_device[0], iccom_device[0])

        # Link iccom device to iccom socket device 
        print("#### Link iccom dev to iccom sk device ...")
        link_iccom_sockets_device_to_iccom_device(iccom_device[0], iccom_sockets_device[0])
        
        # Test start
        test_set_not_valid_protocol_family(iccom_sockets_device[1])

        # Delete iccom_sk device
        print("#### Delete iccom sk device ...")
        for x in iccom_sockets_device:
                delete_iccom_sockets_device(x)
                #Delete iccom devices

        ## iccom py end
        print("Removing iccom_socket_if.ko ..")
        execute_command("rmmod iccom_socket_if.ko")
        print("Removing iccom.ko ..")
        execute_command("rmmod iccom.ko")
