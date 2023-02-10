import subprocess

def execute_command(command):
        subprocess.run(command, shell=True)

def execute_command_with_result(command):
        return subprocess.check_output(command, shell=True, text=True)

def create_iccom_device():
        command = "sudo sh -c \"echo > /sys/class/iccom/create_device\""
        execute_command(command)

def create_dummy_transport_device():
        command = "sudo sh -c \"echo > /sys/class/dummy_transport/create_transport\""
        execute_command(command)

def link_dummy_transport_device_to_iccom_device(dummy_transport_device, iccom_device):
        command = "sudo sh -c \"echo {} > /sys/devices/platform/{}/transport\"".format(dummy_transport_device, iccom_device)
        execute_command(command)

def create_iccom_channel(iccom_device, channel):
        command = "sudo sh -c \"echo c{} > /sys/devices/platform/{}/channels_ctl\"".format(channel, iccom_device)
        execute_command(command)

def delete_channel(iccom_device, channel):
        command = "sudo sh -c \"echo d{} > /sys/devices/platform/{}/channels_ctl\"".format(channel, iccom_device)
        execute_command(command)

def send_iccom_data_to_transport(iccom_device, channel, message):
        command = "sudo sh -c \"echo {} > /sys/devices/platform/{}/channels/{}\"".format(message, iccom_device, channel)
        execute_command(command)

def receive_transport_data_to_iccom(iccom_device, channel):
        command = "cat /sys/devices/platform/{}/channels/{}".format(iccom_device, channel)
        return execute_command_with_result(command)

def send_transport_data_to_iccom(dummy_transport_device, hex_str):
        command = "sudo sh -c \"echo {} > /sys/devices/platform/{}/W\"".format(hex_str, dummy_transport_device)
        execute_command(command)

def check_iccom_to_transport_next_xfer_data(dummy_transport_device):
        command = "cat /sys/devices/platform/{}/R".format(dummy_transport_device)
        return execute_command_with_result(command)

def create_transport_device_RW_files(dummy_transport_device):
        command = "sudo sh -c \"echo 1 > /sys/devices/platform/{}/showRW_ctl\"".format(dummy_transport_device)
        execute_command(command)

def delete_transport_device_RW_files(dummy_transport_device):
        command = "sudo sh -c \"echo 0 > /sys/devices/platform/{}/showRW_ctl\"".format(dummy_transport_device)
        execute_command(command)