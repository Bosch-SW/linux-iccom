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
