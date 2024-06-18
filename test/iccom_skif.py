import errno
import socket
import re
from time import sleep
import glob
import os

from sysfs import *

# Size of the header within a netlink message
NLMSG_HDR_SIZE_BYTES = 16

# Creates an iccom socket via sysfs interface
#
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_iccom_sockets_device(err_expectation):
        print("Creating ICComSkif device.")
        file = "/sys/class/iccom_socket_if/create_device"
        command = " "
        write_sysfs_file(file, command, err_expectation)

# Deletes an iccom socket via sysfs interface
#
# @iccom_sk_id iccom socket interface device id
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_iccom_sockets_device(iccom_sk_id, err_expectation):
        print("Deleting ICComSkif device: ", iccom_sk_id)
        file = "/sys/class/iccom_socket_if/delete_device"
        command = "%s" % (iccom_sk_id)
        write_sysfs_file(file, command, err_expectation)

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
        write_sysfs_file(file, command, err_expectation)

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
        write_sysfs_file(file, command, err_expectation)
