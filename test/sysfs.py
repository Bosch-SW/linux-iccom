import subprocess
import zlib
from time import sleep
import errno
import os
import string
import random

# Read a sysfs file and handle expectations
# within the function by raising errors when errors
# are found or expectations are mismatched
#
# @file {string} file to read
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
#
# Returns:
# Empty String
# String with data read
#
# Throws an exception if the received error doesn't match expected
def read_sysfs_file(file, err_expectation):

    try:
        with open(file, 'r') as file:
            return str(file.read())
    except OSError as e:
        if err_expectation == None:
            raise RuntimeError("Sysfs read file unexpected error \n"
                               "    (file) %s \n"
                               "    (error) %s \n"
                               % (file, e.errno))
        else:
            if (e.errno != err_expectation):
                raise RuntimeError("Sysfs read file expectation mismatch\n"
                     "    (file) %s \n"
                     "    (actual) %s \n"
                     "    (expectation) %s \n"
                     % (file, e.errno, err_expectation))
    return ""

# Write a sysfs file and handle expectations
# within the function by raising errors when errors
# are found or expectations are mismatched
#
# @file {string} file to write
# @content_to_write {string} content to write
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
#
# Throws an exception if the received error doesn't match expected
def write_sysfs_file(file, content_to_write, err_expectation):
    try:
        with open(file, 'w') as file:
            file.write(content_to_write)
    except OSError as e:
        if err_expectation == None:
            raise RuntimeError(
                    ("Sysfs write file unexpected error \n"
                    "    (file) %s \n"
                    "    (error) %s "
                    + ("(ENOENT: no such file or dir)" if e.errno == 2 else "")
                    + "\n")
                    % (file, e.errno))
        else:
            if (e.errno != err_expectation):
                raise RuntimeError("Sysfs write file expectation mismatch\n"
                     "    (file) %s \n"
                     "    (actual) %s \n"
                     "    (expectation) %s \n"
                     % (file, e.errno, err_expectation))

# Checks whether a sysfs file exists or not and handle expectations
# within the function by raising errors when errors
# are found or expectations are mismatched
#
# @file {string} file to check for presence
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# Throws an exception if the received error doesn't match expected
def check_sysfs_file_presence_expectation(file, expectation):
    if os.path.exists(file) != expectation:
        raise RuntimeError("sysfs file presence expectation mismatch\n"
                               "    (file) %s \n"
                               "    (actual) %s \n"
                               "    (expectation) %s \n"
                               % (file, not expectation, expectation))
