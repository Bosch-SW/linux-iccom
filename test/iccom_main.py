import subprocess
import os

from iccom import iccom_version

import iccom_test
import iccom_skif_test
import iccom_tty_test

def execute_command(command):
    if (subprocess.run(command, shell=True).returncode != 0):
        raise Exception("Failed to run: %s" % (command,))

class ModulesDeployer:
    def __init__(self, modules_list):
        self.mods_list = modules_list

    def deploy_modules(self):
        for mpath in self.mods_list:
            print("#### Inserting %s" % (mpath,))
            execute_command("insmod %s" % (mpath,))
    
    def dismiss_modules(self):
        for mpath in reversed(self.mods_list):
            print("#### Removing %s" % (mpath,))
            name = os.path.splitext(os.path.basename(mpath))[0] 
            execute_command("rmmod %s" % (name,))

    def __enter__(self):
        self.deploy_modules()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.dismiss_modules()
        return self

if __name__ == '__main__':

    tests = []

    with ModulesDeployer([
            "/modules/iccom.ko"
            , "/modules/fd_test_transport.ko"
            , "/modules/iccom_socket_if.ko"
            , "/modules/iccom_tty.ko"
            ]):

        print("ICCom repository revision: %s" % (iccom_version(None),))

        # Run tests
        tests.append(iccom_test.run_tests())
        tests.append(iccom_skif_test.run_tests())
        tests.append(iccom_tty_test.run_tests())

    for t in tests:
         t.print()
