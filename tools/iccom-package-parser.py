import sys
import json
import os

tools_dir_path = os.path.dirname(os.path.realpath(__file__))
iccom_repo_root = os.path.realpath(os.path.join(tools_dir_path, "../"))
test_dir_path = os.path.join(iccom_repo_root, "test/")
sys.path.append(test_dir_path)

try:
    import iccom
except e:
    print("It looks like you don't have the iccom.py file available"
          "the python PATH nor in %s folder. I'm expected either\n"
          "* to get launched directly from the iccom repository\n"
          "* or to have the iccom.py file next to me or in\n"
          "  default python path (iccom.py is located in the\n"
          "  <ICCOM_REPO_ROOT>/test/iccom.py)\n" % (test_dir_path,))
    exit()

# proper serialization for the bytearrays
class BytearrayEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
            return str(obj.hex())
        else:
            super().default(obj)

def main_parsing():
    if (len(sys.argv) < 2):
        print("Hello, I parse ICCom data packages, pls give me"
            " a hex string as first arg.\n")
        print(" example:  python3 iccom-package-parser.py "
            "00180100020095747300020082747300"
            "0200837473000200847473ffffffffff"
            "ffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffbfa6d7a7"
            "\n\n")
        exit()

    package_hex_string = sys.argv[1]
    package_bytes = bytearray.fromhex(package_hex_string)

    print("Parsing: %s\n" % package_hex_string)
    res = iccom.iccom_package_parse(package_bytes, pedantic=True)
    print(json.dumps(res, indent=4, cls=BytearrayEncoder))

main_parsing()