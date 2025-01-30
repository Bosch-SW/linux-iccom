import sys

# Parses ICCom package into human readable data.
# For now just prints it to stdout.
# NOTE: For now just handles the proper-formed packages.
def iccom_parse(data_package_bytes):
    package_payload_size = int.from_bytes(data_package_bytes[0:2], 'big')
    package_sequence_id = int.from_bytes(data_package_bytes[2:3], 'little')
    ppb = data_package_bytes[3:3 + package_payload_size]

    print("Package:")
    print("  payload size: %d bytes" % package_payload_size)
    print("  sequence id: %d" % package_sequence_id)

    pkt_off = 0
    while (pkt_off < package_payload_size):
        p_size = int.from_bytes(ppb[pkt_off : pkt_off + 2], 'big')
        hi_ch = int.from_bytes(ppb[pkt_off + 2 : pkt_off + 3], 'big')
        lo_ch = int.from_bytes(ppb[pkt_off + 3 : pkt_off + 4], 'big') & 0x7F
        ch = (hi_ch << 7) | lo_ch
        complete = ((int.from_bytes(ppb[pkt_off + 3 : pkt_off + 4], 'big') & 0x80) == 0x80)

        print("  Pkt:")
        print("    ch: %d" % ch)
        print("    complete: %s" % ("true" if complete else "false"))
        print("    payload size: %d bytes" % p_size)
        print("    payload: %s" % (ppb[pkt_off + 4: pkt_off + 4 + p_size].hex(),))

        pkt_off += 4 + p_size

if (len(sys.argv) < 2):
    print("Hello, I parse ICCom data packages, pls give me a hex string as first arg.\n")
    print(" example:  python3 parser.py 001801000200957473000200827473000200837473000200847473ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfa6d7a7\n\n")
    exit()

package_hex_string = sys.argv[1]
package_bytes = bytearray.fromhex(package_hex_string)

print("Parsing: %s\n" % package_hex_string)
iccom_parse(package_bytes)