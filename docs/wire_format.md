This file describes the ICCom on-wire message format(s), and
serves to keep the systems on-wire compatible when they are
connected with the ICCom.

The stack diagram is the following:

```
-------------------------------------------------
|   ICCom clients: IccomSkif, IccomTty, ....    |
-------------------------------------------------
           |       ICCom       |
           ---------------------
           |    Full Duplex    |
           |     transport     |
           ---------------------
```

The underlying transport is full duplex, so every time sides exchange
**equal** amount of data on the transport layer (below ICCom driver).

**The current file describes the data format between the ICCom
and Full Duplex transport layer.** In case the Full Duplex transport
is represented by SymSPI or Fdvio drivers, then they don't distort
the data and it is in this case equal to what we should actually
see on a physical layer of the communication.

**NOTE:** for any protocol version it makes sense to check the
  testing code under the `/test/iccom_*.py`.

# Version 1.0 messaging

**NOTE:** for ultimate check up for every single detail, please
  consult the `/test/iccom_test.py` which contains the vast majority
  of self-explanatory testing code for ICCom driver. You may want
  to start with `iccom_tests_sanity_check` function there.

Each interaction goes in two steps:
* first the data package exchange is carried out (data frame),
* second goes the ack packages exchange (ack frame).

Example:

* data frame:
  * A -> B:  data package of total size of 64 bytes;
    and at the same time:
    B -> A:  data package of total size of 64 bytes;
* ack frame:
  * A -> B:  ack or nack indication of total size 1 byte;
    and at the same time:
    B -> A:  ack or nack indication of total size 1 byte;

## Data package

The data package has the statically configurable size (default data
package size is `64 bytes`) and has the following per-byte structure
(see also `/test/iccom.py` file the `iccom_package` function):

```
   [0;1]      |      [2;2]       |  [3;..]   | (between) | {last 4 bytes}
PAYLOAD_SIZE  |  PACKAGE_SEQ_ID  |  PAYLOAD  |  PADDING  |     CRC32
(BIG endian)  | (little endian)  |           |           | (little endian)
```

Here is more detailed fields description:
* `[0;1] bytes`: **the payload size in bytes** (the actual
  package paylod data size: package header, package crc32,
  package payload area padding are **not** a part of payload).
  **NOTE:** byteorder is `big-endian`.
* `[2;2] bytes`: **the package sequential ID** which is incremented
  with each package sent and wraps around. Serves to prevent
  duplicated data receivings. All values are valid: `[0,255]`.
  If receiver gets a package with the ID == to the ID of the previous
  package then the current package will be discarded with ACK (treated
  as a duplicated package).
* `[3; 3 + PAYLOAD_SIZE - 1] bytes`: **the actual package payload bytes**.
  The payload area is sequentially filled with packages data (see the
  Data package structure section), no gaps between packages.
* `[3 + PAYLOAD_SIZE; PACKAGE_SIZE - CRC32_SIZE - 1] bytes`: **(might absent if
  there is no space between payload end and CRC32) the padding of
  unused payload area**, the padding uses for now the `0xff` value.
* `[PACKAGE_SIZE - CRC32_SIZE; PACKAGE_SIZE - 1] bytes`: the last
  bytes of the package (for now last 4 bytes) **crc32** in little endian
  byte order. CRC32 is computed on top of **all bytes of the package
  except of the CRC32 bytes themselves**.
      
## Ack/nack package

Ack/nack-package is a fixed content small (1 byte) package  which
confirms/not-confirms the receiving of the previously sent Data package.

* Ack package is: `0xD0`
* Nack package is: `0xE1`

## Data package payload structure

The data package payload area is filled sequentially (without gaps) with
the Data Packets. After last packet (as mentioned in Data package section)
there must be a `0xff` padding filling the empty space (if there is one)
of package payload area.

Shortly the Data Package payload can be described as follows:

```
${data_packet}${data_packet}...${data_packet}${0xff to fill empty space left}
```

Where each `${data_packet}` is the contents of Data packet. Data
packet has the following structure.

### Data packet structure

Data packet is intended to deliver a user message (part of user a message),
via transport to the specific logical channel. Hence the data structure
(see also `/test/iccom.py` file the `iccom_packet` function):

```
|     [0;1]        |         [2;2]                |
|  PAYLOAD_SIZE    |   [14;7] bits of channel     |
|  (BIG endian)    |  ( (channel & 0x7F80) >> 7)  | 
```
and continue:
```
 |                      [3;3]                     |     [4;...]    |
 |  [6;0] bits of channel | [7] bit complete flag |     PAYLOAD    |
 |    (channel & 0x7F)       (indicates that msg  |                |
 |                              is completed)     |                |
```

**NOTE:** the packet size varies with it's payload size.

* `[0;1] bytes`: **the packet payload (payload section) size in bytes**.
* `[2;2] bytes`: the `[14;7]` bits of the ICCom logical channel number, 
  **NOTE:** the logical channel number is in total 15 bits in size, with
  corresponding values range [0; 32768]. 
  This byte value is computed as `channel & 0x7F80 >> 7`.
* `[3;3] bytes`: `[6;0]` bits are the `[6;0]` bits of the ICCom logical
  channel number. And the `[7;7]` bit is set when the current message on
  current logical channel is completed (can be delivered to upper layer).
  This byte value is computed as `channel & 0x007F | (complete ? 0x80 : 0x0)`.
* `[4; ...] bytes`: the payload bytes, the user message bytes.