# Introduction into apps and system performance debugging using ICCom

OK, I'm not going to make it long: here you will find a cheatlist
on debugging your application communication with iccom tools.

Hint: all the relative paths below are written relative to the
repository root.

# Cheatsheet

## Get Channels statistics overview

Getting a data streaming overview allows one to see the system
perfomance bottle necks and excessive data streaming cases.

To see overal **incoming** messages statistics per channel
run the following command:

```
$ cat /sys/devices/platform/iccom0/channels
    # NOTE: "iccom0" is just a local iccom device name, you
    #       may have it different
```

it will output a list of channels together with corresponding

* total number of messages **received**
* total number of bytes **received**

like this:

```
22200:  I: 20 m 272 b   # on channel 22200 was received 20 msgs
12510:  I: 1 m 8 b      #    in total of 272 payload bytes.
24:  I: 1 m 38 b
150:  I: 1 m 14 b
141:  I: 3 m 34 b
168:  I: 1 m 14 b
```

## Parse full data package

If you somehow got the iccom data package (more on this later)
and need to check which payloads are contained in the package
use the `./tools/parser.py` utility (**NOTE: it for now assumes
that the package is correct, so you will not see a full-blown
parsing covering invalid package datas**):

```
$ python3 parser.py 001801000200957473000200827473000200837473000200847473ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfa6d7a7
```

where the first `parser.py` argument is the full data package
hex representation.

It will output the parse information for the package like following:

```
Parsing: 001801000200957473000200827473000200837473000200847473ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfa6d7a7

{
    "package_payload_size": 24,
    "package_sequence_id": 1,
    "packets": [
        {"ch": 21, "complete": true, "data_size": 2, "data": "7473"},
        {"ch": 2, "complete": true, "data_size": 2, "data": "7473"},
        {"ch": 3, "complete": true, "data_size": 2, "data": "7473"},
        {"ch": 4, "complete": true, "data_size": 2, "data": "7473"}
    ]
}
```

## Actually check what does your application talk about

Sometimes it is needed for debugging/logging reasons to know what is/was
the application ICCom communication at a given time frame:

```
    App Frontend
         |ch X    <---    say, we need to know the interaction
         |                between backend and frontend for some
         |                faulty scenario.
         |
===================== kernel boundary
  ---------------
     ICComSkif
  ---------------
       ICCom
  ---------------
        ...
        ...
         |
         |ch X
    App Backend

```

The best way to debug it would be using the extra routing table
rules to duplicate the incoming and outgoing application traffic
to the separate unused channels.

Here is the example to debug channel number 12, iccom skif device 27:

```
$ echo -n "+;12u20012u;12d10012u;" > /sys/devices/platform/iccom_socket_if.27/routing_table

    # NOTE: to undo the duplication use the following cmd
    #   $ echo -n "-;12u20012u;12d10012u;" > /sys/devices/platform/iccom_socket_if.27/routing_table

    # NOTE: "iccom_socket_if.27" is just an example of the
    #   ICComSkif device name, it most probably will be different
    #   in your case.

    # NOTE: for more details on package routing see the
    #   ICComSkif advanced routing documentation.
```

this command will take the incoming messages (from kernel toward
user space) in channel 12 and duplicate them to channel 20012
toward user space, and also take the outgoing messages in channel
12 and duplicate them to the channel 10012 toward user space as well.
It will make the communication channels looking like:

```
    App Frontend
       ch|12
         |
         |       LOGGING UTILITY
         |        ^          ^
         |        |          |
         v      ch|10012   ch|20012
=================================== kernel boundary
         |       /          /
         |\     /     _____/
         | \___^     /
         ^          /        So, the channel 12 works
         |  _______^      as it worked before, but messages
         v /              ^ messages duplicated -> ch 20012
         |/               v messages duplicated -> ch 10012
         ^
         |                Logging utility can get those and log
         |                them.
         v
     ICComSkif
  ---------------
       ICCom
  ---------------
        ...
        ...
         ^
         |ch 12
         v
    App Backend

```

Having this done you would get a full access to the target channel
data streams (12-th channel in this case).

NOTE: the thing to be careful about is that incoming and outgoing
**messages streams are not to be expected to be perfectly synchronized
between each other**, meaning that there is no guarantee that
application will see atomically the same send-receive order
as the logging utility (rcv/snd threads scheduling might
easily swap the closely-timed messages). But they surely will be
ordered within the streams and given that the system is alive
also be local with relative to time (mesages with small time
difference for application remain time-close for logging utility).