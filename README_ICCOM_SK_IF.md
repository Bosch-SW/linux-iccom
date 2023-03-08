# 1. Iccom Sockets If user guide

Table of contents
- [1. Iccom Sockets If user guide](#1-iccom-sockets-if-user-guide)
	- [1.1. Introduction](#11-introduction)
	- [1.2. Iccom Sockets sysfs class and device attributes](#12-iccom-sockets-sysfs-class-and-device-attributes)
		- [1.2.1. Iccom sockets if class](#121-iccom-sockets-if-class)
			- [1.2.1.1. create\_device](#1211-create_device)
			- [1.2.1.2. version](#1212-version)
		- [1.2.2. Iccom sockets if device attributes](#122-iccom-sockets-if-device-attributes)
			- [1.2.2.1. protocol\_family](#1221-protocol_family)
			- [1.2.2.2. iccom\_dev](#1222-iccom_dev)


## 1.1. Introduction

The `Iccom sockets if` implementation has proven its functionality when running
in the physical environment, in a physical target device. However, its configuration
and the possibility to work in a development environment where the physical 
target is not available, highlighted this driver's low flexibility aspect.
In order to enable one to easily test and run this driver in a development 
environment where the actual target is not available, sysfs facilities are now
encompassed in the `Iccom sockets if` platform driver implementation.
This sysfs implementation will allow one to trigger the iccom sockets if device 
creation, its configuration (e.g., protocol family) and to do dynamic linkage 
from a created `Iccom sockets if` to an existing iccom device.
Using the test python scripts globally available to the iccom world (i.e., `Iccom`,
`Iccom sockets if` and `transport` drivers) one will be able to test individually
each driver and, moreover, test the data path from the transport layer to the
`Iccom sockets if` layer.

## 1.2. Iccom Sockets sysfs class and device attributes

The sysfs implementation for the `Iccom sockets if` means that nowadays there is a
new Iccom Sockets If class. This class allows to create the several `Iccom sockets if` 
devices to be used alongside the development activities. With these `Iccom sockets if` 
devices comes their attributes that will allow to configure
and test the desired `Iccom` channels (and transport layer), for example. All
these configuration and testing activities are accomplished without having a 
dependency with a physical target device that most of the times is not available
at early project stages. 

### 1.2.1. Iccom sockets if class

This class allows to group all devices from the `Iccom sockets if` since they all 
share the same functionality. Additionaly, using the sysfs filesystem there is
a way of interfacing with the `Iccom sockets if` driver that is defined in the 
Kernel space.
Currently there are two attributes available for the `Iccom sockets if`: one to 
create `Iccom sockets if` devices [(create_device)](#1211-create_device) and the
other to get the version/revision from the `Iccom sockets if` driver [(version)](#1212-version).

#### 1.2.1.1. create_device

In order to create an `Iccom sockets if` device the following command can be
issued and automatically it will set the device name and its id. 

	echo > /sys/class/iccom_socket_if/create_device

This will result in a new device, completely registered and with a set of 
attributes that can be used to configure it.
#### 1.2.1.2. version

During the development cycle somthing that can be useful is to know which **version**
does a device represents and therefore it will be noticeable which `Iccom sockets if`
driver implementation it provides. The following command returns this information:

	echo > /sys/class/iccom_socket_if/version

### 1.2.2. Iccom sockets if device attributes

With each `Iccom sockets if` device created, a set of attributes get exposed for
configuration needs. These attributes compose the configuration part of each 
device.

#### 1.2.2.1. protocol_family

The **protocol_family** makes possible the configuration of the socket's 
protocol family that is part of an `Iccom sockets if` device. Each device has to
have a socket with different protocol family.

	echo PROTOCOL_FAMILY_NR > /sys/devices/platform/iccom_socket_if.x/protocol_family

#### 1.2.2.2. iccom_dev

In order to be possible to test the sending and receiving of messages between
the `Iccom sockets if` layer and the others below, there's the need of having
an associated `Iccom` device.
Furthermore, the **iccom_dev** attributes makes possible the indication of an
existing `Iccom` device and to bind it to the respective `Iccom sockets if` 
device.

	echo iccom.X > /sys/devices/platform/iccom_socket_if.Y/iccom_dev

As soon as this attribute is affected (as shown above), the `Iccom` device is 
binded to the indicated `Iccom sockets if` device, the associated netlink socket
is created and initialized and the underlaying protocol is initialized, as well 
as the callbacks that will handle data comming from both upper and lower layers.