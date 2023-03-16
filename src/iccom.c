/*
 * This file defines the Inter Chip/CPU communication protocol (ICCom)
 * driver for communication between two CPUs based on full duplex
 * fully symmetrical transport layer (like one provided by SymSPI).
 *
 * Copyright (c) 2020 Robert Bosch GmbH
 * Artem Gulyaev <Artem.Gulyaev@de.bosch.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// SPDX-License-Identifier: GPL-2.0

// ICCom protocol overiview is the following:
//
// * based on full-duplex and fully symmetrical transport layer
//   (like SymSPI)
// * single transmission frame consists of two steps:
//   * data package transmission (in both directions)
//   * ack package transmission (in both directions)
// * data package (is of fixed size) consists of
//   * header
//   * payload
//   * CRC32 control field
// * ack package is just a single predefined byte which acks the
//   transmission (or not acks, if not equal to ack byte)
// * if data package is not acked, then it shall be resent in the next
//   frame
// * package payload contains packets
// * every packet consists of
//   * header (defines the destination address of the payload and its size)
//   * payload itself
//
// that is it.

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <linux/full_duplex_interface.h>
#include <linux/iccom.h>

#include <linux/platform_device.h>
#include <linux/of_device.h>

/* --------------------- BUILD CONFIGURATION ----------------------------*/

// package layout info, see @iccom_package description
// (all sizes in bytes)

// Defines the log verbosity level for ICCom
// 0: total silence
// 1: only error messages
// 2: + warnings
// 3: (DEFAULT) + key info messages (info level 0)
// 4: + optional info messages (info level 1)
// 5: + all info messages (debug information) (info level 2)
//    NOTE: automatically enables debug mode at 5 level of
//    	verbosity
//    NOTE: the xfers and packge dumps will be printed at the
//    	KERNEL_INFO level, so if your kernel is more silient
//    	than this, you will not see the xfer nor packages hex dumps
#define ICCOM_VERBOSITY 3

// The minimal time which must pass between repeated error is reported
// to avoid logs flooding.
// 0: no minimal interval
// >0: minimal time interval in mseconds
#define ICCOM_MIN_ERR_REPORT_INTERVAL_MSEC 10000
// The rate (number of msec) at which the error rate decays double.
// The error rate is relevant in interpretation of the errors,
// cause occasional errors usually don't have very high significance,
// while high error rate usually indicates a real fault.
// Surely: > 0
#define ICCOM_ERR_RATE_DECAY_RATE_MSEC_PER_HALF 2000
// Minimal decay rate, even if error events are sequential
#define ICCOM_ERR_RATE_DECAY_RATE_MIN 3

// All debug macro can be set via kernel config
#if ICCOM_VERBOSITY >= 5
#define ICCOM_DEBUG
#endif

#ifdef ICCOM_DEBUG
// -1 means "all"
#ifndef ICCOM_DEBUG_CHANNEL
#define ICCOM_DEBUG_CHANNEL -1
#endif
// -1 means "unlimited", 0 means "do not print"
#ifndef ICCOM_DEBUG_MESSAGES_PRINTOUT_MAX_COUNT
#define ICCOM_DEBUG_MESSAGES_PRINTOUT_MAX_COUNT 5
#endif
// -1 means "unlimited", 0 means "do not print"
#ifndef ICCOM_DEBUG_PACKAGES_PRINT_MAX_COUNT
#define ICCOM_DEBUG_PACKAGES_PRINT_MAX_COUNT 5
#endif
#endif /* ICCOM_DEBUG */

#define ICCOM_LOG_PREFIX "ICCom: "

// Selects the workqueue to use to run consumer delivery operations
// to not to block the underlying transport layer.
//
// Three options are available now:
// * "ICCOM_WQ_SYSTEM": see system_wq in workqueue.h.
// * "ICCOM_WQ_SYSTEM_HIGHPRI": see system_highpri_wq in
//   workqueue.h.
// * "ICCOM_WQ_PRIVATE": use privately constructed single threaded
//   workqueue.
//
// NOTE: the selection of the workqueue depends on the
//      generic considerations on ICCom functioning
//      within the overall system context. Say if ICCom serves
//      as a connection for an optional device, or device which
//      can easily wait for some sec (in the worst case) to react
//      then "ICCOM_WQ_SYSTEM" workqeue is a nice option to select.
//      On the other hand if no delays are allowed in handling ICCom
//      communication (say, to communicate to hardware watchdog)
//      then "ICCOM_WQ_SYSTEM_HIGHPRI" or "ICCOM_WQ_PRIVATE" is
//      surely more preferrable.
//
// Can be set via kernel config, see:
// 		BOSCH_ICCOM_WORKQUEUE_MODE configuration parameter
#ifndef ICCOM_WORKQUEUE_MODE
#define ICCOM_WORKQUEUE_MODE ICCOM_WQ_PRIVATE
#endif

#define ICCOM_WQ_SYSTEM 0
#define ICCOM_WQ_SYSTEM_HIGHPRI 1
#define ICCOM_WQ_PRIVATE 2

// Comparator
#define ICCOM_WORKQUEUE_MODE_MATCH(x)		\
	ICCOM_WORKQUEUE_MODE == ICCOM_WQ_##x

// the number alias to workqueue mode
#ifndef ICCOM_WORKQUEUE_MODE
#error ICCOM_WORKQUEUE_MODE must be defined to \
		one of [ICCOM_WQ_SYSTEM, ICCOM_WQ_SYSTEM_HIGHPRI, \
		ICCOM_WQ_PRIVATE].
#endif


// DEV STACK
// @@@@@@@@@@@@@
//
// Verification:
//      * Handle transport device transport error by restarting
//        the frame, otherwise the communication will halt every
//        time other side indicates an error.
//
// WIP:
//      * verbosity levels smooth adjustment
//
// BACKLOG:
//
//      * TODO in iccom_close
//
//      * allow socket callbacks definition hierarchy and mapping
//        PER CHANNEL END:
//
//                Ch#1clb      Ch#5clb
//                  |            |
//
//          |---Callb.1--map-||--Clb.2-map--|   |--Callb.1--map-|
//
//          |----------- global callback (for all channels) -------|
//
//          GLOBAL END
//
//      * set MAX number of bytes per channel in message storage and
//        drop with new incoming messages otherwise we might end up
//        in message storage uncontrollable expansion due to forgotten
//        /unprocessed messages.
//
//      * incremental CRC32 computation
//
//      * kmem_cache_free check if neede (review)
//
//      * THE MINIMAL PACKAGE FILLING UP RATIO INTRODUCTION (to avoid
//        almost empty packages to be sent to the other side)
//           + introduction of priority messages (which trigger the
//             package send even it is almost empty)
//
//      * fixing writing package payload length from
//          adding the byte-bit endianness transformation procedures
//              V __iccom_package_set_payload_size
//              V __iccom_package_payload_size
//              __iccom_package_set_src
//              __iccom_package_get_src
//
//      * fixing __iccom_packet_parse_into_struct
//          ver iccom_packet_get_channel
//
//      * ver __iccom_read_next_packet
//        for package 00 01 00 05 23 45 32 ff ff
//          ver __iccom_packet_parse_into_struct
//
//      * ADDING THREAD SAFETY TO THE ICCOM MESSAGE STORAGE
//          ver. __iccom_msg_storage_allocate_next_msg_id
//              CORRECTING __iccom_msg_storage_allocate_next_msg_id USAGE
//                  ver. iccom_msg_storage_push_message usage
//                      ver __iccom_construct_message_in_storage usage
//                          ver __iccom_read_next_packet usage
//
//      * ver __iccom_process_package_payload and usage
//
//      * Condenced printing
//
//      * Add "do {.....} while (0)" for all function-like macro
//
//      * make statistics robust
//
//      * verify the reason of crash if uncomment the following line
//        (around 2910 line):
//           __iccom_msg_storage_printout(&iccom->p->rx_messages);
//
//      * __iccom_enqueue_new_tx_data_package might better to return
//        pointer to the created package or error-pointer in case of
//        errors
//
//      * ALLOCATE WHOLE MESSAGE SIZE IMMEDIATELY WITH THE FIRST BLOCK
//        OF THE MESSAGE
//
//      * ADD INITIAL EMPTY PACKAGE ON INIT
//
//      * TO VERIFY: MESSAGES with finalized == false
//        || uncommitted_length will never be
//              delivered/amened/deleted to/by consumer
//
//      * CONST REF =)
//
//      * TECHNICALLY WE CAN LEAVE THE XFER DATA UNTOUCHED, and simply
//        generate the memory regions list for every message, like
//        following
//
//        |--------------XFER---------------|
//           |MSG1 part1  | MSG2  part 3|
//
//        MSG1: part 1 ptr + size; part 2 ptr + size, part 3 ptr + size;
//        MSG2: part 1 ptr + size; part 2 ptr + size, part 3 ptr + size;...
//
//
//      * TO THINK ABOUT BANDWIDTH QUOTES/LOAD BALANCING, to make consumers
//        to have bandwidth preallocated and thus guaranteed to avoid the
//        situations when single consumer consumes whole bandwidth of the
//        whole device.
//
//      * BANDWIDTH ALLOCATION CAN BE MADE BY PRIORITIZATION of incoming
//        packets (the more bytes is sent, the less priority gets)
//
//      * if callback thread is blocked for more than gitven threshold,
//        then it is reasonable to launch the second worker thread by
//        timeout to 1) avoid excessive threads creation 2) still be able
//        to avoid one single consumer callback to block the whole ICCom
//        callback path
//
//      * Add maximum message sending attempt (not totally sure if it is
//        needed)
//
// @@@@@@@@@@@@@

/* --------------------- GENERAL CONFIGURATION --------------------------*/

// TODO: consider
// This channel ID is used to xfer ICCom technical information
// to the other side ICCom.
#define ICCOM_TECHNICAL_CHANNEL_ID 0

// should be > 0
#define ICCOM_INITIAL_PACKAGE_ID 1

#if ICCOM_DATA_XFER_SIZE_BYTES > ICCOM_ACK_XFER_SIZE_BYTES
#define ICCOM_BUFFER_SIZE ICCOM_DATA_XFER_SIZE_BYTES
#else
#define ICCOM_BUFFER_SIZE ICCOM_ACK_XFER_SIZE_BYTES
#endif

#define ICCOM_TEST_SYSFS_CHANNEL_ROOT "channels"
#define ICCOM_TEST_SYSFS_CHANNEL_PERMISSIONS 0644

/* --------------------- DATA PACKAGE CONFIGURATION ---------------------*/

// unused payload space filled with this value
#define ICCOM_PACKAGE_EMPTY_PAYLOAD_VALUE 0xFF
#define ICCOM_PACKAGE_PAYLOAD_DATA_LENGTH_FIELD_SIZE_BYTES 2
#define ICCOM_PACKAGE_ID_FIELD_SIZE_BYTES 1
#define ICCOM_PACKAGE_CRC_FIELD_SIZE_BYTES 4

// packet layout info (all sizes in bytes), see
//      SALT documentation, 20 November 2018
//          , 1.4.4 Payload data organization
//      blocks: Table 11, Table 13.
#define ICCOM_PACKET_HEADER_PAYLOAD_SIZE_FIELD_SIZE_BYTES 2
#define ICCOM_PACKET_HEADER_LUN_FIELD_SIZE_BYTES 1
#define ICCOM_PACKET_HEADER_CID_COMPLETE_FIELD_SIZE_BYTES 1

#define ICCOM_PACKET_HEADER_SIZE_BYTES					\
	(ICCOM_PACKET_HEADER_PAYLOAD_SIZE_FIELD_SIZE_BYTES		\
	 + ICCOM_PACKET_HEADER_LUN_FIELD_SIZE_BYTES			\
	 + ICCOM_PACKET_HEADER_CID_COMPLETE_FIELD_SIZE_BYTES)

/* ---------------------- ACK PACKAGE CONFIGURATION ---------------------*/
#define ICCOM_PACKAGE_ACK_VALUE 0xD0
#define ICCOM_PACKAGE_NACK_VALUE 0xE1

/* ---------------------- ADDITIONAL VALUES -----------------------------*/

#define ICCOM_PACKET_INVALID_CHANNEL_ID -1
#define ICCOM_PACKET_MIN_CHANNEL_ID 0
#define ICCOM_PACKET_MAX_CHANNEL_ID 0x7FFF
#define ICCOM_PACKET_INVALID_MESSAGE_ID 0
#define ICCOM_PACKET_INITIAL_MESSAGE_ID 1

/* --------------------- UTILITIES SECTION ----------------------------- */

// to keep the compatibility with Kernel versions earlier than v5.5
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
    #define pr_warning pr_warn
#endif

#if ICCOM_VERBOSITY >= 1
#define iccom_err(fmt, ...)						\
	pr_err(ICCOM_LOG_PREFIX"%s: "fmt"\n", __func__, ##__VA_ARGS__)
#define iccom_err_raw(fmt, ...)						\
	pr_err(ICCOM_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#else
#define iccom_err(fmt, ...)
#define iccom_err_raw(fmt, ...)
#endif

#if ICCOM_VERBOSITY >= 2
#define iccom_warning(fmt, ...)						\
	pr_warning(ICCOM_LOG_PREFIX"%s: "fmt"\n", __func__		\
		   , ##__VA_ARGS__)
#define iccom_warning_raw(fmt, ...)					\
	pr_warning(ICCOM_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#else
#define iccom_warning(fmt, ...)
#define iccom_warning_raw(fmt, ...)
#endif

#if ICCOM_VERBOSITY >= 3
#define iccom_info_helper(fmt, ...)					\
	pr_info(ICCOM_LOG_PREFIX"%s: "fmt"\n", __func__, ##__VA_ARGS__)
#define iccom_info_raw_helper(fmt, ...)					\
	pr_info(ICCOM_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_info_helper_0(fmt, ...)					\
	iccom_info_helper(fmt, ##__VA_ARGS__)
#define iccom_info_raw_helper_0(fmt, ...)				\
	iccom_info_raw_helper(fmt, ##__VA_ARGS__)
#else
#define iccom_info_helper(fmt, ...)
#define iccom_info_raw_helper(fmt, ...)
#define iccom_info_helper_0(fmt, ...)
#define iccom_info_raw_helper_0(fmt, ...)
#endif

#if ICCOM_VERBOSITY >= 4
#define iccom_info_helper_1(fmt, ...)					\
	iccom_info_helper(fmt, ##__VA_ARGS__)
#define iccom_info_raw_helper_1(fmt, ...)				\
	iccom_info_raw_helper(fmt, ##__VA_ARGS__)
#else
#define iccom_info_helper_1(fmt, ...)
#define iccom_info_raw_helper_1(fmt, ...)
#endif

#if ICCOM_VERBOSITY >= 5
#define iccom_info_helper_2(fmt, ...)					\
	iccom_info_helper(fmt, ##__VA_ARGS__)
#define iccom_info_raw_helper_2(fmt, ...)				\
	iccom_info_raw_helper(fmt, ##__VA_ARGS__)
#else
#define iccom_info_helper_2(fmt, ...)
#define iccom_info_raw_helper_2(fmt, ...)
#endif

// information messages levels
#define ICCOM_LOG_INFO_KEY_LEVEL 0
#define ICCOM_LOG_INFO_OPT_LEVEL 1
#define ICCOM_LOG_INFO_DBG_LEVEL 2

#define iccom_info_helper__(level, fmt, ...)				\
	iccom_info_helper_##level(fmt, ##__VA_ARGS__)
#define iccom_info_raw_helper__(level, fmt, ...)			\
	iccom_info_raw_helper_##level(fmt, ##__VA_ARGS__)

#define iccom_info(level, fmt, ...)					\
	iccom_info_helper__(level, fmt, ##__VA_ARGS__)
#define iccom_info_raw(level, fmt, ...)					\
	iccom_info_raw_helper__(level, fmt, ##__VA_ARGS__)

#define ICCOM_TEST_TRANSPORT_CHECK_DEVICE(device, error_action)		\
	if (IS_ERR_OR_NULL(device)) {					\
		iccom_err("%s: no device;\n", __func__);		\
		error_action;						\
	}
#define ICCOM_TEST_TRANSPORT_CHECK_DEVICE_PRIVATE(msg, error_action)	\
	if (IS_ERR_OR_NULL(dev_get_drvdata(device))) {			\
		iccom_err("%s: no private part of device; "msg"\n"	\
			  , __func__);					\
		error_action;						\
	}
#define ICCOM_TEST_TRANSPORT_DEV_TO_XFER_DEV_DATA				\
	struct iccom_test_transport_dev * iccom_test_transport =		\
		(struct iccom_test_transport_dev *)dev_get_drvdata(device);	\
	struct xfer_device_data *xfer_dev_data =				\
		iccom_test_transport->p->xfer_dev_data;

#define ICCOM_TEST_TRANSPORT_XFER_DEV_ON_FINISH(error_action)		\
	if (xfer_dev_data->finishing) {					\
		error_action;						\
	}
#define ICCOM_CHECK_DEVICE(msg, error_action)				\
	if (IS_ERR_OR_NULL(iccom)) {					\
		iccom_err("%s: no device; "msg"\n", __func__);		\
		error_action;						\
	}
#define ICCOM_CHECK_DEVICE_PRIVATE(msg, error_action)			\
	if (IS_ERR_OR_NULL(iccom->p)) {					\
		iccom_err("%s: no private part of device; "msg"\n"	\
			  , __func__);					\
		error_action;						\
	}
#define ICCOM_CHECK_CLOSING(msg, closing_action)			\
	if (iccom->p->closing) {					\
		iccom_warning("%s: device is closing; "msg"\n"		\
			      , __func__);				\
		closing_action;						\
	}
#define ICCOM_CHECK_CHANNEL_EXT(channel, msg, error_action)		\
	if ((channel < ICCOM_PACKET_MIN_CHANNEL_ID			\
			|| channel > ICCOM_PACKET_MAX_CHANNEL_ID)	\
		    && channel != ICCOM_ANY_CHANNEL_VALUE) {		\
		iccom_err("%s: bad channel; "msg"\n", __func__);	\
		error_action;						\
	}
#define ICCOM_CHECK_CHANNEL(msg, error_action)				\
	ICCOM_CHECK_CHANNEL_EXT(channel, msg, error_action);

#define ICCOM_CHECK_PTR(ptr, error_action)				\
	if (IS_ERR_OR_NULL(ptr)) {					\
		iccom_err("%s: pointer "# ptr" is invalid;\n"		\
			  , __func__);					\
		error_action;						\
	}

#define ICCOM_MSG_STORAGE_CHECK_STORAGE(msg, error_action)		\
	if (IS_ERR_OR_NULL(storage)) {					\
		iccom_err("%s: bad msg storage ptr; "msg"\n", __func__);\
		error_action;						\
	}

#define __iccom_err_report(err_no, sub_error_no)			\
	__iccom_error_report(iccom, err_no, sub_error_no, __func__)

/* ------------------------ FORWARD DECLARATIONS ------------------------*/

struct full_duplex_xfer *__iccom_xfer_failed_callback(
		const struct full_duplex_xfer __kernel *failed_xfer
		, const int next_xfer_id
		, int error_code
		, void __kernel *consumer_data);
struct full_duplex_xfer *__iccom_xfer_done_callback(
			const struct full_duplex_xfer __kernel *done_xfer
			, const int next_xfer_id
			, bool __kernel *start_immediately__out
			, void *consumer_data);

/* --------------------------- MAIN STRUCTURES --------------------------*/

// This structure is needed for the iccom test transport to hold
// the its private data
//
// @xfer_device_data {ptr valid} iccom test transport device
struct iccom_test_transport_dev_private {
	struct xfer_device_data *xfer_dev_data;
};

// This structure is needed for the iccom test transport to hold
// the duplex iface and the xfer device so that it can communicate
// with iccom to exchange data. It describes the test transport private data
//
// @full_duplex_sym_iface {ptr valid} full duplex interface
// @p {ptr valid} iccom test transport private data
struct iccom_test_transport_dev
{
	struct full_duplex_sym_iface * duplex_iface;
	struct iccom_test_transport_dev_private *p;
};

// Describes the sysfs channels which shall hold
// all messages received from iccom to the upper
// layer for a specific sysfs channel. The user
// space can retrieve all the channel messages
// one by one
//
// @ch_id {number} ICCom logical channel ID
// @number_of_msgs {number} number of messages 
// that a particular channel has to be read from
// userspace
// @sysfs_ch_msgs_head channels messages list head
// @list list_head for pointing to next channel
struct iccom_test_sysfs_channel {
	unsigned int ch_id;
	unsigned int number_of_msgs;
	struct list_head sysfs_ch_msgs_head;
	struct list_head list;
};

// Describes the sysfs channels messages
// received from iccom to upper layer which
// will be read by user space later in time
//
// @data {ptr valid} contains the message received from iccom
// @size {number} number of characters in the message
// @list list_head for pointing to next previous message
struct iccom_test_sysfs_channel_msg {
	struct iccom_message *msg;
	struct list_head list;
};

// Describes the transport device data
//
// @xfer the xfer to execute data
// @got_us_data true if for the given @xfer User Space has provided the
//      wire data already (this guy is being reset every new xfer).
// @next_xfer_id contains the next xfer id 
//      to be transmitted
// @running contains the status whether transport
//      is running or not
// @finishing contains the status whether transport
//      is finishing its work
struct xfer_device_data {
	struct full_duplex_xfer xfer;
	bool got_us_data;
	int next_xfer_id;
	bool running;
	bool finishing;
};

// Device list entry definition used to represent the list of devices
// from a specific driver which will hold all devices for iccom or even
// for iccom_test_transport. This shall be used to unregister the devices
// before module is removed safely
//
// @dev device object from driver
// @list list head pointing to the next device entry
struct device_list{
        struct device *dev;
        struct list_head list;
};

// TODO: probably not needed
// (probably needed only for xfer)
//
// Describes the single consumer message.
//
// @list_anchor messages list anchor point
// @data the consumer raw byte data. Always owns the data.
// @length size of payload in @data in bytes (while message is
//      unfinished keeps the current data length)
//      NOTE: the @length may be less than allocated @data size
//          due to rollback of uncommitted changes.
// @channel the id of the channel the message is assigned to.
// @id the sequential message id (assigned by iccom to uniquely
//      identify the message among others within adequate time
//      frame). @id is wrapped around so it will be unique only
//      within some message relevance time frame, but not globally.
//
//      NOTE: in legacy ICCom implementation is not used.
//
//      NOTE(TODO): while the field is not used, we will use message
//          id always equal to 0
//
// @priority the message priority value which indicates the importance
//      of fast delivery of the message. The higher the value, the
//      faster the message needs to be delivered.
//      0 - background xfer (should be used for non-urgent bulk
//          xfers, which are not time relevant)
//      100 - highest priority (should be used only for really
//          critically urgent messages, which need to be delivered
//          asap)
//
//      NOTE: in legacy ICCom implementation is not used.
//
// @finalized true if the message is done and ready to be delivered
//      to the consumer. False if message is under construction.
// @uncommitted_length the size of uncommitted part of the message data
//      this value indicates how many bytes in in message data were
//      added with the last package. If package parsing fails at some
//      later point, then the whole package will be resent and
//      received again, thus as long we have no packets IDs in
//      protocol right now, we need to revert all applied changes
//      from failed package to maintain data integrity.
struct iccom_message {
	struct list_head list_anchor;

	char *data;
	size_t length;
	unsigned int channel;
	unsigned int id;
	unsigned int priority;
	bool finalized;

	size_t uncommitted_length;
};

// Describes the single data package. The data package is a data,
// which is sent/received within single data xfer of underlying
// communication layer. So package data is identical with xfer data.
//
// @list_anchor the binding to the list
// @data the raw xfer data to be sent
// @size the size of the xfer for underlying layer (in bytes):
//      total number of bytes in the package
// @owns_data if true, then the data pointed by xfer_data is owned
//      by the package and must be freed upon package destruction.
//
// NOTE: for now we will use the following package configuration:
//      SALT documentation, 20 November 2018, 1.4.2 Transmission
//      blocks: Table 8:
//          * 2 byte message length,
//          * 1 byte package sequential ID
//          * PAYLOAD (size depends on package size)
//          * 2 byte SRC
//      This is done for backward compatibility with the previous
//      implementation.
//
struct iccom_package {
	struct list_head list_anchor;

	uint8_t *data;
	size_t size;

	bool owns_data;
};

// Packet header descriptor.
// See SALT documentation, 20 November 2018, 1.4.4 Payload data
//     organization, blocks: Table 11, Table 13.
//
// NOTE: the @complete field is the most significant bit (MSB)
// 	of the cid-complete byte.
typedef struct {
	uint16_t payload: 16;
	uint8_t lun: 8;
	uint8_t cid: 7;
	uint8_t complete: 1;
} iccom_package_header;

// The structure describes the ICCom packet
// @payload pointer to the first payload byte
//      NOTE: NULL <=> invalid packet
//      NOTE: never owns the payload data.
// @payload_length the size of the packet payload (in bytes).
//      NOTE: 0 <=> invalid packet
// @channel the channel to which the packet is attached.
// @finalizing if true, then the packet contains the last
//      chunk of the corresponding message.
//
// See SALT documentation, 20 November 2018
//          , 1.4.4 Payload data organization
//      blocks: Table 11, Table 13.
struct iccom_packet {
	void *payload;
	size_t payload_length;
	unsigned int channel;
	bool finalizing;
};

// The channel record of iccom_message_storage
// Contains the link to the next channel and link to
// messages of current channel.
//
// @channel_anchor the anchor of channels list
// @channel the channel value
// @messages the head of the channel messages list
//      NOTE: the incoming messages are always added to the
//          end of the list (to its tail).
// @current_last_message_id the id of the latest message in
//      the channel (the value is not relevant if there is
//      no messages in the channel).
//      TODO: this field should be removed as message id is
//          added to the packet structure.
// @consumer_callback_data {ANY} data to provide to the consumer
//      in the @message_ready_callback
// @message_ready_callback {NULL || valid callback pointer}
//      points to the consumer callback, which is called every
//      time when message gets ready in the channel.
//
//      This callback is called from a separate thread, however
//      all callbacks are executed in the same thread, so long
//      callback processing will lead to blocking of other consumers.
//
//      TODO: avoid this cross-consumer blocking dependency
//
//      RETURNS:
//          true: then ownership of message data (@msg_data) is
//              transferred to the consumer;
//          false: then message data ownership remains in ICCom,
//              and is immediately discarded after callback invocation.
struct iccom_message_storage_channel
{
	struct list_head channel_anchor;
	unsigned int channel;

	struct list_head messages;

	unsigned int current_last_message_id;

	void *consumer_callback_data;
	iccom_msg_ready_callback_ptr_t message_ready_callback;
};

// Describes the messages storage. Intended to be used to
// store the received ICCom messages while they are under construction
// or were constructed but not yet fetched by consumer.
//
// The exact implementation of the struct is defined by speed and
// memory requirements and may vary, but the interface methods
// (iccom_message_storage_*) are intended to persist.
//
// @channels_list the list of channel records of the storage.
// @lock the mutex to protect the storage from data-races.
//      NOTE: we will try to lock mutex only for operations
//          directly on the storage, while leaving the message
//          data writing/copying unlocked.
//          (this implies that consumer guarantees that no concurrent
//          calls to the same channel will happen)
// @iccom the pointer for the iccom_dev to be used for sysfs sniffing
// purposed for storing iccom messages to the upper layer
//       to be used for sysfs callback message delivery
// @message_ready_global_callback {NULL || valid callback pointer}
//      points to the consumer global callback, which is called every
//      time when channel doesn't have a dedicated channel callback
//      defined. If it is NULL, then will not be invoked.
// @global_consumer_data {any} this value is passed to the
//      @message_ready_global_callback.
// @uncommitted_finalized_count the number of finalized messages since
//      last commit.
struct iccom_message_storage
{
	struct list_head channels_list;
	struct mutex lock;

	struct iccom_dev *iccom;

	iccom_msg_ready_callback_ptr_t message_ready_global_callback;
	void *global_consumer_data;

	int uncommitted_finalized_count;
};

// Iccom device statistics
//
// @packages_bad_data_received incremented every time we get
//      a package with a broken data (like wrong length, wrong
//      CRC32 sum, etc.).
// @packages_duplicated_received incremented every time we
//      get a duplicated package.
// @packages_parsing_failed incremented every time we fail
//      to parse the package data into correct packets.
//
// NOTE: statistics is not guaranteed to be percise or even
//      selfconsistent. This data is mainly for debugging,
//      general picture monitoring. Don't use these values
//      for non-statistical/monitoring purposes. This is due
//      to absence of correct sync in statistics operations
//      which otherwise will introduce too big overhead.
struct iccom_dev_statistics {
	unsigned long long transport_layer_xfers_done_count;
	unsigned long long raw_bytes_xfered_via_transport_layer;
	unsigned long long packages_xfered;
	unsigned long long packages_sent_ok;
	unsigned long long packages_received_ok;
	unsigned long long packages_bad_data_received;
	unsigned long long packages_duplicated_received;
	unsigned long long packages_parsing_failed;
	unsigned long long packets_received_ok;
	unsigned long long messages_received_ok;
	unsigned long packages_in_tx_queue;
	unsigned long long total_consumers_bytes_received_ok;
	unsigned long messages_ready_in_storage;

// TODO:
//	unsigned long long packets_sent;
//	unsigned long long messages_sent;
//	unsigned long long total_consumers_bytes_sent;
};

// Keeps the error history record
// @err_num keeps the error number which the record belongs to
// @total_count the total count of the error happened since last
//      ICCom start
// @in_curr_report_interval_count the number of errors of @err_num
//      type happened within current report interval.
// @last_report_time_msec the msec time when the error type was
//      last reported. If new error comes earlier than
//      @last_report_time_msec + ICCOM_MIN_ERR_REPORT_INTERVAL_MSEC
//      then it is only put into statistics but not reported (will be
//      reported as new error of this type occurred after silence time)
//      NOTE: or if error rate threshold is reached
// @last_occurrence_time_msec the time interval since last event of the
//      error in mseconds.
// @exp_avg_interval_msec the exponentially weightened average interval
// 	between error events in mseconds.
// @err_msg the error message to be sent to kernel message buffer
// @last_reported is set to true, when the last error was reported to
//      user.
// @err_per_sec_threshold sets the error rate starting from which the
// 	error is reported as error (not as warning or info). This
// 	will be used to identify the real issues like full stall of
// 	communication among occasional errors which always might happen
// 	on HW communication line.
struct iccom_error_rec {
	unsigned char err_num;
	unsigned int total_count;
	unsigned int unreported_count;
	unsigned long last_report_time_msec;
	unsigned long last_occurrence_time_msec;
	unsigned long exp_avg_interval_msec;
	const char *err_msg;
	bool last_reported;
	unsigned int err_per_sec_threshold;
};

// Describes the internal ICCom data
// @iccom pointer to corresponding iccom_dev structure.
// @tx_data_packages_head the list of data packages (struct iccom_package)
//      to send to the other side. Head.next points to earliest-came
//      from consumer message.
//
//      As long as messages have no IDs and message parts have no
//      sequential ID in legacy (rev.1.0) protocol
//      implementationm, then we are not able to shuffle
//      the messages parts for xfer for the same channel. If
//      message started to be xfered in given channel, it should
//      be xfered till no its data left, sequentially.
//
//      The list doesn't contain the ack packages, only data packages.
//
//      NOTE: there is always at least one package in the list
//          after any queue manipulation ends.
//
//      NOTE: all packages in queue are always finalized
//          between queue manipulations
//      NOTE: new package is added only when we need it (either
//          no packages to prepare for xfer, or previous
//          package in TX queue ran out of space but we still
//          have data to write to TX)
//
//      TX queue manipulation routines:
//          __iccom_queue_*
//
// @tx_queue_lock mutex to protect the TX packages queue from data
//      races.
// @ack_val const by usage. Keeps the ACK value, which is to be sent to
//      the other side when ACK.
// @nack_val const by usage. Keeps the NACK value, which is to be sent to
//      the other side when NACK.
// @xfer the currently going xfer, it only points to the data but never
//      owns it.
// @data_xfer_stage according to the protocol, data and ack packages are
//      interleave, so this field indicates if we are in the data xfer
//      cycle now or in ack xfer cycle. If the filed is true, then we
//      are now in data xfer stage, and thus
//          * if underlying layer is not busy, then we are free to start
//            data package xfer,
//          * if underlying layer is busy, then upon xfer finished we
//            need to send the ack package.
//      If the field is false (implies underlying layer is busy):
//          * then upon xfer finished we may start next data package xfer.
// @next_tx_message_id keeps the next outgoing message id. Wraps around.
// @last_rx_package_id the sequence ID of the last package we have
//      received from the other side. If we receive two packages
//      with the same sequence ID, than we will drop all but one of the
//      packages with the same sequence ID.
// @rx_messages the incoming messages storage. Stores completed incoming
//      messages as well as under construction incoming messages.
// @work_queue pointer to personal ICCom dedicated work-queue to handle
//      communication jobs. It is used mainly for stability consderations
//      cause publicitly available work-queue can potentially be blocked
//      by other running/pending tasks. So to stay on a safe side we
//      will allocate our own single-threaded workqueue for our purposes.
//      NOTE: used only when ICCOM_WORKQUEUE_MODE equals ICCOM_WQ_PRIVATE
// @consumer_delivery_work the kworker which is responsible for
//      notification and delivery to the consumer finished incoming
//      messages.
// @closing true only when iccom device is going to be shutdown.
// @statistics the integral operational information about ICCom device
//      instance.
// @errors tracks the errors by type, and allows the flooding error
//      reporting protection
// @proc_root the root iccom directory in the proc file system
//      this directory is now aiming to provide statistical
//      information on ICCom but later might be used to set some
//      ICCom parameters dynamically.
// @statistics_ops ICCom statistics device operations (to read out
//      ICCom statistics info to user space)
// @statistics_file the file in proc fs which provides the ICCom
//      statistics to user space.
// @channels_root it has the sysfs channel folder kobject holding all
//      sysfs channels associated with an iccom device
// @sysfs_test_ch_head the list which shall hold the user space channels
//      received data from iccom received from transport to send to upper layers
struct iccom_dev_private {
	struct iccom_dev *iccom;

	struct list_head tx_data_packages_head;
	struct mutex tx_queue_lock;

	unsigned char ack_val;
	unsigned char nack_val;

	// never owns the data pointed to
	struct full_duplex_xfer xfer;

	bool data_xfer_stage;

	int next_tx_package_id;
	int last_rx_package_id;

	struct iccom_message_storage rx_messages;

#if ICCOM_WORKQUEUE_MODE_MATCH(PRIVATE)
	struct workqueue_struct *work_queue;
#endif
	struct work_struct consumer_delivery_work;

	bool closing;

	struct iccom_dev_statistics statistics;

	struct iccom_error_rec errors[ICCOM_ERROR_TYPES_COUNT];

	struct kobject* channels_root;

	struct list_head sysfs_test_ch_head;

	struct mutex sysfs_test_ch_lock;
};

/* ------------------------ GLOBAL VARIABLES ----------------------------*/

// Serves to speed up the CRC32 calculation using the precomputed values.
uint32_t iccom_crc32_lookup_tbl[256];

static const char ICCOM_ERROR_S_NOMEM[] = "no memory available";
static const char ICCOM_ERROR_S_TRANSPORT[]
	= "Xfer failed on transport layer. Restarting frame.";

// Serves to allocate unique ids for an iccom platform device
struct ida iccom_dev_id;
// Serves to allocate unique ids for an iccom test transport platform device
struct ida iccom_test_transport_dev_id;

/* ------------------------ FORWARD DECLARATIONS ------------------------*/

#ifdef ICCOM_DEBUG
static int __iccom_msg_storage_printout_channel(
		struct iccom_message_storage_channel *channel_rec
		, int max_printout_count);
static int __iccom_msg_storage_printout(
		struct iccom_message_storage *storage
		, int max_printout_count
		, int channel);
#endif

/* ----------------------------- UTILS ----------------------------------*/

// Generates the CRC32 lookup table (on Little Endian data)
// (top bit is at pos 0).
//
// SEE ALSO:
//   https://en.wikipedia.org/wiki/Cyclic_redundancy_check
//   https://www.kernel.org/doc/Documentation/crc32.txt
//   https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
static void __iccom_crc32_gen_lookup_table(void)
{
	uint32_t crc;

	// CRC32 parameters
	const uint32_t POLYNOMIAL = 0xEDB88320;
	const uint32_t TOP_BIT = 0x00000001;
	const uint32_t DIVIDENT_SIZE_BITS = 8;

	for (uint32_t i = 0; i < ARRAY_SIZE(iccom_crc32_lookup_tbl); i++) {
		crc = i;
		for (int j = 0; j < DIVIDENT_SIZE_BITS; j++) {
			crc = (crc & TOP_BIT) ? ((crc >> 1) ^ POLYNOMIAL)
					      : (crc >> 1);
		}
		iccom_crc32_lookup_tbl[i] = crc;
	}
}

// Computes CRC32 (on Little Endian data) (top bit is at pos 0).
// @data {valid data ptr if size > 0, otherwise any}
// @size_bytes {size of data in bytes && >= 0}
//
// The target formula:
// crc = (crc >> 8) ^ little_endian_table[data[i] ^ (8 right bits of crc)]
//
// SEE ALSO: https://en.wikipedia.org/wiki/Cyclic_redundancy_check
//           https://www.kernel.org/doc/Documentation/crc32.txt
static inline uint32_t __iccom_compute_crc32(
		uint8_t *data, size_t size_bytes)
{
	const uint8_t BITMASK = 0xFF;
	const uint8_t BITMASK_SIZE = 8;

	uint32_t crc = 0xFFFFFFFF;
	uint8_t *end_ptr = data + size_bytes;

	// byte-wise computation, MSB first
	for (; data != end_ptr; ++data) {
		uint8_t lookup_idx = (uint8_t)((crc ^ (*data)) & BITMASK);
		crc = (crc >> BITMASK_SIZE) ^ iccom_crc32_lookup_tbl[lookup_idx];
	}

	return ~crc;
}

/* --------------------- RAW PACKAGE MANIPULATION -----------------------*/

// Helper. Gets the size of package overall payload space even it is
// already occupied with some payload.
// See @iccom_package description.
static inline size_t __iccom_package_payload_room_size(
		struct iccom_package *package)
{
	return package->size
		- ICCOM_PACKAGE_PAYLOAD_DATA_LENGTH_FIELD_SIZE_BYTES
		- ICCOM_PACKAGE_ID_FIELD_SIZE_BYTES
		- ICCOM_PACKAGE_CRC_FIELD_SIZE_BYTES;
}

// Helper. Sets the package payload length. See @iccom_package description.
static inline void __iccom_package_set_payload_size(
		struct iccom_package *package, size_t length)
{
	*((__be16*)package->data) = __cpu_to_be16((uint16_t)length);
}

// Helper. Gets the package payload length. See @iccom_package description.
static inline size_t __iccom_package_payload_size(
		struct iccom_package *package, bool *ok__out)
{
	size_t declared_size = (size_t)__be16_to_cpu(*((__be16*)package->data));
	size_t max_possible = __iccom_package_payload_room_size(package);
	if (declared_size <= max_possible) {
		if (!IS_ERR_OR_NULL(ok__out)) {
			*ok__out = true;
		}
		return declared_size;
	}
	if (!IS_ERR_OR_NULL(ok__out)) {
		*ok__out = false;
	}
	return 0;
}

// Helper. Gets if the package is empty.
static inline size_t __iccom_package_is_empty(
		struct iccom_package *package, bool *ok__out)
{
	return __iccom_package_payload_size(package, ok__out) == 0;
}

// Helper. Returns the pointer to the first byte of the payload.
static inline void *__iccom_package_payload_start_addr(
		struct iccom_package *package)
{
	return package->data
		+ ICCOM_PACKAGE_PAYLOAD_DATA_LENGTH_FIELD_SIZE_BYTES
		+ ICCOM_PACKAGE_ID_FIELD_SIZE_BYTES;
}

// Helper. Gets the size of package free space for payload (in bytes).
// See @iccom_package description.
static inline size_t __iccom_package_get_payload_free_space(
		struct iccom_package *package, bool *ok__out)
{
	return __iccom_package_payload_room_size(package)
	       - __iccom_package_payload_size(package, ok__out);
}

// Helper. Sets the package ID. See @iccom_package description.
static inline void __iccom_package_set_id(
		struct iccom_package *package, int id)
{
	*(package->data
		+ ICCOM_PACKAGE_PAYLOAD_DATA_LENGTH_FIELD_SIZE_BYTES)
			= (uint8_t)id;
}

// Helper. Gets the package ID. See @iccom_package description.
static inline int __iccom_package_get_id(
		struct iccom_package *package)
{
	return (int)(*(package->data
			+ ICCOM_PACKAGE_PAYLOAD_DATA_LENGTH_FIELD_SIZE_BYTES));
}

// Helper. Sets the package SRC. See @iccom_package description.
static inline void __iccom_package_set_src(
		struct iccom_package *package, unsigned int src)
{
	int src_offset = package->size - ICCOM_PACKAGE_CRC_FIELD_SIZE_BYTES;
	*((uint32_t *)(package->data + src_offset)) = (uint32_t)src;
}

// Helper. Gets the package SRC. See @iccom_package description.
static inline unsigned int __iccom_package_get_src(
		struct iccom_package *package)
{
	int src_offset = package->size - ICCOM_PACKAGE_CRC_FIELD_SIZE_BYTES;
	return *((uint32_t *)(package->data + src_offset));
}

// Helper. Returns the address of the beginning of the package payload
// free space.
//
// NOTE: if no free spage returns NULL
static inline void * __iccom_package_get_free_space_start_addr(
		struct iccom_package *package, bool *ok__out)
{
	size_t free_length = __iccom_package_get_payload_free_space(
						   package, ok__out);
	if (!free_length) {
		return NULL;
	}
	return (package->data + package->size
			    - ICCOM_PACKAGE_CRC_FIELD_SIZE_BYTES)
	       - free_length;
}

// Helper. Fills package unused payload area with symbol.
// See @iccom_package description.
//
// RETURNS:
//      number of filled bytes
static unsigned int __iccom_package_fill_unused_payload(
		struct iccom_package *package, uint8_t symbol)
{
	// See @iccom_package description.

	size_t free_length = __iccom_package_get_payload_free_space(
						      package, NULL);

	if (free_length == 0) {
		return free_length;
	}

	memset(__iccom_package_get_free_space_start_addr(package, NULL)
	       , symbol, free_length);

	return free_length;
}

// Helper. Verifies that all free payload bytes set to given symbol.
// @package the package with at least checked payload size not exceeding
//      the package size
//
// RETURNS:
//      true: if all is OK (all unused payload bytes are set to
//          given symbol)
//      false: else
bool __iccom_package_check_unused_payload(
		struct iccom_package *package, uint8_t symbol)
{
	// See @iccom_package description.
	bool ok = false;
	const size_t free_length = __iccom_package_get_payload_free_space(
							     package, &ok);
	if (!ok) {
		return false;
	}
	uint8_t *start = __iccom_package_get_free_space_start_addr(package
								   , &ok);
	if (!ok) {
		return false;
	}
	int32_t val32 = symbol | symbol << 8 | symbol << 16 | symbol << 24;
	for (int i = 0; i < free_length / 4; i++) {
		if (*((int32_t*)start) != val32) {
			return false;
		}
		start += 4;
	}
	for (int j = 0; j < free_length % 4; j++) {
		if (*(start) != symbol) {
			return false;
		}
		start++;
	}

	return true;
}

// Helper. Returns the pointer to an iccom_package structure
// given by its list anchor pointer.
static inline struct iccom_package *__iccom_get_package_from_list_anchor(
		struct list_head *anchor)
{
	const int offset = offsetof(struct iccom_package, list_anchor);
	return (struct iccom_package *)((char*)anchor - offset);
}

// Helper. Returns the pointer to first package in TX queue.
// NOTE: the first package still could be unfinished.
//
// LOCKING: storage should be locked before this call
//
// RETURNS:
//      pointer to the first package in TX queue if one;
//      NULL if no packages in TX queue;
static inline struct iccom_package *__iccom_get_first_tx_package(
		struct iccom_dev *iccom)
{
	if (list_empty(&iccom->p->tx_data_packages_head)) {
		return NULL;
	}
	return __iccom_get_package_from_list_anchor(
			iccom->p->tx_data_packages_head.next);
}

// Helper. No locking.
//
// RETURNS:
//      {valid ptr} : the pointer to last (latest came) package in
//          TX queue.
//      {NULL} : if TX queue is empty
static inline struct iccom_package *__iccom_get_last_tx_package(
		struct iccom_dev *iccom)
{
	if (list_empty(&iccom->p->tx_data_packages_head)) {
		return NULL;
	}
	return __iccom_get_package_from_list_anchor(
			iccom->p->tx_data_packages_head.prev);
}

/* --------------------- PACKAGE MANIPULATION ---------------------------*/

// Computes CRC32 on the package.
// @package {valid package ptr}
// RETURNS:
//      computed CRC32 value
static unsigned int __iccom_package_compute_src(
	struct iccom_package *package)
{
	return __iccom_compute_crc32(package->data
		, package->size - ICCOM_PACKAGE_CRC_FIELD_SIZE_BYTES);
}

// Helper. Inits data structures of the package to the initial
// empty unfinalized package state.
//
// After this operation one may add data to the package.
//
// @package the allocated package struct to initialize
// @package_size the size of the package in bytes
//
// RETURNS:
//      0 on success
//      < 0 - the negative error code
static int __iccom_package_init(struct iccom_package *package
		, size_t package_size_bytes)
{
	package->size = package_size_bytes;
	package->owns_data = true;
	package->data = (uint8_t*)kmalloc(package->size, GFP_KERNEL);
	if (!package->data) {
		iccom_err("no memory");
		package->size = 0;
		return -ENOMEM;
	}

	__iccom_package_set_payload_size(package, 0);

	INIT_LIST_HEAD(&package->list_anchor);
	return 0;
}

// Helper. Frees the package data, allocated for @package structure
// if package owns the data, and the package itself.
//
// @package pointer to iccom_package structure allocated on heap.
//
// LOCKING: storage should be locked before this call
static void __iccom_package_free(struct iccom_package *package)
{
	if (package->owns_data) {
		kfree(package->data);
	}
	package->data = NULL;
	list_del(&package->list_anchor);
	kfree(package);
}

// Helper. Finishes the creation of the package.
//      * fills up unused payload data with
//        ICCOM_PACKAGE_EMPTY_PAYLOAD_VALUE
//      * sets correct CRC sum.
// @package {valid ptr to package}
//
// After this operation package is correct.
// After this call the package is ready to be sent.
static void __iccom_package_finalize(struct iccom_package *package)
{
	__iccom_package_fill_unused_payload(package
			, ICCOM_PACKAGE_EMPTY_PAYLOAD_VALUE);
	__iccom_package_set_src(package, __iccom_package_compute_src(package));
}

// Helper. Clears the package to make it contain no payload.
// @package {valid ptr to package}
//
// After this operation package is correct and empty.
// After this call the package is ready to be sent.
static void __iccom_package_make_empty(struct iccom_package *package)
{
	__iccom_package_set_payload_size(package, 0);
	__iccom_package_finalize(package);
}

#ifdef ICCOM_DEBUG
static void iccom_dbg_printout_package(struct iccom_package *pkg)
{
	ICCOM_CHECK_PTR(pkg, return);

	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL
		       , "========= PACKAGE:");
	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL
		       , "ptr: %px\tdata ptr: %px\tdata size: %zu"
		       , pkg, pkg->data, pkg->size);
	print_hex_dump(KERN_INFO, ICCOM_LOG_PREFIX"PKG data: ", 0, 16
		       , 1, pkg->data, pkg->size, true);
	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL, "= Decoded info: =");
	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL
		       , "PL size: %zu\tPL free: %zu\tid: %d\tCRC: %u"
		       , __iccom_package_payload_size(pkg, NULL)
		       , __iccom_package_get_payload_free_space(pkg, NULL)
		       , __iccom_package_get_id(pkg)
		       , __iccom_package_get_src(pkg));
}

// @max_printout_count {>=-1}, maximum number of packaged to print total,
//      -1 means "unlimited", 0 means "do not print"
static void iccom_dbg_printout_tx_queue(struct iccom_dev *iccom
		, int max_printout_count)
{
	ICCOM_CHECK_DEVICE("", return);
	ICCOM_CHECK_DEVICE_PRIVATE("", return);

	if (!max_printout_count) {
		return;
	}

	int printed = 0;
	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
		   , "======= The TX packages queue: BEGIN");
	struct iccom_package *pkg;
	list_for_each_entry(pkg, &iccom->p->tx_data_packages_head
			    , list_anchor) {
		if (max_printout_count > 0 && printed >= max_printout_count) {
			iccom_warning_raw("PACKAGES QUEUE PRINTOUT CUTOFF");
			break;
		}
		iccom_dbg_printout_package(pkg);
		printed++;
	}
	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
		   , "======= The TX packages queue: END");
}

// TODO: extract to independent source
// TODO: fix print to contain log prefix
void iccom_dbg_printout_xfer(const struct full_duplex_xfer *const xfer)
{
	if (IS_ERR(xfer)) {
		printk("xfer ptr BROKEN: %px\n", xfer);
		return;
	} else if (!xfer) {
		printk("xfer ptr NULL\n");
		return;
	}
	printk("Xfer ptr: %px\n", xfer);
	printk("Xfer size: %zu\n", xfer->size_bytes);
	if (IS_ERR(xfer->data_tx)) {
		printk("Xfer TX data ptr: BROKEN: %px\n", xfer->data_tx);
	} else if (xfer->data_tx) {
		printk("Xfer TX data ptr: %px\n", xfer->data_tx);
		print_hex_dump(KERN_INFO, "TX data: ", 0, 16
			    , 1, xfer->data_tx, xfer->size_bytes, true);
	} else {
		printk("Xfer TX data ptr: NULL\n");
	}
	if (IS_ERR(xfer->data_rx_buf)) {
		printk("Xfer RX data ptr: BROKEN: %px\n", xfer->data_rx_buf);
	} else if (xfer->data_rx_buf) {
		printk("Xfer RX data ptr: %px\n", xfer->data_rx_buf);
		print_hex_dump(KERN_INFO, "RX data: ", 0, 16
			    , 1, xfer->data_rx_buf, xfer->size_bytes
			    , true);
	} else {
		printk("Xfer RX data ptr: NULL\n");
	}
}

const char state_finalized[] = "finalized";
const char state_under_construction[] = "under construction";
void iccom_dbg_printout_message(const struct iccom_message *const msg)
{
	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL, "-- message --");
	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL
		       , "ch: %u\tid: %u\tpriority: %u\tlen: %lu"
			 "\tuncommitted len: %lu\t state: %s"
		       , msg->channel
		       , msg->id, msg->priority, msg->length
		       , msg->uncommitted_length
		       , msg->finalized ? state_finalized
					: state_under_construction);
	if (IS_ERR(msg->data)) {
		iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL
			       , "data: broken: %px", msg->data);
	} else if (!msg->data) {
		iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL, "data: NULL");
	} else {
		print_hex_dump(KERN_INFO, "data: ", 0, 16
			       , 1, msg->data, msg->length, true);
	}
}

#else /* ICCOM_DEBUG */

// remove debug methods
#define iccom_dbg_printout_package(pkg)
#define iccom_dbg_printout_tx_queue(iccom, max_printout_count)
#define iccom_dbg_printout_xfer(xfer)
#define iccom_dbg_printout_message(msg)

#endif /* ICCOM_DEBUG */

/* --------------------- PACKETS MANIPULATION ---------------------------*/

// Returns packet size for given payload size (all in bytes).
//
// See SALT documentation, 20 November 2018
//          , 1.4.4 Payload data organization
//      blocks: Table 11, Table 13.
static inline size_t iccom_packet_packet_size_bytes(
		const size_t payload_size)
{
	return ICCOM_PACKET_HEADER_SIZE_BYTES + payload_size;
}

// Returns minimal packet size in bytes.
//
// See SALT documentation, 20 November 2018
//          , 1.4.4 Payload data organization
//      blocks: Table 11, Table 13.
static inline size_t iccom_packet_min_packet_size_bytes(void)
{
	return iccom_packet_packet_size_bytes(1);
}

// Returns the packet payload begin address
// @package_begin the address of the first packet byte
//
// See SALT documentation, 20 November 2018
//          , 1.4.4 Payload data organization
//      blocks: Table 11, Table 13.
static inline void *iccom_packet_payload_begin_addr(
		void *package_begin)
{
	return package_begin + ICCOM_PACKET_HEADER_SIZE_BYTES;
}

// Conversion to legacy format of LUN and CID
// @channel channel (if channel is bigger than
//      supported, the higher bits are truncated.
static inline uint8_t iccom_packet_channel_lun(
		const unsigned int channel)
{
	return (uint8_t)(((uint32_t)channel >> 7) & 0x000000FF);
}

// Conversion to legacy format of LUN and CID
// @channel channel
static inline uint8_t iccom_packet_channel_sid(
		const unsigned int channel)
{
	return (uint8_t)(((uint32_t)channel) & 0x0000007F);
}

// Conversion from legacy format of LUN and CID
// @lun the LUN value
// @cid the CID value, if bigger than allowed - truncated
static inline unsigned int iccom_packet_luncid_channel(
		const uint8_t lun, const uint8_t cid)
{
	return (unsigned int)((((uint32_t)lun) << 7)
			      | (((uint32_t)cid) & 0x0000007F));
}

// Helper. Writes the packet header into the destination given by @target.
//
// @payload_size_bytes valid payload value
// @channel valid channel value
// @message_complete if this packet finalizes the message
// @target should have at least ICCOM_PACKET_HEADER_SIZE_BYTES
//      bytes available.
//
// See SALT documentation, 20 November 2018
//          , 1.4.4 Payload data organization
//      blocks: Table 11, Table 13.
//
// RETURNS:
//      number of bytes written to target
inline static size_t iccom_packet_write_header(
		const size_t payload_size_bytes
		, const unsigned int channel
		, const bool message_complete
		, void * const target)
{
	((iccom_package_header*)target)->payload
			= __cpu_to_be16((uint16_t)payload_size_bytes);
	((iccom_package_header*)target)->lun
			= iccom_packet_channel_lun(channel);
	((iccom_package_header*)target)->cid
			= iccom_packet_channel_sid(channel);
	((iccom_package_header*)target)->complete
			= message_complete ? 1 : 0;

	return ICCOM_PACKET_HEADER_SIZE_BYTES;
}

// Fills up the packet structure from given raw byte package data.
//
// @start_from {valid kernel pointer} the pointer to the first byte
//      of the packet (including header)
// @max_bytes_available {>=0} the maximum possible size of the packet
//      (usually restricted by corresponsding package payload area).
// @packet__out {valid pointer} pointer to the iccom_packet structure
//      to write the parsed packet data in.
//
// See SALT documentation, 20 November 2018
//          , 1.4.4 Payload data organization
//      blocks: Table 11, Table 13.
//
// RETURNS:
//      0 on success
//      <0 - negated error valus if failed
static int __iccom_packet_parse_into_struct(
		void *start_from
		, const size_t max_bytes_available
		, struct iccom_packet *packet__out)
{
#ifdef ICCOM_DEBUG
	if (IS_ERR_OR_NULL(start_from)) {
		iccom_err("Broken start_from pointer");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(packet__out)) {
		iccom_err("Broken packet__out pointer");
		return -EINVAL;
	}
#endif
	iccom_package_header *src = (iccom_package_header*)start_from;

	if (max_bytes_available < iccom_packet_min_packet_size_bytes()) {
		goto invalidate_packet;
	}

	packet__out->payload_length = (size_t)(__be16_to_cpu(src->payload));
	if (iccom_packet_packet_size_bytes(packet__out->payload_length)
			> max_bytes_available) {
		goto invalidate_packet;
	}
	packet__out->channel = iccom_packet_luncid_channel(src->lun, src->cid);
	packet__out->finalizing = (bool)src->complete;
	packet__out->payload = iccom_packet_payload_begin_addr(start_from);

	return 0;

invalidate_packet:
	packet__out->payload = NULL;
	packet__out->payload_length = 0;
	return -EINVAL;
}

// Adds the maximum possible amount of bytes from message to the package.
// Wraps message data into the packet data structure and then adds
// the packet to the package payload area.
//
// NOTE: doesn't finalize the package, as long as more info might be
//      added to the package later.
//
// @package {valid ptr || NULL} the package to try to add the data to
//      if NULL then function does nothing and correspondingly returns
//      0.
// @packet_payload the consumer payload to put into the packet which then
//      will be added to the package. This data is wrapped into packet
//      and then the packet is added to the package payload room.
// @payload_size_bytes the lengthe of @packet_payload in bytes.
// @channel the channel to which the packet attached
//
// RETURNS:
//      the number of consumer payload bytes which were added to the
//      package.
//      0 means that no more pakets can be added to the package. So
//      the package is ready to be sent.
static size_t iccom_package_add_packet(struct iccom_package *package
		, char *packet_payload, const size_t payload_size_bytes
		, const unsigned int channel)
{
	if (IS_ERR_OR_NULL(package)) {
		return 0;
	}

	size_t package_free_space_bytes
		= __iccom_package_get_payload_free_space(package, NULL);

	if (package_free_space_bytes <= ICCOM_PACKET_HEADER_SIZE_BYTES) {
		return 0;
	}

	// size of payload to be written to the packet
	size_t payload_write_size_bytes = package_free_space_bytes
					       - ICCOM_PACKET_HEADER_SIZE_BYTES;
	if (payload_write_size_bytes > payload_size_bytes) {
		payload_write_size_bytes = payload_size_bytes;
	}

	size_t bytes_written_to_package = 0;
	uint8_t *start_ptr = __iccom_package_get_free_space_start_addr(package
								       , NULL);

	bytes_written_to_package += iccom_packet_write_header(
					    payload_write_size_bytes
					    , channel
					    , payload_write_size_bytes
						    == payload_size_bytes
					    , start_ptr);
	memcpy(start_ptr + bytes_written_to_package, packet_payload
	       , payload_write_size_bytes);

	bytes_written_to_package += payload_write_size_bytes;

	size_t new_length = __iccom_package_payload_size(package, NULL)
			    + bytes_written_to_package;
	__iccom_package_set_payload_size(package, new_length);

	return payload_write_size_bytes;
}

/* ------------------ MESSAGES MANIPULATION -----------------------------*/

// Helper. Initializes new message struct.
// @msg {valid msg struct ptr}
static inline void __iccom_message_init(struct iccom_message __kernel *msg)
{
	memset(msg, 0, sizeof(struct iccom_message));
	INIT_LIST_HEAD(&msg->list_anchor);
}

// Helper. Frees the data, allocated by message. The message struct
// itself is managed by the caller. If message is in the list,
// then it is removed from the list. Frees the message itself also.
//
// @msg message allocated on heap
//
// LOCKING: protection of the list the message may be in is the
//      responsibility of the caller.
static void __iccom_message_free(struct iccom_message *msg)
{
	if (IS_ERR_OR_NULL(msg)) {
		return;
	}
	list_del(&(msg->list_anchor));
	if (!IS_ERR_OR_NULL(msg->data)) {
		kfree(msg->data);
	}
	kfree(msg);
}

// Helper. Returns if the message is ready
static inline bool __iccom_message_is_ready(struct iccom_message *msg)
{
	return msg->finalized && msg->uncommitted_length == 0;
}

/* ---------------- MESSAGES STORE PRIVATE SECTION -----------------*/

// Helper. Returns channel from channel list anchor. No checks.
static inline struct iccom_message_storage_channel *
__iccom_msg_storage_anchor2channel(struct list_head *anchor)
{
	return container_of(anchor
			    , struct iccom_message_storage_channel
			    , channel_anchor);
}

// Helper. Returns next channel in the channels list or NULL
// if next is head.
static inline struct iccom_message_storage_channel *
__iccom_msg_storage_next_channel(
		struct iccom_message_storage_channel * const ch
		, struct list_head *const head)
{
	if (ch->channel_anchor.next == head) {
		return NULL;
	}
	return container_of(ch->channel_anchor.next
			    , struct iccom_message_storage_channel
			    , channel_anchor);
}

// Helper. Returns previous channel in the channels list. No checks.
static inline struct iccom_message_storage_channel *
__iccom_msg_storage_prev_channel(
		struct iccom_message_storage_channel * const ch
		, struct list_head *const head)
{
	if (ch->channel_anchor.prev == head) {
		return NULL;
	}
	return container_of(ch->channel_anchor.prev
			    , struct iccom_message_storage_channel
			    , channel_anchor);
}

// Helper. Tries to find a record which corresponds to a given channel.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to find
//
// LOCKING: storage should be locked before calling this function
//
// RETURNS:
//      !NULL pointer to storage channel record - if found
//      NULL - if not
struct iccom_message_storage_channel *__iccom_msg_storage_find_channel(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
	struct iccom_message_storage_channel *channel_rec;
	list_for_each_entry(channel_rec, &storage->channels_list
			    , channel_anchor) {
		if (channel_rec->channel == channel) {
			return channel_rec;
		}
	}
	return NULL;
}

// Helper. Tries to find a message in given channel record given
// by message id.
//
// @channel_rec {valid ptr || NULL}
//      valid: points to the channel to search the message in
//      NULL: then function simply returns NULL.
// @msg_id the target id of the message to search for
//
// LOCKING: storage should be locked before calling this function
//
// RETURNS:
//      !NULL pointer to message - if the message is found
//      NULL pointer - if message was not found or nowhere to search
struct iccom_message *__iccom_msg_storage_find_message_in_channel(
		struct iccom_message_storage_channel *channel_rec
		, unsigned int msg_id)
{
	if (!channel_rec) {
		return NULL;
	}

	struct iccom_message *msg;
	list_for_each_entry(msg, &channel_rec->messages
			    , list_anchor) {
		if (msg->id == msg_id) {
			return msg;
		}
	}

	return NULL;
}

// Helper. Adds a new channel to the storage. If channel exists, returns
// pointer to existing struct.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {valid channel number} the channel number to add/retrieve
//
// LOCKING: storage should be locked before calling this function
//
// RETURNS:
//      Pointer to existing or newly created channel:
//          if everything is OK.
//      NULL: if allocation of new channel failed.
static struct iccom_message_storage_channel *
__iccom_msg_storage_add_channel(struct iccom_message_storage *storage
				, unsigned int channel)
{
	struct iccom_message_storage_channel * channel_rec
		= __iccom_msg_storage_find_channel(storage, channel);
	if (channel_rec) {
		return channel_rec;
	}

	channel_rec = kmalloc(sizeof(struct iccom_message_storage_channel)
			      , GFP_KERNEL);
	if (!channel_rec) {
		iccom_warning("No memory to create new channel.");
		return NULL;
	}

	// initialization
	list_add_tail(&(channel_rec->channel_anchor)
		      , &(storage->channels_list));
	channel_rec->channel = channel;
	INIT_LIST_HEAD(&channel_rec->messages);
	channel_rec->current_last_message_id
			= ICCOM_PACKET_INVALID_MESSAGE_ID;
	channel_rec->consumer_callback_data = NULL;
	channel_rec->message_ready_callback = NULL;

	return channel_rec;
}

// RETURNS:
//      true: channel has no consumer/consumer dedicated data
//          (and thus can be freed without any data loss)
//      false: channel contains some consumer data and can not
//          be freed witout data loss
static inline bool iccom_msg_storage_channel_has_no_data(
	struct iccom_message_storage_channel *channel_rec)
{
	return list_empty(&(channel_rec->messages))
		    && !channel_rec->consumer_callback_data
		    && !channel_rec->message_ready_callback;
}

// Helper. Removes given channel from the storage and discards all
// its messages, other pointed data and channel structure itself.
//
// LOCKING: storage should be locked before calling this function
static void __iccom_msg_storage_free_channel(
	struct iccom_message_storage_channel *channel_rec)
{
	if (!channel_rec) {
		return;
	}

	while (!list_empty(&(channel_rec->messages))) {
		struct iccom_message *msg_rm
			= container_of(channel_rec->messages.next
				       , struct iccom_message
				       , list_anchor);
		__iccom_message_free(msg_rm);
	}

	list_del(&(channel_rec->channel_anchor));
	kfree(channel_rec);

	return;
}

// Deep copies an iccom message and validates
// whether the deep copy was sucessful
//
// @src {valid prt} iccom message to be copied
// @dest {valid prt} iccom message to copy to
//
// RETURNS:
//      0: ok
//     <0: errors
ssize_t iccom_test_sysfs_ch_msg_deep_copy(struct iccom_message *src, struct iccom_message *dst) {
	if (IS_ERR_OR_NULL(src) || IS_ERR_OR_NULL(dst)) {
		return -EINVAL;
	}

	dst->data = (char *) kzalloc(src->length, GFP_KERNEL);

	if (IS_ERR_OR_NULL(dst->data)) {
		return -ENOMEM;
	}

	memcpy(dst->data, src->data, src->length);
	dst->list_anchor = src->list_anchor;
	dst->length = src->length;
	dst->channel = src->channel;
	dst->id = src->id;
	dst->priority = src->priority;
	dst->finalized = src->finalized;
	dst->uncommitted_length = src->uncommitted_length;

	return 0;
}

// Free an sysfs iccom message complety
//
// @msg {valid prt} iccom message to be freed
void iccom_test_sysfs_ch_msg_free(struct iccom_message *msg) {
	if (IS_ERR_OR_NULL(msg)) {
		return;
	}

	if (!IS_ERR_OR_NULL(msg->data)) {
		kfree(msg->data);
	}
	kfree(msg);
}

// Routine to store an iccom message for
// a particular sysfs channel to later on
// be fetched by the userspace.
// The sysfs channels list shall be locked
// whenever there is a userspace access. 
// - When we store a new message in a sysfs
//   channel for later usage by the user space
// - When userspace reads a message from a sysfs
//   channel
// - When userspce creates/deletes a sysfs channel
//
// @iccom {valid prt} iccom_dev pointer
// @ch_id {number} ICCom logical channel ID
// @msg {valid prt} iccom message contaning
// the message received to the upper layer 
//
// RETURNS:
//      0: ok
//     <0: errors
ssize_t iccom_test_sysfs_ch_enqueue_msg(
		struct iccom_dev *iccom, unsigned int ch_id,
		struct iccom_message *msg)
{
	struct iccom_test_sysfs_channel *ch_entry, *tmp = NULL;
	struct iccom_test_sysfs_channel_msg * ch_msg_entry = NULL;
	ssize_t error_result;

	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(msg)) {
		iccom_err("Sysfs iccom message is null");
		return -EFAULT;
	}
	if (IS_ERR_OR_NULL(msg->data)) {
		iccom_err("Sysfs iccom message data is null");
		return -EFAULT;
	}
	if (msg->length == 0) {
		iccom_err("Sysfs iccom message data size is 0");
		return -EINVAL;
	}
	
	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_for_each_entry_safe(ch_entry, tmp,
				&iccom->p->sysfs_test_ch_head , list) {
		if (ch_entry->ch_id != ch_id) {
			continue;
		}
		if (ch_entry->number_of_msgs >= ICCOM_SYSFS_MAX_MSG_ALLOWED_PER_CHANNEL) {
			iccom_err("Discarding sysfs message for channel %d", ch_id);
			error_result = -ENOBUFS;
			goto finalize;
		}

		ch_msg_entry = (struct iccom_test_sysfs_channel_msg *)
				kzalloc(sizeof(struct iccom_test_sysfs_channel_msg), GFP_KERNEL);
		if (IS_ERR_OR_NULL(ch_msg_entry)) {
			error_result = -ENOMEM;
			goto finalize;
		}

		ch_msg_entry->msg = (struct iccom_message *)
					kmalloc(sizeof(struct iccom_message), GFP_KERNEL);
		if (IS_ERR_OR_NULL(ch_msg_entry->msg)) {
			error_result = -ENOMEM;
			goto iccom_msg_allocation_failed;
		}

		ch_entry->number_of_msgs++;
		error_result = iccom_test_sysfs_ch_msg_deep_copy(msg, ch_msg_entry->msg);
		if (error_result != 0) {
			goto iccom_msg_deep_copy_failed;
		}

		list_add(&ch_msg_entry->list, &ch_entry->sysfs_ch_msgs_head);
		mutex_unlock(&iccom->p->sysfs_test_ch_lock);
		return 0;
	}

	mutex_unlock(&iccom->p->sysfs_test_ch_lock);
	return -EINVAL;

iccom_msg_deep_copy_failed:
	iccom_test_sysfs_ch_msg_free(ch_msg_entry->msg);
	kfree(ch_msg_entry);
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);
	return error_result;
iccom_msg_allocation_failed:
	kfree(ch_msg_entry);
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);
	return error_result;
finalize:
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);
	return error_result;
}

// ICCom callback to signal that a new iccom message
// has been received for a particular sysfs channel
//
// @channel {number} number of the channel
// @msg_data {valid ptr} message data
// @msg_len {number} message length
// @consumer_data {valid ptr} consumer pointer holding where the information
// shall be sent to
static void iccom_test_sysfs_ch_callback(
		struct iccom_dev *iccom, unsigned int channel,
		struct iccom_message *msg)
{
	iccom_warning("Received from iccom for channel %d message '%s' size %zu"
		, channel, msg->data, msg->length);

	if(iccom_test_sysfs_ch_enqueue_msg(iccom, channel, msg) != 0) {
		iccom_err("Failed to store iccom message for channel %d",
			channel);
	}
}

// Checks whether sysfs channel is already
// created/present
//
// @iccom {valid prt} iccom_dev pointer
// @ch_id {number} ICCom logical channel ID
//
// RETURNS:
//      true: channel already exists
//      false: channel does not exists
bool iccom_test_sysfs_is_ch_present(
		struct iccom_dev *iccom, unsigned int ch_id)
{
	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return false;
	}

	struct iccom_test_sysfs_channel *ch_entry, *tmp;
	list_for_each_entry_safe(ch_entry, tmp,
			&iccom->p->sysfs_test_ch_head , list) {
		if (ch_entry->ch_id == ch_id) {
			return true;
		}
	}
	return false;
}

// Notifies the channel consumer about all ready messages
// in the channel (in FIFO sequence). Notified messages are
// discarded from the channel if consumer callback
// returns true.
//
// Should be executed in async mode to avoid blocking of underlying
// layer (full duplex transport) by upper layers (data consumer).
//
// If channel has no callback installed, then its messages are
// ignored and stay in the storage. TODO: if there are more than
// fixed number of messages in the channel pending to consumer layer
// then incoming messages are to be dropped and channel overflow
// signalized.
//
// @channel_rec {valid ptr} pointer to the channel to work with
//
// LOCKING:
// 	TODO: CLARIFY: storage should be locked before calling this
// 		function
//
// RETURNS:
//      >=0: number of messages processed: (notified and then discarded)
//      <0: negqated error code
static int __iccom_msg_storage_pass_channel_to_consumer(
		struct iccom_message_storage *storage
		, struct iccom_message_storage_channel *channel_rec)
{
	if (IS_ERR_OR_NULL(channel_rec)) {
		return -EINVAL;
	}

	iccom_msg_ready_callback_ptr_t msg_ready_callback = NULL;
	void *callback_consumer_data = NULL;

	mutex_lock(&storage->lock);

	bool iccom_test_sysfs_channel_present = iccom_test_sysfs_is_ch_present(
					storage->iccom, channel_rec->channel);

	if (!IS_ERR_OR_NULL(channel_rec->message_ready_callback)) {
		msg_ready_callback = channel_rec->message_ready_callback;
		callback_consumer_data = channel_rec->consumer_callback_data;
	} else if (!IS_ERR_OR_NULL(storage->message_ready_global_callback)) {
		msg_ready_callback = storage->message_ready_global_callback;
		callback_consumer_data = storage->global_consumer_data;
	} else if (iccom_test_sysfs_channel_present == false) {
		mutex_unlock(&storage->lock);
		return 0;
	}

	int count = 0;
	struct iccom_message *msg;

	// NOTE: the only guy to remove the message from the
	// 	storage is us, so if we unlock the mutex while our
	// 	consumer deals with the message, we only allow
	// 	to add new messages into the storage, while removing
	// 	them is our responsibility, so we shall not face with
	// 	the issue that we step onto message which will suddenly
	// 	be removed.
	list_for_each_entry(msg, &channel_rec->messages
			    , list_anchor) {
		if (!__iccom_message_is_ready(msg)) {
			continue;
		}
		mutex_unlock(&storage->lock);

		count++;
		bool ownership_to_consumer = false;

		if (iccom_test_sysfs_channel_present == true) {
			iccom_test_sysfs_ch_callback(
				storage->iccom, channel_rec->channel, msg);
		}

		if (!IS_ERR_OR_NULL(msg_ready_callback) && !IS_ERR_OR_NULL(callback_consumer_data)) {
			ownership_to_consumer = msg_ready_callback(
							channel_rec->channel
							, msg->data, msg->length
							, callback_consumer_data);
		}

		if (ownership_to_consumer) {
			msg->data = NULL;
			msg->length = 0;
		}

		mutex_lock(&storage->lock);
		// removing notified message from the storage
		struct iccom_message *prev;
		prev = container_of(msg->list_anchor.prev
				    , struct iccom_message, list_anchor);
		// @@@@@@@@@@@@@@@@@@@ TODO: verify locks
		__iccom_message_free(msg);
		msg = prev;
	}
	mutex_unlock(&storage->lock);

	return count;
}

// Helper. Allocates the next message id for the channel.
// Returns the value of the next message id for the channel
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to work with
//
// LOCKING: storage should be locked before calling this function
//
// RETURNS:
//      >=ICCOM_PACKET_INITIAL_MESSAGE_ID the value of the next
//          message id for the channel
//      if channel was not found also returns
//          ICCOM_PACKET_INITIAL_MESSAGE_ID
static unsigned int __iccom_msg_storage_allocate_next_msg_id(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return -ENODEV);
	ICCOM_CHECK_CHANNEL("", return -EBADSLT);
#endif

	struct iccom_message_storage_channel *channel_rec;
	channel_rec = __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		return ICCOM_PACKET_INITIAL_MESSAGE_ID;
	}
	unsigned int next_id;
	if (list_empty(&channel_rec->messages)) {
		next_id = ICCOM_PACKET_INITIAL_MESSAGE_ID;
		channel_rec->current_last_message_id = next_id;
		return next_id;
	}

	next_id = channel_rec->current_last_message_id + 1;
	if (next_id == 0) {
		next_id = ICCOM_PACKET_INITIAL_MESSAGE_ID;
	}
	channel_rec->current_last_message_id = next_id;

	return next_id;
}

// Tries to find a message given by its channel and message id
// in storage.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
// @msg_id {number} the id of the message to retrieve
//
// LOCKING: storage should be locked before this call
//
// RETURNS:
//      !NULL pointer to message - if the message is found
//      NULL pointer - if no message was found
static inline struct iccom_message *__iccom_msg_storage_get_message(
		struct iccom_message_storage *storage
		, unsigned int channel
		, unsigned int msg_id)
{
	struct iccom_message_storage_channel *channel_rec;
	channel_rec = __iccom_msg_storage_find_channel(storage, channel);
	return __iccom_msg_storage_find_message_in_channel(
					channel_rec, msg_id);
}

// Helper. Rolls back all uncommitted message data in channel.
//
// LOCKING: needs storage to be locked before the call, by caller
static void __iccom_msg_storage_channel_rollback(
	struct iccom_message_storage_channel *channel_rec)
{
	struct iccom_message *msg;

	list_for_each_entry(msg, &channel_rec->messages, list_anchor) {
		if (msg->uncommitted_length == 0) {
			continue;
		}
		// no reallocation needed, as long as every time new
		// data added or message freed the old area is freed
		// and its length is managed by slab allocator
		msg->finalized = false;
		msg->length -= msg->uncommitted_length;
		msg->uncommitted_length = 0;
	}
}

// Helper. Commits all uncommitted changes in the channel.
//
// LOCKING: needs storage to be locked before the call, by caller
static void __iccom_msg_storage_channel_commit(
	struct iccom_message_storage_channel *channel_rec)
{
	struct iccom_message *msg;

	list_for_each_entry(msg, &channel_rec->messages, list_anchor) {
		if (msg->uncommitted_length == 0) {
			continue;
		}
		msg->uncommitted_length = 0;
	}
}

#ifdef ICCOM_DEBUG
// @max_printout_count {>=-1}, maximum number of msgs to print total,
//      -1 means "unlimited", 0 means "do not print"
// LOCKING: needs storage to be locked before the call, by caller
static int __iccom_msg_storage_printout_channel(
		struct iccom_message_storage_channel *channel_rec
		, int max_printout_count)
{
	if (!max_printout_count) {
		return 0;
	}
	int printed = 0;
	struct iccom_message *msg;
	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL
		       , "== CH: %d ==", channel_rec->channel);
	list_for_each_entry(msg, &channel_rec->messages, list_anchor) {
		if (max_printout_count > 0 && printed >= max_printout_count) {
			iccom_warning_raw("CHANNEL PRINTOUT CUTOFF");
			break;
		}
		iccom_dbg_printout_message(msg);
		printed++;
	}
	return printed;
}

// @max_printout_count {>=-1}, maximum number of msgs to print total,
//      -1 means "unlimited", 0 means "do not print"
// @channel {>=-1} channel to print, -1 means all
//
// LOCKING: needs storage to be locked before the call, by caller
static int __iccom_msg_storage_printout(
		struct iccom_message_storage *storage
		, int max_printout_count
		, int channel)
{
	if (!max_printout_count) {
		return 0;
	}
	int printed = 0;
	struct iccom_message_storage_channel *channel_rec;
	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL
		       , "== Messages Storage ==");
	if (max_printout_count < 0) {
		list_for_each_entry(channel_rec, &storage->channels_list
				    , channel_anchor) {
			if (channel >= 0 && channel_rec->channel != channel) {
				continue;
			}
			printed += __iccom_msg_storage_printout_channel(
							 channel_rec, 0);
		}
		goto done;
	}

	list_for_each_entry(channel_rec, &storage->channels_list
			    , channel_anchor) {
		if (printed >= max_printout_count) {
			iccom_warning_raw("MESSAGES STORAGE PRINTOUT CUTOFF");
			break;
		}
		if (channel >= 0 && channel_rec->channel != channel) {
			continue;
		}
		printed += __iccom_msg_storage_printout_channel(
				channel_rec, max_printout_count - printed);
	}
done:
	iccom_info_raw(ICCOM_LOG_INFO_DBG_LEVEL
		       , "== Messages Storage END ==");
	return printed;
}
#endif
/* ------------------ MESSAGES STORE API --------------------------------*/

// Tries to find a message given by its channel and message id
// in storage.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
// @msg_id {number} the id of the message to retrieve
//
// CONCURRENCE: thread safe
// OWNERSHIP: the message ownership remains belong to storage
//
// RETURNS:
//      !NULL pointer to message - if the message is found
//      NULL pointer - if no message was found
__maybe_unused
struct iccom_message *iccom_msg_storage_get_message(
		struct iccom_message_storage *storage
		, unsigned int channel
		, unsigned int msg_id)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return NULL);
	ICCOM_CHECK_CHANNEL("", return NULL);
#endif
	mutex_lock(&storage->lock);
	struct iccom_message *res = __iccom_msg_storage_get_message(
					    storage, channel, msg_id);
	mutex_unlock(&storage->lock);
	return res;
}

// Returns the yongest message in the channel (if one),
// if there is no messages - returns NULL. The youngest
// message may, surely, be unfinished.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
//
// CONCURRENCE: thread safe
// OWNERSHIP: the message ownership remains belong to storage
//
// RETURNS:
//      !NULL pointer to message - if the message is found
//      NULL pointer - if no message was found (or even if
//          no relevant channel found)
__maybe_unused
struct iccom_message *iccom_msg_storage_get_last_message(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return NULL);
	ICCOM_CHECK_CHANNEL("", return NULL);
#endif
	struct iccom_message *msg = NULL;
	struct iccom_message_storage_channel *channel_rec;

	mutex_lock(&storage->lock);
	channel_rec = __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		goto finalize;
	}
	if (list_empty(&channel_rec->messages)) {
		goto finalize;
	}

	msg = container_of(channel_rec->messages.prev
			   , struct iccom_message, list_anchor);

finalize:
	mutex_unlock(&storage->lock);
	return msg;
}

// Returns the yongest message in the channel if it is not finalized;
// if there is no such message - returns NULL.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
//
// CONCURRENCE: thread safe
// OWNERSHIP: the message ownership remains belong to storage
//
// RETURNS:
//      !NULL pointer to message - if the message is found
//      NULL pointer - if no message was found (or even if
//          no relevant channel found)
__maybe_unused
struct iccom_message *iccom_msg_storage_get_last_unfinalized_message(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return NULL);
	ICCOM_CHECK_CHANNEL("", return NULL);
#endif
	struct iccom_message *msg = NULL;
	struct iccom_message_storage_channel *channel_rec;

	mutex_lock(&storage->lock);
	channel_rec = __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		goto finalize;
	}
	if (list_empty(&channel_rec->messages)) {
		goto finalize;
	}

	msg = container_of(channel_rec->messages.prev
			   , struct iccom_message, list_anchor);
	if (msg->finalized) {
		msg = NULL;
	}

finalize:
	mutex_unlock(&storage->lock);
	return msg;
}


// Returns the oldest message in the channel (if one),
// if there is no messages - returns NULL. The oldest
// message may still be unfinished.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
//
// CONCURRENCE: thread safe
// OWNERSHIP: the message ownership remains belong to storage
//
// NOTE: the ownership of the messages is still belongs to
//      the storage.
//
// RETURNS:
//      !NULL pointer to message - if the message is found
//      NULL pointer - if no message was found (or even if
//          no relevant channel found)
__maybe_unused
struct iccom_message *iccom_msg_storage_get_first_message(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return NULL);
	ICCOM_CHECK_CHANNEL("", return NULL);
#endif
	struct iccom_message *msg = NULL;
	struct iccom_message_storage_channel *channel_rec;

	mutex_lock(&storage->lock);
	channel_rec = __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		goto finalize;
	}
	if (list_empty(&channel_rec->messages)) {
		goto finalize;
	}

	msg = container_of(channel_rec->messages.next
			   , struct iccom_message, list_anchor);
finalize:
	mutex_unlock(&storage->lock);
	return msg;
}

// Returns the oldest finalized message in the channel (if one),
// if there is no such messages or channel - returns NULL.
// The finalized messages with uncommitted data are ignored.
// Message remains in the storage.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
//
// CONCURRENCE: thread safe
// OWNERSHIP: the message ownership remains belong to storage
//
// RETURNS:
//      !NULL pointer to message - if the message is found
//      NULL pointer - if no message was found (or even if
//          no relevant channel found, or channel number
//          is invalid)
__maybe_unused
struct iccom_message *iccom_msg_storage_get_first_ready_message(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return NULL);
	ICCOM_CHECK_CHANNEL("", return NULL);
#endif
	struct iccom_message *msg = NULL;
	struct iccom_message_storage_channel *channel_rec;

	mutex_lock(&storage->lock);
	channel_rec = __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		goto finalize;
	}
	if (list_empty(&channel_rec->messages)) {
		goto finalize;
	}

	list_for_each_entry(msg, &channel_rec->messages
			    , list_anchor) {
		if (__iccom_message_is_ready(msg)) {
			goto finalize;
		}
	}
	msg = NULL;
finalize:
	mutex_unlock(&storage->lock);
	return msg;
}

// Pops the oldest finalized message in the channel (if one),
// if there is no such messages or channel - returns NULL.
// The finalized messages with uncommitted data are ignored.
// Message is removed from the storage
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
//
// CONCURRENCE: thread safe
// OWNERSHIP: the message ownership is transferred to the caller
//
// RETURNS:
//      !NULL pointer to message - if the message is found
//      NULL pointer - if no message was found (or even if
//          no relevant channel found, or channel number
//          is invalid)
__maybe_unused
struct iccom_message *iccom_msg_storage_pop_first_ready_message(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return NULL);
	ICCOM_CHECK_CHANNEL("", return NULL);
#endif
	struct iccom_message *msg = NULL;
	struct iccom_message_storage_channel *channel_rec;

	mutex_lock(&storage->lock);
	channel_rec = __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		goto finalize;
	}
	if (list_empty(&channel_rec->messages)) {
		goto finalize;
	}

	list_for_each_entry(msg, &channel_rec->messages
			    , list_anchor) {
		if (__iccom_message_is_ready(msg)) {
			list_del(&(msg->list_anchor));
			goto finalize;
		}
	}
	msg = NULL;
finalize:
	mutex_unlock(&storage->lock);
	return msg;
}

// Removes the message from the storage and returns pointer to
// the popped message. Messages ownership is transferred to the
// caller.
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
//
// CONCURRENCE: thread safe
// OWNERSHIP: the message ownership is transferred to the storage
//
// RETURNS:
//      !NULL pointer to the popped message, if found
//      NULL, if no message was found or call parameters
//          are invalid
__maybe_unused
struct iccom_message *iccom_msg_storage_pop_message(
		struct iccom_message_storage *storage
		, unsigned int channel
		, unsigned int msg_id)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return NULL);
	ICCOM_CHECK_CHANNEL("", return NULL);
#endif
	struct iccom_message *msg = NULL;

	mutex_lock(&storage->lock);

	struct iccom_message_storage_channel * channel_rec
		= __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		goto finalize;
	}

	msg = __iccom_msg_storage_find_message_in_channel(
					channel_rec, msg_id);
	if (!msg) {
		goto finalize;
	}

	list_del(&(msg->list_anchor));

	// NOTE: we will save the channel record to avoid excessive
	//      memory de-re-allocations, as long as channel with
	//      high probability will persist and be reused.
	//
	// TODO: add last use timestamp to the channel record to
	//      remove it after long enough idle period.

finalize:
	mutex_unlock(&storage->lock);
	return msg;
}

// Adds new message to the message storage. The message ownership
// is transferred to the storage. While not provided externally
// by protocol, automatically assignes message ID.
//
// @storage {valid ptr} the pointer to the storage to use
// @msg {valid ptr to heap region} message to add to the storage,
//      required to have valid channel id set.
//      Message struct MUST be dynamically allocated.
//
// CONCURRENCE: thread safe
// OWNERSHIP: the message ownership is transferred to the storage
//
// RETURNS: 0 - if successfully added message to the storage
//          <0 - negated error code, if failed
//              -ENOMEM: no memory to allocate new channel
//              -EALREADY: message already exists
//
__maybe_unused
int iccom_msg_storage_push_message(
		struct iccom_message_storage __kernel *storage
		, struct iccom_message __kernel *msg)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return -ENODEV);
	ICCOM_CHECK_PTR(msg, return -EINVAL);
	ICCOM_CHECK_CHANNEL_EXT(msg->channel, "", return -EBADSLT);
#endif
	mutex_lock(&storage->lock);

	int res = 0;
	struct iccom_message_storage_channel * channel_rec
			= __iccom_msg_storage_add_channel(storage
							  , msg->channel);
	if (!channel_rec) {
		iccom_err("%s: no memory for channel", __func__);
		res = -ENOMEM;
		goto finalize;
	}

	if (__iccom_msg_storage_find_message_in_channel(
			channel_rec, msg->id)) {
		iccom_err("Could not put a message with id %x"
			  " to %x channel: message already exists"
			  , msg->id, msg->channel);
		res = -EALREADY;
		goto finalize;
	}

	list_add_tail(&(msg->list_anchor), &(channel_rec->messages));

	// TODO: as protocol contains the message id, then it should
	//      be set externally (not by storage)
	//
	// while message id is not used in protocol we just generate
	// new message ids by our-selves
	// TODO: no need to search for the channel for the second time
	msg->id = __iccom_msg_storage_allocate_next_msg_id(
			storage, msg->channel);

finalize:
	mutex_unlock(&storage->lock);
	return res;
}

// Removes the message from its storage.
//
// NOTE: TODO: thread safe
__maybe_unused
void iccom_msg_storage_remove_message(struct iccom_message *msg)
{
	list_del(&(msg->list_anchor));
}


// Removes all unused channel records from the storage.
//
// NOTE: TODO: thread safe
//
// NOTE: Later it may perform additional cleanup inside the
// channel.
__maybe_unused
void iccom_msg_storage_collect_garbage(
		struct iccom_message_storage *storage)
{
	if (list_empty(&storage->channels_list)) {
		return;
	}

	struct iccom_message_storage_channel *channel_rec
		= __iccom_msg_storage_anchor2channel(
			storage->channels_list.next);

	while (true) {
		struct list_head *next = channel_rec->channel_anchor.next;
		if (iccom_msg_storage_channel_has_no_data(channel_rec)) {
			list_del(&channel_rec->channel_anchor);
			kfree(channel_rec);
		}
		if (next == &storage->channels_list) {
			break;
		}
		channel_rec = __iccom_msg_storage_anchor2channel(next);
	}
}

// Removes the channel from the storage (with all attached
// messages).
//
// CONCURRENCE: thread safe
//
// @storage {valid ptr} the pointer to the messages storage
// @channel {number} the channel number to search the message in
__maybe_unused
void iccom_msg_storage_remove_channel(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return);
	ICCOM_CHECK_CHANNEL_EXT(channel, "", return);
#endif
	mutex_lock(&storage->lock);
	struct iccom_message_storage_channel *channel_rec
		= __iccom_msg_storage_find_channel(storage, channel);
	__iccom_msg_storage_free_channel(channel_rec);
	mutex_unlock(&storage->lock);
}

// Cleans whole storage (all channels and contained messages are
// removed and freed). Including all callback related information.
//
// NOTE: thread safe
__maybe_unused
void iccom_msg_storage_clear(struct iccom_message_storage *storage)
{
	mutex_lock(&storage->lock);
	while (!list_empty(&storage->channels_list)) {
		struct list_head *first = storage->channels_list.next;
		__iccom_msg_storage_free_channel(
			__iccom_msg_storage_anchor2channel(first));
	}
	storage->uncommitted_finalized_count = 0;
	mutex_unlock(&storage->lock);
	storage->message_ready_global_callback = NULL;
	storage->global_consumer_data = NULL;
}

// Cleans and frees whole storage (the struct itself it not freed).
// NOTE: should be called only on closing of the ICCom driver,
//      when all calls which might affect storage are blocked.
__maybe_unused
void iccom_msg_storage_free(struct iccom_message_storage *storage)
{
	storage->iccom = NULL;
	iccom_msg_storage_clear(storage);
	mutex_destroy(&storage->lock);
}

// Appends the data to the registered message, and updates
// the finalizes flag and uncommitted_length fields of
// iccom_message.
//
// @storage {valid storage pointer} storage to work with
// @channel {number} channel number to work with
// @msg_id {number} message id to attach the new data to
// @new_data {valid new data pointer} pointer to data to append
// @new_data_length {correct new data length} in bytes
// @final indicates if the message should be finalized (works
//      only once for the message)
//
// CONCURRENCE: thread safe, but consumer must ensure that
//      no update work with non-finalized messages
//      will be performed while data appending (this is for now a case)
//      (or at least on the message under update)
//
// RETURNS:
//      0: on success
//      <0: Negated error code if fails
__maybe_unused
int iccom_msg_storage_append_data_to_message(
	    struct iccom_message_storage *storage
	    , unsigned int channel, unsigned int msg_id
	    , void *new_data, size_t new_data_length
	    , bool final)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return -ENODEV);
	ICCOM_CHECK_CHANNEL("", return -EBADSLT);
	if (IS_ERR_OR_NULL(new_data)) {
		iccom_err("%s: new message data pointer broken", __func__);
		return -EINVAL;
	}
	if (new_data_length == 0) {
		iccom_err("%s: new message data length is 0", __func__);
		return -EINVAL;
	}
#endif
	mutex_lock(&storage->lock);
	struct iccom_message *msg = __iccom_msg_storage_get_message(
					    storage, channel, msg_id);
	if (IS_ERR_OR_NULL(msg)) {
		iccom_err("No such message to extend: channel %x"
			  ", id %x", channel, msg_id);
		mutex_unlock(&storage->lock);
		return -EBADF;
	}

	if (msg->finalized) {
		iccom_err("Can not add data to finalized message"
			  "(channel %x, msg id %x)", channel, msg_id);
		mutex_unlock(&storage->lock);
		return -EACCES;
	}

	mutex_unlock(&storage->lock);

	// We unlock here cause we have a contract with storage consumer:
	// to not to modify/delete unfinalized messages. Our aim is to
	// keep all heavy operations (like memcpy) out of lock.

	// TODO: avoid reallocation (allocate maximum available message
	// size only once).
	void *new_store = kmalloc(msg->length + new_data_length, GFP_KERNEL);
	if (!new_store) {
		iccom_err("Could not allocate memory for new message data.");
		return -ENOMEM;
	}

	if (!IS_ERR_OR_NULL(msg->data) && msg->length > 0) {
		memcpy(new_store, msg->data, msg->length);
	}
	memcpy(new_store + msg->length, new_data, new_data_length);

	// caution: the order of lines matters here: we update the pointer
	// first to keep the data selfconsistent, cause new data block
	// contains the old one, thus the data still will be selfconsistent
	char *old_data = msg->data;
	msg->data = new_store;
	mutex_lock(&storage->lock);
	msg->length += new_data_length;
	msg->uncommitted_length = new_data_length;
	mutex_unlock(&storage->lock);
	kfree(old_data);

	if (final) {
		msg->finalized = true;
		__sync_add_and_fetch(&storage->uncommitted_finalized_count, 1);
	}

	return 0;
}

// Sets the channel callback. If previous exists it is overwritten.
//
// @channel {valid channel value | ICCOM_ANY_CHANNEL_VALUE}
//      the channel to install the callback; if equals to
//      ICCOM_ANY_CHANNEL_VALUE then callback is installed
//      as global callback for the whole storage.
//
// CONCURRENCE: thread safe
//
// RETURNS:
//      0: on success
//      <0: negated error code
__maybe_unused
static int iccom_msg_storage_set_channel_callback(
		struct iccom_message_storage *storage
		, unsigned int channel
		, iccom_msg_ready_callback_ptr_t message_ready_callback
		, void *consumer_data)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return -ENODEV);
	ICCOM_CHECK_CHANNEL("", return -EBADSLT);
	if (IS_ERR(message_ready_callback)) {
		iccom_err("broken message ready callback ptr");
		return -EINVAL;
	}
#endif
	if (channel == ICCOM_ANY_CHANNEL_VALUE) {
		mutex_lock(&storage->lock);
		storage->message_ready_global_callback
				= message_ready_callback;
		storage->global_consumer_data
				= consumer_data;
		mutex_unlock(&storage->lock);
		return 0;
	}

	mutex_lock(&storage->lock);

	int res = 0;
	struct iccom_message_storage_channel *channel_rec
		= __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		if (IS_ERR_OR_NULL(message_ready_callback)) {
			goto finalize;
		}
		channel_rec = __iccom_msg_storage_add_channel(storage
							      , channel);
		if (!channel_rec) {
			iccom_err("%s: no memory for channel", __func__);
			res = -ENOMEM;
			goto finalize;
		}
	}
	channel_rec->consumer_callback_data = consumer_data;
	channel_rec->message_ready_callback = message_ready_callback;

finalize:
	mutex_unlock(&storage->lock);
	return res;
}

// Resets the channel callback.
// RETURNS:
//      0: on success
//      <0: negated error code
__maybe_unused
static inline int iccom_msg_storage_reset_channel_callback(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
	return iccom_msg_storage_set_channel_callback(storage
			, channel, NULL, NULL);
}

// Gets the channel callback.
//
// CONCURRENCE: thread safe
//
// RETURNS:
//      ERR PTR: on failure
//      NULL: if channel doesn't exist || callback is not set
//      callback pointer: if channel exists and callback is set
__maybe_unused
static  iccom_msg_ready_callback_ptr_t
iccom_msg_storage_get_channel_callback(
		struct iccom_message_storage *storage
		, unsigned int channel)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return ERR_PTR(-ENODEV));
	ICCOM_CHECK_CHANNEL("", return ERR_PTR(-EBADSLT));
#endif

	if (channel == ICCOM_ANY_CHANNEL_VALUE) {
		return storage->message_ready_global_callback;
	}

	mutex_lock(&storage->lock);

	iccom_msg_ready_callback_ptr_t res = NULL;
	struct iccom_message_storage_channel *channel_rec
		= __iccom_msg_storage_find_channel(storage, channel);
	if (!channel_rec) {
		goto finalize;
	}
	res = channel_rec->message_ready_callback;
finalize:
	mutex_unlock(&storage->lock);
	return res;
}

// Invokes callbacks of all channels with finished messages.
// If callback returns true, then message is discarded from
// the storage.
//
// RETURNS:
//      >=0: how many messages were notified and discarded
//      <0: negated error code
__maybe_unused
static inline int iccom_msg_storage_pass_ready_data_to_consumer(
		struct iccom_message_storage *storage)
{
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return -ENODEV);

	struct iccom_message_storage_channel *channel_rec;
	int count = 0;
	list_for_each_entry(channel_rec, &storage->channels_list
			    , channel_anchor) {
		int res = __iccom_msg_storage_pass_channel_to_consumer(
						  storage, channel_rec);
		if (res < 0) {
			iccom_err("consumer notification failed err: %d", res);
			return res;
		}
		count += res;
	}

	return count;
}

// Rolls back the uncommitted changes in the storage.
// Needs to cleanup the storage from data which was taken from
// broken package to avoid the data duplication when other
// side sends us the same package for the second time.
//
// CONCURRENCE: thread safe
//
// NOTE: as long as broken package is pretty rare situation,
//      the function is not intended to be very time efficient
//      it just scans whole storage and rolls back all uncommitted
//      data
__maybe_unused
static void iccom_msg_storage_rollback(
	    struct iccom_message_storage *storage)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return);
#endif
	struct iccom_message_storage_channel *channel_rec;
	mutex_lock(&storage->lock);
	list_for_each_entry(channel_rec, &storage->channels_list
			    , channel_anchor) {
		__iccom_msg_storage_channel_rollback(channel_rec);
	}
	mutex_unlock(&storage->lock);
}

// Commits all uncommitted changes in the storage.
//
// CONCURRENCE: thread safe
__maybe_unused
static void iccom_msg_storage_commit(
	    struct iccom_message_storage *storage)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return);
#endif
	struct iccom_message_storage_channel *channel_rec;
	mutex_lock(&storage->lock);
	list_for_each_entry(channel_rec, &storage->channels_list
			    , channel_anchor) {
		__iccom_msg_storage_channel_commit(channel_rec);
	}
	storage->uncommitted_finalized_count = 0;
	mutex_unlock(&storage->lock);
}

// Initializes the message storage
// RETURNS:
//      0: all fine
//      <0: negative error code
__maybe_unused
static int iccom_msg_storage_init(
	    struct iccom_message_storage *storage)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return -EINVAL);
#endif
	INIT_LIST_HEAD(&storage->channels_list);
	mutex_init(&storage->lock);
	storage->uncommitted_finalized_count = 0;
	storage->message_ready_global_callback = NULL;
	storage->global_consumer_data = NULL;
	storage->iccom = container_of(storage
				, struct iccom_dev_private, rx_messages)->iccom;
	return 0;
}

// CONCURRENCE: thread safe
// RETURNS:
//      >=0: number of finalized since last commit messages
//      <0: negated error code
__maybe_unused
static inline int iccom_msg_storage_uncommitted_finalized_count(
	    struct iccom_message_storage *storage)
{
#ifdef ICCOM_DEBUG
	ICCOM_MSG_STORAGE_CHECK_STORAGE("", return -ENODEV);
#endif
	return storage->uncommitted_finalized_count;
}

/* -------------------------- UTILITIES ---------------------------------*/

// Helper.
// Initializes the report error array.
static void __iccom_error_report_init(struct iccom_dev *iccom)
{
	memset(iccom->p->errors, 0, sizeof(iccom->p->errors));

#define ICCOM_ERR_REC(idx, ERR_NAME, threshold_err_per_sec)		\
	iccom->p->errors[idx].err_num = ICCOM_ERROR_##ERR_NAME;		\
	iccom->p->errors[idx].err_msg					\
		= (const char*)&ICCOM_ERROR_S_##ERR_NAME;		\
	iccom->p->errors[idx].err_per_sec_threshold			\
		= threshold_err_per_sec;

	ICCOM_ERR_REC(0, NOMEM, 0);
	ICCOM_ERR_REC(1, TRANSPORT, 5);

#undef ICCOM_ERR_REC
}

// Helper.
// Returns the error record pointer given by error number
//
// @iccom {valid ptr to iccom device}
// @err_no {the valid error number to report}
static inline struct iccom_error_rec *__iccom_get_error_rec(
		struct iccom_dev *iccom, unsigned char err_no)
{
	ICCOM_CHECK_DEVICE_PRIVATE("no device", return NULL);

	for (int i = 0; i < ARRAY_SIZE(iccom->p->errors); ++i) {
		if (iccom->p->errors[i].err_num == err_no) {
			return &(iccom->p->errors[i]);
		}
	}
	return NULL;
}


// Helper.
// Reports error to the kernel log and also tracks the history of errors
// and protects kernel log from error messages flood in case of external
// errors triggering.
//
// @iccom {valid ptr to iccom device}
// @err_no {the valid error number to report}
// @sub_error_no subsystem error number (might be used to pass
//      subsystem error code)
// @func_name {NULL || valid string pointer} function name where
//      the error was raised
//
// RETURNS:
//      true: if it is OK to be verbose now
//      false: else (silence required)
static bool __iccom_error_report(struct iccom_dev *iccom
				  , unsigned char err_no
				  , int sub_error_no
				  , const char *func_name)
{
	ICCOM_CHECK_DEVICE_PRIVATE("no device", return true);

	struct iccom_error_rec *e_ptr = __iccom_get_error_rec(iccom
							      , err_no);
	if (e_ptr == NULL) {
		iccom_err("unknown error type given: %u" , err_no);
		return true;
	}

	// NOTE: wraps every ~24 hours
	const uint32_t now_msec = (uint32_t)(ktime_divns(ktime_get(), 1000000));
	e_ptr->total_count++;

	const unsigned int since_last_report_msec
			= (now_msec >= e_ptr->last_report_time_msec)
			  ? (now_msec - e_ptr->last_report_time_msec)
			  : (e_ptr->last_report_time_msec - now_msec);
	const unsigned int since_last_occurrence_msec
			= (now_msec >= e_ptr->last_occurrence_time_msec)
			  ? (now_msec - e_ptr->last_occurrence_time_msec)
			  : (e_ptr->last_occurrence_time_msec - now_msec);
	e_ptr->last_occurrence_time_msec = now_msec;

	// approximately calculating the decay rate at this time point
	// surely it will not be exactly the exp decay, but will resemble
	// the general behaviour
	const unsigned int decay_percent
		= max(min((unsigned int)((50 * since_last_occurrence_msec)
					 / ICCOM_ERR_RATE_DECAY_RATE_MSEC_PER_HALF)
			  , (unsigned int)100)
		      , (unsigned int)ICCOM_ERR_RATE_DECAY_RATE_MIN);
	const unsigned int threshold = e_ptr->err_per_sec_threshold;
	const unsigned int prev_rate
		= 1000 / max((unsigned int)(e_ptr->exp_avg_interval_msec), 1U);

	e_ptr->exp_avg_interval_msec
		= max((unsigned int)(((100 - decay_percent)
				        * e_ptr->exp_avg_interval_msec
		      		      + decay_percent
				        * since_last_occurrence_msec) / 100)
		      , 1U);

	const unsigned int rate = 1000 / e_ptr->exp_avg_interval_msec;

#ifdef ICCOM_DEBUG
	iccom_err_raw("====== error %d ======", err_no);
	iccom_err_raw("diff interval: %u", since_last_occurrence_msec);
	iccom_err_raw("decay percent: %u", decay_percent);
	iccom_err_raw("new avg interval: %lu", e_ptr->exp_avg_interval_msec);
	iccom_err_raw("rate_prev = %u", prev_rate);
	iccom_err_raw("rate = %u", rate);
#endif

	if (since_last_report_msec < ICCOM_MIN_ERR_REPORT_INTERVAL_MSEC
			&& !(prev_rate < threshold && rate >= threshold)) {
		e_ptr->unreported_count++;
		e_ptr->last_reported = false;
		return false;
	}

	e_ptr->last_report_time_msec = now_msec;
	e_ptr->last_reported = true;

	static const char *const level_err = "error";
	static const char *const level_warn = "warning";
	const char *const report_class_str = (rate >= threshold)
					     ? level_err : level_warn;

	if (func_name) {
		iccom_err_raw("ICCom %s %u (avg. rate per sec: %d): "
			      "%s (sub %s: %d), raised by %s"
			      , report_class_str, err_no
			      , rate, e_ptr->err_msg, report_class_str
			      , sub_error_no, func_name);
	} else {
		iccom_err_raw("ICCom %s %u (avg. rate per sec: %d): "
			      "%s (sub %s: %d)"
			      , report_class_str, err_no
			      , rate, e_ptr->err_msg, report_class_str
			      , sub_error_no);
	}

	if (e_ptr->unreported_count > 0) {
		iccom_err_raw("meanwhile, %s %d happened %d times"
			      " since last reporting %u msecs ago. Total "
			      "count is %u.", report_class_str, err_no
			      , e_ptr->unreported_count
			      , since_last_report_msec, e_ptr->total_count);
		e_ptr->unreported_count = 0;
	}

	return true;
}

// Helper.
// Inits the workqueue which is to be used by ICCom
// in its current configuration. If we use system-provided
// workqueue - does nothing.
//
// RETURNS:
//      >= 0     - on success
//      < 0     - negative error code
//
// ERRORS:
//      EAGAIN if workqueue init fails
static inline int __iccom_init_workqueue(
		const struct iccom_dev __kernel *const iccom)
{
#if ICCOM_WORKQUEUE_MODE_MATCH(SYSTEM)
	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, "using system wq");
	(void)iccom;
	return 0;
#elif ICCOM_WORKQUEUE_MODE_MATCH(SYSTEM_HIGHPRI)
	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, "using system_highpri wq");
	(void)iccom;
	return 0;
#elif ICCOM_WORKQUEUE_MODE_MATCH(PRIVATE)
	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, "using private wq");
	iccom->p->work_queue = alloc_workqueue("iccom", WQ_HIGHPRI, 0);

	if (iccom->p->work_queue) {
		return 0;
	}

	iccom_err("%s: the private work queue init failed."
				, __func__);
	return -EAGAIN;
#endif
}

// Helper.
// Closes the workqueue which was used by SymSPI
// in its current configuration. If we use system-provided
// workqueu - does nothing.
static inline void __iccom_close_workqueue(
		const struct iccom_dev *const iccom)
{
#if ICCOM_WORKQUEUE_MODE_MATCH(PRIVATE)
	destroy_workqueue(iccom->p->work_queue);
	iccom->p->work_queue = NULL;
#else
	(void)iccom;
#endif
}

// Helper.
// Wrapper over schedule_work(...) for queue selected by configuration.
// Schedules SymSPI work to the target queue.
static inline void __iccom_schedule_work(
		const struct iccom_dev *const iccom
		, struct work_struct *work)
{
#if ICCOM_WORKQUEUE_MODE_MATCH(SYSTEM)
	(void)iccom;
	schedule_work(work);
#elif ICCOM_WORKQUEUE_MODE_MATCH(SYSTEM_HIGHPRI)
	(void)iccom;
	queue_work(system_highpri_wq, work);
#elif ICCOM_WORKQUEUE_MODE_MATCH(PRIVATE)
	queue_work(iccom->p->work_queue, work);
#else
#error no known SymSPI work queue mode defined
#endif
}

// Helper.
// Wrapper over cancel_work_sync(...) in case we will
// need some custom queue operations on cancelling.
static inline void __iccom_cancel_work_sync(
		const struct iccom_dev *const iccom
		, struct work_struct *work)
{
	cancel_work_sync(work);
}

// Helper. Provides next outgoing package id.
static int __iccom_get_next_package_id(struct iccom_dev *iccom)
{
	int pkg_id = iccom->p->next_tx_package_id++;
	if (iccom->p->next_tx_package_id <= 0) {
		iccom->p->next_tx_package_id = ICCOM_INITIAL_PACKAGE_ID;
	}
	return pkg_id;
}

// Helper. Returns true if we have at least one package in TX list.
static inline bool __iccom_have_packages(struct iccom_dev *iccom)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("", return -EINVAL);
#endif
	return !list_empty(&iccom->p->tx_data_packages_head);
}

// Helper. Enqueues new empty (unfinalized) package to fill to tx
// packages queue (to the end of queue). The former last package
// (if one) will be finalized. The ID of the package is set upon
// creation.
//
// NOTE: The newly added package is not finalized, but is ready for data
//      to be added.
//
// RETURNS:
//      0 on success
//      < 0 - the negative error code
static int __iccom_enqueue_new_tx_data_package(struct iccom_dev *iccom)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("", return -EINVAL);
#endif
	if (__iccom_have_packages(iccom)) {
		__iccom_package_finalize(__iccom_get_last_tx_package(iccom));
	}

	struct iccom_package *new_package;
	new_package = kmalloc(sizeof(struct iccom_package), GFP_KERNEL);
	if (!new_package) {
		iccom_err("no memory for new package");
		return -ENOMEM;
	}

	int res = __iccom_package_init(new_package
				       , ICCOM_DATA_XFER_SIZE_BYTES);
	if (res < 0) {
		iccom_err("no memory for new package");
		kfree(new_package);
		return res;
	}

	int package_id = __iccom_get_next_package_id(iccom);
	__iccom_package_set_id(new_package, package_id);

	list_add_tail(&new_package->list_anchor
		      , &iccom->p->tx_data_packages_head);

	iccom->p->statistics.packages_in_tx_queue++;

	return 0;
}

// Helper. Returns true if we have > 1 packages in TX packages queue.
//
// LOCKING: storage should be locked before this call
//
// RETURNS:
//      true: if >1 packages exist in TX packages queue
//      false: else
static bool __iccom_have_multiple_packages(struct iccom_dev *iccom)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return false);
	ICCOM_CHECK_DEVICE_PRIVATE("", return false);
#endif
	struct list_head *const head = &iccom->p->tx_data_packages_head;
	struct list_head *curr = head;
	int count;
	for (count = 0; count < 2; count++) {
		if (curr->next == head) {
			break;
		}
		curr = curr->next;
	}
	return count == 2;
}

// Helper. Enqueues new finalized and empty package to tx packages
// queue (to the end of queue). The former last package (if one)
// is finalized.
//
// RETURNS:
//      0: on success
//      <0: negative error code on error
static int __iccom_enqueue_empty_tx_data_package(struct iccom_dev *iccom)
{
	int res = __iccom_enqueue_new_tx_data_package(iccom);
	if (res != 0) {
		return res;
	}
	struct iccom_package *pkg = __iccom_get_last_tx_package(iccom);
	__iccom_package_make_empty(pkg);
	return 0;
}

// Helper. Returns true if the package checksum is correct.
static inline bool __iccom_verify_package_crc(
	struct iccom_package *package)
{
	return __iccom_package_get_src(package)
		    == __iccom_package_compute_src(package);
}

// Helper. Verifies the selfconsistency of all package-level data
// (header, crc, free space).
//
// RETURNS:
//      package is ok: the package payload size >= 0
//      else: -1
static int __iccom_verify_package_data(struct iccom_package *package)
{
	bool pkg_ok;
	size_t payload_size = __iccom_package_payload_size(package, &pkg_ok);
	if (!pkg_ok) {
		iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
			   , "RX Package PL size incorrect: %zu"
			   , payload_size);
		iccom_dbg_printout_package(package);
		return -1;
	}
	if (!__iccom_package_check_unused_payload(package
			, ICCOM_PACKAGE_EMPTY_PAYLOAD_VALUE)) {
		iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
			    , "RX Package layout incorrect:"
			      " PL free space not filled with %hhx"
			    , ICCOM_PACKAGE_EMPTY_PAYLOAD_VALUE);
		iccom_dbg_printout_package(package);
		return -1;
	}
	if (!__iccom_verify_package_crc(package)) {
		iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
			   , "RX Package CRC incorrect");
		iccom_dbg_printout_package(package);
		return -1;
	}
	return (int)payload_size;
}

// Helper. Fills up the full_duplex_xfer data structure to make a
// full-duplex data xfer for the first pending data package in TX queue.
//
// NOTE: surely the first package in TX queue should be finalized before
//      this call
static void __iccom_fillup_next_data_xfer(struct iccom_dev *iccom
					  , struct full_duplex_xfer *xfer)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return);
	if (IS_ERR_OR_NULL(xfer)) {
		iccom_err("Valid xfer provided. Logical error.");
		return;
	}
	if (!__iccom_have_packages(iccom)) {
		iccom_err("No packages in TX queue. Logical error.");
		return;
	}
#endif

	struct iccom_package *src_pkg = __iccom_get_first_tx_package(iccom);

#ifdef ICCOM_DEBUG
	if (IS_ERR_OR_NULL(src_pkg)) {
		iccom_err("Broken pkg pointer. Logical error.");
		return;
	}
	if (__iccom_verify_package_data(src_pkg) < 0) {
		iccom_err("First TX package is not finalized. Logical error.");
		return;
	}
#endif
	xfer->size_bytes = src_pkg->size;
	xfer->data_tx = src_pkg->data;
	xfer->data_rx_buf = NULL;
	xfer->consumer_data = (void*)iccom;
	xfer->done_callback = &__iccom_xfer_done_callback;
	xfer->fail_callback = &__iccom_xfer_failed_callback;
}

// Helper. Fills up the full_duplex_xfer data structure to make a
// full-duplex ack/nack xfer.
static inline void __iccom_fillup_ack_xfer(
		struct iccom_dev *iccom
		, struct full_duplex_xfer *xfer
		, bool ack)
{
	xfer->size_bytes = ICCOM_ACK_XFER_SIZE_BYTES;
	xfer->data_tx = ack ? &iccom->p->ack_val : &iccom->p->nack_val;
	xfer->data_rx_buf = NULL;
	xfer->consumer_data = (void*)iccom;
	xfer->done_callback = &__iccom_xfer_done_callback;
	xfer->fail_callback = &__iccom_xfer_failed_callback;
}

// Helper. Returns true if the package is ACK package which approves
// the correct receiving of the data.
static inline bool __iccom_verify_ack(struct iccom_package *package)
{
	return (package->size == ICCOM_ACK_XFER_SIZE_BYTES)
		&& (package->data[0] == ICCOM_PACKAGE_ACK_VALUE);
}

// Helper. Moves TX package queue one step forward.
// If there are multiple data packages, simply discards the heading
// package. If there is only one package (which is supposed to be
// just sent), then empties it, updates its ID and finalizes it so
// it is ready for next xfer.
//
// To be called when the first in TX queue package xfer was
// proven to be done successfully (its ACK was received).
//
// NOTE: thread safe
//
// RETURNS:
//      if there is a non-empty package for xfer from our side.
static bool __iccom_queue_step_forward(struct iccom_dev *iccom)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return false);
	ICCOM_CHECK_DEVICE_PRIVATE("", return false);
	if (!__iccom_have_packages(iccom)) {
		iccom_err("empty TX packages: logical error");
		return false;
	}
#endif
	bool have_data;
	// this function is called indirectly by transport layer below,
	// while the TX queue can be updated independently by the
	// consumer, so need mutex here for protection
	mutex_lock(&iccom->p->tx_queue_lock);

	// if we have more than one package in the queue, this
	// means we have some our data to send in further packages
	if (__iccom_have_multiple_packages(iccom)) {
		struct iccom_package *delivered_package
			     = __iccom_get_first_tx_package(iccom);
		__iccom_package_free(delivered_package);
		iccom->p->statistics.packages_in_tx_queue--;
		have_data = true;
		goto finalize;
	}

	// we have only one package in queue
	struct iccom_package *delivered_package
		= __iccom_get_first_tx_package(iccom);

	// set this package empty and update with new id
	int next_id = __iccom_get_next_package_id(iccom);
	__iccom_package_set_id(delivered_package, next_id);
	__iccom_package_make_empty(delivered_package);

	have_data = false;
finalize:
	mutex_unlock(&iccom->p->tx_queue_lock);
	return have_data;
}

// Frees whole TX queue (should be called only on ICCom
// destruction when all external calls which might modify the
// TX queue are already disabled).
static void __iccom_queue_free(struct iccom_dev *iccom)
{
#ifdef ICCOM_DEBUG
	if (!__iccom_have_packages(iccom)) {
	    iccom_err("empty TX packages");
	}
#endif
	mutex_lock(&iccom->p->tx_queue_lock);

	struct iccom_package *first_package
		    = __iccom_get_first_tx_package(iccom);

	while (first_package) {
	    __iccom_package_free(first_package);
	    first_package = __iccom_get_first_tx_package(iccom);
	}

	// freeing the TX queue access
	mutex_unlock(&iccom->p->tx_queue_lock);

	mutex_destroy(&iccom->p->tx_queue_lock);
}

// Helper. Enqueues given message into the queue. Adds as many
// packages as needed.
//
// CONCURRENCE: thread safe
//
// RETURNS:
//      < 0 : the negated error number
//      0   : success
static int __iccom_queue_append_message(struct iccom_dev *iccom
			       , char *data, const size_t length
			       , unsigned int channel
			       , unsigned int priority)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return -ENODEV);
	ICCOM_CHECK_CHANNEL("", return -EBADSLT);
	if (IS_ERR_OR_NULL(data)) {
		iccom_err("bad data pointer");
		return -EINVAL;
	}
	if (!length) {
		iccom_err("bad data length");
		return -ENODATA;
	}
	if (!__iccom_have_packages(iccom)) {
		iccom_err("empty TX packages: logical error");
		return -EFAULT;
	}
#endif

	int bytes_written = 0;
	struct iccom_package *dst_package = NULL;
	int res = 0;

	mutex_lock(&iccom->p->tx_queue_lock);
	// we will assume the first package to be in active xfer
	// (however there might be some IDLE pause between xfers)
	// so if only one package left we will simply add a brand
	// new one
	if (!__iccom_have_multiple_packages(iccom)) {
		// TODO: we can consider to update first package
		// if its xfer have not yet began, to do this we need
		// to create its updated memory in separate place,
		// and then try to update the xfer data on transport
		// layer device, and if succeeded, then we may put
		// this data into the first package.
		res = __iccom_enqueue_new_tx_data_package(iccom);
		if (res < 0) {
			iccom_err("Could not post message: err %d", res);
			goto finalize;
		}
	}

	while (length > bytes_written) {
		dst_package = __iccom_get_last_tx_package(iccom);

		// adding message part (or whole) to the latest package
		int bytes_written_old = bytes_written;
		bytes_written += iccom_package_add_packet(
					 dst_package
					 , data + bytes_written
					 , length - bytes_written
					 , channel);

		// some bytes were written to the package
		if (bytes_written != bytes_written_old) {
			continue;
		}

		// last package in queue already has no space
		res = __iccom_enqueue_new_tx_data_package(iccom);
		if (res < 0) {
			// TODO make robust previous packages
			//      cleanup here to remove parts of
			//      failed message.
			iccom_err("Could not post message: err %d"
				  , res);
			goto finalize;
		}
	}

	// we will always finalize package to make it always be ready
	// for sending, however this doesn't mean that we can not add
	// more data to the finalized but not full package later
	__iccom_package_finalize(dst_package);

finalize:
	mutex_unlock(&iccom->p->tx_queue_lock);
	return res;
}

// Helper. Adds new message to the storage channel. If channel does
// not exist, creates it. Returns pointer to newly created message.
//
// @iccom {valid iccom pointer}
// @channel {valid channel number} the channel to add the new message
//
// CONCURRENCE: thread safe
// OWNERSHIP: of the new message belongs to the storage
//
// RETURNS:
//      !NULL: valid pointer to newly created and initialized
//          iccom_message
//      NULL: if fails
static struct iccom_message *__iccom_construct_message_in_storage(
		struct iccom_dev *iccom
		, unsigned int channel)
{
	struct iccom_message *msg;
	msg = kmalloc(sizeof(struct iccom_message), GFP_KERNEL);
	if (IS_ERR_OR_NULL(msg)) {
		iccom_err("No memory for new message");
		return NULL;
	}
	// TODO: allocate either the message maximum or expected
	// (if known) size to avoid reallocation
	__iccom_message_init(msg);
	msg->channel = channel;

	if (iccom_msg_storage_push_message(&iccom->p->rx_messages
					   , msg) != 0) {
		kfree(msg);
		return NULL;
	}
	return msg;
}

// Helper. Parses the next packet from the package. Starts at given
// position and if parsing is successful adds the parsed consumer data
// into the iccom consumer messages storage.
//
// @iccom {valid iccom ptr}
// @start_from {valid ptr} the pointer to the first packet byte
//      (first byte of packet header)
// @max_bytes_available the maximum possible total packet size (in
//      bytes), this is usually equal to the number of bytes left till
//      the end of the package payload area.
//      NOTE: any value less than minimal possible packet size
//          immediately will lead to parsing error.
// @consumer_bytes_count__out {NULL | valid ptr}: pointer to the
//      output variable where to ADD number of consumer bytes
//      parced from the packet. If not valid ptr - not used.
// @finalized_message__out {NULL | valid ptr}: pointer to the
//      output variable where to WRITE, if the message was just
//      finalized. If not valid ptr - not used.
//
// NOTE: if parsing of a packet failed, then all rest packets from
//      given package will be dropped, as long as the parsing
//      will be unreliable.
//
// CONCURRENCE: no simultaneous calls allowed, but finalized messages
//      storage can be read by consumer freely
//
// RETURNS:
//      >0: size of data read from the start (equals to the size of the
//          package which was read (in bytes)), this also means that
//          parsing of the packet was successful.
//       0: caller provided 0 bytes available, so nothing left to parse
//      <0: negative error number if parsing failed
static int __iccom_read_next_packet(struct iccom_dev __kernel *iccom
	, void __kernel *start_from
	, size_t max_bytes_available
	, size_t *consumer_bytes_count__out
	, bool *finalized_message__out)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("", return -EINVAL);
	ICCOM_CHECK_PTR(start_from, return -EINVAL);
#endif
	if (max_bytes_available == 0) {
		return 0;
	}

	struct iccom_packet packet;
	int res = __iccom_packet_parse_into_struct(start_from
				    , max_bytes_available, &packet);
	if (res < 0) {
		iccom_err("Broken packet detected.");
		return res;
	}

	// while message id is not used we always append data to the
	// latest message within the channel
	// TODO: adapt as protocol includes message ID
	struct iccom_message *msg
			= iccom_msg_storage_get_last_unfinalized_message(
					    &iccom->p->rx_messages
					    , packet.channel);

	if (!msg) {
		msg = __iccom_construct_message_in_storage(
				iccom, packet.channel);
		if (!msg) {
			iccom_err("No memory for incoming message.");
			return -ENOMEM;
		}
	}

	res = iccom_msg_storage_append_data_to_message(
		    &iccom->p->rx_messages, msg->channel, msg->id
		    , packet.payload, packet.payload_length
		    , packet.finalizing);

	if (res < 0) {
		return res;
	}
	if (!IS_ERR_OR_NULL(consumer_bytes_count__out)) {
		*consumer_bytes_count__out = packet.payload_length;
	}
	if (!IS_ERR_OR_NULL(finalized_message__out)) {
		*finalized_message__out = packet.finalizing;
	}

	return iccom_packet_packet_size_bytes(packet.payload_length);
}

// Helper. Full parsing of the package and dispatching all its packets
// to the consumer messages storage.
//
// @iccom {valid iccom ptr}
// @start_from {valid ptr} to the first byte of the package
//      payload.
// @payload_size {>=0} the exact size of the package payload in bytes
//
// Rolls back the applied changes from the package if parsing
// fails at some point. So the message storage is guaranteed to
// remain in selfconsistent state: either whole package is
// applied or whole package is not applied.
//
// To be called directly or indirectly by transport layer.
//
// CONCURRENCE: no simultaneous calls allowed, protected
//      async reading of finalized messages is OK.
//
// RETURNS:
//      0: on successful parsing of the whole package
//      -EBADMSG: if parsing failed (also due to out-of-memory conditions)
static int __iccom_process_package_payload(
		struct iccom_dev __kernel *iccom
		, void __kernel *start_from
		, size_t payload_size)
{
	int packets_done = 0;
	size_t bytes_to_parse = payload_size;
	void *start = start_from;
	size_t consumer_bytes_parsed_total = 0;

	while (bytes_to_parse > 0) {
		int bytes_read = __iccom_read_next_packet(iccom
					    , start, bytes_to_parse
					    , &consumer_bytes_parsed_total
					    , NULL);
		if (bytes_read <= 0) {
			iccom_msg_storage_rollback(&iccom->p->rx_messages);
			iccom_err("Package parsing failed on %d packet"
				  "(starting from 0). Error code: %d"
				  , packets_done, bytes_read);
			print_hex_dump(KERN_WARNING, ICCOM_LOG_PREFIX
				       ": Failed package payload: ", 0, 16, 1
				       , start_from, payload_size, true);
			// NOTE: the no-memory case is aggregated here also
			// 	to ask other size to resend the message
			return -EBADMSG;
		}

		start += bytes_read;
		bytes_to_parse -= bytes_read;
		packets_done++;
	}

	int finalized = iccom_msg_storage_uncommitted_finalized_count(
				&iccom->p->rx_messages);
	iccom_msg_storage_commit(&iccom->p->rx_messages);

	iccom->p->statistics.packets_received_ok += packets_done;
	iccom->p->statistics.messages_received_ok += finalized;
	iccom->p->statistics.total_consumers_bytes_received_ok
			+= consumer_bytes_parsed_total;
	__sync_add_and_fetch(
			&iccom->p->statistics.messages_ready_in_storage
			, finalized);

	if (finalized > 0) {
		// notify consumer if there is any new ready messages
		__iccom_schedule_work(iccom
				, &iccom->p->consumer_delivery_work);
	}
	return 0;
}

// Helper. Initiates the xfer of the first package in TX queue using
// the underlying transport layer. We must have finalized data package
// in TX queue before calling this function.
//
// NOTE: if the underlying transport is busy, then we will not shedule
//      xfer here, but in xfer-done callback.
//
// RETURNS:
//      0 on success
//      < 0 - the negative error code
static int __iccom_initiate_data_xfer(struct iccom_dev *iccom)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("", return -EINVAL);
#endif
	if (!__iccom_have_packages(iccom)) {
		iccom_err("No data to be sent.");
		return -ENODATA;
	}

	// to guarantee selfconsistence, we will just trigger
	// current xfer, while the xfer data is only to be updated
	// from the xfer done callback, the xfer done callback is
	// guaranteed to be called after data_xchange(...) invocation
	int res = iccom->xfer_iface.data_xchange(
			iccom->xfer_device, NULL, false);

	switch (res) {
	case FULL_DUPLEX_ERROR_NOT_READY:
		return 0;
	case FULL_DUPLEX_ERROR_NO_DEVICE_PROVIDED:
		iccom_err("No underlying xfer device provided");
		return -ENODEV;
	default: return 0;
	}
}


// Transport layer return point.
//
// Called from transport layer, when xfer failed. Dedicated
// to handle supervised error recovery or halting xfer device.
//
// See full_duplex_xfer.fail_callback description for details.
//
// CONCURRENCE: no simultaneous calls, also with other
//      transport layer return points
struct full_duplex_xfer *__iccom_xfer_failed_callback(
		const struct full_duplex_xfer __kernel *failed_xfer
		, const int next_xfer_id
		, int error_code
		, void __kernel *consumer_data)
{
	// The xfer failed

	struct iccom_dev *iccom = (struct iccom_dev *)consumer_data;
	ICCOM_CHECK_DEVICE("External error. No device provided."
			   , return ERR_PTR(-ENODATA));
	// if we are closing, then we will halt bottom transport layer
	// by returning error pointer value
	ICCOM_CHECK_CLOSING("will not invoke", return ERR_PTR(-ENODATA));

	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL, "FAILED xfer:");
	iccom_dbg_printout_xfer(failed_xfer);
	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL, "TX queue:");
	iccom_dbg_printout_tx_queue(iccom
				, ICCOM_DEBUG_PACKAGES_PRINT_MAX_COUNT);

	__iccom_err_report(ICCOM_ERROR_TRANSPORT, error_code);

	// we always goto ack stage with NACK package
	// and then repeat the data xfer within the next frame.
	__iccom_fillup_ack_xfer(iccom, &iccom->p->xfer, false);
	iccom->p->data_xfer_stage = false;

	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL, "Next xfer:");
	iccom_dbg_printout_xfer(&iccom->p->xfer);
	return &iccom->p->xfer;
}

// Transport layer return point.
//
// CONCURRENCE: no simultaneous calls
//
// Called from transport layer, when xfer is done.
struct full_duplex_xfer *__iccom_xfer_done_callback(
			const struct full_duplex_xfer __kernel *done_xfer
			, const int next_xfer_id
			, bool __kernel *start_immediately__out
			, void *consumer_data)
{
	// The xfer was just finished. The done_xfer.data_rx_buf contains
	// the received data.

	struct iccom_dev *iccom = (struct iccom_dev *)consumer_data;
	ICCOM_CHECK_DEVICE("External error. No device provided."
			   , return ERR_PTR(-ENODATA));
	// if we are closing, then we will halt bottom transport layer
	// by returning error pointer value
	ICCOM_CHECK_CLOSING("will not invoke", return ERR_PTR(-ENODATA));

	// convenience wrappers around done_xfer.data_tx/rx_buf
	struct iccom_package rx_pkg = {.data = done_xfer->data_rx_buf
				       , .size = done_xfer->size_bytes
				       , .owns_data = false};
	if (IS_ERR_OR_NULL(rx_pkg.data)) {
		iccom_err("got broken RX data pointer: %px; "
			  , rx_pkg.data);
		return ERR_PTR(-ENODATA);
	}

	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL, "Done xfer:");
	iccom_dbg_printout_xfer(done_xfer);
	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL, "TX queue:");
	iccom_dbg_printout_tx_queue(iccom
			, ICCOM_DEBUG_PACKAGES_PRINT_MAX_COUNT);

	iccom->p->statistics.raw_bytes_xfered_via_transport_layer
		    += done_xfer->size_bytes;
	iccom->p->statistics.transport_layer_xfers_done_count++;

	// If we are in data xfering stage, thus the data xfer has been
	// just finished, so we need to verify it and send the ack/nack
	// answer back. TODO: later we may indicate the CRC failure with
	// other side drop flag timeout so we'll need no ack/nack xfers
	// at all.
	if (iccom->p->data_xfer_stage) {
		iccom->p->statistics.packages_xfered++;

		*start_immediately__out = true;

		int payload_size = __iccom_verify_package_data(&rx_pkg);

		// if package level data is not selfconsistent
		if (payload_size < 0) {
			__iccom_fillup_ack_xfer(iccom, &iccom->p->xfer, false);
			iccom->p->statistics.packages_bad_data_received += 1;
			goto finalize;
		}

		// package is selfconsistent, but we already received
		// and processed it successfully, then we will say that
		// this package is (already) OK
		int rx_pkg_id = __iccom_package_get_id(&rx_pkg);
		if (rx_pkg_id == iccom->p->last_rx_package_id) {
			__iccom_fillup_ack_xfer(iccom, &iccom->p->xfer, true);
			iccom->p->statistics.packages_duplicated_received += 1;
			goto finalize;
		}

		// package is selfconsistent and we have not processed it
		// yet, so we'll try to process it
		void *pkg_payload = __iccom_package_payload_start_addr(&rx_pkg);
		if (__iccom_process_package_payload(iccom, pkg_payload
					  , (size_t)payload_size) != 0) {
			__iccom_fillup_ack_xfer(iccom, &iccom->p->xfer, false);
			iccom->p->statistics.packages_parsing_failed += 1;
			goto finalize;
		}

		// package parsing was OK
		iccom->p->statistics.packages_received_ok++;
		iccom->p->last_rx_package_id = rx_pkg_id;
		__iccom_fillup_ack_xfer(iccom, &iccom->p->xfer, true);
		goto finalize;
	}

	// If we are in ack stage, then we have just finished the
	// ack xfer and can goto to the next frame (using old or
	// new data depending on the ack state of the other side).

	// If other side acked the correct receiving of our data
	if (__iccom_verify_ack(&rx_pkg)) {
		iccom->p->statistics.packages_sent_ok++;
		// TODO to schedule only if at least one message finalized
		*start_immediately__out = __iccom_queue_step_forward(iccom);
	} else {
		// We must resend the failed package immediately.
		// TODO: probably we may avoid resending the empty
		//      package if new packages arrived in TX queue.
		*start_immediately__out = true;
	}

	// preparing the next xfer with the first pending package in queue
	__iccom_fillup_next_data_xfer(iccom, &iccom->p->xfer);

finalize:
	// switching to other stage (the only point where the
	// data_xfer_stage is being written)
	iccom->p->data_xfer_stage = !iccom->p->data_xfer_stage;
#ifdef ICCOM_DEBUG
	mutex_lock(&iccom->p->rx_messages.lock);
	__iccom_msg_storage_printout(&iccom->p->rx_messages
				     , ICCOM_DEBUG_MESSAGES_PRINTOUT_MAX_COUNT
				     , ICCOM_DEBUG_CHANNEL);
	mutex_unlock(&iccom->p->rx_messages.lock);
#endif
	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL, "Next xfer:");
	iccom_dbg_printout_xfer(&iccom->p->xfer);

	return &iccom->p->xfer;
}

// Stops the underlying byte xfer device and detaches it from
// the ICCom driver.
void __iccomm_stop_xfer_device(struct iccom_dev *iccom)
{
	iccom->xfer_iface.close(iccom->xfer_device);
}


// The consumer notification procedure, is sheduled every time, when
// any incoming message is finished and ready to be delivered to the
// consumer. Due to latency in scheduling not only notifies about
// initial message, but also checks for other finished messages.
//
// @work the scheduled work which launched the notification
static void __iccom_consumer_notification_routine(
	struct work_struct *work)
{
	if (IS_ERR_OR_NULL(work)) {
		iccom_err("no notification work provided");
		return;
	}

	struct iccom_dev_private *iccom_p = container_of(work
		, struct iccom_dev_private, consumer_delivery_work);

	int passed = iccom_msg_storage_pass_ready_data_to_consumer(
					     &iccom_p->rx_messages);
	if (passed >= 0) {
		__sync_add_and_fetch(
			    &iccom_p->statistics.messages_ready_in_storage
			    , -passed);
	}
}

// Verifies if the interface of full duplex transport device contains all
// records relevant for ICCom
static bool __iccom_verify_transport_layer_interface(
		const struct full_duplex_sym_iface  *const iface)
{
	return !IS_ERR_OR_NULL(iface)
		    && !IS_ERR_OR_NULL(iface->data_xchange)
		    && !IS_ERR_OR_NULL(iface->is_running)
		    && !IS_ERR_OR_NULL(iface->init)
		    && !IS_ERR_OR_NULL(iface->reset)
		    && !IS_ERR_OR_NULL(iface->close);
}

// Helper. Initializes the iccom packages storage (TX storage).
// RETURNS:
//      0: all fine
//      <0: negative error code
static inline int __iccom_init_packages_storage(struct iccom_dev *iccom)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("", return -EINVAL);
#endif
	INIT_LIST_HEAD(&iccom->p->tx_data_packages_head);
	mutex_init(&iccom->p->tx_queue_lock);
	iccom->p->next_tx_package_id = ICCOM_INITIAL_PACKAGE_ID;
	return 0;
}

// Helper. Frees all resources owned by packages storage.
static inline void __iccom_free_packages_storage(struct iccom_dev *iccom)
{
#ifdef ICCOM_DEBUG
	ICCOM_CHECK_DEVICE("", return);
	ICCOM_CHECK_DEVICE_PRIVATE("", return);
#endif
	mutex_lock(&iccom->p->tx_queue_lock);
	while (__iccom_have_packages(iccom)) {
		__iccom_package_free(__iccom_get_first_tx_package(iccom));
	}
	mutex_unlock(&iccom->p->tx_queue_lock);
	mutex_destroy(&iccom->p->tx_queue_lock);
}

/* -------------------------- KERNEL SPACE API --------------------------*/

// API
//
// Sends the consumer data to the other side via specified channel.
//
// @data {valid data pointer} the consumer data to be sent to external
//      @channel.
//      NOTE: consumer guarantees that the data remain untouched
//              until call returns.
//      OWNERSHIP:
//              consumer
// @length {>0} the @data size in bytes.
// @channel [ICCOM_PACKET_MIN_CHANNEL_ID; ICCOM_PACKET_MAX_CHANNEL_ID]
//      the id of the channel to be used to send the message
//      should be between ICCOM_PACKET_MIN_CHANNEL_ID and
//      ICCOM_PACKET_MAX_CHANNEL_ID inclusive
// @priority Defines the message priority. TODO (not yet implemented).
// @iccom {valid iccom device ptr} the protocol driver to be used to
//      send the message
//
// CONCURRENCE: thread safe
//
// RETURNS:
//      0 : on success
//
//      TODO:
//          Message id (>= 0) on success (it can be used as timestamp
//          the bigger the id the later message was ordered for xfer).
//
//      <0 : negated error code if fails.
__maybe_unused
int iccom_post_message(struct iccom_dev *iccom
		, char *data, const size_t length
		, unsigned int channel
		, unsigned int priority)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);
	ICCOM_CHECK_CHANNEL("bad channel", return -EBADSLT);
	if (IS_ERR_OR_NULL(data)) {
		iccom_err("broken data pointer provided");
		return -EINVAL;
	}
	if (!length) {
		iccom_err("Will not post empty message.");
		return -ENODATA;
	}
	ICCOM_CHECK_CLOSING("will not invoke", return -EBADFD);

#if defined(ICCOM_DEBUG) && defined(ICCOM_DEBUG_PACKAGES_PRINT_MAX_COUNT)
#if ICCOM_DEBUG_PACKAGES_PRINT_MAX_COUNT != 0
	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
		   , "TX queue before adding new message");
	mutex_lock(&iccom->p->tx_queue_lock);
	iccom_dbg_printout_tx_queue(iccom
			, ICCOM_DEBUG_PACKAGES_PRINT_MAX_COUNT);
	mutex_unlock(&iccom->p->tx_queue_lock);
#endif
#endif

	// TODO drop request if there are too many pending
	// packages to be sent.

	int res = 0;
	res = __iccom_queue_append_message(iccom, data, length, channel
					   , priority);

	if (res < 0) {
		iccom_err("Failed to post the message: err = %d", res);
		return res;
	}

	// for now we send the package if it is not empty
	res = __iccom_initiate_data_xfer(iccom);
	if (res < 0) {
		iccom_err("Failed to post the message: err = %d", res);
		return res;
	}

	return 0;
}

// API
//
// Forces the ICCom to start xfer of the current heading package
// even it is empty.
//
// @iccom {valid iccom device ptr} the protocol driver to be used
//
// RETURNS:
//      0 : on success
//
//      TODO:
//          Message id (>= 0) on success (it can be used as timestamp
//          the bigger the id the later message was ordered for xfer).
//
//      <0 : negated error code if fails.
__maybe_unused
int iccom_flush(struct iccom_dev *iccom)
{
	int res = __iccom_initiate_data_xfer(iccom);
	if (res < 0) {
		iccom_err("Failed to initiate the message: err = %d", res);
		return res;
	}

	return 0;
}

// API
//
// Adds the message ready callback to the channel. This callback will be
// called every time a message is ready in the channel. After the callback
// invocation the message data is discarded.
//
// @iccom {valid ptr} device to work with
// @channel {valid channel number | ICCOM_ANY_CHANNEL_VALUE}
//      the channel to install the callback; if equals to
//      ICCOM_ANY_CHANNEL_VALUE then callback is installed
//      as global callback for all channels.
//      NOTE: global callback is used only when specific channel
//          callback is not set.
// @message_ready_callback {valid ptr || NULL} the pointer to the
//      callback which is to be called when channel gets a message
//      ready. NULL value disables the callback function on the channel.
//
//      CALLBACK DATA OWNERSHIP: if callback returns true, then
//          ownership of message data (@msg_data) is transferred to
//          the consumer; if callback returns false, then message
//          data ownership remains in ICCom, and the message (and its
//          data) is immediately discarded after callback invocation.
//
// @consumer_data {any} the consumer value to pass to the
//      @message_ready_callback.
//
// RETURNS:
//      0: on success
//      <0: negated error code
__maybe_unused
int iccom_set_channel_callback(struct iccom_dev *iccom
		, unsigned int channel
		, iccom_msg_ready_callback_ptr_t message_ready_callback
		, void *consumer_data)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);
	ICCOM_CHECK_CHANNEL("bad channel", return -EBADSLT);
	ICCOM_CHECK_CLOSING("will not invoke", return -EBADFD);
	if (IS_ERR(message_ready_callback)) {
		iccom_err("broken callback pointer provided");
		return -EINVAL;
	}

	return iccom_msg_storage_set_channel_callback(
			&iccom->p->rx_messages, channel
			, message_ready_callback
			, consumer_data);
}

// API
//
// Removes callback from the channel.
//
// @iccom {valid ptr} device to work with
// @channel {valid channel number | ICCOM_ANY_CHANNEL_VALUE}
//      the channel to remove the callback; if equals to
//      ICCOM_ANY_CHANNEL_VALUE then global callback is
//      removed;
//      NOTE: if no callback defined for the channel,
//          its messages are simply discarded.
//
// RETURNS:
//      0: on success
//      <0: negated error code
__maybe_unused
int iccom_remove_channel_callback(struct iccom_dev *iccom
		, unsigned int channel)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);
	ICCOM_CHECK_CHANNEL("bad channel", return -EBADSLT);
	ICCOM_CHECK_CLOSING("will not invoke", return -EBADFD);
	return iccom_msg_storage_reset_channel_callback(
			&iccom->p->rx_messages, channel);
}

// API
//
// Gets message ready callback of the channel.
//
// @iccom {valid ptr} device to work with
// @channel {valid channel number | ICCOM_ANY_CHANNEL_VALUE}
//      the channel to get the callback from; if equals to
//      ICCOM_ANY_CHANNEL_VALUE then global callback pointer
//      is returned.
//
// CONCURRENCE: thread safe
//
// RETURNS:
//      ERR PTR: on failure
//      NULL: if channel doesn't exist || callback is not set
//      callback pointer: if channel exists and callback is set
__maybe_unused
iccom_msg_ready_callback_ptr_t iccom_get_channel_callback(
		struct iccom_dev *iccom
		, unsigned int channel)
{
	ICCOM_CHECK_DEVICE("no device provided", return ERR_PTR(-ENODEV));
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return ERR_PTR(-EINVAL));
	ICCOM_CHECK_CHANNEL("bad channel", return ERR_PTR(-EBADSLT));
	ICCOM_CHECK_CLOSING("will not invoke", return ERR_PTR(-EBADFD));
	return iccom_msg_storage_get_channel_callback(
			&iccom->p->rx_messages, channel);
}

// API
//
// Pops the oldest (first came) finalized and committed message
// from RX queue of the given channel to the kernel space.
//
// @iccom {inited iccom_dev ptr || ERR_PTR || NULL} the initialized ICCom
//      device pointer, if error-ptr or NULL, the error is returned.
// @channel {number} the channel number to read the message from.
//      If channel number is invalid then indicate it with error.
// @msg_data_ptr__out {valid kernel ptr || ERR_PTR || NULL}:OUT
//      the pointer to the pointer to the message data,
//      valid ptr:
//          set to:
//          NULL: if no message data provided (no messages available)
//          !NULL: pointer to message data (if message was get)
//          UNTOUCHED: if errors
//      ERR_PTR || NULL:
//          call does nothing, error returned
// @buf_size__out {valid kernel ptr || ERR_PTR || NULL}:OUT
//      the pointer to the size of the message data
//      valid ptr:
//          set to:
//          0: when *msg_data_ptr__out is set to NULL
//          >0: size of message data pointed by *msg_data_ptr__out
//              is !NULL
//          UNTOUCHED: if errors
//      ERR_PTR || NULL:
//          call does nothing, error returned
// @msg_id__out {valid kernel ptr || ERR_PTR || NULL}:OUT
//      the ptr to write the msg_id to.
//      valid ptr:
//          set to ICCOM_PACKET_INVALID_MESSAGE_ID if no message,
//          set to message ID if message is read,
//          untouched if other errors
//      ERROR/NULL: not used
//
// CONCURRENCE: thread safe
// OWNERSHIP: of the provided message data is transferred to the caller.
//
// RETURNS:
//     0: no errors (absence of messages is not an error)
//     negated error code if read failed:
//         -ENODEV: iccom_dev pointer is not valid
//         -EINVAL: iccom_dev pointer points to broken device
//         -EBADSLT: the channel provided is invalid (out of channel
//              range
//         -EFAULT: @msg_data_ptr__out or @buf_size__out pointer
//              is not valid
//         -EBADFD: the device is closing now, no calls possible
__maybe_unused
int iccom_read_message(struct iccom_dev *iccom
		, unsigned int channel
		, void __kernel **msg_data_ptr__out
		, size_t __kernel *buf_size__out
		, unsigned int *msg_id__out)
{
	ICCOM_CHECK_DEVICE("", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("", return -EINVAL);
	ICCOM_CHECK_CHANNEL("", return -EBADSLT);
	ICCOM_CHECK_CLOSING("", return -EBADFD);
	ICCOM_CHECK_PTR(msg_data_ptr__out, return -EFAULT);
	ICCOM_CHECK_PTR(buf_size__out, return -EFAULT);

	struct iccom_message *msg;
	msg = iccom_msg_storage_pop_first_ready_message(
			&iccom->p->rx_messages, channel);

	if (!msg) {
		*msg_data_ptr__out = NULL;
		*buf_size__out = 0;
		if (!IS_ERR_OR_NULL(msg_id__out)) {
			*msg_id__out = ICCOM_PACKET_INVALID_MESSAGE_ID;
		}
		return 0;
	}

	__sync_add_and_fetch(
		    &iccom->p->statistics.messages_ready_in_storage, -1);

	*msg_data_ptr__out = msg->data;
	*buf_size__out = msg->length;
	if (!IS_ERR_OR_NULL(msg_id__out)) {
		*msg_id__out = msg->id;
	}

	kfree(msg);
	return 0;
}

// API
//
// Initializes the iccom_dev structure.
//
// @iccom {valid iccom_dev ptr} managed by consumer. Not to be
//      amended while ICCom is active (not closed).
//
//      @xfer_device field of iccom_dev structure must
//      point to valid transport layer device.
//
//      @xfer_iface member should be valid and contain all
//      pointers.
//
//      iccom_dev_private structure pointer initialized by iccom
//      for internal needs.
//
// If this call succeeds, it is possible to use all other iccom
// methods on initialized iccom struct.
//
// NOTE: caller should never invoke ICCom methods on struct iccom_dev
// which init method didn't return with success state (yet).
//
// CONCURRENCE: caller should ensure that no one of iccom_init(...),
//      iccom_close(...) will be called under data-race conditions
//      with the same struct iccom_dev.
//
// CONTEXT: sleepable
//
// RETURNS:
//      0 on success
//      negative error code on error
__maybe_unused
int iccom_init(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("struct ptr broken", return -ENODEV);

	if (IS_ERR_OR_NULL(iccom->xfer_device)) {
		iccom_err("No transport layer device provided");
		return -ENODEV;
	}
	if (!__iccom_verify_transport_layer_interface(
			    &iccom->xfer_iface)) {
		iccom_err("Not all relevant interface methods are defined");
		return -ENODEV;
	}

	iccom_info_raw(ICCOM_LOG_INFO_OPT_LEVEL
		       , "creating device (%px)", iccom);

	// initialization sequence
	int res = 0;
	iccom->p = kmalloc(sizeof(struct iccom_dev_private), GFP_KERNEL);
	if (!iccom->p) {
		iccom_err("No memory.");
		res = -ENOMEM;
		goto finalize;
	}
	iccom->p->iccom = iccom;

	__iccom_error_report_init(iccom);

	res = iccom_msg_storage_init(&iccom->p->rx_messages);
	if (res < 0) {
		iccom_err("Could not initialize messages storage.");
		goto free_private;
	}

	res = __iccom_init_packages_storage(iccom);
	if (res < 0) {
		iccom_err("Could not initialize packages storage.");
		goto free_msg_storage;
	}

	// init TX ack/nack data
	iccom->p->ack_val = ICCOM_PACKAGE_ACK_VALUE;
	iccom->p->nack_val = ICCOM_PACKAGE_NACK_VALUE;

	// initial empty package
	res = __iccom_enqueue_empty_tx_data_package(iccom);
	if (res != 0) {
		iccom_err("Could not add initial TX package");
		goto free_pkg_storage;
	}

	__iccom_fillup_next_data_xfer(iccom, &iccom->p->xfer);
	iccom->p->data_xfer_stage = true;

	// init workqueue for delivery to consumer
	res = __iccom_init_workqueue(iccom);
	if (res != 0) {
		iccom_err("Could not init own workqueue.");
		goto free_pkg_storage;
	}

	// initiate consumer notification work
	INIT_WORK(&iccom->p->consumer_delivery_work
		  , __iccom_consumer_notification_routine);

	iccom->p->closing = false;

	// Initializing transport layer and start communication
	res = iccom->xfer_iface.init(iccom->xfer_device
				     , &iccom->p->xfer);

	if (res < 0) {
		iccom_err("Full duplex xfer device failed to"
			  " initialize, err: %d", res);
		goto free_workqueue;
	}

	return 0;

free_workqueue:
	__iccom_close_workqueue(iccom);
free_pkg_storage:
	__iccom_free_packages_storage(iccom);
free_msg_storage:
	iccom_msg_storage_free(&iccom->p->rx_messages);
free_private:
	kfree(iccom->p);
	iccom->p = NULL;
finalize:
	return res;
}

// API
//
// Prints out the statistics message into kernel message buffer
//
// @iccom {valid ptr} device to work with
//
// CONCURRENCE: thread safe
__maybe_unused
void iccom_print_statistics(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("no device provided", return);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return);
	ICCOM_CHECK_CLOSING("will not invoke", return);

	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "====== ICCOM (%px) statistics ======", iccom);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "TRANSPORT LAYER: xfers done count:\t%llu"
		       , iccom->p->statistics.transport_layer_xfers_done_count);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "TRANSPORT LAYER: bytes xfered:\t%llu"
		       , iccom->p->statistics.raw_bytes_xfered_via_transport_layer);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "PACKAGES: xfered TOTAL:\t%llu"
		       , iccom->p->statistics.packages_xfered);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "PACKAGES: sent OK:\t%llu"
		       , iccom->p->statistics.packages_sent_ok);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "PACKAGES: received OK:\t%llu"
		       , iccom->p->statistics.packages_received_ok);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "PACKAGES: sent FAIL:\t%llu"
		       , iccom->p->statistics.packages_xfered
			 - iccom->p->statistics.packages_sent_ok);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "PACKAGES: received FAIL:\t%llu"
		       , iccom->p->statistics.packages_xfered
			 - iccom->p->statistics.packages_received_ok);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "PACKAGES: in TX queue:\t%lu"
		       , iccom->p->statistics.packages_in_tx_queue);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "PACKETS: received OK:\t%llu"
		       , iccom->p->statistics.packets_received_ok);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "MESSAGES: received OK:\t%llu"
		       , iccom->p->statistics.messages_received_ok);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "MESSAGES: ready in RX storage:\t%lu"
		       , iccom->p->statistics.messages_ready_in_storage);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "BANDWIDTH: total consumer bytes received OK:\t%llu"
		       , iccom->p->statistics.total_consumers_bytes_received_ok);
}

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// TODO
// API
//
// Closes the ICCom communication.
//
// NOTE: thread safe
__maybe_unused
void iccom_close(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("no device provided", return);
	ICCOM_CHECK_DEVICE_PRIVATE("broken private device part ptr"
				   , return);

	if (IS_ERR_OR_NULL(iccom->xfer_device)) {
	    iccom_err("Looks like provided device doesn't have"
		      " any transport layer device attached");
		return;
	}

	// only one close sequence may run at the same time
	// turning this flag will block all further external
	// calls to given ICCom instance
	bool expected_state = false;
	bool dst_state = true;
	bool res = __atomic_compare_exchange_n(&iccom->p->closing
			, &expected_state, dst_state, false
			, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	if (!res) {
		iccom_err("iccom is already closing now");
		return;
	}
	iccom_info_raw(ICCOM_LOG_INFO_OPT_LEVEL
		       , "closing device (%px)", iccom);

	__iccom_cancel_work_sync(iccom
			, &iccom->p->consumer_delivery_work);

	__iccomm_stop_xfer_device(iccom);

	__iccom_close_workqueue(iccom);

	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	// TODO
	// Consider the case when consumer has entered some of our
	// method, but have not yet exited, so we may run into condition
	// when we risk to free the data while some method is still
	// working with it. This will lead to crash.

	// Cleanup all our allocated data
	iccom_msg_storage_free(&iccom->p->rx_messages);
	__iccom_queue_free(iccom);

	iccom->p->iccom = NULL;
	kfree(iccom->p);
	iccom->p = NULL;
}

// API
//
// Inits underlying full duplex transport and iccom devices in binded.
//
// @iccom {valid ptr to iccom_dev struct} points to unititialized iccom_dev
//      struct
// @full_duplex_if {valid ptr to full_duplex_sym_iface struct} points
//      to valid and filled with correct pointers full_duplex_sym_iface
//      struct
// @full_duplex_device points to the full duplex device structure,
//      which is ready to be used with full_duplex_if->init(...) call.
//
// RETURNS:
//      0: if all fine
//      <0: if failed (negated error code)
__maybe_unused
int iccom_init_binded(struct iccom_dev *iccom
		, const struct full_duplex_sym_iface *const full_duplex_if
		, void *full_duplex_device)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_PTR(full_duplex_device, return -ENODEV);
	if (!__iccom_verify_transport_layer_interface(full_duplex_if)) {
		iccom_err("Not all relevant interface methods are defined");
		return -EINVAL;
	}

	iccom->xfer_device = full_duplex_device;
	iccom->xfer_iface = *full_duplex_if;
	iccom->p = NULL;

	int res = iccom_init(iccom);
	if (res < 0) {
		iccom_err("ICCom driver initialization failed, "
			  "err: %d", res);
		full_duplex_if->close(full_duplex_device);
		return res;
	}

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL
		   , "iccom & full duplex device inited");
	return 0;
}

// API
//
// Closes both binded full-duplex transport and iccom devices.
//
// @iccom {valid ptr to iccom_dev struct} points to unititialized iccom_dev
//      struct
__maybe_unused
void iccom_close_binded(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("no device provided", return);

	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL, "Closing ICCom device");
	iccom_close(iccom);

	if (!IS_ERR_OR_NULL(iccom->xfer_device) && 
			!IS_ERR_OR_NULL(&iccom->xfer_iface.close)) {
		iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL, "Closing transport device");
		iccom->xfer_iface.close(iccom->xfer_device);
	}
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL, "Closing done");
}

// API
//
// Returns true, if the device is running
//
// @iccom {valid ptr to iccom_dev struct} points to unititialized iccom_dev
//      struct
__maybe_unused
bool iccom_is_running(struct iccom_dev *iccom)
{
	return !(IS_ERR_OR_NULL(iccom)
		 || IS_ERR_OR_NULL(iccom->p));
}

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

EXPORT_SYMBOL(iccom_post_message);
EXPORT_SYMBOL(iccom_flush);
EXPORT_SYMBOL(iccom_set_channel_callback);
EXPORT_SYMBOL(iccom_remove_channel_callback);
EXPORT_SYMBOL(iccom_get_channel_callback);
EXPORT_SYMBOL(iccom_read_message);
EXPORT_SYMBOL(iccom_print_statistics);
EXPORT_SYMBOL(iccom_init);
EXPORT_SYMBOL(iccom_close);
EXPORT_SYMBOL(iccom_init_binded);
EXPORT_SYMBOL(iccom_close_binded);
EXPORT_SYMBOL(iccom_is_running);

// Adds a generic device into a list to be further used to
// delete those devices using the platform_device_unregister
//
// @dev {valid ptr} device to be stored
// @data {valid ptr} list head necessary for the list
//
// RETURNS:
//      0: ok
//     <0: errors
int iccom_sysfs_add_device_to_list(struct device *dev, void* data)
{
	if(IS_ERR_OR_NULL(dev)) {
		iccom_err("device is null");
		return -EFAULT;
	}

	if(IS_ERR_OR_NULL(data)) {
		iccom_err("data is null");
		return -EFAULT;
	}

	struct list_head *devices_list_head = (struct list_head *)data;

	if(IS_ERR_OR_NULL(devices_list_head)) {
		iccom_err("List for device storing is invalid.");
		return -EINVAL;
	}
	
	struct device_list *device_list_entry = 
				kzalloc(sizeof(struct device_list),GFP_KERNEL);
	if(IS_ERR_OR_NULL(device_list_entry)) {
		iccom_err("No available memory to create \
				a device_list entry.");
		return -ENOMEM;
	}

	device_list_entry->dev = dev;
	list_add(&device_list_entry->list, devices_list_head);

	return 0;
}

// Destroys all the platform devices associated with a platform
// driver by looping them first and then by calling
// platform_device_unregister for each of them
//
// @driver {valid ptr} driver which holds the devices
void iccom_sysfs_driver_unregister_devices(struct device_driver *driver)
{
	struct list_head driver_devices_list_head;
	struct device_list *driver_device_list_entry, *tmp;
	int ret;

	if(IS_ERR_OR_NULL(driver)) {
		iccom_err("Driver is null");
		return;
	}

	INIT_LIST_HEAD(&driver_devices_list_head);

	ret = driver_for_each_device(driver, NULL, 
				&driver_devices_list_head,
				 &iccom_sysfs_add_device_to_list);
	if(ret < 0) {
		iccom_err("Failed to unregister devices from driver %s.", driver->name);
		list_for_each_entry_safe(driver_device_list_entry, tmp,
				&driver_devices_list_head, list) {
		list_del(&driver_device_list_entry->list);
		kfree(driver_device_list_entry);
		}
		return;
	} 
	
	list_for_each_entry_safe(driver_device_list_entry, tmp,
				&driver_devices_list_head, list) {
		platform_device_unregister(
			to_platform_device(driver_device_list_entry->dev));
		list_del(&driver_device_list_entry->list);
		kfree(driver_device_list_entry);
	}
}

// Initializes the sysfs channels list. This list
// shall have all channels (holding the iccom messages
// received from transport) for a particular iccom instance
//
// @iccom {valid prt} iccom_dev pointer
void __iccom_test_sysfs_initialize_ch_list(struct iccom_dev *iccom)
{
	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return;
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return;
	}

	INIT_LIST_HEAD(&iccom->p->sysfs_test_ch_head);
}

// Initializes the sysfs channel msgs list which shall
// hold all the iccom messages associated with a specific
// sysfs channel
//
// @ch_entry {valid prt} sysfs channel entry
void __iccom_test_sysfs_init_ch_msgs_list(
		struct iccom_test_sysfs_channel * ch_entry)
{
	INIT_LIST_HEAD(&ch_entry->sysfs_ch_msgs_head);
}

// Destroys an iccom message stored in a specific
// sysfs channel
//
// @ch_msg_entry {valid prt} sysfs channel msg entry
void iccom_test_sysfs_ch_msg_del_entry(
		struct iccom_test_sysfs_channel_msg *ch_msg_entry)
{
	if (IS_ERR_OR_NULL(ch_msg_entry)) {
		return;
	}
	if (!IS_ERR_OR_NULL(ch_msg_entry->msg)) {
		iccom_test_sysfs_ch_msg_free(ch_msg_entry->msg);
	}
	list_del(&ch_msg_entry->list);
}

// Destroy a sysfs channel and all its containing
// iccom messages stored for the specific sysfs channel
//
// @ch_entry {valid prt} sysfs channel entry
void iccom_test_sysfs_ch_del_entry(struct iccom_test_sysfs_channel *ch_entry)
{
	struct iccom_test_sysfs_channel_msg *ch_msg_entry, *tmp;

	if (IS_ERR_OR_NULL(ch_entry)) {
		return;
	}
	ch_entry->ch_id = -1;
	ch_entry->number_of_msgs = 0;

	/* Destroy all msgs from a sysfs channel*/
	list_for_each_entry_safe(ch_msg_entry, tmp,
			&ch_entry->sysfs_ch_msgs_head, list) {
		iccom_test_sysfs_ch_msg_del_entry(ch_msg_entry);
	}
	
	list_del(&ch_entry->list);
}

// Destroy all sysfs channels and their iccom
// messages associated with a specific iccom instance.
// The sysfs channels list shall be locked
// whenever there is a userspace access. 
// - When we store a new message in a sysfs
//   channel for later usage by the user space
// - When userspace reads a message from a sysfs
//   channel
// - When userspce creates/deletes a sysfs channel
//
// @iccom {valid prt} iccom_dev pointer for device
void iccom_test_sysfs_ch_del(struct iccom_dev *iccom)
{
	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return;
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return;
	}

	struct iccom_test_sysfs_channel *ch_entry, *tmp;
	
	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_for_each_entry_safe(ch_entry, tmp,
				&iccom->p->sysfs_test_ch_head , list) {
		iccom_test_sysfs_ch_del_entry(ch_entry);
	}
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);
}

// Routine for extracting an iccom message
// from a specific sysfs channel and remove it from
// the list for userspace usage
//
// @ch_entry {valid prt} channel where the message
// is stored
// @buf__out {ptr valid} pointer where data shall be written to
// @data_size {valid prt} size of the output data that was written
ssize_t iccom_test_sysfs_ch_pop_msg(
		struct iccom_test_sysfs_channel *ch_entry, char * buf__out,
		size_t buf_size)
{
	struct iccom_test_sysfs_channel_msg *ch_msg_entry, *tmp;
	list_for_each_entry_safe_reverse(ch_msg_entry, tmp,
				&ch_entry->sysfs_ch_msgs_head, list) {
		ssize_t length = ch_msg_entry->msg->length;
		if(length > buf_size) {
			iccom_err("Sysfs channel %d message is bigger than the buffer", ch_entry->ch_id);
			return -EINVAL;
		}
		memcpy(buf__out, ch_msg_entry->msg->data, length);
		ch_entry->number_of_msgs--;
		iccom_test_sysfs_ch_msg_del_entry(ch_msg_entry);
		
		return length;
	}

	return -EIO;
}

// Routine to retrieve a sysfs channel iccom message
// and provide it to userspace.
// The sysfs channels list shall be locked
// whenever there is a userspace access. 
// - When we store a new message in a sysfs
//   channel for later usage by the user space
// - When userspace reads a message from a sysfs
//   channel
// - When userspce creates/deletes a sysfs channel
//
// @iccom {valid prt} iccom_dev pointer
// @ch_id {number} ICCom logical channel ID
// @buf__out {valid prt} where the data shall be copied to
// @data_size {valid prt} size of data copied
ssize_t iccom_test_sysfs_ch_pop_msg_by_ch_id(
		struct iccom_dev *iccom, unsigned int ch_id,
		char * buf__out, size_t buf_size)
{
	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return -EFAULT;
	}

	struct iccom_test_sysfs_channel *cursor, *tmp;

	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_for_each_entry_safe(cursor, tmp,
				&iccom->p->sysfs_test_ch_head , list) {
		if (cursor->ch_id == ch_id) {
			ssize_t result = iccom_test_sysfs_ch_pop_msg(
						cursor, buf__out, buf_size);
			mutex_unlock(&iccom->p->sysfs_test_ch_lock);
			return result;
		}
	}
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);

	iccom_err("Sysfs channel not found");
	return -EINVAL;
}

// Add a sysfs channel for an ICCom device.
// The sysfs channels list shall be locked
// whenever there is a userspace access. 
// - When we store a new message in a sysfs
//   channel for later usage by the user space
// - When userspace reads a message from a sysfs
//   channel
// - When userspce creates/deletes a sysfs channel
//
// @iccom {valid prt} iccom_dev pointer
// @ch_id {number} ICCom logical channel ID
//
// RETURNS:
//      0: ok
//     <0: errors
ssize_t iccom_test_sysfs_ch_add_by_iccom(
		struct iccom_dev *iccom, unsigned int ch_id)
{
	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return -EFAULT;
	}

	struct iccom_test_sysfs_channel * iccom_ch_entry = NULL;

	if (iccom_test_sysfs_is_ch_present(iccom, ch_id) == true) {
		return -EINVAL;
	}

	iccom_ch_entry = kzalloc(sizeof(struct iccom_test_sysfs_channel),GFP_KERNEL);

	if (IS_ERR_OR_NULL(iccom_ch_entry)) {
		iccom_err("No memory to allocate sysfs channel entry.");
		return -ENOMEM;
	}

	iccom_ch_entry->ch_id = ch_id;
	iccom_ch_entry->number_of_msgs = 0;
	__iccom_test_sysfs_init_ch_msgs_list(iccom_ch_entry);
	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_add(&iccom_ch_entry->list, &iccom->p->sysfs_test_ch_head );
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);

	return 0;
}

// Destroy a sysfs channel for an ICCom device
// The sysfs channels list shall be locked
// whenever there is a userspace access. 
// - When we store a new message in a sysfs
//   channel for later usage by the user space
// - When userspace reads a message from a sysfs
//   channel
// - When userspce creates/deletes a sysfs channel
//
// @iccom {valid prt} iccom_dev pointer
// @ch_id {number} ICCom logical channel ID
//
//RETURNS
// 0: channel exists and deleted
// -EINVAL: channel does not exist
ssize_t iccom_test_sysfs_ch_del_by_iccom(
		struct iccom_dev *iccom, unsigned int ch_id)
{
	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return -EFAULT;
	}

	struct iccom_test_sysfs_channel *ch_entry, *tmp;
	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_for_each_entry_safe(ch_entry, tmp, &iccom->p->sysfs_test_ch_head , list) {
		if (ch_entry->ch_id == ch_id) {
			iccom_test_sysfs_ch_del_entry(ch_entry);
			mutex_unlock(&iccom->p->sysfs_test_ch_lock);
			iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
				, "sniffer destroyed for ch: %d"
				, ch_id);
			return 0;
		}
	}
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);

	return -EINVAL;
}

// Trim a sysfs input buffer comming from userspace
// with might have unwanted characters
//
// @buf {valid prt} buffer to be trimmed
// @size {number} size of data valid without 0-terminator
//
//RETURNS
// count: size of valid data within the array
size_t iccom_test_sysfs_trim_buffer(char *buf, size_t size)
{
	size_t count = size;
	while (count > 0 && ((buf[count - 1] == '\n') || (buf[count - 1] == ' ')
			|| (buf[count - 1] == '\t') || (buf[count - 1] == 0))) {
		buf[count-- - 1] = 0;
	}
	return count;
}

// ICCom version (show) class attribute used to know the git revision
// that ICCom is at the moment
//
// @class {valid ptr} iccom class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to write output to user space
//
// RETURNS:
//      0: no data to be displayed
//      > 0: size of data to be showed in user space
static ssize_t version_show(
		struct class *class, struct class_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s", ICCOM_VERSION);
}

static CLASS_ATTR_RO(version);

// Sysfs class method for creating iccom instances 
// trough the usage of sysfs internal mechanisms
//
// @class {valid ptr} iccom class
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to read input from user space
// @count {number} size of buffer from user space
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t create_iccom_store(
		struct class *class, struct class_attribute *attr,
		const char *buf, size_t count)
{
	// Allocate one unused ID
	int device_id = ida_alloc(&iccom_dev_id, GFP_KERNEL);

	if (device_id < 0) {
		iccom_err("Could not allocate a new unused ID");
		return -EINVAL;
	}

	struct platform_device * new_pdev = 
		platform_device_register_simple("iccom",device_id,NULL,0);

	if (IS_ERR_OR_NULL(new_pdev)) {
		iccom_err("Could not register the device iccom.%d",device_id);
		return -EFAULT;
	}

	return count;
}

static CLASS_ATTR_WO(create_iccom);

// Sysfs class method for deleting iccom instances 
// trough the usage of sysfs internal mechanisms
//
// @class {valid ptr} iccom class
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to read input from user space
// @count {number} size of buffer from user space
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t delete_iccom_store(
		struct class *class, struct class_attribute *attr,
		const char *buf, size_t count)
{
	if (count >= PAGE_SIZE) {
		iccom_warning("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	// Sysfs store procedure has data from userspace with length equal
	// to count. The next byte after the data sent (count + 1) will always
	// be a 0-terminator char. This is the default behavior of sysfs.
	size_t total_count = count + 1;
	char *device_name = (char *) kzalloc(total_count, GFP_KERNEL);
	
	if (IS_ERR_OR_NULL(device_name)) {
		return -ENOMEM;
	}
	
	memcpy(device_name, buf, total_count);

	// NOTE: count is a length without the last 0-terminator char
	if (device_name[count] != 0) {
		iccom_warning("NON-null-terminated string is provided by sysfs.");
		goto clean_up_device_name_buffer_memory;
	}

	(void)iccom_test_sysfs_trim_buffer(device_name, count);

	struct device *iccom_device = 
		bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);

	if (IS_ERR_OR_NULL(iccom_device)) {
		iccom_err("Iccom device is null.");
		return -EFAULT;
	}

	platform_device_unregister(to_platform_device(iccom_device));

	return count;

clean_up_device_name_buffer_memory:
	kfree(device_name);
	return -EFAULT;
}

static CLASS_ATTR_WO(delete_iccom);

// List of all ICCom class attributes
//
// @class_attr_version sysfs file for checking
//                     the version of ICCom
// @class_attr_create_iccom sysfs file for creating
//                              iccom devices
// @class_attr_delete_iccom sysfs file for deleting
//                              iccom devices
static struct attribute *iccom_class_attrs[] = {
	&class_attr_version.attr,
	&class_attr_create_iccom.attr,
	&class_attr_delete_iccom.attr,
	NULL
};

ATTRIBUTE_GROUPS(iccom_class);

// Method designs to tell in userspace wheter the
// transport is already associated to the iccom device
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to user space
//
// RETURNS:
//      0: no data to be displayed
//      > 0: size of data to be showed in user space
static ssize_t transport_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);
	
	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return scnprintf(buf, PAGE_SIZE,
			"%s", "No transport device associated yet - iccom is null");
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return scnprintf(buf, PAGE_SIZE,
			"%s", "No transport device associated yet - iccom private data is null");
	}

	if (IS_ERR_OR_NULL(iccom->xfer_device)) {
		iccom_err("Iccom device data xfer_device is null.");
		return scnprintf(buf, PAGE_SIZE, 
			"%s", "No transport device associated yet - iccxfer device is null");
	}

	return scnprintf(buf, PAGE_SIZE, "%s", "Transport device associated");
}

// Method to allow associating a transport to
// an iccom device and initialize the iccom device
// via iccom_init_binded
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to read input from user space
// @count {number} size of buffer from user space
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t transport_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct iccom_dev *iccom = 
				(struct iccom_dev *)dev_get_drvdata(dev);
	struct iccom_test_transport_dev * iccom_test_transport = NULL;
	struct device *iccom_test_transport_device = NULL;
	int ret;

	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	if (!IS_ERR_OR_NULL(iccom->xfer_device)) {
		iccom_err("Transport test device is already associated.");
		return -EINVAL;
	}

	if (count >= PAGE_SIZE) {
		iccom_warning("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	// Sysfs store procedure has data from userspace with length equal
	// to count. The next byte after the data sent (count + 1) will always
	// be a 0-terminator char. This is the default behavior of sysfs.
	size_t total_count = count + 1;
	char *device_name = (char *) kzalloc(total_count, GFP_KERNEL);
	
	if (IS_ERR_OR_NULL(device_name)) {
		return -ENOMEM;
	}
	
	memcpy(device_name, buf, total_count);

	// NOTE: count is a length without the last 0-terminator char
	if (device_name[count] != 0) {
		iccom_warning("NON-null-terminated string is provided by sysfs.");
		goto clean_up_device_name_buffer_memory;
	}

	(void)iccom_test_sysfs_trim_buffer(device_name, count);

	iccom_test_transport_device = 
		bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);

	if (IS_ERR_OR_NULL(iccom_test_transport_device)) {
		iccom_err("Transport test device is null.");
		return -EFAULT;
	}

	iccom_test_transport = (struct iccom_test_transport_dev *)
					dev_get_drvdata(iccom_test_transport_device);

	if (IS_ERR_OR_NULL(iccom_test_transport)) {
		iccom_err("Transport test device data is null.");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(iccom_test_transport->duplex_iface)) {
		iccom_err("Transport test device data iface is null.");
		return -EFAULT;
	}

	ret = iccom_init_binded(
			iccom, iccom_test_transport->duplex_iface,
			(void*)iccom_test_transport_device);

	if (ret != 0) {
		iccom_err("Iccom Init failed with the provided device.");
		return -EINVAL;
	}

	__iccom_test_sysfs_initialize_ch_list(iccom);

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom Private data is null");
		return -EFAULT;
	}
		
	// Create sysfs channels root directory to hold sysfs channels
	iccom->p->channels_root = kobject_create_and_add(
						ICCOM_TEST_SYSFS_CHANNEL_ROOT,
						&(dev->kobj));

	if (IS_ERR_OR_NULL(iccom->p->channels_root)) {
		iccom_err("Sysfs channel failed to create channel root");
	}

	iccom_warning("Iccom device binding to transport device was sucessful");
	return count;

clean_up_device_name_buffer_memory:
	kfree(device_name);
	return -EFAULT;
}

static DEVICE_ATTR_RW(transport);

// Iccom device statistics (show) attribute for showing the
// statistics data of a iccom device
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to user space
//
// RETURNS:
//      0: no data to be displayed
//    > 0: size of data to be showed in user space
static ssize_t statistics_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return scnprintf(buf, PAGE_SIZE, "%s", "Statistics error.");
	}

	const struct iccom_dev_statistics * const stats = 
						&iccom->p->statistics;

	size_t len = (size_t)scnprintf(buf, PAGE_SIZE,
			"transport_layer: xfers done:  %llu\n"
			"transport_layer: bytes xfered:  %llu\n"
			"packages: xfered total:  %llu\n"
			"packages: sent ok:  %llu\n"
			"packages: received ok:  %llu\n"
			"packages: sent fail (total):  %llu\n"
			"packages: received fail (total):  %llu\n"
			"packages:     received corrupted:  %llu\n"
			"packages:     received duplicated:  %llu\n"
			"packages:     detailed parsing failed:  %llu\n"
			"packages: in tx queue:  %lu\n"
			"packets: received ok:  %llu\n"
			"messages: received ok:  %llu\n"
			"messages: ready rx:  %lu\n"
			"bandwidth: consumer bytes received:\t%llu\n"
			"\n"
			"Note: this is only general statistical/monitoring"
			" info and is not expected to be used in precise"
			" measurements due to atomic selfconsistency"
			" maintenance would put overhead in the driver.\n"
			,stats->transport_layer_xfers_done_count
			,stats->raw_bytes_xfered_via_transport_layer
			,stats->packages_xfered
			,stats->packages_sent_ok
			,stats->packages_received_ok
			,stats->packages_xfered - stats->packages_sent_ok
			,stats->packages_xfered - stats->packages_received_ok
			,stats->packages_bad_data_received
			,stats->packages_duplicated_received
			,stats->packages_parsing_failed
			,stats->packages_in_tx_queue
			,stats->packets_received_ok
			,stats->messages_received_ok
			,stats->messages_ready_in_storage
			,stats->total_consumers_bytes_received_ok);

	return len;
}

static DEVICE_ATTR_RO(statistics);

// Channel (show) attribute, for reading data
// written to the channel
//
// @kobj {valid ptr} channel kobject instance
// @attr {valid ptr} kobject attribute properties
// @buf {valid ptr} buffer to read input from user space
//
// RETURNS:
//      0: no data to be displayed
//    > 0: size of data to be showed in user space
//    < 0: errors
static ssize_t channel_show(
		struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	unsigned ch_id = 0;

	if (IS_ERR_OR_NULL(kobj->parent)) {
		iccom_err("Sysfs channel parent is null.");
		return -EFAULT;
	}

	struct device *iccom_dev = kobj_to_dev(kobj->parent);

	if (IS_ERR_OR_NULL(iccom_dev)) {
		iccom_err("Sysfs channel iccom device is null.");
		return -EFAULT;
	}

	struct iccom_dev *iccom = (struct iccom_dev*)dev_get_drvdata(iccom_dev);

	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	if (kstrtouint(attr->attr.name, 10, &ch_id) != 0) {
		iccom_err("Sysfs channel id is not an unsigned int.");
		return -EINVAL;
	}

	ssize_t data_size = iccom_test_sysfs_ch_pop_msg_by_ch_id(iccom, ch_id, buf, PAGE_SIZE);

	if(data_size < 0) {
		iccom_err("Sysfs Channel msg poping failed with errors");
	}

	return data_size;
}

// Channel (store) attribute, for writing data
// to a channel
//
// @kobj {valid ptr} channel kobject instance
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from user space
// @count {number} size of buffer from user space
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t channel_store(
		struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned ch_id = 0;

	if (kstrtouint(attr->attr.name, 10, &ch_id) != 0) {
		iccom_err("Sysfs channel id is not an unsigned int.");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(kobj->parent)) {
		iccom_err("Sysfs channel parent is null.");
		return -EFAULT;
	}

	struct device *iccom_dev = kobj_to_dev(kobj->parent);

	if (IS_ERR_OR_NULL(iccom_dev)) {
		iccom_err("Sysfs channel iccom device is null.");
		return -EFAULT;
	}

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(iccom_dev);

	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	int ret = iccom_post_message(
		iccom,
		buf,
		(const size_t)count,
		ch_id,
		1);

	if (ret < 0) {
		iccom_err("Failed to post message for channel %d with result %d",
				ch_id, ret);
	}

	return count;
}

// Channel control (store) attribute, for creating or
// destroying channel instances
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from user space
// @count {number} size of buffer from user space
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t channels_ctl_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	char option;
	ssize_t sysfs_result;
	unsigned int ch_id;
	static char channel_name[ICCOM_TEST_SYSFS_CH_CMD_MAX_CHAR+1];

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(iccom->p)) {
		iccom_err("Iccom private data is null");
		return -EFAULT;
	}
	
	if (IS_ERR_OR_NULL(iccom->p->channels_root)) {
			iccom_err("Sysfs channel does not have a channel root");
			return -EFAULT;
	}

	if (2 != sscanf(buf,"%c%u", &option, &ch_id)) {
		iccom_err("Sysfs channel input shall have a character and a unsigned int.");
		return -EINVAL;
	}

	scnprintf(channel_name, sizeof(channel_name)/sizeof(char), "%d", ch_id);

	struct kernfs_node *knode = sysfs_get_dirent(iccom->p->channels_root->sd, channel_name);

	static struct kobj_attribute channel_attr = {
		.attr = { .name = channel_name, .mode = ICCOM_TEST_SYSFS_CHANNEL_PERMISSIONS },
		.show = channel_show,
		.store = channel_store,
	};

	if (option == ICCOM_SYSFS_CREATE_CHANNEL) {
		if (!IS_ERR_OR_NULL(knode)) {
			iccom_err("Sysfs channel already exists");
			return -EINVAL;
		}
		if(sysfs_create_file(iccom->p->channels_root,
						&channel_attr.attr) != 0) {
			iccom_err("Sysfs channel file creation failed");
			return -EINVAL;
		}

		sysfs_result = iccom_test_sysfs_ch_add_by_iccom(iccom, ch_id);
		if (sysfs_result != 0) {
			iccom_err("Sysfs channel list add failed");
			sysfs_remove_file(iccom->p->channels_root, &channel_attr.attr);
			return sysfs_result;
		}
	} else if (option == ICCOM_SYSFS_DELETE_CHANNEL) {
		if (IS_ERR_OR_NULL(knode)) {
			iccom_err("Sysfs channel does not exist");
			return -EFAULT;
		}
		sysfs_remove_file(iccom->p->channels_root, &channel_attr.attr);
		
		sysfs_result = iccom_test_sysfs_ch_del_by_iccom(iccom, ch_id);
		if (sysfs_result != 0) {
			iccom_err("Sysfs channel list removal failed");
			return sysfs_result;
		}
	} else {
		iccom_err("Sysfs channel operation shall be either a c or d");
		return -EINVAL;
	}

	return count;
}

static DEVICE_ATTR_WO(channels_ctl);

// List of all ICCom device attributes
//
// @dev_attr_transport the ICCom transport file
// @dev_attr_statistics the ICCom statistics file
// @dev_attr_channels_ctl the ICCOM channels file
static struct attribute *iccom_dev_attrs[] = {
	&dev_attr_transport.attr,
	&dev_attr_statistics.attr,
	&dev_attr_channels_ctl.attr,
	NULL,
};

ATTRIBUTE_GROUPS(iccom_dev);

// The ICCom class definition
//
// @name class name
// @owner the module owner
// @class_groups group holding all the attributes
static struct class iccom_class = {
	.name = "iccom",
	.owner = THIS_MODULE,
	.class_groups = iccom_class_groups
};

// Registers the ICCom class for sysfs
//
// RETURNS:
//      0: ok
//      !0: nok
int iccom_test_sysfs_iccom_class_register(void) {
	return class_register(&iccom_class);
};

// Unregisters the ICCom class for sysfs
void iccom_test_sysfs_iccom_class_unregister(void) {
	class_unregister(&iccom_class);
};

// Iccom device probe which initializes the device
// and allocates the iccom_dev
//
// @pdev {valid ptr} iccom device
//
// RETURNS:
//      0: ok
//     <0: errors
static int iccom_probe(struct platform_device *pdev) {
	struct iccom_dev *iccom;

	if (IS_ERR_OR_NULL(pdev)) {
		iccom_err("Probing a Iccom Device failed - pdev NULL pointer!");
		return -EINVAL;
	}

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
			"Probing a Iccom Device with id: %d", pdev->id);

	iccom = (struct iccom_dev *)
				kmalloc(sizeof(struct iccom_dev), GFP_KERNEL);

	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom device data is null. Failed to allocate the memory.");
		return -ENOMEM;
	}

	iccom->xfer_device = NULL;
	iccom->p = NULL;

	dev_set_drvdata(&pdev->dev, iccom);

	return 0;
};

// Iccom device remove which deinitialize the device
// and frees the iccom_dev
//
// @pdev {valid ptr} iccom device
//
// RETURNS:
//      0: ok
//     <0: errors
static int iccom_remove(struct platform_device *pdev) {

	struct iccom_dev *iccom;

	if (IS_ERR_OR_NULL(pdev)) {
		iccom_err("Iccom pdev is null.");
		return -EFAULT;
	}

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
			"Removing a Iccom Device with id: %d", pdev->id);

	iccom = (struct iccom_dev *)dev_get_drvdata(&pdev->dev);

	if (IS_ERR_OR_NULL(iccom)) {
		iccom_err("Iccom is null");
		return -EFAULT;
	}

	iccom_test_sysfs_ch_del(iccom);
	if (!IS_ERR_OR_NULL(iccom->p) && !IS_ERR_OR_NULL(iccom->p->channels_root)) {
		kobject_put(iccom->p->channels_root);
		iccom->p->channels_root = NULL;
	}
	iccom_close_binded(iccom);
	
	kfree(iccom);
	iccom = NULL;

	return 0;
};

// The ICCom driver compatible definition
//
// @compatible name of compatible driver
struct of_device_id iccom_driver_id[] = {
	{
		.compatible = "iccom",
	}
};

// The ICCom driver definition
//
// @probe probe device function
// @remove remove device function
// @driver structure driver definition
// @driver::owner the module owner
// @driver::name name of driver
// @driver::of_match_table compatible driver devices
// @driver::dev_groups devices groups with all attributes
struct platform_driver iccom_driver = {
	.probe = iccom_probe,
	.remove = iccom_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "iccom",
		.of_match_table = iccom_driver_id,
		.dev_groups = iccom_dev_groups
	}
};

/*------------------- FULL DUPLEX INTERFACE AUXILIAR ------------------------*/

// Initializes the xfer data to the default empty state
//
// @xfer {valid ptr} transfer structure
void xfer_init(struct full_duplex_xfer *xfer) {
	memset(xfer, 0, sizeof(struct full_duplex_xfer));
}

// Frees all owned by @xfer data
//
// @xfer {valid ptr} transfer structure
void xfer_free(struct full_duplex_xfer *xfer) {
	if (IS_ERR_OR_NULL(xfer)) {
		return;
	}
	if (!IS_ERR_OR_NULL(xfer->data_tx)) {
		kfree(xfer->data_tx);
	}
	if (!IS_ERR_OR_NULL(xfer->data_rx_buf)) {
		kfree(xfer->data_rx_buf);
	}
	memset(xfer, 0, sizeof(struct full_duplex_xfer));
}

// Write the data received from user space into the xfer
// rx_data_buf and allocates the necessary space for it
//
// @xfer_dev {valid ptr} xfer device
// @data_transport_to_iccom {array} data from userspace to be copied
// @data_transport_to_iccom_size {number} size of data to be copied
//
// RETURNS:
//      0: ok
//      -EINVAL: xfer is null pointer
//      -ENOMEM: no memory to allocate
int iccom_sysfs_test_update_wire_data(
		struct xfer_device_data *xfer_dev,
		char data_transport_to_iccom[],
		size_t data_transport_to_iccom_size)
{
	if (IS_ERR_OR_NULL(&xfer_dev->xfer)) {
		return -EINVAL;
	}

	if (!IS_ERR_OR_NULL(xfer_dev->xfer.data_rx_buf)) {
		kfree(xfer_dev->xfer.data_rx_buf);
	}

	if (!IS_ERR_OR_NULL(data_transport_to_iccom) &&
		data_transport_to_iccom_size) {
		xfer_dev->xfer.size_bytes = data_transport_to_iccom_size;
		xfer_dev->xfer.data_rx_buf =
			kmalloc(xfer_dev->xfer.size_bytes, GFP_KERNEL);
		if (!xfer_dev->xfer.data_rx_buf) {
			return -ENOMEM;
		}
		memcpy(xfer_dev->xfer.data_rx_buf, data_transport_to_iccom,
			xfer_dev->xfer.size_bytes);
	}

	// NOTE: the actual xfer will happen on-read (wire data show)
	// 	to keep the US in sync. The total workflow goes:
	// 	* US writes to wire
	// 		* this data gets saved in current xfer
	// 		* transport dev remembers that the wire data is provided
	// 	* US reads from wire
	// 		* transport dev gets read request
	// 		* if no write was provided before - reject to read. Else:
	// 		* the current xfer wire data is provided to US
	// 		* transport dev confirms xfer_done(...) to ICCom
	// 		* ICCom updates the current xfer with new data
	xfer_dev->got_us_data = true;

	return 0;
}

// Deep copy of src xfer to a dst xfer
// with memory allocation and pointers checks
//
// @src {valid ptr} source xfer
// @src {valid ptr} destination xfer
//
// RETURNS:
//      0: ok
//     <0: errors
int deep_xfer_copy(struct full_duplex_xfer *src, struct full_duplex_xfer *dst) {
	if (IS_ERR_OR_NULL(src) || IS_ERR_OR_NULL(dst)) {
		return -EINVAL;
	}

	xfer_free(dst);

	dst->size_bytes = src->size_bytes;

	if (!IS_ERR_OR_NULL(src->data_tx) && src->size_bytes) {
		dst->data_tx = kmalloc(dst->size_bytes, GFP_KERNEL);
		if (IS_ERR_OR_NULL(dst->data_tx)) {
			return -ENOMEM;
		}
		memcpy(dst->data_tx, src->data_tx, dst->size_bytes);
	}

	if (!IS_ERR_OR_NULL(src->data_rx_buf) && src->size_bytes) {
		dst->data_rx_buf = kmalloc(dst->size_bytes, GFP_KERNEL);
		if (IS_ERR_OR_NULL(dst->data_rx_buf)) {
			kfree(dst->data_tx);
			dst->data_tx = NULL;
			return -ENOMEM;
		}
		memcpy(dst->data_rx_buf, src->data_rx_buf
			, dst->size_bytes);
	}

	dst->xfers_counter = src->xfers_counter;
	dst->id = src->id;
	dst->consumer_data = src->consumer_data;
	dst->done_callback = src->done_callback;
	return 0;
}

// Iterates on the next xfer id for transmission
//
// @xfer_dev {valid ptr} xfer device
//
// RETURNS:
//      >0: id of the next xfer
int iterate_to_next_xfer_id(struct xfer_device_data *xfer_dev) {
	int res = xfer_dev->next_xfer_id;

	xfer_dev->next_xfer_id++;

	if (xfer_dev->next_xfer_id < 0) {
		xfer_dev->next_xfer_id = 1;
	}
	return res;
}

// Accepts the data from iccom, copies its original
// data into two xfers and iterates on the next
// xfer id to be transmitted
//
// @xfer_dev {valid ptr} xfer device
// @xfer {valid ptr} received xfer from iccom
//
// RETURNS:
//      0: ok
//     <0: errors
int accept_data(
		struct xfer_device_data* xfer_dev,
		struct __kernel full_duplex_xfer *xfer)
{
	// Copy xfer to dev xfer as is. In later
	// stage override the data_rx_buf in iccom_sysfs_test_update_wire_data
	int res = deep_xfer_copy(xfer, &xfer_dev->xfer);
	if (res < 0) {
		return res;
	}

	xfer_dev->xfer.id = iterate_to_next_xfer_id(xfer_dev);

	return xfer_dev->xfer.id;
}

// Function to trigger an exchange of data between
// iccom and transport with validation of data
//
// @xfer_dev {valid ptr} xfer device
__maybe_unused
static void iccom_transport_exchange_data(struct xfer_device_data *xfer_dev)
{
	if (IS_ERR_OR_NULL(xfer_dev->xfer.done_callback)) {
		return;
	}

	bool start_immediately = false;
	struct full_duplex_xfer *next_xfer
			= xfer_dev->xfer.done_callback(
				&xfer_dev->xfer,
				xfer_dev->next_xfer_id,
				&start_immediately,
				xfer_dev->xfer.consumer_data);

	// for a new xfer US must provide a new data, so dropping the flag
	xfer_dev->got_us_data = false;

	if (IS_ERR_OR_NULL(next_xfer)) {
		return;
	}

	accept_data(xfer_dev, next_xfer);
}

/*------------------- FULL DUPLEX INTERFACE API ----------------------------*/

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to start exchange of data
// between ICCom and Transport. The xfer data is always
// null as no actual data is expected to be exchanged
// in this function.
//
// @device {valid ptr} transport device
// @xfer {valid ptr} xfer data
// @force_size_change {bool} force size variable
//
// RETURNS:
//      0: ok
//     <0: errors
__maybe_unused
int data_xchange(
		void __kernel *device , struct __kernel full_duplex_xfer *xfer,
		bool force_size_change)
{
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE_PRIVATE("", return -EFAULT);
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE(device, return -ENODEV);
	ICCOM_TEST_TRANSPORT_DEV_TO_XFER_DEV_DATA;
	ICCOM_TEST_TRANSPORT_XFER_DEV_ON_FINISH(return -EHOSTDOWN);
	return 0;
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to update the default data
// that will be exchanged
//
// @device {valid ptr} transport device
// @xfer {valid ptr} xfer data
// @force_size_change {bool} force size variable
//
// RETURNS:
//      0: ok
//      <0: error happened
__maybe_unused
int default_data_update(
                void __kernel *device, struct full_duplex_xfer *xfer,
                bool force_size_change)
{
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE_PRIVATE("", return -EFAULT);
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE(device, return -ENODEV);
        ICCOM_TEST_TRANSPORT_DEV_TO_XFER_DEV_DATA;
        return accept_data(xfer_dev_data, xfer);
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to know whether xfer
// device is running or not
//
// @device {valid ptr} transport device
//
// RETURNS:
//      true: running
//      false: not running
__maybe_unused
bool is_running(void __kernel *device) {
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE_PRIVATE("", return false);
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE(device, return false);
	ICCOM_TEST_TRANSPORT_DEV_TO_XFER_DEV_DATA;
	ICCOM_TEST_TRANSPORT_XFER_DEV_ON_FINISH(return false);
	return xfer_dev_data->running;
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to initialize the
// transport iface and copy the default xfer provided by ICCom
//
// @device {valid ptr} transport device
// @default_xfer {valid ptr} default xfer
//
// RETURNS:
//      0: ok
//     <0: errors
__maybe_unused
int init(void __kernel *device, struct full_duplex_xfer *default_xfer) {
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE_PRIVATE("", return -EFAULT);
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE(device, return -ENODEV);
	ICCOM_TEST_TRANSPORT_DEV_TO_XFER_DEV_DATA;
	xfer_init(&xfer_dev_data->xfer);
	xfer_dev_data->next_xfer_id = 1;
	xfer_dev_data->finishing = false;
	xfer_dev_data->running = true;
	xfer_dev_data->got_us_data = false;
	return accept_data(xfer_dev_data, default_xfer);
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to close the
// transport iface and free the memory
//
// @device {valid ptr} transport device
//
// RETURNS:
//      0: ok
//     <0: errors
__maybe_unused
int close(void __kernel *device) {
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE_PRIVATE("", return -EFAULT);
	ICCOM_TEST_TRANSPORT_CHECK_DEVICE(device, return -ENODEV);
	ICCOM_TEST_TRANSPORT_DEV_TO_XFER_DEV_DATA;
	xfer_dev_data->finishing = true;
	xfer_dev_data->running = false;
	xfer_free(&xfer_dev_data->xfer);
	return 0;
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to reset the iface
// which closes and inits again the device
//
// @device {valid ptr} transport device
// @default_xfer {valid ptr} default xfer
//
// RETURNS:
//      0: ok
//     <0: errors
__maybe_unused
int reset(void __kernel *device, struct full_duplex_xfer *default_xfer) {
	close(device);
	return init(device, default_xfer);
}

/*------------------- ICCOM TEST TRANSPORT DEVICE ----------------------------*/

// Parse the hex string into a byte array.
//
// String must be a null-terminated string of 2-digit numbers (hex digits):
// Example:
// 		11030AFFDDCD\0
// each 2-digit number will be converted to the byte value,
// and the result will be written to the
//
// NOTE: if parsing failed somewhere in the middle, then result is still
// 	an error (so either all is fine or all failed, not inbetween)
//
// @str {valid ptr} buffer, containing the input null-terminated string
// @str_len {number} length of string given by @str (in bytes)
// 	**NOT** including the 0-terminator
//
// 	NOTE: if the @str_len is 0, then no parsing is done at all
// 		function just returns.
//
// @bytearray__out {array} array to copy the data to
// @out_size {>=0} size of the @bytearray__out in bytes
//
// RETURNS:
//      >=0: the size of the data written to @bytearray__out
//      <0: negated error code
ssize_t iccom_convert_hex_str_to_byte_array(const char *str, const size_t str_len
		, uint8_t *bytearray__out, size_t out_size)
{
    	// number of characters in the input string per one byte parsed
	#define CHARS_PER_BYTE  2

    	// to be "intelligent" we go for this check first
	if (str_len == 0) {
		return 0;
	}

	// errors block
	if (IS_ERR_OR_NULL(str)) {
		iccom_err("broken string ptr.");
		return -EINVAL;
	}
	if (str[str_len] != 0) {
		iccom_err("string does not terminate with 0.");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(bytearray__out)) {
		iccom_err("bad output array ptr.");
		return -EINVAL;
	}
	if (str_len % CHARS_PER_BYTE != 0) {
		iccom_err("string"
			" must contain %d-multiple number of hex digits"
			" + 0-terminator only. String provided (in -- quotes):"
			" --%s--"
			, CHARS_PER_BYTE, str);
		return -EINVAL;
	}
	if (out_size < str_len / CHARS_PER_BYTE) {
		iccom_err("receiver array"
			" is smaller (%zu) than needed (%zu)."
			, out_size, str_len / CHARS_PER_BYTE);
		return -EINVAL;
	}

	char tmp[CHARS_PER_BYTE + 1];
	tmp[CHARS_PER_BYTE] = 0;

	int w_idx = 0;
	for (int i = 0; i <= str_len - CHARS_PER_BYTE; i += CHARS_PER_BYTE) {
		memcpy(tmp, str + i, CHARS_PER_BYTE);

		unsigned int val;
		int res = kstrtouint(tmp, 16, &val);

		if (res != 0) {
			iccom_err("failed at part: %s", tmp);
			return val;
		}
		if (val > 0xFF) {
			iccom_err("failed, part overflow: %s", tmp);
			return val;
		}
		*(bytearray__out + w_idx++) = (uint8_t)val;
	}

	#undef CHARS_PER_BYTE

	return w_idx;
}

// Encode the iccom data sent to transport by
// converting each number (one byte) into four bytes (in char format 0xXX)
// and write the data in a new output table
//
// @buf__out {valid ptr} buffer to copy the data to
// @buffer_size {number} size of buffer data
// @data_iccom_to_transport {array} array holding the data to be copied
// @data_iccom_to_transport_size {number} size of array
ssize_t iccom_convert_byte_array_to_hex_str(
		char *buf__out, size_t buf_size,
		const uint8_t data_iccom_to_transport[],
		const size_t data_iccom_to_transport_size)
{
	ssize_t length = 0;

	/* Each byte shall be transformed into 2 hexadecimal characters */
	if(data_iccom_to_transport_size * 2 > buf_size) {
		iccom_err("Sysfs iccom to transport data is bigger than the buffer");
		return -EINVAL;
	}
	
	for(int i = 0; i < data_iccom_to_transport_size; i++)
	{
		length += scnprintf(buf__out + length,
						PAGE_SIZE - length,
						"%02x", data_iccom_to_transport[i]);
	}
	return length;
}

// Transport device R (show) attribute for checking if
// what data has been transmitted from ICCom to Transport
//
// @dev {valid ptr} Transport device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to user space
//
// RETURNS:
//      0: No data
//      > 0: size of data to be showed in user space
static ssize_t R_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	if(IS_ERR_OR_NULL(dev)) {
		iccom_err("the wire transport kernel dev not provided");
		return -EINVAL;
	}
	struct iccom_test_transport_dev * iccom_test_transport
		= (struct iccom_test_transport_dev *)dev_get_drvdata(dev);

	if(IS_ERR_OR_NULL(iccom_test_transport)) {
		iccom_err("the wire transport dev broken ptr");
		return -EFAULT;
	}

	if(IS_ERR_OR_NULL(iccom_test_transport->p)) {
		iccom_err("the wire transport dev private data broken ptr");
		return -EFAULT;
	}

	struct xfer_device_data *xfer_dev = iccom_test_transport->p->xfer_dev_data;
	if(IS_ERR_OR_NULL(xfer_dev)) {
		iccom_err("the xfer dev broken ptr");
		return -EINVAL;
	}
	if (!xfer_dev->got_us_data) {
		iccom_err("to read something you need to write something first =)");
		return -EPROTO;
	}

	ssize_t length = iccom_convert_byte_array_to_hex_str(
				buf, PAGE_SIZE, (uint8_t*)xfer_dev->xfer.data_tx,
				xfer_dev->xfer.size_bytes);
	
	if (length <= 0) {
		iccom_warning("Conversion from byte array to hex string failed");
		return -EINVAL;
	}
	

	// Do the actual xfer here
	iccom_transport_exchange_data(xfer_dev);

	return length;
}

static DEVICE_ATTR_RO(R);

// Transport device W (store) attribute for writing
// data from userspace to the transport
//
// @dev {valid ptr} Transport device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer with the data from user space
// @count {number} the @buf string length not-including the  0-terminator
// 	which is automatically appended by sysfs subsystem
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t W_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct iccom_test_transport_dev * iccom_test_transport = NULL;

	iccom_test_transport = (struct iccom_test_transport_dev *)dev_get_drvdata(dev);

	if(IS_ERR_OR_NULL(iccom_test_transport)) {
		iccom_err("the wire transport dev broken ptr");
		return -EFAULT;
	}

	if(IS_ERR_OR_NULL(iccom_test_transport->p)) {
		iccom_err("the wire transport dev private data broken ptr");
		return -EFAULT;
	}

	struct xfer_device_data *xfer_dev = iccom_test_transport->p->xfer_dev_data;
	if(IS_ERR_OR_NULL(xfer_dev)) {
		iccom_err("the xfer dev broken ptr");
		return -EINVAL;
	}

	if(IS_ERR_OR_NULL(xfer_dev)) {
		iccom_warning("Transport Device is null!");
		return -EFAULT;
	}

	if (count >= PAGE_SIZE) {
		iccom_warning("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	// Sysfs store procedure has data from userspace with length equal
	// to count. The next byte after the data sent (count + 1) will always
	// be a 0-terminator char. This is the default behavior of sysfs.
	size_t total_count = count + 1;
	char *hex_buffer = (char *) kzalloc(total_count, GFP_KERNEL);
	
	if (IS_ERR_OR_NULL(hex_buffer)) {
		return -ENOMEM;
	}
	
	memcpy(hex_buffer, buf, total_count);
	
	// NOTE: count is a length without the last 0-terminator char
	if (hex_buffer[count] != 0) {
		iccom_warning("NON-null-terminated string is provided by sysfs.");
		goto clean_up_hex_buffer_memory;
	}

	total_count = iccom_test_sysfs_trim_buffer(hex_buffer, count);
	
	char wire_data[ICCOM_DATA_XFER_SIZE_BYTES];
	ssize_t xfer_size = iccom_convert_hex_str_to_byte_array(hex_buffer, total_count,
						wire_data, sizeof(wire_data));

	#ifdef ICCOM_DEBUG
	print_hex_dump(KERN_INFO, ICCOM_LOG_PREFIX"Sim RX data: ", 0, 16
			, 1, wire_data, xfer_size, true);
	#endif

	if (xfer_size <= 0) {
		iccom_warning("transport Device Decoding failed for str: %s"
				, hex_buffer);
		goto clean_up_hex_buffer_memory;
	}

	iccom_sysfs_test_update_wire_data(xfer_dev, wire_data, xfer_size);
	kfree(hex_buffer);
	return count;

clean_up_hex_buffer_memory:
	kfree(hex_buffer);
	return -EINVAL;
}

static DEVICE_ATTR_WO(W);

// Show RW (store) attribute, for creating
// or destroying the R and W files on
// transport
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from user space
// @count {number} size of buffer from user space
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t showRW_ctl_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int result;

	if (kstrtouint(buf, 10, &result) != 0) {
		iccom_err("Value received is not an unsigned int.");
		return -EINVAL;
	}
	
	if (result > 2) {
		iccom_err("Value shall be 0 or 1 to enable/disable RW files");
		return -EINVAL;
	}

	struct kernfs_node* knode_R = sysfs_get_dirent(dev->kobj.sd,"R");
	struct kernfs_node* knode_W = sysfs_get_dirent(dev->kobj.sd,"W");

	if (result == ICCOM_SYSFS_CREATE_RW_FILES) {
		if (!IS_ERR_OR_NULL(knode_R) || !IS_ERR_OR_NULL(knode_W)) {
			iccom_err("Files already exist");
			return -EINVAL;
		}

		if (device_create_file(dev, &dev_attr_R) != 0) {
			iccom_err("Error creating files");
			return -EINVAL;
		}

		if (device_create_file(dev, &dev_attr_W) != 0) {
			device_remove_file(dev, &dev_attr_R);
			iccom_err("Error creating files");
			return -EINVAL;
		}
	} else if (result == ICCOM_SYSFS_REMOVE_RW_FILES) {
		if (IS_ERR_OR_NULL(knode_R) || IS_ERR_OR_NULL(knode_W)) {
			iccom_err("Files do not exist");
			return -EFAULT;
		}

		device_remove_file(dev,&dev_attr_R);
		device_remove_file(dev,&dev_attr_W);
	} else {
		iccom_err("To create or remove RW files the option shall be 0 or 1");
		return -EINVAL;
	}

	return count;
}

static DEVICE_ATTR_WO(showRW_ctl);

// List of all Transport device attributes
//
// @dev_attr_showRW_ctl the Transport file to create/delete the R and W files
static struct attribute *iccom_test_transport_dev_attrs[] = {
	&dev_attr_showRW_ctl.attr,
	NULL,
};

ATTRIBUTE_GROUPS(iccom_test_transport_dev);

// Sysfs file to create Iccom Test Transport
// devices via user space
//
// @class {valid ptr} transport class
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to read input from user space
// @count {number} size of buffer from user space
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t create_transport_store(
		struct class *class, struct class_attribute *attr,
		const char *buf, size_t count)
{
	// Allocate one unused ID
	int device_id = ida_alloc(&iccom_test_transport_dev_id,GFP_KERNEL);

	if (device_id < 0) {
		iccom_err("Could not allocate a new unused ID");
		return -EINVAL;
	}

	struct platform_device *new_pdev = 
		platform_device_register_simple("iccom_test_transport",
							device_id, NULL, 0);

	if (IS_ERR_OR_NULL(new_pdev)) {
		iccom_err("Could not register the device iccom_test_transport.%d",
								device_id);
		return -EFAULT;
	}

	return count;
}

static CLASS_ATTR_WO(create_transport);

// Sysfs class method for deleting iccom_test_transport instances
// trough the usage of sysfs internal mechanisms
//
// @class {valid ptr} iccom class
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to read input from user space
// @count {number} size of buffer from user space
//
// RETURNS:
//  count: ok
//    < 0: errors
static ssize_t delete_transport_store(
		struct class *class, struct class_attribute *attr,
		const char *buf, size_t count)
{
	if (count >= PAGE_SIZE) {
		iccom_warning("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	// Sysfs store procedure has data from userspace with length equal
	// to count. The next byte after the data sent (count + 1) will always
	// be a 0-terminator char. This is the default behavior of sysfs.
	size_t total_count = count + 1;
	char *device_name = (char *) kzalloc(total_count, GFP_KERNEL);
	
	if (IS_ERR_OR_NULL(device_name)) {
		return -ENOMEM;
	}
	
	memcpy(device_name, buf, total_count);

	// NOTE: count is a length without the last 0-terminator char
	if (device_name[count] != 0) {
		iccom_warning("NON-null-terminated string is provided by sysfs.");
		goto clean_up_device_name_buffer_memory;
	}

	(void)iccom_test_sysfs_trim_buffer(device_name, count);

	struct device *iccom_test_transport_device = 
		bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);

	if (IS_ERR_OR_NULL(iccom_test_transport_device)) {
		iccom_err("Iccom Test Transport device is null.");
		return -EFAULT;
	}

	platform_device_unregister(to_platform_device(iccom_test_transport_device));

	return count;

clean_up_device_name_buffer_memory:
	kfree(device_name);
	return -EFAULT;
}

static CLASS_ATTR_WO(delete_transport);

// List of all Transport class attributes
//
// @class_attr_create_transport sysfs file for creating
//                              iccom_test_transport devices
// @class_attr_delete_transport sysfs file for deleting
//                              iccom_test_transport devices
static struct attribute *iccom_test_transport_class_attrs[] = {
	&class_attr_create_transport.attr,
	&class_attr_delete_transport.attr,	
	NULL
};

ATTRIBUTE_GROUPS(iccom_test_transport_class);

// The Transport class definition
//
// @name class name
// @owner the module owner
// @class_groups group holding all the attributes
static struct class iccom_test_transport_class = {
    .name = "iccom_test_transport",
    .owner = THIS_MODULE,
    .class_groups = iccom_test_transport_class_groups
};

// Registers the Transport class for sysfs
//
// RETURNS:
//      0: ok
//      !0: nok
int iccom_test_sysfs_transport_class_register(void) {
	return class_register(&iccom_test_transport_class);
};

// Unregisters the ICCom class for sysfs
void iccom_test_sysfs_transport_class_unregister(void) {
	class_unregister(&iccom_test_transport_class);
};

// Transport device probe which initializes the device
// and allocates the iccom_test_transport_dev
//
// @pdev {valid ptr} transport device
//
// RETURNS:
//      0: ok
//     <0: errors
static int iccom_test_transport_probe(struct platform_device *pdev) {
	struct iccom_test_transport_dev *iccom_test_transport;

	if (IS_ERR_OR_NULL(pdev)) {
		iccom_err("Transport test device pdev is null.");
		return -EFAULT;
	}

	iccom_test_transport = (struct iccom_test_transport_dev *) 
		kmalloc(sizeof(struct iccom_test_transport_dev), GFP_KERNEL);

	if (IS_ERR_OR_NULL(iccom_test_transport)) {
		iccom_err("Transport test device allocation failed");
		return -ENOMEM;
	}

	iccom_test_transport->p = (struct iccom_test_transport_dev_private *)
		kmalloc(sizeof(struct iccom_test_transport_dev_private), GFP_KERNEL);

	if (IS_ERR_OR_NULL(iccom_test_transport->p)) {
		goto no_memory_private_data;
	}

	iccom_test_transport->duplex_iface = (struct full_duplex_sym_iface *)
		kmalloc(sizeof(struct full_duplex_sym_iface), GFP_KERNEL);

	if (IS_ERR_OR_NULL(iccom_test_transport->duplex_iface)) {
		goto no_memory_full_duplex;
	}

	iccom_test_transport->p->xfer_dev_data = (struct xfer_device_data *) 
			kmalloc(sizeof(struct xfer_device_data), GFP_KERNEL);

	if (IS_ERR_OR_NULL(iccom_test_transport->p->xfer_dev_data)) {
		goto no_memory_xfer_data;
	}

	/* Full duplex interface definition */
	iccom_test_transport->duplex_iface->data_xchange = &data_xchange;
	iccom_test_transport->duplex_iface->default_data_update = &default_data_update;
	iccom_test_transport->duplex_iface->is_running = &is_running;
	iccom_test_transport->duplex_iface->init = &init;
	iccom_test_transport->duplex_iface->reset = &reset;
	iccom_test_transport->duplex_iface->close = &close;

	dev_set_drvdata(&pdev->dev, iccom_test_transport);

	return 0;

no_memory_private_data:
	iccom_err("Transport test device private data allocation failed");
	kfree(iccom_test_transport);
	iccom_test_transport = NULL;
	return -ENOMEM;
no_memory_full_duplex:
	iccom_err("Transport test device full duplex allocation failed");
	kfree(iccom_test_transport->p);
	kfree(iccom_test_transport);
	iccom_test_transport->p  = NULL;
	iccom_test_transport = NULL;
	return -ENOMEM;
no_memory_xfer_data:
	iccom_err("Transport test device xfer device allocation failed");
	kfree(iccom_test_transport->p);
	kfree(iccom_test_transport->duplex_iface);
	kfree(iccom_test_transport);
	iccom_test_transport->p  = NULL;
	iccom_test_transport->duplex_iface  = NULL;
	iccom_test_transport = NULL;
	return -ENOMEM;
};

// Transport device remove which deinitialize the device
// and frees the iccom_test_transport_dev
//
// @pdev {valid ptr} transport device
//
// RETURNS:
//      0: ok
//     <0: errors
static int iccom_test_transport_remove(struct platform_device *pdev) {
	struct iccom_test_transport_dev *iccom_test_transport;

	if (IS_ERR_OR_NULL(pdev)) {
		iccom_err("Transport test device pdev is null.");
		return -EFAULT;
	}

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
		"Removing a iccom test transport device with id: %d", pdev->id);

	iccom_test_transport = (struct iccom_test_transport_dev *)
						dev_get_drvdata(&pdev->dev);

	if (IS_ERR_OR_NULL(iccom_test_transport)) {
		iccom_err("Transport test data is null.");
		return -EFAULT;
	}

	if (!IS_ERR_OR_NULL(iccom_test_transport->duplex_iface)) {
		kfree(iccom_test_transport->duplex_iface);
		iccom_test_transport->duplex_iface = NULL;
	}

	if(!IS_ERR_OR_NULL(iccom_test_transport->p) &&
		!IS_ERR_OR_NULL(iccom_test_transport->p->xfer_dev_data)) {
		kfree(iccom_test_transport->p->xfer_dev_data);
		iccom_test_transport->p->xfer_dev_data = NULL;
	}

	if(!IS_ERR_OR_NULL(iccom_test_transport->p)) {
		kfree(iccom_test_transport->p);
		iccom_test_transport->p = NULL;
	}

	kfree(iccom_test_transport);
	iccom_test_transport = NULL;

	return 0;
}

// The Transport driver compatible definition
//
// @compatible name of compatible driver
struct of_device_id iccom_test_transport_driver_id[] = {
	{
		.compatible = "iccom_test_transport",
	}
};

// The Transport driver definition
//
// @probe probe device function
// @remove remove device function
// @driver structure driver definition
// @driver::owner the module owner
// @driver::name name of driver
// @driver::of_match_table compatible driver devices
// @driver::dev_groups devices groups with all attributes
struct platform_driver iccom_test_transport_driver = {
	.probe = iccom_test_transport_probe,
	.remove = iccom_test_transport_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "iccom_test_transport",
		.of_match_table = iccom_test_transport_driver_id,
		.dev_groups = iccom_test_transport_dev_groups
	}
};

// Module init method to register
// the ICCom and transport drivers
// as well as to initialize the id
// generators and the crc32 table
//
// RETURNS:
//      0: ok
//     !0: nok
static int __init iccom_module_init(void)
{
	int ret;

	__iccom_crc32_gen_lookup_table();

	ida_init(&iccom_dev_id);
	ida_init(&iccom_test_transport_dev_id);

	ret = platform_driver_register(&iccom_driver);
	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
				"Iccom Driver Register result: %d", ret);
	iccom_test_sysfs_iccom_class_register();

	ret = platform_driver_register(&iccom_test_transport_driver);
	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
				"Transport Driver Register result: %d", ret);
	iccom_test_sysfs_transport_class_register();


	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, "module loaded");
	return ret;
}

// Module exit method to unregister
// the ICCom and transport drivers
// as well as to deinitialize the id
// generators
//
// RETURNS:
//      0: ok
//     !0: nok
static void __exit iccom_module_exit(void)
{
	ida_destroy(&iccom_dev_id);
	ida_destroy(&iccom_test_transport_dev_id);

	iccom_test_sysfs_iccom_class_unregister();
	iccom_test_sysfs_transport_class_unregister();

	iccom_sysfs_driver_unregister_devices(&iccom_driver.driver);
	iccom_sysfs_driver_unregister_devices(&iccom_test_transport_driver.driver);

	platform_driver_unregister(&iccom_driver);
	platform_driver_unregister(&iccom_test_transport_driver);

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, "module unloaded");
}

module_init(iccom_module_init);
module_exit(iccom_module_exit);

MODULE_DESCRIPTION("InterChipCommunication protocol module.");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");
