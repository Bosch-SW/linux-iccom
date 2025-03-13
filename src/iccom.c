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
#include <linux/version.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>

#include <linux/full_duplex_interface.h>
#include <linux/iccom.h>

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
//       verbosity
//    NOTE: the xfers and package dumps will be printed at the
//      KERNEL_INFO level, so if your kernel is more silient
//      than this, you will not see the xfer nor packages hex dumps
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
#ifndef ICCOM_DEBUG
#define ICCOM_DEBUG
#endif
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

// the ID of the very first package being sent
#define ICCOM_INITIAL_PACKAGE_ID 0
// keep it negative
#define ICCOM_PACKAGE_HAVE_NOT_RECEIVED_ID -1

/* --------------------- DATA PACKAGE CONFIGURATION ---------------------*/

// unused payload space filled with this value
// NOTE: changing this value REQUIRES MANDATORY recomputation of the
//		crc32 checksums tables below in utilities section.
#define ICCOM_PACKAGE_EMPTY_PAYLOAD_VALUE 0xFF
#define ICCOM_PACKAGE_PAYLOAD_DATA_LENGTH_FIELD_SIZE_BYTES 2
#define ICCOM_PACKAGE_ID_FIELD_SIZE_BYTES 1
#define ICCOM_PACKAGE_CRC_FIELD_SIZE_BYTES 4
#define ICCOM_PACKAGE_HEADER_SIZE_BYTES 			\
			(ICCOM_PACKAGE_ID_FIELD_SIZE_BYTES 		\
			 + ICCOM_PACKAGE_PAYLOAD_DATA_LENGTH_FIELD_SIZE_BYTES)

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

/* ---------------------- ADDITIONAL VALUES -----------------------------*/

#define ICCOM_TRANSPORT_LINK_FLAGS  DL_FLAG_STATELESS

/* --------------------- UTILITIES SECTION ----------------------------- */

// to keep the compatibility with Kernel versions earlier than v5.5
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
	#define pr_warning pr_warn
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
	#define ICCOM_CLASS_MODIFIER const
	#define ICCOM_CLASS_ATTR_MODIFIER const
#else
	#define ICCOM_CLASS_MODIFIER
	#define ICCOM_CLASS_ATTR_MODIFIER
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
#define ICCOM_CHECK_XFER_DEVICE(msg, error_action)			\
	if (IS_ERR_OR_NULL(iccom->xfer_device)) {			\
		iccom_err("%s: no xfer device; "msg"\n"	\
			  , __func__);					\
		error_action;						\
	}
#define ICCOM_CHECK_CLOSING(msg, closing_action)			\
	if (atomic_read(&iccom->p->closing)) {				\
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

/* ------------------------ FORWARD STRUCTS -----------------------------*/

struct iccom_package;
struct iccom_message_storage;
struct iccom_message;
struct iccom_test_sysfs_channel;

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

ssize_t __iccom_test_sysfs_initialize_ch_list(struct iccom_dev *iccom);
void iccom_test_sysfs_ch_del(struct iccom_dev *iccom);


bool __iccom_package_check_unused_payload(
		struct iccom_package *package, uint8_t symbol);

#ifdef ICCOM_DEBUG
static void iccom_dbg_printout_package(struct iccom_package *pkg);
static void iccom_dbg_printout_tx_queue(struct iccom_dev *iccom
		, int max_printout_count);
void iccom_dbg_printout_xfer(const struct full_duplex_xfer *const xfer);
void iccom_dbg_printout_message(const struct iccom_message *const msg);
#endif

struct iccom_message_storage_channel *__iccom_msg_storage_find_channel(
		struct iccom_message_storage *storage
		, unsigned int channel);
struct iccom_message *__iccom_msg_storage_find_message_in_channel(
		struct iccom_message_storage_channel *channel_rec
		, unsigned int msg_id);
struct iccom_message * __iccom_message_data_clone(
		struct iccom_message *src);
ssize_t iccom_test_sysfs_ch_enqueue_msg(
		struct iccom_dev *iccom, unsigned int ch_id,
		struct iccom_message *msg);
bool iccom_test_sysfs_is_ch_present(
		struct iccom_dev *iccom, unsigned int ch_id);
static inline struct iccom_message *__iccom_msg_storage_get_message(
		struct iccom_message_storage *storage
		, unsigned int channel
		, unsigned int msg_id);
struct iccom_message *iccom_msg_storage_get_message(
		struct iccom_message_storage *storage
		, unsigned int channel
		, unsigned int msg_id);
struct iccom_message *iccom_msg_storage_get_last_message(
		struct iccom_message_storage *storage
		, unsigned int channel);
struct iccom_message *iccom_msg_storage_get_last_unfinalized_message(
		struct iccom_message_storage *storage
		, unsigned int channel);
struct iccom_message *iccom_msg_storage_get_first_message(
		struct iccom_message_storage *storage
		, unsigned int channel);
struct iccom_message *iccom_msg_storage_get_first_ready_message(
		struct iccom_message_storage *storage
		, unsigned int channel);
struct iccom_message *iccom_msg_storage_pop_first_ready_message(
		struct iccom_message_storage *storage
		, unsigned int channel);
struct iccom_message *iccom_msg_storage_pop_message(
		struct iccom_message_storage *storage
		, unsigned int channel
		, unsigned int msg_id);
int iccom_msg_storage_push_message(
		struct iccom_message_storage __kernel *storage
		, struct iccom_message __kernel *msg);
void iccom_msg_storage_remove_message(struct iccom_message *msg);
void iccom_msg_storage_collect_garbage(
		struct iccom_message_storage *storage);
void iccom_msg_storage_remove_channel(
		struct iccom_message_storage *storage
		, unsigned int channel);
void iccom_msg_storage_clear(struct iccom_message_storage *storage);
void iccom_msg_storage_free(struct iccom_message_storage *storage);
int iccom_msg_storage_append_data_to_message(
	    struct iccom_message_storage *storage
	    , unsigned int channel, unsigned int msg_id
	    , void *new_data, size_t new_data_length
	    , bool final);

int iccom_init(struct iccom_dev *iccom, struct platform_device *pdev);
int iccom_start(struct iccom_dev *iccom);
void iccom_print_statistics(struct iccom_dev *iccom);
bool iccom_is_running(struct iccom_dev *iccom);

void __iccom_stop_xfer_device(struct iccom_dev *iccom);
int __iccom_bind_xfer_device(struct device *iccom_dev
		, const struct full_duplex_sym_iface *const full_duplex_if
		, struct device *full_duplex_device);
void __iccom_unbind_xfer_device(struct iccom_dev *iccom);
void iccom_delete(struct iccom_dev *iccom, struct platform_device *pdev);

ssize_t __iccom_test_sysfs_initialize_ch_list(struct iccom_dev *iccom);
void iccom_test_sysfs_init_ch_msgs_list(
		struct iccom_test_sysfs_channel * ch_entry);
void iccom_test_sysfs_ch_del_entry(
		struct iccom_test_sysfs_channel *ch_entry);
void iccom_test_sysfs_ch_del(struct iccom_dev *iccom);
ssize_t iccom_test_sysfs_ch_pop_msg(
		struct iccom_test_sysfs_channel *ch_entry, char * buf__out,
		size_t buf_size);
ssize_t iccom_test_sysfs_ch_pop_msg_by_ch_id(
		struct iccom_dev *iccom, unsigned int ch_id,
		char * buf__out, size_t buf_size);
ssize_t iccom_test_sysfs_ch_add_by_iccom(
		struct iccom_dev *iccom, unsigned int ch_id);
ssize_t iccom_test_sysfs_ch_del_by_iccom(
		struct iccom_dev *iccom, unsigned int ch_id);
size_t iccom_test_sysfs_trim_buffer(char *buf, size_t size);


/* --------------------------- MAIN STRUCTURES --------------------------*/

// Describes the sysfs channel structure which shall store
// all sniffed messages from iccom to iccom socket (upper layer)
// in a linked list. The userspace can retrieve all the sysfs channel
// messages one by one
//
// @ch_id {number} ICCom logical channel ID
// @num_msgs {number} number of sniffed messages stored
//                    for the particular sysfs channel
// @ch_msgs_head sysfs channel messages list head
// @list_anchor list_head for pointing to next channel
struct iccom_test_sysfs_channel {
	unsigned int ch_id;
	unsigned int num_msgs;
	struct list_head ch_msgs_head;
	struct list_head list_anchor;
};

// TODO: probably not needed
// (probably needed only for xfer)
//
// Describes the single consumer message.
//
// @list_anchor messages list anchor point
// @data the consumer raw byte data. Always owns the data.
//       The type has been changed from char* to uint8* as
//       there are value expansion in comparisons which lead
//       to wrong comparision results.
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

	uint8_t *data;
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
// @data the raw xfer data to be sent. The type has been changed
//       from char* to uint8* as there are value expansion in comparisons
//       which lead to wrong comparision results.
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
// 
// @total_msgs_rcv indicates the total number of the messages received
//		on this channel.
// @total_consumer_bytes_rcv indicates the total number of consumer
//		bytes received on this channel.
struct iccom_message_storage_channel
{
	struct list_head channel_anchor;
	unsigned int channel;

	struct list_head messages;

	unsigned int current_last_message_id;

	void *consumer_callback_data;
	iccom_msg_ready_callback_ptr_t message_ready_callback;

	int64_t total_msgs_rcv;
	int64_t total_consumer_bytes_rcv;
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
// @iccom pointer to corresponding iccom_dev structure.
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
	struct iccom_dev *iccom;

	struct list_head channels_list;
	struct mutex lock;

	iccom_msg_ready_callback_ptr_t message_ready_global_callback;
	void *global_consumer_data;

	atomic_t uncommitted_finalized_count;
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
// NOTE: statistics is not guaranteed to be precise or even
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
	atomic_long_t messages_ready_in_storage;

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
// @next_tx_package_id keeps the next outgoing message id. Wraps around.
//		All values (specifically [0;255]) are valid.
// @last_rx_package_id the sequence ID of the last package we have
//      received from the other side. If we receive two packages
//      with the same sequence ID, than we will drop all but one of the
//      packages with the same sequence ID.
//		NOTE: package ID in real packages always runs in range [0;255]
//			so the value last_rx_package_id == ICCOM_PACKAGE_HAVE_NOT_RECEIVED_ID
//			which is <0 is used ONLY to indicate "have not received anything yet".
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
// @sysfs_test_ch_rw_in_use {unsigned int} sysfs channel that is
//      selected for read/write operation requested by the userspace
//      via sysfs file channels_RW. Those operations will use this variable
//      to distinguish which sysfs channel operation shall take place.
//      Userpace shall set the sysfs test channel before the read/write
//      via sysfs file channels_ctl.
// @sysfs_test_ch_head the list which shall hold the sysfs channels
//      sniffed per sysfs channel. Userspace can then fetch those
//      via the sysfs file channels_RW
// @sysfs_test_ch_lock mutex to protect the sysfs channels from from data
//      races.
// @pdev The platform device we register on creation.
//    It works only for linking between devices (ICCom and, say, transport).
struct iccom_dev_private {
	struct iccom_dev *iccom;

	struct list_head tx_data_packages_head;
	struct mutex tx_queue_lock;

	unsigned char ack_val;
	unsigned char nack_val;

	// never owns the data pointed to
	struct full_duplex_xfer xfer;

	bool data_xfer_stage;

	uint8_t next_tx_package_id;
	int last_rx_package_id;

	struct iccom_message_storage rx_messages;

#if ICCOM_WORKQUEUE_MODE_MATCH(PRIVATE)
	struct workqueue_struct *work_queue;
#endif
	struct work_struct consumer_delivery_work;

	atomic_t closing;

	struct iccom_dev_statistics statistics;

	struct iccom_error_rec errors[ICCOM_ERROR_TYPES_COUNT];

	unsigned int sysfs_test_ch_rw_in_use;

	struct list_head sysfs_test_ch_head;

	struct mutex sysfs_test_ch_lock;

	struct platform_device *pdev; 
};

/* ------------------------ GLOBAL VARIABLES ----------------------------*/

// The ISO HDLC CRC32, 4-bit lookup table, used in crc32 computation.
// NOTE: using the 4-bit lookup table seems better than 8-bit, due to whole
//		table fitting into a usual cache line, so way less cache misses occurs.
static uint32_t iccom_crc32_lookup_tbl_4bit[16] = {
	0x0, 0x4c11db7, 0x9823b6e, 0xd4326d9, 0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005
	, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd
};

// The ISO HDLC CRC32, 4-bit lookup table, used in crc32 computation.
// NOTE: uses the G = 0x04C11DB7.
// NOTE: using the 4-bit lookup table seems better than 8-bit, due to whole
//		table fitting into a usual cache line, so way less cache misses occurs.
static uint32_t iccom_crc32_lookup_tbl_4bit_refl[16] = {
	0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c
	, 0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61B38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};

// The fast padding computation lookup tables.
// Strategy is the following:
//		* for up to 1K of padding - single computation is
//		  used using 1K lookup table.
//		* for bigger packages the computation works
//		  in steps, first: compute up to closest lower
//		  1K boundary using multi_K table, second compute
//		  the rest using 1K table.
//      * for even bigger messages 16K tables are used.

// Main part of CRC of concatenation formula is:
//		res = gf_multiply(a, f) ^ b
// where a is the message A CRC,
// b is the message B CRC,
// f is the x^(size(B))
//
// padding_crc is the array of b values, array index
// defines padding size in bytes.
static uint32_t iccom_crc32_padding_crc[1024] = {
	  0x0, 0xb1f740b4, 0xff48647d, 0x48647d00, 0xc704dd7b, 0xf6e7fb28, 0xc532d80f, 0xc960b446
	, 0xae006622, 0x7c3094b0, 0x54db7637, 0x112aa6f, 0xa79c3203, 0xc2ad45bf, 0x48ba5443, 0x192d9e7b
	, 0xf2b110cb, 0x80dd4dd3, 0x5b6735a, 0x104171df, 0xbc9744c4, 0xae8192ae, 0xfdc418b0, 0xcd9a8b6e
	, 0x473b38fe, 0xa00e9ec6, 0x4e46d0ba, 0xff2f2ac9, 0x2f2ac900, 0x3b524be9, 0x1cc50f45, 0xde545a0
	, 0x657f6667, 0x75f18a48, 0xb70c7e38, 0x1ef0a5cf, 0x31cdf4ce, 0xacf0fe93, 0x852a1ede, 0xe5201531
	, 0x438e3ca6, 0x60eb01a, 0xa5c11706, 0x960a7bd1, 0x8417e798, 0xdc184e86, 0x8d2e1639, 0xc7201f89
	, 0xd2250928, 0x8ce71833, 0xaef083e, 0x7175a862, 0x202a22e4, 0x3f61254, 0x4aa6326d, 0xcc98b15
	, 0x4d70ced0, 0xc4726610, 0x8d1fb6f1, 0xf680d789, 0xa21e790f, 0x572322d4, 0xf4056fb6, 0x2e247d61
	, 0x3127375e, 0x46336e93, 0xac99ee71, 0xec3afcde, 0x7bae23a9, 0xd42b3f32, 0x98574f81, 0xe5ad1792
	, 0xce8c9fa6, 0x5c6cd627, 0x90ba57d7, 0x2ebdac2a, 0xa8f67c5e, 0x90aca502, 0x384f792a, 0xcb4ea9c
	, 0x301147d0, 0x7482fd24, 0xc0ba0f8f, 0x56725f2d, 0xa1b98b01, 0xfd920a0d, 0x9b88366e, 0x3797de4b
	, 0xec5c3621, 0x1d64dca9, 0xa8f7b417, 0x9164ec02, 0xf4c7649d, 0xec2f5661, 0x6e049ca9, 0x25408f29
	, 0x7e9eb43f, 0xf379c259, 0x4ccec264, 0x7ebfcfa7, 0xd2025a59, 0xabb46933, 0xdffaeedb, 0x62cd6de0
	, 0xd9bd5d4d, 0x3ff8b652, 0xa53cc299, 0x6bdfe4d1, 0xe9fd9c42, 0xab0bd4c2, 0x60471fdb, 0x5a4d5d23
	, 0xabb71e65, 0xdc8db8db, 0x18d84b39, 0x3a54f7c, 0x19fb1a6d, 0x243506cb, 0xfd64b88, 0x5ff37509
	, 0x25a5f0e, 0xe22a75da, 0x57a987a3, 0x7ea018b6, 0xcdd54b59, 0x8fb0ffe, 0x6cf0530c, 0xd80d1147
	, 0x8b75a1e5, 0x86118e3b, 0xd3f3d6e8, 0x5ef9c584, 0xc2bcfb9, 0xaf3462d0, 0x4cf57b07, 0x4506aca7
	, 0x9418fca8, 0x9f12a5f6, 0xbe003097, 0x3077fac0, 0x123fed24, 0xcb8984aa, 0x4eb2b14c, 0xb4edcc9
	, 0xd46042d5, 0xd32aa881, 0x8787ac84, 0x4110745f, 0x91c47274, 0x5459129d, 0x8376006f, 0xa3b8e983
	, 0xf572b363, 0x5d39b5d6, 0xc118bb60, 0xf007ad9a, 0x3fe227bd, 0xbfad2d99, 0x99abe977, 0x1dcafc25
	, 0x6d73817, 0x7c491a06, 0x2d55c037, 0x4dd94787, 0x6dfb3110, 0xd7ae10f0, 0x103bab58, 0xc64dc3c4
	, 0xbb38599f, 0x1fdb99ab, 0x1e308d79, 0xf1e542ce, 0xd9cc6e0a, 0x4ecbf152, 0x720ec2c9, 0x5603af3d
	, 0xd0499b01, 0xe9f70a5d, 0xa19dcbc2, 0xd9d2c90d, 0x506cf652, 0xa596b9b3, 0xc1a4ced1, 0x4c721c9a
	, 0xc26131a7, 0x84ce4c43, 0x5b39586, 0x15a7addf, 0x4d8e2faf, 0x3a931910, 0xd956ebf2, 0xd44e0952
	, 0xfd612f81, 0x68adba6e, 0x96e0059b, 0x6e69ad98, 0x4871be29, 0xd2c7f47b, 0x6e1a4b33, 0x3b971529
	, 0xd99bcf45, 0x196abe52, 0xb59139cb, 0x8a356da1, 0xc21cd78c, 0xf9286743, 0x32e10eb2, 0x8d49a44a
	, 0xa0926c89, 0xd2b49fba, 0x1d718a33, 0xbda12e17, 0x9c2a5c19, 0x8bbaf94e, 0x4949253b, 0xee9dfbcc
	, 0xd52b0ac7, 0x9ca3a736, 0x241d64e, 0xf9a335da, 0xb9b397b2, 0x9d978fc5, 0x32a838f9, 0xc47fef4a
	, 0x8096ecf1, 0x4e17515a, 0xaeaecac9, 0xd29c7fb0, 0x35918033, 0xe380754f, 0xf9680f14, 0x728959b2
	, 0xd198d43d, 0x3c792bea, 0x29e25c40, 0xe941465b, 0x17d1cdc2, 0x326c09c1, 0x4ed74a, 0xff200ab4
	, 0x200ab400, 0x2360f654, 0x4461848d, 0xf7f1cb1f, 0xd7c3f2b8, 0x7dd9e358, 0xb96d8380, 0x4383bdc5
	, 0xb8fd31a, 0x156f91d5, 0x85b225af, 0x7d1b6431, 0x7beaea80, 0x90e21632, 0x76fc492a, 0xb78c3ae1
	, 0x9eb47ccf, 0x1c181420, 0xd0fe20a0, 0x5e4cab5d, 0xb94516b9, 0x6b1684c5, 0x209d8842, 0xb45cb454
	, 0x4379ef16, 0xf1dd001a, 0xe18eba0a, 0xfe25717a, 0x21b067b7, 0x9d725ce3, 0xd77b1ef9, 0xc535a258
	, 0xce1ae346, 0xca103627, 0xd3c121fb, 0x6c0ed684, 0x26889947, 0xbbcbfce6, 0xec7ee0ab, 0x3fb256a9
	, 0xefdc3999, 0x90284270, 0xbca80b2a, 0x91ce7cae, 0x5e57c89d, 0xa226d6b9, 0x6f8c94d4, 0xa989ef9e
	, 0xebfe78b5, 0xa16d18ac, 0x2901a70d, 0xaba0b5b, 0x2476cd62, 0x4c1de288, 0xad9f23a7, 0xee363769
	, 0x7ee7afc7, 0x8a623a59, 0x954b2f8c, 0xc8009c41, 0xcae97c95, 0x2a8b93fb, 0x8dcddb82, 0x24eda489
	, 0xd7740988, 0xca22d358, 0xe1245efb, 0x54c1807a, 0x1be4e76f, 0x324a3fa5, 0x2678b34a, 0x4be1f1e6
	, 0x4fcb1da2, 0x76232f7e, 0x68ea6ee1, 0xd1348a9b, 0x90278dea, 0xb367912a, 0x661bc113, 0x1c15d891
	, 0xdd3291a0, 0xa3302d8e, 0x7db6be63, 0xd630b880, 0x8a52c6ef, 0xa5b7998c, 0xe084f1d1, 0xf0afb7cd
	, 0x97f870bd, 0x72dd962f, 0x8557493d, 0x9877f631, 0xc514a792, 0xef1f2946, 0x53389d70, 0xfcbebd6a
	, 0xb3fe4cd9, 0xffc63213, 0xc6321300, 0xc4e89d9f, 0x17e439f1, 0x7983ac1, 0x378ad1b1, 0xf153cc21
	, 0x6f42810a, 0x679c319e, 0x9f244826, 0x88ede097, 0x1313dae2, 0xe37f5f1d, 0x6425d14, 0xe92c1906
	, 0x7a8e90c2, 0xf0594985, 0x610638bd, 0x1fab2694, 0x6e8fb279, 0xae6e5f29, 0x12099fb0, 0xfdfb10aa
	, 0xf292916e, 0xa35ce8d3, 0x1173e363, 0x8ac4e573, 0x3394058c, 0xfc8387fd, 0x8ec4dbd9, 0x20aed950
	, 0x870da654, 0xcb1aa45f, 0xdd92444c, 0x3e5c18e, 0x5975e86d, 0x9e4176bc, 0xe9126720, 0x44f0b6c2
	, 0x66c3841f, 0xc450d491, 0xafad37f1, 0xd5a05a07, 0x17f36736, 0x10c6fdc1, 0x3b1b5ac4, 0x55d42245
	, 0xa87c5d8, 0x19b84e62, 0x676109cb, 0x621c1d26, 0x8cd9b4d, 0x5a64e00c, 0x820a3165, 0xdb48fe34
	, 0xc3d9f43c, 0x38cacaf4, 0x8907349c, 0xfd06cc55, 0xf4e6e6e, 0xc7d69309, 0x24a98928, 0x9359a888
	, 0xc001d5f3, 0xeda8232d, 0xedb0cd1e, 0xf55efe1e, 0x7174c8d6, 0x214a96e4, 0x67830fe3, 0x801a3526
	, 0xc2ce865a, 0x2b79b143, 0x7b2e7e35, 0x5476a332, 0xacc7af6f, 0xb27be2de, 0x7ea928a4, 0xc4e55959
	, 0x1a20fff1, 0xf293bc12, 0xa27194d3, 0x38cefed4, 0x8d33149c, 0xda22ba89, 0xad5c548b, 0x2d411b69
	, 0x59021987, 0xe9b09cbc, 0xe60b2ac2, 0x65f2e97f, 0xf87e9248, 0x60d51805, 0xc84a8323, 0x80f61e95
	, 0x2ee5355a, 0xf06f0c5e, 0x5743e3bd, 0x94c406b6, 0x43e8bbf6, 0x6089e01a, 0x94b29c23, 0x35722ef6
	, 0x2eb04f, 0x9f470fb4, 0xebaa7297, 0xf5673aac, 0x48b07ad6, 0x13030b7b, 0xf3aec61d, 0x9bca8664
	, 0x7527d44b, 0x61527d38, 0x4beea394, 0x40996fa2, 0x1c1e92c3, 0xd678c3a0, 0xc229e6ef, 0xcc190443
	, 0xc0750849, 0x9975992d, 0xc3baa625, 0x5b98d3f4, 0x7af8d4d2, 0x861d5985, 0xdf2468e8, 0xbc4b5ee0
	, 0x729bb6ae, 0xc377c83d, 0x96f6cbf4, 0x78a7c298, 0xd08928eb, 0x2944e05d, 0x4ffd5b5b, 0x4065d67e
	, 0xe0a74ec3, 0xd310a5cd, 0xbd8ae084, 0xb7e4cf19, 0xf64184cf, 0x634d3f0f, 0x5d2eaffa, 0xd6029760
	, 0xb87d26ef, 0x57e7cf72, 0x30e8c9b6, 0x8d0c9b24, 0xe5ad0289, 0xce9984a6, 0x4977d627, 0xd06ee7cc
	, 0xce8bc75d, 0x5b342d27, 0xd60607d2, 0xbced94ef, 0xd451b9ae, 0xe2d1d381, 0xac0fdca3, 0x7a082ede
	, 0x76e75585, 0xac9095e1, 0xe5416cde, 0x22f7d3a6, 0xd7856b3a, 0x3b406158, 0xeefbe45, 0x62c7a5be
	, 0xd375034d, 0xd82c6084, 0xaa0462e5, 0x6b30256c, 0x63c2142, 0x97504f06, 0xdae22d2f, 0x6dcbf28b
	, 0xe76d8bf0, 0x792c6c8, 0x3d76d8b1, 0x22d01af7, 0xf04c3a3a, 0x747587bd, 0x37c0968f, 0xbb14f221
	, 0x337027ab, 0x18a1a0fd, 0x7a4e8b7c, 0x3042f785, 0x2732a824, 0x53b8251, 0x9db07adf, 0x155d22f9
	, 0xb70109af, 0x138732cf, 0x7797721d, 0xd8761056, 0xf074b0e5, 0x4cff58bd, 0x4f2516a7, 0x98282a7e
	, 0x9ac8e892, 0x73883ffc, 0xd43f878a, 0x8ceff781, 0x200ba3e, 0xb8cf45da, 0xe584fa72, 0xe7617fa6
	, 0xb6690c8, 0xfc2c43d5, 0x2100f3d9, 0x2de632e3, 0xfe2b9387, 0x2f529ab7, 0x4301fce9, 0x89ceff1a
	, 0x34cd4a55, 0xbb8b0ef8, 0xac8cfeab, 0xf92a26de, 0x30a093b2, 0xc5569f24, 0xad279f46, 0x568ad669
	, 0x5930cf01, 0xdb661abc, 0xed3d7c3c, 0x78efdc1e, 0x9897aeeb, 0x254c7d92, 0x726c0f3f, 0x34ce593d
	, 0xb89866f8, 0xb2a7d872, 0xa29384a4, 0xdade89d4, 0x516f098b, 0xa2a87d04, 0xe12729d4, 0x57b6af7a
	, 0x6188c1b6, 0x91522d94, 0xc206f29d, 0xe30d7643, 0x746b0314, 0x29443f8f, 0x4f22895b, 0x9fb7d67e
	, 0x1b73b897, 0xa515c7a5, 0x42dad8d1, 0x562bdaad, 0xf83c0b01, 0x224c5105, 0x6c07c83a, 0x2f962747
	, 0x87bc0ce9, 0x7ab0195f, 0xced0d485, 0x27f527, 0x960267b4, 0x8c0b8298, 0xe675a33e, 0x1b7b157f
	, 0xadb82fa5, 0xc93a3569, 0xf4814922, 0xaa02e961, 0x6dbba16c, 0x973e6cf0, 0xb4c1db2f, 0xde169416
	, 0x8a76bd57, 0x81cc218c, 0x101b31ed, 0xe6d776c4, 0xb9aeef7f, 0x80ef42c5, 0x37b9655a, 0xc2e72721
	, 0x2d8ca43, 0x60bf38da, 0xa26a5c23, 0x23060ed4, 0x2299048d, 0xb952403a, 0x7c4007c5, 0x24480337
	, 0x72d3b788, 0x8b76ee3d, 0x855e563b, 0x9168f031, 0xf8db579d, 0xc510cd05, 0xeb75be46, 0x2aabebac
	, 0xadb58c82, 0xc4991269, 0x666bcff1, 0x6c1b3a91, 0x33648c47, 0xc0a4cfd, 0x8eb726d0, 0x5353d050
	, 0x97f39d6a, 0x7930412f, 0x43cb825c, 0x43b04a1a, 0x38780c1a, 0x3bc1da9c, 0x8f547a45, 0xb4ce58e7
	, 0xd1955c16, 0x31f100ea, 0x9004da93, 0x9030e82a, 0xa402512a, 0x518d4a66, 0x40eb9004, 0x6ee134c3
	, 0xc0e8e529, 0x498f92d, 0x3a0a1b68, 0x405493f2, 0xd1e2c2c3, 0x466fd5ea, 0xf0229771, 0x1ad8ccbd
	, 0xaa0f012, 0x3e8d8462, 0xd4cfef2e, 0x7c875381, 0xe31c4737, 0x655a7714, 0x50e0f948, 0x2999a3b3
	, 0x92beb55b, 0x23dd1b44, 0xf98c948d, 0x9612c0b2, 0x9cac8498, 0xd62784e, 0xe2428867, 0x3f543aa3
	, 0x9b03399, 0x230d29bb, 0x29be6b8d, 0xb5768b5b, 0x6d87fda1, 0xab62a1f0, 0x9322ddb, 0xa1136bbb
	, 0x5772b00d, 0xa597b6b6, 0xc0abcbd1, 0x47b6012d, 0x2d374dc6, 0x2f54b687, 0x452dcce9, 0xbf78b2a8
	, 0x4c34d877, 0x84a5dca7, 0x6e237186, 0x2ada029, 0x15d552da, 0x3f712aaf, 0x2ca03f99, 0xbce7f430
	, 0xde3166ae, 0xad840557, 0xf510c769, 0x3f4dbfd6, 0x10354699, 0xc8a002c4, 0x6a77f995, 0x4521c5f5
	, 0xb371aea8, 0x70244313, 0x75004e53, 0x46c86538, 0x57924571, 0x4562cab6, 0xf07eeda8, 0x46a215bd
	, 0x3de2c071, 0xb6c8daf7, 0xde957778, 0x995d357, 0x6ede7bb, 0x4696b606, 0x9417b71, 0xd245c1bb
	, 0xec2f8b33, 0x6ed9cea9, 0xf8128f29, 0xcc87905, 0x4c82ded0, 0x32a37ba7, 0xcf3cb14a, 0xe8832790
	, 0xd1711b75, 0xd5b663ea, 0x1ca8a36, 0x7fbc6b03, 0xd567e3ee, 0xd04a8e36, 0xeae23d5d, 0xb9e9ed1b
	, 0xc7ed26c5, 0x1f1c4528, 0xd9ec0e79, 0x6eab8252, 0x8a5e7429, 0xa9055f8c, 0x674e6ab5, 0x4d7f6326
	, 0xcbdf9010, 0x18a60b4c, 0x7de53a7c, 0x85b4a780, 0x7b994b31, 0xe343a732, 0x3aba7214, 0xf03deff2
	, 0x5a04fbd, 0x67d96df, 0xd6e7d206, 0x5d3840ef, 0xc0ed8260, 0x1ffb02d, 0x4a867003, 0x2c8be515
	, 0x973d7830, 0xb7d51b2f, 0xc795b2cf, 0x67884f28, 0x8b5afe26, 0xa94e4d3b, 0x2c5cddb5, 0x4005d830
	, 0x80a900c3, 0x71fb635a, 0xaee11ae4, 0x9d4c52b0, 0xe9754df9, 0x23da6fc2, 0xfef8128d, 0xfcd390b7
	, 0xded391d9, 0x4f737257, 0xce4cda7e, 0x9c290e27, 0x88e8c74e, 0x163403e2, 0xd3633476, 0xce1b5b84
	, 0xcba8f427, 0x6fc23c4c, 0xe721779e, 0x4b6ea8c8, 0xc09233a2, 0x7e4e722d, 0x23bfd059, 0x9b47898d
	, 0xf8283d4b, 0x367a1b05, 0x5586596, 0xfe57bddf, 0x537cc2b7, 0xb8e17a6a, 0xcbbb4a72, 0x7c7c694c
	, 0x18268a37, 0xfd64417c, 0x6dc3476e, 0xefd86ef0, 0x947f2b70, 0xf8c57df6, 0xdb3aa605, 0xb181c53c
	, 0x89cdec7d, 0x37de2d55, 0xa5af2821, 0xf8355cd1, 0x2b1b8105, 0x191e3835, 0xc1175ecb, 0xffe2069a
	, 0xe2069a00, 0x7b465da3, 0x3c553532, 0x5fc8440, 0x5ab66bdf, 0x5081e265, 0x48828eb3, 0x21f76e7b
	, 0xda7b90e3, 0xf4763e8b, 0x5d754061, 0x8ded0c60, 0x43a4689, 0x98b5bf68, 0x75dfe92, 0xf24e82b1
	, 0x7f4f37d3, 0x263b33ee, 0x86155e6, 0xf6aa4b0c, 0x8882fc0f, 0x7c0f42e2, 0x6b0d2437, 0x3b3d7a42
	, 0x73f4a445, 0xa8a43e8a, 0xc2ee7102, 0xb8ee943, 0x1455c8d5, 0xbb2a3818, 0xdba1eab, 0x3a246d67
	, 0x6e229cf2, 0x340d429, 0xfc604f6d, 0x6d0c4bd9, 0x20d4d9f0, 0xfd0d0654, 0x4846f6e, 0x269c5868
	, 0xaf0ad3e6, 0x72444d07, 0x1c8c613d, 0x448b3da0, 0x1d48e61f, 0x84cd0217, 0x6fdc186, 0x56b08b06
	, 0x636da001, 0x7db1a1fa, 0xd12f2180, 0x8b8c96ea, 0x7f26813b, 0x4f8ddbee, 0x30e5637e, 0x80a65324
	, 0x7ea8845a, 0xc549a759, 0xb21fe246, 0x1aa9b0a4, 0x7bdce912, 0xa6e18432, 0xbbda6908, 0xfdeb0eab
	, 0xe28c906e, 0xf14c33a3, 0x70bd030a, 0xec405753, 0x105aea9, 0xb098f403, 0x943dceca, 0xba20c7f6
	, 0x384ed1c, 0x38597a6d, 0x1ab7ad9c, 0x65c1d112, 0xcb46ff48, 0x81c9534c, 0x1569f1ed, 0x83d21daf
	, 0x7a52983, 0xa9993b1, 0x7ee2762, 0x419772b1, 0x16c29c74, 0x25fca276, 0xc2b3eb3f, 0x5614d443
	, 0xc732e501, 0xc0df8128, 0x33fcf82d, 0x947e26fd, 0xf9c8f0f6, 0xd276bbb2, 0xdf558233, 0xcda185e0
	, 0x7c35b6fe, 0x51f93837, 0x3499c104, 0xef005ff8, 0x4c4e2370, 0xfe5edba7, 0x5a1abab7, 0xfc508a65
	, 0x5dc943d9, 0x31eeb460, 0x8fb05093, 0x50e48ee7, 0x2dee0cb3, 0xf615c387, 0x370a770f, 0x71f57221
	, 0xa0f061e4, 0xb0b9f2ba, 0xb53b77ca, 0x207b6ca1, 0x52b85754, 0x78b584dd, 0xc2cf6deb, 0x2a920043
	, 0x945e6382, 0xd98d8ff6, 0xf2a0d52, 0xa3b5af09, 0xf8343963, 0x2a7e3305, 0x786d2582, 0x1a6e32eb
	, 0xbc5ea612, 0x676344ae, 0x60517826, 0x4c2aa023, 0x9add88a7, 0x66e80afc, 0xefde3791, 0x92264a70
	, 0xbb223044, 0x5b242ab, 0x147080df, 0x9e623218, 0xca56c320, 0x953426fb, 0xb709eb41, 0x1b65dccf
	, 0xb3719fa5, 0x70154e13, 0x440d4e53, 0x9b3b151f, 0x84b4af4b, 0x7f509d86, 0x399166ee, 0xd66a332b
	, 0xd0d96def, 0x7901e45d, 0x726ef05c, 0x36313a3d, 0x4e795d96, 0xc0a206c9, 0x4e7b192d, 0xc2e6bdc9
	, 0x3422243, 0xfe96256d, 0x92e470b7, 0x7918f744, 0x6b7de95c, 0x4bf01142, 0x5e2bb9a2, 0xde57e9b9
	, 0xcb0b1257, 0xcc244c4c, 0xfd3d0749, 0x3485726e, 0xf3b335f8, 0x86396364, 0xfb1e89e8, 0xd8d9edc
	, 0xda41a67, 0x2420a167, 0x1a71e788, 0xa38bc512, 0xc65e2263, 0xa8d9fe9f, 0xbf2e6402, 0x1ae27277
	, 0x301e3a12, 0x7bff3f24, 0x8537b232, 0xf88cf931, 0x92be6105, 0x23094544, 0x2dd2948d, 0xca8dfd87
	, 0x4e0a81fb, 0xb37e6bc9, 0x7fe12213, 0x882ef3ee, 0xd000a3e2, 0xa0cfe95d, 0x8f314bba, 0xd1ffa7e7
};

// See padding_crc above.
//
// msg_factor is the array of f values, array index
// defines padding size in bytes.
static uint32_t iccom_crc32_msg_factor[1024] = {
	  0x1, 0x100, 0x10000, 0x1000000, 0x4c11db7, 0xd219c1dc, 0x1d8ac87, 0xdc6d9ab7
	, 0x490d678d, 0x1b280d78, 0x4f576811, 0x5ba1dcca, 0xf200aa66, 0x8090a067, 0xf9ac87ee, 0x7f6e306
	, 0xe8a45605, 0x47f7cec1, 0xdd0fe172, 0x2fb7bf3a, 0x17d3315d, 0x8167d675, 0xa1b8859, 0x34028fd6
	, 0xc5b9cd4c, 0xf382b7f2, 0x64c29d0, 0x56af9db2, 0xcd8c54b5, 0xe013a34a, 0xd60a6c79, 0x1717f5b
	, 0x75be46b7, 0x4937c18c, 0x218e0c78, 0x12eed357, 0xab40b71e, 0x9ad3836f, 0xd9148248, 0x27d0f3e6
	, 0x569700e5, 0xf51103b5, 0x8f7e2362, 0x2f603f53, 0xc053585d, 0xed2cd99, 0xee43390a, 0xba1e8c73
	, 0x8c3828a8, 0x6428d38a, 0x97723a4b, 0x4960209b, 0x766f1b78, 0x95292855, 0x1bf005f5, 0x975fe511
	, 0x64bf7a9b, 0xdb2b4b, 0xdb2b4b00, 0x119b8088, 0xd3504ec7, 0x4c96aa30, 0x9720db13, 0x1b81789b
	, 0xe6228b11, 0xfda47acb, 0x1c0fb0da, 0x76ad9a14, 0x57a84455, 0xce94ae02, 0xf5aa3293, 0x344f0562
	, 0x8833794c, 0x7c7d4156, 0xa8f9d083, 0x2ef738b6, 0x5395a0ea, 0xe07467de, 0xb1cef879, 0x7707e9c9
	, 0xf91a84e2, 0xb1f5ef06, 0x4c1096c9, 0x111c2213, 0x54f2d5c7, 0x99461adb, 0x41ce1091, 0xfe57fcc0
	, 0xe2ca9d03, 0x6b61e17, 0xac985ab2, 0x5c797f6a, 0x34e45a63, 0x236c784c, 0xf918dc39, 0xb3ad3406
	, 0x1d49ada7, 0x3471faa3, 0xb6ccb84c, 0x6b008ccc, 0x8762c1f6, 0x158a46eb, 0xd1925b1b, 0x87014d5e
	, 0x7606eeeb, 0xfcdcbb55, 0x600f336d, 0xa396ab97, 0x6ac7e7d7, 0x44c8c741, 0xef4547ab, 0xb8a130c4
	, 0x3a06a4c6, 0xfd1c7d46, 0xa4083dda, 0xea16fad2, 0xfcd922af, 0x6596c96d, 0x2da9c0fc, 0x2ecc33
	, 0x2ecc3300, 0x689e16ea, 0x14bbc12f, 0xe4d482ac, 0x22ffca5, 0x267e9e6e, 0xfc3b9552, 0x8721346d
	, 0x567fddeb, 0x1dcc0db5, 0xb1d1e8a3, 0x681733c9, 0x9d9ee22f, 0x8a32924d, 0x74147b38, 0xe7cb533b
	, 0x10bd4d7c, 0xf15ca770, 0xd1de90be, 0xcbcae85e, 0xbc2905f8, 0xa137ee1a, 0xc20051b9, 0x545912f7
	, 0x32812adb, 0x5c9a8dfe, 0xd716ce63, 0x191278ec, 0x7ca0c77f, 0x757ff983, 0x8888f58c, 0xc7f18156
	, 0xb24c969c, 0xf82a2a10, 0x859a00b1, 0xe4c93a85, 0x1f97d5a5, 0xe38bc3cd, 0x4329cda0, 0x1008f6ae
	, 0x44e77570, 0xc0f776ab, 0xaafc3b99, 0x229e19d8, 0xfb8558e, 0x801a33bd, 0x733f5dee, 0xd2aad53e
	, 0xb2cc4e87, 0x78f23110, 0x348de05f, 0x4ad6444c, 0xcd48eaa1, 0x24adb74a, 0x26908a3c, 0x122fc752
	, 0x6a54b21e, 0xd79d0e41, 0x92d25aec, 0xfec5ecf0, 0x70daad03, 0x3a191ee7, 0xe2a65c46, 0x6a775b17
	, 0xf4740741, 0xeebbcad5, 0x42ed5373, 0xd0573819, 0x46a352e9, 0x8d52d4c5, 0xa15a33d, 0x3a29ebd6
	, 0xd2536d46, 0x4b743687, 0x6bfb3c16, 0x7cd21bf6, 0x7a37083, 0xbd37d305, 0xbb200ead, 0xb67beb1f
	, 0xdc53dfcc, 0x77481c8d, 0xb6efc0e2, 0x487822cc, 0x6aac51cf, 0x2f7edf41, 0xdeb34a5d, 0x9e5fb6e3
	, 0x46257894, 0xb78a9c5, 0x53e20e61, 0x97daecde, 0xe1b6b59b, 0x77dda0ce, 0x235383e2, 0xc6e37239
	, 0xa47ee42b, 0x9ccf0bd2, 0xdf1a72fa, 0x33a60c54, 0x7f7d1f49, 0xa5e4e95a, 0x2036765, 0xae55e6e
	, 0xcad4b8d6, 0xa6b8904f, 0x533954bc, 0x4c8031de, 0x81bb3513, 0xd6f8ee59, 0xf3f35f5b, 0x77a480d0
	, 0x5a739de2, 0x24809fd1, 0xbb8113c, 0x935af761, 0x72a97c47, 0x404a6189, 0x7ee7f977, 0x3bc3caed
	, 0x3cb34bf1, 0x527507f4, 0x4126469, 0x1601fdc, 0x64dec1b7, 0x6160074b, 0xc8639020, 0x18125d21
	, 0x784417c8, 0x82ab385f, 0xcbb68480, 0xc045dbf8, 0x18516899, 0x3b71afc8, 0x8ed66ef1, 0x83ecb1e4
	, 0x88fe2237, 0xb1263a56, 0x9fc5c6c9, 0xd8944f23, 0xa3dc8551, 0x20e921d7, 0x710261e0, 0xe614e050
	, 0xcbcf3bcb, 0xb9fa90f8, 0x65678571, 0xdce5dcfc, 0xc14b2c8d, 0x1267002e, 0x2293ce1e, 0x26f938e
	, 0x6611b56e, 0xa796e525, 0x798d230b, 0x4f5ee6e8, 0x522f25ca, 0x5e305a69, 0x7443620d, 0xb0d2663b
	, 0x6f58b67e, 0xcc5c052a, 0x348321fd, 0x4417e64c, 0x30644aab, 0xb078c690, 0xc5f81d7e, 0xb25285f2
	, 0xe6394410, 0xe66b7bcb, 0xb454a0cb, 0xfa9a30a2, 0x3c0289df, 0xe3b729f4, 0x7fc3f4a0, 0x1b0f005a
	, 0x685a4a11, 0xd0e73a2f, 0xf6a164e9, 0x325a59bb, 0x87e9edfe, 0x9ea64eeb, 0xbfdd7094, 0x5801a4c3
	, 0x5f3b85bf, 0x7b5da9ba, 0x96566c86, 0x69f7f02c, 0x799c1a98, 0x5e6775e8, 0x236ce30d, 0xf9839d39
	, 0x28ec3406, 0x521f5d58, 0x6e48c869, 0xd8e30f9d, 0xd49c3b51, 0x9ea46c35, 0xbdffae94, 0x735d9fad
	, 0xb068963e, 0xd5a8b37e, 0xaeed5e82, 0x20ff7404, 0x6757b2e0, 0xe5507692, 0x821adf12, 0x7a51c980
	, 0x9ef74b31, 0xeed8aa94, 0x218d1273, 0x11f0d857, 0xb80891c7, 0x93a7a7c6, 0x8ff9db47, 0xa8981a53
	, 0x4f3de8b6, 0x31217bca, 0xf188ba27, 0x5c3c7be, 0xd402d56b, 0x4a5635, 0x4a563500, 0x4d39a6a1
	, 0x3ced57a4, 0xc6952f4, 0x5c5e6f64, 0x13f45463, 0xb5069ea9, 0xac654f15, 0xa16cd86a, 0x993621b9
	, 0x31f57291, 0x2581e127, 0xe07fa8b, 0x3b742b0a, 0x8b52acf1, 0x10ebda8f, 0xa7cb5470, 0x243c760b
	, 0xb751cb3c, 0xf2b2e17b, 0x32dbbd67, 0x60d31fe, 0x17b7b3b2, 0xe5e53975, 0x37553812, 0x9f4d2f95
	, 0x507d1323, 0x5848807, 0x934d6c6b, 0x65327647, 0x8916eafc, 0x5d2fece1, 0x66b6ccd4, 0xef5f25
	, 0xef5f2500, 0xa2c39bc4, 0x3b36a960, 0xc9d0c6f1, 0xaf859196, 0x4cf17db3, 0xf0f75813, 0x7ee0ee09
	, 0x3cd4b4ed, 0x358a1bf4, 0x49ecf2fb, 0xfabd7b78, 0x1b4953df, 0x2e09cf11, 0xad6207ea, 0xa2e53add
	, 0x1d97b060, 0xea6c3da3, 0x861e53af, 0x6dd9025c, 0x446a1c44, 0x4d9e42ab, 0x9b095da4, 0x70b54ff
	, 0x1513af05, 0x487bb51b, 0x693b86cf, 0xb5eaf998, 0x40027e15, 0x36f86577, 0x36d15722, 0x1fe30222
	, 0x975c44cd, 0x671ea69b, 0xac440d92, 0x802e5f6a, 0x47538aee, 0x794bce72, 0x89b39fe8, 0xf85af8e1
	, 0xf548f1b1, 0xd68c2762, 0x873a645b, 0x4d2febeb, 0x2aa01da4, 0x17b4c436, 0xe692bd75, 0x4d921ecb
	, 0x97553da4, 0x6e67cf9b, 0xf7e4fd9d, 0x7302300c, 0xefc7373e, 0x3ad1a5c4, 0x2a1d7f46, 0xaad62636
	, 0x883b6d8, 0xa5be35b8, 0x58df8565, 0x811a23bf, 0x77ee4259, 0x10b114e2, 0xfd053970, 0xbd4c0bda
	, 0xc0f8d1ad, 0xa55b3d99, 0xbdd7a465, 0x5b576ead, 0x4b2cd66, 0xa1c910dc, 0x3cfe97b9, 0x1fa94ff4
	, 0xdd1192cd, 0x31c4003a, 0x14f34a27, 0xac5f8aac, 0x9ba9616a, 0xa7379aff, 0xd8f2f90b, 0xc56aad51
	, 0x20e2aaf2, 0x7a8944e0, 0x467a2b31, 0x542b0cc5, 0x409f18db, 0xab9eab77, 0x44cfea6f, 0xe86869ab
	, 0x8bc860c1, 0x8a27ea8f, 0x616cb938, 0xc4dde320, 0x936dc645, 0x45985847, 0xbb1b5c1c, 0x8d295a1f
	, 0x719b793d, 0x7f0c3d50, 0xd4c6f05a, 0xc46f6735, 0x21e9d345, 0x7531ee57, 0xc69f218c, 0xd82d512b
	, 0x1ac28d51, 0xa1165ca6, 0xe3b2edb9, 0x7a07b9a0, 0xc8876b31, 0xfce94c21, 0x55f8476d, 0x9715ad6c
	, 0x2ef7079b, 0x53aa8dea, 0xdf5967de, 0x70b32854, 0x539c49e7, 0xe99d6ade, 0x7a0a0876, 0xc536bd31
	, 0x7cf2caf2, 0x27727483, 0xf41065e5, 0x8ad96ed5, 0x9fe8e338, 0xf5b1be23, 0x2fc3b562, 0x63d9695d
	, 0x788fbd4e, 0x4901be5f, 0x17f1df78, 0xa389f375, 0x759f05d7, 0x6874a18c, 0xfe0ca72f, 0xb9917203
	, 0xe857e71, 0xb9f0d10a, 0x6f267771, 0xb29d0a2a, 0x29b69c10, 0xc7656ef, 0x435a7464, 0x63b132ae
	, 0x10d44e4e, 0x985f9570, 0x5c80a626, 0xcd3d1663, 0x5151754a, 0x2d23fcb0, 0x8a128033, 0x54060538
	, 0x6d96e5db, 0xb8d9b44, 0xa6d08f61, 0x3b267abc, 0xd9031af1, 0x30484ae6, 0x9c788b90, 0x689a30fa
	, 0x109dd12f, 0xd1c0f470, 0xd5ae265e, 0xa8787e82, 0xaf5939b6, 0x90595db3, 0x7c40889e, 0x95301883
	, 0x2c0d3f5, 0xc951ce6e, 0x2e8d0e96, 0x29a380ea, 0x196aacef, 0x474c47f, 0x67c009dc, 0x72eb4a92
	, 0x27cb489, 0x7536b26e, 0xc1c3188c, 0x9a53012e, 0x5996c348, 0xcc9d1308, 0xf59503fd, 0xb7e6b62
	, 0x5520a961, 0x4ffba16c, 0xf768a1ca, 0xff5e670c, 0xef904cb4, 0x6daa2fc4, 0x37478444, 0x8df17995
	, 0xa9b8f33d, 0x6b159b01, 0x92750cf6, 0x5993f6f0, 0xc9a8ab08, 0xd7e86896, 0xe7b48dec, 0x6f639a7c
	, 0xf770072a, 0xe7f8870c, 0x23697a7c, 0xfc1aec39, 0xa6585f6d, 0xb3f676bc, 0x460b17a7, 0x25179ac5
	, 0x987c188b, 0x7f0d5d26, 0xd5a6865a, 0xa0d87a82, 0x2955d40e, 0xef3e48ef, 0xc3ae74c4, 0xfebd7240
	, 0x8441d03, 0x6215eeb8, 0xb0c945f9, 0x747b747e, 0x88c4153b, 0x8b113656, 0x53717d8f, 0x4a902de
	, 0xba06a8dc, 0x941c87a8, 0x2a9ee542, 0x294c2236, 0xf6c870ef, 0x5b4e5fbb, 0x1d83db66, 0xfe073ba3
	, 0xb20dfe03, 0xb942b510, 0xdd426d71, 0x623bbc3a, 0x9e9bc7f9, 0x82546294, 0x34ec4f80, 0x2b799b4c
	, 0xcaf33181, 0x8131c74f, 0x5c0ab259, 0x47296963, 0x3a84372, 0xa50054d9, 0xe6bee465, 0x61cb0ecb
	, 0x636a1020, 0xcbf6c04e, 0x800115f8, 0x681918ee, 0x93b5c52f, 0x9d9b3247, 0x8fe2fa4d, 0xb3b91053
	, 0x96df8a7, 0x4f31570f, 0x3d9ec2ca, 0x7b3d2143, 0xf6de9586, 0x4dab36bb, 0xae7d4da4, 0xb0ec5204
	, 0x516c897e, 0x10dfc8b0, 0x93d96b70, 0xf1356d47, 0xb814a7be, 0x8f91dec6, 0xc09d9b53, 0xc011c399
	, 0x4c490999, 0x48837213, 0x91fc8ecf, 0xdd52e929, 0x72bfe43a, 0x56d21c89, 0xb00d6fb5, 0xb051387e
	, 0xec06f37e, 0xf656c31d, 0xc5fdadbb, 0xb7e240f2, 0x41392f7b, 0x96816c0, 0x4adf300f, 0xc43ca9a1
	, 0x72274745, 0xce716389, 0x1067b993, 0x2ba84870, 0x1b200d81, 0x47579111, 0x7d503172, 0x8148e934
	, 0x2524c959, 0xab2f848b, 0xf5e0166f, 0x7e6bf962, 0xb7c3dfed, 0x60a6307b, 0xa95bd97, 0xba3741d6
	, 0xa5f58da8, 0x13679565, 0x26c798a9, 0x453d5252, 0x1e11491c, 0x61d6677a, 0x7e03a120, 0xdf9b9ded
	, 0xb2491b54, 0xfda7e210, 0x1f976bda, 0xe335bccd, 0xfd56cda0, 0xeeb8dbda, 0x41fc5c73, 0xcc1b1ec0
	, 0x7398cbfd, 0x753cc63e, 0xcbb7488c, 0xc189d7f8, 0xd09c752e, 0x8dee65e9, 0xb6a48f3d, 0x337fdcc
	, 0x3abeead9, 0x45526246, 0x71215d1c, 0xc5281c50, 0x6253abf2, 0xf68c0ff9, 0x1f3149bb, 0x4517ddcd
	, 0x349ed61c, 0x59e0074c, 0xba591708, 0xcba353a8, 0xd592f3f8, 0x94add882, 0x9bc1cf42, 0xcf99b2ff
	, 0xfc77d224, 0xcb66426d, 0x108336f8, 0xcf272370, 0x42e65d24, 0xdb596f19, 0x63bf9988, 0x1e7f684e
	, 0xff7357a, 0xcf7ac7bd, 0x1f029024, 0x76ce42cd, 0x34709d55, 0xb7ab4e4c, 0x837917b, 0x119996b8
	, 0xd1467ec7, 0x5324915e, 0x5145d3de, 0x398568b0, 0x73932d9f, 0x7edaa43e, 0x69e83ed, 0x8405a0b2
	, 0x7fa82432, 0x70df925a, 0x3f2647e7, 0xca3a372d, 0x48376b4f, 0x25e5d2cf, 0x6a34128b, 0xb73d9b41
	, 0x9ee29c7b, 0xfb0fe094, 0xad13a268, 0xd340b8dd, 0x5c60b030, 0x2d2b0063, 0x82ee5333, 0x8edde880
	, 0x886ac0e4, 0x25c4e956, 0x4b0f8b8b, 0x10463016, 0xa21cd70, 0xe47a6d6, 0x7b28760a, 0xe389dc86
	, 0x413686a0, 0x6c1cdc0, 0xdb4b8db2, 0x715d3288, 0xb9478850, 0xd87f2d71, 0x48bed751, 0xac59cccf
	, 0x9def026a, 0xfbd2d74d, 0x70247b68, 0xc4cf75e7, 0x81fb0145, 0x96ccb859, 0xf3232f2c, 0xa7d4f7d0
	, 0x3b9fd60b, 0x60afadf1, 0x3083797, 0x574b1d9, 0x6374b26b, 0xd5548b4e, 0x52d56e82, 0xa47b1269
	, 0x993949d2, 0x3e9d1991, 0x75a55c9a, 0x522dec8c, 0x5cf91c69, 0xb4875963, 0x296398a2, 0xd972e4ef
	, 0x41b654e6, 0x86138bc0, 0x60016d5c, 0xadc89a97, 0x87847dd, 0x5e4f30b8, 0xb29b30d, 0x2f8c661
	, 0xf1445a6e, 0xc9238ebe, 0x5ccdde96, 0x8045a663, 0x2caa83ee, 0x7acc384, 0xb284d405, 0x3068b310
	, 0xbc817d90, 0x94f861a, 0x6d4fea0f, 0xd2824f44, 0x9a563487, 0x5ca36a48, 0xeef17863, 0x85fe573
	, 0x79ed9eb8, 0x2fe355e8, 0x4339e35d, 0x260bae, 0x260bae00, 0x890bfb52, 0x403e42e1, 0xac49177
	, 0xeb1ba1d6, 0xf5433b18, 0xdd468e62, 0x66d8af3a, 0x6e8cb125, 0x1c9a439d, 0xe35edd14, 0x963714a0
	, 0x88fd62c, 0xa9dec1b8, 0xd271e01, 0x16d387d3, 0x851045c2, 0x6e8c4985, 0x1c62e39d, 0x1bfedd14
	, 0x99870411, 0x80d0da91, 0xb9d671ee, 0x49869371, 0x90dcf178, 0xf9ec439e, 0x47329306, 0x18522672
	, 0x383f44c8, 0xcd7e4828, 0x120f3e4a, 0x4aadaa1e, 0xb6a6b8a1, 0x10061cc, 0x4a0d1b7, 0xb3d5c1dc
	, 0x65bc77a7, 0x7170afc, 0x94dac05, 0x6f65f50f, 0xf11f742a, 0x920dcabe, 0x2155bef0, 0xc95c5b57
	, 0x23183796, 0x8d570639, 0xfc75f3d, 0xff1080bd, 0xa177fdb4, 0x8213ffb9, 0x73716280, 0x9c95bb3e
	, 0x85aa9efa, 0xd4577185, 0x55eeb835, 0x81eaf56c, 0x87389159, 0x4fdae9eb, 0xd62026ca, 0x2b3bcc5b
	, 0x88a42681, 0xeb228c56, 0xcc6ebb18, 0x63d13fd, 0x2795b0b2, 0x13d454e5, 0x950618a9, 0x34c0f9f5
	, 0x7cfee4c, 0xd1a91c05, 0xbc46535e, 0xce61481a, 0x4c2a93, 0x4c2a9300, 0x2b19eb13, 0xaa836e81
	, 0x5dcb01d8, 0x825bf5d4, 0x3b7b0f80, 0x847626f1, 0xc2e6732, 0x1b6ba964, 0xcf37411, 0xc6788a64
	, 0x3f86b92b, 0x6ac4fb2d, 0x47d43d41, 0xfefc6172, 0x49572f03, 0x41608378, 0x50c415c0, 0xbc826b07
	, 0xa59111a, 0x769bccd6, 0x61fe8655, 0x56e28e20, 0x809fc6b5, 0xf6ca55ee, 0x596b5ebb, 0x3100e008
	, 0xd0137827, 0x2e36ce9, 0xeaeed26e, 0x4f19eaf, 0xe29ad9dc, 0x56f2c117, 0x90d0f1b5, 0xf5ec8e9e
	, 0x72f30862, 0x1a3e4489, 0x5ddf84a6, 0x96de8bd4, 0xe110a22c, 0xd1ca17ce, 0xdf4d985e, 0x644ca854
	, 0xf309e44b, 0x8d1f90d0, 0x4751b63d, 0x7b771d72, 0xbce2a486, 0x6a96901a, 0x15bf0a41, 0xe4def11b
	, 0x85c4ba5, 0x7a4348b8, 0x8c767331, 0x2a734a8a, 0xc4e3ea36, 0xad64d045, 0xa43295dd, 0xd0befdd2
	, 0xaf6699e9, 0xaff902b3, 0x306258b3, 0xb66ade90, 0xcd6650cc, 0xa17da4a, 0x38509cd6, 0xa2a65628
	, 0x5efb4560, 0xbf5c6b0d, 0xd91a3dc3, 0x296f78e6, 0xd592a0ef, 0x94fecf82, 0xc8d6cf42, 0xad4d3f21
	, 0x8dddf1dd, 0x8530bb3d, 0x4e72b685, 0x7abe557d, 0x716bb631, 0x8fc33150, 0x92720d53, 0x5e9253f0
	, 0xd64afb0d, 0x41e60b5b, 0xd64c36c0, 0x472bc65b, 0x1077b72, 0x3ba6fb7, 0xb72c91d9, 0x8fe8047b
	, 0xb9472653, 0xd8d12e71, 0xe6bdd751, 0x62f83acb, 0x5d1d36f9, 0x546cd4d4, 0x74709db, 0x594e8b05
	, 0x14d55e08, 0x8a4ba5ac, 0xd239a38, 0x1257bed3, 0x122d331e, 0x68a0fe1e, 0x2a53352f, 0xe49c4f36
	, 0x4ae266a5, 0xf96a03a1, 0xc172ac06, 0x2be78b2e, 0x54e35381, 0x88c05cdb, 0x8f58d656, 0x9950b53
	, 0xb7c2a30f, 0x61dad27b, 0x72b6a020, 0x5f960689, 0xd6de9fba, 0xd582bc5b, 0x84e27b82, 0x98731432
};

// Similar to above, but index is the size of the padding / 1024.
static uint32_t iccom_crc32_padding_crc_1k[16] = {
	  0x0, 0x5b0af1ea, 0x87d6bd73, 0x4a8fc65b, 0xd8e6126c, 0x75ec88ee, 0xc2c2ecca, 0x35d4b7b1
	, 0x85b5bb36, 0x2a42672f, 0x184ceb35, 0xeadc45d6, 0xa930cbde, 0x8758d429, 0x81425d7, 0x460f4508
};
// Similar to above, but index is the size of the padding / 1024.
static uint32_t iccom_crc32_msg_factor_1k[16] = {
	  0x1, 0x7001e426, 0x75de2b2, 0xbd25e2c6, 0xf12a7f90, 0x64a0dc49, 0x4202b4aa, 0x224843c6
	, 0xf0b4a1c1, 0xe38d94b2, 0xc359f472, 0xdec1b332, 0xa662ad27, 0x3ad145be, 0x4f454569, 0x4b12ca52
};

// Similar to above, but index is the size of the padding / (1024*16).
static uint32_t iccom_crc32_padding_crc_16k[16] = {
	  0x0, 0xaaa7fa43, 0xd8683a58, 0xd2c5317a, 0xa50f3c90, 0x70eda4e6, 0x90c932ca, 0x898a325e
	, 0x807305d6, 0xf6876329, 0x8d179886, 0xf062a7e0, 0x4b4c2a27, 0x81fd5142, 0x97841c95, 0xf9b99519
};
// Similar to above, but index is the size of the padding / (1024*16).
static uint32_t iccom_crc32_msg_factor_16k[16] = {
	  0x1, 0x58f46c0c, 0xc3395ade, 0x573ace37, 0x96837f8c, 0x2f064eb3, 0xd0a28234, 0xa25578a3
	, 0x544037f9, 0x962f9ec6, 0x5eaf5387, 0xa783dc67, 0xad081968, 0xf63a238f, 0x355cb641, 0xd36dc940
};

static const char ICCOM_ERROR_S_NOMEM[] = "no memory available";
static const char ICCOM_ERROR_S_TRANSPORT[]
	= "Xfer failed on transport layer. Restarting frame.";

// Serves to allocate unique ids for
// creating iccom platform devices trough
// the usage of sysfs interfaces
struct ida iccom_dev_id;

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

// Computes ISO HDLC CRC32 on the given data.
//
// NOTE: uses the lookup table of the size of 16 to make a better use
//		of data cache (in comparison with 256 bytes, for example).
//
// @data {valid data ptr if size > 0, otherwise any}
// @size_bytes {size of data in bytes && >= 0}
//
// SEE ALSO: https://en.wikipedia.org/wiki/Cyclic_redundancy_check
//           https://www.kernel.org/doc/Documentation/crc32.txt
static inline uint32_t __iccom_compute_iso_hdlc_crc32(
		uint8_t *data, size_t size_bytes)
{
	uint32_t crc = 0xFFFFFFFF;

	while (size_bytes > 0) {

		crc = (crc >> 4) ^ iccom_crc32_lookup_tbl_4bit_refl[(crc ^ (*data)) & 0x0F];
		crc = (crc >> 4) ^ iccom_crc32_lookup_tbl_4bit_refl[(crc ^ ((*data) >> 4)) & 0x0F];

		data++;
		size_bytes--;
	}

	return ~crc;
}

// Reflects the bit order of the value in log time.
uint32_t __iccom_reflect_int32(uint32_t val)
{
	uint32_t mask = 0xffff0000;
	val = ((val & mask) >> 16) | ((val & (~mask)) << 16);
	mask = 0xff00ff00;
	val = ((val & mask) >> 8) | ((val & (~mask)) << 8);
	mask = 0xf0f0f0f0;
	val = ((val & mask) >> 4) | ((val & (~mask)) << 4);
	mask = 0xcccccccc;
	val = ((val & mask) >> 2) | ((val & (~mask)) << 2);
	mask = 0xaaaaaaaa;
	val = ((val & mask) >> 1) | ((val & (~mask)) << 1);
	return val;
}

// Divides the int64 by the poly defined in the external
// table (currently ISO HDLC CRC32).
static inline uint32_t __iccom_gf_divide_int64_fast_key4(
		const uint32_t hi, const uint32_t lo)
{
	uint32_t curr = 0;

	uint32_t val = hi;

	for (int i = 0; i < 2; i++) {
		curr = iccom_crc32_lookup_tbl_4bit[(curr >> 28) & 0x0f]
					^ ((curr << 4) | ((val >> 28) & 0x0f));
		curr = iccom_crc32_lookup_tbl_4bit[(curr >> 28) & 0x0f]
					^ ((curr << 4) | ((val >> 24) & 0x0f));
		curr = iccom_crc32_lookup_tbl_4bit[(curr >> 28) & 0x0f]
					^ ((curr << 4) | ((val >> 20) & 0x0f));
		curr = iccom_crc32_lookup_tbl_4bit[(curr >> 28) & 0x0f]
					^ ((curr << 4) | ((val >> 16) & 0x0f));
		curr = iccom_crc32_lookup_tbl_4bit[(curr >> 28) & 0x0f]
					^ ((curr << 4) | ((val >> 12) & 0x0f));
		curr = iccom_crc32_lookup_tbl_4bit[(curr >> 28) & 0x0f]
					^ ((curr << 4) | ((val >>  8) & 0x0f));
		curr = iccom_crc32_lookup_tbl_4bit[(curr >> 28) & 0x0f]
					^ ((curr << 4) | ((val >>  4) & 0x0f));
		curr = iccom_crc32_lookup_tbl_4bit[(curr >> 28) & 0x0f]
					^ ((curr << 4) | ((val >>  0) & 0x0f));

		val = lo;
	}

	return curr;
}

// Galois Field multiplication of two int32 values.
// @a, @b the numbers (polynoms) to multiply.
// @hi_out, @lo_out the ptrs to store the resulting poly hi and lo parts.
static inline void __iccom_gf_multiply_int32(
		uint32_t a, uint32_t b
		, uint32_t *hi_out, uint32_t *lo_out)
{
	uint32_t res_lo = 0x0;
	uint32_t res_hi = 0x0;

	for (int i = 0; i < 32; i++) {
		if (a == 0) {
			break;
		}
		if (a & 0x1) {
			res_lo ^= b << i;
			// NOTE: this `if` is needed for x86 and similar platforms
			//	which perform the shift in terms of modulo of the register
			//	size. For ARM, for example b >> 32 == 0, this is exactly the
			//	thing needed here, while on x86 it will result into a shift
			//	by 32 mod 32 = 0 bits, which will result in b >> 32 == b (which
			//	is not needed here).
			if (i) {
				res_hi ^= b >> (32 - i);
			}
		}
		a >>= 1;
	}

	*hi_out = res_hi;
	*lo_out = res_lo;
}

// The computation of the ISO HDLC CRC32 of the data concatenated
// with padding of given size.
//
// NOTE: the exact padding value is used only in the lookup tables
//		generation, so not explicitly stated here. Original padding
//		value, used for the tables generation is 0xff.
uint32_t __iccom_compute_crc32_iso_hdlc_padding_optimized(
	uint8_t *data, const size_t size_bytes
	, size_t padding_size)
{
	const uint32_t xor_out = 0xffffffff;
	// something one can not avoid, just compute crc32 of useful payload
	const uint32_t ai = __iccom_compute_iso_hdlc_crc32(data, size_bytes);

	uint32_t a = __iccom_reflect_int32(ai ^ xor_out);
	uint32_t b;
	uint32_t f;
	size_t step_size;
	uint32_t res_hi;
	uint32_t res_lo;

	while (padding_size) {

		if (padding_size < ARRAY_SIZE(iccom_crc32_padding_crc)) {
			b = iccom_crc32_padding_crc[padding_size];
			f = iccom_crc32_msg_factor[padding_size];
			step_size = padding_size;
		} else if (padding_size < ARRAY_SIZE(iccom_crc32_padding_crc_1k) * 1024) {
			const uint32_t idx = padding_size / 1024;
			b = iccom_crc32_padding_crc_1k[idx];
			f = iccom_crc32_msg_factor_1k[idx];
			step_size = idx * 1024;
		} else {
			const uint32_t idx = padding_size / (16 * 1024);
			b = iccom_crc32_padding_crc_16k[idx];
			f = iccom_crc32_msg_factor_16k[idx];
			step_size = idx * (1024 * 16);
		}
		
		__iccom_gf_multiply_int32(a, f, &res_hi, &res_lo);
		res_lo ^= b;

		a = __iccom_gf_divide_int64_fast_key4(res_hi, res_lo);
		padding_size -= step_size;
	}

	// And here we recover the reflection and xor on top of the out.
	return (__iccom_reflect_int32(a) ^ xor_out);
}

/* --------------------- RAW PACKAGE MANIPULATION -----------------------*/

// Helper. Gets the size of package overall payload space even it is
// already occupied with some payload.
// See @iccom_package description.
static inline size_t __iccom_package_payload_room_size(
		struct iccom_package *package)
{
	return package->size
		- ICCOM_PACKAGE_HEADER_SIZE_BYTES
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
		struct iccom_package *package, uint8_t id)
{
	*(package->data
		+ ICCOM_PACKAGE_PAYLOAD_DATA_LENGTH_FIELD_SIZE_BYTES) = id;
}

// Helper. Gets the package ID. See @iccom_package description.
static inline uint8_t __iccom_package_get_id(struct iccom_package *package)
{
	return (uint8_t)(*(package->data
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
	const size_t payload_size = __iccom_package_payload_size(package, NULL);
	const size_t padding_size = __iccom_package_payload_room_size(package) - payload_size;

	// NOTE: due to (almost) guaranteed cache miss for big table
	//		access it is reasonable to deploy concatenation
	//		mechanics only when padding is not less than some value.
	const uint32_t OPTIMIZED_COMPUTE_THRESHOLD_SIZE = 16;
	if (padding_size < OPTIMIZED_COMPUTE_THRESHOLD_SIZE) {
		return __iccom_compute_iso_hdlc_crc32(package->data
			, package->size - ICCOM_PACKAGE_CRC_FIELD_SIZE_BYTES);
	}

	if (payload_size > __iccom_package_payload_room_size(package)) {
		// if we here, it is logical error
		return 0;
	}

	return __iccom_compute_crc32_iso_hdlc_padding_optimized(
				package->data, ICCOM_PACKAGE_HEADER_SIZE_BYTES + payload_size
				, padding_size);
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
	package = NULL;
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
		, const char *packet_payload, const size_t payload_size_bytes
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
		msg->data = NULL;
	}
	kfree(msg);
	msg = NULL;
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

	channel_rec->total_msgs_rcv = 0;
	channel_rec->total_consumer_bytes_rcv = 0;

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
	channel_rec = NULL;

	return;
}

// Clones an iccom message and returns
// the new iccom message which has been
// allocated within this function.
//
// NOTE: The ownership of iccom_message received remains
//       in the caller. This function allocates a new
//       iccom_message, copies the received iccom_message
//       content and returns the pointer to the newly
//       allocate iccom_message which the caller must free
//       when not needed anymore.
//
// @src {valid prt} iccom message to be copied
//
// RETURNS:
//  != NULL: pointer to newly created iccom_message
//     NULL: Failed to clone
struct iccom_message * __iccom_message_data_clone(
		struct iccom_message *src)
{
	if (IS_ERR_OR_NULL(src)) {
		iccom_err("Iccom message is null cannot clone.");
		return NULL;
	}
	struct iccom_message *dst = (struct iccom_message *)
					kmalloc(sizeof(struct iccom_message), GFP_KERNEL);
	if (IS_ERR_OR_NULL(dst)) {
		iccom_err("No memory to create iccom message.");
		return NULL;
	}

	dst->data = (uint8_t *) kzalloc(src->length, GFP_KERNEL);

	if (IS_ERR_OR_NULL(dst->data)) {
		iccom_err("No memory to create the data within iccom message.");
		kfree(dst);
		dst = NULL;
		return NULL;
	}

	memcpy(dst->data, src->data, src->length);
	dst->length = src->length;
	dst->channel = src->channel;
	dst->id = src->id;
	dst->priority = src->priority;
	dst->finalized = src->finalized;
	dst->uncommitted_length = src->uncommitted_length;

	return dst;
}

// Stores an iccom message for a particular sysfs
// channel. This message can be fetched by userspace.
//
// NOTE: This function handles on its own the lock and unlock
//       of the sysfs mutex.
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
// @ch_id {number} ICCom logical channel ID
// @msg {valid prt} iccom message contaning
// the message received to the upper layer
//
// RETURNS:
//       0: ok
// -EINVAL: iccom device private data broken, iccom_message
//          length is 0 or failed to enqueue message
// -EFAULT: iccom_message or its data is null or clone
//          of iccom_message failed
// -ENODEV: Iccom device is null
// -ENOBUFS: List with all sniffed iccom_messages has reached
//            the maximum allowed number
ssize_t iccom_test_sysfs_ch_enqueue_msg(
		struct iccom_dev *iccom, unsigned int ch_id,
		struct iccom_message *msg)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);
	ICCOM_CHECK_PTR(msg, return -EFAULT);
	ICCOM_CHECK_PTR(msg->data, return -EFAULT);

	ssize_t error_result;
	bool enqueue_msg_status = false;

	if (msg->length == 0) {
		iccom_err("Sysfs iccom message data size is 0");
		return -EINVAL;
	}

	struct iccom_test_sysfs_channel *ch_entry = NULL, *tmp = NULL;

	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_for_each_entry_safe(ch_entry, tmp,
				&iccom->p->sysfs_test_ch_head , list_anchor) {
		if (ch_entry->ch_id != ch_id) {
			continue;
		}
		if (ch_entry->num_msgs >= ICCOM_SYSFS_MAX_MSG_ALLOWED_PER_CHANNEL) {
			iccom_err("Discarding sysfs message for channel %d", ch_id);
			error_result = -ENOBUFS;
			goto finalize;
		}

		struct iccom_message * msg_cloned = __iccom_message_data_clone(msg);
		if (IS_ERR_OR_NULL(msg_cloned)) {
			error_result = -EFAULT;
			goto finalize;
		}

		list_add(&msg_cloned->list_anchor, &ch_entry->ch_msgs_head);
		ch_entry->num_msgs++;
		enqueue_msg_status = true;
		break;
	}

	mutex_unlock(&iccom->p->sysfs_test_ch_lock);

	if (!enqueue_msg_status)	{
		iccom_err("Sysfs channel not found %d. Not stored msg.", ch_id);
		return -EINVAL;
	}
	return 0;

finalize:
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);
	return error_result;
}

// ICCom callback called whenever there is a new sniffed iccom_message
// in the iccom device for a particular sysfs channel
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
// @channel {number} number of the channel
// @msg {valid ptr} iccom_message with the data
static void iccom_test_sysfs_ch_callback(
		struct iccom_dev *iccom, unsigned int channel,
		struct iccom_message *msg)
{
#ifdef ICCOM_DEBUG
	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, ICCOM_LOG_PREFIX
			"Sniffed iccom message for ch: %d.", channel);
	print_hex_dump(KERN_INFO, "with data: ", 0, 16
			, 1, msg->data, msg->length, true);
#endif

	if (iccom_test_sysfs_ch_enqueue_msg(iccom, channel, msg) != 0) {
		iccom_err("Failed to store iccom message for channel %d",
			channel);
	}
}

// Checks whether sysfs channel has been created
// in the channels list
//
// NOTE: The caller must lock and unlock the sysfs mutex
//       as this function does not handle that on its own.
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
// @ch_id {number} ICCom logical channel ID
//
// RETURNS:
//      true: channel already exists
//      false: channel does not exists or
//             iccom device or iccom device
//             private data are NULL
bool iccom_test_sysfs_is_ch_present(
		struct iccom_dev *iccom, unsigned int ch_id)
{
	ICCOM_CHECK_DEVICE("no device provided", return false);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return false);

	bool ch_present = false;

	struct iccom_test_sysfs_channel *ch_entry = NULL, *tmp = NULL;

	list_for_each_entry_safe(ch_entry, tmp,
			&iccom->p->sysfs_test_ch_head, list_anchor) {
		if (ch_entry->ch_id == ch_id) {
			ch_present = true;
			break;
		}
	}
	return ch_present;
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

	// NOTE: The sysfs channel present must be verified
	//       before we lock the storage->lock mutex as
	//       otherwise two different mutex will lock anw may
	//       collide and provoke an unwanted deadlock.
	mutex_lock(&storage->iccom->p->sysfs_test_ch_lock);

	const bool iccom_test_sysfs_channel_present =
		iccom_test_sysfs_is_ch_present(storage->iccom,
						 channel_rec->channel);

	mutex_unlock(&storage->iccom->p->sysfs_test_ch_lock);

	mutex_lock(&storage->lock);
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

		if (iccom_test_sysfs_channel_present) {
			iccom_test_sysfs_ch_callback(
				storage->iccom, channel_rec->channel, msg);
		}

		if (!IS_ERR_OR_NULL(msg_ready_callback) &&
				!IS_ERR_OR_NULL(callback_consumer_data)) {
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
		channel_rec->total_consumer_bytes_rcv += msg->uncommitted_length;
		msg->uncommitted_length = 0;
		if (msg->finalized) {
			channel_rec->total_msgs_rcv++;
		}
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
			channel_rec = NULL;
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
	atomic_set(&storage->uncommitted_finalized_count, 0);
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
	old_data = NULL;

	if (final) {
		msg->finalized = true;
		atomic_add(1, &storage->uncommitted_finalized_count);
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
	atomic_set(&storage->uncommitted_finalized_count, 0);
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
	atomic_set(&storage->uncommitted_finalized_count, 0);
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
	return atomic_read(&storage->uncommitted_finalized_count);
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
// Closes the consumer-delivery workqueue.
// If we use system-provided workqueue - does nothing.
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
// Schedules the work on consumer-delivery workqueue.
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
static uint8_t __iccom_get_next_package_id(struct iccom_dev *iccom)
{
	// we wrap up uint8_t, as designed
	return iccom->p->next_tx_package_id++;
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
				       , ICCOM_DEFAULT_DATA_XFER_SIZE_BYTES);
	if (res < 0) {
		iccom_err("no memory for new package");
		kfree(new_package);
		new_package = NULL;
		return res;
	}

	__iccom_package_set_id(new_package, __iccom_get_next_package_id(iccom));

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
	__iccom_package_set_id(delivered_package, __iccom_get_next_package_id(iccom));
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
			       , const char *data, const size_t length
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
		msg = NULL;
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
	atomic_long_add(finalized,
			&iccom->p->statistics.messages_ready_in_storage);

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
		const uint8_t rx_pkg_id = __iccom_package_get_id(&rx_pkg);
		if ((int)rx_pkg_id == iccom->p->last_rx_package_id) {
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
		iccom->p->last_rx_package_id = (int)rx_pkg_id;
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

// Stops the underlying byte xfer device.
void __iccom_stop_xfer_device(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("no device provided", return);
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return);
	ICCOM_CHECK_PTR(&iccom->xfer_iface.close, return);

	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL, "Stopping transport dev");
	iccom->xfer_iface.close(iccom->xfer_device);
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL, "Stopped transport dev");
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
		atomic_long_add(-passed,
			&iccom_p->statistics.messages_ready_in_storage);
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

// Helper. Initializes the statistics structure of ICCom.
// NOTE: the ICCom sysfs should be created beforehand
static inline void __iccom_statistics_init(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("", return);
	ICCOM_CHECK_DEVICE_PRIVATE("", return);

	// initial statistics data
	iccom->p->statistics.transport_layer_xfers_done_count = 0;
	iccom->p->statistics.raw_bytes_xfered_via_transport_layer = 0;
	iccom->p->statistics.packages_xfered = 0;
	iccom->p->statistics.packages_sent_ok = 0;
	iccom->p->statistics.packages_received_ok = 0;
	iccom->p->statistics.packages_bad_data_received = 0;
	iccom->p->statistics.packages_duplicated_received = 0;
	iccom->p->statistics.packages_parsing_failed = 0;
	iccom->p->statistics.packets_received_ok = 0;
	iccom->p->statistics.messages_received_ok = 0;
	iccom->p->statistics.packages_in_tx_queue = 0;
	iccom->p->statistics.total_consumers_bytes_received_ok = 0;
	atomic_long_set(&iccom->p->statistics.messages_ready_in_storage, 0);
}

// Handles the iccom ctl channel messages. Those messages
// include protocol negotiations messages, embedded
// ack messages, etc..
//
// @channel must always be ICCOM_CTL_CHANNEL.
// @consumer_data points to iccom_dev.
static bool __iccom_ctl_msg_handler(unsigned int channel
				, void *msg_data, size_t msg_len
				, void *consumer_data)
{
	// here the ctl handling logic shall be
	return false;
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
		, const char *data, const size_t length
		, unsigned int channel
		, unsigned int priority)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return -ENODEV);
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

	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
			, "sending data: ch. %d, size: %zu"
			, channel, length);

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
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return -ENODEV);
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
//		NOTE: the ICCOM_CTL_CHANNEL is reserved for the internal
//			ICCom communications, it will not be possible to use it
//			from outside of the ICCom.
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
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return -ENODEV);
	ICCOM_CHECK_CHANNEL("bad channel", return -EBADSLT);
	ICCOM_CHECK_CLOSING("will not invoke", return -EBADFD);
	if (IS_ERR(message_ready_callback)) {
		iccom_err("broken callback pointer provided");
		return -EINVAL;
	}
	if (channel == ICCOM_CTL_CHANNEL) {
		iccom_err("channel %d is reserved for iccom internal ctl messages"
				  " so, can not assign a custom callback to it"
				  , ICCOM_CTL_CHANNEL);
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
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return -ENODEV);
	ICCOM_CHECK_CHANNEL("bad channel", return -EBADSLT);
	ICCOM_CHECK_CLOSING("will not invoke", return -EBADFD);
	if (channel == ICCOM_CTL_CHANNEL) {
		iccom_err("channel %d is reserved for iccom internal ctl messages"
				  " so, can not remove it's callback"
				  , ICCOM_CTL_CHANNEL);
		return -EINVAL;
	}
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
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return ERR_PTR(-ENODEV));
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
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return -ENODEV);
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

	atomic_long_add(-1,
			&iccom->p->statistics.messages_ready_in_storage);

	*msg_data_ptr__out = msg->data;
	*buf_size__out = msg->length;
	if (!IS_ERR_OR_NULL(msg_id__out)) {
		*msg_id__out = msg->id;
	}

	kfree(msg);
	msg = NULL;
	return 0;
}

// Binds the underlying full duplex transport with ICCom.
//
// @iccom_dev {valid ptr} pointer to ICCom device structure.
// @full_duplex_if {valid ptr to full_duplex_sym_iface struct} points
//      to valid and filled with correct pointers full_duplex_sym_iface
//      struct
// @full_duplex_device {valid ptr to fd device} points to the full
//      duplex device structure,which is ready to be used
//      with full_duplex_if->init(...) call.
//
// RETURNS:
//        0: Bind sucessfull
//		  <0: negated error code on failure
int __iccom_bind_xfer_device(struct device *iccom_dev
		, const struct full_duplex_sym_iface *const full_duplex_if
		, struct device *full_duplex_device)
{
	ICCOM_CHECK_PTR(iccom_dev, return -ENODEV);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(iccom_dev);

	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_PTR(full_duplex_device, return -ENODEV);

	if (!__iccom_verify_transport_layer_interface(full_duplex_if)) {
		iccom_err("Not all relevant interface methods are defined");
		return -EINVAL;
	}

	struct device_link *link_downwards = device_link_add(iccom_dev
									, full_duplex_device
									, ICCOM_TRANSPORT_LINK_FLAGS);

	if (IS_ERR_OR_NULL(link_downwards)) {
		iccom_err("Unable to create link to transport device %s"
					, dev_name(full_duplex_device));
		return -EFAULT;
	}

	iccom->xfer_device = (void*)full_duplex_device;
	iccom->xfer_iface = *full_duplex_if;

	return 0;
}

// Unbinds iccom device from current transport device and
// it's interface.
//
// NOTE: condition for execution, that device is not in use already
//    (was already stopped).
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
void __iccom_unbind_xfer_device(struct iccom_dev *iccom)
{
	struct device *old_xdev = iccom->xfer_device;
	iccom->xfer_device = NULL;
	memset(&iccom->xfer_iface, 0, sizeof(struct full_duplex_sym_iface));
	if (!IS_ERR_OR_NULL(old_xdev)) {
		device_link_remove(&iccom->p->pdev->dev, old_xdev);
		iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, "unbound from transport");
	}
}

// API
//
// Deletes the iccom_dev structure via device removing.
// When an iccom device get's removed iccom_delete is
// called to do the cleanup.
//
// @iccom {valid ptr} pointer to corresponding iccom_dev structure.
// @pdev {valid ptr} accociated platform device.
//
// NOTE: caller should never invoke ICCom methods on struct iccom_dev
// which after this method is called.
//
// CONCURRENCE: caller should ensure that no one of iccom_init(...),
//      iccom_delete(...) will be called under data-race conditions
//      with the same struct iccom_dev.
//
// CONTEXT: sleepable
//
// RETURNS:
//      0 on success
//      negative error code on error
__maybe_unused
void iccom_delete(struct iccom_dev *iccom, struct platform_device *pdev)
{
	ICCOM_CHECK_DEVICE("no device provided", return);
	ICCOM_CHECK_DEVICE_PRIVATE("broken private device part ptr", return);
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return);
	ICCOM_CHECK_PTR(pdev, return);

	// only one close sequence may run at the same time
	// turning this flag will block all further external
	// calls to given ICCom instance
	int expected_state = 0;
	int dst_state = 1;
	if (atomic_cmpxchg(&iccom->p->closing
					, expected_state, dst_state) != expected_state) {
		iccom_err("iccom is already closing now");
		return;
	}
	iccom_info_raw(ICCOM_LOG_INFO_OPT_LEVEL
		       , "closing device (%px)", iccom);

	__iccom_stop_xfer_device(iccom);
	__iccom_unbind_xfer_device(iccom);

	__iccom_cancel_work_sync(iccom
			, &iccom->p->consumer_delivery_work);
	__iccom_close_workqueue(iccom);

	dev_set_drvdata(&pdev->dev, NULL);

	// TODO: FIXME
	// Consider the case when consumer has entered some of our
	// method, but have not yet exited, so we may run into condition
	// when we risk to free the data while some method is still
	// working with it. This will lead to crash.

	// Cleanup all our allocated data
	iccom_msg_storage_free(&iccom->p->rx_messages);
	__iccom_queue_free(iccom);

	iccom_test_sysfs_ch_del(iccom);
	mutex_destroy(&iccom->p->sysfs_test_ch_lock);

	iccom->p->pdev = NULL;
	iccom->p->iccom = NULL;
	kfree(iccom->p);
	iccom->p = NULL;
}

// API
//
// Initializes the iccom_dev structure via device probing.
// When an iccom device get's probed iccom_init is called.
//
// @iccom {valid ptr} iccom device to be initialized
// @pdev {valid pdev ptr} a vailid pointer to the platform
//		device to get accociated with.
//
// If this call succeeds, it is possible to use all other iccom
// methods on initialized iccom struct.
//
// NOTE: caller should never invoke ICCom methods on struct iccom_dev
// which init method didn't return with success state (yet).
//
// CONCURRENCE: caller should ensure that no one of iccom_init(...),
//      iccom_delete(...) will be called under data-race conditions
//      with the same struct iccom_dev.
//
// CONTEXT: sleepable
//
// RETURNS:
//      0 on success
//      negative error code on error
__maybe_unused
int iccom_init(struct iccom_dev *iccom, struct platform_device *pdev)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_PTR(pdev, return -EINVAL);

	iccom_info_raw(ICCOM_LOG_INFO_OPT_LEVEL
		       , "creating device (%px)", iccom);

	// initialization sequence
	int res = 0;
	iccom->p = kzalloc(sizeof(struct iccom_dev_private), GFP_KERNEL);
	if (!iccom->p) {
		iccom_err("No memory.");
		res = -ENOMEM;
		goto finalize;
	}
	iccom->p->pdev = pdev;
	iccom->p->iccom = iccom;
	iccom->xfer_device = NULL;
	memset(&iccom->xfer_iface, 0, sizeof(struct full_duplex_sym_iface));

	__iccom_statistics_init(iccom);
	__iccom_error_report_init(iccom);

	res = iccom_msg_storage_init(&iccom->p->rx_messages);
	if (res < 0) {
		iccom_err("Could not initialize messages storage.");
		goto free_private;
	}

	if (iccom_msg_storage_set_channel_callback(
			&iccom->p->rx_messages, ICCOM_CTL_CHANNEL
			, __iccom_ctl_msg_handler , iccom) < 0) {
		iccom_err("Could not register ctl channel clbk.");
		goto free_msg_storage;
	}

	res = __iccom_init_packages_storage(iccom);
	if (res < 0) {
		iccom_err("Could not initialize packages storage.");
		goto unregister_ctl_msgs_handler;
	}

	iccom->p->last_rx_package_id = ICCOM_PACKAGE_HAVE_NOT_RECEIVED_ID;

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

	mutex_init(&iccom->p->sysfs_test_ch_lock);

	res = __iccom_test_sysfs_initialize_ch_list(iccom);

	if (res != 0) {
		iccom_err("Sysfs Channel List initialization failed");
		goto discard_testing_sysfs_mutex;
	}

	dev_set_drvdata(&pdev->dev, iccom);

	atomic_set(&iccom->p->closing, 0);

	return 0;

discard_testing_sysfs_mutex:
	mutex_destroy(&iccom->p->sysfs_test_ch_lock);
free_pkg_storage:
	__iccom_free_packages_storage(iccom);
unregister_ctl_msgs_handler:
	iccom_msg_storage_reset_channel_callback(
		&iccom->p->rx_messages, ICCOM_CTL_CHANNEL);
free_msg_storage:
	iccom_msg_storage_free(&iccom->p->rx_messages);
free_private:
	iccom->p->pdev = NULL;
	kfree(iccom->p);
	iccom->p = NULL;
finalize:
	return res;
}

// API
//
// Starts the iccom device making sure the xfer
// interface is proper and initializes the communication
// with the transport associated
//
// @iccom {valid ptr} managed by consumer. Not to be
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
//      iccom_delete(...) will be called under data-race conditions
//      with the same struct iccom_dev.
//
// CONTEXT: sleepable
//
// RETURNS:
//      0 on success
//      negative error code on error
__maybe_unused
int iccom_start(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return -ENODEV);

	if (!__iccom_verify_transport_layer_interface(
				&iccom->xfer_iface)) {
		iccom_err("Broken transport IF.");
		return -EINVAL;
	}

	// Initializing transport layer and start communication
	int ret = iccom->xfer_iface.init(iccom->xfer_device, &iccom->p->xfer);

	if (ret < 0) {
		iccom_err("Full duplex xfer device failed to"
			  " initialize, err: %d", ret);
	}

	return ret;
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
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return);
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
		       , "MESSAGES: ready in RX storage:\t%ld"
		       , atomic_long_read(&iccom->p->statistics.messages_ready_in_storage));
	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL
		       , "BANDWIDTH: total consumer bytes received OK:\t%llu"
		       , iccom->p->statistics.total_consumers_bytes_received_ok);
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
	ICCOM_CHECK_DEVICE("no device provided", return false);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return false);
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return -ENODEV);
	return true;
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
EXPORT_SYMBOL(iccom_is_running);


// Initializes the sysfs channels list. This list
// shall have all sysfs channels information for a
// particular iccom instance.
//
// NOTE: The caller does not need to lock and unlock the sysfs mutex
//       as this function get's called in the iccom_probe function
//       where the device get's initialized and sysfs is not yet
//       available to be used so no interference with userspace.
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
//
// RETURNS:
//      0: ok
//      <0 - negated error valus if failed
ssize_t __iccom_test_sysfs_initialize_ch_list(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);

	INIT_LIST_HEAD(&iccom->p->sysfs_test_ch_head);
	return 0;
}

// Initializes the sysfs channel msgs list which shall
// hold all the iccom messages associated with a specific
// sysfs channel
//
// NOTE: The caller must lock and unlock the sysfs mutex
//       as this function does not handle that on its own.
//
// @ch_entry {valid prt} sysfs channel entry
void iccom_test_sysfs_init_ch_msgs_list(
		struct iccom_test_sysfs_channel * ch_entry)
{
	ICCOM_CHECK_PTR(ch_entry, return);
	INIT_LIST_HEAD(&ch_entry->ch_msgs_head);
}

// Destroys a sysfs channel and all its containing
// iccom messages stored for the specific sysfs channel
//
// NOTE: The caller must lock and unlock the sysfs mutex
//       as this function does not handle that on its own.
//
// @ch_entry {valid prt} sysfs channel entry
void iccom_test_sysfs_ch_del_entry(
		struct iccom_test_sysfs_channel *ch_entry)
{
	ICCOM_CHECK_PTR(ch_entry, return);

	ch_entry->ch_id = -1;
	ch_entry->num_msgs = 0;

	/* Destroy all msgs from a sysfs channel*/
	struct iccom_message *msg = NULL, *tmp = NULL;

	list_for_each_entry_safe(msg, tmp,
			&ch_entry->ch_msgs_head, list_anchor) {
		__iccom_message_free(msg);
	}

	list_del(&ch_entry->list_anchor);
}

// Destroy all sysfs channels and their iccom
// messages associated with a specific iccom instance.
//
// NOTE: This function handles on its own the lock and unlock
//       of the sysfs mutex.
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
void iccom_test_sysfs_ch_del(struct iccom_dev *iccom)
{
	ICCOM_CHECK_DEVICE("no device provided", return);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return);

	struct iccom_test_sysfs_channel *ch_entry = NULL, *tmp = NULL;

	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_for_each_entry_safe(ch_entry, tmp,
				&iccom->p->sysfs_test_ch_head , list_anchor) {
		iccom_test_sysfs_ch_del_entry(ch_entry);
	}
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);
}

// Extractd an iccom message from a specific sysfs channel
// and remove it from the list for userspace usage
//
// NOTE: The caller must lock and unlock the sysfs mutex
//       as this function does not handle that on its own.
//
// @ch_entry {valid prt} channel where the message
//                       is stored
// @buf__out {ptr valid} pointer where data shall be written to
// @data_size {valid prt} size of the output data that was written
//
// RETURNS:
//    >= 0: ok
//      <0 - negated error valus if failed
ssize_t iccom_test_sysfs_ch_pop_msg(
		struct iccom_test_sysfs_channel *ch_entry, char * buf__out,
		size_t buf_size)
{
	struct iccom_message *msg = NULL, *tmp = NULL;
	list_for_each_entry_safe_reverse(msg, tmp,
				&ch_entry->ch_msgs_head, list_anchor) {
		ssize_t length = msg->length;
		if (length > buf_size) {
			iccom_err("Sysfs channel %d message is bigger"
					" than the buffer", ch_entry->ch_id);
			return -EINVAL;
		}
		ch_entry->num_msgs--;
		memcpy(buf__out, msg->data, length);
		__iccom_message_free(msg);
		return length;
	}

	iccom_err("Sysfs channel %d does not have msgs"
			" to be popped.", ch_entry->ch_id);
	return -EIO;
}

// Routine to retrieve a sysfs channel iccom message
// and provide it to userspace.
//
// NOTE: This function handles on its own the lock and unlock
//       of the sysfs mutex.
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
// @ch_id {number} ICCom logical channel ID
// @buf__out {valid prt} where the data shall be copied to
// @data_size {valid prt} size of data copied
//
// RETURNS:
//    >= 0: ok
//      <0: negated error valus if failed
ssize_t iccom_test_sysfs_ch_pop_msg_by_ch_id(
		struct iccom_dev *iccom, unsigned int ch_id,
		char * buf__out, size_t buf_size)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);

	struct iccom_test_sysfs_channel *cursor = NULL, *tmp = NULL;

	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_for_each_entry_safe(cursor, tmp,
				&iccom->p->sysfs_test_ch_head , list_anchor) {
		if (cursor->ch_id == ch_id) {
			ssize_t result = iccom_test_sysfs_ch_pop_msg(
						cursor, buf__out, buf_size);
			mutex_unlock(&iccom->p->sysfs_test_ch_lock);
			return result;
		}
	}
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);

	iccom_err("Sysfs channel %d not found.", ch_id);
	return -EINVAL;
}

// Adds a sysfs channel for an ICCom device.
//
// NOTE: This function handles on its own the lock and unlock
//       of the sysfs mutex.
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
// @ch_id {number} ICCom logical channel ID
//
// RETURNS:
//      0: ok
//     <0: negated error valus if failed
ssize_t iccom_test_sysfs_ch_add_by_iccom(
		struct iccom_dev *iccom, unsigned int ch_id)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);
	ssize_t ret;

	struct iccom_test_sysfs_channel * iccom_ch_entry = NULL;

	mutex_lock(&iccom->p->sysfs_test_ch_lock);

	if (iccom_test_sysfs_is_ch_present(iccom, ch_id)) {
		ret = -EINVAL;
		goto finalize;
	}

	iccom_ch_entry = kzalloc(sizeof(struct iccom_test_sysfs_channel)
								,GFP_KERNEL);

	if (IS_ERR_OR_NULL(iccom_ch_entry)) {
		iccom_err("No memory to allocate sysfs channel entry.");
		ret = -ENOMEM;
		goto finalize;
	}

	iccom_ch_entry->ch_id = ch_id;
	iccom_ch_entry->num_msgs = 0;
	iccom_test_sysfs_init_ch_msgs_list(iccom_ch_entry);
	list_add(&iccom_ch_entry->list_anchor, &iccom->p->sysfs_test_ch_head);
	ret = 0;

finalize:
	mutex_unlock(&iccom->p->sysfs_test_ch_lock);
	return ret;
}

// Destroys a sysfs channel for an ICCom device
//
// NOTE: This function handles on its own the lock and unlock
//       of the sysfs mutex.
//
// @iccom {valid prt} pointer to corresponding iccom_dev structure.
// @ch_id {number} ICCom logical channel ID
//
//RETURNS
//    0: channel exists and deleted
//   <0: negated error valus if failed
ssize_t iccom_test_sysfs_ch_del_by_iccom(
		struct iccom_dev *iccom, unsigned int ch_id)
{
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);

	struct iccom_test_sysfs_channel *ch_entry = NULL, *tmp = NULL;

	mutex_lock(&iccom->p->sysfs_test_ch_lock);
	list_for_each_entry_safe(ch_entry, tmp, &iccom->p->sysfs_test_ch_head
								, list_anchor) {
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

// Trims a sysfs input buffer coming from userspace
// wich might have unwanted characters
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

// The sysfs version_show function get's triggered
// whenever from userspace one wants to read the sysfs
// file version.
// It shall return git revision that ICCom is at the moment.
//
// @class {valid ptr} iccom class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to write output to user space
//
// RETURNS:
//      0: no data to be displayed
//     > 0: size of data to be showed in user space
//      <0: negated error code
static ssize_t version_show(
		ICCOM_CLASS_MODIFIER struct class *class
		, ICCOM_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, char *buf)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);
	return scnprintf(buf, PAGE_SIZE, "%s", ICCOM_VERSION);
}

static CLASS_ATTR_RO(version);

// The sysfs create_iccom_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file create_iccom.
// It shall create iccom devices with an unique id.
//
// @class {valid ptr} iccom class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//  count: ok
//     <0: negated error code
static ssize_t create_iccom_store(
		ICCOM_CLASS_MODIFIER struct class *class
		, ICCOM_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count)
{
	// Allocate one unused ID
	int device_id = ida_alloc(&iccom_dev_id, GFP_KERNEL);

	if (device_id < 0) {
		iccom_err("Could not allocate a new unused ID");
		return -EINVAL;
	}

	// NOTE: The iccom driver behaves as a bus driver
	//       and therefore devices that get created are owned by
	//       that particular bus. Via Sysfs we have the ability
	//       to manually create HW devices on the bus which need
	//       to be manually deleted later on (the same way they
	//       were created manually) or when the bus get deleted
	struct platform_device *new_pdev =
		platform_device_register_simple("iccom", device_id, NULL, 0);

	if (IS_ERR_OR_NULL(new_pdev)) {
		iccom_err("Could not register the device iccom.%d", device_id);
		ida_free(&iccom_dev_id, device_id);
		return -EFAULT;
	}

	return count;
}

static CLASS_ATTR_WO(create_iccom);

// The sysfs delete_iccom_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file delete_iccom.
// It shall delete the iccom device wich matchs the provided id.
//
// @class {valid ptr} iccom class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//  count: ok
//     <0: negated error code
static ssize_t delete_iccom_store(
		ICCOM_CLASS_MODIFIER struct class *class
		, ICCOM_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count)
{
	if (count >= PAGE_SIZE) {
		iccom_warning("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	// NOTE: count is a length without the last 0-terminator char
	if (buf[count] != 0) {
		iccom_warning("NON-null-terminated string is provided by sysfs.");
		return -EFAULT;
	}

	// Sysfs store procedure has data from userspace with length equal
	// to count. The next byte after the data sent (count + 1) will alwaysfv
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
		kfree(device_name);
		device_name = NULL;
		return -EFAULT;
	}

	(void)iccom_test_sysfs_trim_buffer(device_name, count);

	struct device *iccom_device =
		bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);
	device_name = NULL;

	if (IS_ERR_OR_NULL(iccom_device)) {
		iccom_err("Iccom device is null.");
		return -EFAULT;
	}

	platform_device_unregister(to_platform_device(iccom_device));

	return count;
}

static CLASS_ATTR_WO(delete_iccom);

// List containing all iccom class attributes
//
// @class_attr_version sysfs file for checking
//                     the version of ICCom
// @class_attr_create_iccom sysfs file for creating
//                          iccom devices
// @class_attr_delete_iccom sysfs file for deleting
//                          iccom devices
static struct attribute *iccom_class_attrs[] = {
	&class_attr_version.attr,
	&class_attr_create_iccom.attr,
	&class_attr_delete_iccom.attr,
	NULL
};

ATTRIBUTE_GROUPS(iccom_class);

// The ICCom class definition
//
// @name class name
// @owner the module owner
// @class_groups group holding all the attributes
static struct class iccom_class = {
	.name = "iccom",
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
	.owner = THIS_MODULE,
#endif
	.class_groups = iccom_class_groups
};

// The sysfs transport_show function get's triggered
// whenever from userspace one wants to read the sysfs
// file transport.
// It shall return whether full duplex test transport is
// associated to the iccom device.
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to userspace
//
// NOTE: userspace will receive an empty string ("")
//       whenever there is no full duplex test transport
//       associated. In sucess case it shall return to userspace:
//       "Transport device associated"
//
// RETURNS:
//      0: no transported associated
//    > 0: device is associated
static ssize_t transport_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	// NOTE: Here we return 0 so that the user space receives
	//       an empty string.
	ICCOM_CHECK_DEVICE("no device provided", return 0);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return 0);
	ICCOM_CHECK_XFER_DEVICE("broken xfer device", return 0);

	return scnprintf(buf, PAGE_SIZE, "%s", "Transport device associated");
}

// The sysfs transport_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file transport.
// It shall associate a full duplex test transport device
// to an iccom device, validate the full duplex interface
// and start the iccom communication with the transport.
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer with the data from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//    >=0: transport associated sucessfully
//         and communication started
//     <0: negated error code
static ssize_t transport_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);

	if (count >= PAGE_SIZE) {
		iccom_warning("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	// NOTE: count is a length without the last 0-terminator char
	if (buf[count] != 0) {
		iccom_warning("NON-null-terminated string is provided by sysfs.");
		return -EFAULT;
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

	(void)iccom_test_sysfs_trim_buffer(device_name, count);

	struct device *fd_tt_dev =
		bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);
	device_name = NULL;

	if (IS_ERR_OR_NULL(fd_tt_dev)) {
		iccom_err("Transport platform device %s was not found.", buf);
		return -EFAULT;
	}

	// TODO: FIXME
	// NOTE: such casting is bad and vulnerable, cause in general
	// there is no guarantee, that the transport device actually IS
	// a transport device, so writing the wrong device can easily
	// crash everything. 
	struct full_duplex_device *full_duplex_dev =
		(struct full_duplex_device *) dev_get_drvdata(fd_tt_dev);

	if (IS_ERR_OR_NULL(full_duplex_dev)) {
		iccom_err("The transport device data was not found: %s",
				device_name);
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(full_duplex_dev->iface)) {
		iccom_err("Transport test device data iface is null.");
		return -EFAULT;
	}

	int ret = __iccom_bind_xfer_device(dev, full_duplex_dev->iface, fd_tt_dev);

	if (ret != 0) {
		iccom_err("Iccom transport device binding failed.");
		return ret;
	}

	ret = iccom_start(iccom);
	if (ret < 0) {
		iccom_err("ICCom driver start failed, err: %d", ret);
		goto unbind_transport;
	}

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL
		 , "ICCom dev %s bound to transport %s and started."
		 , dev_name(dev), dev_name(fd_tt_dev));

	return count;

unbind_transport:
	__iccom_unbind_xfer_device(iccom);
	return ret;
}

static DEVICE_ATTR_RW(transport);

// The sysfs statistics_show function get's triggered
// whenever from userspace one wants to read the sysfs
// file statistics.
// It shall return iccom device statistics.
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to userspace
//
// RETURNS:
//      >0: statistics data
//       0: not mapped
//      <0: negated error code
static ssize_t statistics_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -ENODEV);

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
			"messages: ready rx:  %ld\n"
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
			,atomic_long_read(&stats->messages_ready_in_storage)
			,stats->total_consumers_bytes_received_ok);

	return len;
}
static DEVICE_ATTR_RO(statistics);

// Prints info about the current iccom channels.
static ssize_t channels_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -ENODEV);

	size_t len = 0;

	// need to lock storage to get the info
	struct iccom_message_storage *storage = &iccom->p->rx_messages;
	struct iccom_message_storage_channel *channel_rec = NULL;
	mutex_lock(&storage->lock);
	list_for_each_entry(channel_rec, &storage->channels_list
			    , channel_anchor) {
		len += (size_t)scnprintf(buf + len, PAGE_SIZE - len,
				"%d:  I: %llu m %llu b\n"
				, channel_rec->channel
				, channel_rec->total_msgs_rcv
				, channel_rec->total_consumer_bytes_rcv
				);
	}
	atomic_set(&storage->uncommitted_finalized_count, 0);
	mutex_unlock(&storage->lock);

	return len;
}
static DEVICE_ATTR_RO(channels);

// The size of the data package currently used, in bytes
static ssize_t data_package_size_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -ENODEV);

	size_t len = (size_t)scnprintf(buf, PAGE_SIZE,
			"%u\n", ICCOM_DEFAULT_DATA_XFER_SIZE_BYTES);

	return len;
}
static DEVICE_ATTR_RO(data_package_size);

// The sysfs channels_RW_show function get's triggered
// whenever from userspace one wants to read the sysfs
// file channels_RW.
// It shall return the next iccom_message data stored in the
// specific sysfs channel msgs list for the particular iccom device.
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to userspace
//
// RETURNS:
//      >0: iccom_message data
//       0: not mapped
//      <0: negated error code
static ssize_t channels_RW_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);

	unsigned int ch_id = iccom->p->sysfs_test_ch_rw_in_use;

	return iccom_test_sysfs_ch_pop_msg_by_ch_id(iccom, ch_id,
							buf, PAGE_SIZE);
}

// The sysfs channels_RW_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file channels_RW.
// Allows to provide data from userspace to post a new
// iccom_message via iccom_post_message.
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer with the data from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//    >=0: sucessfully executed the command
//     <0: negated error code
static ssize_t channels_RW_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);

	unsigned int ch_id = iccom->p->sysfs_test_ch_rw_in_use;

	iccom_info(ICCOM_LOG_INFO_DBG_LEVEL
			, "data from user via sysfs: ch. %d, size: %zu"
			, ch_id, (size_t)count);

	int ret = iccom_post_message(iccom, buf, (const size_t)count,
						ch_id, 1);

	if (ret < 0) {
		iccom_err("Failed to post message for channel %d with result %d",
				ch_id, ret);
		return ret;
	}

	return count;
}

static DEVICE_ATTR_RW(channels_RW);

// The sysfs channels_ctl_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file channels_ctl.
// Allows to create and destroy sysfs channels as well as
// to set the operating sysfs channel for channels_RW read
// and write operations.
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer with the data from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//    >=0: sucessfully executed the command
//     <0: negated error code
static ssize_t channels_ctl_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	ICCOM_CHECK_PTR(buf, return -EINVAL);

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(dev);

	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);
	ICCOM_CHECK_DEVICE_PRIVATE("broken device data", return -EINVAL);

	char option;
	unsigned int ch_id;
	if (2 != sscanf(buf,"%c%u", &option, &ch_id)) {
		goto wrong_usage;
	}

	if (option == ICCOM_SYSFS_CREATE_CHANNEL) {
		ssize_t ret = iccom_test_sysfs_ch_add_by_iccom(iccom, ch_id);
		if (ret != 0) {
			iccom_err("Adding sysfs channel %d failed", ch_id);
			return ret;
		}
	} else if (option == ICCOM_SYSFS_DELETE_CHANNEL) {
		ssize_t ret = iccom_test_sysfs_ch_del_by_iccom(iccom, ch_id);
		if (ret != 0) {
			iccom_err("Removing sysfs channel %d failed", ch_id);
			return ret;
		}
	}
	else if(option == ICCOM_SYSFS_SET_CHANNEL) {
		iccom->p->sysfs_test_ch_rw_in_use = ch_id;
	} else {
		goto wrong_usage;
	}

	return count;

wrong_usage:
	iccom_err("Sysfs channel ctl format error!\n"
			"xN where x - is one of [%c;%c;%c]\n"
			"(%c - creates debug channel"
			"%c - deletes debug channel"
			"%c - set the debug channel)\n"
			"where N - is the channel number\n",
			ICCOM_SYSFS_CREATE_CHANNEL,
			ICCOM_SYSFS_DELETE_CHANNEL,
			ICCOM_SYSFS_SET_CHANNEL,
			ICCOM_SYSFS_CREATE_CHANNEL,
			ICCOM_SYSFS_DELETE_CHANNEL,
			ICCOM_SYSFS_SET_CHANNEL);
	return -EINVAL;
}

static DEVICE_ATTR_WO(channels_ctl);

// List containing default attributes that an
// iccom device can have.
//
// @dev_attr_transport the ICCom transport file
// @dev_attr_statistics the ICCom statistics file
// @dev_attr_channels_ctl the ICCOM channels file
static struct attribute *iccom_dev_attrs[] = {
	&dev_attr_transport.attr,
	&dev_attr_statistics.attr,
	&dev_attr_channels.attr,
	&dev_attr_channels_ctl.attr,
	&dev_attr_channels_RW.attr,
	&dev_attr_data_package_size.attr,
	NULL,
};

ATTRIBUTE_GROUPS(iccom_dev);

static int iccom_device_tree_node_setup(struct platform_device *pdev,
				struct iccom_dev *iccom)
{
	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
			"Probing an Iccom via device tree with id: %d", pdev->id);

	struct device_node *iccom_dt_node = pdev->dev.of_node;

	struct device_node *transport_dt_node = of_parse_phandle(iccom_dt_node,
								"transport_dev", 0);
	if (IS_ERR_OR_NULL(transport_dt_node)) {
		iccom_err("transport_dev property is not defined or valid");
		return -EINVAL;
	}

	struct platform_device *transport_pdev =
				of_find_device_by_node(transport_dt_node);
	of_node_put(transport_dt_node);
	if (IS_ERR_OR_NULL(transport_pdev)) {
		iccom_err("Unable to find transport from specified node");
		return -ENODEV;
	}

	struct full_duplex_device *full_duplex_dev =
		(struct full_duplex_device *) dev_get_drvdata(&transport_pdev->dev);

	if (IS_ERR_OR_NULL(full_duplex_dev)) {
		iccom_err("Unable to get transport device data of %s"
				, dev_name(&pdev->dev));
		return -EPROBE_DEFER;
	}

	if (IS_ERR_OR_NULL(full_duplex_dev->iface)) {
		iccom_err("Transport device data iface is null.");
		return -EFAULT;
	}

	int ret = __iccom_bind_xfer_device(&pdev->dev
					, full_duplex_dev->iface
					, &transport_pdev->dev);
	if (ret != 0) {
		iccom_err("Iccom transport device binding failed.");
		return ret;	
	}

	ret = iccom_start(iccom);
	if (ret < 0) {
		iccom_err("ICCom driver start failed, err: %d", ret);
		goto unbind_transport;
	}

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL
		 , "ICCom dev %s bound to transport %s and started."
		 , dev_name(&pdev->dev), dev_name(&transport_pdev->dev));

	return 0;

unbind_transport:
	__iccom_unbind_xfer_device(iccom);
	return ret;
}

// Probing function for iccom devices wich get's
// called whenever a new device is found. It allocates
// the device structure needed in memory and initializes
// the iccom properties.
//
// @pdev {valid ptr} transport platform device
//
// RETURNS:
//      0: Sucessfully probed the device
//     <0: negated error code
static int iccom_probe(struct platform_device *pdev)
{
	ICCOM_CHECK_PTR(pdev, return -EINVAL);

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL
			, "probing Iccom device with id: %d", pdev->id);

	struct iccom_dev *iccom = (struct iccom_dev *)
				kmalloc(sizeof(struct iccom_dev), GFP_KERNEL);

	ICCOM_CHECK_DEVICE("device allocation failed.", return -ENOMEM);

	int ret = iccom_init(iccom, pdev);
	if (ret != 0) {
		iccom_err("iccom_init failed");
		goto free_iccom;
	}

	/* Device Tree Detection */
	if (!IS_ERR_OR_NULL(pdev->dev.of_node)) {
		ret = iccom_device_tree_node_setup(pdev, iccom);
		if (ret != 0) {
			iccom_err("Unable to setup device tree node: %d", ret);
			goto delete_iccom;
		}
	}

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
			"Iccom device %s created.", dev_name(&pdev->dev));

	return 0;

delete_iccom:
	iccom_delete(iccom, pdev);
free_iccom:
	kfree(iccom);
	iccom = NULL;
	return ret;
};

// Remove function for iccom devices wich get's called
// whenever the device will be destroyed. It frees the
// device structure allocated previously in the probe
// function and stops the transport.
//
// @pdev {valid ptr} transport platform device
//
// RETURNS:
//      0: Sucessfully removed the device
//     <0: negated error code
static int iccom_remove(struct platform_device *pdev)
{
	ICCOM_CHECK_PTR(pdev, return -ENODEV);

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
			"Removing ICCom dev: %s", dev_name(&pdev->dev));

	struct iccom_dev *iccom = (struct iccom_dev *)dev_get_drvdata(&pdev->dev);
	ICCOM_CHECK_DEVICE("no device provided", return -ENODEV);

	iccom_info_raw(ICCOM_LOG_INFO_KEY_LEVEL, "Closing ICCom device");
	iccom_delete(iccom, pdev);

	kfree(iccom);
	iccom = NULL;

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL,
			"Removed ICCom dev: %s", dev_name(&pdev->dev));

	return 0;
};

// The ICCom driver compatible definition for
// matching the driver to devices available
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

// Module init method to register the iccom driver,
// the sysfs class and to generate the crc32 table
//
// RETURNS:
//      0: Sucessfully loaded the module
//     <0: negated error code
static int __init iccom_module_init(void)
{
	int ret;

	ida_init(&iccom_dev_id);

	ret = platform_driver_register(&iccom_driver);
	if (ret != 0) {
		iccom_err("ICCcom driver register failed: %d", ret);
		return ret;
	}

	ret = class_register(&iccom_class);
	if (ret != 0) {
		iccom_err("ICCcom class register failed: %d", ret);
		ida_destroy(&iccom_dev_id);
		platform_driver_unregister(&iccom_driver);

		return ret;
	}

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, "Sucessfully loaded iccom module");
	return 0;
}

// Module exit method to unregister the
// ICCom driver, the sysfs class and
// destroy the ida
static void __exit iccom_module_exit(void)
{
	class_unregister(&iccom_class);
	platform_driver_unregister(&iccom_driver);
	ida_destroy(&iccom_dev_id);

	iccom_info(ICCOM_LOG_INFO_KEY_LEVEL, "Sucessfully unloaded iccom module");
}

module_init(iccom_module_init);
module_exit(iccom_module_exit);

MODULE_DESCRIPTION("InterChipCommunication protocol module.");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");
