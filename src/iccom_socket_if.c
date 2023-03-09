/*
 * This file defines the ICCom protocol driver user space socket
 * interface (via Netlink sockets).
 *
 * Copyright (c) 2020 Robert Bosch GmbH
 * Artem Gulyaev <Artem.Gulyaev@de.bosch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/signal.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <uapi/linux/netlink.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <stddef.h>


#include <linux/iccom.h>

// DEV STACK
// @@@@@@@@@@@@@
//
//      Draft for iccom socket adapter.
//
// BACKLOG:
//
//      * NOTE: the netlink doesn't guarantee the delivery of the message,
//        especially under memory pressure conditions. This is needed to be
//        taken into account: use the sequence ID and ack packets from user
//        space and back to guarantee the package delivery.
//
//      * adjust code style according to the Linux kernel code style
//
//      * Probably to change completion to thread sleep finally,
//        as long as this might work not well otherwise.
//
//      * Dst port parameter passing
//      * Priority parameter passing
//
//      * Consider ability to open a general socket, which
//        will
//        * receive all incoming from remote side messages
//          (from all channels)
//        * be able to send to any named channel using the single
//          socket using different Netlink Message Header destination
//          address
//      * Allow sockets to choose
//        * transport xfer device
//        * transport xfer device parameters
//
//      * Don't use explicit aggregation driver dependency,
//        provide abstract interface to the aggregation driver
//        instead.
//
// @@@@@@@@@@@@@ recvmsg

/* --------------------- BUILD CONFIGURATION ----------------------------*/

// define this for debug mode
//#define ICCOM_SOCKET_DEBUG

// The maximum client message size (client data size in bytes per message)
#define ICCOM_SOCKET_MAX_MESSAGE_SIZE_BYTES 4096
#define NETLINK_ICCOM 22
#define PROTOCOL_FAMILY_RESET_VALUE -1

#define ICCOM_SOCKETS_CLOSE_POLL_PERIOD_JIFFIES msecs_to_jiffies(200)

#define ICCOM_SOCKETS_LOG_PREFIX "ICCom_sockets: "


// Maximal ordinary channel value. The ordinary channel can go
// from [0; ICCOM_SK_MAX_CHANNEL_VAL]
// And the loopback channels (loop remote end) can settle also in area
//      [ICCOM_SK_MAX_CHANNEL_VAL + 1; 2 * ICCOM_SK_MAX_CHANNEL_VAL  + 1]
// NOTE: loopback channels can go also in ordinary channel area
#define ICCOM_SK_MAX_CHANNEL_VAL 0x7FFF


// Iccom socket device found and the msg (received from userspace)
// was successfully dispatched.
#define ICCOM_SK_FIND_DISPATCH_DEVICE_SUCESS				1
// Iccom socket device found and but device is exiting
// meaning the msg (received from userspace) will not be dispatched.
#define ICCOM_SK_FIND_DISPATCH_DEVICE_ERR_DEVICE_EXITING		2
// Iccom socket device not found meaning cannot dispatch the msg
// (received from userspace).
#define ICCOM_SK_FIND_DISPATCH_DEVICE_ERR_DEVICE_NOT_FOUND		0

/* --------------------- UTILITIES SECTION ----------------------------- */

// to keep the compatibility with Kernel versions earlier than v5.5
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
    #define pr_warning pr_warn
#endif

#define iccom_socket_err(fmt, ...)					\
	pr_err(ICCOM_SOCKETS_LOG_PREFIX"%s: "fmt"\n", __func__		\
	       , ##__VA_ARGS__)
#define iccom_socket_warning(fmt, ...)					\
	pr_warning(ICCOM_SOCKETS_LOG_PREFIX"%s: "fmt"\n", __func__	\
	       , ##__VA_ARGS__)
#define iccom_socket_info(fmt, ...)					\
	pr_info(ICCOM_SOCKETS_LOG_PREFIX"%s: "fmt"\n", __func__		\
		, ##__VA_ARGS__)
#ifdef ICCOM_SOCKET_DEBUG
#define iccom_socket_dbg(fmt, ...)					\
	pr_info(ICCOM_SOCKETS_LOG_PREFIX"%s: "fmt"\n", __func__		\
		, ##__VA_ARGS__)
#else
#define iccom_socket_dbg(fmt, ...)
#endif

#define iccom_socket_err_raw(fmt, ...)					\
	pr_err(ICCOM_SOCKETS_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_socket_warning_raw(fmt, ...)				\
	pr_warning(ICCOM_SOCKETS_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_socket_info_raw(fmt, ...)					\
	pr_info(ICCOM_SOCKETS_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#ifdef ICCOM_SOCKET_DEBUG
#define iccom_socket_dbg_raw(fmt, ...)					\
	pr_info(ICCOM_SOCKETS_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#else
#define iccom_socket_dbg_raw(fmt, ...)
#endif

#define ICCOM_SK_CHECK_DEVICE(msg, error_action)			\
	if (IS_ERR_OR_NULL(iccom_sk)) {					\
		iccom_socket_err("%s: no device; "msg"\n", __func__);	\
		error_action;						\
	}

#define ICCOM_SK_CHECK_PTR(ptr, error_action)				\
	if (IS_ERR_OR_NULL(ptr)) {					\
		iccom_socket_err("%s: pointer "# ptr" is invalid;\n"	\
				 , __func__);				\
		error_action;						\
	}

#define ICCOM_SK_CHECK_SYSFS_CLASS_PARAMS(msg, error_action)		\
	if (IS_ERR_OR_NULL(class) || IS_ERR_OR_NULL(attr)		\
		|| IS_ERR_OR_NULL(buf)) {				\
		iccom_socket_err("%s: parameters are invalid; "msg"\n"	\
				, __func__);				\
		error_action;						\
	}								\

#define ICCOM_SK_CHECK_SYSFS_DEVICE_PARAMS(msg, error_action)		\
	if (IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(attr)		\
		|| IS_ERR_OR_NULL(buf)) {				\
		iccom_socket_err("%s: parameters are invalid; "msg"\n"	\
				, __func__);				\
		error_action;						\
	}								\

#define fitsin(TYPE, FIELD, SIZE)					\
	(offsetof(TYPE, FIELD) + sizeof(((TYPE*)(NULL))->FIELD) <= (SIZE))

/* -------------------------- STRUCTS -----------------------------------*/


// The struct which described the loopback mapping rule.
//
//          shift
//    |------------------->|
//    |                    |
// ---[-------]------------[-------]----------
//  from     to          from     to
//                     + shift  + shift
//
//    |-------|            |-------|
//     original            loopback
//     channel              mapped
//      range               range
//
// @from {<= to} the first port to loopback (inclusive)
// @to {>= from} the last port to loopback (inclusive)
// @shift defines a window where to make a loopback
//     ports.
//     NOTE: if shift == 0, then rule is no active
struct iccom_sk_loopback_mapping_rule {
	int from;
	int to;
	int shift;
};

// ICCom socket interface provider.
//
// @socket the socket we are working with
// @protocol_family_id id for the socket protocol family
//			value >= 22 is a netlink valid value
//			value < 22 is a netlink invalid value
//			value == -1 is an initialization value
// @pump_task the ptr to thread which pumpts messages to ICCom device
// @iccom the ICCom device to work with
// @initialized completed as everything is ready to be run after
//      initialization.
// @exiting should be set to true, to request internal thread
//      to exit, after set exiting flag one needs to wait for
//      @pump_main_loop_done.
// @pump_main_loop_done is completed when pump task thread gone out
//      of its main loop (no more socket/iccom usage), so close
//      sequence is able to close the socket safely.
// @socket_closed is completed as socket is closed.
//      this directory is now aiming to provide loopback control
//      but later some information and other ctl functions might be
//      added.
// @loopback_ctl_ops loopback control file operations
// @lback_map_rule the channel loopback mapping rule pointer,
//      allocated on heap.
struct iccom_sockets_device {
	struct sock *socket;
	int protocol_family_id;
	struct task_struct *pump_task;

	struct iccom_dev *iccom;

	struct completion initialized;
	bool exiting;
	struct completion pump_main_loop_done;
	struct completion socket_closed;

        struct iccom_sk_loopback_mapping_rule *lback_map_rule;
};

/* -------------------------- EXTERN VARS -------------------------------*/

/* -------------------------- GLOBAL VARS -------------------------------*/

// ID Allocator
struct ida iccom_skif_device_id;

/* --------------------- FORWARD DECLARATIONS ---------------------------*/

static int __iccom_socket_dispatch_msg_up(
		struct iccom_sockets_device *iccom_sk
		, const uint32_t channel, const void *const data
		, const size_t data_size_bytes);

static int __iccom_socket_dispatch_msg_down(
		struct iccom_sockets_device *iccom_sk
		, struct sk_buff *sk_buffer);

static int __iccom_socket_match_channel2lbackrule(
	const struct iccom_sk_loopback_mapping_rule *const rule
	, const int channel);

static void __iccom_socket_netlink_data_ready(struct sk_buff *skb);

/* --------------------- ENTRY POINTS -----------------------------------*/

// Searchs the iccom socket device that shall transmite the msg
// received down to its linked iccom instance. The search is done
// by comparing the socket id from socket buffer and iccom socket device
// socket
//
// @dev {valid ptr} device to be stored
// @data {valid ptr} sk_buff with the socket data received
//                   to be sent to the iccom device associated
//                   with the iccom sk
//
// RETURNS:
//      0: device found. Dispatched to the proper device
//      1: socket msg not for the device in the loop
//      2: device found but exiting
//     <0: pointers are null
int __iccom_socket_select_device_for_dispatching_msg_down(struct device *dev, void* data)
{
	if(IS_ERR_OR_NULL(dev)) {
		iccom_socket_err("device is null");
		return -EFAULT;
	}

	if(IS_ERR_OR_NULL(data)) {
		iccom_socket_err("data is null");
		return -EFAULT;
	}

	struct iccom_sockets_device *iccom_sockets_dev = 
				(struct iccom_sockets_device *)dev_get_drvdata(dev);
	
	if (IS_ERR_OR_NULL(iccom_sockets_dev)) {
		iccom_socket_err("Invalid socket device.");
		return ICCOM_SK_FIND_DISPATCH_DEVICE_ERR_DEVICE_NOT_FOUND;
	}

	struct sk_buff *skb = (struct sk_buff *)data;

	if(skb->sk != iccom_sockets_dev->socket) {
		iccom_socket_info("Iccom socket device socket is different than the "
					"received one. Msg not for this device but for other device.");
		return ICCOM_SK_FIND_DISPATCH_DEVICE_ERR_DEVICE_NOT_FOUND;
	}

	if (iccom_sockets_dev->exiting) {
		iccom_socket_err("iccom sk device is exiting");
		return ICCOM_SK_FIND_DISPATCH_DEVICE_ERR_DEVICE_EXITING;
	}

	__iccom_socket_dispatch_msg_down(iccom_sockets_dev, skb);

	return ICCOM_SK_FIND_DISPATCH_DEVICE_SUCESS;
}

// Is called whenever inderlying protocol layer gets new message
// for us from the other side.
static bool __iccom_socket_msg_rx_callback(
		unsigned int channel
		, void *msg_data, size_t msg_len
		, void *consumer_data)
{
	struct iccom_sockets_device *iccom_sk
		    = (struct iccom_sockets_device *)consumer_data;

	ICCOM_SK_CHECK_DEVICE("", return false);

	const int lback = __iccom_socket_match_channel2lbackrule(
				iccom_sk->lback_map_rule, channel);
	// loopback mode for this channel was enabled, so external
	// party is dropped from the loop channel
	if (lback != 0) {
	    return false;
	}

	__iccom_socket_dispatch_msg_up(iccom_sk, channel, msg_data
				       , msg_len);

	// we will not take ownership over the msg_data
	return false;
}

/* --------------------- GENERAL SECTION --------------------------------*/

// Helper. Shows the relationship between loopback loop and the channel
//      number.
//
// RETURNS:
//      >0: when given channel represents is local end of the loop
//      0: when given channel has nothing to do with loopback, or loopback
//         is not accessible
//      <0: when given channel represents is remote end of the loop
static int __iccom_socket_match_channel2lbackrule(
	const struct iccom_sk_loopback_mapping_rule *const rule
	, const int channel)
{
	if (IS_ERR_OR_NULL(rule)) {
		return 0;
	}
	if (rule->shift == 0) {
		return 0;
	}
	if (channel >= rule->from && channel <= rule->to) {
		return 1;
	}
	if (channel >= rule->from + rule->shift
		    && channel <= rule->to + rule->shift) {
		return -1;
	}
	return 0;
}


// RETURNS:
//      >=0: on success
//      <0: on failure
static int __iccom_socket_lback_rule_verify(
	const struct iccom_sk_loopback_mapping_rule *const rule)
{
	// if shift is zero, the rule is disabled
	if (rule->shift == 0) {
		return 0;
	}

	if (rule->from < 0 || rule->from > ICCOM_SK_MAX_CHANNEL_VAL) {
		iccom_socket_err("'from' out of bounds: %d", rule->from);
		return -EINVAL;
	}
	if (rule->to < 0 || rule->to > ICCOM_SK_MAX_CHANNEL_VAL) {
		iccom_socket_err("'to' out of bounds: %d", rule->to);
		return -EINVAL;
	}
	if (rule->to < rule->from) {
		iccom_socket_err("'from'(%d) < 'to'(%d)"
				 , rule->from, rule->to);
		return -EINVAL;
	}
	if (rule->to + rule->shift > 2 * ICCOM_SK_MAX_CHANNEL_VAL + 1
			|| rule->from + rule->shift < 0) {
		iccom_socket_err("'shift'(%d) moves segment out of"
				 " bounds", rule->shift);
		return -EINVAL;
	}
	if (abs(rule->shift) < rule->to - rule->from + 1) {
		iccom_socket_err("'shift'(%d) moves segment on its own"
				 , rule->shift);
		return -EINVAL;
	}
	return 0;
}

// The message header is used in following way:
// * nlmsg_type -> the destination channel (port number)
// * nlmsg_flags (lo byte) -> priority
// * nlmsg_pid -> sending process port ID
//
// RETURNS:
//      0: success
//      <0: negated error code, if fails
static int __iccom_socket_dispatch_msg_down(
		struct iccom_sockets_device *iccom_sk
		, struct sk_buff *sk_buffer)
{
	struct nlmsghdr *nl_header = (struct nlmsghdr *)sk_buffer->data;

	// TODO: use bitfields here
	uint32_t channel_nr = NETLINK_CB(sk_buffer).portid & 0x00007FFF;
	// TODO: use bitfields here
	uint32_t priority = ((uint32_t)nl_header->nlmsg_type) >> 8;

	if (!NLMSG_OK(nl_header, sk_buffer->len)) {
		iccom_socket_warning("Broken netlink message to be sent:"
				     " socket id: %d; ignored;"
				     , channel_nr);
		return -EINVAL;
	}

	iccom_socket_dbg_raw("-> TX data from user space (ch. %d):"
			     , channel_nr);
#ifdef ICCOM_SOCKET_DEBUG
	print_hex_dump(KERN_DEBUG
		       , ICCOM_SOCKETS_LOG_PREFIX"US -> TX data: "
		       , 0, 16, 1, NLMSG_DATA(sk_buffer->data)
		       , NLMSG_PAYLOAD(nl_header, 0)
		       , true);
#endif

	const int lback = __iccom_socket_match_channel2lbackrule(
				iccom_sk->lback_map_rule, channel_nr);
	// loopback mode for this channel
	if (lback != 0) {
		const int shift = iccom_sk->lback_map_rule->shift;
		const uint32_t dst_ch = (lback > 0) ? (channel_nr + shift)
						    : (channel_nr - shift);
		return __iccom_socket_dispatch_msg_up(iccom_sk
				, dst_ch
				, NLMSG_DATA(nl_header)
				, NLMSG_PAYLOAD(nl_header, 0));
	}

	return iccom_post_message(iccom_sk->iccom
			, NLMSG_DATA(nl_header)
			, NLMSG_PAYLOAD(nl_header, 0)
			, channel_nr
			, priority);
}

// Sends the given message data incoming from ICCom layer
// up to the netlink socket and correspondingly to User Space
// application behind it.
//
// @iccom_sk {valid iccom socket dev ptr}
// @channel {valid channel number}
// @data {valid data ptr}
// @data_size_bytes {size of data pointed by @data}
//
// RETURNS:
//      0: success
//      <0: negated error code, if fails
static int __iccom_socket_dispatch_msg_up(
		struct iccom_sockets_device *iccom_sk
		, const uint32_t channel, const void *const data
		, const size_t data_size_bytes)
{
	if (data_size_bytes > ICCOM_SOCKET_MAX_MESSAGE_SIZE_BYTES) {
		iccom_socket_err("received message is bigger than max"
				 "  allowed: %lu > %d bytes; dropping;"
				 , data_size_bytes
				 , ICCOM_SOCKET_MAX_MESSAGE_SIZE_BYTES);
		return -ENOMEM;
	}
	const uint32_t dst_port_id = channel;

	//   TODO: reuse allocated memory if possible
	struct sk_buff *sk_buffer = alloc_skb(NLMSG_SPACE(data_size_bytes),
					      GFP_KERNEL);

	if (IS_ERR_OR_NULL(sk_buffer)) {
		iccom_socket_err("could not allocate socket buffer,"
				 " req. size: %lu"
				 , NLMSG_SPACE(data_size_bytes));
		return -EPIPE;
	}

	struct nlmsghdr *nl_header = __nlmsg_put(sk_buffer, dst_port_id
						 , 0, 0, data_size_bytes
						 , 0);

	memcpy(NLMSG_DATA(nl_header), data, data_size_bytes);

	NETLINK_CB(sk_buffer).portid = 0;
	NETLINK_CB(sk_buffer).dst_group = 0;
	NETLINK_CB(sk_buffer).flags = 0;

	iccom_socket_dbg_raw("<- data to User space (ch. %d):"
			     , dst_port_id);
#ifdef ICCOM_SOCKET_DEBUG
	print_hex_dump(KERN_DEBUG
		       , ICCOM_SOCKETS_LOG_PREFIX"US <- RX data: "
		       , 0, 16, 1, data, data_size_bytes, true);
#endif

	int res = netlink_unicast(iccom_sk->socket, sk_buffer, dst_port_id
				  , MSG_DONTWAIT);

	if (res >= 0) {
		return 0;
	}

	switch (-res) {
	// happens when no one listenes the port, which is
	// not an error generally
	case ECONNREFUSED: return 0;
	default:
		iccom_socket_err("Send to user space failed, err: %d"
				 , -res);
	}

	return res;
}

// RETURNS:
//      0: if success
//      negated error code: if fails
static int __iccom_socket_reg_socket_family(
		struct iccom_sockets_device *iccom_sk)
{
	struct netlink_kernel_cfg netlink_cfg = {
			.groups = 0
			, .flags = 0
			, .input = &__iccom_socket_netlink_data_ready
			, .cb_mutex = NULL
			, .bind = NULL
			, .compare = NULL
		    } ;
	// TODO: optionally: add support for earlier versions of kernel
	iccom_sk->socket = netlink_kernel_create(&init_net
						 , iccom_sk->protocol_family_id
					, &netlink_cfg);

	if (IS_ERR(iccom_sk->socket)) {
		return PTR_ERR(iccom_sk->socket);
	} else if (!iccom_sk->socket) {
		iccom_socket_err("could not create kernel netlink socket"
				 " for family: %d", iccom_sk->protocol_family_id);
		return -ENODEV;
	}
	return 0;
}

// Unregisters iccom socket family.
static void __iccom_socket_unreg_socket_family(
		struct iccom_sockets_device *iccom_sk)
{
	if (IS_ERR_OR_NULL(iccom_sk)
		    || IS_ERR_OR_NULL(iccom_sk->socket)) {
		return;
	}
	iccom_sk->exiting = true;
	netlink_kernel_release(iccom_sk->socket);
	iccom_sk->socket = NULL;
	complete(&iccom_sk->socket_closed);
}

// Provides an ability to read loopback rule from User Space.
//
//
// RETURNS:
//      >= 0: number of bytes actually provided to user space, on success
//      < 0: negated error code, on failure
static ssize_t read_loopback_rule_show(struct device *dev, 
                                        struct device_attribute *attr,
                                        char *buf)
{
        ICCOM_SK_CHECK_PTR(buf, return -EINVAL);

        struct iccom_sockets_device *iccom_sk
                = (struct iccom_sockets_device *)dev_get_drvdata(dev);

        if(IS_ERR_OR_NULL(iccom_sk)) {
                iccom_socket_err("Invalid parameters.");
                return -EINVAL;
        }

	const int BUFFER_SIZE = 256;

        char *buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

        if (IS_ERR_OR_NULL(buffer)) {
                iccom_socket_err("failed to create new buffer:"
                                 " no memory");
                return -ENOMEM;
        }

	const struct iccom_sk_loopback_mapping_rule *const rule
			    = iccom_sk->lback_map_rule;

        size_t len = (size_t)snprintf(buffer, BUFFER_SIZE, "%d %d %d\n\n"
                                      "NOTE: the loopback will map the "
                                      "[a;b] channels other sides to"
                                      " [a + shift; b + shift] local "
                                      "channels where a = first argument"
                                      ", b = second argument,"
                                      " shift = third argument\n"
                                      , rule->from, rule->to, rule->shift)
                     + 1;

        if (len > BUFFER_SIZE) {
                iccom_socket_warning("loopback control output "
                                     "was too big for buffer"
                                     ", required length: %zu", len);
                len = BUFFER_SIZE;
                buffer[BUFFER_SIZE - 1] = 0;
        }

        kfree(buffer);

        return len;
}
static DEVICE_ATTR_RO(read_loopback_rule);

// @buf pointer to the beginning of the string buffer
//      NOTE: buffer can be temporary modified within parsing
// @len size of the buffer (in chars)
// @out pointer to the struct where the results are to be written
//      NOTE: useful data is guaranteed to be there only when
//          return code is successful
//
// RETURNS:
//      >=0: successful parsing
//      < 0: on failure (negated error code)
int  __iccom_sk_parse_lback_string(char *const buf
		, const size_t len
		, struct iccom_sk_loopback_mapping_rule *const out)
{
	ICCOM_SK_CHECK_PTR(buf, return -EINVAL);
	ICCOM_SK_CHECK_PTR(out, return -EINVAL);

	// identifies the current field to parse string into
	int number = -1;
	char *start = buf;

	for (int i = 0; i < len; i++) {
		const char c = buf[i];
		if (number < 0 && (c == ' ' || c == '\n' || c == '\t')) {
			continue;
		}
		if (number < 0) {
			start = buf + i;
			number = -number;
			continue;
		}
		if (c != ' ' && c != '\n' && c != '\t') {
			continue;
		}

		const char orig_c = buf[i];
		buf[i] = 0;

		long target;
		int res = kstrtol(start, 10, &target);
		buf[i] = orig_c;

		if (res != 0) {
			iccom_socket_err("failed parsing arg %d in: %s"
					 , number, buf);
			return -EINVAL;
		};

		switch (number) {
		case 1: out->from = (int)target; break;
		case 2: out->to = (int)target; break;
		case 3: out->shift = (int)target; break;
		default: return -EINVAL;
		}

		number = -(number + 1);
	}

	if (__iccom_socket_lback_rule_verify(out) < 0) {
		return -EINVAL;
	}

	return 0;
}

// Provides an ability to update (and also disable) current loopback
// rule from User Space.
//
//
// RETURNS:
//      >= 0: number of bytes actually were written, on success
//      < 0: negated error code, on failure
static ssize_t set_loopback_rule_store(struct device *dev, 
                                        struct device_attribute *attr,
                                        const char *buf, size_t count)
{
        ICCOM_SK_CHECK_PTR(buf, return -EINVAL);

        struct iccom_sockets_device *iccom_sk
                = (struct iccom_sockets_device *)dev_get_drvdata(dev);
        int ret = 0;

        if(IS_ERR_OR_NULL(iccom_sk)) {
                iccom_socket_err("Invalid parameters.");
                return -EINVAL;
        }

	const unsigned int BUFFER_SIZE = 64;

        // we only get the whole data at once
        if (count > BUFFER_SIZE) {
                iccom_socket_warning(
                        "Ctrl message should be written at once"
                        " and not exceed %u bytes.", BUFFER_SIZE);
                return -EFAULT;
        }

        char *buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

        if (IS_ERR_OR_NULL(buffer)) {
                iccom_socket_err("failed to create new rule buffer:"
                                 " no memory");
                return -ENOMEM;
        }
        memcpy(buffer, buf, count);

        struct iccom_sk_loopback_mapping_rule parsing_res;
        ret = __iccom_sk_parse_lback_string(buffer, count, &parsing_res);
        if (ret < 0) {
                iccom_socket_warning("Parsing failed: %s", buffer);
                goto finalize;
        }

	struct iccom_sk_loopback_mapping_rule * new_rule
			    = (struct iccom_sk_loopback_mapping_rule *)
			      kmalloc(sizeof(*new_rule), GFP_KERNEL);
	if (IS_ERR_OR_NULL(new_rule)) {
		iccom_socket_err("failed to create new loopback rule:"
				 " no memory");
		ret = -ENOMEM;
		goto finalize;
	}
	*new_rule = parsing_res;

	struct iccom_sk_loopback_mapping_rule *tmp_ptr
			    = iccom_sk->lback_map_rule;
	WRITE_ONCE(iccom_sk->lback_map_rule, new_rule);

	if (!IS_ERR_OR_NULL(tmp_ptr)) {
		kfree(tmp_ptr);
		tmp_ptr = NULL;
	}

	ret = (ssize_t)count;

finalize:

	kfree(buf);
	buf = NULL;

	return ret;
}
static DEVICE_ATTR_WO(set_loopback_rule);

// Helper. Initializes the loopback control on ICCom Sockets.
//
// NOTE: the loopback default rule (turned off) will be initialized
//          anyway even if there is no definition of this rule later on.
//
// RETURNS:
//      >= 0: on success,
//      < 0: on failure (negated error code)
static int __iccom_sk_loopback_ctl_init(
		struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SK_CHECK_DEVICE("", return -ENODEV);

        iccom_sk->lback_map_rule = NULL;

	// initial rule data
	iccom_sk->lback_map_rule = (struct iccom_sk_loopback_mapping_rule *)
				   kmalloc(sizeof(*iccom_sk->lback_map_rule)
					   , GFP_KERNEL);
	if (IS_ERR_OR_NULL(iccom_sk->lback_map_rule)) {
		iccom_socket_err("failed to create loopback rule:"
				 " no memory");
		return -ENOMEM;
	}
	memset(iccom_sk->lback_map_rule, 0, sizeof(*iccom_sk->lback_map_rule));

        return 0;
}

// Closes the iccom sk loopback controller
static void __iccom_sk_loopback_ctl_close(
		struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SK_CHECK_DEVICE("", return);

	if (!IS_ERR_OR_NULL(iccom_sk->lback_map_rule)) {
	    struct iccom_sk_loopback_mapping_rule *ptr
			= iccom_sk->lback_map_rule;
	    iccom_sk->lback_map_rule = NULL;

            kfree(ptr);
            ptr = NULL;
        }
}

// Closes underlying protocol layer.
static void __iccom_socket_protocol_device_close(
		struct iccom_sockets_device *iccom_sk)
{
	if (IS_ERR_OR_NULL(iccom_sk)
		    || !iccom_is_running(iccom_sk->iccom)) {
		return;
	}
	iccom_sk->exiting = true;
}

// Inits underlying protocol layer.
//
// RETURNS:
//      0: if success
//      <0: negated error code else
static int __iccom_socket_protocol_device_init(
		struct iccom_sockets_device *iccom_sk)
{
	int res = iccom_set_channel_callback(iccom_sk->iccom
			, ICCOM_ANY_CHANNEL_VALUE
			, &__iccom_socket_msg_rx_callback
			, (void *)iccom_sk);
	if (res < 0) {
		__iccom_socket_protocol_device_close(iccom_sk);
		return res;
	}
	return res;
}

// iccom_skif_reset_data - resets iccom sk if struct data
//
// @iccom_sk - iccom sk device to have its data reset
//
// RETURNS: void
static void iccom_skif_reset_data(struct iccom_sockets_device *iccom_sk)
{
	if (!IS_ERR_OR_NULL(iccom_sk)) {
		memset(iccom_sk, 0, sizeof(*iccom_sk));
		iccom_sk->protocol_family_id = PROTOCOL_FAMILY_RESET_VALUE;
	}
}

// iccom_skif_init - initializes the iccom socket device data structure
//
// @iccom_sk - iccom sk device to initialize
//
// RETURNS:
//      0: if success
//      <0: negated error code else
static int iccom_skif_init(struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SK_CHECK_DEVICE("", return -ENODEV);
	
	iccom_skif_reset_data(iccom_sk);
	init_completion(&iccom_sk->initialized);
	init_completion(&iccom_sk->socket_closed);
	init_completion(&iccom_sk->pump_main_loop_done);
	__iccom_sk_loopback_ctl_init(iccom_sk);
	complete(&iccom_sk->initialized);

	iccom_socket_info("iccom socket if initialization completed");
	return 0;
}

// iccom_skif_close - closes whole iccom sockets device inclusive all
// 			underlying layers
//
// @iccom_sk - iccom sk device to close
//
// RETURNS:
//      0: if success
//      <0: negated error code else
static int iccom_skif_close(struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SK_CHECK_DEVICE("", return -ENODEV);

	// order matters
	__iccom_sk_loopback_ctl_close(iccom_sk);
//	__iccom_sk_procfs_close(iccom_sk);
	__iccom_socket_unreg_socket_family(iccom_sk);
	__iccom_socket_protocol_device_close(iccom_sk);
	iccom_skif_reset_data(iccom_sk); //makes sense?
	return 0;
}

// iccom_skif_run - launches iccom sockets interface layer
//
// @iccom_sk - iccom sk device to launch
//
// RETURNS:
//      0: if success
//      <0: negated error code else
static int iccom_skif_run(struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SK_CHECK_DEVICE("", return -ENODEV);

	// order matters
	int res = __iccom_socket_reg_socket_family(iccom_sk);
	if (res < 0) {
		goto failed;
	}
	iccom_socket_info_raw("opened kernel netlink socket: %px"
			      , iccom_sk->socket);
	res = __iccom_socket_protocol_device_init(iccom_sk);
	if (res < 0) {
		goto failed;
	}

	//__iccom_sk_loopback_ctl_init(iccom_sk);

	// launches pump thread
	complete(&iccom_sk->initialized);

	iccom_socket_info_raw("protocol device initialization done");
	return 0;

failed:
	iccom_skif_close(iccom_sk);
	return res;
}

// iccom_skif_stop - stop iccom sockets interface layer
//
// @iccom_sk - iccom sk device to stop
//
// RETURNS:
//      0: if success
//      <0: negated error code else
static int iccom_skif_stop(struct iccom_sockets_device *iccom_sk)
{
	int ret = 0;

	ret = iccom_remove_channel_callback(iccom_sk->iccom, 
					ICCOM_ANY_CHANNEL_VALUE);
	if (ret < 0) {
		iccom_socket_err("Unable to stop the iccom sk if");
		return ret;
	}

	__iccom_socket_protocol_device_close(iccom_sk);

	return 0;
}

// version_show - retrieves git revision for current implementation
//
// @class - iccom class
// @attr - class attribute properties
// @buf - buffer to write output to user space
//
// return:
//      0: length of data is zero - no data
//      > 0: data size of data to be showed in user space
static ssize_t version_show(struct class *class, struct class_attribute *attr,
                            char *buf) 
{
	ICCOM_SK_CHECK_SYSFS_CLASS_PARAMS("", return -EINVAL);

	return scnprintf(buf, PAGE_SIZE, "version: %s", ICCOM_GIT_REPO_HASH);
}
static CLASS_ATTR_RO(version);

// delete_device_store - delete iccom socket device
//
// @class - iccom class
// @attr - device attribute properties
// @buf - buffer to read input from user space
// @count - size of buffer from user space
//
// return:
//      count - all data processed
static ssize_t delete_device_store(struct class *class, struct class_attribute *attr,
						 const char *buf, size_t count)
{
	ICCOM_SK_CHECK_SYSFS_CLASS_PARAMS("", return -EINVAL);

	if (count >= PAGE_SIZE) {
		iccom_socket_err("Input data is longer than expected (%lu)", 
				  PAGE_SIZE);
		return -EINVAL;
	}

	size_t total_count = count + 1;
	char *device_name;

	device_name = (char *) kzalloc(total_count, GFP_KERNEL);

	if (IS_ERR_OR_NULL(device_name)) {
		return -ENOMEM;
	}

	memcpy(device_name, buf, total_count);

	if (device_name[count] != 0) {
		iccom_socket_err("Non-null terminated string. Invalid input.");
		kfree(device_name);
		return -EINVAL;
	}

	struct device *device_to_delete;

	device_to_delete = 
		bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);

	if (IS_ERR_OR_NULL(device_to_delete)) {
		iccom_socket_err("Unable to find provided device.");
		return -EINVAL;
	}

	platform_device_unregister(to_platform_device(device_to_delete));

	return count;
}
static CLASS_ATTR_WO(delete_device);

// create_device_store - creates iccom socket devices
//
// @class - iccom class
// @attr - device attribute properties
// @buf - buffer to read input from user space
// @count - size of buffer from user space
//
// return:
//      count - all data processed
static ssize_t create_device_store(struct class *class, struct class_attribute *attr,
				   const char *buf, size_t count)
{
	ICCOM_SK_CHECK_SYSFS_CLASS_PARAMS("", return -EINVAL);

	int device_id = ida_alloc(&iccom_skif_device_id, GFP_KERNEL);
	if (device_id < 0) {
		iccom_socket_err("Could not allocate a new unused ID");
		return -EINVAL;
	}

	struct platform_device * new_pdev;

	new_pdev = platform_device_register_simple("iccom_socket_if", device_id,
						    NULL, 0);
	if (IS_ERR_OR_NULL(new_pdev)) {
		iccom_socket_err("Could not register the device iccom socket.%d",
				 device_id);
		return -EINVAL;
	}
	iccom_socket_info("Device iccom socket.%d created", device_id);

	return count;
}
static CLASS_ATTR_WO(create_device);

static struct attribute *iccom_socket_if_class_attrs[] = {
    &class_attr_version.attr,
    &class_attr_create_device.attr,
    &class_attr_delete_device.attr,
    NULL
};

ATTRIBUTE_GROUPS(iccom_socket_if_class);

static struct class iccom_socket_if_class = {
    .name = "iccom_socket_if",
    .owner = THIS_MODULE,
    .class_groups = iccom_socket_if_class_groups
};

// Iccom_dev_show - checks if iccom device is already associated to iccom socket
//
// @dev - iccom device
// @attr - device attribute properties
// @buf - buffer to write output to user space
//
// return:
//      bytes - message with status
static ssize_t iccom_dev_show(struct device *dev, struct device_attribute *attr,
                              char *buf) 
{
	ICCOM_SK_CHECK_SYSFS_DEVICE_PARAMS("", return -EINVAL);

	struct iccom_sockets_device *iccom_sockets_dev = 
			    (struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sockets_dev)) {
		iccom_socket_err("Invalid parameters.");
		goto invalid_input;
	}

	if (IS_ERR_OR_NULL(iccom_sockets_dev->iccom)) {
		iccom_socket_err("Iccom Sk has no Iccom device "
				 "associtated/invalid.");
		goto invalid_input;
	}

	return scnprintf(buf, PAGE_SIZE, "Iccom Sk has an Iccom device already "
				"associated: %s", kobject_name(&(dev->kobj)));

invalid_input:
	return scnprintf(buf, PAGE_SIZE, " ");
}

// iccom_dev_store - binds iccom devices to iccom socket devices
//
// @dev - iccom socket device
// @attr - device attribute properties
// @buf - buffer to read input from user space
// @count - size of buffer from user space
//
// return:
//      count - all data processed
static ssize_t iccom_dev_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	ICCOM_SK_CHECK_SYSFS_DEVICE_PARAMS("", return -EINVAL);

	struct iccom_sockets_device *iccom_sockets_dev = 
			    (struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sockets_dev)) {
		iccom_socket_err("Invalid iccom sockets device.");
		return -EINVAL;
	}

	if (!IS_ERR_OR_NULL(iccom_sockets_dev->iccom)) {
		iccom_socket_err("Iccom device already associated Iccom socket");
		return -EINVAL;
	}
	
	if (count >= PAGE_SIZE) {
		iccom_socket_err("Input data is longer than expected (%lu)", 
				  PAGE_SIZE);
		return -EINVAL;
	}

	char *device_name;
	size_t total_count = count + 1;

	device_name = (char *) kzalloc(total_count, GFP_KERNEL);

	if (IS_ERR_OR_NULL(device_name)) {
		return -ENOMEM;
	}

	memcpy(device_name, buf, total_count);

	if (device_name[count] != 0) {
		iccom_socket_err("Non-null terminated string. Invalid input.");
		kfree(device_name);
		return -EFAULT;
	}

	struct device *iccom_dev_to_link;

	iccom_dev_to_link = bus_find_device_by_name(&platform_bus_type, NULL, 
						    device_name);

	kfree(device_name);

	if (IS_ERR_OR_NULL(iccom_dev_to_link)) {
		iccom_socket_err("Iccom device given as input is invalid.");
		return -EINVAL;
	}

	struct device_link* link = device_link_add(dev, iccom_dev_to_link, 
						DL_FLAG_AUTOREMOVE_CONSUMER);
	if (IS_ERR_OR_NULL(link)) {
		iccom_socket_err("Unable to bind iccom sk to provided iccom.");
		return -EINVAL;
	}

	struct iccom_dev *iccom_dev;

	iccom_dev = (struct iccom_dev *) dev_get_drvdata(iccom_dev_to_link);
	if (IS_ERR_OR_NULL(iccom_dev)) {
		device_link_del(link);
		iccom_socket_err("Iccom device given as input is invalid.");
		return -EINVAL;
	}

	iccom_sockets_dev->iccom = iccom_dev;

	int ret = 0;
	ret = iccom_skif_run(iccom_sockets_dev);
	if (ret != 0) {
		device_link_del(link);
		iccom_socket_err("Iccom sk if device run failed.");
		return -EINVAL;
	}

	iccom_socket_info("Iccom device binding to Iccom socket device was "
			  "sucessful");
	return count;
}
static DEVICE_ATTR_RW(iccom_dev);

// iccom_skif_check_protocol_family_availability - traverses the tree of devices 
//                                                 assigned to the iccom_sockets_if
//                                                 driver and checks if given protocol 
//                                                 family number is already in use
//
// @dev - iccom socket device
// @data - buffer with protocol family number
//
// return:
//      0 - input protocol family is not assigned to existing devices
//      1 - input protocol family is already in use (stops search)
static int iccom_skif_check_protocol_family_availability(struct device *dev, 
								void *data)
{
	struct iccom_sockets_device *iccom_sock_dev = 
			(struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sock_dev) || IS_ERR_OR_NULL(data)) {
		iccom_socket_err("Invalid parameters.");
		return -ENOENT;
	}

	int protocol_family;

	protocol_family = *((int *)data);

	if (protocol_family == iccom_sock_dev->protocol_family_id) {
		return 1;
	}
	return 0;
}

// protocol_family_store - sets a protocol family to a iccom socket device
//
// @dev - iccom socket device
// @attr - device attribute properties
// @buf - buffer to read input from user space
// @count - size of buffer from user space
//
// return:
//      count - all data processed
static ssize_t protocol_family_store(struct device *dev, 
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	ICCOM_SK_CHECK_SYSFS_DEVICE_PARAMS("", return -EINVAL);

	struct iccom_sockets_device *iccom_sk_dev = 
			    (struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk_dev)) { 
		iccom_socket_err("Invalid parameters.");
		return -EINVAL;
	}

	/*if (iccom_sk_dev->socket_closed == 0) {
		iccom_socket_err("Cannot change protocol family as iccom sk if \
				 layer is in running state");
		return -EINVAL;
	}*/

	if (iccom_sk_dev->protocol_family_id >= 0) {
		iccom_socket_err("Protocol family is already assigned to this "
				 "iccom socket interface device (current value "
				 "%d).", iccom_sk_dev->protocol_family_id);
		return -EPFNOSUPPORT;
	}

	if (count >= PAGE_SIZE) {
		iccom_socket_err("Input data is longer than expected (%lu)", 
				  PAGE_SIZE);
		return -EINVAL;
	}

	unsigned int protocol_family;
	int ret = 0;

	ret = kstrtouint(buf, 10, &protocol_family);
	if (ret != 0) {
		iccom_socket_err("Specified protocol family %s is invalid "
				 "(error:%d)", 
			buf, ret);
		return -EINVAL;
	}

	ret = driver_for_each_device(dev->driver, NULL, &protocol_family, 
				&iccom_skif_check_protocol_family_availability);
	if (ret != 0) {
		iccom_socket_err("Specified protocol family %s is already in "
				 "use. Please use a different one. (ret: %d)", 
				 buf, ret);
		return -EINVAL;
	}

	iccom_sk_dev->protocol_family_id = protocol_family;

	return count;
}
static DEVICE_ATTR_WO(protocol_family);

static struct attribute *iccom_socket_if_dev_attrs[] = {
	&dev_attr_iccom_dev.attr,
	&dev_attr_protocol_family.attr,
	&dev_attr_read_loopback_rule.attr,
	&dev_attr_set_loopback_rule.attr,
        NULL,
};

ATTRIBUTE_GROUPS(iccom_socket_if_dev);

static int iccom_skif_find_unused_protocol_family(struct platform_device *pdev)
{
	int ret = 0;

	for (int ptc_fam = NETLINK_ICCOM; ptc_fam < 255; ptc_fam++) { //TODO: MAX VALUE???
		ret = driver_for_each_device(pdev->dev.driver, NULL, &ptc_fam, 
				&iccom_skif_check_protocol_family_availability);
		if (!ret) {
			iccom_socket_info("Found available protocol family %d",
					ptc_fam);
			return ptc_fam;
		}
	}
	return PROTOCOL_FAMILY_RESET_VALUE;
}

static int iccom_skif_validate_protocol_family(struct platform_device *pdev, 
							int *protocol_family)
{
	if (IS_ERR_OR_NULL(pdev) || IS_ERR_OR_NULL(protocol_family)) {
		iccom_socket_err("Invalid parameters to validate protocol "
				 "family");
		return -EINVAL;
	}

	if (*protocol_family == PROTOCOL_FAMILY_RESET_VALUE) {
		iccom_socket_warning("Protocol family property is not defined "
				     "or does not have a value");
		*protocol_family = iccom_skif_find_unused_protocol_family(pdev);
		if (*protocol_family == PROTOCOL_FAMILY_RESET_VALUE) {
			iccom_socket_err("Failed to get available protocol "
					 "family");
			return -EPFNOSUPPORT;
		}

		iccom_socket_info("Setting a new protocol family value %d "
				  "to device %s", *protocol_family, 
				  pdev->dev.kobj.name);
		return 0;
	} else if (*protocol_family < NETLINK_ICCOM) {
		iccom_socket_err("Protocol family property has a not supported "
				 "netlink value (shall be greater than or "
				 "equal to %d)", NETLINK_ICCOM);
		return -EINVAL;
	}

	int ret = 0;
	ret = driver_for_each_device(pdev->dev.driver, NULL, protocol_family, 
				&iccom_skif_check_protocol_family_availability);
	if (ret) {
		iccom_socket_err("Specified protocol family %s is already in "
				 "use or is invalid . Please use a different "
				 "one. (ret: %d)", ret);
		return -EINVAL;
	}

	return 0;
}

static int iccom_skif_device_tree_node_setup(struct platform_device *pdev, 
				struct iccom_sockets_device *iccom_skif_dev_data)
{
	iccom_socket_info("Probing an Iccom Socket via DT");

	struct device_node *iccom_sk_dt_node = pdev->dev.of_node;
	
	int ret = 0;
	ret = of_property_read_u32(iccom_sk_dt_node, "protocol_family", 
				&iccom_skif_dev_data->protocol_family_id);
	if (ret == -EOVERFLOW) {
		iccom_socket_err("Protocol family property has invalid value: "
				 "%d", ret);
		return -EINVAL;
	}
	ret = iccom_skif_validate_protocol_family(pdev,
				&(iccom_skif_dev_data->protocol_family_id));
	if (ret) {
		iccom_socket_err("Unable to validate or find valid protocol "
				 "family property: %d", ret);
		return -EINVAL;
	}

	struct device_node *iccom_dt_node = of_parse_phandle(iccom_sk_dt_node, 
								"iccom_dev", 0);
	if (IS_ERR_OR_NULL(iccom_dt_node)) {
		iccom_socket_err("Iccom_dev property is not defined or valid");
		return -EINVAL;
	}

	struct platform_device *iccom_pdev = 
				of_find_device_by_node(iccom_dt_node);
	of_node_put(iccom_dt_node);
	if (IS_ERR_OR_NULL(iccom_pdev)) {
		iccom_socket_err("Unable to find Iccom from specified node");
		return -ENODEV;
	}

	struct device_link* link = device_link_add(&pdev->dev, 
			&iccom_pdev->dev, DL_FLAG_AUTOREMOVE_CONSUMER);
	if (IS_ERR_OR_NULL(link)) {
		iccom_socket_err("Unable to bind iccom sk to specified iccom");
		return -EINVAL;
	}

	struct iccom_dev *iccom_dev_data = (struct iccom_dev *) 
				dev_get_drvdata(&iccom_pdev->dev);
	if (IS_ERR_OR_NULL(iccom_dev_data)) {
		device_link_del(link);
		iccom_skif_reset_data(iccom_skif_dev_data);
		iccom_socket_err("Unable to get Iccom device specified by "
				 "device tree node");
		return -EPROBE_DEFER;
	}

	iccom_skif_dev_data->iccom = iccom_dev_data;

	ret = iccom_skif_run(iccom_skif_dev_data);
	if (ret != 0) {
		device_link_del(link);
		iccom_skif_reset_data(iccom_skif_dev_data);
		iccom_socket_err("Iccom sk if device run failed");
		return -EINVAL;
	}
	return 0;
}

// iccom_sk_sysfs_init - registers the ICCOM Socket IF class for sysfs
//
// return: 
//	0: OK
//	!0: NOK
int iccom_socket_sysfs_init(void)
{
	return class_register(&iccom_socket_if_class);
}

// iccom_sk_sysfs_init - unregisters the ICCOM Socket IF class for sysfs
//
// return: 
//	void
void iccom_socket_sysfs_destroy(void)
{
	class_unregister(&iccom_socket_if_class);
}

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

// iccom_socket_if_probe - creates iccom socket device
//
// @pdev - refers to an iccom sockets device
//
// return:
//      0: ok
//      -EINVAL: device is null pointer
//      -ENOMEM: no memory to allocate
static int iccom_socket_if_probe(struct platform_device *pdev)
{
	if (IS_ERR_OR_NULL(pdev)) {
		iccom_socket_err("Probing a Iccom Socket Device failed: NULL");
		return -EINVAL;
	}

	iccom_socket_info("Probing an Iccom Sk Device with id: %d", pdev->id);

	struct iccom_sockets_device *iccom_skif_dev_data;

	iccom_skif_dev_data = (struct iccom_sockets_device *)
				 kzalloc(sizeof(struct iccom_sockets_device), 
					  GFP_KERNEL);
	if (IS_ERR_OR_NULL(iccom_skif_dev_data)) {
		iccom_socket_err("Probing a Iccom Socket Device failed: no "
				 "available space");
		return -ENOMEM;
	}

	int ret;
	ret = iccom_skif_init(iccom_skif_dev_data);
	if (ret < 0) {
		iccom_socket_err("Failed when probing: %d", 
				ret);
		goto free_iccom_skif_data;
	}

	if (!IS_ERR_OR_NULL(pdev->dev.of_node)) {
		ret = iccom_skif_device_tree_node_setup(pdev, iccom_skif_dev_data);
		if (ret != 0) {
			iccom_socket_err("Unable to setup device tree node: %d",
					ret);
			goto free_iccom_skif_data;
		}
	}
	dev_set_drvdata(&pdev->dev, iccom_skif_dev_data);

	return 0;

free_iccom_skif_data:
	kfree(iccom_skif_dev_data);
	return ret;
}

// iccom_socket_if_remove - remove existing device
//
// @pdev - refers to iccom device
//
// return:
//      0: probing ok
//      -EINVAL: device is null pointer
static int iccom_socket_if_remove(struct platform_device *pdev)
{
	if (IS_ERR_OR_NULL(pdev)) {
	       goto invalid_params;
	}
	iccom_socket_info("Removing an Iccom Sk Device with id: %d", pdev->id);

	struct iccom_sockets_device *iccom_sockets_dev;

	iccom_sockets_dev = (struct iccom_sockets_device *)
					       dev_get_drvdata(&pdev->dev);
	if (IS_ERR_OR_NULL(iccom_sockets_dev)) {
	       goto invalid_params;
	}

	int res = iccom_skif_close(iccom_sockets_dev);
	if (res < 0) {
	       iccom_socket_err("Module closing failed, err: %d", -res);
	}

	kfree(iccom_sockets_dev);
	iccom_sockets_dev = NULL;

	return 0;

invalid_params:
       iccom_socket_warning("Removing a Iccom Device failed - NULL pointer!");
       return -EINVAL;
}

struct of_device_id iccom_socket_if_driver_id[] = {
	{
		.compatible = "iccom_socket_if",
	}
};

struct platform_driver iccom_socket_driver = {
	.probe = iccom_socket_if_probe,
	.remove = iccom_socket_if_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "iccom_socket_if",
		.of_match_table = iccom_socket_if_driver_id,
		.dev_groups = iccom_socket_if_dev_groups
	}
};

// Callback function that retrieves the netlink socket data sent from
// userspace to kernel space. Inside this function it is searched
// which iccom socket device matches the socket inside skb and then
// the device that matches dispatches the msg.
//
// @skb {valid ptr} socket buffer containing the data and socket id
static void __iccom_socket_netlink_data_ready(struct sk_buff *skb)
{
	// NOTE: This kernel function will loop the devices till some device
	//       has the same socket id which will then stop the loop and send
	//       the data to the proper channel right away
	int ret = driver_for_each_device(&iccom_socket_driver.driver, NULL, skb,
				&__iccom_socket_select_device_for_dispatching_msg_down);

	if(ret != ICCOM_SK_FIND_DISPATCH_DEVICE_SUCESS) {
		iccom_socket_err("Failed to dispatch msg down for the "
					" iccom sk device. Error code: %d", ret);
	}
}

static int __init iccom_socket_module_init(void)
{
	int ret;

	ida_init(&iccom_skif_device_id);

	ret = platform_driver_register(&iccom_socket_driver);
	iccom_socket_sysfs_init();

	iccom_socket_info("Module loaded");
	return ret;
}

static void __exit iccom_socket_module_exit(void)
{
	ida_destroy(&iccom_skif_device_id);
	iccom_socket_sysfs_destroy();
	platform_driver_unregister(&iccom_socket_driver);

	iccom_socket_info("Module unloaded");
}

module_init(iccom_socket_module_init);
module_exit(iccom_socket_module_exit);

MODULE_DESCRIPTION("InterChipCommunication protocol User Space sockets"
		   " interface module.");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");
