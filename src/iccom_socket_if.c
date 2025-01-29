/*
 * This file defines the ICCom protocol driver userspace socket
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
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/hashtable.h>
#include <linux/ctype.h>
#include <linux/sort.h>

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
//#define ICCOM_SKIF_DEBUG

// The maximum client message size (client data size in bytes per message)
#define ICCOM_SKIF_MAX_MESSAGE_SIZE_BYTES 4096
// The minimum value for the netlink iccom socket protocol family that can be
// registered for an iccom socket device.
#define NETLINK_PROTOCOL_FAMILY_MIN 22
// The maximum value for the netlink iccom socket protocol family that can be
// registered for an iccom socket device.
#define NETLINK_PROTOCOL_FAMILY_MAX 255
// The default/reset value for the netlink iccom socket protocol family. It
// identifies whether or not the socket family has been properly initialized.
#define NETLINK_PROTOCOL_FAMILY_RESET_VALUE -1

// Defines how many extra actions can be handled by the routing rule.
#define ICCOM_SKIF_ROUTING_MAX_ACTIONS 10
// Defines number of buckets in bits (9 -> 2 ^ 9 = 512 buckets)
#define ICCOM_SKIF_ROUTING_HASH_SIZE_BITS 9
// Defines the message direction:
//	"down": originates from US.
//	"up": originates from underlying ICCom transport.
#define ICCOM_SKIF_DIR_DOWN false
#define ICCOM_SKIF_DIR_UP true

#define ICCOM_SKIF_CLOSE_POLL_PERIOD_JIFFIES msecs_to_jiffies(200)

#define ICCOM_SKIF_LOG_PREFIX "ICCom_sockets: "


// Maximal ordinary channel value. The ordinary channel can go
// from [0; ICCOM_SKIF_MAX_CHANNEL_VAL]
// And the loopback channels (loop remote end) can settle also in area
//      [ICCOM_SKIF_MAX_CHANNEL_VAL + 1; 2 * ICCOM_SKIF_MAX_CHANNEL_VAL  + 1]
// NOTE: loopback channels can go also in ordinary channel area
#define ICCOM_SKIF_MAX_CHANNEL_VAL 0x7FFF


// Value to indicate that the correct Iccom socket device has been found and
// the reveiced msg from userspace has been successfully dispatched to the
// corresponding iccom device.
#define ICCOM_SKIF_DEVICE_FOUND		1
// Value to indicate that the correct Iccom socket device has been found but
// the device is exiting hence the msg has not been dispatched.
#define ICCOM_SKIF_DEVICE_EXITING	2
// Value to indicate that the correct Iccom socket device has not been found
// hence the msg has not been dispatched.
#define ICCOM_SKIF_DEVICE_NOT_FOUND	0

/* --------------------- UTILITIES SECTION ----------------------------- */

// to keep the compatibility with Kernel versions earlier than v5.5
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
	#define pr_warning pr_warn
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
	#define ICCOM_SKIF_CLASS_MODIFIER const
	#define ICCOM_SKIF_CLASS_ATTR_MODIFIER const
#else
	#define ICCOM_SKIF_CLASS_MODIFIER
	#define ICCOM_SKIF_CLASS_ATTR_MODIFIER
#endif

#define iccom_skif_err(fmt, ...)					\
	pr_err(ICCOM_SKIF_LOG_PREFIX"%s: "fmt"\n", __func__		\
		, ##__VA_ARGS__)
#define iccom_skif_warning(fmt, ...)					\
	pr_warning(ICCOM_SKIF_LOG_PREFIX"%s: "fmt"\n", __func__	\
		, ##__VA_ARGS__)
#define iccom_skif_info(fmt, ...)					\
	pr_info(ICCOM_SKIF_LOG_PREFIX"%s: "fmt"\n", __func__		\
		, ##__VA_ARGS__)
#ifdef ICCOM_SKIF_DEBUG
#define iccom_skif_dbg(fmt, ...)					\
	pr_info(ICCOM_SKIF_LOG_PREFIX"%s: "fmt"\n", __func__		\
		, ##__VA_ARGS__)
#else
#define iccom_skif_dbg(fmt, ...)
#endif

#define iccom_skif_err_raw(fmt, ...)					\
	pr_err(ICCOM_SKIF_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_skif_warning_raw(fmt, ...)				\
	pr_warning(ICCOM_SKIF_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_skif_info_raw(fmt, ...)					\
	pr_info(ICCOM_SKIF_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#ifdef ICCOM_SKIF_DEBUG
#define iccom_skif_dbg_raw(fmt, ...)					\
	pr_info(ICCOM_SKIF_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#else
#define iccom_skif_dbg_raw(fmt, ...)
#endif

#define ICCOM_SKIF_CHECK_DEVICE(msg, error_action)			\
	if (IS_ERR_OR_NULL(iccom_sk)) {					\
		iccom_skif_err("%s: no device; "msg"\n", __func__);	\
		error_action;						\
	}

#define ICCOM_SKIF_CHECK_PTR(ptr, error_action)				\
	if (IS_ERR_OR_NULL(ptr)) {					\
		iccom_skif_err("%s: pointer "# ptr" is invalid;\n"	\
				, __func__);				\
		error_action;						\
	}

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
struct iccom_skif_loopback_mapping_rule {
	int from;
	int to;
	int shift;
};


// Describes a single action for the message being processed.
// @dst_channel the destination channel number.
// @direction the destination direction
//		0 - down (toward ICCom and further down to the other side)
//		1 - up (from ICComSkif to user space)
// NOTE: no-action registered for the channel 
// NOTE: DO NOT PACK!
struct iccom_skif_routing_action {
	int dst_channel;
	bool direction;
};


// Single rule describing the actions to be taken 
//
// NOTE: keep it in a way that zeroing the memory (except for the
//		list anchor member) would lead to valid object.
//
// @hash_list_anchor exactly this.
// @incoming_channel the channel number to which the rule should
//	be applied
// @initial_direction the initial direction of a message
//	this rule should be applied to:
//		0 - down (From user space to kernel)
//		1 - up (from kernel to user space)
// @use_default_action to use the default action or not.
// @custom_acts array of custom actions to perform on target,
//		its actual size given by @custom_acts_size
// @custom_acts_size tracks the actual size of the @custom_acts array.
struct iccom_skif_routing_rule {
	struct hlist_node hash_list_anchor;

	int incoming_channel;
	bool initial_direction;

	bool use_default_action;	

	struct iccom_skif_routing_action custom_acts[ICCOM_SKIF_ROUTING_MAX_ACTIONS];
	size_t custom_acts_size;
};

// Contains full routing information for the IccomSkif.
// @rules the hash table for all routing rules.
//		HASH KEY:
//			provided by hash function @__iccom_skif_routing_hkey.
//		NOTE: we're not working with per-element RCU handling for one
//			main reason - the routing table shall not be available in
//			transient states (per-element RCU operation leaves room
//			for transient states to be available to readers, when, say
//			half or routing table is old and half is already new).
// @allowed_by_default if set to true, then the default routing action
//		is "allow to pass". If set to false then the default routing
//		action is "block".
//		NOTE: by default set to false.
struct iccom_skif_routing {
	DECLARE_HASHTABLE(rules, ICCOM_SKIF_ROUTING_HASH_SIZE_BITS);
	bool allowed_by_default;
};

// ICCom socket interface provider.
//
// @socket the socket we are working with
// @protocol_family_id id for the socket protocol family.
//                     It can have the following values:
//                       - Between NETLINK_PROTOCOL_FAMILY_MIN and NETLINK_PROTOCOL_FAMILY_MAX
//                         is a valid value range
//                       - Value NETLINK_PROTOCOL_FAMILY_RESET_VALUE is the initialization value
//                       - Other values are invalid
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
// @lback_map_rule the channel loopback mapping rule pointer,
//      allocated on heap.
// @routing the routing rules hash table pointer, is used when routing
//		is enabled to determine what actions shall be taken for
//		this or that incoming message.
//		NOTE: if NULL: routing is disabled
struct iccom_sockets_device {
	struct sock *socket;
	int protocol_family_id;
	struct task_struct *pump_task;

	struct iccom_dev *iccom;

	struct completion initialized;
	bool exiting;
	struct completion pump_main_loop_done;
	struct completion socket_closed;

	struct iccom_skif_loopback_mapping_rule *lback_map_rule;
	struct iccom_skif_routing __rcu *routing;
};

/* -------------------------- EXTERN VARS -------------------------------*/

/* -------------------------- GLOBAL VARS -------------------------------*/

// Serves to allocate unique ids for
// creating iccom sk platform devices through
// the usage of sysfs interfaces
struct ida iccom_skif_dev_id;

/* --------------------- FORWARD DECLARATIONS ---------------------------*/

int __iccom_skif_handle_us_msg(struct device *dev, void *skb_ptr);
static bool __iccom_skif_msg_rx_callback(
		unsigned int channel
		, void *msg_data, size_t msg_len
		, void *consumer_data);
inline int __iccom_skif_routing_hkey(const uint32_t channel
		, const bool direction);
static int __iccom_skif_match_channel2lbackrule(
		const struct iccom_skif_loopback_mapping_rule *const rule
		, const int channel);
static int __iccom_skif_lback_rule_verify(
		const struct iccom_skif_loopback_mapping_rule *const rule);
inline struct iccom_skif_routing_rule *__iccom_skif_match_rule(
		struct hlist_head *rules_hash
		, int hash_size_bits, int in_channel, bool in_dir);
static int __iccom_skif_route_msg(
		struct iccom_sockets_device *iccom_sk
		, const uint32_t in_channel
		, const bool in_dir
		, const void *const data
		, const size_t data_size_bytes
		, const int priority);
inline int __iccom_skif_dispatch_msg_down(
		struct iccom_sockets_device *iccom_sk
		, const uint32_t dst_channel
		, const void *const data
		, const size_t data_size_bytes
		, const int priority);
static int __iccom_skif_dispatch_msg_up(
		struct iccom_sockets_device *iccom_sk
		, const uint32_t dst_channel
		, const void *const data
		, const size_t data_size_bytes
		, const int priority);
static int __iccom_skif_reg_socket_family(
		struct iccom_sockets_device *iccom_sk);
static void __iccom_skif_unreg_socket_family(
		struct iccom_sockets_device *iccom_sk);
static ssize_t read_loopback_rule_show(struct device *dev,
		struct device_attribute *attr
		, char *buf);
void __iccom_skif_routing_free(struct iccom_skif_routing **rt);
void __iccom_skif_routing_drop(struct iccom_sockets_device *iccom_sk);
int __iccom_skif_routing_table_append(
		struct iccom_skif_routing *from
		, struct iccom_skif_routing *to);
ssize_t __iccom_skif_print_rule(
		struct iccom_skif_routing_rule *rule
		, char *buf, ssize_t size);
static ssize_t __iccom_skif_parse_rule(
		const char *buf, size_t count
		, struct iccom_skif_routing_rule **out);
static ssize_t routing_table_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count);
static ssize_t routing_table_show(struct device *dev,
		struct device_attribute *attr,
		char *buf);
int  __iccom_skif_parse_lback_string(char *const buf
		, const size_t len
		, struct iccom_skif_loopback_mapping_rule *const out);
static ssize_t set_loopback_rule_store(struct device *dev,
		struct device_attribute *attr
		, const char *buf, size_t count);
static int __iccom_skif_loopback_ctl_init(
		struct iccom_sockets_device *iccom_sk);
static void __iccom_skif_loopback_ctl_close(
		struct iccom_sockets_device *iccom_sk);
static void __iccom_skif_protocol_device_close(
		struct iccom_sockets_device *iccom_sk);
static int __iccom_skif_protocol_device_init(
		struct iccom_sockets_device *iccom_sk);
static void iccom_skif_reset_protocol_family(struct iccom_sockets_device *iccom_sk);
static int iccom_skif_init(struct iccom_sockets_device *iccom_sk);
static int iccom_skif_close(struct iccom_sockets_device *iccom_sk);
static int iccom_skif_run(struct iccom_sockets_device *iccom_sk);
static int iccom_skif_stop(struct iccom_sockets_device *iccom_sk);
size_t iccom_skif_sysfs_trim_buffer(char *buf, size_t size);
static ssize_t version_show(
		ICCOM_SKIF_CLASS_MODIFIER struct class *class
		, ICCOM_SKIF_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, char *buf);
static ssize_t delete_device_store(
		ICCOM_SKIF_CLASS_MODIFIER struct class *class
		, ICCOM_SKIF_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count);
static ssize_t create_device_store(
		ICCOM_SKIF_CLASS_MODIFIER struct class *class
		, ICCOM_SKIF_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count);
static ssize_t iccom_dev_show(struct device *dev
		, struct device_attribute *attr
		, char *buf);
static ssize_t iccom_dev_store(struct device *dev
		, struct device_attribute *attr
		, const char *buf, size_t count);
static int iccom_skif_pfamily_avail(struct device *dev, void *data);
static ssize_t protocol_family_store(struct device *dev,
		struct device_attribute *attr
		, const char *buf, size_t count);
static int iccom_skif_new_pfamily(struct platform_device *pdev);
static int iccom_skif_validate_pfamily(struct platform_device *pdev
		, int *protocol_family);
static int iccom_skif_device_tree_node_setup(
		struct platform_device *pdev
		, struct iccom_sockets_device *iccom_sk);
static int iccom_skif_probe(struct platform_device *pdev);
static int iccom_skif_remove(struct platform_device *pdev);
static void __iccom_skif_netlink_data_ready(struct sk_buff *skb);
static int __init iccom_skif_module_init(void);
static void __exit iccom_skif_module_exit(void);


/* --------------------- ENTRY POINTS -----------------------------------*/

// Searches the iccom socket device that shall transmit the msg
// received from UserSpace down to the corresponding iccom instance.
// The search is done by comparing the socket id from socket buffer
// and iccom socket device socket id.
//
// NOTE: it doesn't own the message data.
//
// @dev {valid ptr} iccom socket device
// @skb_ptr {valid ptr} struct sk_buff ptr with the socket data received
//                   to be dispatched.
//
// RETURNS:
//      ICCOM_SKIF_DEVICE_FOUND: Iccom sk device found hence msg dispatched.
//      ICCOM_SKIF_DEVICE_NOT_FOUND: Iccom sk device not found hence msg
//			not dispatched.
//      ICCOM_SKIF_DEVICE_EXITING:  Iccom sk device found but exiting
//			hence msg not dispatched.
//     -EFAULT: pointers are null
int __iccom_skif_handle_us_msg(struct device *dev, void *skb_ptr)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ptr;

	if (IS_ERR_OR_NULL(dev)) {
		iccom_skif_err("device is null");
		return -EFAULT;
	}

	if (IS_ERR_OR_NULL(skb)) {
		iccom_skif_err("skb ptr is null");
		return -EFAULT;
	}

	struct iccom_sockets_device *iccom_sk =
				(struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("Invalid socket device.");
		return -EFAULT;
	}

	if (skb->sk != iccom_sk->socket) {
		iccom_skif_info("Iccom socket device socket is different than the "
					"received one. Msg not for this device but for other device.");
		return ICCOM_SKIF_DEVICE_NOT_FOUND;
	}

	if (iccom_sk->exiting) {
		iccom_skif_err("iccom sk device is exiting");
		return ICCOM_SKIF_DEVICE_EXITING;
	}

	struct nlmsghdr *nl_header = (struct nlmsghdr *)skb->data;
	// TODO: use bitfields here
	uint32_t channel = NETLINK_CB(skb).portid & 0x00007FFF;
	// TODO: use bitfields here
	uint32_t priority = ((uint32_t)nl_header->nlmsg_type) >> 8;

	if (!NLMSG_OK(nl_header, skb->len)) {
		iccom_skif_warning("Broken netlink message rq to be sent:"
					" socket id: %d; ignored;"
					, channel);
		return -EINVAL;
	}

	__iccom_skif_route_msg(
			iccom_sk
			, channel
			, ICCOM_SKIF_DIR_DOWN
			, NLMSG_DATA(nl_header)
			, NLMSG_PAYLOAD(nl_header, 0)
			, priority);

	return ICCOM_SKIF_DEVICE_FOUND;
}

// Is called whenever inderlying protocol layer gets new message
// for us from the other side.
static bool __iccom_skif_msg_rx_callback(
		unsigned int channel
		, void *msg_data, size_t msg_len
		, void *consumer_data)
{
	struct iccom_sockets_device *iccom_sk
			= (struct iccom_sockets_device *)consumer_data;

	ICCOM_SKIF_CHECK_DEVICE("", return false);

	__iccom_skif_route_msg(iccom_sk
			, channel
			, ICCOM_SKIF_DIR_UP
			, msg_data
			, msg_len
			, 0);

	// we will not take ownership over the msg_data
	return false;
}

/* --------------------- GENERAL SECTION --------------------------------*/

// Helper. Generates hash key for given channel and original message
// direction.
// @channel incoming message incoming channel #
// @direction incoming message original direction
//		0 - down,
//		1 - up
inline int __iccom_skif_routing_hkey(const uint32_t channel
				, const bool direction)
{
	// just set the top bit to the direction.
	return channel | ((direction ? 1 : 0) << 31);
}

// Helper. Shows the relationship between loopback loop and the channel
//      number.
//
// RETURNS:
//      >0: when given channel represents is local end of the loop
//      0: when given channel has nothing to do with loopback, or loopback
//         is not accessible
//      <0: when given channel represents is remote end of the loop
static int __iccom_skif_match_channel2lbackrule(
	const struct iccom_skif_loopback_mapping_rule *const rule
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
static int __iccom_skif_lback_rule_verify(
	const struct iccom_skif_loopback_mapping_rule *const rule)
{
	// if shift is zero, the rule is disabled
	if (rule->shift == 0) {
		return 0;
	}

	if (rule->from < 0 || rule->from > ICCOM_SKIF_MAX_CHANNEL_VAL) {
		iccom_skif_err("'from' out of bounds: %d", rule->from);
		return -EINVAL;
	}
	if (rule->to < 0 || rule->to > ICCOM_SKIF_MAX_CHANNEL_VAL) {
		iccom_skif_err("'to' out of bounds: %d", rule->to);
		return -EINVAL;
	}
	if (rule->to < rule->from) {
		iccom_skif_err("'from'(%d) < 'to'(%d)"
				 , rule->from, rule->to);
		return -EINVAL;
	}
	if (rule->to + rule->shift > 2 * ICCOM_SKIF_MAX_CHANNEL_VAL + 1
			|| rule->from + rule->shift < 0) {
		iccom_skif_err("'shift'(%d) moves segment out of"
				 " bounds", rule->shift);
		return -EINVAL;
	}
	if (abs(rule->shift) < rule->to - rule->from + 1) {
		iccom_skif_err("'shift'(%d) moves segment on its own"
				 , rule->shift);
		return -EINVAL;
	}
	return 0;
}

// @rules_hash array of hash buckets.
// @hash_size_bits the number of hash buckets (buckets count: 2^hash_size_bits)
// @in_channel the incoming message channel.
// @in_dir the incoming message initial direction, 1 - up, 0 - down.
//
// RETURNS: pointer to the matching rule, if rule matches given
//		filter data. If no rule matches: NULL.
//
// THREADING: no locking, no checks, no RCU locking, nothing:
//		caller MUST care.
inline struct iccom_skif_routing_rule *__iccom_skif_match_rule(
		struct hlist_head *rules_hash
		, int hash_size_bits, int in_channel, bool in_dir)
{
	const int hkey = __iccom_skif_routing_hkey(in_channel, in_dir);

	struct hlist_head *rth_head = &(rules_hash[hash_min(hkey, hash_size_bits)]);

	struct iccom_skif_routing_rule *rule;

	hlist_for_each_entry(rule, rth_head, hash_list_anchor)	{
		if (rule->incoming_channel == in_channel
				&& rule->initial_direction == in_dir) {
			return rule;
		}
	}
	return NULL;
}

// Just a comparator for the struct iccom_skif_routing_action.
// Orders first by the destination channel, and then by direction.
// Down direction is "smaller" than up direction.
int __iccom_skif_routing_action_cmp(
	const void *a, const void *b, const void *priv)
{
	(void)priv;
	struct iccom_skif_routing_action *first = (struct iccom_skif_routing_action*)(a);
	struct iccom_skif_routing_action *second = (struct iccom_skif_routing_action*)(b);

	if (first->dst_channel < second->dst_channel) {
		return -1;
	}
	if (first->dst_channel > second->dst_channel) {
		return 1;
	}
	if (first->direction == second->direction) {
		return 0;
	}
	if (first->direction == false) {
		return -1;
	}
	return 1;
}

// Merges two rules @dst and @add into @dst using the OR logic.
// NOTE: modifies both dst and add by sorting their actions
// NOTE: if merge fails will not revert data to the original state.
// @dst {VALID ptr to the rule}
// @add {NULL | VALID ptr to the rule}, if NULL then just returns.
// RETURNS: 0: merge successful
//		<0: merge failed
// CONTEXT: rules are not modified in parallel
static int __iccom_skif_merge_rules(
	struct iccom_skif_routing_rule *const dst
	, struct iccom_skif_routing_rule *const add)
{
	if (IS_ERR_OR_NULL(add)) {
		return 0;
	}
	if (IS_ERR_OR_NULL(dst)) {
		return -EINVAL;
	}

	if (add->use_default_action) {
		dst->use_default_action = true;
	}

	// jep, small arrays, not really relevant, but still

	// sorting both dst and add
	sort_r(dst->custom_acts, dst->custom_acts_size
		   , sizeof(dst->custom_acts[0])
		   , __iccom_skif_routing_action_cmp
		   , NULL, NULL);
	sort_r(add->custom_acts, add->custom_acts_size
		   , sizeof(add->custom_acts[0])
		   , __iccom_skif_routing_action_cmp
		   , NULL, NULL);

	// merging both together in one and dropping duplicated entries
	struct iccom_skif_routing_action tmp[2 * ICCOM_SKIF_ROUTING_MAX_ACTIONS];
	int i = 0; // dst idx
	int j = 0; // add idx
	int tgt = 0;
	while ((i < dst->custom_acts_size || j < add->custom_acts_size)
			&& tgt < ARRAY_SIZE(tmp)) {
		// selecting which source is smaller
		int cmp;
		if (i >= dst->custom_acts_size) {
			cmp = 1;
		} else if (j >= add->custom_acts_size) {
			cmp = -1;
		} else {
			cmp = __iccom_skif_routing_action_cmp(
				&dst->custom_acts[i], &add->custom_acts[j], NULL);
		}

		// taking the smaller value from source
		struct iccom_skif_routing_action *value = NULL;
		if (cmp < 0) {
			value = &dst->custom_acts[i];
			i++;
		} else if (cmp > 0) {
			value = &add->custom_acts[j];
			j++;
		} else {
			value = &dst->custom_acts[i];
			i++;
			j++;
		}

		// writing it into array if prev value there is not equal
		// to to-be-inserted one
		if (tgt == 0 
			|| __iccom_skif_routing_action_cmp(&tmp[tgt - 1]
			                                   , value, NULL) < 0){
			tmp[tgt] = *value;
			tgt++;
		}
	}

	const int result_len = tgt;

	if (result_len > ICCOM_SKIF_ROUTING_MAX_ACTIONS) {
		iccom_skif_err("can not merge routing rules, result is too big.");
		return -EFBIG;
	}			

	memcpy(dst->custom_acts, tmp, result_len * sizeof(tmp[0]));
	dst->custom_acts_size = result_len;

	return 0;
}

// Processes the message according to the current routing configuration.
// If routing is enabled follows the routing rules provided by userland.
// If routing is disabled then only classical loopback functionality is
// available.
// NOTE: so, either routing is enabled OR loopback (not together).
//
// @in_channel the channel via which message arrived
// @in_dir the initial direction of the incoming message
//		0 - down
//		1 - up
// @data the message data ptr
// @data_size_bytes size of the @data in bytes
// @priority the message priority (not used for now)
//
// RETURNS:
//      0: success
//      <0: negated error code, if fails
static int __iccom_skif_route_msg(
		struct iccom_sockets_device *iccom_sk
		, const uint32_t in_channel
		, const bool in_dir
		, const void *const data
		, const size_t data_size_bytes
		, const int priority)
{
	// classical path (no-routing, only loopback available)
	if (IS_ERR_OR_NULL(iccom_sk->routing)) {
		if (in_dir == ICCOM_SKIF_DIR_UP) {
			const int lback = __iccom_skif_match_channel2lbackrule(
						iccom_sk->lback_map_rule, in_channel);
			// loopback mode for this channel was enabled, so external
			// party is dropped from the loop channel
			if (lback != 0) {
				return 0;
			}

			return __iccom_skif_dispatch_msg_up(
						iccom_sk, in_channel, data, data_size_bytes
						, priority);
		} else if (in_dir == ICCOM_SKIF_DIR_DOWN) {
			const int lback = __iccom_skif_match_channel2lbackrule(
						iccom_sk->lback_map_rule, in_channel);
			// loopback mode for this channel
			if (lback != 0) {
				const int shift = iccom_sk->lback_map_rule->shift;
				const uint32_t dst_ch = (lback > 0) ? (in_channel + shift)
									: (in_channel - shift);
				return __iccom_skif_dispatch_msg_up(iccom_sk
							, dst_ch, data, data_size_bytes, priority);
			}

			return __iccom_skif_dispatch_msg_down(iccom_sk
							, in_channel, data, data_size_bytes, priority);
		}
		return 0;
	}

	struct iccom_skif_routing_rule *rule = NULL;

	// NOTE: +1 for default action
	typeof(rule->custom_acts[0]) acts[ARRAY_SIZE(rule->custom_acts) + 1];
	size_t acts_size = 0;
	bool use_default = false;

	// Just getting the rule in RCU way.
	// NOTE: we can not lock while we sending, cause send might block,
	//		that is why we need a copy-on-stack of the actions.
	rcu_read_lock();
	struct iccom_skif_routing *rt = rcu_dereference(iccom_sk->routing);
	if (!IS_ERR_OR_NULL(rt)) {
		rule = __iccom_skif_match_rule(
					rt->rules, ICCOM_SKIF_ROUTING_HASH_SIZE_BITS
					, in_channel, in_dir);
		if (!IS_ERR_OR_NULL(rule)) {
			// The fastest way to copy.
			// NOTE: we rely on routing action to be padded to alignment.
			memcpy(&acts[0], &rule->custom_acts[0]
				, sizeof(acts[0]) * rule->custom_acts_size);
			acts_size = rule->custom_acts_size;
			// NOTE: if channel is mentioned, then it will not be under
			//	global default.
			use_default = rule->use_default_action;
		} else {
			// NOTE: if channel is not mentioned, then it will be under
			//	global default.
			use_default = rt->allowed_by_default;
		}
	}
	rcu_read_unlock();

	if (use_default) {
		struct iccom_skif_routing_action ra = {
				.dst_channel= in_channel, .direction = in_dir };
		acts[acts_size] = ra;
		acts_size += 1;
	}

	// Executing the rule
	for (int i = 0; i < acts_size; i++) {
		if (acts[i].direction == ICCOM_SKIF_DIR_UP) {
			__iccom_skif_dispatch_msg_up(
						iccom_sk, acts[i].dst_channel, data, data_size_bytes
						, priority);
		} else if (acts[i].direction == ICCOM_SKIF_DIR_DOWN) {
			__iccom_skif_dispatch_msg_down(
						iccom_sk, acts[i].dst_channel, data, data_size_bytes
						, priority);
		}
	}
	return 0;
}

// Sends the message toward the underlying ICCom driver.
//
// @iccom_sk {valid iccom socket dev ptr}
// @dsg_channel {valid channel number} target channel to send the msg.
// @data {valid data ptr}
// @data_size_bytes {size of data pointed by @data}
// @priority the priority of the message (not used for now)
//
// NOTE: doesn't have ownership over the message data.
//
// The message header is used in following way:
// * nlmsg_type -> the destination channel (port number)
// * nlmsg_flags (lo byte) -> priority
// * nlmsg_pid -> sending process port ID
//
// RETURNS:
//      0: success
//      <0: negated error code, if fails
inline int __iccom_skif_dispatch_msg_down(
		struct iccom_sockets_device *iccom_sk
		, const uint32_t dst_channel
		, const void *const data
		, const size_t data_size_bytes
		, const int priority)
{
	iccom_skif_dbg_raw("-> TX data (ch. %d):", dst_channel);
#ifdef ICCOM_SKIF_DEBUG
	print_hex_dump(KERN_DEBUG
			, ICCOM_SKIF_LOG_PREFIX"   -> TX data: "
			, 0, 16, 1, NLMSG_DATA(data)
			, data_size_bytes
			, true);
#endif

	return iccom_post_message(iccom_sk->iccom
			, data, data_size_bytes, dst_channel, priority);
}

// Sends the given message up to the netlink socket and correspondingly
// to userspace application behind it.
//
// NOTE: does NOT take ownership over message data: just copies it.
//
// @iccom_sk {valid iccom socket dev ptr}
// @dsg_channel {valid channel number} target channel to send the msg.
// @data {valid data ptr}
// @data_size_bytes {size of data pointed by @data}
// @priority the priority of the message (not used for now)
//
// RETURNS:
//      0: success
//      <0: negated error code, if fails
static int __iccom_skif_dispatch_msg_up(
		struct iccom_sockets_device *iccom_sk
		, const uint32_t dst_channel
		, const void *const data
		, const size_t data_size_bytes
		, const int priority)
{
	if (data_size_bytes > ICCOM_SKIF_MAX_MESSAGE_SIZE_BYTES) {
		iccom_skif_err("received message is bigger than max"
				"  allowed: %lu > %d bytes; dropping;"
				, (unsigned long)data_size_bytes
				, ICCOM_SKIF_MAX_MESSAGE_SIZE_BYTES);
		return -ENOMEM;
	}
	const uint32_t dst_port_id = dst_channel;

	//   TODO: reuse allocated memory if possible
	struct sk_buff *sk_buffer = alloc_skb(NLMSG_SPACE(data_size_bytes),
						GFP_KERNEL);

	if (IS_ERR_OR_NULL(sk_buffer)) {
		iccom_skif_err("could not allocate socket buffer,"
					" req. size: %lu"
					, (unsigned long)NLMSG_SPACE(data_size_bytes));
		return -EPIPE;
	}

	struct nlmsghdr *nl_header = __nlmsg_put(sk_buffer, dst_port_id
							, 0, 0, data_size_bytes
							, 0);

	memcpy(NLMSG_DATA(nl_header), data, data_size_bytes);

	NETLINK_CB(sk_buffer).portid = 0;
	NETLINK_CB(sk_buffer).dst_group = 0;
	NETLINK_CB(sk_buffer).flags = 0;

	iccom_skif_dbg_raw("<- data to userspace (ch. %d):"
				, dst_port_id);
#ifdef ICCOM_SKIF_DEBUG
	print_hex_dump(KERN_DEBUG
			, ICCOM_SKIF_LOG_PREFIX"US <- RX data: "
			, 0, 16, 1, data, data_size_bytes, true);
#endif

	// NOTE: sending to the port == 0 (channel == 0), will lead to
	//	us ourselves to receive the message back =)
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
		iccom_skif_err("Send to userspace failed, err: %d"
					, -res);
	}

	return res;
}

// RETURNS:
//      0: if success
//      negated error code: if fails
static int __iccom_skif_reg_socket_family(
		struct iccom_sockets_device *iccom_sk)
{
	struct netlink_kernel_cfg netlink_cfg = {
			.groups = 0
			, .flags = 0
			, .input = &__iccom_skif_netlink_data_ready
			, .cb_mutex = NULL
			, .bind = NULL
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
			, .compare = NULL
#endif
			};
	// TODO: optionally: add support for earlier versions of kernel
	iccom_sk->socket = netlink_kernel_create(&init_net
						 , iccom_sk->protocol_family_id
					, &netlink_cfg);

	if (IS_ERR(iccom_sk->socket)) {
		return PTR_ERR(iccom_sk->socket);
	} else if (!iccom_sk->socket) {
		iccom_skif_err("could not create kernel netlink socket"
				" for family: %d", iccom_sk->protocol_family_id);
		return -ENODEV;
	}
	return 0;
}

// Unregisters iccom socket family.
static void __iccom_skif_unreg_socket_family(
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

// Provides an ability to read loopback rule from userspace.
//
//
// RETURNS:
//      >= 0: number of bytes actually provided to userspace, on success
//      < 0: negated error code, on failure
static ssize_t read_loopback_rule_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	ICCOM_SKIF_CHECK_PTR(buf, return -EINVAL);

	struct iccom_sockets_device *iccom_sk
		= (struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("Invalid parameters.");
		return -EINVAL;
	}

	const struct iccom_skif_loopback_mapping_rule *const rule
				= iccom_sk->lback_map_rule;

	size_t len = (size_t)scnprintf(buf, PAGE_SIZE, "%d %d %d\n\n"
					"NOTE: the loopback will map the "
					"[a;b] channels other sides to"
					" [a + shift; b + shift] local "
					"channels where a = first argument"
					", b = second argument,"
					" shift = third argument\n"
					, rule->from, rule->to, rule->shift);
	return len;
}
static DEVICE_ATTR_RO(read_loopback_rule);

// Frees resources related to the routing table and sets routing
// object pointer to NULL.
//
// @rt {valid ptr to routing ptr} pointer to routing object pointer.
//		NOTE: if pointer to the routing is NULL, then does nothing.
//
// THREADING:
//		no protections on any concurrency. Caller is responsible
//		to take care of it.
void __iccom_skif_routing_free(struct iccom_skif_routing **rt)
{
	if (IS_ERR_OR_NULL(*rt)) {
		return;
	}

	// clean up old routing table
	int bucket;
	struct iccom_skif_routing_rule *rule;
	struct hlist_node *node;

	hash_for_each_safe((*rt)->rules, bucket, node, rule, hash_list_anchor) {
		hlist_del(&rule->hash_list_anchor);
		kfree(rule);
	}
	kfree(*rt);
	*rt = NULL;
}

// Drops the routing table, and thus switches the IccomSkif into
// classical mode.
//
// THREADING: MUST NOT be called in concurrent way (caller has to ensure
//    that no concurrent __iccom_skif_routing_drop(...) is carried out)
//
// @iccom_sk {valid ptr} the IccomSkif device.
void __iccom_skif_routing_drop(struct iccom_sockets_device *iccom_sk)
{
	struct iccom_skif_routing *old_rt = rcu_dereference(iccom_sk->routing);
	rcu_assign_pointer(iccom_sk->routing, NULL);
	synchronize_rcu();
	__iccom_skif_routing_free(&old_rt);
	iccom_skif_info("Dropped routing table.");
}

// Appends routing table contents from routing table @from to
// routing table @to.
//
// NOTE: for now just raw implementation without duplications check.
// NOTE: copies the entries from @from to @to, doesn't move them, cause
//    usually we want to have the original table intact, while we creating
//    the next version of table.
// NOTE: if fails, the @to might have partial data imported from @from.
//
// @from {NULL | valid ptr} the valid routing table to read contents from.
//		NOTE: if NULL, then function just returns with success.
// @to {valid ptr} the valid routing table to append the contents to.
//      NOTE: the routing table must be initialized.
//
// RETURNS:
//    0: on success,
//    <0: negated error code on failure
//
// THREADING: 
//		No locking / sync is used for @from neither for @to.
//      Caller must ensure that @from is not altered in parallel, and
//      that @to is not read / altered in parallel.
int __iccom_skif_routing_table_append(
	struct iccom_skif_routing *from
	, struct iccom_skif_routing *to)
{
	if (IS_ERR_OR_NULL(from)) {
		return 0;
	}

	int bkt;
	struct iccom_skif_routing_rule *rule = NULL;
	hash_for_each(from->rules, bkt, rule, hash_list_anchor) {
		struct iccom_skif_routing_rule *new_rule = kmalloc(sizeof(*new_rule), GFP_KERNEL);
		if (IS_ERR_OR_NULL(new_rule)) {
			iccom_skif_err("No memory for new routing table rule, sorry.");
			return -ENOMEM;
		}
		*new_rule = *rule;
		INIT_HLIST_NODE(&new_rule->hash_list_anchor);
		hash_add(to->rules, &new_rule->hash_list_anchor
					, __iccom_skif_routing_hkey(new_rule->incoming_channel
												, new_rule->initial_direction));
	}

	return 0;
}

// Prints out the given rule into string buffer.
// Guarantees that the buf will be a valid C-string.
//
// @rule {valid rule valid ptr | NULL}.
//		If NULL then does nothing.
// @buf {ptr to the buffer of size @size}
// @size @buf size
//
// RETURNS: the number of chars written into the buffer not including
//		the final \0 char.
ssize_t __iccom_skif_print_rule(
				struct iccom_skif_routing_rule *rule
				, char *buf, ssize_t size)
{
	if (IS_ERR_OR_NULL(rule)) {
		return 0;	
	}

	ssize_t count = 0;

	// the incoming msg selector
	count += scnprintf(buf + count, size - count, "%u%c", rule->incoming_channel
					, rule->initial_direction ? 'u' : 'd');
	
	if (rule->use_default_action) {
		count += scnprintf(buf + count, size - count, " x");
	}

	for (int i = 0; i < rule->custom_acts_size; i++) {
		count += scnprintf(buf + count, size - count, " %u%c"
					, rule->custom_acts[i].dst_channel
					, rule->custom_acts[i].direction ? 'u' : 'd');
	}

	count += scnprintf(buf + count, size - count, ";");
	return count;
}

// Parses the ONE rule from one-rule-describing C-string.
//
// NOTE: All whitespace (including \n) will be ignored.
// NOTE: the rules are separated by ;
//
// NOTE: at the end of parsing the read cursor will be located at
//    the first non-space char after the just-parsed-rule.
//
// @buf points to the beginning of the C-string to parse (must be
//    null-terminated).
//    NOTE: All whitespace (including \n) will be ignored.
//	  NOTE: buf[count - 1] must be == 0.
// @count the number of chars available in the buffer, including
//    the \0 char at the end.
// @out in case of success this pointer will be set to newly created
//    rule, else will be set to NULL.
//
// RETURNS:
//		0: nothing was parsed - faced EOF,
//         in this case @out will be set to NULL.
//		>0: number of chars successfully parced into a rule,
//          in this case @out will point to the newly created rule.
//		<0: error faced (negated value).
//         in this case @out will be set to NULL.
static ssize_t __iccom_skif_parse_rule(
					const char *buf, size_t count
					, struct iccom_skif_routing_rule **out)
{
	const size_t orig_count = count;

	*out = NULL;
	int ret = 0;

	if (buf[count - 1] != 0) {
		iccom_skif_err("C-string must be provided. 0 must be a buffer end.");
		return -EINVAL;
	}
	if (count == 1) {
		return 0;
	}

	struct iccom_skif_routing_rule *rule = kzalloc(sizeof(*rule), GFP_KERNEL);

	if (IS_ERR_OR_NULL(rule)) {
		iccom_skif_err("No memory for new rule, sorry.");
		return -ENOMEM;
	}

	INIT_HLIST_NODE(&rule->hash_list_anchor);

	// Rule format described in @routing_table_store comments.

	uint32_t channel = 0;
	char dir_char = 0;
	int chars_parsed = 0;
	#define ICCOM_SKIF_JUMP_PARSE() \
		{ count -= chars_parsed; buf += chars_parsed; chars_parsed = 0; }

	// incoming message parameters
    int args_count = sscanf(buf, " %u %c %n", &channel, &dir_char, &chars_parsed);
	if (args_count != 2 || (dir_char != 'u' && dir_char != 'd')) {
		iccom_skif_err("Rule parsing error, the Rule string must start with"
		               " message incoming channel number (positive int) and"
					   " then the char 'u' or 'd' describing initial message"
					   " direction. Example:  \"1234u\" or \" 1234 u\"for"
					   " message incoming via channel 1234 and originally"
					   " directing upwards.\n\n"
					   " NOTE: all whitespaces including newlines are ignored.\n"
					   "\n"
					   " Offending location: %s\n", buf);
		ret = -EINVAL;
		goto cleanup_rule;
	}

	rule->incoming_channel = channel;
	rule->initial_direction = (dir_char == 'u');

	ICCOM_SKIF_JUMP_PARSE();

	// scan actions, one per cycle
	while (count) {
		chars_parsed = skip_spaces(buf) - buf;
		ICCOM_SKIF_JUMP_PARSE();

		// the default action check
		if (count && buf[0] == 'x') {
			rule->use_default_action = true;
			chars_parsed = 1;
			ICCOM_SKIF_JUMP_PARSE();
			continue;
		}
		if (count && buf[0] == ';') {
			// parsing done
			chars_parsed = 1;
			ICCOM_SKIF_JUMP_PARSE();
			break;
		}
		if (count && buf[0] == 0) {
			iccom_skif_err("Something got wrong, 0-char mid of"
					" the string buffer, while semicolon or"
					" next action is expected.");
			ret = -EINVAL;
			goto cleanup_rule;
		}

		// incoming message parameters
		args_count = sscanf(buf, " %u %c %n", &channel, &dir_char, &chars_parsed);
		if (args_count != 2 || (dir_char != 'u' && dir_char != 'd')) {
			iccom_skif_err(
					"Rule parsing error, the Rule action list must follow"
					" the Rule header (message incoming channel number + "
					" initial message direction). The action list itself"
					" consists of 0 or more action records. After last action"
					" there MUST be a ';' char which denotes the end of the"
					" rule record. Each action consists of"
					" Target channel number (unsigned int) followed by target"
					" message direction 'u' (upwards) or 'd' (downwards)."
					" Alternatively rule can be one 'x' char saying \"default\""
					" action to be taken (continue same channel same direction)."
					" Example:  \"234d\" to send message downwards via channel"
					" 234.\n"
					"\n"
					" Offending location: %s", buf);
			ret = -EINVAL;
			goto cleanup_rule;
		}

		if (rule->custom_acts_size >= ICCOM_SKIF_ROUTING_MAX_ACTIONS) {
			iccom_skif_err("Sorry, we don't support more than "
					" %d custom actions per rule (this can be configured"
					" at build time).\n"
					"\n"
					" Offending location: %s"
					, ICCOM_SKIF_ROUTING_MAX_ACTIONS, buf);
			ret = -EINVAL;
			goto cleanup_rule;
		}

		const bool direction = (dir_char == 'u');
		if (channel == rule->incoming_channel
				&& direction == rule->initial_direction) {
			rule->use_default_action = true;
		} else {
			rule->custom_acts[rule->custom_acts_size].dst_channel = channel;
			rule->custom_acts[rule->custom_acts_size].direction = direction;
			rule->custom_acts_size += 1;
		}

		ICCOM_SKIF_JUMP_PARSE();
	}

	// to be a bit more predictable to simplify tests as well: sort the actions
	sort_r(rule->custom_acts, rule->custom_acts_size
		   , sizeof(rule->custom_acts[0])
		   , __iccom_skif_routing_action_cmp
		   , NULL, NULL);

	*out = rule;
	return orig_count - count;

cleanup_rule:
	kfree(rule);
	return ret;
	#undef ICCOM_SKIF_JUMP_PARSE
}

// Provides an ability to set the routing table from US.
//
// NOTE: @count counts the string length without final 0.
// 
// NOTE: writing "-;" command string disables routing and IccomSkif goes
//		into classical mode (with only loopback option available).
//
// NOTE: if routing is enabled, then EVERYTHING WHICH IS NOT EXPLICITLY
//		ALLOWED IS BLOCKED.
//
// NOTE: no need to syncronize routing table writes, cause sysfs
//		shall take care of write operations sync.	
//
// FORMAT: 			(NOTE: ${X} means "contents of X")
//
//		NOTE: input format is a sequence of commands. Commands
//			are separated with semicolons. All whitespaces are ignored.
//			Each command must end with semicolon (including the last one).
//
//  * <GLOBAL_COMMANDS_LIST>:  "${CMD};${CMD};....${CMD};"
//		OPTIONAL SEMICOLON SEPARATED LIST of global commands, available
//		commands are:
//		* "+":
//          when given, then the incoming data will be appended to
//          existing table
//		* "-":
//			will drop the routing and switch IccomSkif into classic mode.
//		* `x`:
//          set default action for all channels and directions to `allow`,
//		    meaning that if channel is not mentioned explicitly in routing
//		    table, then the message will just continue as it goes: same
//			channel, same direction.
//
//		EXAMPLE:
//			"+; <some rules here>" will append the rules defined after "+"
//			command to the existing routing table.
//		EXAMPLE:
//			" x;\n" will drop the routing and switch to the classic mode.
//			NOTE: all whitespaces including newlines are ignored.
//
//  * <RULES_LIST>: "${RULE};${RULE};...${RULE};"
//  	A SEMICOLON SEPARATED LIST of rules. All whitespaces including
//      newlines are ignored.
//
//		Each RULE is the string of following format:
//      * "${INCOMING_CHANNEL_NUMBER}${INCOMING_DIR}${ACTION}...${ACTION}"
//         where:
//         * INCOMING_CHANNEL_NUMBER is positive decimal integer
//           describing original message channel.
//             * EXAMPLE: "1234"
//         * INCOMING_DIR is original message direction: either 'u'
//           for UPWARD direction (from transport driver to User Space),
//           OR 'd' for DOWNWARD direction (from US to transport driver)
//             * EXAMPLE: "u"
//         * ACTION is either "x" for default action, or a string:
//			 "${DST_CHANNEL}${DST_DIRECTION}", where
//             * DST_CHANNEL is the channel number to send the msg
//                 * EXAMPLE: "421"
//             * DST_DIRECTION is the destination direction to send
//               the msg ('u' or 'd'):
//                 * EXAMPLE: "d"
//
//	Here are some full examples:
//
//	EXAMPLE:
//
// 		NOTE: all whitespaces including newlines are ignored.
//
//		" - ;\n"
//          same as next example
//		"-;"
//          Global command: disable routing, switch to classical mode.
//		"123ux;\n"
//          One rule: messages incoming via ch 123 UPWARDS will be subjected
//          to default action (continue upwards the same channel),
//          all other channels and directions are blocked.
//		"123u 24u 351u 1000d x;"
//			same as next example:
//		" 123u 24u 351u 1000d x;  \n\n"
//			same as next example:
//		"123u24u351u1000dx;"
//          One rule: messages incoming via ch 123 UPWARDS will be sent to
//          * channel 24 upwards,
//          * channel 351 upwards,
//          * channel 1000 downwards,
//          * channel 123 upwards (default),
//          all other channels and directions are blocked.
//		"123ux;\n"
//		" 123dx  ;\n"
//          Two rules. Messages on ch 123 will continue as they go
//          (so 123 channel is bidirectional IO),
//          all other channels are blocked.
//		"123ux;"
//		"123dx;"
//		"3411ux;"
//		"5522dx;"
//          4 rules. Messages on ch 123 will continue as they go
//          (so 123 channel is bidirectional IO),
//			channel 3411 is readonly for US,
//          channel 5522 is writeonly for US,
//          all other channels are blocked.
//		"123ux1111u;"
//		"123dx1111u;"
//		"3411ux1111u;"
//		"5522dx1111u;"
//          4 rules. Messages on ch 123 will continue as they go
//          (so 123 channel is bidirectional IO),
//			channel 3411 is readonly for US,
//          channel 5522 is writeonly for US,
//			copy of all non-blocked messages will be
//			delivered to channel 1111 toward US,
//          all other channels are blocked.
//
// RETURNS:
//      >= 0: number of bytes actually provided to userspace, on success
//      < 0: negated error code, on failure
static ssize_t routing_table_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	ICCOM_SKIF_CHECK_PTR(buf, return -EINVAL);

	struct iccom_sockets_device *iccom_sk
		= (struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("No iccom_skif device.");
		return -EINVAL;
	}

	if (buf[count] != 0) {
		iccom_skif_err("Input buffer must be a valid C-string, and end up with 0-char.");
		return -EINVAL;
	}

	const char *orig_buf = buf;
	const size_t orig_count = count;

	int ret = 0;

	#define ICCOM_SKIF_JUMP_PARSE() \
		{ count -= chars_parsed; buf += chars_parsed; chars_parsed = 0; }

	// OK, starting parsing.

	char global_cmd = 0;
	int chars_parsed = 0;
	// NOTE: the return of sscanf does NOT include %n chars parsed variable
	int args_count = sscanf(buf, " %c ; %n", &global_cmd, &chars_parsed);

	// got global cmd
	if (args_count == 1 && chars_parsed) {
		ICCOM_SKIF_JUMP_PARSE();
	}

	// If the cmd is "-", then routing
	// gets disabled and IccomSkif switches into classical mode.
	if (global_cmd == '-') {
		if (count > 0) {
			iccom_skif_info("Extra data is expected with global command '-'."
			                " If you drop the table, just use \"x;\" with optional"
							" whitespaces here-there. Incoming table: %s\n"
							" Stopped at pos %zu, chars left: %zu."
							, orig_buf, buf - orig_buf, count);
			return -EINVAL;
		}
		// NOTE: sysfs takes care that there are no concurrent write IO
		__iccom_skif_routing_drop(iccom_sk);
		return orig_count;
	}
	
	// preparing a new routing table
	struct iccom_skif_routing *new_rt = kmalloc(sizeof(*new_rt), GFP_KERNEL);

	if (IS_ERR_OR_NULL(new_rt)) {
		iccom_skif_err("No memory for new routing table, sorry.");
		return -ENOMEM;
	}

	hash_init(new_rt->rules);
	new_rt->allowed_by_default = false;

	// "x" means "use the 'allowed' as default instead of 'blocked'"
	if (global_cmd == 'x') {
		new_rt->allowed_by_default = true;
	}

	// If first cmd is "+" then we append new table to existing routing table.
	if (global_cmd == '+') {
		// NOTE: just raw "+" - no effect, old rt persists
		if (count == 0) {
			ret = orig_count;
			iccom_skif_info("Old routing table persisted with no changes."
					" If you want to append the rules to existing table just"
					" append them after \"+;\" command.");
			goto release_new_rt;
		}

		// NOTE: sysfs takes care that only one writer presents at every
		//  moment. We can safely read the Routing Table without
		//  concurrency concerns (as long as this sysfs store call the
		//  only guy who can change routing table).

		// NOTE: we don't do the move of the buckets, cause a lock shall be
		//  needed in this case, else readers will see table routing in a
		//  transient state (some buckets are moved and some remain attached,
		//  which is inconsistent).

		if (__iccom_skif_routing_table_append(iccom_sk->routing, new_rt) != 0) {
			ret = -ENOMEM;
			iccom_skif_err("Failed to append old rules.");
			goto release_new_rt;
		};
	}

	// now parsing the rules.
	int rule_idx = 0;
	while (count) {
		// just drop all whitespace incl newlines between rules
		while (count) {
			if (isspace(*buf) || *buf == '\n' || *buf == '\r') {
				chars_parsed = 1;
				ICCOM_SKIF_JUMP_PARSE();
			} else {
				break;
			}
		}
		struct iccom_skif_routing_rule *new_rule;
		chars_parsed = __iccom_skif_parse_rule(buf, count + 1, &new_rule);
		if (chars_parsed < 0) {
			iccom_skif_err("Failed to parse the Routing Table: \"%s\"."
			 		" Failed rule position: %zu, rule index: %d"
					, orig_buf, buf - orig_buf, rule_idx);
			ret = -EINVAL;
			goto release_new_rt;
		}

		if (!chars_parsed) {
			iccom_skif_info("Routing Table was successfully parsed.");
			break;
		}

		// check it it already exists, then discard it
		
		struct iccom_skif_routing_rule *const existing_rule = __iccom_skif_match_rule(
					new_rt->rules, ICCOM_SKIF_ROUTING_HASH_SIZE_BITS
					, new_rule->incoming_channel, new_rule->initial_direction);
		if (IS_ERR_OR_NULL(existing_rule)) {
			hash_add(new_rt->rules, &new_rule->hash_list_anchor
						, __iccom_skif_routing_hkey(new_rule->incoming_channel
													, new_rule->initial_direction));
		} else {
			// merge rules with OR logic
			ret = __iccom_skif_merge_rules(existing_rule, new_rule);

			kfree(new_rule);
			new_rule = NULL;

			if (ret < 0) {
				iccom_skif_warning("Failed to make a full merge of : \"%s\" into"
						" the current table. Failed merge rule position: %zu,"
						" rule index: %d. All changes will be discarded."
						, orig_buf, buf - orig_buf, rule_idx);
				goto release_new_rt;
			}
		}

		rule_idx += 1;
		ICCOM_SKIF_JUMP_PARSE();
	}

	// NOTE: as long as store is the only RT updater, the sysfs will take care
	// 	about avoiding concurrent updaters.
	struct iccom_skif_routing *old_rt = iccom_sk->routing;
	rcu_assign_pointer(iccom_sk->routing, new_rt);

	synchronize_rcu();
	__iccom_skif_routing_free(&old_rt);

	return orig_count;

release_new_rt:
	__iccom_skif_routing_free(&new_rt);
	return ret;

	#undef ICCOM_SKIF_JUMP_PARSE
}

// Exhibits the current Routing Table to the US.
//
// NOTE: for the format description see the @routing_table_store function.
//
// NOTE: for now we're limit ourselves to one PAGE output size.
//
// RETURNS:
//      >= 0: number of bytes actually provided to userspace, on success
//      < 0: negated error code, on failure
static ssize_t routing_table_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	ICCOM_SKIF_CHECK_PTR(buf, return -EINVAL);

	struct iccom_sockets_device *iccom_sk
		= (struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("Invalid parameters.");
		return -EINVAL;
	}

	ssize_t count = 0;

	rcu_read_lock();

	struct iccom_skif_routing *rt = rcu_dereference(iccom_sk->routing);

	// routing disabled case
	if (IS_ERR_OR_NULL(rt)) {
		count += scnprintf(buf + count, PAGE_SIZE - count, "-;");
		goto done;
	}

	// routing enabled

	if (rt->allowed_by_default) {
		count += scnprintf(buf + count, PAGE_SIZE - count, "x;\n");
	}

	int bkt;
	struct iccom_skif_routing_rule *rule = NULL;
	hash_for_each(rt->rules, bkt, rule, hash_list_anchor) {
		count += __iccom_skif_print_rule(rule, buf + count, PAGE_SIZE - count);
		// to look nice, split in lines
		count += scnprintf(buf + count, PAGE_SIZE - count, "\n");
	}

done:
	rcu_read_unlock();
	return count;
}
static DEVICE_ATTR(routing_table, 0600, routing_table_show, routing_table_store);

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
int  __iccom_skif_parse_lback_string(char *const buf
		, const size_t len
		, struct iccom_skif_loopback_mapping_rule *const out)
{
	ICCOM_SKIF_CHECK_PTR(buf, return -EINVAL);
	ICCOM_SKIF_CHECK_PTR(out, return -EINVAL);

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
			iccom_skif_err("failed parsing arg %d in: %s"
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

	if (__iccom_skif_lback_rule_verify(out) < 0) {
		return -EINVAL;
	}

	return 0;
}

// Provides an ability to update (and also disable) current loopback
// rule from userspace.
//
//
// RETURNS:
//      >= 0: number of bytes actually were written, on success
//      < 0: negated error code, on failure
static ssize_t set_loopback_rule_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	ICCOM_SKIF_CHECK_PTR(buf, return -EINVAL);

	struct iccom_sockets_device *iccom_sk
		= (struct iccom_sockets_device *)dev_get_drvdata(dev);
	int ret = 0;

	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("Invalid parameters.");
		return -EINVAL;
	}

	const unsigned int BUFFER_SIZE = 64;

	// we only get the whole data at once
	if (count > BUFFER_SIZE) {
		iccom_skif_warning(
			"Ctrl message should be written at once"
			" and not exceed %u bytes.", BUFFER_SIZE);
		return -EFAULT;
	}

	char *buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

	if (IS_ERR_OR_NULL(buffer)) {
		iccom_skif_err("failed to create new rule buffer:"
				 " no memory");
		return -ENOMEM;
	}
	memcpy(buffer, buf, count);

	struct iccom_skif_loopback_mapping_rule parsing_res;
	ret = __iccom_skif_parse_lback_string(buffer, count, &parsing_res);
	if (ret < 0) {
		iccom_skif_warning("Parsing failed: %s", buffer);
		goto finalize;
	}

	struct iccom_skif_loopback_mapping_rule * new_rule
				= (struct iccom_skif_loopback_mapping_rule *)
					kmalloc(sizeof(*new_rule), GFP_KERNEL);
	if (IS_ERR_OR_NULL(new_rule)) {
		iccom_skif_err("failed to create new loopback rule:"
				 " no memory");
		ret = -ENOMEM;
		goto finalize;
	}
	*new_rule = parsing_res;

	struct iccom_skif_loopback_mapping_rule *tmp_ptr
				= iccom_sk->lback_map_rule;
	WRITE_ONCE(iccom_sk->lback_map_rule, new_rule);

	if (!IS_ERR_OR_NULL(tmp_ptr)) {
		// BAD! RefCounter needed! The old map-rule might
		// be still in use at the moment of deletion!
		kfree(tmp_ptr);
		tmp_ptr = NULL;
	}

	ret = count;

finalize:
	kfree(buffer);
	buffer = NULL;

	return ret;
}
static DEVICE_ATTR_WO(set_loopback_rule);

// Helper. Initializes the loopback control on ICCom Sockets.
//
// NOTE: The loopback default rule (turned off) will be allocated
//       and initialized.
//
// RETURNS:
//      >= 0: on success,
//      < 0: on failure (negated error code)
static int __iccom_skif_loopback_ctl_init(
		struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SKIF_CHECK_DEVICE("", return -ENODEV);

	// initial rule data
	iccom_sk->lback_map_rule = (struct iccom_skif_loopback_mapping_rule *)
					kmalloc(sizeof(*iccom_sk->lback_map_rule)
						, GFP_KERNEL);
	if (IS_ERR_OR_NULL(iccom_sk->lback_map_rule)) {
		iccom_skif_err("failed to create loopback rule:"
				 " no memory");
		return -ENOMEM;
	}
	memset(iccom_sk->lback_map_rule, 0, sizeof(*iccom_sk->lback_map_rule));

	return 0;
}

// Closes the iccom sk loopback controller
static void __iccom_skif_loopback_ctl_close(
		struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SKIF_CHECK_DEVICE("", return);

	if (!IS_ERR_OR_NULL(iccom_sk->lback_map_rule)) {
		struct iccom_skif_loopback_mapping_rule *ptr
			= iccom_sk->lback_map_rule;
		iccom_sk->lback_map_rule = NULL;

		kfree(ptr);
		ptr = NULL;
	}
}

// Closes underlying protocol layer.
static void __iccom_skif_protocol_device_close(
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
static int __iccom_skif_protocol_device_init(
		struct iccom_sockets_device *iccom_sk)
{
	int res = iccom_set_channel_callback(iccom_sk->iccom
			, ICCOM_ANY_CHANNEL_VALUE
			, &__iccom_skif_msg_rx_callback
			, (void *)iccom_sk);
	if (res < 0) {
		__iccom_skif_protocol_device_close(iccom_sk);
		return res;
	}
	return res;
}

// Resets the iccom socket netlink protocol family to its default value
//
// @iccom_sk - iccom sk device to have its data reset
static void iccom_skif_reset_protocol_family(struct iccom_sockets_device *iccom_sk)
{
	if (!IS_ERR_OR_NULL(iccom_sk)) {
		memset(iccom_sk, 0, sizeof(*iccom_sk));
		iccom_sk->protocol_family_id = NETLINK_PROTOCOL_FAMILY_RESET_VALUE;
	}
}

// Initializes the iccom socket device data structure
//
// @iccom_sk - iccom sk device to initialize
//
// RETURNS:
//      0: if success
//      <0: negated error code else
static int iccom_skif_init(struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SKIF_CHECK_DEVICE("", return -ENODEV);

	iccom_sk->iccom = NULL;
	iccom_sk->lback_map_rule = NULL;

	rcu_assign_pointer(iccom_sk->routing, NULL);
	iccom_skif_reset_protocol_family(iccom_sk);
	init_completion(&iccom_sk->initialized);
	init_completion(&iccom_sk->socket_closed);
	init_completion(&iccom_sk->pump_main_loop_done);
	__iccom_skif_loopback_ctl_init(iccom_sk);
	complete(&iccom_sk->initialized);

	iccom_skif_info("iccom socket if initialization completed");
	return 0;
}

// Closes whole iccom socket device inclusive all
// underlying layers
//
// @iccom_sk - iccom sk device to close
//
// RETURNS:
//      0: if success
//      <0: negated error code else
static int iccom_skif_close(struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SKIF_CHECK_DEVICE("", return -ENODEV);

	// order matters
	__iccom_skif_loopback_ctl_close(iccom_sk);
	__iccom_skif_unreg_socket_family(iccom_sk);
	__iccom_skif_protocol_device_close(iccom_sk);
	iccom_skif_reset_protocol_family(iccom_sk);
	__iccom_skif_routing_drop(iccom_sk);

	return 0;
}

// Launches iccom sockets interface layer
//
// @iccom_sk - iccom sk device to launch
//
// RETURNS:
//      0: if success
//      <0: negated error code else
static int iccom_skif_run(struct iccom_sockets_device *iccom_sk)
{
	ICCOM_SKIF_CHECK_DEVICE("", return -ENODEV);

	// order matters
	int res = __iccom_skif_reg_socket_family(iccom_sk);
	if (res < 0) {
		goto failed;
	}
	iccom_skif_info_raw("opened kernel netlink socket: %px, family: %d"
				, iccom_sk->socket, iccom_sk->protocol_family_id);
	res = __iccom_skif_protocol_device_init(iccom_sk);
	if (res < 0) {
		goto failed;
	}

	// launches pump thread
	complete(&iccom_sk->initialized);

	iccom_skif_info_raw("protocol device initialization done");
	return 0;

failed:
	iccom_skif_close(iccom_sk);
	return res;
}

// Stops iccom sockets interface layer
//
// @iccom_sk - iccom sk device to stop
//
// RETURNS:
//      0: if success
//      <0: negated error code else
__maybe_unused
static int iccom_skif_stop(struct iccom_sockets_device *iccom_sk)
{
	int ret = 0;

	ret = iccom_remove_channel_callback(iccom_sk->iccom,
					ICCOM_ANY_CHANNEL_VALUE);
	if (ret < 0) {
		iccom_skif_err("Unable to stop the iccom sk if");
		return ret;
	}

	__iccom_skif_protocol_device_close(iccom_sk);

	return 0;
}

// Trims a sysfs input buffer coming from userspace
// wich might have unwanted characters
//
// @buf {valid prt} buffer to be trimmed
// @size {number} size of data valid without 0-terminator
//
//RETURNS
// count: size of valid data within the array
size_t iccom_skif_sysfs_trim_buffer(char *buf, size_t size)
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
// @class {valid ptr} iccom sk class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to write output to user space
//
// RETURNS:
//      0: no data to be displayed
//     > 0: size of data to be showed in user space
//      <0: negated error code
static ssize_t version_show(
		ICCOM_SKIF_CLASS_MODIFIER struct class *class
		, ICCOM_SKIF_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s", ICCOM_VERSION);
}
static CLASS_ATTR_RO(version);

// The sysfs delete_device_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file delete_iccom.
// It shall delete the iccom socket device wich matchs the provided id.
//
// @class {valid ptr} iccom socket class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the 0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//  count: ok
//     <0: negated error code
static ssize_t delete_device_store(
		ICCOM_SKIF_CLASS_MODIFIER struct class *class
		, ICCOM_SKIF_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count)
{
	if (count >= PAGE_SIZE) {
		iccom_skif_err("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	// NOTE: count is a length without the last 0-terminator char
	if (buf[count] != 0) {
		iccom_skif_err("NON-null-terminated string is provided by sysfs.");
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
		iccom_skif_err("NON-null-terminated string is provided by sysfs.");
		kfree(device_name);
		device_name = NULL;
		return -EFAULT;
	}

	(void)iccom_skif_sysfs_trim_buffer(device_name, count);

	struct device *device_to_delete =
		bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);
	device_name = NULL;

	if (IS_ERR_OR_NULL(device_to_delete)) {
		iccom_skif_err("Unable to find provided device.");
		return -EFAULT;
	}

	platform_device_unregister(to_platform_device(device_to_delete));

	return count;
}
static CLASS_ATTR_WO(delete_device);

// The sysfs create_device_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file create_device.
// It shall create iccom socket devices with an unique id.
//
// @class {valid ptr} iccom socket class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the 0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//  count: ok
//     <0: negated error code
static ssize_t create_device_store(
		ICCOM_SKIF_CLASS_MODIFIER struct class *class
		, ICCOM_SKIF_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count)
{
	int device_id = ida_alloc(&iccom_skif_dev_id, GFP_KERNEL);
	if (device_id < 0) {
		iccom_skif_err("Could not allocate a new unused ID");
		return -EINVAL;
	}

	struct platform_device * new_pdev =
				platform_device_register_simple("iccom_socket_if", device_id,
							NULL, 0);
	if (IS_ERR_OR_NULL(new_pdev)) {
		iccom_skif_err("Could not register the device iccom socket.%d",
				 device_id);
		return -EINVAL;
	}
	iccom_skif_info("Iccom Scif device .%s created", dev_name(&new_pdev->dev));

	return count;
}
static CLASS_ATTR_WO(create_device);

// List containing all iccom socket class attributes
//
// @class_attr_version sysfs file for checking
//                     the version of ICCom
// @class_attr_create_device sysfs file for creating
//                          iccom socket devices
// @class_attr_delete_device sysfs file for deleting
//                          iccom socket devices
static struct attribute *iccom_skif_class_attrs[] = {
	&class_attr_version.attr,
	&class_attr_create_device.attr,
	&class_attr_delete_device.attr,
	NULL
};

ATTRIBUTE_GROUPS(iccom_skif_class);

// The ICCom socket class definition
//
// @name class name
// @owner the module owner
// @class_groups group holding all the attributes
static struct class iccom_skif_class = {
	.name = "iccom_socket_if",
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
	.owner = THIS_MODULE,
#endif
	.class_groups = iccom_skif_class_groups
};

// The sysfs iccom_dev_show function get's triggered
// whenever from userspace one wants to read the sysfs
// file iccom_dev.
// It checkes whether the iccom socket device is associated alread
// with an iccom device.
//
// @dev {valid ptr} iccom socket device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to userspace
//
// RETURNS:
//      0: no iccom associated
//    > 0: device is associated
static ssize_t iccom_dev_show(struct device *dev, struct device_attribute *attr,
				char *buf)
{
	struct iccom_sockets_device *iccom_sk =
				(struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("Invalid parameters.");
		return 0;
	}

	if (IS_ERR_OR_NULL(iccom_sk->iccom)) {
		iccom_skif_err("Iccom Sk has no Iccom device "
				 "associtated/invalid.");
		return 0;
	}

	return scnprintf(buf, PAGE_SIZE, "Iccom Sk has an Iccom device already "
				"associated: %s", kobject_name(&(dev->kobj)));
}

// The sysfs iccom_dev_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file iccom_dev.
// Binds an iccom device to an iccom socket device.
//
// @dev {valid ptr} iccom socket device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer with the data from userspace
// @count {number} the @buf string length not-including the 0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//    >=0: iccom associated successfully
//     <0: negated error code
static ssize_t iccom_dev_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct iccom_sockets_device *iccom_sk =
				(struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("Invalid iccom sockets device.");
		return -EINVAL;
	}

	if (!IS_ERR_OR_NULL(iccom_sk->iccom)) {
		iccom_skif_err("Iccom device already associated Iccom socket");
		return -EINVAL;
	}

	if (count >= PAGE_SIZE) {
		iccom_skif_err("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	// NOTE: count is a length without the last 0-terminator char
	if (buf[count] != 0) {
		iccom_skif_err("NON-null-terminated string is provided by sysfs.");
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

	(void)iccom_skif_sysfs_trim_buffer(device_name, count);

	struct device *iccom_dev_to_link =
			bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);
	device_name = NULL;

	if (IS_ERR_OR_NULL(iccom_dev_to_link)) {
		iccom_skif_err("Iccom device given as input is invalid.");
		return -EINVAL;
	}

	struct device_link* link = device_link_add(dev, iccom_dev_to_link,
						DL_FLAG_AUTOREMOVE_CONSUMER);
	if (IS_ERR_OR_NULL(link)) {
		iccom_skif_err("Unable to bind iccom sk to provided iccom.");
		return -EINVAL;
	}

	struct iccom_dev *iccom =
			(struct iccom_dev *) dev_get_drvdata(iccom_dev_to_link);
	if (IS_ERR_OR_NULL(iccom)) {
		device_link_del(link);
		iccom_skif_err("Iccom device given as input is invalid.");
		return -EINVAL;
	}

	iccom_sk->iccom = iccom;

	int ret = iccom_skif_run(iccom_sk);
	if (ret != 0) {
		device_link_del(link);
		iccom_skif_err("Iccom sk if device run failed.");
		return -EINVAL;
	}

	iccom_skif_info("Iccom device binding to Iccom socket device was "
				"sucessful");
	return count;
}
static DEVICE_ATTR_RW(iccom_dev);

// Traverses the platform driver devices (iccom socket devices) that are registered
// and checks if given netlink protocol family number is already in use
//
// @dev - iccom socket device
// @data - protocol family number
//
// return:
//      0 - input protocol family is not assigned to existing devices
//      1 - input protocol family is already in use (stops search)
static int iccom_skif_pfamily_avail(struct device *dev, void *data)
{
	struct iccom_sockets_device *iccom_sk =
			(struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk) || IS_ERR_OR_NULL(data)) {
		iccom_skif_err("Invalid parameters.");
		return -ENOENT;
	}

	int protocol_family = *((int *)data);

	if (protocol_family == iccom_sk->protocol_family_id) {
		return 1;
	}
	return 0;
}

// The sysfs protocol_family_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file protocol_family.
// Sets the netlink protocol family to an iccom socket device.
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer with the data from userspace
// @count {number} the @buf string length not-including the 0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//    >=0: protocol family associated successfully
//     <0: negated error code
static ssize_t protocol_family_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct iccom_sockets_device *iccom_sk =
				(struct iccom_sockets_device *)dev_get_drvdata(dev);

	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("Invalid parameters.");
		return -EINVAL;
	}

	if (iccom_sk->protocol_family_id != NETLINK_PROTOCOL_FAMILY_RESET_VALUE) {
		iccom_skif_err("Protocol family is already assigned to this "
					"iccom socket interface device (current value "
					"%d).", iccom_sk->protocol_family_id);
		return -EPFNOSUPPORT;
	}

	if (count >= PAGE_SIZE) {
		iccom_skif_err("Input data is longer than expected (%lu)",
					PAGE_SIZE);
		return -EINVAL;
	}

	unsigned int protocol_family;
	int ret = 0;

	ret = kstrtouint(buf, 10, &protocol_family);
	if (ret != 0) {
		iccom_skif_err("Specified protocol family %s is invalid "
					"(error:%d)",
			buf, ret);
		return -EINVAL;
	}

	if (protocol_family == NETLINK_PROTOCOL_FAMILY_RESET_VALUE) {
		iccom_skif_err("Protocol family is already with reset value. You need to specify a "
					"different value than the reset value ("
					"%d).", NETLINK_PROTOCOL_FAMILY_RESET_VALUE);
		return -EINVAL;
	}

	ret = driver_for_each_device(dev->driver, NULL, &protocol_family,
				&iccom_skif_pfamily_avail);
	if (ret != 0) {
		iccom_skif_err("Specified protocol family %s is already in "
					"use. Please use a different one. (ret: %d)",
					buf, ret);
		return -EINVAL;
	}

	iccom_sk->protocol_family_id = protocol_family;

	return count;
}
static DEVICE_ATTR_WO(protocol_family);

// List containing default attributes that an
// iccom socket device can have.
//
// @dev_attr_iccom_dev the ICCom socket iccom_dev file
// @dev_attr_protocol_family the ICCom socket protocol_family file
// @dev_attr_read_loopback_rule the ICCOM socket read_loopback_rule file
// @dev_attr_set_loopback_rule the ICCOM socket set_loopback_rule file
// @dev_attr_routing_table the ICComSkif routing table IO.
static struct attribute *iccom_skif_dev_attrs[] = {
	&dev_attr_iccom_dev.attr,
	&dev_attr_protocol_family.attr,
	&dev_attr_read_loopback_rule.attr,
	&dev_attr_set_loopback_rule.attr,
	&dev_attr_routing_table.attr,
	NULL
};

ATTRIBUTE_GROUPS(iccom_skif_dev);

// Finds a netlink protocol family which is not yet in use
// by any iccom socket device.
//
// @pdev - iccom socket device
//
// return:
//      >0: protocol family to be used
//      <0: no netlink protocol family available
static int iccom_skif_new_pfamily(struct platform_device *pdev)
{
	int ret = 0;

	for (int protocol_family = NETLINK_PROTOCOL_FAMILY_MIN;
			protocol_family < NETLINK_PROTOCOL_FAMILY_MAX+1;
			protocol_family++) {
		ret = driver_for_each_device(pdev->dev.driver, NULL, &protocol_family,
				&iccom_skif_pfamily_avail);
		if (!ret) {
			iccom_skif_info("Found available protocol family %d",
					protocol_family);
			return protocol_family;
		}
	}
	return NETLINK_PROTOCOL_FAMILY_RESET_VALUE;
}

// Verifies whether the netlink protocol family is between the minimum and
// maximum range allowed for iccom socket devices and that no iccom socket
// device is using the family protocols.
//
// @pdev - iccom socket device
// @protocol_family - protocol family to be verified
//
// return:
//      0: verification was successfull and protocol family can be used
//     <0: negated error code
static int iccom_skif_validate_pfamily(struct platform_device *pdev,
							int *protocol_family)
{
	if (IS_ERR_OR_NULL(pdev) || IS_ERR_OR_NULL(protocol_family)) {
		iccom_skif_err("Invalid parameters to validate protocol "
					"family");
		return -EINVAL;
	}

	if (*protocol_family == NETLINK_PROTOCOL_FAMILY_RESET_VALUE) {
		iccom_skif_warning("Protocol family property is not defined "
					"or does not have a value");
		*protocol_family = iccom_skif_new_pfamily(pdev);
		if (*protocol_family == NETLINK_PROTOCOL_FAMILY_RESET_VALUE) {
			iccom_skif_err("Failed to get available protocol "
					 "family");
			return -EPFNOSUPPORT;
		}

		iccom_skif_info("Setting a new protocol family value %d "
					"to device %s", *protocol_family,
					pdev->dev.kobj.name);
		return 0;
	} else if (*protocol_family < NETLINK_PROTOCOL_FAMILY_MIN ||
				*protocol_family > NETLINK_PROTOCOL_FAMILY_MAX) {
		iccom_skif_err("Protocol family property %d has a not supported "
					"netlink value (shall be respect the following range "
					"[%d, %d])", *protocol_family
					, NETLINK_PROTOCOL_FAMILY_MIN
					, NETLINK_PROTOCOL_FAMILY_MAX);
		return -EINVAL;
	}

	int ret = driver_for_each_device(pdev->dev.driver, NULL, protocol_family,
				&iccom_skif_pfamily_avail);
	if (ret) {
		iccom_skif_err("Specified protocol family %d is already in "
				 "use or is invalid . Please use a different "
				 "one. (ret: %d)", *protocol_family, ret);
		return -EINVAL;
	}

	return 0;
}

// Function to parse the device tree and associate the iccom
// device to the corresponding iccom socket device. It expects to have a
// phandle in iccom socket instance to a iccom (iccom_dev) and the
// protocol_family attribute in the device tree.
// After parsing is completed successfully the iccom socket device get's initialized
// and binded to the iccom and the iccom socket is capable of using the iccom
// in its fully capabilities.
//
// @pdev {valid ptr} iccom socket device
// @iccom_sk {valid prt} pointer to corresponding iccom_sk structure.
//
// RETURNS:
//    >=0: Successfully parsed device tree and setup iccom socket device
//     <0: negated error code
static int iccom_skif_device_tree_node_setup(struct platform_device *pdev,
				struct iccom_sockets_device *iccom_sk)
{
	iccom_skif_info("Probing an Iccom Socket via DT");

	struct device_node *iccom_skif_dt_node = pdev->dev.of_node;

	int ret = 0;
	ret = of_property_read_u32(iccom_skif_dt_node, "protocol_family",
				&iccom_sk->protocol_family_id);
	if (ret == -EOVERFLOW) {
		iccom_skif_err("Protocol family property has invalid value: "
				 "%d", ret);
		return -EINVAL;
	}
	ret = iccom_skif_validate_pfamily(pdev,
				&(iccom_sk->protocol_family_id));
	if (ret) {
		iccom_skif_err("Unable to validate or find valid protocol "
				 "family property: %d", ret);
		return -EINVAL;
	}

	struct device_node *iccom_dt_node = of_parse_phandle(iccom_skif_dt_node,
								"iccom_dev", 0);
	if (IS_ERR_OR_NULL(iccom_dt_node)) {
		iccom_skif_err("Iccom_dev property is not defined or valid");
		return -EINVAL;
	}

	struct platform_device *iccom_pdev =
				of_find_device_by_node(iccom_dt_node);
	of_node_put(iccom_dt_node);
	if (IS_ERR_OR_NULL(iccom_pdev)) {
		iccom_skif_err("Unable to find Iccom from specified node");
		return -ENODEV;
	}

	struct device_link* link = device_link_add(&pdev->dev,
			&iccom_pdev->dev, DL_FLAG_AUTOREMOVE_CONSUMER);
	if (IS_ERR_OR_NULL(link)) {
		iccom_skif_err("Unable to bind iccom sk to specified iccom");
		return -EINVAL;
	}

	struct iccom_dev *iccom = (struct iccom_dev *)
				dev_get_drvdata(&iccom_pdev->dev);
	if (IS_ERR_OR_NULL(iccom)) {
		device_link_del(link);
		iccom_skif_reset_protocol_family(iccom_sk);
		iccom_skif_err("Unable to get Iccom device specified by "
				 "device tree node");
		return -EPROBE_DEFER;
	}

	iccom_sk->iccom = iccom;

	ret = iccom_skif_run(iccom_sk);
	if (ret != 0) {
		device_link_del(link);
		iccom_skif_reset_protocol_family(iccom_sk);
		iccom_skif_err("Iccom sk if device run failed");
		return -EINVAL;
	}
	return 0;
}

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

// Probing function for iccom socket devices wich get's
// called whenever a new device is found. It allocates
// the device structure needed in memory and initializes
// the iccom socket properties.
//
// @pdev {valid ptr} iccom socket platform device
//
// RETURNS:
//      0: Successfully probed the device
//     <0: negated error code
static int iccom_skif_probe(struct platform_device *pdev)
{
	if (IS_ERR_OR_NULL(pdev)) {
		iccom_skif_err("probing a Iccom Socket device failed: NULL");
		return -EINVAL;
	}

	iccom_skif_info("probing IccomSkif device with id: %d", pdev->id);

	struct iccom_sockets_device *iccom_sk =
			(struct iccom_sockets_device *)kzalloc(sizeof(struct iccom_sockets_device),
						GFP_KERNEL);
	if (IS_ERR_OR_NULL(iccom_sk)) {
		iccom_skif_err("Probing a Iccom Socket Device failed: no "
				 "available space");
		return -ENOMEM;
	}

	int ret = iccom_skif_init(iccom_sk);
	if (ret < 0) {
		iccom_skif_err("Failed when probing: %d",
				ret);
		goto free_iccom_skif_data;
	}

	if (!IS_ERR_OR_NULL(pdev->dev.of_node)) {
		ret = iccom_skif_device_tree_node_setup(pdev, iccom_sk);
		if (ret != 0) {
			iccom_skif_err("Unable to setup device tree node: %d", ret);
			goto free_iccom_skif_data;
		}
	}
	dev_set_drvdata(&pdev->dev, iccom_sk);

	iccom_skif_info("IccomSkif device %s created.", dev_name(&pdev->dev));

	return 0;

free_iccom_skif_data:
	kfree(iccom_sk);
	iccom_sk = NULL;
	return ret;
}

// Remove function for iccom socket devices wich get's called
// whenever the device will be destroyed. It frees the
// device structure allocated previously in the probe
// function and stops the iccom socket.
//
// @pdev {valid ptr} iccom socket platform device
//
// RETURNS:
//      0: Successfully removed the device
//     <0: negated error code
static int iccom_skif_remove(struct platform_device *pdev)
{
	if (IS_ERR_OR_NULL(pdev)) {
		goto invalid_params;
	}
	iccom_skif_info("Removing an Iccom Sk Device with id: %d", pdev->id);

	struct iccom_sockets_device *iccom_sk =
				(struct iccom_sockets_device *) dev_get_drvdata(&pdev->dev);
	if (IS_ERR_OR_NULL(iccom_sk)) {
		goto invalid_params;
	}

	int res = iccom_skif_close(iccom_sk);
	if (res < 0) {
		iccom_skif_err("Module closing failed, err: %d", -res);
	}

	kfree(iccom_sk);
	iccom_sk = NULL;

	return 0;

invalid_params:
	iccom_skif_warning("Removing a Iccom Device failed - NULL pointer!");
	return -EINVAL;
}

// The ICCom socket driver compatible definition for
// matching the driver to devices available
//
// @compatible name of compatible driver
struct of_device_id iccom_skif_driver_id[] = {
	{
		.compatible = "iccom_socket_if",
	},
	{}
};

// The ICCom socket driver definition
//
// @probe probe device function
// @remove remove device function
// @driver structure driver definition
// @driver::owner the module owner
// @driver::name name of driver
// @driver::of_match_table compatible driver devices
// @driver::dev_groups devices groups with all attributes
struct platform_driver iccom_skif_driver = {
	.probe = iccom_skif_probe,
	.remove = iccom_skif_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "iccom_socket_if",
		.of_match_table = iccom_skif_driver_id,
		.dev_groups = iccom_skif_dev_groups
	}
};

// Callback function that retrieves the netlink socket data sent from
// userspace to kernel space. Inside this function it is searched
// which iccom socket device's socket id matches the skb's socket id
// and then the device that matches dispatches the msg.
//
// @skb {valid ptr} socket buffer containing the data and socket id
static void __iccom_skif_netlink_data_ready(struct sk_buff *skb)
{
	// NOTE: This kernel function will loop the iccom socket devices till
	//       one of the devices socket id matches the skb socket id. Then
	//       the msg from skb will be dispatched through the found iccom
	//       socket device.
	int ret = driver_for_each_device(&iccom_skif_driver.driver, NULL, skb,
				&__iccom_skif_handle_us_msg);

	if (ret != ICCOM_SKIF_DEVICE_FOUND) {
		iccom_skif_err("Failed to dispatch msg down for the "
					" iccom sk device. Error code: %d", ret);
	}
}

// Module init method to register the iccom socket driver
// and the sysfs class and initialize the ida
//
// RETURNS:
//      0: Successfully loaded the module
//     <0: negated error code
static int __init iccom_skif_module_init(void)
{
	ida_init(&iccom_skif_dev_id);

	int ret = platform_driver_register(&iccom_skif_driver);
	if (ret != 0) {
		pr_err("iccom_skif: failed to register platform driver.");
		goto unroll_ida;
	}

	ret = class_register(&iccom_skif_class);
	if (ret != 0) {
		pr_err("iccom_skif: failed to register iccom_skif class.");
		goto unroll_platform_driver;
	}

	iccom_skif_info("Module loaded");

	return 0;

unroll_platform_driver:
	platform_driver_unregister(&iccom_skif_driver);
unroll_ida:
	ida_destroy(&iccom_skif_dev_id);

	return ret;
}

// Module exit method to unregister the iccom socket driver,
// and unregister the sysfs class and destroy the ida
static void __exit iccom_skif_module_exit(void)
{
	ida_destroy(&iccom_skif_dev_id);
	class_unregister(&iccom_skif_class);
	platform_driver_unregister(&iccom_skif_driver);

	iccom_skif_info("Module unloaded");
}

module_init(iccom_skif_module_init);
module_exit(iccom_skif_module_exit);

MODULE_DESCRIPTION("InterChipCommunication protocol userspace sockets"
		   " interface module.");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");
