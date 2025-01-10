//// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ BEGIN
/*
 * This file provides a ICCom bus based TTY driver. ICCom TTY device
 * is attached to specific ICCom channel (usually provided by DT config),
 * and turns this channel into TTY device (as seeing from user land).
 * So the UART/serial data stream is tunneled through ICCom channel
 * and gets exposed to user land as usual local TTY device.
 *
 * Copyright (c) 2024 Robert Bosch GmbH
 * Artem Gulyaev <Artem.Gulyaev@de.bosch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
#include <linux/container_of.h>
#endif
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/stringify.h>
#include <linux/delay.h>

#include <linux/iccom.h>

// Debuging level.
// 0: debugging disabled
// >0: debugging enabled
#ifndef ICTTY_DEBUG_LEVEL
	#define ICTTY_DEBUG_LEVEL 0
#endif

// This value will be used when nothing is explicitly set by DT or other configuration
// means.
#define ICTTY_DEFAULT_MAX_MSG_SIZE 256

#define ICCOM_TTY_NAME	"ttyICCOM"

#define ICCOM_TTY_MAX_TTY_COUNT 16

#define ICCOM_DEV_NAME_LEN 63
#define ICCOM_TTY_NODE_NAME_LEN 63

/* --------------------- UTILITIES SECTION ----------------------------- */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
	#define ICCOM_TTY_CLASS_MODIFIER const
	#define ICCOM_TTY_CLASS_ATTR_MODIFIER const
#else
	#define ICCOM_TTY_CLASS_MODIFIER
	#define ICCOM_TTY_CLASS_ATTR_MODIFIER
#endif

#define ICTTY_LOG_PREFIX "ictty: "

#define ICTTY_DEV ictty->base_pdev->dev

#define ictty_emerg(fmt, ...)                                               \
    dev_emerg(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n"       \
              , __func__, __LINE__, ##__VA_ARGS__)
#define ictty_crit(fmt, ...)                                                \
    dev_crit(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n"        \
              , __func__, __LINE__, ##__VA_ARGS__)
#define ictty_alert(fmt, ...)                                               \
    dev_alert(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n"       \
              , __func__, __LINE__, ##__VA_ARGS__)
#define ictty_err(fmt, ...)                                                 \
    dev_err(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n"         \
              , __func__, __LINE__, ##__VA_ARGS__)
#define ictty_warn(fmt, ...)                                                \
    dev_warn(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: "fmt"\n", __func__, ##__VA_ARGS__)
#define ictty_notice(fmt, ...)                                              \
    dev_notice(&(ICTTY_DEV), ICTTY_LOG_PREFIX": "fmt"\n", ##__VA_ARGS__)
#define ictty_info(fmt, ...)                                                \
    dev_info(&(ICTTY_DEV), ICTTY_LOG_PREFIX": "fmt"\n", ##__VA_ARGS__)
#if ICTTY_DEBUG_LEVEL > 0
#define ictty_trace(fmt, ...)                                               \
    dev_info(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n"        \
              , __func__, __LINE__, ##__VA_ARGS__)
#else
    #define ictty_trace(fmt, ...)
#endif

#define ictty_emerg_rlim(fmt, ...)                                               \
    dev_emerg_ratelimited(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n"\
              , __func__, __LINE__, ##__VA_ARGS__)
#define ictty_crit_rlim(fmt, ...)                                           \
    dev_crit_ratelimited(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n" \
              , __func__, __LINE__, ##__VA_ARGS__)
#define ictty_alert_rlim(fmt, ...)                                          \
    dev_alert_ratelimited(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n"\
              , __func__, __LINE__, ##__VA_ARGS__)
#define ictty_err_rlim(fmt, ...)                                            \
    dev_err_ratelimited(&(ICTTY_DEV), ICTTY_LOG_PREFIX"%s: at %d line: "fmt"\n"  \
              , __func__, __LINE__, ##__VA_ARGS__)
#define ictty_warn_rlim(fmt, ...)                                           \
    dev_warn_ratelimited(&(ICTTY_DEV), ICTTY_LOG_PREFIX": "fmt"\n"          \
              , ##__VA_ARGS__)
#define ictty_notice_rlim(fmt, ...)                                         \
    dev_notice_ratelimited(&(ICTTY_DEV), ICTTY_LOG_PREFIX": "fmt"\n"        \
              , ##__VA_ARGS__)
#define ictty_info_rlim(fmt, ...)                                           \
    dev_info_ratelimited(&(ICTTY_DEV), ICTTY_LOG_PREFIX": "fmt"\n"          \
              , ##__VA_ARGS__)

#define ICTTY_CHECK_DEVICE(error_action)                    \
	if (IS_ERR_OR_NULL(ictty)) {                            \
		ictty_err("no device;");                            \
		error_action;                                       \
	}
#define ICTTY_CHECK_PTR(ptr, error_action)                     \
	if (IS_ERR_OR_NULL(ptr)) {                                 \
		ictty_err(#ptr"(%px): ptr error\n", ptr);              \
		error_action;                                          \
	}
#define ICTTY_CHECK_PTR_RAW(ptr, error_action)                 \
	if (IS_ERR_OR_NULL(ptr)) {                                 \
		pr_err("iccom_tty: %s: %d: %s(%px): ptr error\n"       \
				, __func__, __LINE__, #ptr, ptr);              \
		error_action;                                          \
	}
#define ICTTY_ERROR_CONDITION(error_condition, error_action)   \
	if ((error_condition)) {                                   \
		ictty_err("error condition met: "#error_condition"\n");\
		error_action;                                          \
	}

/* --------------------------- MAIN STRUCTURES --------------------------*/

// The ICCom TTY statistics data
struct iccom_tty_statistics {
	uint64_t total_sent_msgs;
	uint64_t total_rcv_msgs;
	uint64_t total_sent_bytes;
	uint64_t total_rcv_bytes;
};

// The ICCom TTY device representation data.
//
// @tty_port the TTY device data.
// @iccom the iccom device to work with.
// @iccom_ch the ICCom channel to work with.
// @max_msg_size [bytes] the max msg size supported by given device instance.
//		defaults to 256.
// @tty_number the TTY number (used in device name suffix like /dev/ttyICCOM14)
// @base_pdev the platform device we work on top of.
// @statistics the device statistics information.
struct iccom_tty_dev {
	struct tty_port tty_port;
	struct iccom_dev *iccom;
	unsigned int iccom_ch;	
	size_t max_msg_size;
	int tty_number;
	struct platform_device *base_pdev;
	struct iccom_tty_statistics statistics;
};

/*---------------------- PRE DECLARATIONS ----------------------------*/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
static unsigned int ictty_tty_write_room(struct tty_struct *tty);
#else
static int ictty_tty_write_room(struct tty_struct *tty);
#endif
static int ictty_install(struct tty_driver *driver, struct tty_struct *tty);
static int ictty_tty_open(struct tty_struct *tty, struct file *filp);
static void ictty_tty_close(struct tty_struct *tty, struct file *filp);
static void ictty_tty_hangup(struct tty_struct *tty);

void ictty_tty_port_destruct(struct tty_port *port);

static int ictty_probe(struct platform_device *pdev);
static int ictty_remove(struct platform_device *pdev);

/*----------------------- TTY DEVICE API -----------------------------*/

// Called from User Space upon writing the data to the TTY.
// RETURNS:
//		data_size: if whole data is written correctly
//		[0; data_size): if data was partially written
//		<0: on failure
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static ssize_t ictty_tty_write(
		struct tty_struct *tty, const u8 *data, size_t data_size)
#else
static int ictty_tty_write(
		struct tty_struct *tty, const unsigned char *data, int data_size)
#endif
{
	ICTTY_CHECK_PTR_RAW(tty, return -ENOTTY);
	ICTTY_CHECK_PTR_RAW(tty->dev, return -ENODEV);

	struct iccom_tty_dev *ictty = (struct iccom_tty_dev *)dev_get_drvdata(tty->dev);
	ICTTY_CHECK_DEVICE(return -EFAULT);

	ICTTY_CHECK_PTR(ictty->iccom, return -EADDRNOTAVAIL);

	ictty_trace("-> TX data (ch. %d):", ictty->iccom_ch);
#if ICTTY_DEBUG_LEVEL > 0
	print_hex_dump(KERN_DEBUG
			, ICTTY_LOG_PREFIX"   -> TX data: ", 0, 16, 1, data, data_size, true);
#endif

	int res = iccom_post_message(ictty->iccom
					, data, data_size, ictty->iccom_ch, 0);

	if (res != 0) {
		return res;
	}

	ictty->statistics.total_sent_msgs += 1;
	ictty->statistics.total_sent_bytes += data_size;

	return data_size;
}

// Called by ICCom when it has some incoming message to deliver upwards.
// @channel the ICCom channel of the incoming data.
// @consumer_data the data pointer provided by iccom tty earlier (ptr to iccom_tty_dev)
//
// NOTE: we don't take ownership of the msg data, thus always return false.
static bool __iccom_tty_msg_rx_callback(
		unsigned int channel
		, void *msg_data, size_t msg_len
		, void *consumer_data)
{
	struct iccom_tty_dev *ictty = (struct iccom_tty_dev*)consumer_data;
	ICTTY_CHECK_DEVICE(return false);

	ICTTY_ERROR_CONDITION(msg_len <= 0, return false);
	ICTTY_CHECK_PTR(msg_data, return false);
	ICTTY_ERROR_CONDITION(channel != ictty->iccom_ch, return false);

	ictty_trace("<- RX data (ch. %d) for iccom_tty #%d:", ictty->iccom_ch
			, ictty->tty_number);
#if ICTTY_DEBUG_LEVEL > 0
	print_hex_dump(KERN_INFO
			, ICTTY_LOG_PREFIX"   <- RX data: ", 0, 16, 1, msg_data
			, msg_len, true);
#endif

	int res = tty_insert_flip_string(&ictty->tty_port, msg_data, msg_len);
	if (res >= 0 && res != msg_len) {
		ictty_err_rlim("truncated %d chars from incoming data"
				, (int32_t)msg_len - (int32_t)res);
	} else if (res < 0) {
		ictty_err_rlim("failed to propagate msg to tty buf, err: %d", -res);
	}
	tty_flip_buffer_push(&ictty->tty_port);

	if (res > 0) {
		ictty->statistics.total_rcv_msgs += 1;
		ictty->statistics.total_rcv_bytes += res;
	}
	return false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
static unsigned int ictty_tty_write_room(struct tty_struct *tty)
#else
static int ictty_tty_write_room(struct tty_struct *tty)
#endif
{
	ICTTY_CHECK_PTR_RAW(tty, return 0);
	ICTTY_CHECK_PTR_RAW(tty->dev, return 0);

	struct iccom_tty_dev *ictty = (struct iccom_tty_dev *)dev_get_drvdata(tty->dev);
	ICTTY_CHECK_DEVICE(return 0);

	return ictty->max_msg_size;
}

static int ictty_install(struct tty_driver *driver, struct tty_struct *tty)
{
	if (IS_ERR_OR_NULL(driver)) {
		pr_err("iccom_tty: failed to install tty port: driver is missing");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(tty)) {
		pr_err("iccom_tty: failed to install tty port: tty is missing");
		return -EINVAL;
	}
	if (tty->index >= driver->num) {
		pr_err("iccom_tty: wrong tty index %d for the driver max count %d"
				, tty->index, driver->num);
		return -EINVAL;
	}
	struct tty_port *port = driver->ports[tty->index];
	if (IS_ERR_OR_NULL(port)) {
		pr_err("iccom_tty: failed to install tty port: tty port is missing");
		return -EINVAL;
	}
	tty->port = port;

	struct iccom_tty_dev *ictty = container_of(tty->port
						, struct iccom_tty_dev
						, tty_port);
	ICTTY_CHECK_DEVICE(return -ENODEV);

	int res = tty_port_install(&ictty->tty_port, driver, tty);

	if (res != 0) {
		ictty_err("failed to install tty port, err: %d", res);
	}

	return res;
}

static int ictty_tty_open(struct tty_struct *tty, struct file *filp)
{
	if (IS_ERR_OR_NULL(tty)) {
		pr_err("iccom_tty: failed to open tty, tty is missing");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(tty->port)) {
		pr_err("iccom_tty: failed to open tty, tty port is missing");
		return -EINVAL;
	}

	return tty_port_open(tty->port, tty, filp);
}

static void ictty_tty_close(struct tty_struct *tty, struct file *filp)
{
	if (IS_ERR_OR_NULL(tty)) {
		pr_err("iccom_tty: failed to close tty: tty is missing");
		return ;
	}
	if (IS_ERR_OR_NULL(tty->port)) {
		pr_err("iccom_tty: failed to close tty: tty port is missing");
		return ;
	}

	return tty_port_close(tty->port, tty, filp);
}

static void ictty_tty_hangup(struct tty_struct *tty)
{
	if (IS_ERR_OR_NULL(tty)) {
		pr_err("iccom_tty: failed to hangup tty: tty is missing");
		return ;
	}
	if (IS_ERR_OR_NULL(tty->port)) {
		pr_err("iccom_tty: failed to hangup tty: tty port is missing");
		return ;
	}
	tty_port_hangup(tty->port);
}

void ictty_tty_port_destruct(struct tty_port *port)
{
	(void)port;
	// NOTE: the port will be freed together with the corresponding iccom tty
	//	device (cause it is a part of the iccom_tty device, which can not be
	//  freed independently), so this function presense inhibit the default
	//  tty_port free call in tty framework.
}

/*------------------------- SYSFS IO BLOCK ---------------------------*/

static ssize_t statistics_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	ICTTY_CHECK_PTR_RAW(dev, return 0);
	ICTTY_CHECK_PTR_RAW(attr, return 0);
	ICTTY_CHECK_PTR_RAW(buf, return 0);

	struct iccom_tty_dev *ictty = dev_get_drvdata(dev);
	ICTTY_CHECK_DEVICE(return 0);

	size_t len = (size_t)scnprintf(buf, PAGE_SIZE,
			"total_sent_msgs:  %llu\n"
			"total_rcv_msgs:  %llu\n"
			"total_sent_bytes:  %llu\n"
			"total_rcv_bytes:  %llu\n"
			, ictty->statistics.total_sent_msgs
			, ictty->statistics.total_rcv_msgs
			, ictty->statistics.total_sent_bytes
			, ictty->statistics.total_rcv_bytes);

	return len;
}
static DEVICE_ATTR_RO(statistics);

// List attributes that ICCom TTY device exposes
//
// @dev_attr_statistics the ICCom TTY statistics info
static struct attribute *iccom_tty_dev_attrs[] = {
	&dev_attr_statistics.attr,
	NULL,
};

ATTRIBUTE_GROUPS(iccom_tty_dev);

// The dynamic node addition was added in v6.6 kernel.
#if defined(CONFIG_OF_DYNAMIC) && LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)

// When triggered by write from user land, creates new ICCom TTY
// platform device, bound to the given ICCom and channel.
//
// Write format:
//		<ICCom device name>:<channel number to bind>:<tty number>
//
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
// RETURNS:
//  count: ok
//     <0: negated error code
static ssize_t create_iccom_tty_store(
		ICCOM_TTY_CLASS_MODIFIER struct class *class
		, ICCOM_TTY_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count)
{
	ICTTY_CHECK_PTR_RAW(class, return -ENODEV);
	ICTTY_CHECK_PTR_RAW(buf, return -EINVAL);
	ICTTY_CHECK_PTR_RAW(attr, return -EINVAL);

	char iccom_dev_name[ICCOM_DEV_NAME_LEN + 1] = {};
	int iccom_ch = 0;
	int iccom_tty_num = 0;
	
	int args_count = sscanf(buf
					,"%" __stringify(ICCOM_DEV_NAME_LEN) "[^:]:%d:%d"
					, &iccom_dev_name[0], &iccom_ch, &iccom_tty_num);
	if (args_count != 3 || iccom_ch < 0) {
		pr_err("iccom_tty: failed to parse the iccom tty creation cmd: '%s'."
				" The creation of the new iccom tty device requires the"
				" following format: '<iccom dev name>:<iccom channel number>"
				":<tty number>'.\n"
				" NOTE: the channel must be > 0.\n"
				" NOTE: iccom name fit into "
				__stringify(ICCOM_DEV_NAME_LEN) " chars.\n"
				" NOTE: the channel must not be used already.\n"
				" NOTE: the tty number (appears as /dev/tty* name suffix)"
				" must be in range [0;"
				__stringify(ICCOM_TTY_MAX_TTY_COUNT)").\n"
				, buf);
		return -EINVAL;
	}

	if (iccom_tty_num < 0 || iccom_tty_num >= ICCOM_TTY_MAX_TTY_COUNT) {
		pr_err("iccom_tty: bad iccom tty creation cmd: '%s':"
				" the tty number (== %d) (it appears as /dev/tty* name suffix)"
				" must be in range [0;"
				__stringify(ICCOM_TTY_MAX_TTY_COUNT)").\n"
				, buf, iccom_tty_num);
		return -EINVAL;
	}

	// Now we need to ensure that the target ICCom dev is there
	struct device *iccom_dev =
			bus_find_device_by_name(&platform_bus_type, NULL, iccom_dev_name);

	if (IS_ERR_OR_NULL(iccom_dev)) {
		pr_err("iccom_tty: couldn't find iccom dev with name: %s"
				, iccom_dev_name);
		return -ENODEV;
	}

	int ret = 0;
	struct iccom_dev *iccom = dev_get_drvdata(iccom_dev);
	if (IS_ERR_OR_NULL(iccom)) {
		pr_err("iccom_tty: couldn't get driver data for iccom dev: %s", iccom_dev_name);
		ret = -ENOENT;
		goto put_iccom_dev;
	}

	// Not ideal check, but it will work for non-concurrent initialization
	// scenarios, and at least will report the inconsistent configuration.

	if (iccom_get_channel_callback(iccom, iccom_ch) != NULL) {
		pr_err("iccom_tty: the channel %d of iccom device %s is already occupied"
		       ", will not override.", iccom_ch, iccom_dev_name);
		ret = -EBUSY;
		goto put_iccom_dev;
	}

	char node_name[ICCOM_TTY_NODE_NAME_LEN + 1];
	ret = snprintf(node_name, sizeof(node_name), "iccomtty.%s:%d"
			, iccom_dev_name, iccom_ch);

	if (ret < 0 || ret >= sizeof(node_name)) {
		pr_err("iccom_tty: can not render the iccom_tty node name");
		ret = -EINVAL;
		goto put_iccom_dev;
	}

	// CONFIG_OF_DYNAMIC is needed to be defined for this
	struct of_changeset chgset;
	of_changeset_init(&chgset);
	struct device_node *iccom_tty_node = of_changeset_create_node(
				&chgset, of_find_node_by_path("/"), node_name);

	if (IS_ERR_OR_NULL(iccom_tty_node)) {
		pr_err("iccom_tty: couldn't create iccom_tty DT node");
		ret = -EFAULT;
		goto destroy_changeset;
	}

	if (IS_ERR_OR_NULL(iccom_tty_node->parent)) {
		pr_err("iccom_tty: couldn't attach iccom_tty node to root node.");
		ret = -EFAULT;
		goto cleanup_dt_node;
	}

	ret = of_changeset_attach_node(&chgset, iccom_tty_node);
	if (ret != 0) {
		pr_err("iccom_tty: couldn't attach iccom_tty DT node");
		goto cleanup_dt_node;
	};

	const u32 channel = iccom_ch;
	ret = of_changeset_add_prop_u32_array(&chgset
				    , iccom_tty_node, "channel", &channel, 1);
	if (ret != 0) {
		pr_err("iccom_tty: couldn't append `channel` property to the node");
		goto cleanup_dt_node;
	};

	const u32 tty_number = iccom_tty_num;
	ret = of_changeset_add_prop_u32_array(&chgset
				    , iccom_tty_node, "tty_number", &tty_number, 1);
	if (ret != 0) {
		pr_err("iccom_tty: couldn't append `tty_number` property to the node");
		goto cleanup_dt_node;
	};

	if (IS_ERR_OR_NULL(iccom_dev->of_node)) {
		ret = of_changeset_add_prop_string(&chgset
				 , iccom_tty_node, "iccom_dev_name", iccom_dev_name);
		if (ret != 0) {
			pr_err("iccom_tty: couldn't append `iccom_dev_name` property to the node");
			goto cleanup_dt_node;
		};
	} else {
		const phandle iccom_phandle = iccom_dev->of_node->phandle;
		ret = of_changeset_add_prop_u32_array(&chgset
						, iccom_tty_node, "iccom_dev", &iccom_phandle, 1);
		if (ret != 0) {
			pr_err("iccom_tty: couldn't append `iccom_dev` property to the node");
			goto cleanup_dt_node;
		};
	}

	ret = of_changeset_add_prop_string(&chgset
				, iccom_tty_node, "compatible", "iccom_tty");
	if (ret != 0) {
		pr_err("iccom_tty: couldn't append `compatible` property to the node");
		goto cleanup_dt_node;
	}

	pr_info("iccom_tty: instantiating iccom_tty #%u on iccom \"%s\" channel %d"
			, tty_number, iccom_dev_name, iccom_ch);

	ret = of_changeset_apply(&chgset);
	if (ret != 0) {
		pr_err("iccom_tty: couldn't roll out new iccom tty device node.");
		goto cleanup_dt_node;
	}

	return count;

cleanup_dt_node:
	of_node_put(iccom_tty_node);
destroy_changeset:
	of_changeset_destroy(&chgset);
put_iccom_dev:
	put_device(iccom_dev);
	return ret;
}
#else
static ssize_t create_iccom_tty_store(
		ICCOM_TTY_CLASS_MODIFIER struct class *class
		, ICCOM_TTY_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count)
{
	pr_err("iccom_tty: sorry, kernel compiled without dynamic DT support"
			" (v6.6 kernel minimum needed and CONFIG_OF_DYNAMIC is set needed):"
			" can not create new iccom_tty node.");
	return -ENOTSUPP;
}
#endif //CONFIG_OF_DYNAMIC
static CLASS_ATTR_WO(create_iccom_tty);


// The dynamic node addition was added in v6.6 kernel.
#if defined(CONFIG_OF_DYNAMIC) && LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
//// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ END
//
static ssize_t remove_iccom_tty_store(
		ICCOM_TTY_CLASS_MODIFIER struct class *class
		, ICCOM_TTY_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count)
{
	char iccom_dev_name[ICCOM_DEV_NAME_LEN + 1] = {};
	int iccom_ch = 0;
	
	int args_count = sscanf(buf
					,"%" __stringify(ICCOM_DEV_NAME_LEN) "[^:]:%d"
					, &iccom_dev_name[0], &iccom_ch);
	if (args_count != 2 || iccom_ch < 0) {
		pr_err("iccom_tty: failed to parse the iccom tty creation cmd: '%s'."
				" The creation of the new iccom tty device requires the"
				" following format: '<iccom dev name>:<iccom channel number>'.\n"
				" NOTE: the channel must be > 0.\n"
				" NOTE: iccom name fit into "
				__stringify(ICCOM_DEV_NAME_LEN) " chars.\n"
				" NOTE: the channel must not be used already.\n"
				" NOTE: the tty number (appears as /dev/tty* name suffix).\n"
				, buf);
		return -EINVAL;
	}

	char node_name[ICCOM_TTY_NODE_NAME_LEN + 1];
	int ret = snprintf(node_name, sizeof(node_name), "iccomtty.%s:%d"
					, iccom_dev_name, iccom_ch);

	if (ret < 0 || ret >= sizeof(node_name)) {
		pr_err("iccom_tty: can not render the iccom_tty node name");
		return -EINVAL;
	}

	struct device_node *tty_node = of_find_node_by_name(NULL, node_name);
	if (IS_ERR_OR_NULL(tty_node)) {
		pr_err("iccom_tty: could not find a iccom_tty node with name: %s"
				, node_name);
		return -ENODEV;
	}

	ret = of_detach_node(tty_node);
	if (ret != 0) {
		pr_err("iccom_tty: failed to remove iccom_tty node with name: %s"
				, node_name);
		return -EFAULT;
	}

	of_node_put(tty_node);
	tty_node = NULL;

	pr_info("iccom_tty: removed iccom_tty node with name: %s", node_name);

	return count;
}
#else
static ssize_t remove_iccom_tty_store(
		ICCOM_TTY_CLASS_MODIFIER struct class *class
		, ICCOM_TTY_CLASS_ATTR_MODIFIER struct class_attribute *attr
		, const char *buf, size_t count)
{
	pr_err("iccom_tty: sorry, kernel compiled without dynamic DT support"
			" (v6.6 kernel minimum needed and CONFIG_OF_DYNAMIC is set needed):"
			" can not remove iccom_tty node.");
	return -ENOTSUPP;
}
#endif //CONFIG_OF_DYNAMIC
static CLASS_ATTR_WO(remove_iccom_tty);


static struct attribute *iccom_tty_class_attrs[] = {
	&class_attr_create_iccom_tty.attr,
	&class_attr_remove_iccom_tty.attr,
	NULL
};

//// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ BEGIN
ATTRIBUTE_GROUPS(iccom_tty_class);

// The ICCom TTY class definition
//
// @name class name
// @owner the module owner
// @class_groups group holding all the attributes
static struct class iccom_tty_class = {
	.name = "iccom_tty",
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
	.owner = THIS_MODULE,
#endif
	.class_groups = iccom_tty_class_groups
};

/*-------------------------- ORG BLOCK -------------------------------*/

static const struct tty_operations ictty_tty_ops = {
	.install	= ictty_install,
	.open		= ictty_tty_open,
	.close		= ictty_tty_close,
	.write		= ictty_tty_write,
	.write_room	= ictty_tty_write_room,
	.hangup		= ictty_tty_hangup,
};

static const struct tty_port_operations ictty_tty_port_ops = {
	.destruct = ictty_tty_port_destruct
};

// The ICCom TTY driver compatible devices list.
// @compatible name of compatible device.
struct of_device_id iccom_tty_devices_id[] = {
	{
		.compatible = "iccom_tty",
	}
};

// The ICCom TTY platform device driver definition
struct platform_driver iccom_tty_platform_driver = {
	.probe = ictty_probe
	, .remove = ictty_remove
	, .driver = {
		.owner = THIS_MODULE
		, .name = "iccom_tty"
		, .of_match_table = iccom_tty_devices_id
		, .dev_groups = iccom_tty_dev_groups
	}
};

// ptr to dynamically allocated TTY driver instance.
static struct tty_driver *iccom_tty_serial_driver;

// The ICCom TTY tty(serial) device driver definition.
// NOTE: corresponding devices not to be declared in DT,
//		please declare the 'iccom_tty' there instead.
struct tty_driver iccom_tty_serial_driver_base = {
	.driver_name = "iccom_tty__",
	.name = ICCOM_TTY_NAME,
	.major = 0,
	.type = TTY_DRIVER_TYPE_CONSOLE,
	.init_termios = {
		// NOTE: those will be applied dynamically at registration time:
		// 		SEE ALSO: iccom_tty_module_init
		//.c_oflag = tty_std_termios.c_oflag & ~(OPOST | ONLCR),
		//.c_lflag = tty_std_termios.c_lflag & ~(ECHO | ICANON),
	},
	.ops = &ictty_tty_ops
};



/* ------------------ PL DEVICE PROBING / REMOVAL ---------------------- */

// We will work with the DT by default. The x86 platform we can cover by simulating
// the DT Overlays there.
//
// The DT node example:
//	
//		// ICCom TTY definition
//		// it will be attached to ICCom iccom0, and use the channel 7435
//		ictty0: ictty0 {
//			compatible = "iccom_tty";
//
//			// ONE of TWO following MUST present:
//			//		NOTE: if both are preasent, only the @iccom_dev is relevant
//			// OR: @iccom_dev points to the iccom device to use via phandle
//			iccom_dev = <&iccom0>;
//			// OR: @iccom_dev points to the iccom device to use via iccom dev name
//			iccom_dev_name = "iccom.0";
//			
//			// mandatory property, tells the iccom channel to use for this tty
//			channel = <7435>;
//			// mandatory property, the TTY number, will appear in the TTY
//			// device name, like ttyICCOM4
//			tty_number= <4>;
//
//			// optional, max msg size [bytes] sets the max iccom message size to
//			// use (bigger messages will be split into separate messages),
//			// defaults to 128.
//			max_msg_size = <256>;
//		};
//
//  	// ICCom device definition
//		iccom0: iccom0 {
//			compatible = "iccom";
//			...
//		};
static int ictty_probe(struct platform_device *pdev)
{
	if (IS_ERR_OR_NULL(pdev)) {
		pr_err("ictty_probe: no platform device provided");
		return -EFAULT;
	}
	dev_info(&pdev->dev, "probing an iccom tty platform device with ID: %d\n"
			, pdev->id);

	struct device_node *ictty_node = dev_of_node(&pdev->dev);
	if (IS_ERR_OR_NULL(ictty_node)) {
		dev_err(&pdev->dev, "no iccom tty DT node available\n");
		return -EINVAL;
	}

	struct platform_device *iccom_pdev = NULL;
	do {
		struct device_node *iccom_node
				= of_parse_phandle(ictty_node, "iccom_dev", 0);
		
		if (!IS_ERR_OR_NULL(iccom_node)) {
			iccom_pdev = of_find_device_by_node(iccom_node);
			of_node_put(iccom_node);
			iccom_node = NULL;
			if (IS_ERR_OR_NULL(iccom_pdev)) {
				dev_err(&pdev->dev, "unable to find iccom device given by"
						" 'iccom_dev' property\n");
				return -ENODEV;
			}
			break;
		}

		// if no iccom_dev prop, we try to work with iccom_dev_name

		const char *iccom_name = NULL;
		if (of_property_read_string(ictty_node, "iccom_dev_name", &iccom_name) == 0) {
			struct device *dev
					= bus_find_device_by_name(&platform_bus_type, NULL, iccom_name);
			iccom_name = NULL;
			if (IS_ERR_OR_NULL(dev)) {
				dev_err(&pdev->dev, "unable to find iccom device given by"
						" 'iccom_dev_name' property: %s\n", iccom_name);
				return -ENODEV;
			}

			iccom_pdev = to_platform_device(dev);
			break;
		}

		dev_err(&pdev->dev, "EITHER 'iccom_dev' property must be set for iccom tty node"
				" and point to valid iccom device, like: 'iccom_dev = <&iccom0>;'"
				" OR 'iccom_dev_name' property must be set and have value of the"
				" target iccom device name, like: 'iccom_dev_name = \"iccom.0\";'.");
		return -ENODEV;
	} while(false);

	struct iccom_dev *iccom
			= (struct iccom_dev*)dev_get_drvdata(&iccom_pdev->dev);
	if (IS_ERR_OR_NULL(iccom)) {
		dev_err(&pdev->dev, "unable to get iccom device data of %s\n"
				, dev_name(&iccom_pdev->dev));
		return -EPROBE_DEFER;
	}

	int tty_channel = 0;
	int res = of_property_read_u32_index(ictty_node, "channel"
					, 0, &tty_channel);
	if (res != 0) {
		dev_err(&pdev->dev, "failed to parse 'channel' of the dt node, error: %d"
				", channel property example: 'channel = <1234>;'\n", -res);
		return res;
	}

	int tty_number = 0;
	res = of_property_read_u32_index(ictty_node, "tty_number"
					, 0, &tty_number);
	if (res != 0) {
		dev_err(&pdev->dev, "failed to parse 'tty_number' of the dt node, error: %d"
				", channel property example: 'tty_number= <4>;'"
				" this number is used as a tty device identification number in"
				" in /dev/tty* names.", -res);
		return res;
	}
	if (tty_number < 0 || tty_number >= ICCOM_TTY_MAX_TTY_COUNT) {
		dev_err(&pdev->dev, "'tty_number' property (== %d) of the dt node is out of"
				" proper range: [0;%d)", tty_number, ICCOM_TTY_MAX_TTY_COUNT);
		return -EINVAL;
	}

	uint32_t max_msg_size = ICTTY_DEFAULT_MAX_MSG_SIZE;
	of_property_read_u32_index(ictty_node, "max_msg_size", 0, &max_msg_size);

	// OK, we have everything to start the device, so let's do it.

	struct iccom_tty_dev *ictty = kzalloc(sizeof(*ictty), GFP_KERNEL);
	if (IS_ERR_OR_NULL(ictty)) {
		dev_err(&pdev->dev, "failed to allocate the iccom_tty_dev\n");
		return -ENOMEM;
	}

	ictty->iccom = iccom;
	ictty->iccom_ch = tty_channel;
	ictty->max_msg_size = (size_t)max_msg_size;
	// port refcount will be 1 after init
	tty_port_init(&ictty->tty_port);
	ictty->tty_port.ops = &ictty_tty_port_ops;
	ictty->base_pdev = pdev;
	ictty->tty_number = tty_number;

	struct device *tty_dev = tty_port_register_device(
				&ictty->tty_port, iccom_tty_serial_driver
				, tty_number, &pdev->dev);
	if (IS_ERR_OR_NULL(tty_dev)) {
		dev_err(&pdev->dev, "failed to register tty device");
		res = -EBADF;
		goto free_ictty_and_port;
	}
	dev_set_drvdata(tty_dev, ictty);

	res = iccom_set_channel_callback(ictty->iccom
                , ictty->iccom_ch
                , __iccom_tty_msg_rx_callback
                , ictty);
	if (res != 0) {
		dev_err(&pdev->dev, "failed to setup iccom callback, err: %d"
				, res);
		res = -EPROBE_DEFER;
		goto unregister_tty_dev;
	}

	struct device_link *link_downwards = device_link_add(&pdev->dev
									, &iccom_pdev->dev
									, DL_FLAG_STATELESS);
	if (IS_ERR_OR_NULL(link_downwards)) {
		dev_err(&pdev->dev, "failed to create link to iccom %s"
					, dev_name(&iccom_pdev->dev));
		res = -ECONNREFUSED;
		goto remove_iccom_callback;
	}

	dev_set_drvdata(&pdev->dev, ictty);

	pr_info("iccom_tty: created iccom_tty with name \"%s\""
			", using iccom \"%s\" channel %d and max msg size %d."
			, dev_name(tty_dev), dev_name(&iccom_pdev->dev)
			, ictty->iccom_ch, max_msg_size);

	return 0;

remove_iccom_callback:
	iccom_remove_channel_callback(ictty->iccom, ictty->iccom_ch);
unregister_tty_dev:
	dev_set_drvdata(tty_dev, NULL);
	tty_unregister_device(iccom_tty_serial_driver, ictty->iccom_ch);
free_ictty_and_port:
	tty_port_put(&ictty->tty_port);
	memset(ictty, 0, sizeof(*ictty));
	kfree(ictty);
	ictty = NULL;

	return res;
}

// Handles removal of the ICCom TTY platform device.
static int ictty_remove(struct platform_device *pdev)
{
	if (IS_ERR_OR_NULL(pdev)) {
		pr_err("ictty_remove: no platform device provided\n");
		return -ENODEV;
	}

	struct iccom_tty_dev *ictty = dev_get_drvdata(&pdev->dev);
	ICTTY_CHECK_DEVICE(return -ENODEV);

	ictty_info("removing iccom tty device on ch. %d", ictty->iccom_ch);

	iccom_remove_channel_callback(ictty->iccom, ictty->iccom_ch);

	tty_port_tty_hangup(&ictty->tty_port, false);

	tty_unregister_device(iccom_tty_serial_driver, ictty->tty_number);

	dev_set_drvdata(&pdev->dev, NULL);

	int final_kref;
	int attempts = 5;
	do {
		final_kref = kref_read(&(ictty->tty_port.kref));
		if (final_kref != 1) {
			ictty_err("tty_port unbalanced kref == %d before final put!"
					, final_kref);
			usleep_range(300000, 400000);
			attempts -= 1;
		}
	} while (final_kref != 1 && attempts > 0);

	tty_port_put(&ictty->tty_port);
	memset(ictty, 0, sizeof(*ictty));
	kfree(ictty);
	ictty = NULL;

	return 0;
}

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

static int __init iccom_tty_module_init(void)
{
	pr_info("loading iccom tty module...");
	
	struct tty_driver *tty_drv = tty_alloc_driver(
			ICCOM_TTY_MAX_TTY_COUNT, TTY_DRIVER_REAL_RAW
			| TTY_DRIVER_DYNAMIC_DEV);
	if (IS_ERR_OR_NULL(tty_drv)) {
		pr_err("iccom_tty module: failed to allocate tty driver, error: %ld"
				, PTR_ERR(tty_drv));
		return PTR_ERR(tty_drv);
	}

	tty_drv->driver_name = iccom_tty_serial_driver_base.driver_name;
	tty_drv->name = iccom_tty_serial_driver_base.name;
	tty_drv->major = iccom_tty_serial_driver_base.major;
	tty_drv->type = iccom_tty_serial_driver_base.type;

	tty_drv->init_termios = tty_std_termios;
	tty_drv->init_termios.c_oflag = tty_std_termios.c_oflag & ~(OPOST | ONLCR),
	tty_drv->init_termios.c_lflag = tty_std_termios.c_lflag & ~(ECHO | ICANON),

	tty_set_operations(tty_drv, iccom_tty_serial_driver_base.ops);

	iccom_tty_serial_driver = tty_drv;

	int ret = tty_register_driver(iccom_tty_serial_driver);
	if (ret != 0) {
		pr_err("iccom_tty module: failed to register the tty driver"
				" for iccom_tty, error: %d", -ret);
		goto tty_drv_reg_failed;
	}

	ret = platform_driver_register(&iccom_tty_platform_driver);
	if (ret != 0) {
		pr_err("iccom_tty module: failed to register the platform"
				" driver for iccom_tty, error: %d", ret);
		goto platform_drv_reg_failed;
	}

	ret = class_register(&iccom_tty_class);
	if (ret != 0) {
		pr_err("iccom_tty module: failed to register the iccom_tty class");
		goto class_register_failed;
	}

	pr_info("iccom_tty module loaded.");

	return 0;

class_register_failed:
	platform_driver_unregister(&iccom_tty_platform_driver);
platform_drv_reg_failed:
	tty_unregister_driver(tty_drv);
tty_drv_reg_failed:
	iccom_tty_serial_driver = NULL;
	tty_driver_kref_put(tty_drv);
	tty_drv = NULL;
	return ret;
}

static void __exit iccom_tty_module_exit(void)
{
	pr_info("unloading iccom_tty module...");

	class_unregister(&iccom_tty_class);
	platform_driver_unregister(&iccom_tty_platform_driver);
	tty_unregister_driver(iccom_tty_serial_driver);
	tty_driver_kref_put(iccom_tty_serial_driver);
	iccom_tty_serial_driver = NULL;

	pr_info("sucessfully unloaded iccom_tty module");
}

module_init(iccom_tty_module_init);
module_exit(iccom_tty_module_exit);

MODULE_DESCRIPTION("ICCom bus based TTY driver.");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@de.bosch.com>");
MODULE_LICENSE("GPL v2");
//// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ END