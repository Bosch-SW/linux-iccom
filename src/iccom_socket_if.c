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
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <stddef.h>

#include "./iccom.h"

// TEMPORARY CHANGE: explicit use of iccom-example protocol module
// TODO: ICCom shall ultimately not depend on the specific protocol drivers
//      it is only temporary change while migration on graceful
//      architecture is ongoing.
// TODO: remove the dependency
#include "./iccom-example.h"

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

#define ICCOM_SOCKETS_CLOSE_POLL_PERIOD_JIFFIES msecs_to_jiffies(200)

#define ICCOM_SOCKETS_LOG_PREFIX "ICCom_sockets: "


// Maximal ordinary channel value. The ordinary channel can go
// from [0; ICCOM_SK_MAX_CHANNEL_VAL]
// And the loopback channels (loop remote end) can settle also in area
//      [ICCOM_SK_MAX_CHANNEL_VAL + 1; 2 * ICCOM_SK_MAX_CHANNEL_VAL  + 1]
// NOTE: loopback channels can go also in ordinary channel area
#define ICCOM_SK_MAX_CHANNEL_VAL 0x7FFF

#define ICCOM_SK_PROC_ROOT_NAME "iccomif"
#define ICCOM_SK_LBACKCTL_FILE_NAME "loopbackctl"

#define ICCOM_SK_PROC_RW_PERMISSIONS 0600
/* --------------------- UTILITIES SECTION ----------------------------- */

#define iccom_socket_err(fmt, ...)                                       \
        pr_err(ICCOM_SOCKETS_LOG_PREFIX"%s: "fmt"\n", __func__           \
               , ##__VA_ARGS__)
#define iccom_socket_warning(fmt, ...)                                   \
        pr_warning(ICCOM_SOCKETS_LOG_PREFIX"%s: "fmt"\n", __func__       \
               , ##__VA_ARGS__)
#define iccom_socket_info(fmt, ...)                                      \
        pr_info(ICCOM_SOCKETS_LOG_PREFIX"%s: "fmt"\n", __func__          \
                , ##__VA_ARGS__)
#ifdef ICCOM_SOCKET_DEBUG
#define iccom_socket_dbg(fmt, ...)                                       \
        pr_info(ICCOM_SOCKETS_LOG_PREFIX"%s: "fmt"\n", __func__          \
                , ##__VA_ARGS__)
#else
#define iccom_socket_dbg(fmt, ...)
#endif

#define iccom_socket_err_raw(fmt, ...)                                   \
        pr_err(ICCOM_SOCKETS_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_socket_warning_raw(fmt, ...)                               \
        pr_warning(ICCOM_SOCKETS_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_socket_info_raw(fmt, ...)                                  \
        pr_info(ICCOM_SOCKETS_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#ifdef ICCOM_SOCKET_DEBUG
#define iccom_socket_dbg_raw(fmt, ...)                                   \
        pr_info(ICCOM_SOCKETS_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#else
#define iccom_socket_dbg_raw(fmt, ...)
#endif

#define ICCOM_SK_CHECK_DEVICE(msg, error_action)                         \
        if (IS_ERR_OR_NULL(iccom_sk)) {                                  \
                iccom_socket_err("%s: no device; "msg"\n", __func__);    \
                error_action;                                            \
        }

#define ICCOM_SK_CHECK_PTR(ptr, error_action)                            \
        if (IS_ERR_OR_NULL(ptr)) {                                       \
                iccom_socket_err("%s: pointer "# ptr" is invalid;\n"     \
                                 , __func__);                            \
                error_action;                                            \
        }

#define fitsin(TYPE, FIELD, SIZE)                                        \
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
// @proc_root the root iccom_sockets directory in the proc file system
//      this directory is now aiming to provide loopback control
//      but later some information and other ctl functions might be
//      added.
// @loopback_ctl_ops loopback control file operations
// @loopback_ctl_file the loopback control file itself
// @lback_map_rule the channel loopback mapping rule pointer,
//      allocated on heap.
struct iccom_sockets_device {
        struct sock *socket;
        struct task_struct *pump_task;

        struct iccom_dev iccom;

        struct completion initialized;
        bool exiting;
        struct completion pump_main_loop_done;
        struct completion socket_closed;

        struct proc_dir_entry *proc_root;

        struct file_operations loopback_ctl_ops;
        struct proc_dir_entry *loopback_ctl_file;

        struct iccom_sk_loopback_mapping_rule *lback_map_rule;
};

/* -------------------------- EXTERN VARS -------------------------------*/

/* -------------------------- GLOBAL VARS -------------------------------*/

// Singleton device for now.
struct iccom_sockets_device __iccom_sockets_dev;

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

/* --------------------- ENTRY POINTS -----------------------------------*/

// Is called whenever User Space sends any data via our Netlink sockets
// family.
static void __iccom_socket_netlink_data_ready(struct sk_buff *skb)
{
        // TODO: to clarify if possible to pass iccom_sockets_device
        //      as parameter part

        if (__iccom_sockets_dev.exiting) {
                return;
        }

    //    struct sock *socket = __iccom_sockets_dev.socket;

        __iccom_socket_dispatch_msg_down(&__iccom_sockets_dev, skb);

        // TODO: try to clarify how to make it run via separate thread
    //    wake_up_interruptible_all(sk_sleep(socket));
    //    force_sig(SIGUSR1, __iccom_sockets_dev.pump_task);
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

        return iccom_post_message(&iccom_sk->iccom
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
                                 "  allowed: %d > %d bytes; dropping;"
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
                                 " req. size: %d"
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
                                                 , NETLINK_ICCOM
                                                 , &netlink_cfg);

        if (IS_ERR(iccom_sk->socket)) {
                return PTR_ERR(iccom_sk->socket);
        } else if (!iccom_sk->socket) {
                iccom_socket_err("could not create kernel netlink socket"
                                 " for family: %d", NETLINK_ICCOM);
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
// Is invoked when user reads the /proc/<ICCOM_SK>/<LOOPBACK_CTL> file.
//
// Is restricted to the file size of SIZE_MAX bytes.
//
// RETURNS:
//      >= 0: number of bytes actually provided to user space, on success
//      < 0: negated error code, on failure
static ssize_t __iccom_sk_lback_rule_read(struct file *file
                , char __user *ubuf
                , size_t count
                , loff_t *ppos)
{
        ICCOM_SK_CHECK_PTR(file, return -EINVAL);
        ICCOM_SK_CHECK_PTR(ubuf, return -EINVAL);
        ICCOM_SK_CHECK_PTR(ppos, return -EINVAL);

        struct iccom_sockets_device *iccom_sk
                = (struct iccom_sockets_device *)PDE_DATA(file->f_inode);

        ICCOM_SK_CHECK_DEVICE("no device provided", return -ENODEV);

        const int BUFFER_SIZE = 256;

        if (*ppos >= BUFFER_SIZE || *ppos > SIZE_MAX) {
                return 0;
        }

        char *buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);

        if (IS_ERR_OR_NULL(buf)) {
                return -ENOMEM;
        }

        const struct iccom_sk_loopback_mapping_rule *const rule
                            = iccom_sk->lback_map_rule;

        size_t len = (size_t)snprintf(buf, BUFFER_SIZE, "%d %d %d\n\n"
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
                buf[BUFFER_SIZE - 1] = 0;
        }

        const unsigned long nbytes_to_copy
                        = (len >= (size_t)(*ppos))
                                ?  min(len - (size_t)(*ppos), count)
                                : 0;
        const unsigned long not_copied
                        = copy_to_user(ubuf, buf + (size_t)(*ppos)
                                       , nbytes_to_copy);
        kfree(buf);
        buf = NULL;
        *ppos += nbytes_to_copy - not_copied;

        return nbytes_to_copy - not_copied;
}

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
// Is invoked when user writes the /proc/<ICCOM_SK>/<LOOPBACK_CTL> file.
//
// Is restricted to the file size of SIZE_MAX bytes.
//
// RETURNS:
//      >= 0: number of bytes actually were written, on success
//      < 0: negated error code, on failure
static ssize_t __iccom_sk_lback_rule_write(struct file *file
                , const char __user *ubuf
                , size_t count
                , loff_t *ppos)
{
        ICCOM_SK_CHECK_PTR(file, return -EINVAL);
        ICCOM_SK_CHECK_PTR(ubuf, return -EINVAL);

        struct iccom_sockets_device *iccom_sk
                = (struct iccom_sockets_device *)PDE_DATA(file->f_inode);

        ICCOM_SK_CHECK_DEVICE("no device provided", return -ENODEV);

        const unsigned int BUFFER_SIZE = 64;

        // we only get the whole data at once
        if (*ppos != 0 || count > BUFFER_SIZE) {
                iccom_socket_warning(
                        "Ctrl message should be written at once"
                        " and not exceed %u bytes.", BUFFER_SIZE);
                return -EFAULT;
        }

        char *buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);

        if (IS_ERR_OR_NULL(buf)) {
                return -ENOMEM;
        }

        const unsigned long not_copied = copy_from_user(buf, ubuf, count);
        ssize_t ret = 0;

        if (not_copied != 0) {
                iccom_socket_warning("Not all bytes were copied from user.");
                ret = -EIO;
                goto finalize;
        }

        struct iccom_sk_loopback_mapping_rule parsing_res;
        ret = __iccom_sk_parse_lback_string(buf, count, &parsing_res);
        if (ret < 0) {
                iccom_socket_warning("Parsing failed: %s", buf);
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

// Helper. Inits the ICCom Sockets procfs.
// RETURNS:
//      >= 0: on success,
//      < 0: on failure (negated error code)
static int __iccom_sk_procfs_init(
                struct iccom_sockets_device *iccom_sk)
{
        ICCOM_SK_CHECK_DEVICE("", return -ENODEV);

        iccom_sk->proc_root = proc_mkdir(ICCOM_SK_PROC_ROOT_NAME, NULL);

        if (IS_ERR_OR_NULL(iccom_sk->proc_root)) {
                iccom_socket_err("failed to create ICCom Socket proc"
                                 "root folder with name: "
                                 ICCOM_SK_PROC_ROOT_NAME);
                return -EIO;
        }
        return 0;
}

// Removes the ICcom Sockets proc root
static void __iccom_sk_procfs_close(
                struct iccom_sockets_device *iccom_sk)
{
        ICCOM_SK_CHECK_DEVICE("", return);

        if (IS_ERR_OR_NULL(iccom_sk->proc_root)) {
                return;
        }

        proc_remove(iccom_sk->proc_root);
        iccom_sk->proc_root = NULL;
}

// Helper. Initializes the loopback control on ICCom Sockets.
//
// NOTE: the ICCom Sockets proc rootfs should be created beforehand,
//      if not: then we will fail to create loopback node, but
//          the loopback default rule (turned off) will be initialized
//          anyway.
//
// RETURNS:
//      >= 0: on success,
//      < 0: on failure (negated error code)
static int __iccom_sk_loopback_ctl_init(
                struct iccom_sockets_device *iccom_sk)
{
        ICCOM_SK_CHECK_DEVICE("", return -ENODEV);

        // fallback state
        memset(&iccom_sk->loopback_ctl_ops, 0
               , sizeof(iccom_sk->loopback_ctl_ops));
        iccom_sk->lback_map_rule = NULL;
        iccom_sk->loopback_ctl_file = NULL;

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

        // loopback control ops
        iccom_sk->loopback_ctl_ops.read = &__iccom_sk_lback_rule_read;
        iccom_sk->loopback_ctl_ops.write = &__iccom_sk_lback_rule_write;

        if (IS_ERR_OR_NULL(iccom_sk->proc_root)) {
                iccom_socket_err("failed to create loopback control proc entry:"
                                 " no ICCom Sockets root proc entry");
                iccom_sk->loopback_ctl_file = NULL;
                return -ENOENT;
        }

        iccom_sk->loopback_ctl_file = proc_create_data(
                                           ICCOM_SK_LBACKCTL_FILE_NAME
                                           , ICCOM_SK_PROC_RW_PERMISSIONS
                                           , iccom_sk->proc_root
                                           , &iccom_sk->loopback_ctl_ops
                                           , (void*)iccom_sk);

        if (IS_ERR_OR_NULL(iccom_sk->loopback_ctl_file)) {
                iccom_socket_err("failed to create loopback control proc entry.");
                return -EIO;
        }

        return 0;
}

// Removes the ICcom proc statistics file
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

        if (IS_ERR_OR_NULL(iccom_sk->loopback_ctl_file)) {
                return;
        }

        proc_remove(iccom_sk->loopback_ctl_file);
        iccom_sk->loopback_ctl_file = NULL;
}

// Closes underlying protocol layer.
static void __iccom_socket_protocol_device_close(
                struct iccom_sockets_device *iccom_sk)
{
        if (IS_ERR_OR_NULL(iccom_sk)
                    || !iccom_is_running(&iccom_sk->iccom)) {
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
        res = iccom_set_channel_callback(&iccom_sk->iccom
                        , ICCOM_ANY_CHANNEL_VALUE
                        , &__iccom_socket_msg_rx_callback
                        , (void *)iccom_sk);
        if (res < 0) {
                __iccom_socket_protocol_device_close(iccom_sk);
                return res;
        }
        return res;
}

// closes whole iccom sockets device inclusive all
// underlying layers
static int __iccom_socket_device_close(
                struct iccom_sockets_device *iccom_sk)
{
        ICCOM_SK_CHECK_DEVICE("", return -ENODEV);

        // order matters
        __iccom_sk_loopback_ctl_close(iccom_sk);
        __iccom_sk_procfs_close(iccom_sk);
        __iccom_socket_unreg_socket_family(iccom_sk);
        __iccom_socket_protocol_device_close(iccom_sk);
        return 0;
}

// Initializes the device structure.
// RETURNS:
//      0: if success
//      <0: negated error code else
static int __iccom_socket_device_init(
                struct iccom_sockets_device *iccom_sk)
{
        ICCOM_SK_CHECK_DEVICE("", return -ENODEV);

        memset(iccom_sk, 0, sizeof(*iccom_sk));
        init_completion(&iccom_sk->initialized);
        init_completion(&iccom_sk->socket_closed);
        init_completion(&iccom_sk->pump_main_loop_done);

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
        __iccom_sk_procfs_init(iccom_sk);
        __iccom_sk_loopback_ctl_init(iccom_sk);

        // launches pump thread
        complete(&iccom_sk->initialized);

        iccom_socket_info_raw("protocol device initialization done");
        return 0;

failed:
        __iccom_socket_device_close(iccom_sk);
        return res;
}

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

static int __init iccom_socket_module_init(void)
{
        iccom_socket_info("loading module");
        int res = __iccom_socket_device_init(&__iccom_sockets_dev);
        if (res < 0) {
                iccom_socket_err("module loading failed, err: %d"
                                 , -res);
                return res;
        }
        iccom_socket_info("module loaded");
        return 0;
}

static void __exit iccom_socket_module_exit(void)
{
        iccom_socket_info("unloading module");
        int res = __iccom_socket_device_close(&__iccom_sockets_dev);
        if (res < 0) {
                iccom_socket_err("module closing failed, err: %d"
                                 , -res);
        }
        iccom_socket_info("module unloaded");
}

module_init(iccom_socket_module_init);
module_exit(iccom_socket_module_exit);

MODULE_DESCRIPTION("InterChipCommunication protocol User Space sockets"
                   " interface module.");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");
