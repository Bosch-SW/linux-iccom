/*
 * This file defines kernel API for Inter Chip/CPU communication protocol
 * (ICCom) driver.
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

// NOTE: for ICCom protocol overview, please see the iccom.c file.

#ifndef ICCOM_HEADER

#include <linux/full_duplex_interface.h>

// the channel value which is interpreted as (any/all) channel(s)
#define ICCOM_ANY_CHANNEL_VALUE -1


// number of error types to be tracked
#define ICCOM_ERROR_TYPES_COUNT 2
// no memory
#define ICCOM_ERROR_NOMEM 1
// transport layer failed
#define ICCOM_ERROR_TRANSPORT 2

// size of data xfer in bytes
#define ICCOM_DATA_XFER_SIZE_BYTES 64
// size of data acknoledgement xfer in bytes
#define ICCOM_ACK_XFER_SIZE_BYTES 1

// defines the sysfs enabling value to create the
// RW files for iccom transport test manipulation
// via user space
#define ICCOM_SYSFS_CREATE_RW_FILES 1U
// defines the sysfs disabling value to remove the
// RW files for iccom transport test manipulation
// via user space
#define ICCOM_SYSFS_REMOVE_RW_FILES 0U

// defines the sysfs create channel character
// to be used to create channels
#define ICCOM_SYSFS_CREATE_CHANNEL 'c'
// defines the sysfs destroy channel character
// to be used to destroy channels
#define ICCOM_SYSFS_DELETE_CHANNEL 'd'

// defines the iccom version we are currently at
#define ICCOM_VERSION "2820bb7e0e3668815ce6e0a7cf019ec3664eaf10"

// maximum size for sysfs channel store command
#define ICCOM_TEST_SYSFS_CH_CMD_MAX_CHAR			25U
// maximum size for device test transport name
#define ICCOM_TRANSPORT_DEVICE_NAME_MAX_CHARACTERS		50U
// number of maximum messages from iccom to
// the upper layer that the list can store
#define ICCOM_SYSFS_MAX_MSG_ALLOWED_PER_CHANNEL			50U

// The message ready for customer layer callback type.
//      @channel {valid channel number} the channel in which ready
//          message is reported,
//      @msg_data {valid pointer} points to the data of the ready
//          message,
//      @msg_len {>0} the size of @msg_data in bytes
//      @consumer_data the pointer provided by consumer when the
//          callback was installed
// RETURNS:
//      if callback returns true, then
//      ownership of message data (@msg_data) is transferred to
//      the consumer; if callback returns false, then message
//      data ownership remains in ICCom, and the message (and its
//      data) is immediately discarded after callback invocation.
typedef bool (*iccom_msg_ready_callback_ptr_t)( unsigned int channel
                  , void *msg_data, size_t msg_len
                  , void *consumer_data);

// Describes the ICCom data
// @p {any} pointer to iccom_dev_private data. This pointer is managed
//      by iccom_dev. The pointed struct is also managed by iccom device.
// @xfer_device the device which supplies the full-duples symmetrical
//      data xfers between Sides. Must be initialised by consumer. This
//      pointer is passed to methods, defined by @xfer_iface.
// @xfer_iface the structure which provides pointers to
//      transport methods of the device, provided by @xfer_device.
// @sysfs_test_ch_head the list which shall hold the user space channels
//      received data from iccom received from transport to send to upper layers
struct iccom_dev {
        struct iccom_dev_private *p;

        void *xfer_device;
        struct full_duplex_sym_iface xfer_iface;
        struct kobject* channels_root;
        struct list_head sysfs_test_ch_head ;
};

/* ------------------ KERNEL SPACE API DECLARATIONS ---------------------*/
/* ---------------for documentation, see iccom.c file -------------------*/

int iccom_post_message(struct iccom_dev *iccom
                , char *data, const size_t length
                , unsigned int channel
                , unsigned int priority);
int iccom_flush(struct iccom_dev *iccom);
int iccom_set_channel_callback(struct iccom_dev *iccom
                , unsigned int channel
                , iccom_msg_ready_callback_ptr_t message_ready_callback
                , void *consumer_data);
int iccom_remove_channel_callback(struct iccom_dev *iccom
                , unsigned int channel);
iccom_msg_ready_callback_ptr_t iccom_get_channel_callback(
                struct iccom_dev *iccom
                , unsigned int channel);
int iccom_read_message(struct iccom_dev *iccom
                , unsigned int channel
                , void __kernel **msg_data_ptr__out
                , size_t __kernel *buf_size__out
                , unsigned int *msg_id__out);
void iccom_print_statistics(struct iccom_dev *iccom);
int iccom_init(struct iccom_dev *iccom);
void iccom_close(struct iccom_dev *iccom);
int iccom_init_binded(
                struct iccom_dev *iccom
                , const struct full_duplex_sym_iface *const full_duplex_if
                , void *full_duplex_device);
void iccom_close_binded(struct iccom_dev *iccom);
bool iccom_is_running(struct iccom_dev *iccom);

#define ICCOM_HEADER

#endif //ICCOM_HEADER
