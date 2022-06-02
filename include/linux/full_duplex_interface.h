/*
 * This file defines kernel API to a full duplex symmetrical
 * transport interface.
 *
 * Copyright (c) 2020 Robert Bosch GmbH
 * Artem Gulyaev <Artem.Gulyaev@de.bosch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// SPDX-License-Identifier: GPL-2.0

#ifndef FULL_DUPLEX_INTERFACE_HEADER

/* This file provides interface structures for a full-duplex
 * communication channel. These structures allow to abstract
 * any (more or less standard) full duplex interface and thus
 * avoid excessive dependencies between modules and allow
 * transport layer be easily switched.
 */

#include <linux/init.h>

/* -------------------- FULL DUPLEX IF --------------------------------- */

// Device is working on other xfer and can not process new request.
#define FULL_DUPLEX_ERROR_NOT_READY EALREADY
// no device was provided to work with
#define FULL_DUPLEX_ERROR_NO_DEVICE_PROVIDED 7


// Represents the single full duplex symmetrical tranfer.
//
// NOTE: Zeroing of all components leads to empty xfer without ID.
//
// @size_bytes Keeps the size of the xfer (number of raw bytes to
//      exchange with the other side).
//      NOTE: if our side triggers the xfer with the data size
//          which is not equal to size_bytes,
//          then there is a huge logical bug in upper layer,
//          cause we should always have the same xfer data size
//          no matter if we have xfer triggered from our Side or
//          from other Side
//      NOTE: zero size denotes empty xfer, and should not be launched
//      NOTE: zero size still may have non-null @data_tx / @data_rx_buf
//          pointers, which means that they point to some data still.
// @data_tx {!NULL && kernel memory} the pointer to data to be
//      sent to the other side. This data is provided by our consumer.
//      Its allocated size always should be more or equal to the
//      @size_bytes (even if @size_bytes is 0).
//      {NULL} then tx data is not defined.
// @data_rx_buf {!NULL && kernel memory}
//      Buffer for data from the other side. Its size always should
//      be more or equal to the @size_bytes.
//      {NULL} then rx data is not processed (even if @size_bytes is 0).
// @xfers_count {readonly for consumer}
//      Set **only** by SYMSPI. When the xfer is accepted from consumer
//      the counter is 0, and increases with every finished HW xfer.
//      The number of times this xfer (its current data was actually
//      xfered).
// @id { >= SYMSPI_INITIAL_XFER_ID } Set **only** by SYMSPI **when
//      the xfer is accepted** from consumer. Just the xfer name
//      (which wraps around) which allows us to tell consumer what
//      data was just sent/failed.
//      NOTE: the xfer is treated as new if consumer provided it
//          in some way (via callback, or via direct call). It
//          is irrelevant if it contains the same TX data as the
//          old one.
// @consumer_data the pointer to be provided to callback, when
//      it is called (usually used as a cookie for the callback
//      function)
// @done_callback
//      The pointer to kernel code callback, which should provide
//      us data for the next xfer. This callback is called when
//      the hardware xfer has been just finished.
//
//      TODO: to save resources, probably it will be better to
//          pass only single pointer to the corresponding
//          struct to the function.
//
//      RANGE:
//           {Valid pointer || NULL}
//
//      The callback **need** to provide us next ready-to-go
//      xfer data, cause this is symmetrical spi communication
//      and thus can also be initiated from other side, and
//      without ready-to-go xfer, we would need to request this
//      data up on other side request might decrease the xfer
//      maximum speed.
//
//      Our consumer will be able to update the current xfer data
//      as it needs.
//
//      CONTEXT:
//           Sleepable
//
//      PARAMS:
//          @done_xfer
//               The pointer to the xfer which was just done.
//          @next_xfer_id
//               The next transfer (if provided) will have this id.
//          @start_immediately__out
//               If true is written there before the callback
//               returns then current xfer will be sent immediately
//               (if new xfer is provided, then it will replace the
//               current xfer first).
//          @consumer_data
//               the consumer pointer, purely for consumer use
//
//      RETURNS:
//           {valid pointer} : next xfer data pointer (owned by
//           consumer, and can be freed after callback return)
//
//           {NULL} : then the old xfer persists.
//
//           {Error pointer} : then we halt in XFER state with our
//           flag raised (and the connection freezes until
//           restarted).
//
//      CONTEXT: which may sleep
//
// @fail_callback is called upon failure of the xfer (either local or
//      other side error)
//
//      NOTE:
//          If this function is undefined, then full duplex interface MUST
//          retry the failed xfer if this is possible.
//
//      PARAMETERS:
//          @failed_xfer
//               The pointer to the xfer which was just failed.
//          @next_xfer_id
//               The next transfer (if provided) will have this id.
//          @error_code, which defines the error code (positive)
//              which caused failure.
//          @consumer_data
//               the consumer pointer, purely for consumer use
//
//      RETURNS:
//
//          {valid pointer} : the next xfer to try to run,
//          {NULL} : retry to do xfer which just have failed,
//          {error-pointer} : halt the device until explicit start/restart.
//
struct full_duplex_xfer {
        size_t size_bytes;

        void __kernel *data_tx;
        void __kernel *data_rx_buf;

        int xfers_counter;

        int id;

        void __kernel *consumer_data;

        struct full_duplex_xfer *(*done_callback)(
                        const struct full_duplex_xfer __kernel *done_xfer
                        , const int next_xfer_id
                        , bool __kernel *start_immediately__out
                        , void __kernel *consumer_data);

        struct full_duplex_xfer *(*fail_callback)(
                        const struct full_duplex_xfer __kernel *failed_xfer
                        , const int next_xfer_id
                        , int error_code
                        , void __kernel *consumer_data);
};

// Defines the public interface to the symmetrical full duplex
// transport channel. This means two things:
//      1. Any data xfer is symmetric w.r.t. amount of data to
//         be xfered. So both sides of communication within
//         single xfer always send and receive the same amount
//         of data.
//      2. Any side can initiate the xfer at any time (when
//         other xfer is not running). So both sides are expected
//         always to have some default data to be sent via the
//         channel, to avoid slowing down the communication.
//
// TODO: move description from symspi to here
//
// @data_xchange see: symspi_data_xchange
// @default_data_update see: symspi_default_data_update
// @init see: symspi_init
// @close see: symspi_close
// @is_running see: symspi_is_running
// @reset see: symspi_reset
struct full_duplex_sym_iface {
        int (*data_xchange)(void __kernel *device
                            , struct __kernel full_duplex_xfer *xfer
                            , bool force_size_change);
        int (*default_data_update)(void __kernel *device
                                   , struct full_duplex_xfer *xfer
                                   , bool force_size_change);
        bool (*is_running)(void __kernel *device);
        int (*init)(void __kernel *device
                    , struct full_duplex_xfer *default_xfer);
        int (*reset)(void __kernel *device
                     , struct full_duplex_xfer *default_xfer);
        int (*close)(void __kernel *device);
};

// The struct represents the full-duplex transport device,
// which is supposed to implement the full_duplex_sym_iface.
// @dev the pointer to the structure which describes
//    the transport device (owned by the ultimate protocol driver)
//    which provides the @iface interface (full duplex byte sequence
//    transfer interface).
// @iface the pointer to the device transport interface.
//    (owned by the transport device driver): full duplex byte
//    sequence transfer interface.
struct full_duplex_device {
        void *dev;
        const struct full_duplex_sym_iface *iface;
};

#define FULL_DUPLEX_INTERFACE_HEADER

#endif //FULL_DUPLEX_INTERFACE_HEADER

