/*
 * This file defines the Full Duplex Test Transport driver
 * (fully symmetrical transport layer) for testing the ICCom
 * functionality
 *
 * Copyright (c) 2023 Robert Bosch GmbH
 * Luis Jacinto <Luis.Jacinto@bosch.com>
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

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>

#include <linux/fd_test_transport.h>

/* ------------- BUILD CONFIGURATION ------------- */

#define FD_TT_VERBOSITY 3

#define FD_TT_LOG_PREFIX "FD Test Transport: "

/* ------------- GENERAL CONFIGURATION -------------*/

/* --------------- DATA PACKAGE CONFIGURATION ---------------*/

// to keep the compatibility with Kernel versions earlier than v5.5
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
    #define pr_warning pr_warn
#endif

#if FD_TT_VERBOSITY >= 1
#define fd_tt_err(fmt, ...)						\
	pr_err(FD_TT_LOG_PREFIX"%s: "fmt"\n", __func__, ##__VA_ARGS__)
#define fd_tt_err_raw(fmt, ...)						\
	pr_err(FD_TT_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#else
#define fd_tt_err(fmt, ...)
#define fd_tt_err_raw(fmt, ...)
#endif

#if FD_TT_VERBOSITY >= 2
#define fd_tt_warning(fmt, ...)						\
	pr_warning(FD_TT_LOG_PREFIX"%s: "fmt"\n", __func__		\
		   , ##__VA_ARGS__)
#define fd_tt_warning_raw(fmt, ...)					\
	pr_warning(FD_TT_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#else
#define fd_tt_warning(fmt, ...)
#define fd_tt_warning_raw(fmt, ...)
#endif

#if FD_TT_VERBOSITY >= 3
#define fd_tt_info_helper(fmt, ...)					\
	pr_info(FD_TT_LOG_PREFIX"%s: "fmt"\n", __func__, ##__VA_ARGS__)
#define fd_tt_info_raw_helper(fmt, ...)					\
	pr_info(FD_TT_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define fd_tt_info_helper_0(fmt, ...)					\
	fd_tt_info_helper(fmt, ##__VA_ARGS__)
#define fd_tt_info_raw_helper_0(fmt, ...)				\
	fd_tt_info_raw_helper(fmt, ##__VA_ARGS__)
#else
#define fd_tt_info_helper(fmt, ...)
#define fd_tt_info_raw_helper(fmt, ...)
#define fd_tt_info_helper_0(fmt, ...)
#define fd_tt_info_raw_helper_0(fmt, ...)
#endif

#if FD_TT_VERBOSITY >= 4
#define fd_tt_info_helper_1(fmt, ...)					\
	fd_tt_info_helper(fmt, ##__VA_ARGS__)
#define fd_tt_info_raw_helper_1(fmt, ...)				\
	fd_tt_info_raw_helper(fmt, ##__VA_ARGS__)
#else
#define fd_tt_info_helper_1(fmt, ...)
#define fd_tt_info_raw_helper_1(fmt, ...)
#endif

#if FD_TT_VERBOSITY >= 5
#define fd_tt_info_helper_2(fmt, ...)					\
	fd_tt_info_helper(fmt, ##__VA_ARGS__)
#define fd_tt_info_raw_helper_2(fmt, ...)				\
	fd_tt_info_raw_helper(fmt, ##__VA_ARGS__)
#else
#define fd_tt_info_helper_2(fmt, ...)
#define fd_tt_info_raw_helper_2(fmt, ...)
#endif

// information messages levels
#define FD_TT_LOG_INFO_KEY_LEVEL 0
#define FD_TT_LOG_INFO_OPT_LEVEL 1
#define FD_TT_LOG_INFO_DBG_LEVEL 2

#define fd_tt_info_helper__(level, fmt, ...)				\
	fd_tt_info_helper_##level(fmt, ##__VA_ARGS__)
#define fd_tt_info_raw_helper__(level, fmt, ...)			\
	fd_tt_info_raw_helper_##level(fmt, ##__VA_ARGS__)

#define fd_tt_info(level, fmt, ...)					\
	fd_tt_info_helper__(level, fmt, ##__VA_ARGS__)
#define fd_tt_info_raw(level, fmt, ...)					\
	fd_tt_info_raw_helper__(level, fmt, ##__VA_ARGS__)

#define FD_TT_GET_FULL_DUPLEX_DEVICE(dev)				\
	struct full_duplex_device * full_duplex_dev =			\
		(struct full_duplex_device *) dev_get_drvdata(dev);
#define FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE()			\
	struct fd_test_transport_dev *xfer_device =			\
		(struct fd_test_transport_dev *)full_duplex_dev->dev;
#define FD_TT_XFER_DEVICE_ON_FINISH(error_action)			\
	if (xfer_device->finishing) {					\
		error_action;						\
	}
#define FD_TT_CHECK_FULL_DUPLEX_DEVICE(msg, error_action)		\
	if (IS_ERR_OR_NULL(full_duplex_dev)) {				\
		fd_tt_err(						\
			"%s: no device; "msg"\n"			\
			, __func__);					\
		error_action;						\
	}
#define FD_TT_CHECK_XFER_DEVICE(msg, error_action)			\
	if (IS_ERR_OR_NULL(full_duplex_dev->dev)) {			\
		fd_tt_err(						\
			"%s: no device; "msg"\n"	\
			, __func__);					\
		error_action;						\
	}
#define FD_TT_CHECK_PTR(ptr, error_action)				\
	if (IS_ERR_OR_NULL(ptr)) {					\
		fd_tt_err(						\
			"%s: pointer "# ptr" is invalid;\n"		\
			, __func__);					\
		error_action;						\
	}
/* ------------- GLOBAL VARIABLES ---------------*/

// Serves to allocate unique ids for
// creating Full Duplex Test Transport
// platform devices trough the usage of
// sysfs interfaces
struct ida fd_tt_dev_id;


/* ------------- FORWARD DECLARATIONS -------------*/

int fd_tt_data_xchange(
			void __kernel *device,
			struct __kernel full_duplex_xfer *xfer,
			bool force_size_change);
int fd_tt_default_data_update(
				void __kernel *device,
				struct full_duplex_xfer *xfer,
				bool force_size_change);
int fd_tt_init(
		void __kernel *device,
		struct full_duplex_xfer *default_xfer);
int fd_tt_reset(
		void __kernel *device,
		struct full_duplex_xfer *default_xfer);
int fd_tt_close(void __kernel *device);
bool fd_tt_is_running(void __kernel *device);

/* -------------- MAIN STRUCTURES -------------*/

const struct full_duplex_sym_iface full_duplex_dev_iface = {
	.data_xchange = &fd_tt_data_xchange,
	.default_data_update = &fd_tt_default_data_update,
	.is_running = &fd_tt_is_running,
	.init = &fd_tt_init,
	.reset = &fd_tt_reset,
	.close = &fd_tt_close
};

// This structure holds the internal/private data belonging
// to a Full Duplex Test Transport platform device. These 
// structure has the information where userspace has written
// data to perform an exchange with iccom, the next xfer id,
// whether or not the transport is running or has finalized
//
// @xfer the xfer to execute data
// @got_us_data true if for the given @xfer userspace has provided the
//      wire data already (this guy is being reset every new xfer).
// @next_xfer_id contains the next xfer id 
//      to be transmitted
// @running contains the status whether transport
//      is running or not
// @finishing contains the status whether transport
//      is finishing its work
struct fd_test_transport_dev {
	struct full_duplex_xfer xfer;
	bool got_us_data;
	int next_xfer_id;
	bool running;
	bool finishing;
};

/*------------- FULL DUPLEX INTERFACE HELPER FUNCTIONS -------------*/

// Initializes the xfer data to the default empty state
//
// @xfer {valid ptr} transfer structure
void fd_tt_xfer_init(struct full_duplex_xfer *xfer)
{
	memset(xfer, 0, sizeof(struct full_duplex_xfer));
}

// Frees all memory allocated within the xfer 
// and defaults all its data 
//
// @xfer {valid ptr} transfer structure
void fd_tt_xfer_free(struct full_duplex_xfer *xfer)
{
	if (IS_ERR_OR_NULL(xfer)) {
		return;
	}
	if (!IS_ERR_OR_NULL(xfer->data_tx)) {
		kfree(xfer->data_tx);
		xfer->data_tx = NULL;
	}
	if (!IS_ERR_OR_NULL(xfer->data_rx_buf)) {
		kfree(xfer->data_rx_buf);
		xfer->data_rx_buf = NULL;
	}
	memset(xfer, 0, sizeof(struct full_duplex_xfer));
}

// Write the data received from userspace into the xfer
// rx_data_buf and allocates the necessary space for it
//
// @xfer_device {valid ptr} xfer device
// @data_transport_to_iccom {array} data from userspace to be copied
// @data_transport_to_iccom_size {number} size of data to be copied
//
// NOTE: The input array is copied into the xfer_device but the
//       array ownership remains in the caller which shall be responsible
//       to free the memory.
//
// RETURNS:
//      0: ok
//      -EINVAL: xfer is null pointer
//      -ENOMEM: no memory to allocate
int fd_tt_update_wire_data(
		struct fd_test_transport_dev *xfer_device,
		char *data_transport_to_iccom,
		size_t data_transport_to_iccom_size)
{
	if (IS_ERR_OR_NULL(&xfer_device->xfer)) {
		return -EINVAL;
	}

	if (!IS_ERR_OR_NULL(xfer_device->xfer.data_rx_buf)) {
		kfree(xfer_device->xfer.data_rx_buf);
		xfer_device->xfer.data_rx_buf = NULL;
	}

	if (!IS_ERR_OR_NULL(data_transport_to_iccom) &&
		data_transport_to_iccom_size) {
		xfer_device->xfer.size_bytes = data_transport_to_iccom_size;
		xfer_device->xfer.data_rx_buf =
			kmalloc(xfer_device->xfer.size_bytes, GFP_KERNEL);
		if (!xfer_device->xfer.data_rx_buf) {
			return -ENOMEM;
		}
		memcpy(xfer_device->xfer.data_rx_buf, data_transport_to_iccom,
			xfer_device->xfer.size_bytes);
	}

	// NOTE: the actual xfer will happen on-read (wire data show)
	//       to keep the userspace in sync. The total workflow goes:
	//       * userspace writes to wire
	//           * this data gets saved in current xfer
	//               * transport dev remembers that the wire data is provided
	//       * userspace reads from wire
	//           * transport dev gets read request
	//           * if no write was provided before - reject to read. Else:
	//           * the current xfer wire data is provided to userspace
	//           * transport dev confirms xfer_done(...) to ICCom
	//           * ICCom updates the current xfer with new data
	xfer_device->got_us_data = true;

	return 0;
}

// Deep copy of src xfer to a dst xfer
// with memory allocation and pointers checks
//
// @src {valid ptr} source xfer
// @dst {valid ptr} destination xfer
//
// RETURNS:
//      0: ok
//      -EINVAL: src or dst is null pointer
//      -ENOMEM: no memory to allocate
int fd_tt_deep_xfer_copy(
		struct full_duplex_xfer *src,
		struct full_duplex_xfer *dst)
{
	if (IS_ERR_OR_NULL(src) || IS_ERR_OR_NULL(dst)) {
		return -EINVAL;
	}

	fd_tt_xfer_free(dst);

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
// @xfer_device {valid ptr} xfer device
//
// RETURNS:
//      >0: id of the next xfer
int fd_tt_iterate_to_next_xfer_id(
		struct fd_test_transport_dev *xfer_device)
{
	int res = xfer_device->next_xfer_id;

	xfer_device->next_xfer_id++;

	if (xfer_device->next_xfer_id < 0) {
		xfer_device->next_xfer_id = 1;
	}
	return res;
}

// Accepts the data from iccom, copies its original
// data into two xfers and iterates on the next
// xfer id to be transmitted
//
// @xfer_device {valid ptr} xfer device
// @xfer {valid ptr} received xfer from iccom
//
// RETURNS:
//     >0: no errors
//     <0: errors
int fd_tt_accept_data(
		struct fd_test_transport_dev* xfer_device,
		struct __kernel full_duplex_xfer *xfer)
{
	// Copy xfer to dev xfer as is. In later
	// stage override the data_rx_buf in fd_tt_update_wire_data
	int res = fd_tt_deep_xfer_copy(xfer, &xfer_device->xfer);
	if (res < 0) {
		return res;
	}

	xfer_device->xfer.id = fd_tt_iterate_to_next_xfer_id(xfer_device);

	return xfer_device->xfer.id;
}

// Function to trigger an exchange of data between
// iccom and full duplex test transport with data
// validation
//
// @xfer_device {valid ptr} xfer device
__maybe_unused
static void fd_tt_trigger_data_exchange(
		struct fd_test_transport_dev *xfer_device)
{
	if (IS_ERR_OR_NULL(xfer_device->xfer.done_callback)) {
		return;
	}

	bool start_immediately = false;
	struct full_duplex_xfer *next_xfer
			= xfer_device->xfer.done_callback(
				&xfer_device->xfer,
				xfer_device->next_xfer_id,
				&start_immediately,
				xfer_device->xfer.consumer_data);

	// NOTE: For a new xfer to happen userspace must
	//       provide new data, so dropping the flag
	xfer_device->got_us_data = false;

	if (IS_ERR_OR_NULL(next_xfer)) {
		return;
	}

	fd_tt_accept_data(xfer_device, next_xfer);
}

/* ------------- FULL DUPLEX INTERFACE API ------------- */

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to start exchange of data
// between ICCom and Transport. The xfer data is always
// null as no actual data is expected to be exchanged
// in this function.
//
// NOTE: This test driver is mainly used for testing
//       the iccom driver and devices. Data-race conditions
//       were not considered for simplicity as this is a testing
//       facility. It is well known that data-race might occur
//       as the code is not protected against it.
//
// @device {valid ptr} transport device
// @xfer {valid ptr} xfer data
// @force_size_change {bool} force size variable
//
// RETURNS:
//      0: ok
//     <0: errors
__maybe_unused
int fd_tt_data_xchange(
		void __kernel *device,
		struct __kernel full_duplex_xfer *xfer,
		bool force_size_change)
{
	FD_TT_CHECK_PTR(device, return -EFAULT)
	FD_TT_GET_FULL_DUPLEX_DEVICE(device);
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return -ENODEV);
	FD_TT_CHECK_XFER_DEVICE("", return -EFAULT);
	FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE();
	FD_TT_XFER_DEVICE_ON_FINISH(return -EHOSTDOWN);
	return 0;
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to update the default data
// that will be exchanged
//
// NOTE: This test driver is mainly used for testing
//       the iccom driver and devices. Data-race conditions
//       were not considered for simplicity as this is a testing
//       facility. It is well known that data-race might occur
//       as the code is not protected against it.
//
// @device {valid ptr} transport device
// @xfer {valid ptr} xfer data
// @force_size_change {bool} force size variable
//
// RETURNS:
//      0: ok
//      <0: error happened
__maybe_unused
int fd_tt_default_data_update(
		void __kernel *device,
		struct full_duplex_xfer *xfer,
		bool force_size_change)
{
	FD_TT_CHECK_PTR(device, return -EFAULT)
	FD_TT_GET_FULL_DUPLEX_DEVICE(device);
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return -ENODEV);
	FD_TT_CHECK_XFER_DEVICE("", return -EFAULT);
	FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE();
	FD_TT_XFER_DEVICE_ON_FINISH(return -EHOSTDOWN);
	return fd_tt_accept_data(xfer_device, xfer);
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to know whether xfer
// device is running or not
//
// NOTE: This test driver is mainly used for testing
//       the iccom driver and devices. Data-race conditions
//       were not considered for simplicity as this is a testing
//       facility. It is well known that data-race might occur
//       as the code is not protected against it.
//
// @device {valid ptr} transport device
//
// RETURNS:
//      true: running
//      false: not running
__maybe_unused
bool fd_tt_is_running(void __kernel *device)
{
	FD_TT_CHECK_PTR(device, return false)
	FD_TT_GET_FULL_DUPLEX_DEVICE(device);
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return false);
	FD_TT_CHECK_XFER_DEVICE("", return false);
	FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE();
	FD_TT_XFER_DEVICE_ON_FINISH(return false);
	return xfer_device->running;
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to initialize the
// transport iface and copy the default xfer provided by ICCom
//
// NOTE: This test driver is mainly used for testing
//       the iccom driver and devices. Data-race conditions
//       were not considered for simplicity as this is a testing
//       facility. It is well known that data-race might occur
//       as the code is not protected against it.
//
// @device {valid ptr} transport device
// @default_xfer {valid ptr} default xfer
//
// RETURNS:
//      0: ok
//     <0: errors
__maybe_unused
int fd_tt_init(
		void __kernel *device,
		struct full_duplex_xfer *default_xfer)
{
	FD_TT_CHECK_PTR(device, return -EFAULT)
	FD_TT_GET_FULL_DUPLEX_DEVICE(device);
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return -ENODEV);
	FD_TT_CHECK_XFER_DEVICE("", return -EFAULT);
	FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE();
	fd_tt_xfer_init(&xfer_device->xfer);
	xfer_device->next_xfer_id = 1;
	xfer_device->finishing = false;
	xfer_device->running = true;
	xfer_device->got_us_data = false;
	return fd_tt_accept_data(xfer_device, default_xfer);
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to close the
// transport iface and free the memory
//
// NOTE: This test driver is mainly used for testing
//       the iccom driver and devices. Data-race conditions
//       were not considered for simplicity as this is a testing
//       facility. It is well known that data-race might occur
//       as the code is not protected against it.
//
// @device {valid ptr} transport device
//
// RETURNS:
//      0: ok
//     <0: errors
__maybe_unused
int fd_tt_close(void __kernel *device)
{
	FD_TT_CHECK_PTR(device, return -EFAULT)
	FD_TT_GET_FULL_DUPLEX_DEVICE(device);
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return -ENODEV);
	FD_TT_CHECK_XFER_DEVICE("", return -EFAULT);
	FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE();

	xfer_device->finishing = true;
	xfer_device->running = false;
	fd_tt_xfer_free(&xfer_device->xfer);

	return 0;
}

// API
//
// See struct full_duplex_interface description.
//
// Function triggered by ICCom to reset the iface
// which closes and inits again the device
//
// NOTE: This test driver is mainly used for testing
//       the iccom driver and devices. Data-race conditions
//       were not considered for simplicity as this is a testing
//       facility. It is well known that data-race might occur
//       as the code is not protected against it.
//
// @device {valid ptr} transport device
// @default_xfer {valid ptr} default xfer
//
// RETURNS:
//      0: ok
//     <0: errors
__maybe_unused
int fd_tt_reset(
		void __kernel *device,
		struct full_duplex_xfer *default_xfer)
{
	fd_tt_close(device);
	return fd_tt_init(device, default_xfer);
}

/* ------------- FULL DUPLEX TEST TRANSPORT DEVICE ------------- */

// Trim a sysfs input buffer coming from userspace
// wich might have unwanted characters
//
// @buf {valid prt} buffer to be trimmed
// @size {number} size of data valid without 0-terminator
//
//RETURNS
// count: size of valid data within the array
size_t fd_tt_sysfs_trim_buffer(char *buf, size_t size)
{
	size_t count = size;
	while (count > 0 && ((buf[count - 1] == '\n') || (buf[count - 1] == ' ')
			|| (buf[count - 1] == '\t') || (buf[count - 1] == 0))) {
		buf[count-- - 1] = 0;
	}
	return count;
}

// Parse the hex string into a byte array.
//
// String must be a null-terminated string of 2-digit numbers (hex digits):
// Example:
//           11030AFFDDCD\0
// each 2-digit number will be converted to the byte value,
// and the result will be written to the buffer
//
// NOTE: if parsing failed somewhere in the middle, then result is still
//       an error (so either all is fine or all failed, not inbetween)
//
// @str {valid ptr} buffer, containing the input null-terminated string
// @str_len {number} length of string given by @str (in bytes)
//                   **NOT** including the 0-terminator
//
// NOTE: if the @str_len is 0, then no parsing is done at all
//       function just returns.
//
// @bytearray__out {array} array to copy the data to
// @out_size {>=0} size of the @bytearray__out in bytes
//
// RETURNS:
//      >=0: the size of the data written to @bytearray__out
//      <0: negated error code
ssize_t fd_tt_convert_hex_str_to_byte_array(
		const char *str, const size_t str_len,
		uint8_t *bytearray__out, size_t out_size)
{
	// to be "intelligent" we go for this check first
	if (str_len == 0) {
		return 0;
	}

	// errors block
	if (IS_ERR_OR_NULL(str)) {
		fd_tt_err("broken string ptr.");
		return -EINVAL;
	}
	if (str[str_len] != 0) {
		fd_tt_err("string does not terminate with 0.");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(bytearray__out)) {
		fd_tt_err("bad output array ptr.");
		return -EINVAL;
	}
	if (str_len % FD_TT_CHARS_PER_BYTE != 0) {
		fd_tt_err("string"
			" must contain %d-multiple number of hex digits"
			" + 0-terminator only. String provided (in -- quotes):"
			" --%s--"
			, FD_TT_CHARS_PER_BYTE, str);
		return -EINVAL;
	}
	if (out_size < str_len / FD_TT_CHARS_PER_BYTE) {
		fd_tt_err("receiver array"
			" is smaller (%zu) than needed (%zu)."
			, out_size, str_len / FD_TT_CHARS_PER_BYTE);
		return -EINVAL;
	}

	char tmp[FD_TT_CHARS_PER_BYTE + 1];
	tmp[FD_TT_CHARS_PER_BYTE] = 0;

	int w_idx = 0;
	for (int i = 0; i <= str_len - FD_TT_CHARS_PER_BYTE; i += FD_TT_CHARS_PER_BYTE) {
		memcpy(tmp, str + i, FD_TT_CHARS_PER_BYTE);

		unsigned int val;
		int res = kstrtouint(tmp, 16, &val);

		if (res != 0) {
			fd_tt_err("failed at part: %s", tmp);
			return val;
		}
		if (val > 0xFF) {
			fd_tt_err("failed, part overflow: %s", tmp);
			return val;
		}
		*(bytearray__out + w_idx++) = (uint8_t)val;
	}

	return w_idx;
}

// Encode the iccom data sent to transport by
// converting each number (one byte) into two bytes (in char format XX)
// and write the data in a new output table
//
// @buf__out {valid ptr} buffer to copy the data to
// @buf_size {number} size of buffer data
// @data_iccom_to_transport {array} array holding the data to be copied
// @data_iccom_to_transport_size {number} size of array
//
// RETURNS:
//      >=0: the size of the data written to @buf__out
//      <0: negated error code
ssize_t fd_tt_iccom_convert_byte_array_to_hex_str(
		char *buf__out, size_t buf_size,
		const uint8_t *data_iccom_to_transport,
		const size_t data_iccom_to_transport_size)
{
	ssize_t length = 0;

	// NOTE: Each byte shall be transformed into hexadecimal characters
	//       with the FD_TT_CHARS_PER_BYTE elements.
	if (data_iccom_to_transport_size * FD_TT_CHARS_PER_BYTE > buf_size) {
		fd_tt_err("Sysfs iccom to transport data is bigger than the buffer");
		return -EINVAL;
	}
	
	for (int i = 0; i < data_iccom_to_transport_size; i++)
	{
		length += scnprintf(buf__out + length,
						PAGE_SIZE - length,
						"%0" __stringify(FD_TT_CHARS_PER_BYTE) "x",
						data_iccom_to_transport[i]);
	}
	return length;
}

// The sysfs transport_RW_show function get's triggered
// whenever from userspace one wants to read the sysfs
// file transport_RW.
// It shall return the data sent from iccom to transport
// (that should be transmitted). Also it shall trigger a
// the xfer exchange between iccom and transport.
//
// @dev {valid ptr} Transport device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to userspace
//
//NOTE: To exchange data between transport and iccom
//      one needs first to write to the transport via
//      userspace trough transport_RW_store. Only then
//      one can read the transport data and after that
//      a new exchange shall happen
//
// RETURNS:
//        0: No data
//      > 0: size of data to be showed in userspace
//  -EPROTO: No data has been written via userspace
//           before trying to read
//  -EINVAL: Converstion from byte to hex failed
//  -EFAULT: Devices are null
//  -ENODEV: Full duplex device does not exist
static ssize_t transport_RW_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	FD_TT_GET_FULL_DUPLEX_DEVICE(dev);
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return -ENODEV);
	FD_TT_CHECK_XFER_DEVICE("", return -EFAULT);
	FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE();

	if (!xfer_device->got_us_data) {
		fd_tt_err("to read something you need to "
				" write something first =)");
		return -EPROTO;
	}

	// NOTE: We return the data available in the transport that got
	//       written by iccom
	ssize_t length = fd_tt_iccom_convert_byte_array_to_hex_str(
				buf, PAGE_SIZE, (uint8_t*)xfer_device->xfer.data_tx,
				xfer_device->xfer.size_bytes);
	
	if (length <= 0) {
		print_hex_dump(KERN_INFO, FD_TT_LOG_PREFIX"Conversion from byte"
				"array to hex string failed: ", 0, 16
				, 1, xfer_device->xfer.data_tx,
				xfer_device->xfer.size_bytes, true);
		return -EINVAL;
	}

	// Perform the next xfer exchange
	fd_tt_trigger_data_exchange(xfer_device);

	return length;
}

// The sysfs transport_RW_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file transport_RW_store.
// It shall write the data that shall be sent from transport
// to the iccom in the next xfer exchange (which happen when
// transport_RW sysfs file get's read).
//
// @dev {valid ptr} Transport device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer with the data from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//  count: ok
//  -EINVAL: buffer size is wrong, 0-terminator missing or xfer size less
//           or equal to zero
//  -EFAULT: Devices are null
//  -ENODEV: Full duplex device does not exist
//  -ENOMEM: No memory to allocate
static ssize_t transport_RW_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	FD_TT_GET_FULL_DUPLEX_DEVICE(dev);
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return -ENODEV);
	FD_TT_CHECK_XFER_DEVICE("", return -EFAULT);
	FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE();

	// Sysfs store procedure has data from userspace with length equal
	// to count. The next byte after the data sent (count + 1) will always
	// be a 0-terminator char. This is the default behavior of sysfs.
	size_t hex_buffer_size = count + 1;
	// Wire data will always be half the size of the received buffer
	// from userspace 
	size_t wire_data_size = count / FD_TT_CHARS_PER_BYTE;
	ssize_t ret;

	if (count >= PAGE_SIZE) {
		fd_tt_warning("Sysfs data can not fit the 0-terminator.");
		return -EINVAL;
	}

	char *hex_buffer = (char *) kzalloc(hex_buffer_size, GFP_KERNEL);
	
	if (IS_ERR_OR_NULL(hex_buffer)) {
		return -ENOMEM;
	}

	char *wire_data = (char *) kzalloc(wire_data_size, GFP_KERNEL);
	
	if (IS_ERR_OR_NULL(wire_data)) {
		ret = -ENOMEM;
		goto hex_buffer_clean_up;
	}
	
	memcpy(hex_buffer, buf, hex_buffer_size);
	
	// NOTE: count is a length without the last 0-terminator char
	if (hex_buffer[count] != 0) {
		fd_tt_warning("NON-null-terminated string is provided by sysfs.");
		ret = -EINVAL;
		goto finalize;
	}

	hex_buffer_size = fd_tt_sysfs_trim_buffer(hex_buffer, count);
	
	ssize_t xfer_size = fd_tt_convert_hex_str_to_byte_array(
					hex_buffer,
					hex_buffer_size,
					wire_data, wire_data_size);

#if FD_TT_VERBOSITY >= 5
	print_hex_dump(KERN_INFO, FD_TT_LOG_PREFIX"Sim RX data: ", 0, 16
			, 1, wire_data, xfer_size, true);
#endif

	if (xfer_size <= 0) {
		fd_tt_warning("transport Device Decoding failed for str: %s"
				, hex_buffer);
		ret = -EINVAL;
		goto finalize;
	}

	fd_tt_update_wire_data(xfer_device, wire_data, xfer_size);
	ret = count;

finalize:
	kfree(wire_data);
	wire_data = NULL;
hex_buffer_clean_up:
	kfree(hex_buffer);
	hex_buffer = NULL;
	return ret;
}

static DEVICE_ATTR_RW(transport_RW);

// The sysfs transport_ctl_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file transport_ctl.
// It allows to create or destroy the transport_RW sysfs
// file for a given transport.
//
// @dev {valid ptr} iccom device
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//  count (1): ok
//         <0: negated error code
static ssize_t transport_ctl_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	if (count != 1) {
		goto wrong_usage;
	}

	char option = buf[0];
	if (option == FD_TT_SYSFS_CREATE_RW_FILES) {
		if (!IS_ERR_OR_NULL(sysfs_get_dirent(dev->kobj.sd, "transport_RW"))) {
			fd_tt_err("Files already exist");
			return -EINVAL;
		}

		if (device_create_file(dev, &dev_attr_transport_RW) != 0) {
			fd_tt_err("Error creating the transport_RW file.");
			return -EINVAL;
		}
	} else if (option == FD_TT_SYSFS_DELETE_RW_FILES) {
		device_remove_file(dev, &dev_attr_transport_RW);
	} else {
		goto wrong_usage;
	}

	return count;

wrong_usage:
	fd_tt_err("Sysfs transport ctl format error!\n"
			"x where x - is one of [%c;%c]\n"
			"(%c - creates sysfs RW files for transport"
			"%c - deletes sysfs RW files for transport)\n",
			FD_TT_SYSFS_CREATE_RW_FILES,
			FD_TT_SYSFS_DELETE_RW_FILES,
			FD_TT_SYSFS_CREATE_RW_FILES,
			FD_TT_SYSFS_DELETE_RW_FILES);
	return -EINVAL;
}

static DEVICE_ATTR_WO(transport_ctl);

// List containing default attributes that a
// full duplex test transport device can have.
//
// NOTE: sysfs file transport_RW is not registered in
//       this list as it can be manually created/destroyed
//       using the sysfs file transport_ctl
//
// @dev_attr_transport_ctl the sysfs file to create
//                      or destroy the RW file
static struct attribute *fd_test_transport_dev_attrs[] = {
	&dev_attr_transport_ctl.attr,
	NULL,
};

ATTRIBUTE_GROUPS(fd_test_transport_dev);

// The sysfs create_transport_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file create_transport.
// It shall create full duplex test transport devices with
// an unique id.
//
// @class {valid ptr} transport class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//  count: ok
//     <0: negated error code
static ssize_t create_transport_store(
		struct class *class, struct class_attribute *attr,
		const char *buf, size_t count)
{
	// Allocate new unused ID
	int device_id = ida_alloc(&fd_tt_dev_id,GFP_KERNEL);

	if (device_id < 0) {
		fd_tt_err("Could not allocate a new unused ID");
		return -EINVAL;
	}

	// NOTE: The FD Test Transport driver behaves as a bus driver
	//       and therefore devices that get created are owned by
	//       that particular bus. Via Sysfs we have the ability
	//       to manually create HW devices on the bus which need 
	//       to be manually deleted later on (the same way they
	//       were created manually) or when the bus get deleted
	struct platform_device *new_pdev = 
		platform_device_register_simple("fd_test_transport",
							device_id, NULL, 0);

	if (IS_ERR_OR_NULL(new_pdev)) {
		fd_tt_err("Could not register the device fd_test_transport.%d",
								device_id);
		ida_free(&fd_tt_dev_id, device_id);
		return -EFAULT;
	}

	return count;
}

static CLASS_ATTR_WO(create_transport);

// The sysfs delete_transport_store function get's triggered
// whenever from userspace one wants to write the sysfs
// file delete_transport.
// It shall delete the full duplex test transport device
// wich matchs the provided id.
//
// @class {valid ptr} transport class
// @attr {valid ptr} class attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// NOTE: Whenever there is an iccom device using
//       the fd_test_transport with a link dependency
//       we do not allow the userspace to destroy the
//       device. In order to delete properly the transport
//       one needs to destroy first the iccom device and only
//       then one can destroy the transport. Also the userspace
//       is responsible while testing via sysfs for creating 
//       manually the fd_test_transport devices as well as to 
//       destroy them in the end.
//
// RETURNS:
//  count: ok
//     <0: negated error code
static ssize_t delete_transport_store(
		struct class *class, struct class_attribute *attr,
		const char *buf, size_t count)
{
	if (count >= PAGE_SIZE) {
		fd_tt_warning("Sysfs data can not fit the 0-terminator.");
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
		fd_tt_warning("NON-null-terminated string is provided by sysfs.");
		kfree(device_name);
		device_name = NULL;
		return -EFAULT;
	}

	(void)fd_tt_sysfs_trim_buffer(device_name, count);

	struct device *platform_device = 
		bus_find_device_by_name(&platform_bus_type, NULL, device_name);

	kfree(device_name);
	device_name = NULL;
	
	if (IS_ERR_OR_NULL(platform_device)) {
		fd_tt_err("Full Duplex Test Transport device is null.");
		return -EFAULT;
	}

	platform_device_unregister(to_platform_device(platform_device));

	return count;
}

static CLASS_ATTR_WO(delete_transport);

// List containing all transport class attributes
//
// @class_attr_create_transport sysfs file for creating
//                              fd_test_transport devices
// @class_attr_delete_transport sysfs file for deleting
//                              fd_test_transport devices
static struct attribute *fd_tt_class_attrs[] = {
	&class_attr_create_transport.attr,
	&class_attr_delete_transport.attr,
	NULL
};

ATTRIBUTE_GROUPS(fd_tt_class);

// The full duplex test transport class definition
//
// @name class name
// @owner the module owner
// @class_groups group holding all the attributes
static struct class fd_tt_class = {
	.name = "fd_test_transport",
	.owner = THIS_MODULE,
	.class_groups = fd_tt_class_groups
};

// Probing function for full duplex test transport
// devices wich get's called whenever a new device
// is found. It allocates the device structure needed
// in memory and sets the full duplex interface and initializes
// the full duplex test transport properties.
//
// @pdev {valid ptr} transport platform device
//
// RETURNS:
//      0: Sucessfully probed the device
//     <0: negated error code
static int fd_tt_probe(struct platform_device *pdev)
{
	struct full_duplex_device * full_duplex_dev = 
		(struct full_duplex_device *) 
			kmalloc(sizeof(struct full_duplex_device), GFP_KERNEL);

	FD_TT_CHECK_FULL_DUPLEX_DEVICE("device allocation failed",
							return -ENOMEM);

	full_duplex_dev->dev = 
		kmalloc(sizeof(struct fd_test_transport_dev), GFP_KERNEL);

	if (IS_ERR_OR_NULL(full_duplex_dev->dev)) {
		fd_tt_err("Transport test device private data allocation failed");
		kfree(full_duplex_dev);
		full_duplex_dev = NULL;
		return -ENOMEM;
	}

	/* Full duplex interface definition */
	full_duplex_dev->iface = &full_duplex_dev_iface;

	dev_set_drvdata(&pdev->dev, full_duplex_dev);

	fd_tt_info(FD_TT_LOG_INFO_DBG_LEVEL,
			"Successfully probed the Full Duplex"
			" Test Transport device with id: %d", pdev->id);
	return 0;
};

// Remove function for full duplex test transport
// devices wich get's called whenever the device will
// be destroyed. It frees the the device structure
// allocated previously in the probe function and
// clears the full duplex interface.
//
// @pdev {valid ptr} transport platform device
//
// RETURNS:
//      0: Sucessfully removed the device
//     <0: negated error code
static int fd_tt_remove(struct platform_device *pdev)
{
	FD_TT_GET_FULL_DUPLEX_DEVICE(&pdev->dev)
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("full duplex device is null"
					" when trying to remove the"
					" platform device."
					, return -ENODEV);

	if (!IS_ERR_OR_NULL(full_duplex_dev->iface)) {
		full_duplex_dev->iface = NULL;
	}

	if (!IS_ERR_OR_NULL(full_duplex_dev->dev)) {
		kfree(full_duplex_dev->dev);
		full_duplex_dev->dev = NULL;
	}

	kfree(full_duplex_dev);
	full_duplex_dev = NULL;
	
	device_remove_file(&pdev->dev, &dev_attr_transport_RW);

	fd_tt_info(FD_TT_LOG_INFO_DBG_LEVEL,
			"Successfully removed the Full Duplex"
			" Test Transport device with id: %d", pdev->id);
	return 0;
}

// The full duplex test transport driver
// compatible definition for matching the
// driver to devices available
//
// @compatible name of compatible driver
struct of_device_id fd_tt_driver_id[] = {
	{
		.compatible = "fd_test_transport",
	}
};

// The full duplex test transport driver definition
//
// @probe probe device function called when new device is found
//        that matches the compatible string
// @remove remove device function called when the device is to
//         to be destroyed
// @driver structure driver definition
// @driver::owner the module owner
// @driver::name name of driver
// @driver::of_match_table compatible driver devices
// @driver::dev_groups devices groups with all attributes
struct platform_driver fd_tt_driver = {
	.probe = fd_tt_probe,
	.remove = fd_tt_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "fd_test_transport",
		.of_match_table = fd_tt_driver_id,
		.dev_groups = fd_test_transport_dev_groups
	}
};

// Module init method to register
// the full duplex test transport driver
// and the sysfs class
//
// RETURNS:
//      0: Sucessfully loaded the module
//     <0: negated error code
static int __init fd_tt_module_init(void)
{
	ida_init(&fd_tt_dev_id);

	int ret = platform_driver_register(&fd_tt_driver);
	if (ret != 0) {
		fd_tt_err("Full duplex test transport "
				"driver register failed: %d", ret);
		return ret;
	}

	ret = class_register(&fd_tt_class);
	if (ret != 0) {
		fd_tt_err("Full duplex test transport "
				"class register failed: %d", ret);
		ida_destroy(&fd_tt_dev_id);
		platform_driver_unregister(&fd_tt_driver);
		return ret;
	}
	fd_tt_info(FD_TT_LOG_INFO_KEY_LEVEL, "Sucessfully loaded full duplex"
						"test transport module");

	return 0;
}

// Module exit method to unregister
// the full duplex test transport driver,
// the sysfs class and destroy the ida
static void __exit fd_tt_module_exit(void)
{
	class_unregister(&fd_tt_class);
	platform_driver_unregister(&fd_tt_driver);
	ida_destroy(&fd_tt_dev_id);
	fd_tt_info(FD_TT_LOG_INFO_KEY_LEVEL, "Sucessfully unloaded full duplex"
						"test transport module");
}

module_init(fd_tt_module_init);
module_exit(fd_tt_module_exit);

MODULE_DESCRIPTION("Full Duplex Test Transport module.");
MODULE_AUTHOR("Luis Jacinto <Luis.Jacinto@bosch.com>");
MODULE_LICENSE("GPL v2");
