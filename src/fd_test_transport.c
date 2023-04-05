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
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <linux/fd_test_transport.h>

#include <linux/platform_device.h>
#include <linux/of_device.h>

/* ------------- BUILD CONFIGURATION ------------- */

#define FD_TT_LOG_PREFIX "FD Test Transport: "

/* ------------- GENERAL CONFIGURATION -------------*/

/* --------------- DATA PACKAGE CONFIGURATION ---------------*/

// to keep the compatibility with Kernel versions earlier than v5.5
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
    #define pr_warning pr_warn
#endif

#define fd_tt_err(fmt, ...)						\
	pr_err(FD_TT_LOG_PREFIX"%s: "fmt"\n", __func__			\
			, ##__VA_ARGS__)
#define fd_tt_warning(fmt, ...)						\
	pr_warning(FD_TT_LOG_PREFIX"%s: "fmt"\n", __func__		\
			, ##__VA_ARGS__)
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
			"%s: no private part of device; "msg"\n"	\
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

// Serves to allocate unique ids for an
// Full Duplex Test Transport platform device
struct ida fd_test_transport_dev_id;


/* ------------- FORWARD DECLARATIONS -------------*/

int fd_tt_data_xchange(
			void __kernel *device,
			struct __kernel full_duplex_xfer *xfer,
			bool force_size_change);
int fd_tt_default_data_update(
				void __kernel *device,
				struct full_duplex_xfer *xfer,
				bool force_size_change);
bool fd_tt_is_running(void __kernel *device);
int fd_tt_init(
		void __kernel *device,
		struct full_duplex_xfer *default_xfer);
int fd_tt_reset(
		void __kernel *device,
		struct full_duplex_xfer *default_xfer);
int fd_tt_close(void __kernel *device);

/* -------------- MAIN STRUCTURES -------------*/

const struct full_duplex_sym_iface full_duplex_dev_iface = {
	.data_xchange = &fd_tt_data_xchange,
	.default_data_update = &fd_tt_default_data_update,
	.is_running = &fd_tt_is_running,
	.init = &fd_tt_init,
	.reset = &fd_tt_reset,
	.close = &fd_tt_close
};

// This structure is needed for the Full Duplex Test Transport to hold
// all the xfer device internal/private data for the transport
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
struct fd_test_transport_dev {
	struct full_duplex_xfer xfer;
	bool got_us_data;
	int next_xfer_id;
	bool running;
	bool finishing;
};

/*------------- FULL DUPLEX INTERFACE AUXILIAR -------------*/

// Check whether the transport device has link dependencies
//
// @fd_test_transport {valid ptr} transport device to be checked
//
// RETURNS:
//      0: No device link dependent
//   != 0: There is a device link dependent
ssize_t fd_tt_check_link_dependency(struct device *fd_test_transport)
{
	FD_TT_CHECK_PTR(fd_test_transport, return -EFAULT)

	if (list_empty(&fd_test_transport->links.suppliers)) {
		fd_tt_err("There is an dependent device for this transport device.");
		return -EINVAL;
	}
	return 0;
}

// Trim a sysfs input buffer coming from userspace
// with might have unwanted characters
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


// Initializes the xfer data to the default empty state
//
// @xfer {valid ptr} transfer structure
void fd_tt_xfer_init(struct full_duplex_xfer *xfer)
{
	memset(xfer, 0, sizeof(struct full_duplex_xfer));
}

// Frees all owned by @xfer data
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

// Write the data received from user space into the xfer
// rx_data_buf and allocates the necessary space for it
//
// @xfer_device {valid ptr} xfer device
// @data_transport_to_iccom {array} data from userspace to be copied
// @data_transport_to_iccom_size {number} size of data to be copied
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
	xfer_device->got_us_data = true;

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
//      0: ok
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
// iccom and transport with validation of data
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

	// for a new xfer US must provide a new data, so dropping the flag
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
		void __kernel *device , struct __kernel full_duplex_xfer *xfer,
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
		void __kernel *device, struct full_duplex_xfer *xfer,
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
ssize_t fd_tt_convert_hex_str_to_byte_array(
		const char *str, const size_t str_len
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
	if (str_len % CHARS_PER_BYTE != 0) {
		fd_tt_err("string"
			" must contain %d-multiple number of hex digits"
			" + 0-terminator only. String provided (in -- quotes):"
			" --%s--"
			, CHARS_PER_BYTE, str);
		return -EINVAL;
	}
	if (out_size < str_len / CHARS_PER_BYTE) {
		fd_tt_err("receiver array"
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
			fd_tt_err("failed at part: %s", tmp);
			return val;
		}
		if (val > 0xFF) {
			fd_tt_err("failed, part overflow: %s", tmp);
			return val;
		}
		*(bytearray__out + w_idx++) = (uint8_t)val;
	}

	#undef CHARS_PER_BYTE

	return w_idx;
}

// Encode the iccom data sent to transport by
// converting each number (one byte) into two bytes (in char format XX)
// and write the data in a new output table
//
// @buf__out {valid ptr} buffer to copy the data to
// @buffer_size {number} size of buffer data
// @data_iccom_to_transport {array} array holding the data to be copied
// @data_iccom_to_transport_size {number} size of array
ssize_t fd_tt_iccom_convert_byte_array_to_hex_str(
		char *buf__out, size_t buf_size,
		const uint8_t *data_iccom_to_transport,
		const size_t data_iccom_to_transport_size)
{
	ssize_t length = 0;

	/* Each byte shall be transformed into 2 hexadecimal characters */
	if (data_iccom_to_transport_size * 2 > buf_size) {
		fd_tt_err("Sysfs iccom to transport data is bigger than the buffer");
		return -EINVAL;
	}
	
	for (int i = 0; i < data_iccom_to_transport_size; i++)
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
	FD_TT_CHECK_PTR(dev, return -EFAULT)
	FD_TT_GET_FULL_DUPLEX_DEVICE(dev);
	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return -ENODEV);
	FD_TT_CHECK_XFER_DEVICE("", return -EFAULT);
	FD_TT_FULL_DUPLEX_DEVICE_TO_XFER_DEVICE();

	if (!xfer_device->got_us_data) {
		fd_tt_err("to read something you need to write something first =)");
		return -EPROTO;
	}

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
	

	// Do the actual xfer here
	fd_tt_trigger_data_exchange(xfer_device);

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
	FD_TT_CHECK_PTR(dev, return -EFAULT)
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
	size_t wire_data_size = count / 2;
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

	print_hex_dump(KERN_INFO, FD_TT_LOG_PREFIX"Sim RX data: ", 0, 16
			, 1, wire_data, xfer_size, true);

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
		fd_tt_err("Value received is not an unsigned int.");
		return -EINVAL;
	}
	
	struct kernfs_node* knode_R = sysfs_get_dirent(dev->kobj.sd,"R");
	struct kernfs_node* knode_W = sysfs_get_dirent(dev->kobj.sd,"W");

	if (result == FD_TT_SYSFS_CREATE_RW_FILES) {
		if (!IS_ERR_OR_NULL(knode_R) || !IS_ERR_OR_NULL(knode_W)) {
			fd_tt_err("Files already exist");
			return -EINVAL;
		}

		if (device_create_file(dev, &dev_attr_R) != 0) {
			fd_tt_err("Error creating the R file.");
			return -EINVAL;
		}

		if (device_create_file(dev, &dev_attr_W) != 0) {
			device_remove_file(dev, &dev_attr_R);
			fd_tt_err("Error creating the W file.");
			return -EINVAL;
		}
	} else if (result == FD_TT_SYSFS_REMOVE_RW_FILES) {
		if (IS_ERR_OR_NULL(knode_R) || IS_ERR_OR_NULL(knode_W)) {
			fd_tt_err("Files do not exist");
			return -EFAULT;
		}

		device_remove_file(dev,&dev_attr_R);
		device_remove_file(dev,&dev_attr_W);
	} else {
		fd_tt_err("RW Files: enable (%d) / disable %d"
					, FD_TT_SYSFS_CREATE_RW_FILES
					, FD_TT_SYSFS_REMOVE_RW_FILES);
		return -EINVAL;
	}

	return count;
}

static DEVICE_ATTR_WO(showRW_ctl);

// List of all Transport device attributes
//
// @dev_attr_showRW_ctl the Transport file to create
//                      or delete the R and W files
static struct attribute *fd_test_transport_dev_attrs[] = {
	&dev_attr_showRW_ctl.attr,
	NULL,
};

ATTRIBUTE_GROUPS(fd_test_transport_dev);

// Sysfs file to create Full Duplex Test Transport
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
	int device_id = ida_alloc(&fd_test_transport_dev_id,GFP_KERNEL);

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
		return -EFAULT;
	}

	return count;
}

static CLASS_ATTR_WO(create_transport);

// Sysfs class method for deleting fd_test_transport instances
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

	ssize_t link_dependency = fd_tt_check_link_dependency(
						platform_device);
	if (link_dependency != 0) {
		return link_dependency;
	}

	platform_device_unregister(to_platform_device(platform_device));

	return count;
}

static CLASS_ATTR_WO(delete_transport);

// List of all Transport class attributes
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

// The Transport class definition
//
// @name class name
// @owner the module owner
// @class_groups group holding all the attributes
static struct class fd_tt_class = {
	.name = "fd_test_transport",
	.owner = THIS_MODULE,
	.class_groups = fd_tt_class_groups
};

// Registers the Transport class for sysfs
//
// RETURNS:
//      0: ok
//      !0: nok
int fd_tt_sysfs_transport_class_register(void)
{
	return class_register(&fd_tt_class);
};

// Unregisters the ICCom class for sysfs
void fd_tt_sysfs_transport_class_unregister(void)
{
	class_unregister(&fd_tt_class);
};

// Transport device probe which initializes the device
// and allocates the full_duplex_device
//
// @pdev {valid ptr} transport device
//
// RETURNS:
//      0: ok
//     <0: errors
static int fd_tt_probe(struct platform_device *pdev)
{
	struct full_duplex_device *full_duplex_dev;

	if (IS_ERR_OR_NULL(pdev)) {
		fd_tt_err("Transport test device pdev is null.");
		return -EFAULT;
	}

	full_duplex_dev = (struct full_duplex_device *) 
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

	return 0;

no_memory_full_duplex:
	fd_tt_err("Transport test device full duplex allocation failed");
	kfree(full_duplex_dev->dev);
	kfree(full_duplex_dev);
	full_duplex_dev->dev  = NULL;
	full_duplex_dev = NULL;
	return -ENOMEM;
};

// Transport device remove which deinitialize the device
// and frees the full_duplex_device
//
// @pdev {valid ptr} transport device
//
// RETURNS:
//      0: ok
//     <0: errors
static int fd_tt_remove(struct platform_device *pdev)
{

	if (IS_ERR_OR_NULL(pdev)) {
		fd_tt_err("Transport test device pdev is null.");
		return -EFAULT;
	}

	fd_tt_warning("Removing a Full Duplex Test Transport "
				"device with id: %d", pdev->id);

	struct full_duplex_device *full_duplex_dev = 
			(struct full_duplex_device *) dev_get_drvdata(&pdev->dev);

	FD_TT_CHECK_FULL_DUPLEX_DEVICE("", return -ENODEV);

	if (!IS_ERR_OR_NULL(full_duplex_dev->iface)) {
		full_duplex_dev->iface = NULL;
	}

	if (!IS_ERR_OR_NULL(full_duplex_dev->dev)) {
		kfree(full_duplex_dev->dev);
		full_duplex_dev->dev = NULL;
	}

	kfree(full_duplex_dev);
	full_duplex_dev = NULL;

	return 0;
}

// The Transport driver compatible definition
//
// @compatible name of compatible driver
struct of_device_id fd_tt_driver_id[] = {
	{
		.compatible = "fd_test_transport",
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
// the ICCom and transport drivers
// as well as to initialize the id
// generators and the crc32 table
//
// RETURNS:
//      0: ok
//     !0: nok
static int __init fd_tt_module_init(void)
{
	int ret;

	ida_init(&fd_test_transport_dev_id);

	ret = platform_driver_register(&fd_tt_driver);
	fd_tt_warning("Transport Driver Register result: %d", ret);
	fd_tt_sysfs_transport_class_register();
	fd_tt_warning("module loaded");
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
static void __exit fd_tt_module_exit(void)
{
	ida_destroy(&fd_test_transport_dev_id);

	fd_tt_sysfs_transport_class_unregister();

	platform_driver_unregister(&fd_tt_driver);

	fd_tt_warning("module unloaded");
}

module_init(fd_tt_module_init);
module_exit(fd_tt_module_exit);

MODULE_DESCRIPTION("Full Duplex Test Transport module.");
MODULE_AUTHOR("Luis Jacinto <Luis.Jacinto@bosch.com>");
MODULE_LICENSE("GPL v2");
