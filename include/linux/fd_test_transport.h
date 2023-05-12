/*
 * This file defines necessary definitions for the Full Fuplex Test Transport
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

// NOTE: for Full Duplex Test Transport overview, 
//       please see the fd_test_transport.c file.

#ifndef FD_TEST_TRANSPORT_HEADER

#include <linux/full_duplex_interface.h>

// defines the sysfs enabling value to create
// the RW files for full duplex test transport
// manipulation via user space
#define FD_TT_SYSFS_CREATE_RW_FILES 'c'
// defines the sysfs disabling value to remove
// the RW files for full duplex test transport
// manipulation via user space
#define FD_TT_SYSFS_DELETE_RW_FILES 'd'


// defines the number of hex characters needed
// to form a byte while converting between
// an hex string (multiple characters) to a bytearray.
// NOTE: Do not define it as 2U as this macro is not 
//       only used with normal variables but also it is
//       used with __stringify within a scnprintf while
//       converting byte_array to hex and therefore it
//       needs to have only the number 2 as is.
#define FD_TT_CHARS_PER_BYTE 2

#define FD_TEST_TRANSPORT_HEADER

#endif //FD_TEST_TRANSPORT_HEADER
