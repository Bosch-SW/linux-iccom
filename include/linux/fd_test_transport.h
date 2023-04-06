/*
 * This file defines necessary definitions for the full
 * duplex test transport
 *
 * Copyright (c) 2023 Robert Bosch GmbH
 * Luis Jacinto <Luis.Jacinto@bosch.com>
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

// NOTE: for Full Duplex Test Transport overview, 
//       please see the fd_test_transport.c file.

#ifndef FD_TEST_TRANSPORT_HEADER

#include <linux/full_duplex_interface.h>

// defines the sysfs enabling value to create the
// RW files for iccom transport test manipulation
// via user space
#define FD_TT_SYSFS_CREATE_RW_FILES 1U
// defines the sysfs disabling value to remove the
// RW files for iccom transport test manipulation
// via user space
#define FD_TT_SYSFS_REMOVE_RW_FILES 0U

#define FD_TEST_TRANSPORT_HEADER

#endif //FD_TEST_TRANSPORT_HEADER
