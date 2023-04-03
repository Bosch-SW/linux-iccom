/*
 * This file defines necessary definitions for the full duplext test transport
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

// NOTE: for Full Duplex Test Transport overview, please see the fd_test_transport.c file.

#ifndef FD_TEST_TRANSPORT_HEADER

#include <linux/full_duplex_interface.h>

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
struct fd_test_transport_dev_private {
	struct full_duplex_xfer xfer;
	bool got_us_data;
	int next_xfer_id;
	bool running;
	bool finishing;
};

// This structure is needed for the Full Duplex Test Transport to hold
// the duplex iface and the xfer device so that it can communicate
// with iccom to exchange data. It describes the test transport private data
//
// @full_duplex_sym_iface {ptr valid} full duplex interface
// @p {ptr valid} Full Duplex Test Transport private data
struct fd_test_transport_dev {
	struct full_duplex_sym_iface * duplex_iface;
	struct fd_test_transport_dev_private *p;
};

#define FD_TEST_TRANSPORT_HEADER

#endif //FD_TEST_TRANSPORT_HEADER
