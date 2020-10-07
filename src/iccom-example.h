/*
 * This file defines the Inter Chip/CPU communication protocol (ICCom)
 * driver instance with example SymSPI-based configuration.
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

// NOTE: this file is temporary needed for migration to the
//      ultimate protocol drivers architecture.

#include "../full_duplex_interface/full_duplex_interface.h"

struct full_duplex_device iccom_example_protocol_init_transport_layer(void);
