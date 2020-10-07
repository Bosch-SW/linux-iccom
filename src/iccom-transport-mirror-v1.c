/*
 * This file defines the instance of full duplex symmetrical mirror transport
 * driver, which is useful for symmetrical full duplex transport based drivers
 * (like ICCom) testing.
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

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <stddef.h>

#include "../full_duplex_mirror/full_duplex_interface.h"
#include "../full_duplex_mirror/full_duplex_mirror.h"

// DEV STACK
// @@@@@@@@@@@@@
//
// BACKLOG:
//

/* --------------------- BUILD CONFIGURATION ----------------------------*/

// define this for debug mode
//#define TRANSP_MIRROR_DEBUG

#define TRANSP_MIRROR_LOG_PREFIX "FD transport mirror: "

/* --------------------- UTILITIES SECTION ----------------------------- */

#define mirror_v1_iccom_err(fmt, ...)                                    \
        pr_err(TRANSP_MIRROR_LOG_PREFIX"%s: "fmt"\n", __func__           \
               , ##__VA_ARGS__)
#define mirror_v1_iccom__warning(fmt, ...)                               \
        pr_warning(TRANSP_MIRROR_LOG_PREFIX"%s: "fmt"\n", __func__       \
               , ##__VA_ARGS__)
#define mirror_v1_iccom_info(fmt, ...)                                   \
        pr_info(TRANSP_MIRROR_LOG_PREFIX"%s: "fmt"\n", __func__          \
                , ##__VA_ARGS__)
#ifdef TRANSP_MIRROR_DEBUG
#define mirror_v1_iccom_dbg(fmt, ...)                                    \
        pr_info(TRANSP_MIRROR_LOG_PREFIX"%s: "fmt"\n", __func__          \
                , ##__VA_ARGS__)
#else
#define mirror_v1_iccom_dbg(fmt, ...)
#endif

/* -------------------------- STRUCTS -----------------------------------*/

// @mirror the full duplex transport mirror device
struct iccom_mirror_transport_dev {
        struct mirror_xfer_device mirror;
};

// Prepares transport protocol layer which will reflect back
// all data we want to send out.
//
// RETURNS:
static full_duplex_device mirror_v1_protocol_init_transport_layer()
{
        return struct full_duplex_device { (void*)&iccom_sk->mirror
                    , full_duplex_mirror_iface() };
}

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

static int __init mirror_v1_protocol_module_init(void)
{
        mirror_v1_iccom_info("module loaded");
        return 0;
}

static void __exit mirror_v1_protocol_module_exit(void)
{
        mirror_v1_iccom_info("module unloaded");
}

module_init(mirror_v1_protocol_module_init);
module_exit(mirror_v1_protocol_module_exit);

MODULE_DESCRIPTION("The mirror protocol communication driver"
                   " module (transport layer always mirrors back"
                   " everything it gets to send).");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");
