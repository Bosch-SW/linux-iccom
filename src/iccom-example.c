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

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/proc_fs.h>
#include <stddef.h>

#include "../symspi/symspi.h"
#include "./iccom.h"

// DEV STACK
// @@@@@@@@@@@@@
//
// BACKLOG:
//

/* --------------------- BUILD CONFIGURATION ----------------------------*/

#define ICCOM_EXAMPLE_LOG_PREFIX "ICCom SymSPI example: "

#define ICCOM_EXAMPLE_SYMSPI_CONFIG_BITS_PER_WORD 8
#define ICCOM_EXAMPLE_SYMSPI_CONFIG_MODE (SPI_CPOL | SPI_CPHA)

/* --------------------- UTILITIES SECTION ----------------------------- */

#define iccom_example_err(fmt, ...)                               \
        pr_err(ICCOM_EXAMPLE_LOG_PREFIX"%s: "fmt"\n", __func__    \
               , ##__VA_ARGS__)
#define iccom_example_warning(fmt, ...)                           \
        pr_warning(ICCOM_EXAMPLE_LOG_PREFIX"%s: "fmt"\n", __func__\
               , ##__VA_ARGS__)
#define iccom_example_info(fmt, ...)                              \
        pr_info(ICCOM_EXAMPLE_LOG_PREFIX"%s: "fmt"\n", __func__   \
                , ##__VA_ARGS__)

#define fitsin(TYPE, FIELD, SIZE)                                 \
        (offsetof(TYPE, FIELD) + sizeof(((TYPE*)(NULL))->FIELD) <= (SIZE))

/* -------------------------- STRUCTS -----------------------------------*/

// Defines the sample SPI transfer configuration according to the contract
// with the other side (it is used at SymSPI layer, and sets the SPI
// transport configuration details which are specific for given
// communication).
//
// CONTEXT: can not sleep
static void iccom_example_protocol_native_transfer_configuration_hook(
                const struct full_duplex_xfer *const xfer
                , void *const native_transfer
                , const size_t native_transfer_struct_size)
{
        struct spi_transfer *dst = (struct spi_transfer *)native_transfer;

        if (!fitsin(struct spi_transfer, bits_per_word
                    , native_transfer_struct_size)) {
                return;
        }

        const int SPI_FULL_WORD_SIZE_BITS = 32;

        // the whole transfer is done at one burst
        // (with single CS assertion) along the communicatiion
        // contract
        dst->burst_size_bits = xfer->size_bytes * 8;
        if (xfer->size_bytes * 8 >= SPI_FULL_WORD_SIZE_BITS) {
                dst->bits_per_word = SPI_FULL_WORD_SIZE_BITS;
        } else {
                dst->bits_per_word = xfer->size_bytes * 8;
        }
}

// Prepares transport protocol layer according to the
// example communication protocol.
//
// RETURNS:
struct full_duplex_device iccom_example_protocol_init_transport_layer(void)
{
        struct full_duplex_device ret_dev;
        // TODO:
        // TODO:  REALLY, TODO
        // TODO:
        // TODO: use DTS table to get the correct device and
        //      don't use global one
        struct symspi_dev *symspi = symspi_get_global_device();
        if (IS_ERR_OR_NULL(symspi)) {
                iccom_example_err("no SymSPI device found");

                ret_dev.dev = ERR_PTR(-ENODEV);
                ret_dev.iface = NULL;
                return ret_dev;
        }

        symspi->spi->bits_per_word = ICCOM_EXAMPLE_SYMSPI_CONFIG_BITS_PER_WORD;
        symspi->spi->mode |= ICCOM_EXAMPLE_SYMSPI_CONFIG_MODE;
        symspi->spi->master->setup(symspi->spi);
        symspi->native_transfer_configuration_hook
                = &iccom_example_protocol_native_transfer_configuration_hook;

        ret_dev.dev = (void*)symspi;
        ret_dev.iface = symspi_iface();
        return ret_dev;
}
// TODO: remove export as dependency is removed from ICCom layer
EXPORT_SYMBOL(iccom_example_protocol_init_transport_layer);

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

static int __init iccom_example_protocol_module_init(void)
{
        iccom_example_info("module loaded");
        return 0;
}

static void __exit iccom_example_protocol_module_exit(void)
{
        iccom_example_info("module unloaded");
}

module_init(iccom_example_protocol_module_init);
module_exit(iccom_example_protocol_module_exit);

MODULE_DESCRIPTION("The ICCom + SymSPI example communication driver"
                   " module.");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");
