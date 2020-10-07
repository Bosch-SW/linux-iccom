/*
 * This file defines the Inter Chip/CPU communication protocol (ICCom)
 * driver testing module.
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

// DEV STACK:
//
//      SYMSPI binded test, only if BOSCH_SYMSPI_CONFIG is set
//
// BACKLOG:
//      * adjust code style according to the Linux kernel code style
//
//      static, const
//
//      use
//      #define ICCOM_TEST_ENABLE_SYMSPI_BINDED_TEST
//      to enable/disable the symspi-related testes
//
//      FREE MESSAGE DATA RECEIVED
//
//      iccom_test_poll_and_verify_msg  fails regulary
//          used in iccom_test_test_mirror_poll_send_verify_helper
//          used in iccom_test_test_mirror_batch_poll_helper
//              used in iccom_test_test_mirror_batch_send_then_poll_helper
//
//
//      As protocol improved remove restriction on mirror to not to break
//      xfers of size 1.
//
//      iccom_test_test_mirror_poll_5
//          uses __iccom_test_mirror_batch_send_poll_helper
//      and iccom_test_test_mirror_accum_poll_1
//          uses iccom_test_test_mirror_batch_send_then_poll_helper
//      comparison
//
//      888 insert scenario printout
//
//      CALLBACK SHOULD DESTROY MESSAGE DATA FINALLY
//
//      TEST WITH CALLBACK ON CHANNEL
//              writing iccom_test_mirror_multithreading_send_callback_worker
//                  writing __iccom_test_message_ready_callback_default
//                      writing __iccom_test_mirror_batch_post_callback_helper
//                          writing __iccom_test_test_mirror_batch_install_callbacks_helper
//
//
//      ADD SCENARIO PRINTOUT ON EVERY FAILURE
//
//      FUNCTION NAMING FIX!!!
//
//      TEST WITH SEVERAL CALLBACKs ON CHANNELs
//
//      BROKEN MIRROR TESTS (with non zero probablity of
//          xfer data broken)
//
//      spi_finalize_current_message
//      PC is at spi_finalize_current_message+0x94/0x238
//
// DEV STACK END

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/random.h>

#include "iccom.h"
#include "../full_duplex_interface/full_duplex_interface.h"
#include "../full_duplex_mirror/full_duplex_mirror.h"

#include "../symspi/symspi.h"
#include <linux/spi/spi.h>

/*------------------- BUILD CONFIGURATION --------------------------*/

// define this macro if you want to run tests also with
// SymSPI driver (might be useful to verify real communication
// between parties)
#define ICCOM_TEST_SYMSPI

#ifdef ICCOM_TEST_SYMSPI
#define ICCOM_TEST_SYMSPI_CONFIG_BITS_PER_WORD 8
#define ICCOM_TEST_SYMSPI_CONFIG_MODE (SPI_CPOL | SPI_CPHA)
#endif

/*------------------- FORWARD DECLARATIONS -------------------------*/

/*-------------------- TESTS UTILS SECTION -------------------------*/

#define ICCOM_TEST_LOG_PREFIX "ICCOM_TEST: "

#define ICCOM_TEST_LOG_TEST_PREFIX(test_number)                     \
        ICCOM_TEST_LOG_PREFIX"test "#test_number": "

#define iccom_test_err(fmt, ...)                                    \
        pr_err(ICCOM_TEST_LOG_PREFIX"%s: at %d line: "fmt"\n"       \
               , __func__, __LINE__, ##__VA_ARGS__)
#define iccom_test_warn(fmt, ...)                                   \
        pr_warn(ICCOM_TEST_LOG_PREFIX"%s: at %d line: "fmt"\n"      \
                , __func__, __LINE__, ##__VA_ARGS__)
#define iccom_test_info(fmt, ...)                                   \
        pr_info(ICCOM_TEST_LOG_PREFIX"%s: at %d line: "fmt"\n"      \
                , __func__, __LINE__, ##__VA_ARGS__)

#define iccom_test_err_raw(fmt, ...)                                \
        pr_err(ICCOM_TEST_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_test_warn_raw(fmt, ...)                               \
        pr_warn(ICCOM_TEST_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)
#define iccom_test_info_raw(fmt, ...)                               \
        pr_info(ICCOM_TEST_LOG_PREFIX""fmt"\n", ##__VA_ARGS__)

#define ICCOM_TEST_CHECK_DEVICE(device, error_action)               \
        if (IS_ERR_OR_NULL(device)) {                               \
                iccom_test_err("%s: no device;\n", __func__);       \
                error_action;                                       \
        }
#define ICCOM_TEST_CHECK_PTR(ptr, error_action)                     \
        if (IS_ERR_OR_NULL(ptr)) {                                  \
                iccom_test_err("%s: "#ptr"(%px): ptr error\n"       \
                               , __func__, ptr);                    \
                error_action;                                       \
        }

#define ICCOM_TEST_DEV_TO_MIRROR                                    \
        struct mirror_xfer_device *mirror                           \
                    = (struct mirror_xfer_device*)device;

#define ICCOM_TEST_MIRROR_ON_FINISH(error_action)                   \
        if (mirror->finishing) {                                    \
                error_action;                                       \
        }


void iccom_test_print_expected_vs_received(size_t exp_size,
                char *exp_data, size_t real_size, char *real_data)
{
        printk(ICCOM_TEST_LOG_PREFIX"Expected data:\n");
        print_hex_dump(KERN_DEBUG, ICCOM_TEST_LOG_PREFIX"Expected data: "
                       , 0, 16, 1, exp_data, exp_size, true);
        printk(ICCOM_TEST_LOG_PREFIX"Received data:\n");
        print_hex_dump(KERN_DEBUG, ICCOM_TEST_LOG_PREFIX"Received data: "
                       , 0, 16, 1, real_data, real_size, true);
}

// TODO: extract to independent source
// TODO: fix print to contain log prefix
void iccom_test_printout_xfer(const struct full_duplex_xfer *xfer)
{
        if (IS_ERR(xfer)) {
            printk("xfer ptr BROKEN: %px\n", xfer);
            return;
        } else if (!xfer) {
            printk("xfer ptr NULL\n");
            return;
        }
        printk("Xfer ptr: %px\n", xfer);
        printk("Xfer size: %u\n", xfer->size_bytes);
        if (IS_ERR(xfer->data_tx)) {
                printk("Xfer TX data ptr: BROKEN: %px\n", xfer->data_tx);
        } else if (xfer->data_tx) {
                printk("Xfer TX data ptr: %px\n", xfer->data_tx);
                print_hex_dump(KERN_DEBUG, "TX data: ", 0, 16
                            , 1, xfer->data_tx, xfer->size_bytes, true);
        } else {
                printk("Xfer TX data ptr: NULL\n");
        }
        if (IS_ERR(xfer->data_rx_buf)) {
                printk("Xfer RX data ptr: BROKEN: %px\n", xfer->data_rx_buf);
        } else if (xfer->data_rx_buf) {
                printk("Xfer RX data ptr: %px\n", xfer->data_rx_buf);
                print_hex_dump(KERN_DEBUG, "RX data: ", 0, 16
                            , 1, xfer->data_rx_buf, xfer->size_bytes
                            , true);
        } else {
                printk("Xfer RX data ptr: NULL\n");
        }
}

/*----------------------------- MAIN -------------------------------*/

/*-------------------- TESTS DATA SECTION --------------------------*/

char iccom_test_data_default[] = {
        0x00
};

struct full_duplex_xfer iccom_test_default_xfer = {
        .size_bytes = sizeof(iccom_test_data_default)
        , .data_tx = &iccom_test_data_default
        , .data_rx_buf = NULL
        , .consumer_data = NULL
        , .done_callback = NULL
};

uint8_t iccom_test_data_1[] = {
        0x23, 0x45, 0x32, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x34, 0xFF, 0x53, 0x32,
};

uint8_t iccom_test_data_2[] = {
        0x32, 0x54
};

uint8_t iccom_test_data_3[] = {
        0x77
};

uint8_t iccom_test_data_4[] = {
        0x11, 0x3d, 0x23, 0xFA, 0xFB, 0xFD, 0x22, 0xE2,
        0x67, 0x6F, 0xD3, 0xF7, 0x3D, 0xFF, 0x33, 0x32,
        0xDF, 0xAF, 0xFA, 0xFA, 0x34, 0x3F, 0x73, 0x63,
        0x37, 0xDF, 0xF3, 0xFF, 0x6A, 0xFF, 0x53, 0x32,
        0xFA, 0x3F, 0x6F, 0x7F, 0x34
};

#define ICCOM_TEST_SCENARIO_ITEMS_VAR(number)                           \
        iccom_test_scenario_##number##_items
#define ICCOM_TEST_SCENARIO_VAR(number)                                 \
        iccom_test_scenario_##number

#define ICCOM_TEST_SCENARIO_ITEM(data, channel, priority, done_count)   \
        { &data, sizeof(data), channel, priority, done_count }
#define ICCOM_TEST_SCENARIO(number)                                     \
        struct iccom_test_scenario ICCOM_TEST_SCENARIO_VAR(number) = {  \
                .items = (struct iccom_test_scenario_item *)            \
                                &ICCOM_TEST_SCENARIO_ITEMS_VAR(number)  \
                , .items_count = ARRAY_SIZE(                            \
                            ICCOM_TEST_SCENARIO_ITEMS_VAR(number))      \
                , .execution_routine = NULL                             \
        }

#define ICCOM_TEST_MULTITHREADING_SCENARIO_ITEMS_VAR(number)            \
        iccom_test_multithread_scenario_##number##_items
#define ICCOM_TEST_MULTITHREADING_SCENARIO_VAR(number)                  \
        iccom_test_multithread_scenario_##number

#define ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(scenario_number)        \
        &ICCOM_TEST_SCENARIO_VAR(scenario_number)
#define ICCOM_TEST_MULTITHREADING_SCENARIO(number)                      \
        struct iccom_test_concurrent_scenario                           \
                     ICCOM_TEST_MULTITHREADING_SCENARIO_VAR(number) = { \
                .thread_scenarios = (struct iccom_test_scenario **)     \
                   &ICCOM_TEST_MULTITHREADING_SCENARIO_ITEMS_VAR(number)\
                , .threads_count = ARRAY_SIZE(                          \
                   ICCOM_TEST_MULTITHREADING_SCENARIO_ITEMS_VAR(number))\
        }

// Single scenario item
struct iccom_test_scenario_item {
        void *data;
        size_t data_size_bytes;
        int dst_channel;
        int priority;
        int done_count;
};

// Single threaded scenario item
struct iccom_test_scenario {
        struct iccom_test_scenario_item *items;
        size_t items_count;
        int (*execution_routine)(void *data);
};

// Multithreading scenario
struct iccom_test_concurrent_scenario {
        struct iccom_test_scenario **thread_scenarios;
        size_t threads_count;
};

// Data provided to the thread (created by thread caller,
// destroyed by thread caller)
struct iccom_test_thread_data {
        struct iccom_test_scenario *scenario;
        int iterations;
        struct iccom_dev *iccom;
        void *custom_ptr1;
        bool result;
        struct completion completion;
        int timeout_jiffies;
};

/*----------------- TESTS SCENARIOS SECTION ------------------------*/

//Single thread scenarios
struct iccom_test_scenario_item iccom_test_scenario_1_items[] = {
        ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 1, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 2, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 1, 0, 0)
};
struct iccom_test_scenario_item iccom_test_scenario_2_items[] = {
        ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 3, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4, 0, 0)
};
struct iccom_test_scenario_item iccom_test_scenario_3_items[] = {
        ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 7, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 400, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4525, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 7, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 400, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 4525, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 7, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 400, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 4525, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 12, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 4525, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 4525, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 12, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4525, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 7, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 7, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 7, 0, 0)
};
struct iccom_test_scenario_item iccom_test_scenario_4_items[] = {
        ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 145, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 424, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 863, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 5165, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 4825, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 25000, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 145, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 424, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 863, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 5165, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 4825, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 25000, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 145, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 424, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 863, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 5165, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 4825, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 25000, 0, 0)
};

struct iccom_test_scenario_item iccom_test_scenario_5_items[] = {
        ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 146, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 425, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 864, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 5166, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4826, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 25001, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 146, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 425, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 864, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 5166, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4826, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 25001, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 146, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 425, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 864, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 5166, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 4826, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 25001, 0, 0)
};

struct iccom_test_scenario_item iccom_test_scenario_6_items[] = {
        ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 143, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 422, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 861, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 5163, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4823, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 24998, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 143, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 422, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 861, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 5163, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4823, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 24998, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 143, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 422, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 861, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 5163, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 4823, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 24998, 0, 0)
};

struct iccom_test_scenario_item iccom_test_scenario_7_items[] = {
        ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 420, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4821, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 5161, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 141, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 5161, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 420, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 5161, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 4821, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 859, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 4821, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 141, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_2, 24996, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 141, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 859, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 420, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_4, 24996, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_1, 24996, 0, 0)
        , ICCOM_TEST_SCENARIO_ITEM(iccom_test_data_3, 859, 0, 0)
};

ICCOM_TEST_SCENARIO(1);
ICCOM_TEST_SCENARIO(2);
ICCOM_TEST_SCENARIO(3);
ICCOM_TEST_SCENARIO(4);
ICCOM_TEST_SCENARIO(5);
ICCOM_TEST_SCENARIO(6);
ICCOM_TEST_SCENARIO(7);

//Multithreading scenarios
struct iccom_test_scenario *iccom_test_multithread_scenario_1_items[] = {
        ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(1)
        , ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(2)
};
struct iccom_test_scenario *iccom_test_multithread_scenario_2_items[] = {
        ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(1)
        , ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(2)
        , ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(3)
        , ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(4)
        , ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(5)
        , ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(6)
        , ICCOM_TEST_MULTITHREADING_SCENARIO_ITEM(7)
};

ICCOM_TEST_MULTITHREADING_SCENARIO(1);
ICCOM_TEST_MULTITHREADING_SCENARIO(2);

/*----------------- TESTS UTILS SECTION ----------------------------*/

void __iccom_test_printout_scenario_item(struct iccom_test_scenario_item *item)
{
        printk(ICCOM_TEST_LOG_PREFIX"------ scenario item ------\n");
        printk(ICCOM_TEST_LOG_PREFIX"channel: %d\n", item->dst_channel);
        printk(ICCOM_TEST_LOG_PREFIX"priority: %d\n", item->priority);
        printk(ICCOM_TEST_LOG_PREFIX"done count: %d\n", item->done_count);
        printk(ICCOM_TEST_LOG_PREFIX"data size: %d\n", item->data_size_bytes);
        print_hex_dump(KERN_DEBUG, ICCOM_TEST_LOG_PREFIX"data: "
                       , 0, 16, 1, item->data, item->data_size_bytes, true);
}

static void __iccom_test_printout_scenario(
                struct iccom_test_scenario *scenario)
{
        printk(ICCOM_TEST_LOG_PREFIX"====== scenario ======\n");
        for (int i = 0; i < scenario->items_count; i++) {
                __iccom_test_printout_scenario_item(&scenario->items[i]);
        }
        printk(ICCOM_TEST_LOG_PREFIX"==== scenario end ===\n");
}

// Destructs mirror and iccom devices
static void __iccom_test_destroy_binded_iccom(
                const struct full_duplex_sym_iface *const full_duplex_if
                , struct iccom_dev *iccom)
{
        iccom_print_statistics(iccom);
        iccom_close(iccom);
        iccom_test_info_raw("closing transport device");
        full_duplex_if->close(iccom->xfer_device);
}

// Sets selected SPI parameters
static void __iccom_test_configure_symspi(struct symspi_dev *symspi)
{
        // adjusting SPI mode
        symspi->spi->bits_per_word = ICCOM_TEST_SYMSPI_CONFIG_BITS_PER_WORD;
        symspi->spi->mode |= ICCOM_TEST_SYMSPI_CONFIG_MODE;
        symspi->spi->master->setup(symspi->spi);
}


#ifdef ICCOM_TEST_SYMSPI
// RETURNS:
//      0: on success
//      <0: on error
static int __iccom_test_init_symspi_binded_iccom(
                struct iccom_dev *iccom)
{
        struct symspi_dev *symspi = symspi_get_global_device();

        __iccom_test_configure_symspi(symspi);

        if (IS_ERR_OR_NULL(symspi)) {
                iccom_test_err("The symspi global device request"
                               " returned the error code: %ld"
                               , PTR_ERR(symspi));
                return -1;
        }
        if (IS_ERR_OR_NULL(iccom)) {
                iccom_test_err("The ICCom dev ptr is broken: %px"
                               , iccom);
                return -1;
        }

        iccom_test_info("using symspi device: %px", symspi);

        if (iccom_init_binded(iccom, symspi_iface(), (void*)symspi) < 0) {
                return -1;
        }

        return 0;
}
#endif /* ICCOM_TEST_SYMSPI */


// Just polls and verifies the message from the channel
// with timeout
static bool iccom_test_poll_and_verify_msg(
                struct iccom_dev *iccom
                , uint8_t *data
                , size_t data_size_bytes
                , const int channel
                , int timeout_jiffies)
{
        // active wait
        size_t expect_size = data_size_bytes;
        unsigned long start_js = jiffies;

        void *rx_buf = NULL;
        size_t bytes_read = 0;
        unsigned int msg_id = 0;
        while (true) {
                if (jiffies - start_js > timeout_jiffies) {
                        iccom_test_err("read msg timeout");
                        return false;
                }

                int res = iccom_read_message(iccom, channel, &rx_buf
                                             , &bytes_read, &msg_id);
                if (res < 0) {
                        iccom_test_err("iccom_read_message failed:"
                                       " ret val: %d", res);
                        return false;
                }
                if (rx_buf != NULL) {
                       break;
                }
        }

        bool res = true;
        // verification
        if (bytes_read != expect_size) {
                iccom_test_err("Message verification failed:"
                               " wrong message size: %d"
                               ", while expected: %d, on channel: %d"
                               ", chanel message id: %u"
                               , bytes_read, expect_size, channel
                               , msg_id);
                iccom_test_print_expected_vs_received(expect_size,
                                data, bytes_read, rx_buf);
                res = false;
                goto done;
        }
        if (strncmp(rx_buf, data, expect_size) != 0) {
                iccom_test_err("received data != expected data");
                iccom_test_print_expected_vs_received(expect_size,
                                data, bytes_read, rx_buf);
                res = false;
                goto done;
        }

done:
        kfree(rx_buf);
        return res;
}

// Sends given data message using given device to
// given channel and with given priority. Then
// verifies that the data received with given channel
// is exactly the same.
bool iccom_test_test_mirror_poll_send_verify_helper(
                struct iccom_dev *iccom
                , uint8_t *data
                , size_t data_size_bytes
                , const int channel
                , const int priority
                , int timeout_jiffies)
{
        int res = iccom_post_message(iccom
                        , data, data_size_bytes
                        , channel, priority);
        if (res < 0) {
                iccom_test_err("iccom_post_message failed: err: %d", res);
                return false;
        }

        return iccom_test_poll_and_verify_msg(
                        iccom, data, data_size_bytes, channel
                        , timeout_jiffies);
}

// Sends all given data messages to the given channels. Doesn't
// read the messages, only sends. Messages are expected to be
// accumulated in messages storage.
bool iccom_test_test_mirror_batch_send_helper(
                struct iccom_dev *iccom
                , struct iccom_test_scenario *scenario
                , int iterations)
{
        int res = 0;
        for (int i = 0; i < iterations * scenario->items_count; i++) {
                int idx = i % scenario->items_count;
                res = iccom_post_message(iccom
                                , scenario->items[idx].data
                                , scenario->items[idx].data_size_bytes
                                , scenario->items[idx].dst_channel
                                , scenario->items[idx].priority);
                if (res < 0) {
                        iccom_test_err("iccom_post_message "
                                       "failed: err: %d", res);
                        print_hex_dump(KERN_DEBUG, ICCOM_TEST_LOG_PREFIX
                                       "Failed test message data: "
                                       , 0, 16, 1, scenario->items[idx].data
                                       , scenario->items[idx].data_size_bytes
                                       , true);
                        return false;
                }
        }

        return true;
}

// installs given callback to all channels mentioned in scenario
bool __iccom_test_test_mirror_batch_install_callbacks_helper(
                struct iccom_dev *iccom
                , struct iccom_test_scenario *scenario
                , bool (*msg_ready_callback)(
                        unsigned int channel
                        , void *msg_data, size_t msg_len
                        , void *consumer_data)
                , void *consumer_data)
{
        // intentionally not optimized: to test routines
        for (int i = 0; i < scenario->items_count; i++) {
                void *curr_callb = iccom_get_channel_callback(iccom
                                        , scenario->items[i].dst_channel);
                if (IS_ERR(curr_callb)) {
                        iccom_test_err("iccom_get_channel_callback returned"
                                       " error code: %ld", PTR_ERR(curr_callb));
                        return false;
                }
                if (curr_callb == NULL) {
                        int res = iccom_set_channel_callback(iccom
                                            , scenario->items[i].dst_channel
                                            , msg_ready_callback
                                            , consumer_data);
                        if (res != 0) {
                            iccom_test_err("iccom_set_channel_callback returned"
                                               " error code: %d", res);
                                return false;
                        }
                }
        }
        return true;
}

// returns the index of previous record of the channel undef
// current index (wraps around)
int iccom_test_previous_ch_record_idx(
                struct iccom_test_scenario *scenario
                , int curr_idx)
{
        int channel = scenario->items[curr_idx].dst_channel;
        for (int i = curr_idx - 1; i >= 0; i--) {
                if (scenario->items[i].dst_channel == channel) {
                        return i;
                }
        }
        for (int i = scenario->items_count - 1; i >= 0; i--) {
                if (scenario->items[i].dst_channel == channel) {
                        return i;
                }
        }
        return -1;
}

// Receives (polls) messages from given channels and verifies
// them with the given list.
bool iccom_test_test_mirror_batch_poll_helper(
                struct iccom_dev *iccom
                , struct iccom_test_scenario *scenario
                , int iterations
                , int timeout_jiffies)
{
        bool res;
        for (int i = 0; i < iterations * scenario->items_count; i++) {
                int idx = i % scenario->items_count;

                res = iccom_test_poll_and_verify_msg(
                                iccom
                                , scenario->items[idx].data
                                , scenario->items[idx].data_size_bytes
                                , scenario->items[idx].dst_channel
                                , timeout_jiffies);
                if (!res) {
                        iccom_test_err("was using P&V: i = %d; idx = %d"
                                       , i, idx);
                        return false;
                }

                int prev_idx = iccom_test_previous_ch_record_idx(scenario, idx);
                if (prev_idx >= 0) {
                        scenario->items[idx].done_count
                                    = scenario->items[prev_idx].done_count + 1;
                }
        }

        return true;
}

bool iccom_test_test_mirror_batch_send_then_poll_helper(
                struct iccom_dev *iccom
                , struct iccom_test_scenario *scenario
                , int iterations
                , int timeout_jiffies)
{
        bool test_res = iccom_test_test_mirror_batch_send_helper(
                    iccom, scenario, iterations);
        if (!test_res) {
                iccom_test_err("Failed to make a batch send of messages.");
                return false;
        }
        test_res = iccom_test_test_mirror_batch_poll_helper(
                    iccom, scenario, iterations, timeout_jiffies);
        if (!test_res) {
                iccom_test_err("Batch messages verification failed.");
                iccom_test_err("FAILED SCENARIO BEGIN");
                __iccom_test_printout_scenario(scenario);
                iccom_test_err("FAILED SCENARIO END");
                return false;
        }
        return true;
}

// Messages for the channel should come in FIFO order
// for the same channel. Between channels order is undefined.
// No concurrent callbacks for the same channel should be called.
bool __iccom_test_message_ready_callback_default(
        unsigned int channel
        , void *msg_data, size_t msg_len
        , void *consumer_data)
{
        struct iccom_test_scenario *scenario
                    = (struct iccom_test_scenario *)consumer_data;

        int first_idx = -1;
        for (int i = 0; i < scenario->items_count; i++) {
                if (scenario->items[i].dst_channel == channel) {
                        first_idx = i;
                        break;
                }
        }
        if (first_idx == -1) {
                iccom_test_err("Callback is called with channel"
                               " which doesn't present in scenario: %u"
                               , channel);
                goto finalize;
        }

        int second_idx = -1;
        int target_idx = -1;
        int origin_idx = first_idx;
        do {
                int old_second_idx = second_idx;
                for (int i = first_idx + 1; i < scenario->items_count; i++) {
                        if (scenario->items[i].dst_channel == channel) {
                                second_idx = i;
                                break;
                        }
                }
                if (second_idx != old_second_idx) {
                        if (scenario->items[first_idx].done_count
                                   != scenario->items[second_idx].done_count) {
                                target_idx = second_idx;
                                break;
                        }
                        first_idx = second_idx;
                        continue;
                }
                target_idx = origin_idx;
                break;
        } while (true);

        struct iccom_test_scenario_item *item = &scenario->items[target_idx];
        if (item->data_size_bytes != msg_len) {
                iccom_test_err("Actual (%u) and expected (%u) message"
                               " (idx = %d) lengths do not match"
                               , msg_len, item->data_size_bytes, target_idx);
                iccom_test_print_expected_vs_received(item->data_size_bytes,
                                item->data, msg_len, msg_data);
                __iccom_test_printout_scenario(scenario);
                goto finalize;
        }
        if (strncmp(item->data, msg_data, msg_len) != 0) {
                iccom_test_err("Actual and expected message"
                               " datas do not match");
                iccom_test_print_expected_vs_received(item->data_size_bytes,
                                item->data, msg_len, msg_data);
                __iccom_test_printout_scenario(scenario);
                goto finalize;
        }

        scenario->items[target_idx].done_count++;
finalize:
        if (!IS_ERR_OR_NULL(msg_data)) {
                kfree(msg_data);
        }
        return true;
}

void __iccom_test_reset_scenario(struct iccom_test_scenario *scenario)
{
        for (int i = 0; i < scenario->items_count; i++) {
                scenario->items[i].done_count = 0;
        }
}

bool __iccom_test_mirror_batch_post_callback_helper(
                struct iccom_dev *iccom
                , struct iccom_test_scenario *scenario
                , int iterations
                , int timeout_jiffies)
{
        __iccom_test_reset_scenario(scenario);

        if (!__iccom_test_test_mirror_batch_install_callbacks_helper(
                        iccom , scenario
                        , __iccom_test_message_ready_callback_default
                        , (void*)scenario)) {
                iccom_test_err("Could not install callbacks on channels");
                return false;
        }

        if (!iccom_test_test_mirror_batch_send_helper(
                    iccom, scenario, iterations)) {
                iccom_test_err("Could not post all messages.");
                return false;
        }

        unsigned long start_js = jiffies;
        while (true) {
                if ((jiffies - start_js) > timeout_jiffies) {
                        iccom_test_err("read msg timeout");
                        return false;
                }

                bool all_done = true;
                for (int i = 0; i < scenario->items_count; i++) {
                        if (scenario->items[i].done_count != iterations) {
                                all_done = false;
                                break;
                        }
                }

                if (all_done) {
                        return true;
                }
                usleep_range(20000, 40000);
        }

        return false;
}


// Sends all messages from the list, and then receives them all
// and verifies (single thread).
bool iccom_test_test_mirror_accum_poll_st(
                struct iccom_test_scenario *scenario
                , int iterations, int timeout_jiffies)
{
        // init
        bool test_res = true;

        struct mirror_xfer_device mirror;
        struct iccom_dev iccom;

        if (iccom_init_binded(&iccom, full_duplex_mirror_iface()
                              , &mirror) < 0) {
                return false;
        }

        test_res = iccom_test_test_mirror_batch_send_then_poll_helper(
                    &iccom, scenario, iterations, timeout_jiffies);

        __iccom_test_destroy_binded_iccom(full_duplex_mirror_iface(), &iccom);
        return test_res;
}

bool iccom_test_test_mirror_poll_helper(uint8_t *data
                , size_t data_size_bytes, int channel
                , int timeout_jiffies)
{
        // init
        bool test_res = true;

        struct mirror_xfer_device mirror;
        struct iccom_dev iccom;

        if (iccom_init_binded(&iccom, full_duplex_mirror_iface()
                              , &mirror) < 0) {
                return false;
        }

        test_res = iccom_test_test_mirror_poll_send_verify_helper(
                        &iccom, data, data_size_bytes, 1, 0
                        , timeout_jiffies);
        __iccom_test_destroy_binded_iccom(full_duplex_mirror_iface(), &iccom);
        return test_res;
}

bool iccom_test_test_mirror_poll_rand_channel_helper(uint8_t *data,
                size_t data_size_bytes, int iterations
                , int timeout_jiffies)
{
        // init
        bool test_res = true;

        struct mirror_xfer_device mirror;
        struct iccom_dev iccom;

        if (iccom_init_binded(&iccom, full_duplex_mirror_iface()
                              , &mirror) < 0) {
                return false;
        }

        unsigned int channel;
        for (int i = 0; i < iterations; i++) {
                get_random_bytes(&channel, 2);
                channel %= 0x7FFF;
                test_res = iccom_test_test_mirror_poll_send_verify_helper(
                                &iccom, data, data_size_bytes, channel, 0
                                , timeout_jiffies);
                if (!test_res) {
                        break;
                }
        }
        __iccom_test_destroy_binded_iccom(full_duplex_mirror_iface(), &iccom);
        return test_res;

}

bool iccom_test_test_mirror_poll_rand_channel_data_helper(
                int iterations, const size_t max_data_size_bytes
                , int timeout_jiffies)
{
        uint8_t *data = NULL;
        size_t data_size_bytes = 0;

        // init
        bool test_res = true;

        struct mirror_xfer_device mirror;
        struct iccom_dev iccom;

        if (iccom_init_binded(&iccom, full_duplex_mirror_iface()
                              , &mirror) < 0) {
                return false;
        }

        unsigned int channel;
        for (int i = 0; i < iterations; i++) {
                get_random_bytes(&channel, 2);
                channel %= 0x7FFF;

                if (data) {
                        kfree(data);
                        data = NULL;
                }
                get_random_bytes(&data_size_bytes, sizeof(data_size_bytes));
                data_size_bytes %= (max_data_size_bytes - 1);
                data_size_bytes += 1;
                data = kmalloc(data_size_bytes, GFP_KERNEL);
                if (!data) {
                        iccom_test_info("Test data allocation failed");
                        test_res = false;
                        break;
                }

                get_random_bytes(data, data_size_bytes);

                test_res = iccom_test_test_mirror_poll_send_verify_helper(
                                &iccom, data, data_size_bytes, channel, 0
                                , timeout_jiffies);
                if (!test_res) {
                        break;
                }
        }
        if (data) {
                kfree(data);
                data = NULL;
        }
        __iccom_test_destroy_binded_iccom(full_duplex_mirror_iface(), &iccom);
        return test_res;

}

bool __iccom_test_mirror_batch_send_poll_helper(
                struct iccom_test_scenario *scenario
                , int iterations
                , struct iccom_dev *iccom
                , int timeout_jiffies)
{
        for (int i = 0; i < iterations * scenario->items_count; i++) {
                int idx = i % scenario->items_count;
                if (!iccom_test_test_mirror_poll_send_verify_helper(
                                iccom
                                , scenario->items[idx].data
                                , scenario->items[idx].data_size_bytes
                                , scenario->items[idx].dst_channel
                                , scenario->items[idx].priority
                                , timeout_jiffies)) {
                        return false;
                }
        }

        return true;
}

bool __iccom_test_mirror_batch_send_then_poll(
                struct iccom_test_scenario *scenario
                , int iterations
                , int timeout_jiffies)
{
        // init
        struct mirror_xfer_device mirror;
        struct iccom_dev iccom;

        if (iccom_init_binded(&iccom, full_duplex_mirror_iface()
                              , &mirror) < 0) {
                return false;
        }

        bool test_res = __iccom_test_mirror_batch_send_poll_helper(
                                scenario, iterations, &iccom
                                , timeout_jiffies);
        __iccom_test_destroy_binded_iccom(full_duplex_mirror_iface(), &iccom);
        return test_res;
}


//  THREAD WORKERS //

int iccom_test_mirror_multithreading_send_poll_worker(void *data)
{
        struct iccom_test_thread_data *th_data
                    = (struct iccom_test_thread_data *)data;

        th_data->result = __iccom_test_mirror_batch_send_poll_helper(
                                    th_data->scenario
                                    , th_data->iterations
                                    , th_data->iccom
                                    , th_data->timeout_jiffies);

        complete(&th_data->completion);
        return 0;
}

int iccom_test_mirror_multithreading_accum_worker(void *data)
{
        struct iccom_test_thread_data *th_data
                    = (struct iccom_test_thread_data *)data;

        th_data->result = iccom_test_test_mirror_batch_send_then_poll_helper(
                                    th_data->iccom
                                    , th_data->scenario
                                    , th_data->iterations
                                    , th_data->timeout_jiffies);
        complete(&th_data->completion);
        return 0;
}

int iccom_test_mirror_multithreading_send_callback_worker(void *data)
{
        struct iccom_test_thread_data *th_data
                    = (struct iccom_test_thread_data *)data;

        th_data->result = __iccom_test_mirror_batch_post_callback_helper(
                                    th_data->iccom
                                    , th_data->scenario
                                    , th_data->iterations
                                    , th_data->timeout_jiffies);

        complete(&th_data->completion);
        return 0;
}

int iccom_test_mirror_monitoring_thread_worker(void *data)
{
        struct iccom_test_thread_data *th_data
                    = (struct iccom_test_thread_data *)data;
        while (true) {
                iccom_print_statistics(th_data->iccom);
                if (*((bool*)th_data->custom_ptr1)) {
                        complete(&th_data->completion);
                        return 0;
                }
                msleep(jiffies_to_msecs(th_data->timeout_jiffies));
        }
}

//  THREAD LAUNCHERS //

// launches multithreading test
bool __iccom_test_batch_launcher_mt(
                struct iccom_test_concurrent_scenario *mt_scenario
                , int iterations
                , int timeout_jiffies
                , int monitoring_thread_period_jiffies
                , int mirror_errors_per_1Mbyte
                , bool monitor)
{
        bool test_res = true;

        // init
        struct mirror_xfer_device mirror;
        struct iccom_dev iccom;

        mirror.average_errors_per_1Mbyte = mirror_errors_per_1Mbyte;
        if (iccom_init_binded(&iccom, full_duplex_mirror_iface()
                              , &mirror) < 0) {
                return false;
        }

        struct iccom_test_thread_data *thread_datas
                        = kmalloc(sizeof(struct iccom_test_thread_data)
                                        * (mt_scenario->threads_count + 1)
                                  , GFP_KERNEL);

        int i;
        int actually_launched = 0;
        for (i = 0; i < mt_scenario->threads_count; i++) {
                if (!mt_scenario->thread_scenarios[i]->execution_routine) {
                        continue;
                }
                thread_datas[i].scenario = mt_scenario->thread_scenarios[i];
                thread_datas[i].iterations = iterations;
                thread_datas[i].iccom = &iccom;
                thread_datas[i].custom_ptr1 = (void*)&mirror;
                thread_datas[i].result = false;
                thread_datas[i].timeout_jiffies = timeout_jiffies;
                init_completion(&thread_datas[i].completion);

                kthread_run(mt_scenario->thread_scenarios[i]->execution_routine
                            , &thread_datas[i]
                            , "ICCom test worker thread");
                actually_launched++;
        }

        bool finish_monitoring = false;
        // monitoring thread
        if (monitor) {
                thread_datas[i].scenario = NULL;
                thread_datas[i].iterations = 0;
                thread_datas[i].iccom = &iccom;
                thread_datas[i].custom_ptr1 = &finish_monitoring;
                thread_datas[i].result = true;
                thread_datas[i].timeout_jiffies
                            = monitoring_thread_period_jiffies;
                init_completion(&thread_datas[i].completion);

                kthread_run(iccom_test_mirror_monitoring_thread_worker
                            , &thread_datas[i]
                            , "ICCom test monitoring thread");
        }

        iccom_test_info("%d thread(s) launched, waiting for completion"
                        , actually_launched);

        for (i = 0; i < mt_scenario->threads_count; i++) {
                if (!mt_scenario->thread_scenarios[i]->execution_routine) {
                        continue;
                }

                long wait_res = wait_for_completion_timeout(
                                                &thread_datas[i].completion
                                                , timeout_jiffies);
                if (wait_res == 0) {
                        test_res = false;
                        iccom_test_err("Timeout waiting for thread %d ", i);
                        // TODO do something good in this case? to
                        // avoid potential crash
                        continue;
                }
                if (!thread_datas[i].result) {
                        iccom_test_err("Thread %d failed its scenario.", i);
                        test_res = false;
                }
        }
        if (monitor) {
                finish_monitoring = true;
                wait_for_completion(&thread_datas[i].completion);
        }

        kfree(thread_datas);
        __iccom_test_destroy_binded_iccom(full_duplex_mirror_iface(), &iccom);
        return test_res;
}


/*-------------------- TESTS SECTION -------------------------------*/

// TEST 1
//
// * inits iccom with mirror transport layer
// * sends fixed 16 bytes message to the 1st channel
// * polls for receive exactly the same message back
// * closes iccom and mirror
bool iccom_test_test_mirror_poll_1(void)
{
        return iccom_test_test_mirror_poll_helper((uint8_t*)&iccom_test_data_1
                , sizeof(iccom_test_data_1), 1, msecs_to_jiffies(2000));
}

// TEST 2
// same as TEST 1, but for 2-byte message, for 1st channel
bool iccom_test_test_mirror_poll_2(void)
{
        return iccom_test_test_mirror_poll_helper((uint8_t*)&iccom_test_data_2
                , sizeof(iccom_test_data_2), 1, msecs_to_jiffies(2000));
}

// TEST 3
// same as TEST 1, but for 1-byte message, 1st channel
bool iccom_test_test_mirror_poll_3(void)
{
        return iccom_test_test_mirror_poll_helper((uint8_t*)&iccom_test_data_3
                , sizeof(iccom_test_data_3), 1, msecs_to_jiffies(2000));
}

// TEST 4
// same as TEST 1, but for 1-byte message, 0x7FFF channel (max valid)
bool iccom_test_test_mirror_poll_4(void)
{
        return iccom_test_test_mirror_poll_helper((uint8_t*)&iccom_test_data_3
                , sizeof(iccom_test_data_3), 0x7FFF, msecs_to_jiffies(2000));
}

// TEST 5
// same as TEST 1 but: repeated for 1000 on the same
// instance of iccom and for each iteration random
// channel is used.
bool iccom_test_test_mirror_poll_rand_ch_1(void)
{
        return iccom_test_test_mirror_poll_rand_channel_helper(
                        (uint8_t*)&iccom_test_data_1
                        , sizeof(iccom_test_data_1)
                        , 100, msecs_to_jiffies(1000 * 60));
}

// TEST 6
// same as TEST 1 but: repeated for 1000 on the same
// instance of iccom and for each iteration random
// channel and random data (including data size) are used.
bool iccom_test_test_mirror_poll_rand_ch_rand_data_1(void)
{
        return iccom_test_test_mirror_poll_rand_channel_data_helper(
                        100, 4096, msecs_to_jiffies(1000 * 60));
}

// TEST 7
// from scenario 1, one-by-one
// * posts message
// * polls message
bool iccom_test_test_mirror_poll_5(void)
{
        return __iccom_test_mirror_batch_send_then_poll(
                        &iccom_test_scenario_1, 1, msecs_to_jiffies(2000));
}

// TEST 8
// * posts whole scenario 1
// * polls whole scenario 1
bool iccom_test_test_mirror_accum_poll_1(void)
{
        return iccom_test_test_mirror_accum_poll_st(
                        &iccom_test_scenario_1, 1, msecs_to_jiffies(2000));
}

// TEST 9
// multithreading:
//      Thread 1: 100x (write && readback && verify)
//          several messages to 1 and 2 channel (scenario 1)
//      Thread 2: 100x (write && readback && verify)
//          several messages to 3 and 4 channel (scenario 2)
bool iccom_test_test_mirror_multithreading_send_poll_1(void)
{
        iccom_test_multithread_scenario_1.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_poll_worker;
        iccom_test_multithread_scenario_1.thread_scenarios[1]->execution_routine
                    = iccom_test_mirror_multithreading_send_poll_worker;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_1, 100
                        , msecs_to_jiffies(20000), msecs_to_jiffies(2000)
                        , 0, true);
}

// TEST 10
// multithreading:
//      Thread 1: write 100x, readback 100x && verify
//          (of several messages to 1 and 2 channel (scenario 1))
//      Thread 2: write 100x, readback 100x && verify
//          (of several messages to 3 and 4 channel (scenario 2))
bool iccom_test_test_mirror_multithreading_accum_poll_1(void)
{
        iccom_test_multithread_scenario_1.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_accum_worker;
        iccom_test_multithread_scenario_1.thread_scenarios[1]->execution_routine
                    = iccom_test_mirror_multithreading_accum_worker;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_1, 100
                        , msecs_to_jiffies(20000), msecs_to_jiffies(2000)
                        , 0, true);
}

// TEST 11
// multithreading:
//      Thread 1: 100x (write && readback && verify messages from
//          scenario 1)
//      Thread 2: write 100x(scenario 2), readback 100x(scenario 2)
//          ,verify(scenario 2)
bool iccom_test_test_mirror_multithreading_mix_1(void)
{
        iccom_test_multithread_scenario_1.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_poll_worker;
        iccom_test_multithread_scenario_1.thread_scenarios[1]->execution_routine
                    = iccom_test_mirror_multithreading_accum_worker;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_1, 100
                        , msecs_to_jiffies(20000), msecs_to_jiffies(2000)
                        , 0, true);
}

// TEST 12
// * register callback on channels of scenario 1
// * send messages according scenario 1
// * expecting callbacks to be called
// * verify that send data = receive data in callbacks
bool iccom_test_test_mirror_callback_send_receive_1(void)
{
        iccom_test_multithread_scenario_1.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_1.thread_scenarios[1]->execution_routine
                    = NULL;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_1, 1
                        , msecs_to_jiffies(20000), msecs_to_jiffies(2000)
                        , 0, true);
}

// TEST 13
// * register callback on channels of scenario 1
// * send messages according scenario 1
// * expecting callbacks to be called
// * verify that send data = receive data in callbacks
bool iccom_test_test_mirror_callback_send_receive_2(void)
{
        iccom_test_multithread_scenario_1.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_1.thread_scenarios[1]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_1, 1000
                        , msecs_to_jiffies(20000), msecs_to_jiffies(2000)
                        , 0, true);
}

// TEST 14
// (heavy load test)
// 10 000 iterations of 1 thread:
//      * accumulative: enqueue all messages, then poll them all and check
bool iccom_test_test_mirror_callback_send_receive_3(void)
{
        iccom_test_multithread_scenario_2.thread_scenarios[0]->execution_routine
                    = NULL;
        iccom_test_multithread_scenario_2.thread_scenarios[1]->execution_routine
                    = NULL;
        iccom_test_multithread_scenario_2.thread_scenarios[2]->execution_routine
                    = iccom_test_mirror_multithreading_accum_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[3]->execution_routine
                    = NULL;
        iccom_test_multithread_scenario_2.thread_scenarios[4]->execution_routine
                    = NULL;
        iccom_test_multithread_scenario_2.thread_scenarios[5]->execution_routine
                    = NULL;
        iccom_test_multithread_scenario_2.thread_scenarios[6]->execution_routine
                    = NULL;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_2, 10000
                        , msecs_to_jiffies(1000 * 60 * 2)
                        , msecs_to_jiffies(2000)
                        , 0, true);
}

// TEST 15
// (heavy load multithreading test)
// 10 000 iterations of 7 threads:
//      * 1-2 threads (scenario 1-2, send&poll),
//      * 3-4 threads (scenario 3-4, send all then poll),
//      * 5-7 threads (scenario 5-7, callbacks),
bool iccom_test_test_mirror_callback_send_receive_4(void)
{
        iccom_test_multithread_scenario_2.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_poll_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[1]->execution_routine
                    = iccom_test_mirror_multithreading_send_poll_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[2]->execution_routine
                    = iccom_test_mirror_multithreading_accum_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[3]->execution_routine
                    = iccom_test_mirror_multithreading_accum_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[4]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[5]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[6]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_2, 10000
                        , msecs_to_jiffies(1000 * 60 * 20)
                        , msecs_to_jiffies(20000)
                        , 0, true);
}

// TEST 16
// Broken mirror, error rate 100 per 1MByte
//      Thread 1: 1000x (write && readback && verify)
//          several messages to 1 and 2 channel (scenario 1)
bool iccom_test_test_broken_mirror_multithreading_send_poll_1(void)
{
        iccom_test_multithread_scenario_1.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_poll_worker;
        iccom_test_multithread_scenario_1.thread_scenarios[1]->execution_routine
                    = NULL;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_1, 100
                        , msecs_to_jiffies(1000 * 60 * 2), msecs_to_jiffies(2000)
                        , 100, true);
}

// TEST 17
// Broken mirror, error rate 1000 per 1MByte
//      Thread 1: 100x (write && readback && verify)
//          several messages to 1 and 2 channel (scenario 1)
//      Thread 2: 100x (write && readback && verify)
//          several messages to 3 and 4 channel (scenario 1)
bool iccom_test_test_broken_mirror_multithreading_send_poll_2(void)
{
        iccom_test_multithread_scenario_1.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_poll_worker;
        iccom_test_multithread_scenario_1.thread_scenarios[1]->execution_routine
                    = iccom_test_mirror_multithreading_send_poll_worker;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_1, 100
                        , msecs_to_jiffies(1000 * 60 * 5)
                        , msecs_to_jiffies(2000)
                        , 1000, true);
}

// TEST 18
// (heavy load multithreading with noisy channel test), error rate 10 per 1MB
// 5 000 iterations of 7 threads:
//      * 1-7 threads (scenario 1-7, callbacks),
bool iccom_test_test_broken_mirror_callback_send_receive_4(void)
{
        iccom_test_multithread_scenario_2.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[1]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[2]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[3]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[4]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[5]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[6]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_2, 5000
                        , msecs_to_jiffies(1000 * 60 * 10)
                        , msecs_to_jiffies(20000)
                        , 10, true);
}

// TEST 19
// heavy load multithreading with performance test (no errors)
// 30 000 iterations of 7 threads:
//      * 1-7 threads (scenario 1-7, callbacks),
bool iccom_test_test_mirror_callback_send_receive_5(void)
{
        iccom_test_multithread_scenario_2.thread_scenarios[0]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[1]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[2]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[3]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[4]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[5]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        iccom_test_multithread_scenario_2.thread_scenarios[6]->execution_routine
                    = iccom_test_mirror_multithreading_send_callback_worker;
        return __iccom_test_batch_launcher_mt(
                        &iccom_test_multithread_scenario_2, 30000
                        , msecs_to_jiffies(1000 * 60 * 3)
                        , msecs_to_jiffies(20000)
                        , 0, true);
}

// TEST 20
// load/unload test: multiple load/send/poll/receive/unload series
// execution (mainly to check for memory leaks within whole lifecycle).
bool iccom_test_lifecycle_test(void)
{
        for (int i = 0; i < 1000; i++) {
                iccom_test_multithread_scenario_2.thread_scenarios[0]->execution_routine
                            = iccom_test_mirror_multithreading_send_poll_worker;
                iccom_test_multithread_scenario_2.thread_scenarios[1]->execution_routine
                            = iccom_test_mirror_multithreading_send_poll_worker;
                iccom_test_multithread_scenario_2.thread_scenarios[2]->execution_routine
                            = iccom_test_mirror_multithreading_accum_worker;
                iccom_test_multithread_scenario_2.thread_scenarios[3]->execution_routine
                            = iccom_test_mirror_multithreading_accum_worker;
                iccom_test_multithread_scenario_2.thread_scenarios[4]->execution_routine
                            = iccom_test_mirror_multithreading_send_callback_worker;
                iccom_test_multithread_scenario_2.thread_scenarios[5]->execution_routine
                            = iccom_test_mirror_multithreading_send_callback_worker;
                iccom_test_multithread_scenario_2.thread_scenarios[6]->execution_routine
                            = iccom_test_mirror_multithreading_send_callback_worker;
                if (!__iccom_test_batch_launcher_mt(
                                &iccom_test_multithread_scenario_2, 3
                                , msecs_to_jiffies(1000 * 10)
                                , msecs_to_jiffies(10000)
                                , 10, false)) {
                        return false;
                }
        }

        return true;
}

#ifdef ICCOM_TEST_SYMSPI
// TEST 21
// Only bind to the SymSPI driver as full duplex transport
bool iccom_test_symspi_bind(void)
{
        struct iccom_dev iccom;
        if (__iccom_test_init_symspi_binded_iccom(&iccom) < 0) {
                return false;
        }

        __iccom_test_destroy_binded_iccom(symspi_iface(), &iccom);
        return true;
}

// TEST 22
// Graceful close while xfer test.
// NOTE: in this test the request to close the ICCom and SymSPI devices
//      is usually executed earlier than the SPI xfer begins, to
//      exactly this test tests the ability to shut down the SymSPI and
//      ICCom devices while they are not in idle.
bool iccom_test_symspi_single_post(void)
{
        struct iccom_dev iccom;
        if (__iccom_test_init_symspi_binded_iccom(&iccom) < 0) {
                return false;
        }

        int res = iccom_post_message(&iccom
                        , (char*)&iccom_test_data_default
                        , sizeof(iccom_test_data_default)
                        , 1, 0);
        if (res < 0) {
                iccom_test_err("iccom_post_message failed: err: %d", res);
                return false;
        }

        msleep(1000);

        __iccom_test_destroy_binded_iccom(symspi_iface(), &iccom);
        return true;
}

// TEST 23
// Sending the empty package to the other side.
bool iccom_test_symspi_flush_empty_package(void)
{
        struct iccom_dev iccom;
        if (__iccom_test_init_symspi_binded_iccom(&iccom) < 0) {
                return false;
        }

        int res = iccom_flush(&iccom);

        if (res < 0) {
                iccom_test_err("iccom_post_message failed: err: %d", res);
                return false;
        }

        msleep(1000);

        __iccom_test_destroy_binded_iccom(symspi_iface(), &iccom);
        return true;
}

// TEST 24
// Sending several fixed data-loaded packages to the other side
// (payload is fixed).
bool iccom_test_symspi_post_several_fixed_payload_packages(void)
{
        struct iccom_dev iccom;
        if (__iccom_test_init_symspi_binded_iccom(&iccom) < 0) {
                return false;
        }

        for (int i = 0; i < 100; i++) {
                int res = iccom_post_message(&iccom
                                , (char*)&iccom_test_data_3
                                , sizeof(iccom_test_data_3)
                                , 1, 0);

                if (res < 0) {
                        iccom_test_err("iccom_post_message failed:"
                                       " err: %d", res);
                        return false;
                }
        }

        msleep(3000);

        __iccom_test_destroy_binded_iccom(symspi_iface(), &iccom);
        return true;
}

// TEST 25
// Graceful close while xfer test.
// NOTE: in this test the request to close the ICCom and SymSPI devices
//      is usually executed earlier than the SPI xfer begins, to
//      exactly this test tests the ability to shut down the SymSPI and
//      ICCom devices while they are not in idle.
bool iccom_test_symspi_xfer_abort(void)
{
        struct iccom_dev iccom;
        if (__iccom_test_init_symspi_binded_iccom(&iccom) < 0) {
                return false;
        }

        int res = iccom_post_message(&iccom
                        , (char*)&iccom_test_data_default
                        , sizeof(iccom_test_data_default)
                        , 1, 0);

        if (res < 0) {
                iccom_test_err("iccom_post_message failed: err: %d", res);
                return false;
        }

        __iccom_test_destroy_binded_iccom(symspi_iface(), &iccom);
        return true;
}
#endif /* ICCOM_TEST_SYMSPI */


/*-------------------- TESTS LIST ----------------------------------*/

struct iccom_test_test {
        bool (*routine)(void);
        char *name;
        bool result;
};

// If you add a new test, add it here
static struct iccom_test_test iccom_test_tests[] = {
      { iccom_test_test_mirror_poll_1, "TEST MIRROR 1: 16 byte send to 1st"
           "channel -> poling receive -> get the same data as sent", false }
      , { iccom_test_test_mirror_poll_2, "TEST MIRROR 2: 2 byte send to 1st"
           "channel -> poling receive -> get the same data as sent", false }
      , { iccom_test_test_mirror_poll_3, "TEST MIRROR 3: 1 byte send to 1st"
          "channel -> poling receive -> get the same data as sent", false }
      , { iccom_test_test_mirror_poll_4, "TEST MIRROR 4: 1 byte send to 0x7FFF"
          "channel -> poling receive -> get the same data as sent", false }
      , { iccom_test_test_mirror_poll_rand_ch_1, "TEST MIRROR 5: 100 "
          "iterations: 16 byte send to random channel and read out mirrored"
          " by polling"
          , false }
      , { iccom_test_test_mirror_poll_rand_ch_rand_data_1, "TEST MIRROR 6: "
          "100 iterations: random channel selection, random data generation "
          "up to 4096 bytes, send, poll mirrored answer and verify", false }
      , { iccom_test_test_mirror_poll_5, "TEST MIRROR 7: predefined "
          "sequence of send to mirrored iccom (3 predefined datas: send"
          " -> pull -> verify", false }
      , { iccom_test_test_mirror_accum_poll_1, "TEST MIRROR 8:"
          "posts 3 messages one-by-one, and two of these messages are "
          "to the same channel -> polls them all and verifies", false }
      , { iccom_test_test_mirror_multithreading_send_poll_1
          , "TEST MIRROR MT 1: Thread 1: 100x (write && readback && verify)"
            " 3 messages to 1 "
            "and 2 channel (scenario 1); Thread 2: 100x (write && readback"
            " && verify) several messages to 3 and 4 channel (scenario 2)"
         , false }
      , { iccom_test_test_mirror_multithreading_accum_poll_1
          , "TEST MIRROR MT 2: Thread 1: write 100x, readback 100x && verify"
            "(of several messages to 1 and 2 channel (scenario 1))"
            "Thread 2: write 100x, readback 100x && verify"
            "(of several messages to 3 and 4 channel (scenario 2))", false }
      , { iccom_test_test_mirror_multithreading_mix_1
          , "TEST MIRROR MT 3: Thread 1: 100x (write && readback && verify"
            "messages from scenario 1), Thread 2: write 100x(scenario 2), "
            "readback 100x(scenario 2), verify(scenario 2)", false }
      , { iccom_test_test_mirror_callback_send_receive_1
          , "TEST MIRROR 9: register callback on channels of scenario 1"
            "send messages according scenario 1"
            "expecting callbacks to be called"
            "verify that send data = receive data in callbacks"
          , false }
      , { iccom_test_test_mirror_callback_send_receive_2
          , "TEST MIRROR MT 4: (1000 iterations for every scenario) :"
            "2 threads: thread 1 (scenario 1, callbacks); thread 2 (scenario 2"
            ", callbacks)", false }
      , { iccom_test_test_mirror_callback_send_receive_3
          , "TEST MIRROR 10: 10 000 iterations of 1 thread: accumulative: "
            "enqueue all messages, then poll them all and check", false }
      , { iccom_test_test_mirror_callback_send_receive_4
          , "TEST MIRROR MT 5:  (heavy load multithreading test)"
            "10 000 iterations of 4 threads: "
            " 1-2 threads (scenario 1-2, send&poll);"
            " 3-4 threads (scenario 3-4, send all then poll);"
            " 5-7 threads (scenario 5-7, callbacks);"
          , false }
      , { iccom_test_test_broken_mirror_multithreading_send_poll_1
          , "TEST BROKEN MIRROR 1: 1000x (write && readback && verify),"
            " error rate: 100 per 1MByte", false }
      , { iccom_test_test_broken_mirror_multithreading_send_poll_2
          , "TEST BROKEN MIRROR MT 1: 1-2 threads: 100x (write && readback && "
             "verify), error rate: 1000 per 1MByte", false}
      , {iccom_test_test_broken_mirror_callback_send_receive_4
          , "TEST BROKEN MIRROR MT 2: heavy load multithreading with noisy"
            " channel), error rate 10 per 1MB; 5000 iterations of 7"
            " threads: 1-7 threads (scenario 1-7, callbacks)"
          , false }
      , { iccom_test_test_mirror_callback_send_receive_5
          , "TEST MIRROR MT 6:  performance test: "
            "30 000 iterations of 7 threads: "
            "1-7 threads (scenario 1-7, callbacks);"
          , false }
      , { iccom_test_lifecycle_test
          , "TEST BROKEN MIRROR MT 3: multiple versatile lifecycle"
          , false }
#ifdef ICCOM_TEST_SYMSPI
     , { iccom_test_symspi_bind, "TEST SYMSPI 1: only bind to"
            " symspi and the close"
          , false }
      , { iccom_test_symspi_single_post, "TEST SYMSPI 2: single message"
          " to the 0th channel."
          , false }
      , { iccom_test_symspi_flush_empty_package, "TEST SYMSPI 3: flush"
          " empty package"
          , false }
      , { iccom_test_symspi_post_several_fixed_payload_packages
          , "Sending several fixed data-loaded packages to the other side"
            "(payload is fixed)."
          , false }
      , { iccom_test_symspi_xfer_abort, "TEST SYMSPI 4: Graceful close"
          " while xfer test."
          , false }
#endif /* ICCOM_TEST_SYMSPI */
};

/*------------------------- UTILITIES ------------------------------*/

static inline int iccom_test_tests_count(void)
{
        return (!sizeof(iccom_test_tests))
               ? 0 : (sizeof(iccom_test_tests)
                      / sizeof(iccom_test_tests[0]));
}


// Printout test results
static void iccom_test_print_results(void)
{
        iccom_test_info_raw("========= ICCOM TEST RESULTS =========");
        int tests_count = iccom_test_tests_count();
        int failed_count = 0;
        int i;
        for (i = 0; i < tests_count; i++) {
                if (iccom_test_tests[i].result) {
                        iccom_test_info_raw("test[%d]:     OK: %s", i
                                             , iccom_test_tests[i].name);
                } else {
                        iccom_test_err_raw("test[%d]:     FAILED!: %s"
                                            , i, iccom_test_tests[i].name);
                        failed_count++;
                }
        }

        if (failed_count == 0) {
                iccom_test_info_raw("ALL (%d) TESTS PASSED.", tests_count);
        } else {
                iccom_test_err_raw("%d/%d TESTS FAILED", failed_count
                                    , tests_count);
        }
}

/*-------------------- MAIN ROUTINES -------------------------------*/

// RETURNS:
//      0: if all tests passed,
//      <= -1: negated first failed test number
static int iccom_test_run(void)
{
        int first_failed_num = 0;

        iccom_test_info("module loaded");

        // run all decladed tests
        int i;
        int tests_count = iccom_test_tests_count();
        int failed_count = 0;
        for (i = 0; i < tests_count ; i++) {
                iccom_test_info("starting test: [%d]", (i + 1));
                if (!(iccom_test_tests[i].routine())) {
                        iccom_test_err("test %d failed, see dmesg"
                                        " for details.", (i + 1));
                        iccom_test_tests[i].result = false;
                        failed_count++;
                        if (failed_count == 1) {
                                    first_failed_num = -i - 1;
                        }
                } else {
                        iccom_test_info("test [%d] PASSED", (i + 1));
                        iccom_test_tests[i].result = true;
                }
                // to distinguish between tests in logic diagram
                msleep(500);
        }

        iccom_test_print_results();

        return first_failed_num;
}

static int __init iccom_test_module_init(void)
{
        return iccom_test_run();
}

static void __exit iccom_test_module_exit(void)
{
        iccom_test_info("module unloaded...");
}


module_init(iccom_test_module_init);
module_exit(iccom_test_module_exit);

MODULE_DESCRIPTION("Module for testing ICCom driver.");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");

