ccflags-y := -std=gnu99 -Wno-declaration-after-statement
ccflags-y += -I$(src)/include
ccflags-y += -DDEFAULT_SYMBOL_NAMESPACE=

ccflags-$(CONFIG_BOSCH_ICCOM_DEBUG) += -DICCOM_DEBUG
ifeq ($(CONFIG_BOSCH_ICCOM_DEBUG), y)
    ccflags-y += -DDICCOM_DEBUG_CHANNEL=$(CONFIG_BOSCH_ICCOM_DEBUG_CHANNEL)
    ifneq ($(CONFIG_BOSCH_ICCOM_DEBUG_MESSAGES_PRINTOUT_MAX_COUNT),)
        ccflags-y += -DICCOM_DEBUG_MESSAGES_PRINTOUT_MAX_COUNT=$(CONFIG_BOSCH_ICCOM_DEBUG_MESSAGES_PRINTOUT_MAX_COUNT)
    endif
    ifneq ($(CONFIG_BOSCH_ICCOM_DEBUG_PACKAGES_PRINTOUT_MAX_COUNT),)
        ccflags-y += -DICCOM_DEBUG_PACKAGES_PRINTOUT_MAX_COUNT=$(CONFIG_BOSCH_ICCOM_DEBUG_PACKAGES_PRINTOUT_MAX_COUNT)
    endif
endif

# ICCom consumer data delivery work queue configuration
ifeq ($(CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE), "SYSTEM")
    ccflags-y += -DICCOM_WORKQUEUE_MODE=ICCOM_WQ_SYSTEM
else ifeq ($(CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE), "SYSTEM_HIGHPRI")
    ccflags-y += -DICCOM_WORKQUEUE_MODE=ICCOM_WQ_SYSTEM_HIGHPRI
else ifeq ($(CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE), "PRIVATE")
    ccflags-y += -DICCOM_WORKQUEUE_MODE=ICCOM_WQ_PRIVATE
endif

ccflags-y += -DICCOM_VERSION='"${CONFIG_ICCOM_VERSION}"'

obj-$(CONFIG_BOSCH_ICCOM) += src/iccom.o
obj-$(CONFIG_BOSCH_FD_TEST_TRANSPORT) += src/fd_test_transport.o

ifeq ($(CONFIG_BOSCH_ICCOM_TEST_MODULE), y)
    obj-m += src/iccom_test.o
endif

obj-$(CONFIG_BOSCH_ICCOM_SOCKETS) += src/iccom_socket_if.o

# Custom protocol aggregator drivers
obj-$(CONFIG_BOSCH_ICCOM_EXAMPLE) += iccom-example.o
obj-$(CONFIG_BOSCH_ICCOM_TRANSPORT_MIRROR_V1) += iccom-transport-mirror-v1.o
