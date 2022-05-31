ccflags-y := -std=gnu99 -Wno-declaration-after-statement
ccflags-y += -Iinclude/linux

ccflags-$(CONFIG_BOSCH_ICCOM_DEBUG) += -DICCOM_DEBUG
ifeq ($(CONFIG_BOSCH_ICCOM_DEBUG), y)
    ccflags-y += -DDICCOM_DEBUG_CHANNEL=$(CONFIG_BOSCH_ICCOM_DEBUG_CHANNEL)
    ccflags-y += -DICCOM_DEBUG_MESSAGES_PRINTOUT_MAX_COUNT=$(CONFIG_BOSCH_ICCOM_DEBUG_MESSAGES_PRINTOUT_MAX_COUNT)
    ccflags-y += -DICCOM_DEBUG_PACKAGES_PRINTOUT_MAX_COUNT=$(CONFIG_BOSCH_ICCOM_DEBUG_PACKAGES_PRINTOUT_MAX_COUNT)
endif

# ICCom consumer data delivery work queue configuration
ifeq (${CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE}, "SYSTEM")
    ccflags-y += -DICCOM_WORKQUEUE_MODE=ICCOM_WQ_SYSTEM
else ifeq (${CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE}, "SYSTEM_HIGHPRI")
    ccflags-y += -DICCOM_WORKQUEUE_MODE=ICCOM_WQ_SYSTEM_HIGHPRI
else ifeq (${CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE}, "PRIVATE")
    ccflags-y += -DICCOM_WORKQUEUE_MODE=ICCOM_WQ_PRIVATE
endif

#obj-$(CONFIG_BOSCH_ICCOM) += iccom.o
obj-m += src/iccom.o
ifeq ($(CONFIG_BOSCH_ICCOM_TEST_MODULE), y)
    obj-m += src/iccom_test.o
endif

obj-$(CONFIG_BOSCH_ICCOM_SOCKETS) += iccom_socket_if.o

# Custom protocol aggregator drivers
obj-$(CONFIG_BOSCH_ICCOM_EXAMPLE) += iccom-example.o
obj-$(CONFIG_BOSCH_ICCOM_TRANSPORT_MIRROR_V1) += iccom-transport-mirror-v1.o
