#
# Makefile for the Omnivision TCM touchscreen driver.
#

# Each configuration option enables a list of files.

ifneq ($(filter m, $(CONFIG_TOUCHSCREEN_OMNIVISION_TCM)),)
omnivision_tcm-objs := omnivision_tcm_core.o omnivision_tcm_touch.o \
	omnivision_tcm_zeroflash.o \
	omnivision_tcm_reflash.o \
	omnivision_tcm_device.o \
	omnivision_tcm_testing.o \
	omnivision_tcm_csv_parser.o \
	omnivision_tcm_recovery.o \
	omnivision_tcm_diagnostics.o \
	omnivision_tcm_spi.o \
	touch.o

obj-m += omnivision_tcm.o
endif

ifneq ($(filter userdebug, $(TARGET_BUILD_VARIANT)),)
    $(warning "===================== userdebug verison  ======================")
    KBUILD_CFLAGS += -DUSER_DEBUG
endif

ifneq ($(filter y, $(CONFIG_TOUCHSCREEN_OMNIVISION_TCM)),)
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_SPI) += omnivision_tcm_spi.o
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_CORE) += omnivision_tcm_core_module.o
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_DEVICE) += omnivision_tcm_device.o
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_TESTING) += omnivision_tcm_testing.o
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_TESTING) += omnivision_tcm_csv_parser.o
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_REFLASH) += omnivision_tcm_reflash.o
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_RECOVERY) += omnivision_tcm_recovery.o
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_DIAGNOSTICS) += omnivision_tcm_diagnostics.o
obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_ZEROFLASH) += omnivision_tcm_zeroflash.o

obj-$(CONFIG_TOUCHSCREEN_OMNIVISION_TCM_I2C) += omnivision_tcm_i2c.o
omnivision_tcm_core_module-objs := omnivision_tcm_core.o omnivision_tcm_touch.o
endif
