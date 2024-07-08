# Makefile for the focaltech touchscreen drivers.

ifneq ($(filter userdebug, $(TARGET_BUILD_VARIANT)),)
    $(warning "===================== userdebug verison focaltech_tp  ======================")
    KBUILD_CFLAGS += -DUSER_DEBUG
endif

obj-$(CONFIG_TOUCHSCREEN_FOCALTECH_SPI) += focaltech_touch-modules.o
focaltech_touch-modules-y := focaltech_core.o \
		focaltech_ex_fun.o \
		focaltech_ex_mode.o \
		focaltech_gesture.o \
		focaltech_esdcheck.o \
		focaltech_point_report_check.o \
		focaltech_proximity.o \
                focaltech_flash_spi.o \
                focaltech_spi_v2.o \
                focaltech_test.o \
                focaltech_test_ft8057p.o \
                focaltech_test_ini.o


