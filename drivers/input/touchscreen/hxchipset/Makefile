# Makefile for the Himax touchscreen drivers.

ifneq ($(filter y, $(CONFIG_KALLSYMS_ALL)),)
	ccflags-y += -D__KERNEL_KALLSYMS_ALL_ENABLED__
endif

ifneq ($(filter y, $(CONFIG_FB)),)
	ccflags-y += -DHX_CONFIG_FB
endif

ifneq ($(filter y, $(CONFIG_DRM)),)
	ccflags-y += -DHX_CONFIG_DRM
endif

ifneq ($(filter userdebug, $(TARGET_BUILD_VARIANT)),)
   $(warning "===================== userdebug verison  ======================")
   ccflags-y += -DUSER_DEBUG
endif

ifneq ($(filter m, $(CONFIG_TOUCHSCREEN_HIMAX_COMMON)),)
  ccflags-y += -D__HIMAX_MOD__
endif
# obj-y += himax_modular_table.o

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_DEBUG)),)
	himax_mmi-objs += himax_debug.o
endif

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_INSPECT)),)
	himax_mmi-objs += himax_inspection.o
endif

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_INCELL)),)
	himax_mmi-objs += himax_ic_incell_core.o
endif

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_ONCELL)),)
	himax_mmi-objs += himax_ic_oncell_core.o
endif

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_IC_HX852xJ)),)
  ccflags-y += -D__HIMAX_HX852xJ_MOD__
	himax_mmi-objs += himax_ic_HX852xJ.o
endif

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_IC_HX83102)),)
  ccflags-y += -D__HIMAX_HX83102_MOD__
	himax_mmi-objs += himax_ic_HX83102.o
endif

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_IC_HX83108)),)
  ccflags-y += -D__HIMAX_HX83108_MOD__
	himax_mmi-objs += himax_ic_HX83108.o
endif

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_IC_HX83112)),)
  ccflags-y += -D__HIMAX_HX83112_MOD__
	himax_mmi-objs += himax_ic_HX83112.o
endif

ifneq ($(filter y m, $(CONFIG_TOUCHSCREEN_HIMAX_IC_HX83121)),)
  ccflags-y += -D__HIMAX_HX83121_MOD__
	himax_mmi-objs += himax_ic_HX83121.o
endif

ifneq ($(filter m, $(CONFIG_TOUCHSCREEN_HIMAX_COMMON)),)
  ccflags-y += -D__HIMAX_MOD__
  himax_mmi-objs += himax_common.o
  himax_mmi-objs += himax_platform.o
  ifneq ($(filter y, $(CONFIG_TOUCHSCREEN_HIMAX_EMBEDDED_FIRMWARE)),)
    ccflags-y += -DHX_FIRMWARE_HEADER
    himax_mmi-objs += himax_firmware.o
  endif
  obj-m += himax_mmi.o
endif

## FOR GKI
ifneq ($(filter m, $(CONFIG_TOUCHSCREEN_HIMAX_CHIPSET)),)
  ccflags-y += -D__HIMAX_MOD__
  # FOR GKI
  himax_mmi-objs += himax_debug.o
  himax_mmi-objs += himax_inspection.o
  himax_mmi-objs += himax_ic_incell_core.o
  himax_mmi-objs += himax_ic_HX83108.o
  #FOR GKI
  himax_mmi-objs += himax_common.o
  himax_mmi-objs += himax_platform.o
  ifneq ($(filter y, $(CONFIG_TOUCHSCREEN_HIMAX_EMBEDDED_FIRMWARE)),)
    ccflags-y += -DHX_FIRMWARE_HEADER
    himax_mmi-objs += himax_firmware.o
  endif
  obj-m += himax_mmi.o
endif

ifneq ($(filter y, $(CONFIG_TOUCHSCREEN_HIMAX_COMMON)),)
  himax_mmi-objs += himax_common.o
  himax_mmi-objs += himax_platform.o
  ifneq ($(filter y, $(CONFIG_TOUCHSCREEN_HIMAX_EMBEDDED_FIRMWARE)),)
	ccflags-y += -DHX_FIRMWARE_HEADER
	himax_mmi-objs += himax_firmware.o
  endif
  obj-y += himax_mmi.o
endif

