# Copyright (C) 2021-2022 UNISOC Communications Inc.
#
# This software is licensed under the terms of the GNU General Public
# License version 2, as published by the Free Software Foundation, and
# may be copied, distributed, and modified under those terms.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

#ifeq ($(strip $(TARGET_BOARD_VDSP_MODULAR_KERNEL)),ceva1.0)
PRODUCT_PACKAGES += vdsp.ko

PRODUCT_COPY_FILES += vendor/sprd/modules/libcamera/kernel_module/vdsp/Ceva/init.sprd_vdsp.rc:vendor/etc/init/init.sprd_vdsp.rc
#endif

