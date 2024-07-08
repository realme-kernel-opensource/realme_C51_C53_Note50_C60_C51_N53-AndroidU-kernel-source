/*
 * Copyright (C) 2021-2022 UNISOC Communications Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef XRP_INTERNAL_H
#define XRP_INTERNAL_H

#include <linux/completion.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include "xrp_address_map.h"
#include "vdsp_smem.h"
#include "xrp_library_loader.h"

struct device;
struct firmware;
struct xrp_hw_ops;
struct xrp_allocation_pool;

struct firmware_origin {
 size_t size;
 u8 *data;
};

struct xrp_comm {
	struct mutex lock;
	void __iomem *comm;
	struct completion completion;
	u32 priority;
};
struct faceid_mem_addr {
	struct ion_buf ion_fd_weights_p;
	struct ion_buf ion_fd_weights_r;
	struct ion_buf ion_fd_weights_o;
	struct ion_buf ion_fp_weights;
	struct ion_buf ion_flv_weights;
	struct ion_buf ion_fv_weights;

	struct ion_buf ion_fd_mem_pool;
	struct ion_buf ion_face_transfer;
	struct ion_buf ion_face_in;
	struct ion_buf ion_face_out;
};
struct xvp {
	struct device *dev;
	const char *firmware_name;
	const struct firmware *firmware;
	struct firmware_origin firmware2;/*faceid fw*/
	const struct firmware *firmware2_sign;/*faceid sign fw*/
	struct miscdevice miscdev;
	const struct xrp_hw_ops *hw_ops;
	void *hw_arg;
	unsigned n_queues;

	u32 *queue_priority;
	struct xrp_comm *queue;
	struct xrp_comm **queue_ordered;
	void __iomem *comm;
	phys_addr_t pmem;
	phys_addr_t comm_phys;
	phys_addr_t dsp_comm_addr;
	/*ion buff for firmware, comm, dram backup memory*/
	struct ion_buf ion_firmware;
	struct ion_buf ion_comm;
	/*firmware addr infos*/
	void *firmware_viraddr;
	void *firmware2_viraddr;
	phys_addr_t firmware_phys;
	phys_addr_t firmware2_phys;
	phys_addr_t dsp_firmware_addr;

	phys_addr_t shared_size;
	atomic_t reboot_cycle;
	atomic_t reboot_cycle_complete;

	struct xrp_address_map address_map;

	bool host_irq_mode;

	struct xrp_allocation_pool *pool;
	bool off;
	int nodeid;
	bool secmode;/*used for faceID*/
	bool tee_con;/*the status of connect TEE*/
	struct ion_buf ion_faceid_fw;/*faceid fw*/
	struct faceid_mem_addr faceid_pool;
	const struct firmware *faceid_fw;
	void *fd_weights_p_viraddr;
	struct xrp_load_lib_info load_lib;
	uint32_t open_count;
	struct vdsp_mem_desc *vdsp_mem_desc;
};

#endif
