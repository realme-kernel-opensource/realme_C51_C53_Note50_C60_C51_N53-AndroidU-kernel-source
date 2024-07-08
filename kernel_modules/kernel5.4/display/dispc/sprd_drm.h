/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Unisoc Inc.
 */

#ifndef _SPRD_DRM_H_
#define _SPRD_DRM_H_

#include <drm/drm_atomic.h>
#include <drm/drm_print.h>
#include <linux/kthread.h>

#define GSP_MAX_NUM 2

struct sprd_commit_list {
	struct list_head head;
	struct drm_atomic_state *state;
};

struct sprd_drm {
	struct drm_atomic_state *state;
	struct sprd_commit_list *commit;
	struct drm_device *drm;
	struct device *gsp_dev[GSP_MAX_NUM];
	struct list_head post_list;
	struct mutex post_lock;
	struct kthread_worker post_worker;
	struct task_struct *post_thread;
	struct kthread_work post_work;
	struct mutex state_lock;
};

#ifdef CONFIG_DRM_SPRD_DUMMY
extern struct platform_driver sprd_dummy_crtc_driver;
extern struct platform_driver sprd_dummy_connector_driver;
#endif

#ifdef CONFIG_DRM_SPRD_DPU0
extern struct platform_driver sprd_dpu_driver;
extern struct platform_driver sprd_backlight_driver;
#endif

#ifdef CONFIG_DRM_SPRD_DPU1
extern struct platform_driver sprd_dpu1_driver;
#endif

#ifdef CONFIG_DRM_SPRD_DSI
extern struct platform_driver sprd_dsi_driver;
extern struct platform_driver sprd_dphy_driver;
extern struct mipi_dsi_driver sprd_panel_driver;
#endif

#ifdef CONFIG_DRM_SPRD_DP
extern struct platform_driver sprd_dp_driver;
#endif

#ifdef CONFIG_COMPAT
long sprd_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#endif

#endif /* _SPRD_DRM_H_ */
