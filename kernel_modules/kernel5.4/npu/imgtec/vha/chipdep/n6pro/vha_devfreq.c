/*
 * DVFS functions for qogirn6pro NPU.
 *
 * Copyright (C) 2018 Spreadtrum Communications Inc.
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

#include <linux/err.h>
#include <linux/device.h>
#include <linux/of_platform.h>
#include <linux/devfreq.h>
#include <linux/pm_opp.h>
#include <linux/sprd_sip_svc.h>
#include <linux/kernel.h>
#include <linux/thermal.h>
#include <linux/version.h>

#include "vha_common.h"
#include "vha_chipdep.h"
#include "vha_devfreq.h"
#include "vha_cooling.h"

#define VHA_POLL_MS           30
#define VHA_UPTHRESHOLD       85
#define VHA_DOWNDIFFERENTIAL  10
#define NNA_DEFAULT_FREQ      307200
#define HIGH_TEMPERATURE      65000
#define LOW_TEMPERATURE       60000

struct npu_ops {
	int (*set_freq) (uint32_t freq_khz);
	int (*disable_idle) (void);
	int (*get_max_state) (uint32_t *max_state);
	int (*get_opp) (uint32_t index, uint32_t *freq_khz, uint32_t *volt);
	int (*set_volts) (uint32_t high_temp);
};

struct npu_dvfs_state {
	ktime_t start_stamp;
	ktime_t busy_stamp;
	unsigned long busy_time;
	bool npu_active;
	spinlock_t lock;
};

struct npu_dvfs_context {
	bool npu_on;
	int npu_dvfs_on;
	int max_on;
	bool high_temp;
	struct semaphore *sem;
	struct npu_ops ops;
	uint32_t last_freq_khz;
	uint32_t max_freq_khz;
	uint32_t max_state;
	struct thermal_zone_device *npu_tz;
	struct npu_dvfs_state cur_state;
	struct devfreq_dev_profile npu_dp;
	struct devfreq *devfreq;
	struct devfreq_simple_ondemand_data data;
};

DEFINE_SEMAPHORE(npu_dvfs_sem);
static struct npu_dvfs_context npu_dvfs_ctx=
{
	.npu_on = false,
	.npu_dvfs_on = 0,
	.max_on = 0,
	.max_freq_khz = 0,
	.max_state = 0,
	.high_temp = false,
	.cur_state.npu_active = false,
	.sem=&npu_dvfs_sem,
};


static void vha_set_freq(unsigned long freq_khz)
{
	if (npu_dvfs_ctx.npu_on)
		npu_dvfs_ctx.ops.set_freq(freq_khz);
	npu_dvfs_ctx.last_freq_khz = freq_khz > npu_dvfs_ctx.max_freq_khz ?
					npu_dvfs_ctx.max_freq_khz : freq_khz;
}

static ssize_t force_npu_freq_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long force_freq_khz;

	if (npu_dvfs_ctx.npu_dvfs_on || npu_dvfs_ctx.max_on)
		return count;

	sscanf(buf, "%lu\n", &force_freq_khz);

	down(npu_dvfs_ctx.sem);
	vha_set_freq(force_freq_khz);
	up(npu_dvfs_ctx.sem);

	return count;
}

static ssize_t force_npu_freq_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t count = 0;

	count = sprintf(buf, "%d\n", npu_dvfs_ctx.last_freq_khz);
	return count;
}

static ssize_t npu_max_on_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	int max_on = 0;

	sscanf(buf, "%u\n", &max_on);
#ifdef VHA_DEVFREQ
	vha_set_max_freq(max_on);
#endif
	return count;
}

static ssize_t npu_max_on_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t count = 0;

	count = sprintf(buf, "%d\n", npu_dvfs_ctx.max_on);
	return count;
}

static ssize_t npu_auto_dvfs_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t count = 0;

	count = sprintf(buf, "%d\n", npu_dvfs_ctx.npu_dvfs_on);
	return count;
}

static ssize_t npu_auto_dvfs_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned int enable;

	sscanf(buf, "%u\n", &enable);

	if (npu_dvfs_ctx.max_on)
		return count;

	down(npu_dvfs_ctx.sem);
	if (enable == 1)
		npu_dvfs_ctx.npu_dvfs_on = 1;
	else if (enable == 0)
		npu_dvfs_ctx.npu_dvfs_on = 0;
	up(npu_dvfs_ctx.sem);

	return count;
}

static DEVICE_ATTR(force_npu_freq, 0664,
		force_npu_freq_show, force_npu_freq_store);
static DEVICE_ATTR(npu_auto_dvfs, 0664,
		npu_auto_dvfs_show, npu_auto_dvfs_store);
static DEVICE_ATTR(npu_max_on, 0664,
		npu_max_on_show, npu_max_on_store);

static struct attribute *dev_entries[] = {
	&dev_attr_force_npu_freq.attr,
	&dev_attr_npu_auto_dvfs.attr,
	&dev_attr_npu_max_on.attr,
	NULL,
};

static struct attribute_group dev_attr_group = {
	.attrs  = dev_entries,
};

int vha_set_max_freq(int max)
{
	down(npu_dvfs_ctx.sem);
	if (npu_dvfs_ctx.max_on == max)
		goto out;
	npu_dvfs_ctx.max_on = max;

	if (max == 1) {
		npu_dvfs_ctx.npu_dvfs_on = 0;
		vha_set_freq(npu_dvfs_ctx.max_freq_khz);
	} else {
		npu_dvfs_ctx.npu_dvfs_on = 1;
	}
out:
	up(npu_dvfs_ctx.sem);
	return 0;
}

int vha_dvfs_ctx_init(struct device *dev)
{
	int ret = 0;
	uint32_t default_freq_khz;
	struct sprd_sip_svc_handle *sip;
	struct sprd_sip_svc_npu_ops *ops;

	sip = sprd_sip_svc_get_handle();
	if (!sip) {
		dev_err(dev, "npu sip handle get error\n");
		return -EINVAL;
	}

	ops = &sip->npu_ops;

	npu_dvfs_ctx.ops.set_freq = ops->set_freq;
	npu_dvfs_ctx.ops.disable_idle = ops->disable_idle;
	npu_dvfs_ctx.ops.get_max_state = ops->get_max_state;
	npu_dvfs_ctx.ops.get_opp = ops->get_opp;
	npu_dvfs_ctx.ops.set_volts = ops->set_volts;

	spin_lock_init(&npu_dvfs_ctx.cur_state.lock);

	ret = sysfs_create_group(&(dev->kobj), &dev_attr_group);
	if (ret) {
		dev_err(dev, "sysfs create fail: %d\n", ret);
		return ret;
	}

	ret = of_property_read_u32(dev->of_node, "sprd,npu_freq_default", &default_freq_khz);
	if (ret) {
		dev_warn(dev, "read dvfs default fail: %d\n", ret);
		default_freq_khz = NNA_DEFAULT_FREQ;
	}

	npu_dvfs_ctx.last_freq_khz = default_freq_khz;

	ret = npu_dvfs_ctx.ops.get_max_state(&npu_dvfs_ctx.max_state);

	npu_dvfs_ctx.ops.set_volts(0);

	return ret;
}

int vha_dvfs_ctx_deinit(struct device *dev)
{
	sysfs_remove_group(&(dev->kobj), &dev_attr_group);

	return 0;
}

void vha_update_dvfs_state(bool npu_active)
{
	unsigned long flags;
	ktime_t cur = ktime_get();

	if (!npu_dvfs_ctx.devfreq)
		return;

	spin_lock_irqsave(&npu_dvfs_ctx.cur_state.lock, flags);
	//if npu is active and no busy_stamp then set busy_stamp to current
	if (npu_active && !npu_dvfs_ctx.cur_state.busy_stamp)
		npu_dvfs_ctx.cur_state.busy_stamp = cur;

	if (!npu_active) {
		//if npu is not active and has busy_stamp then calculate busy_time
		if (npu_dvfs_ctx.cur_state.busy_stamp)
			npu_dvfs_ctx.cur_state.busy_time = ktime_us_delta(cur,
				npu_dvfs_ctx.cur_state.busy_stamp);
		//reset busy_stamp
		npu_dvfs_ctx.cur_state.busy_stamp = 0;
	}

	npu_dvfs_ctx.cur_state.npu_active = npu_active;
	spin_unlock_irqrestore(&npu_dvfs_ctx.cur_state.lock, flags);
}

static int vha_devfreq_target(struct device *dev, unsigned long *freq, u32 flags)
{
	struct dev_pm_opp *opp;
	unsigned long exact_freq;

	/* get appropriate opp*/
	opp = devfreq_recommended_opp(dev, freq, flags);
	if (IS_ERR_OR_NULL(opp)) {
		dev_err(dev, "Failed to get opp (%ld)\n", PTR_ERR(opp));
		return PTR_ERR(opp);
	}
	/* get frequency*/
	exact_freq = dev_pm_opp_get_freq(opp);
	dev_pm_opp_put(opp);
	if (exact_freq == npu_dvfs_ctx.last_freq_khz * 1000UL)
		goto out;

	down(npu_dvfs_ctx.sem);
	if (npu_dvfs_ctx.npu_on == 0 || npu_dvfs_ctx.npu_dvfs_on == 0)
		goto up_out;

	vha_set_freq(exact_freq / 1000UL);
up_out:
	up(npu_dvfs_ctx.sem);
out:
	*freq = exact_freq;
	return 0;
}

static int vha_devfreq_cur_freq(struct device *dev, unsigned long *freq)
{
	*freq = npu_dvfs_ctx.last_freq_khz * 1000UL;
	return 0;
}

static int vha_devfreq_status(struct device *dev, struct devfreq_dev_status *state)
{
	int temp, ret;
	unsigned long flags;
	ktime_t cur;

	if (!npu_dvfs_ctx.devfreq)
		return -EINVAL;

	memset(state, 0, sizeof(*state));
	cur = ktime_get();
	spin_lock_irqsave(&npu_dvfs_ctx.cur_state.lock, flags);
	state->current_frequency = npu_dvfs_ctx.last_freq_khz * 1000UL;
	if (npu_dvfs_ctx.cur_state.start_stamp) {
		if (npu_dvfs_ctx.cur_state.busy_stamp)
			npu_dvfs_ctx.cur_state.busy_time = ktime_us_delta(cur,
				npu_dvfs_ctx.cur_state.busy_stamp);
		state->busy_time = npu_dvfs_ctx.cur_state.busy_time;
		state->total_time = ktime_us_delta(cur, npu_dvfs_ctx.cur_state.start_stamp);
	}
	//reset start_stamp and busy_time for next window
	npu_dvfs_ctx.cur_state.start_stamp = cur;
	npu_dvfs_ctx.cur_state.busy_time = 0;
	//if npu is active, update busy_stamp for next window
	if (npu_dvfs_ctx.cur_state.npu_active)
		npu_dvfs_ctx.cur_state.busy_stamp = cur;
	spin_unlock_irqrestore(&npu_dvfs_ctx.cur_state.lock, flags);

	if (IS_ERR_OR_NULL(npu_dvfs_ctx.npu_tz) ||
			!npu_dvfs_ctx.npu_tz->ops->get_temp)
		goto out;

	ret = npu_dvfs_ctx.npu_tz->ops->get_temp(npu_dvfs_ctx.npu_tz, &temp);
	if (ret) {
		dev_warn(dev, "failed to get npu temp\n");
		goto out;
	}
	dev_dbg(dev, "cur_temp = %d\n", temp);
	down(npu_dvfs_ctx.sem);
	if (temp >= HIGH_TEMPERATURE) {
		if (!npu_dvfs_ctx.high_temp) {
			npu_dvfs_ctx.ops.set_volts(1);
			npu_dvfs_ctx.high_temp = true;
		}
	} else if (temp <= LOW_TEMPERATURE) {
		if (npu_dvfs_ctx.high_temp) {
			npu_dvfs_ctx.ops.set_volts(0);
			npu_dvfs_ctx.high_temp = false;
		}
	}
	up(npu_dvfs_ctx.sem);
out:
	return 0;
}

int vha_devfreq_init(struct device *dev)
{
	struct devfreq_dev_profile *dp;

	int ret = 0, i;
	uint32_t freq_khz, volt;

	for (i = 0; i < npu_dvfs_ctx.max_state; i++) {
		npu_dvfs_ctx.ops.get_opp(i, &freq_khz, &volt);
		ret = dev_pm_opp_add(dev, freq_khz * 1000UL, volt);
		if (ret) {
			dev_err(dev, "failed to add dev_pm_opp: %d\n", ret);
			return ret;
		}
	}

	dp = &npu_dvfs_ctx.npu_dp;
	dp->polling_ms = VHA_POLL_MS;
	dp->initial_freq = npu_dvfs_ctx.last_freq_khz * 1000UL;
	dp->target = vha_devfreq_target;
	dp->get_cur_freq = vha_devfreq_cur_freq;
	dp->get_dev_status = vha_devfreq_status;

	npu_dvfs_ctx.data.upthreshold = VHA_UPTHRESHOLD;
	npu_dvfs_ctx.data.downdifferential = VHA_DOWNDIFFERENTIAL;

	npu_dvfs_ctx.devfreq = devm_devfreq_add_device(dev, dp, "simple_ondemand",
			&npu_dvfs_ctx.data);
	if (IS_ERR(npu_dvfs_ctx.devfreq)) {
		dev_err(dev, "add devfreq device fail\n");
		ret = (int)PTR_ERR(npu_dvfs_ctx.devfreq);
		goto devfreq_add_device_failed;
	}

	npu_dvfs_ctx.devfreq->scaling_max_freq = dp->freq_table[dp->max_state - 1];
	npu_dvfs_ctx.devfreq->scaling_min_freq = dp->freq_table[0];

	npu_dvfs_ctx.max_freq_khz = dp->freq_table[dp->max_state - 1] / 1000UL;
	npu_dvfs_ctx.npu_dvfs_on = 1;

	ret = devfreq_register_opp_notifier(dev, npu_dvfs_ctx.devfreq);
	if (ret) {
		dev_err(dev, "Failed to register OPP notifier (%d)\n", ret);
		goto devfreq_register_opp_notifier_failed;
	}

	vha_cooling_register(npu_dvfs_ctx.devfreq);

	npu_dvfs_ctx.npu_tz = thermal_zone_get_zone_by_name("ai0-thmzone");
	if (IS_ERR_OR_NULL(npu_dvfs_ctx.npu_tz)) {
		dev_err(dev, "Failed to get ai thermal zone\n");
		ret = -EFAULT;
		goto get_ai_thermal_zone_failed;
	}

	return ret;

get_ai_thermal_zone_failed:
	vha_cooling_unregister();
	devfreq_unregister_opp_notifier(dev, npu_dvfs_ctx.devfreq);
devfreq_register_opp_notifier_failed:
	devm_devfreq_remove_device(dev, npu_dvfs_ctx.devfreq);
	npu_dvfs_ctx.devfreq = NULL;
	npu_dvfs_ctx.npu_dvfs_on = 0;
devfreq_add_device_failed:
	dev_pm_opp_of_remove_table(dev);

	return ret;
}

void vha_devfreq_term(struct device *dev)
{
	if (!npu_dvfs_ctx.devfreq)
		return;

	dev_dbg(dev, "Term NPU devfreq\n");

	vha_cooling_unregister();

	dev_pm_opp_of_remove_table(dev);

	devfreq_unregister_opp_notifier(dev, npu_dvfs_ctx.devfreq);
	npu_dvfs_ctx.npu_on = false;
}

void vha_devfreq_suspend(void)
{
	unsigned long flags;
	if (npu_dvfs_ctx.devfreq) {
		devfreq_suspend_device(npu_dvfs_ctx.devfreq);
		spin_lock_irqsave(&npu_dvfs_ctx.cur_state.lock, flags);
		npu_dvfs_ctx.cur_state.busy_time = 0;
		spin_unlock_irqrestore(&npu_dvfs_ctx.cur_state.lock, flags);
		down(npu_dvfs_ctx.sem);
		npu_dvfs_ctx.npu_on = false;
		up(npu_dvfs_ctx.sem);
	}
	return;
}

void vha_devfreq_resume(void)
{
	unsigned long flags;
	ktime_t cur = ktime_get();

	if (npu_dvfs_ctx.devfreq) {
		down(npu_dvfs_ctx.sem);
		npu_dvfs_ctx.npu_on = true;
		npu_dvfs_ctx.ops.disable_idle();
		vha_set_freq(npu_dvfs_ctx.last_freq_khz);
		up(npu_dvfs_ctx.sem);
		spin_lock_irqsave(&npu_dvfs_ctx.cur_state.lock, flags);
		npu_dvfs_ctx.cur_state.start_stamp = cur;
		npu_dvfs_ctx.cur_state.busy_stamp = 0;
		spin_unlock_irqrestore(&npu_dvfs_ctx.cur_state.lock, flags);
		devfreq_resume_device(npu_dvfs_ctx.devfreq);
	}
	return;
}
