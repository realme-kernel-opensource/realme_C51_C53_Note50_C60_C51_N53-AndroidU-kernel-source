// SPDX-License-Identifier: GPL-2.0
//
// UNISOC APCPU POWER STAT driver
//
// Copyright (C) 2020 Unisoc, Inc.

#include <linux/device.h>
#include <linux/io.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/proc_fs.h>
#include <linux/regmap.h>
#include <linux/seq_file.h>
#include <linux/sipc.h>
#include <linux/slab.h>
#include <linux/soc/sprd/sprd_systimer.h>
#include "sprd_pdbg_comm.h"
#include "sprd_slp_info.h"

enum {
	STAGE_SLP_ENTER,
	STAGE_SLP_EXIT,
	STAGE_INFO_GET,
};

enum {
	INFO_SLP_CNT,
	INFO_SLP_STAT,
	INFO_SLP_TIME,
};

#define INFO_LEN 512
#define TO_MASK(x) BIT(x)
#define MASK_AP_SOC (TO_MASK(SYS_AP) | TO_MASK(SYS_SOC))
#define TYPE_ALL (0xffffffff)
#define HWLOCK_TIMEOUT (5000)

static void slp_info_update_ap(struct subsys_slp_info_data *info_data, u32 stage);
static void slp_info_update_soc(struct subsys_slp_info_data *info_data, u32 stage);
static void slp_info_update_shmem(struct subsys_slp_info_data *info_data, u32 stage);
static void slp_info_update_shmem_ext(struct subsys_slp_info_data *info_data);

static struct slp_info_var slp_info_vars[] = {
	[SYS_AP]    = {"AP",    slp_info_update_ap,    NULL},
	[SYS_SOC]   = {"SOC",   slp_info_update_soc,   NULL},
	[SYS_PHYCP] = {"PHYCP", slp_info_update_shmem, NULL},
	[SYS_PSCP]  = {"PSCP",  slp_info_update_shmem, NULL},
	[SYS_PUBCP] = {"PUBCP", slp_info_update_shmem, NULL},
	[SYS_WTLCP] = {"WTLCP", slp_info_update_shmem, NULL},
	[SYS_WCN_BTWF] = {"WCN_BTWF", slp_info_update_shmem, slp_info_update_shmem_ext},
	[SYS_WCN_GNSS] = {"WCN_GNSS", slp_info_update_shmem, slp_info_update_shmem_ext},
};

static u32 slp_info_reg_read(struct subsys_slp_info_data *info_data, u32 info_type)
{
	u32 out_val;
	int ret;
	struct slp_info_reg *info_reg;

	switch (info_type) {
	case INFO_SLP_CNT:
		info_reg = &info_data->slp_cnt;
		break;
	case INFO_SLP_STAT:
		info_reg = &info_data->slp_state;
		break;
	case INFO_SLP_TIME:
		info_reg = &info_data->slp_time;
		break;
	default:
		return 0;
	}

	ret = regmap_read(info_reg->map, info_reg->reg, &out_val);
	if (ret) {
		SPRD_PDBG_ERR("slp_info_reg_read err: reg[%d], ret %d\n", info_reg->reg, ret);
		return ret;
	}

	out_val = ((out_val >> info_reg->offset) & info_reg->mask);

	return out_val;
}

static void slp_info_caculate(struct subsys_slp_info_data *info_data, u32 info_type, u32 cur_val)
{
	struct subsys_slp_info *slp_info = info_data->slp_info;
	u32 last_val, mask, delta;
	u64 *cal_val;

	switch (info_type) {
	case INFO_SLP_CNT:
		last_val = info_data->slp_cnt.last_val;
		mask = info_data->slp_cnt.mask;
		cal_val = &slp_info->total_slp_cnt;
		break;
	case INFO_SLP_TIME:
		last_val = info_data->slp_time.last_val;
		mask = info_data->slp_time.mask;
		cal_val = &slp_info->total_slp_time;
		break;
	default:
		return;
	}

	delta = ((cur_val >= last_val) ? (cur_val - last_val) : (mask - last_val + cur_val));
	*cal_val += delta;
}

static void slp_info_update_ap(struct subsys_slp_info_data *info_data, u32 stage)
{
	u64 slp_time;
	u32 cur_slp_cnt;
	struct subsys_slp_info *slp_info = NULL;
	struct slp_info_reg *slp_cnt = NULL;

	if (!info_data || !info_data->slp_cnt.map)
		return;

	if (stage > STAGE_INFO_GET)
		return;

	slp_info = info_data->slp_info;
	slp_cnt = &info_data->slp_cnt;
	switch (stage) {
	case STAGE_SLP_ENTER:
		slp_cnt->last_val = slp_info_reg_read(info_data, INFO_SLP_CNT);
		slp_info->last_enter_time = sprd_sysfrt_read();
		break;
	case STAGE_SLP_EXIT:
		cur_slp_cnt = slp_info_reg_read(info_data, INFO_SLP_CNT);
		slp_info->last_exit_time = sprd_sysfrt_read();
		slp_time = slp_info->last_exit_time - slp_info->last_enter_time;
		if (cur_slp_cnt != slp_cnt->last_val)
			slp_info->total_slp_time += slp_time;
		slp_info_caculate(info_data, INFO_SLP_CNT, cur_slp_cnt);
		break;
	case STAGE_INFO_GET:
		slp_info->cur_slp_state = 0;
		slp_info->total_time = sprd_sysfrt_read();
		info_data->slp_info_get = *slp_info;
		break;
	default:
		break;
	}
}

static void slp_info_update_soc(struct subsys_slp_info_data *info_data, u32 stage)
{
	u32 cur_slp_time, cur_slp_cnt;
	struct subsys_slp_info *slp_info = NULL;
	struct slp_info_reg *slp_time = NULL, *slp_cnt = NULL;

	if (!info_data || !info_data->slp_time.map || !info_data->slp_cnt.map)
		return;

	if (stage > STAGE_INFO_GET)
		return;

	slp_info = info_data->slp_info;
	slp_time = &info_data->slp_time;
	slp_cnt = &info_data->slp_cnt;
	switch (stage) {
	case STAGE_SLP_ENTER:
		slp_time->last_val = slp_info_reg_read(info_data, INFO_SLP_TIME);
		slp_cnt->last_val = slp_info_reg_read(info_data, INFO_SLP_CNT);
		break;
	case STAGE_SLP_EXIT:
		cur_slp_time = slp_info_reg_read(info_data, INFO_SLP_TIME);
		cur_slp_cnt = slp_info_reg_read(info_data, INFO_SLP_CNT);
		slp_info_caculate(info_data, INFO_SLP_TIME, cur_slp_time);
		slp_info_caculate(info_data, INFO_SLP_CNT, cur_slp_cnt);

		break;
	case STAGE_INFO_GET:
		slp_info->last_enter_time = 0;/* not support */
		slp_info->last_exit_time = 0;/* not support */
		slp_info->cur_slp_state = 0;
		slp_info->total_time = sprd_sysfrt_read();
		info_data->slp_info_get = *slp_info;
		break;
	default:
		break;
	}
}

static void slp_total_time_compensate(struct subsys_slp_info *slp_info, u32 cur_state)
{
	u64 delta = 0;

	if (!cur_state)
		return;

	if (slp_info->total_time < slp_info->last_enter_time) {
		SPRD_PDBG_ERR("time_compensate err: total %lu, enter %lu\n",
			slp_info->total_time, slp_info->last_enter_time);
		return;
	}

	delta = slp_info->total_time - slp_info->last_enter_time;
	slp_info->total_slp_time += delta;
}

static void slp_info_update_shmem(struct subsys_slp_info_data *info_data, u32 stage)
{
	int ret = -1;
	struct subsys_slp_info *slp_info_get = NULL;

	if (!info_data || !info_data->slp_state.map)
		return;

	if (stage != STAGE_INFO_GET)
		return;

	slp_info_get = &info_data->slp_info_get;

	ret = hwspin_lock_timeout_raw(info_data->lock->hwlock, HWLOCK_TIMEOUT);
	if (ret) {
		SPRD_PDBG_ERR("timeout to get the hwspinlock\n");
		return;
	}

	*slp_info_get = *(info_data->slp_info);

	hwspin_unlock_raw(info_data->lock->hwlock);

	slp_info_get->cur_slp_state = slp_info_reg_read(info_data, INFO_SLP_STAT);
	slp_info_get->total_time = sprd_sysfrt_read();
	slp_total_time_compensate(slp_info_get, slp_info_get->cur_slp_state);
}

static void slp_info_update_shmem_ext(struct subsys_slp_info_data *data)
{
	if (!data || !data->slp_info)
		return;

	pdbg_notifier_call_chain(data->index, data->slp_info);

	data->slp_info_get = *(data->slp_info);
}

static int sprd_slp_info_dt_parse(struct device *dev, struct slp_info_data *data)
{
	int i = 0, ret;
	unsigned int args[3];
	u32 index, info_vars_size = ARRAY_SIZE(slp_info_vars);
	struct device_node *np_child;
	struct subsys_slp_info_data *slp_info_data;

	data->slp_infos_cnt = of_get_child_count(dev->of_node);
	if (data->slp_infos_cnt <= 0) {
		SPRD_PDBG_ERR("%s: slp_infos_cnt error\n", __func__);
		return -ENXIO;
	}

	data->slp_infos = devm_kcalloc(dev, data->slp_infos_cnt, sizeof(struct subsys_slp_info_data),
				       GFP_KERNEL);
	if (!data->slp_infos) {
		SPRD_PDBG_ERR("%s: subsys_slp_info_data alloc error\n", __func__);
		return -ENOMEM;
	}

	for_each_child_of_node(dev->of_node, np_child) {
		slp_info_data = &data->slp_infos[i++];

		ret = of_property_read_u32(np_child, "subsys,index", &index);
		if (ret) {
			SPRD_PDBG_ERR("Fail to find type property\n");
			return -ENXIO;
		}

		if (index >= info_vars_size) {
			SPRD_PDBG_ERR("index cfg error\n");
			return -ENXIO;
		}
		slp_info_data->index = index;
		slp_info_data->info_update = slp_info_vars[index].info_update;
		slp_info_data->info_update_ext = slp_info_vars[index].info_update_ext;
		slp_info_data->update_ext = of_property_read_bool(np_child, "subsys,update_ext");
		slp_info_data->lock = &data->lock;

		slp_info_data->slp_cnt.map =
			syscon_regmap_lookup_by_phandle_args(np_child, "subsys,slp_cnt", 3, args);
		if (!IS_ERR_OR_NULL(slp_info_data->slp_cnt.map)) {
			slp_info_data->slp_cnt.reg = args[0];
			slp_info_data->slp_cnt.offset = args[1];
			slp_info_data->slp_cnt.mask = args[2];
		}

		slp_info_data->slp_state.map =
			syscon_regmap_lookup_by_phandle_args(np_child, "subsys,slp_state", 3, args);
		if (!IS_ERR_OR_NULL(slp_info_data->slp_state.map)) {
			slp_info_data->slp_state.reg = args[0];
			slp_info_data->slp_state.offset = args[1];
			slp_info_data->slp_state.mask = args[2];
		}

		slp_info_data->slp_time.map =
			syscon_regmap_lookup_by_phandle_args(np_child, "subsys,slp_time", 3, args);
		if (!IS_ERR_OR_NULL(slp_info_data->slp_time.map)) {
			slp_info_data->slp_time.reg = args[0];
			slp_info_data->slp_time.offset = args[1];
			slp_info_data->slp_time.mask = args[2];
		}
	}

	return 0;
}

static void slp_info_update(struct subsys_slp_info_data *info_data, u32 stage)
{
	if (info_data->update_ext && info_data->info_update_ext)
		info_data->info_update_ext(info_data);
	else if (!info_data->update_ext && info_data->info_update)
		info_data->info_update(info_data, stage);
}

static void slp_info_update_locked(struct slp_info_data *data, u32 type_mask, u32 stage)
{
	struct subsys_slp_info_data *info_data;
	u32 i;

	mutex_lock(&data->lock.mtx);

	for (i = 0; i < data->slp_infos_cnt; i++) {
		info_data = &data->slp_infos[i];

		if (!(type_mask & TO_MASK(info_data->index)))
			continue;

		slp_info_update(info_data, stage);

		if (type_mask == TO_MASK(info_data->index))
			break;
	}

	mutex_unlock(&data->lock.mtx);
}

static int slp_info_show(struct seq_file *seq, void *offset)
{
	struct subsys_slp_info_data *info_data = seq->private;
	struct subsys_slp_info *info = &info_data->slp_info_get;
	char str[INFO_LEN];
	u32 num = 0, i;

	mutex_lock(&info_data->lock->mtx);

	slp_info_update(info_data, STAGE_INFO_GET);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "subsystem_name(%s)");
	num += scnprintf(str + num, INFO_LEN - num, "%20s\n", slp_info_vars[info_data->index].name);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "total_time(%x)");
	num += scnprintf(str + num, INFO_LEN - num, "%20llx\n", info->total_time);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "total_slp_time(%x)");
	num += scnprintf(str + num, INFO_LEN - num, "%20llx\n", info->total_slp_time);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "last_enter_time(%x)");
	num += scnprintf(str + num, INFO_LEN - num, "%20llx\n", info->last_enter_time);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "last_exit_time(%x)");
	num += scnprintf(str + num, INFO_LEN - num, "%20llx\n", info->last_exit_time);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "total_slp_cnt(%x)");
	num += scnprintf(str + num, INFO_LEN - num, "%20llx\n", info->total_slp_cnt);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "cur_slp_state(%x)");
	num += scnprintf(str + num, INFO_LEN - num, "%20x\n", info->cur_slp_state);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "boot_cnt(%x)");
	num += scnprintf(str + num, INFO_LEN - num, "%20x\n", info->boot_cnt);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "last_ws(%x)");
	num += scnprintf(str + num, INFO_LEN - num, "%10x\n", info->last_ws);

	num += scnprintf(str + num, INFO_LEN - num, "%20s:", "ws_cnt(%x)");
	for (i = 0; i < TOP_IRQ_MAX - 1; i++)
		num += scnprintf(str + num, INFO_LEN - num, "%10x ", info->ws_cnt[i]);
	num += scnprintf(str + num, INFO_LEN - num, "%10x\n", info->ws_cnt[i]);

	mutex_unlock(&info_data->lock->mtx);

	seq_printf(seq, "%s\n", str);

	return 0;
}

static int sprd_slp_info_proc_init(struct slp_info_data *data, struct proc_dir_entry *parent)
{
	struct proc_dir_entry *dir;
	struct subsys_slp_info_data *info_data;
	struct subsys_slp_info *info;
	const char *name;
	int i;

	dir = proc_mkdir("slp_info", parent);
	if (!dir) {
		SPRD_PDBG_ERR("Proc slp_info dir create failed\n");
		return -EBADF;
	}

	for (i = 0; i < data->slp_infos_cnt; i++) {
		info_data = &data->slp_infos[i];
		info = info_data->slp_info;
		name = slp_info_vars[info_data->index].name;
		if (!proc_create_single_data(name, 0644, dir, slp_info_show, info_data)) {
			SPRD_PDBG_ERR("Proc file %s create failed\n", name);
			return -ENODEV;
		}
	}

	return 0;
}

static void slp_info_notify_handler(void *data, unsigned long cmd)
{
	struct slp_info_data *slp_info = data;

	switch (cmd) {
	case SPRD_CPU_PM_ENTER:
		slp_info_update_locked(slp_info, MASK_AP_SOC, STAGE_SLP_ENTER);
		break;
	case SPRD_CPU_PM_EXIT:
		slp_info_update_locked(slp_info, MASK_AP_SOC, STAGE_SLP_EXIT);
		break;
	default:
		break;
	}
}

static void slp_info_devm_action(void *_data)
{
	struct slp_info_data *slp_info = _data;

	mutex_destroy(&slp_info->lock.mtx);
}

static int sprd_slp_info_lock_init(struct device *dev, struct slp_info_data *data)
{
	int id;

	mutex_init(&data->lock.mtx);

	id = of_hwspin_lock_get_id(dev->of_node, 0);
	if (id < 0) {
		SPRD_PDBG_ERR("failed to get hwlock id\n");
		return id;
	}

	data->lock.hwlock = devm_hwspin_lock_request_specific(dev, id);
	if (!data->lock.hwlock) {
		SPRD_PDBG_ERR("failed to request hwlock\n");
		return -ENXIO;
	}

	return 0;
}

static int sprd_slp_info_rmem_init(struct device *dev, struct slp_info_data *data)
{
	struct device_node *np;
	struct resource r;
	resource_size_t size, size_target;
	int ret, i;
	void __iomem *virt_base, *virt_info;
	struct subsys_slp_info_data *slp_data;

	np = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!np) {
		SPRD_PDBG_ERR("No memory-region specified\n");
		return -EINVAL;
	}

	ret = of_address_to_resource(np, 0, &r);
	of_node_put(np);
	if (ret) {
		SPRD_PDBG_ERR("of_address_to_resource fail\n");
		return ret;
	}

	size = resource_size(&r);
	size_target = SLP_INFO_SIZE * SYS_MAX;
	if (size_target > size) {
		SPRD_PDBG_ERR("rmem_init size error\n");
		return -ENOMEM;
	}

	virt_base = devm_ioremap_wc(dev, r.start, size_target);
	if (!virt_base) {
		SPRD_PDBG_ERR("devm_ioremap_wc fail\n");
		return -ENOMEM;
	}

	for (i = 0; i < data->slp_infos_cnt; i++) {
		slp_data = &data->slp_infos[i];
		virt_info = (virt_base + SLP_INFO_SIZE * slp_data->index);
		slp_data->slp_info = (struct subsys_slp_info *)virt_info;
		memset(slp_data->slp_info, 0, sizeof(struct subsys_slp_info));
	}

	return 0;
}

int sprd_slp_info_init(struct device *dev, struct proc_dir_entry *dir, struct slp_info_data **data)
{
	int ret;
	struct slp_info_data *slp_info;

	*data = NULL;

	if (sprd_sysfrt_read() == 0) {
		SPRD_PDBG_ERR("%s: sysfrt not ready, need check\n", __func__);
		return -ENOENT;
	}

	slp_info = devm_kzalloc(dev, sizeof(struct slp_info_data), GFP_KERNEL);
	if (!slp_info) {
		SPRD_PDBG_ERR("%s: slp_info alloc error\n", __func__);
		return -ENOMEM;
	}

	slp_info->notify_cb = slp_info_notify_handler;

	ret = sprd_slp_info_lock_init(dev, slp_info);
	if (ret) {
		SPRD_PDBG_ERR("%s: sprd_slp_info_lock_init error\n", __func__);
		return ret;
	}

	ret = devm_add_action(dev, slp_info_devm_action, slp_info);
	if (ret) {
		slp_info_devm_action(slp_info);
		SPRD_PDBG_ERR("failed to add slp_info devm action\n");
		return ret;
	}

	ret = sprd_slp_info_dt_parse(dev, slp_info);
	if (ret) {
		SPRD_PDBG_ERR("%s: sprd_slp_info_dt_parse error\n", __func__);
		return ret;
	}

	ret = sprd_slp_info_rmem_init(dev, slp_info);
	if (ret) {
		SPRD_PDBG_ERR("%s: sprd_slp_info_rmem_init error\n", __func__);
		return ret;
	}

	ret = sprd_slp_info_proc_init(slp_info, dir);
	if (ret) {
		SPRD_PDBG_ERR("%s: sprd_slp_info_proc_init error\n", __func__);
		return ret;
	}

	*data = slp_info;

	return 0;
}
