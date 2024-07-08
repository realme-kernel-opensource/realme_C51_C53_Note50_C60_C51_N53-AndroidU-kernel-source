// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 Spreadtrum Communications Inc.
 */

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/of_regulator.h>

/*
 * ump518 regulator base address
 */
#define ump518_REGULATOR_BASE		0x1800

/*
 * ump518 regulator lock register
 */
#define ump518_WR_UNLOCK_VALUE		0x6e7f
#define ump518_PWR_WR_PROT		(ump518_REGULATOR_BASE + 0x3d0)

/*
 * ump518 enable register
 */
#define ump518_POWER_PD_SW		(ump518_REGULATOR_BASE + 0x01c)
#define ump518_LDO_VDDRF18_PD		(ump518_REGULATOR_BASE + 0x10c)
#define ump518_LDO_VDDCAMIO_PD		(ump518_REGULATOR_BASE + 0x118)
#define ump518_LDO_VDDWCN_PD		(ump518_REGULATOR_BASE + 0x11c)
#define ump518_LDO_VDDCAMD1_PD		(ump518_REGULATOR_BASE + 0x128)
#define ump518_LDO_VDDCAMD0_PD		(ump518_REGULATOR_BASE + 0x134)
#define ump518_LDO_VDDRF1V25_PD		(ump518_REGULATOR_BASE + 0x140)
#define ump518_LDO_AVDD12_PD		(ump518_REGULATOR_BASE + 0x14c)
#define ump518_LDO_VDDCAMA0_PD		(ump518_REGULATOR_BASE + 0x158)
#define ump518_LDO_VDDCAMA1_PD		(ump518_REGULATOR_BASE + 0x164)
#define ump518_LDO_VDDCAMMOT_PD		(ump518_REGULATOR_BASE + 0x170)
#define ump518_LDO_VDDSIM0_PD		(ump518_REGULATOR_BASE + 0x17c)
#define ump518_LDO_VDDSIM1_PD		(ump518_REGULATOR_BASE + 0x188)
#define ump518_LDO_VDDSIM2_PD		(ump518_REGULATOR_BASE + 0x194)
#define ump518_LDO_VDDEMMCCORE_PD	(ump518_REGULATOR_BASE + 0x1a0)
#define ump518_LDO_VDDSDCORE_PD		(ump518_REGULATOR_BASE + 0x1ac)
#define ump518_LDO_VDDSDIO_PD		(ump518_REGULATOR_BASE + 0x1b8)
#define ump518_LDO_VDD28_PD		(ump518_REGULATOR_BASE + 0x1c4)
#define ump518_LDO_VDDWIFIPA_PD		(ump518_REGULATOR_BASE + 0x1d0)
#define ump518_LDO_VDD18_DCXO_PD	(ump518_REGULATOR_BASE + 0x1dc)
#define ump518_LDO_VDDUSB33_PD		(ump518_REGULATOR_BASE + 0x1e8)
#define ump518_LDO_VDDLDO0_PD		(ump518_REGULATOR_BASE + 0x1f4)
#define ump518_LDO_VDDLDO1_PD		(ump518_REGULATOR_BASE + 0x200)
#define ump518_LDO_VDDLDO2_PD		(ump518_REGULATOR_BASE + 0x20c)
#define ump518_LDO_VDDLDO3_PD		(ump518_REGULATOR_BASE + 0x530)
#define ump518_LDO_VDDKPLED_PD		(ump518_REGULATOR_BASE + 0x38c)

/*
 * ump518 enable mask
 */
#define ump518_DCDC_CPU_PD_MASK			BIT(4)
#define ump518_DCDC_GPU_PD_MASK			BIT(3)
#define ump518_DCDC_CORE_PD_MASK		BIT(5)
#define ump518_DCDC_MODEM_PD_MASK		BIT(11)
#define ump518_DCDC_MEM_PD_MASK			BIT(6)
#define ump518_DCDC_MEMQ_PD_MASK		BIT(12)
#define ump518_DCDC_GEN0_PD_MASK		BIT(8)
#define ump518_DCDC_GEN1_PD_MASK		BIT(7)
#define ump518_DCDC_SRAM_PD_MASK		BIT(13)
#define ump518_LDO_AVDD18_PD_MASK		BIT(2)
#define ump518_LDO_VDDRF18_PD_MASK		BIT(0)
#define ump518_LDO_VDDCAMIO_PD_MASK		BIT(0)
#define ump518_LDO_VDDWCN_PD_MASK		BIT(0)
#define ump518_LDO_VDDCAMD1_PD_MASK		BIT(0)
#define ump518_LDO_VDDCAMD0_PD_MASK		BIT(0)
#define ump518_LDO_VDDRF1V25_PD_MASK		BIT(0)
#define ump518_LDO_AVDD12_PD_MASK		BIT(0)
#define ump518_LDO_VDDCAMA0_PD_MASK		BIT(0)
#define ump518_LDO_VDDCAMA1_PD_MASK		BIT(0)
#define ump518_LDO_VDDCAMMOT_PD_MASK		BIT(0)
#define ump518_LDO_VDDSIM0_PD_MASK		BIT(0)
#define ump518_LDO_VDDSIM1_PD_MASK		BIT(0)
#define ump518_LDO_VDDSIM2_PD_MASK		BIT(0)
#define ump518_LDO_VDDEMMCCORE_PD_MASK		BIT(0)
#define ump518_LDO_VDDSDCORE_PD_MASK		BIT(0)
#define ump518_LDO_VDDSDIO_PD_MASK		BIT(0)
#define ump518_LDO_VDD28_PD_MASK		BIT(1)
#define ump518_LDO_VDDWIFIPA_PD_MASK		BIT(0)
#define ump518_LDO_VDD18_DCXO_PD_MASK		BIT(10)
#define ump518_LDO_VDDUSB33_PD_MASK		BIT(0)
#define ump518_LDO_VDDLDO0_PD_MASK		BIT(0)
#define ump518_LDO_VDDLDO1_PD_MASK		BIT(0)
#define ump518_LDO_VDDLDO2_PD_MASK		BIT(0)
#define ump518_LDO_VDDLDO3_PD_MASK		BIT(0)
#define ump518_LDO_VDDKPLED_PD_MASK		BIT(15)

/*
 * ump518 vsel register
 */
#define ump518_DCDC_CPU_VOL			(ump518_REGULATOR_BASE + 0x44)
#define ump518_DCDC_GPU_VOL			(ump518_REGULATOR_BASE + 0x54)
#define ump518_DCDC_CORE_VOL			(ump518_REGULATOR_BASE + 0x64)
#define ump518_DCDC_MODEM_VOL			(ump518_REGULATOR_BASE + 0x74)
#define ump518_DCDC_MEM_VOL			(ump518_REGULATOR_BASE + 0x84)
#define ump518_DCDC_MEMQ_VOL			(ump518_REGULATOR_BASE + 0x94)
#define ump518_DCDC_GEN0_VOL			(ump518_REGULATOR_BASE + 0xa4)
#define ump518_DCDC_GEN1_VOL			(ump518_REGULATOR_BASE + 0xb4)
#define ump518_DCDC_WPA_VOL			(ump518_REGULATOR_BASE + 0xc8)
#define ump518_DCDC_SRAM_VOL			(ump518_REGULATOR_BASE + 0xdc)
#define ump518_LDO_AVDD18_VOL			(ump518_REGULATOR_BASE + 0x104)
#define ump518_LDO_VDDRF18_VOL			(ump518_REGULATOR_BASE + 0x110)
#define ump518_LDO_VDDCAMIO_VOL			(ump518_REGULATOR_BASE + 0x28)
#define ump518_LDO_VDDWCN_VOL			(ump518_REGULATOR_BASE + 0x120)
#define ump518_LDO_VDDCAMD1_VOL			(ump518_REGULATOR_BASE + 0x12c)
#define ump518_LDO_VDDCAMD0_VOL			(ump518_REGULATOR_BASE + 0x138)
#define ump518_LDO_VDDRF1V25_VOL		(ump518_REGULATOR_BASE + 0x144)
#define ump518_LDO_AVDD12_VOL			(ump518_REGULATOR_BASE + 0x150)
#define ump518_LDO_VDDCAMA0_VOL			(ump518_REGULATOR_BASE + 0x15c)
#define ump518_LDO_VDDCAMA1_VOL			(ump518_REGULATOR_BASE + 0x168)
#define ump518_LDO_VDDCAMMOT_VOL		(ump518_REGULATOR_BASE + 0x174)
#define ump518_LDO_VDDSIM0_VOL			(ump518_REGULATOR_BASE + 0x180)
#define ump518_LDO_VDDSIM1_VOL			(ump518_REGULATOR_BASE + 0x18c)
#define ump518_LDO_VDDSIM2_VOL			(ump518_REGULATOR_BASE + 0x198)
#define ump518_LDO_VDDEMMCCORE_VOL		(ump518_REGULATOR_BASE + 0x1a4)
#define ump518_LDO_VDDSDCORE_VOL		(ump518_REGULATOR_BASE + 0x1b0)
#define ump518_LDO_VDDSDIO_VOL			(ump518_REGULATOR_BASE + 0x1bc)
#define ump518_LDO_VDD28_VOL			(ump518_REGULATOR_BASE + 0x1c8)
#define ump518_LDO_VDDWIFIPA_VOL		(ump518_REGULATOR_BASE + 0x1d4)
#define ump518_LDO_VDD18_DCXO_VOL		(ump518_REGULATOR_BASE + 0x1e0)
#define ump518_LDO_VDDUSB33_VOL			(ump518_REGULATOR_BASE + 0x1ec)
#define ump518_LDO_VDDLDO0_VOL			(ump518_REGULATOR_BASE + 0x1f8)
#define ump518_LDO_VDDLDO1_VOL			(ump518_REGULATOR_BASE + 0x204)
#define ump518_LDO_VDDLDO2_VOL			(ump518_REGULATOR_BASE + 0x210)
#define ump518_LDO_VDDLDO3_VOL			(ump518_REGULATOR_BASE + 0x530)
#define ump518_LDO_VDDKPLED_VOL			(ump518_REGULATOR_BASE + 0x38c)

/*
 * ump518 vsel register mask
 */
#define ump518_DCDC_CPU_VOL_MASK		GENMASK(8, 0)
#define ump518_DCDC_GPU_VOL_MASK		GENMASK(8, 0)
#define ump518_DCDC_CORE_VOL_MASK		GENMASK(8, 0)
#define ump518_DCDC_MODEM_VOL_MASK		GENMASK(8, 0)
#define ump518_DCDC_MEM_VOL_MASK		GENMASK(7, 0)
#define ump518_DCDC_MEMQ_VOL_MASK		GENMASK(8, 0)
#define ump518_DCDC_GEN0_VOL_MASK		GENMASK(7, 0)
#define ump518_DCDC_GEN1_VOL_MASK		GENMASK(7, 0)
#define ump518_DCDC_WPA_VOL_MASK		GENMASK(7, 0)
#define ump518_DCDC_SRAM_VOL_MASK		GENMASK(8, 0)
#define ump518_LDO_AVDD18_VOL_MASK		GENMASK(5, 0)
#define ump518_LDO_VDDRF18_VOL_MASK		GENMASK(5, 0)
#define ump518_LDO_VDDCAMIO_VOL_MASK		GENMASK(5, 0)
#define ump518_LDO_VDDWCN_VOL_MASK		GENMASK(5, 0)
#define ump518_LDO_VDDCAMD1_VOL_MASK		GENMASK(4, 0)
#define ump518_LDO_VDDCAMD0_VOL_MASK		GENMASK(4, 0)
#define ump518_LDO_VDDRF1V25_VOL_MASK		GENMASK(4, 0)
#define ump518_LDO_AVDD12_VOL_MASK		GENMASK(4, 0)
#define ump518_LDO_VDDCAMA0_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDCAMA1_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDCAMMOT_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDSIM0_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDSIM1_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDSIM2_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDEMMCCORE_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDSDCORE_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDSDIO_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDD28_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDWIFIPA_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDD18_DCXO_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDUSB33_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDLDO0_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDLDO1_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDLDO2_VOL_MASK		GENMASK(7, 0)
#define ump518_LDO_VDDLDO3_VOL_MASK		GENMASK(9, 2)
#define ump518_LDO_VDDKPLED_VOL_MASK		GENMASK(14, 7)

enum ump518_regulator_id {
	ump518_DCDC_CPU,
	ump518_DCDC_GPU,
	ump518_DCDC_CORE,
	ump518_DCDC_MODEM,
	ump518_DCDC_MEM,
	ump518_DCDC_MEMQ,
	ump518_DCDC_GEN0,
	ump518_DCDC_GEN1,
	ump518_DCDC_WPA,
	ump518_DCDC_SRAM,
	ump518_LDO_AVDD18,
	ump518_LDO_VDDRF18,
	ump518_LDO_VDDCAMIO,
	ump518_LDO_VDDWCN,
	ump518_LDO_VDDCAMD1,
	ump518_LDO_VDDCAMD0,
	ump518_LDO_VDDRF1V25,
	ump518_LDO_AVDD12,
	ump518_LDO_VDDCAMA0,
	ump518_LDO_VDDCAMA1,
	ump518_LDO_VDDCAMMOT,
	ump518_LDO_VDDSIM0,
	ump518_LDO_VDDSIM1,
	ump518_LDO_VDDSIM2,
	ump518_LDO_VDDEMMCCORE,
	ump518_LDO_VDDSDCORE,
	ump518_LDO_VDDSDIO,
	ump518_LDO_VDD28,
	ump518_LDO_VDDWIFIPA,
	ump518_LDO_VDD18_DCXO,
	ump518_LDO_VDDUSB33,
	ump518_LDO_VDDLDO0,
	ump518_LDO_VDDLDO1,
	ump518_LDO_VDDLDO2,
	ump518_LDO_VDDLDO3,
	ump518_LDO_VDDKPLED,
};

static struct dentry *debugfs_root;

static const struct regulator_ops ump518_regu_linear_ops = {
	.enable = regulator_enable_regmap,
	.disable = regulator_disable_regmap,
	.is_enabled = regulator_is_enabled_regmap,
	.list_voltage = regulator_list_voltage_linear,
	.get_voltage_sel = regulator_get_voltage_sel_regmap,
	.set_voltage_sel = regulator_set_voltage_sel_regmap,
};

#define ump518_REGU_LINEAR(_id, en_reg, en_mask, vreg, vmask,	\
			   vstep, vmin, vmax, min_sel) {	\
	.name			= #_id,				\
	.of_match		= of_match_ptr(#_id),		\
	.ops			= &ump518_regu_linear_ops,	\
	.type			= REGULATOR_VOLTAGE,		\
	.id			= ump518_##_id,			\
	.owner			= THIS_MODULE,			\
	.min_uV			= vmin,				\
	.n_voltages		= ((vmax) - (vmin)) / (vstep) + 1,	\
	.uV_step		= vstep,			\
	.enable_is_inverted	= true,				\
	.enable_val		= 0,				\
	.enable_reg		= en_reg,			\
	.enable_mask		= en_mask,			\
	.vsel_reg		= vreg,				\
	.vsel_mask		= vmask,			\
	.linear_min_sel		= min_sel,			\
}

static struct regulator_desc regulators[] = {
	ump518_REGU_LINEAR(DCDC_CPU, ump518_POWER_PD_SW,
			   ump518_DCDC_CPU_PD_MASK, ump518_DCDC_CPU_VOL,
			   ump518_DCDC_CPU_VOL_MASK, 3125, 0, 1596875, 0),
	ump518_REGU_LINEAR(DCDC_GPU, ump518_POWER_PD_SW,
			   ump518_DCDC_GPU_PD_MASK, ump518_DCDC_GPU_VOL,
			   ump518_DCDC_GPU_VOL_MASK, 3125, 0, 1596875, 0),
	ump518_REGU_LINEAR(DCDC_CORE, ump518_POWER_PD_SW,
			   ump518_DCDC_CORE_PD_MASK, ump518_DCDC_CORE_VOL,
			   ump518_DCDC_CORE_VOL_MASK, 3125, 0, 1596875, 0),
	ump518_REGU_LINEAR(DCDC_MODEM, ump518_POWER_PD_SW,
			   ump518_DCDC_MODEM_PD_MASK, ump518_DCDC_MODEM_VOL,
			   ump518_DCDC_MODEM_VOL_MASK, 3125, 0, 1596875, 0),
	ump518_REGU_LINEAR(DCDC_MEM, ump518_POWER_PD_SW,
			   ump518_DCDC_MEM_PD_MASK, ump518_DCDC_MEM_VOL,
			   ump518_DCDC_MEM_VOL_MASK, 6250, 0, 1593750, 0),
	ump518_REGU_LINEAR(DCDC_MEMQ, ump518_POWER_PD_SW,
			   ump518_DCDC_MEMQ_PD_MASK, ump518_DCDC_MEMQ_VOL,
			   ump518_DCDC_MEMQ_VOL_MASK, 3125, 0, 1596875, 0),
	ump518_REGU_LINEAR(DCDC_GEN0, ump518_POWER_PD_SW,
			   ump518_DCDC_GEN0_PD_MASK, ump518_DCDC_GEN0_VOL,
			   ump518_DCDC_GEN0_VOL_MASK, 9375, 20000, 2410625, 0),
	ump518_REGU_LINEAR(DCDC_GEN1, ump518_POWER_PD_SW,
			   ump518_DCDC_GEN1_PD_MASK, ump518_DCDC_GEN1_VOL,
			   ump518_DCDC_GEN1_VOL_MASK, 6250, 50000, 1643750, 0),
	ump518_REGU_LINEAR(DCDC_SRAM, ump518_POWER_PD_SW,
			   ump518_DCDC_SRAM_PD_MASK, ump518_DCDC_SRAM_VOL,
			   ump518_DCDC_SRAM_VOL_MASK, 3125, 0, 1596875, 0),
	ump518_REGU_LINEAR(LDO_AVDD18, ump518_POWER_PD_SW,
			   ump518_LDO_AVDD18_PD_MASK, ump518_LDO_AVDD18_VOL,
			   ump518_LDO_AVDD18_VOL_MASK, 10000, 1175000, 1805000, 0),
	ump518_REGU_LINEAR(LDO_VDDRF18, ump518_LDO_VDDRF18_PD,
			   ump518_LDO_VDDRF18_PD_MASK, ump518_LDO_VDDRF18_VOL,
			   ump518_LDO_VDDRF18_VOL_MASK, 10000, 1175000, 1805000, 0),
	ump518_REGU_LINEAR(LDO_VDDCAMIO, ump518_LDO_VDDCAMIO_PD,
			   ump518_LDO_VDDCAMIO_PD_MASK, ump518_LDO_VDDCAMIO_VOL,
			   ump518_LDO_VDDCAMIO_VOL_MASK, 10000, 1200000, 1830000, 0),
	ump518_REGU_LINEAR(LDO_VDDWCN, ump518_LDO_VDDWCN_PD,
			   ump518_LDO_VDDWCN_PD_MASK, ump518_LDO_VDDWCN_VOL,
			   ump518_LDO_VDDWCN_VOL_MASK, 15000, 900000, 1845000, 0),
	ump518_REGU_LINEAR(LDO_VDDCAMD1, ump518_LDO_VDDCAMD1_PD,
			   ump518_LDO_VDDCAMD1_PD_MASK, ump518_LDO_VDDCAMD1_VOL,
			   ump518_LDO_VDDCAMD1_VOL_MASK, 15000, 900000, 1365000, 0),
	ump518_REGU_LINEAR(LDO_VDDCAMD0, ump518_LDO_VDDCAMD0_PD,
			   ump518_LDO_VDDCAMD0_PD_MASK, ump518_LDO_VDDCAMD0_VOL,
			   ump518_LDO_VDDCAMD0_VOL_MASK, 15000, 900000, 1365000, 0),
	ump518_REGU_LINEAR(LDO_VDDRF1V25, ump518_LDO_VDDRF1V25_PD,
			   ump518_LDO_VDDRF1V25_PD_MASK, ump518_LDO_VDDRF1V25_VOL,
			   ump518_LDO_VDDRF1V25_VOL_MASK, 15000, 900000, 1365000, 0),
	ump518_REGU_LINEAR(LDO_AVDD12, ump518_LDO_AVDD12_PD,
			   ump518_LDO_AVDD12_PD_MASK, ump518_LDO_AVDD12_VOL,
			   ump518_LDO_AVDD12_VOL_MASK, 15000, 900000, 1365000, 0),
	ump518_REGU_LINEAR(LDO_VDDCAMA0, ump518_LDO_VDDCAMA0_PD,
			   ump518_LDO_VDDCAMA0_PD_MASK, ump518_LDO_VDDCAMA0_VOL,
			   ump518_LDO_VDDCAMA0_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDCAMA1, ump518_LDO_VDDCAMA1_PD,
			   ump518_LDO_VDDCAMA1_PD_MASK, ump518_LDO_VDDCAMA1_VOL,
			   ump518_LDO_VDDCAMA1_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDCAMMOT, ump518_LDO_VDDCAMMOT_PD,
			   ump518_LDO_VDDCAMMOT_PD_MASK, ump518_LDO_VDDCAMMOT_VOL,
			   ump518_LDO_VDDCAMMOT_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDSIM2, ump518_LDO_VDDSIM2_PD,
			   ump518_LDO_VDDSIM2_PD_MASK, ump518_LDO_VDDSIM2_VOL,
			   ump518_LDO_VDDSIM2_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDEMMCCORE, ump518_LDO_VDDEMMCCORE_PD,
			   ump518_LDO_VDDEMMCCORE_PD_MASK, ump518_LDO_VDDEMMCCORE_VOL,
			   ump518_LDO_VDDEMMCCORE_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDSDCORE, ump518_LDO_VDDSDCORE_PD,
			   ump518_LDO_VDDSDCORE_PD_MASK, ump518_LDO_VDDSDCORE_VOL,
			   ump518_LDO_VDDSDCORE_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDSDIO, ump518_LDO_VDDSDIO_PD,
			   ump518_LDO_VDDSDIO_PD_MASK, ump518_LDO_VDDSDIO_VOL,
			   ump518_LDO_VDDSDIO_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDD28, ump518_POWER_PD_SW,
			   ump518_LDO_VDD28_PD_MASK, ump518_LDO_VDD28_VOL,
			   ump518_LDO_VDD28_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDWIFIPA, ump518_LDO_VDDWIFIPA_PD,
			   ump518_LDO_VDDWIFIPA_PD_MASK, ump518_LDO_VDDWIFIPA_VOL,
			   ump518_LDO_VDDWIFIPA_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDD18_DCXO, ump518_POWER_PD_SW,
			   ump518_LDO_VDD18_DCXO_PD_MASK, ump518_LDO_VDD18_DCXO_VOL,
			   ump518_LDO_VDD18_DCXO_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDUSB33, ump518_LDO_VDDUSB33_PD,
			   ump518_LDO_VDDUSB33_PD_MASK, ump518_LDO_VDDUSB33_VOL,
			   ump518_LDO_VDDUSB33_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDLDO0, ump518_LDO_VDDLDO0_PD,
			   ump518_LDO_VDDLDO0_PD_MASK, ump518_LDO_VDDLDO0_VOL,
			   ump518_LDO_VDDLDO0_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDLDO1, ump518_LDO_VDDLDO1_PD,
			   ump518_LDO_VDDLDO1_PD_MASK, ump518_LDO_VDDLDO1_VOL,
			   ump518_LDO_VDDLDO1_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDLDO2, ump518_LDO_VDDLDO2_PD,
			   ump518_LDO_VDDLDO2_PD_MASK, ump518_LDO_VDDLDO2_VOL,
			   ump518_LDO_VDDLDO2_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDLDO3, ump518_LDO_VDDLDO3_PD,
			   ump518_LDO_VDDLDO3_PD_MASK, ump518_LDO_VDDLDO3_VOL,
			   ump518_LDO_VDDLDO3_VOL_MASK, 10000, 1200000, 3750000, 0),
	ump518_REGU_LINEAR(LDO_VDDKPLED, ump518_LDO_VDDKPLED_PD,
			   ump518_LDO_VDDKPLED_PD_MASK, ump518_LDO_VDDKPLED_VOL,
			   ump518_LDO_VDDKPLED_VOL_MASK, 10000, 1200000, 3750000, 0),
};

static int debugfs_enable_get(void *data, u64 *val)
{
	struct regulator_dev *rdev = data;

	if (rdev && rdev->desc->ops->is_enabled)
		*val = rdev->desc->ops->is_enabled(rdev);
	else
		*val = ~0;
	return 0;
}

static int debugfs_enable_set(void *data, u64 val)
{
	struct regulator_dev *rdev = data;

	if (rdev && rdev->desc->ops->enable && rdev->desc->ops->disable) {
		if (val)
			rdev->desc->ops->enable(rdev);
		else
			rdev->desc->ops->disable(rdev);
	}

	return 0;
}

static int debugfs_voltage_get(void *data, u64 *val)
{
	int sel, ret;
	struct regulator_dev *rdev = data;

	sel = rdev->desc->ops->get_voltage_sel(rdev);
	if (sel < 0)
		return sel;
	ret = rdev->desc->ops->list_voltage(rdev, sel);

	*val = ret / 1000;

	return 0;
}

static int debugfs_voltage_set(void *data, u64 val)
{
	int selector;
	struct regulator_dev *rdev = data;

	val = val * 1000;
	selector = regulator_map_voltage_linear(rdev,
						val - rdev->desc->uV_step / 2,
						val + rdev->desc->uV_step / 2);

	return rdev->desc->ops->set_voltage_sel(rdev, selector);
}

DEFINE_SIMPLE_ATTRIBUTE(fops_enable, debugfs_enable_get, debugfs_enable_set, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(fops_ldo, debugfs_voltage_get, debugfs_voltage_set, "%llu\n");

static void ump518_regulator_debugfs_init(struct regulator_dev *rdev)
{

	debugfs_root = debugfs_create_dir(rdev->desc->name, NULL);

	if (IS_ERR_OR_NULL(debugfs_root)) {
		dev_warn(&rdev->dev, "Failed to create debugfs directory\n");
		rdev->debugfs = NULL;
		return;
	}

	debugfs_create_file("enable", 0644, debugfs_root, rdev, &fops_enable);
	debugfs_create_file("voltage", 0644, debugfs_root, rdev, &fops_ldo);
}

static int ump518_regulator_unlock(struct regmap *regmap)
{
	return regmap_write(regmap, ump518_PWR_WR_PROT, ump518_WR_UNLOCK_VALUE);
}

static int ump518_regulator_probe(struct platform_device *pdev)
{
	int i, ret;
	struct regmap *regmap;
	struct regulator_config config = { };
	struct regulator_dev *rdev;

	regmap = dev_get_regmap(pdev->dev.parent, NULL);
	if (!regmap) {
		dev_err(&pdev->dev, "failed to get regmap.\n");
		return -ENODEV;
	}

	ret = ump518_regulator_unlock(regmap);
	if (ret) {
		dev_err(&pdev->dev, "failed to release regulator lock\n");
		return ret;
	}

	config.dev = &pdev->dev;
	config.regmap = regmap;

	for (i = 0; i < ARRAY_SIZE(regulators); i++) {
		rdev = devm_regulator_register(&pdev->dev, &regulators[i], &config);
		if (IS_ERR(rdev)) {
			dev_err(&pdev->dev, "failed to register regulator %s\n",
				regulators[i].name);
			return PTR_ERR(rdev);
		}
		ump518_regulator_debugfs_init(rdev);
	}

	return 0;
}

static int ump518_regulator_remove(struct platform_device *pdev)
{
	debugfs_remove_recursive(debugfs_root);
	return 0;
}

static const struct of_device_id ump518_regulator_match[] = {
	{ .compatible = "sprd,ump518-regulator" },
	{},
};
MODULE_DEVICE_TABLE(of, ump518_regulator_match);

static struct platform_driver ump518_regulator_driver = {
	.driver = {
		.name = "ump518-regulator",
		.of_match_table = ump518_regulator_match,
	},
	.probe = ump518_regulator_probe,
	.remove = ump518_regulator_remove,
};

module_platform_driver(ump518_regulator_driver);

MODULE_AUTHOR("Yinxin.lin <Yixin.lin@unisoc.com>");
MODULE_DESCRIPTION("Unisoc ump518 regulator driver");
MODULE_LICENSE("GPL v2");
