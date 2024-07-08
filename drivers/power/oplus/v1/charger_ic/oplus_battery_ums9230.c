// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2011 Samsung Electronics Co., Ltd.
 * MyungJoo Ham <myungjoo.ham@samsung.com>
 *
 * This driver enables to monitor battery health and control charger
 * during suspend-to-mem.
 * Charger manager depends on other devices. Register this later than
 * the depending devices.
 *
**/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/io.h>
//#include <linux/firmware.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_wakeup.h>
#include <linux/power_supply.h>
#include <linux/power/sprd_battery_info.h>
#include <linux/reboot.h>
#include <linux/rtc.h>
#include <linux/slab.h>
#include <linux/of_gpio.h>
#include <linux/kthread.h>
#include <linux/pinctrl/consumer.h>
#include <linux/iio/consumer.h>
#include <linux/sysfs.h>
#include <linux/thermal.h>
#include <linux/usb/sprd_pd.h>
#include <linux/workqueue.h>
#include "../oplus_chg_module.h"
#include "../oplus_charger.h"
#include "../oplus_gauge.h"
#include "../oplus_vooc.h"
#include "../oplus_adapter.h"
#include "../oplus_short.h"
#include "../oplus_configfs.h"
#include "../oplus_chg_track.h"
#include "oplus_charge_pump.h"
#include "../voocphy/oplus_voocphy.h"
#include "../voocphy/oplus_sc8547.h"
#include "oplus_battery_ums9230.h"
#include <soc/oplus/boot/boot_mode.h>
#include "oplus_discrete_charger.h"

struct charger_manager *pinfo = NULL;
struct oplus_chg_chip *g_oplus_chip = NULL;
struct thermal_zone_device *Batt_BTB_thermal = NULL;
bool is_mtksvooc_project = false;
static bool probe_done;
static int charger_ic__det_flag = 0;
bool is_bbat_mode;

#define CM_CP_DEFAULT_TAPER_CURRENT		1000000

#define USB_TEMP_HIGH		0x01//bit0
#define USB_WATER_DETECT	0x02//bit1
#define USB_RESERVE2		0x04//bit2
#define USB_RESERVE3		0x08//bit3
#define USB_RESERVE4		0x10//bit4
#define USB_DONOT_USE		0x80000000
static int usb_status = 0;

extern int oplus_usbtemp_monitor_common_new_method(void *data);
extern int bq25910_driver_init(void);
extern int hl7138_subsys_init(void);
extern int sgm41512_charger_init(void);
extern int sgm41542_charger_init(void);
extern int sc8547_subsys_init(void);
extern int sc27xx_typec_set_sink(void);
extern int sc27xx_typec_set_enable(void);
extern int typec_get_cc_polarity_role(void);
extern bool sc27xx_typec_cc1_cc2_voltage_detect(void);
extern int sc27xx_typec_set_sinkonly(void);
extern int sc27xx_typec_set_cc_open(void);


extern struct oplus_chg_operations  sgm41512_chg_ops;
extern struct oplus_chg_operations  sgm41542_chg_ops;
extern struct oplus_chg_operations  bq25910_chg_ops;

extern bool oplus_sgm41512_get_bc12_done(void);
extern bool oplus_sgm41542_get_bc12_done(void);
extern int oplus_sgm41512_get_charger_type(void);
extern int oplus_sgm41542_get_charger_type(void);
extern void oplus_sgm41542_set_ap_current(int value);
extern bool oplus_sgm41542_get_slave_chg_en(void);

bool oplus_usbtemp_condition(void);
static struct task_struct *oplus_usbtemp_kthread;
int con_volt_ums9230[] = {
	1180,
	1179,
	1177,
	1175,
	1173,
	1171,
	1169,
	1166,
	1164,
	1161,
	1158,
	1155,
	1152,
	1149,
	1146,
	1142,
	1138,
	1134,
	1130,
	1126,
	1121,
	1117,
	1112,
	1107,
	1101,
	1096,
	1090,
	1084,
	1077,
	1071,
	1064,
	1057,
	1050,
	1042,
	1034,
	1026,
	1018,
	1009,
	1000,
	991,
	982,
	972,
	962,
	952,
	942,
	931,
	920,
	909,
	898,
	886,
	875,
	863,
	851,
	839,
	826,
	814,
	801,
	788,
	775,
	762,
	749,
	736,
	723,
	709,
	696,
	683,
	669,
	656,
	643,
	630,
	616,
	603,
	590,
	577,
	564,
	551,
	539,
	526,
	514,
	502,
	489,
	477,
	466,
	454,
	443,
	431,
	420,
	409,
	399,
	388,
	378,
	368,
	358,
	348,
	339,
	330,
	320,
	312,
	303,
	295,
	286,
	278,
	270,
	263,
	255,
	248,
	241,
	234,
	227,
	221,
	215,
	208,
	202,
	197,
	191,
	185,
	180,
	175,
	170,
	165,
	160,
	155,
	151,
	147,
	142,
	138,
	134,
	130,
	127,
	123,
	120,
	116,
	113,
	110,
	106,
	103,
	100,
	98,
	95,
	92,
	90,
	87,
	85,
	82,
	80,
	78,
	76,
	74,
	71,
	70,
	68,
	66,
	64,
	62,
	61,
	59,
	57,
	56,
	54,
	53,
	51,
	50,
	49,
	47,
	46,
	45,
};

int con_temp_ums9230[] = {
	-40,
	-39,
	-38,
	-37,
	-36,
	-35,
	-34,
	-33,
	-32,
	-31,
	-30,
	-29,
	-28,
	-27,
	-26,
	-25,
	-24,
	-23,
	-22,
	-21,
	-20,
	-19,
	-18,
	-17,
	-16,
	-15,
	-14,
	-13,
	-12,
	-11,
	-10,
	-9,
	-8,
	-7,
	-6,
	-5,
	-4,
	-3,
	-2,
	-1,
	0,
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	16,
	17,
	18,
	19,
	20,
	21,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	29,
	30,
	31,
	32,
	33,
	34,
	35,
	36,
	37,
	38,
	39,
	40,
	41,
	42,
	43,
	44,
	45,
	46,
	47,
	48,
	49,
	50,
	51,
	52,
	53,
	54,
	55,
	56,
	57,
	58,
	59,
	60,
	61,
	62,
	63,
	64,
	65,
	66,
	67,
	68,
	69,
	70,
	71,
	72,
	73,
	74,
	75,
	76,
	77,
	78,
	79,
	80,
	81,
	82,
	83,
	84,
	85,
	86,
	87,
	88,
	89,
	90,
	91,
	92,
	93,
	94,
	95,
	96,
	97,
	98,
	99,
	100,
	101,
	102,
	103,
	104,
	105,
	106,
	107,
	108,
	109,
	110,
	111,
	112,
	113,
	114,
	115,
	116,
	117,
	118,
	119,
	120,
	121,
	122,
	123,
	124,
	125,
};

void __attribute__((weak)) oplus_dcin_irq_enable(void)
{
	return;
}
void __attribute__((weak)) oplus_wireless_set_otg_en_val(void)
{
	return;
}
int __attribute__((weak)) oplus_get_idt_en_val(void)
{
	return -1;
}
bool oplus_get_wired_chg_present(void)
{
	return false;
}
int qpnp_get_prop_charger_voltage_now(void)
{
	int ret, vol_mv;

	if(!pinfo){
		return -1;
	}

	if(IS_ERR_OR_NULL(pinfo->charger_vbus_chan)) {
       		pinfo->charger_vbus_chan = devm_iio_channel_get(pinfo->dev, "charge_vbus");
       		if (IS_ERR(pinfo->charger_vbus_chan)) {
               		chg_err("Couldn't get charge_vbus...\n");
               		pinfo->charger_vbus_chan = NULL;
			return -1;
       		}
	}

	ret = iio_read_channel_processed(pinfo->charger_vbus_chan, &vol_mv);
	if (ret < 0)
		return ret;

	return vol_mv;
}
int oplus_get_usb_status(void)
{
	if( g_oplus_chip->usb_status == USB_TEMP_HIGH) {
		return g_oplus_chip->usb_status;
	} else {
		return usb_status;
	}
}

bool oplus_get_wired_otg_online(void)
{
	return false;
}

static const struct of_device_id charger_manager_match[] = {
	{
		.compatible = "sprd,charger-manager",
	},
	{},
};
MODULE_DEVICE_TABLE(of, charger_manager_match);

int is_vooc_cfg = false;
static bool is_vooc_project(void)
{
	return is_vooc_cfg;
}
static bool oplus_ship_check_is_gpio(struct oplus_chg_chip *chip)
{
	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return false;
	}

	if (gpio_is_valid(chip->normalchg_gpio.ship_gpio))
		return true;

	return false;
}
#define PWM_COUNT				5

static void smbchg_enter_shipmode(struct oplus_chg_chip *chip)
{
	int i = 0;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return;
	}

	if (oplus_ship_check_is_gpio(chip) == true) {
		chg_err("select gpio control\n");
		if (!IS_ERR_OR_NULL(chip->normalchg_gpio.ship_active) && !IS_ERR_OR_NULL(chip->normalchg_gpio.ship_sleep)) {
			pinctrl_select_state(chip->normalchg_gpio.pinctrl,
				chip->normalchg_gpio.ship_sleep);
			for (i = 0; i < PWM_COUNT; i++) {
				//gpio_direction_output(chip->normalchg_gpio.ship_gpio, 1);
				pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.ship_active);
				mdelay(3);
				//gpio_direction_output(chip->normalchg_gpio.ship_gpio, 0);
				pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.ship_sleep);
				mdelay(3);
			}
		}
		chg_err("power off after 15s\n");
	}else{
		chip->chg_ops->enable_shipmode(true);
		chg_err("enable shipmode, power off after 15s\n");
	}
}
int oplus_get_typec_cc_orientation(void)
{
 	struct oplus_chg_chip *chip = g_oplus_chip;
	int val = 0;

	if (!chip || !pinfo->port)	{
		printk(KERN_ERR "[OPLUS_CHG][%s]: g_oplus_chip not ready!\n", __func__);
		return val;
	}

	val = typec_get_cc_polarity_role();
	printk(KERN_ERR "[OPLUS_CHG][%s]: cc_orientation [%d]\n", __func__, val);

	return val;
}
void oplus_set_otg_switch_status(bool value)
{
 	printk(KERN_ERR "[OPLUS_CHG][%s]: otg switch[%d]\n", __func__, value);
	if (pinfo != NULL && pinfo->port != NULL) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: g_oplus_chip not ready!\n", __func__);
		if(value){
			sc27xx_typec_set_enable();
		}else{
			sc27xx_typec_set_sink();
		}
	}
}
EXPORT_SYMBOL(oplus_set_otg_switch_status);
int oplus_get_otg_online_status(void)
{
 	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: g_oplus_chip not ready!\n", __func__);
		return false;
	}
	printk(KERN_ERR "[OPLUS_CHG][%s]: otg_online [%d]\n", __func__, chip->otg_online);
	return  chip->otg_online;
}

#define DETECT_COUNT	2
void oplus_vbus_short_cc_detect(void)
{
	bool cc_status = false;
	static bool cur_flag = false;
	static bool last_flag = false;
	static int cnt = 0;

	if (!g_oplus_chip)
		return;
	if (g_oplus_chip->cc_safe_enable == false) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: cc-safeguard is closed\n", __func__);
		return;
	}

	cc_status = sc27xx_typec_cc1_cc2_voltage_detect();

	if (cc_status == true && cnt < DETECT_COUNT) {
			cnt++;
			if (DETECT_COUNT == cnt)
				cur_flag = true;

	} else if (cc_status == false && cnt > 0) {
			cnt--;
			if (0 == cnt)
				cur_flag = false;
	}

	if (cur_flag != last_flag) {
		last_flag = cur_flag;

		if (true == cur_flag) {
			g_oplus_chip->cc_safeguard = true;
			g_oplus_chip->cc_allow_fastchg = false;
		} else {
			g_oplus_chip->cc_allow_fastchg = true;
		}
		printk(KERN_ERR "[OPLUS_CHG][%s]: %s\n", __func__, cur_flag ? "enable cc safeguard" : "disable cc safeguard");
	}
	printk(KERN_ERR "[OPLUS_CHG][%s]: cc_allow_fastchg [%d]\n", __func__, g_oplus_chip->cc_allow_fastchg);
}
EXPORT_SYMBOL(oplus_vbus_short_cc_detect);


static void enter_ship_mode_function(struct oplus_chg_chip *chip)
{

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return;
	}

	if (chip->enable_shipmode) {
		smbchg_enter_shipmode(chip);
		printk(KERN_ERR "[OPLUS_CHG][%s]: enter_ship_mode_function\n", __func__);
	}
}

static void cm_cap_remap_init_boundary(struct charger_desc *desc, int index, struct device *dev)
{

	if (index == 0) {
		desc->cap_remap_table[index].lb = (desc->cap_remap_table[index].lcap) * 1000;
		desc->cap_remap_total_cnt = desc->cap_remap_table[index].lcap;
	} else {
		desc->cap_remap_table[index].lb = desc->cap_remap_table[index - 1].hb +
			(desc->cap_remap_table[index].lcap -
			 desc->cap_remap_table[index - 1].hcap) * 1000;
		desc->cap_remap_total_cnt += (desc->cap_remap_table[index].lcap -
					      desc->cap_remap_table[index - 1].hcap);
	}

	desc->cap_remap_table[index].hb = desc->cap_remap_table[index].lb +
		(desc->cap_remap_table[index].hcap - desc->cap_remap_table[index].lcap) *
		desc->cap_remap_table[index].cnt * 1000;

	desc->cap_remap_total_cnt +=
		(desc->cap_remap_table[index].hcap - desc->cap_remap_table[index].lcap) *
		desc->cap_remap_table[index].cnt;

	dev_info(dev, "%s, cap_remap_table[%d].lb =%d,cap_remap_table[%d].hb = %d\n",
		 __func__, index, desc->cap_remap_table[index].lb, index,
		 desc->cap_remap_table[index].hb);
}

static int cm_init_cap_remap_table(struct charger_desc *desc, struct device *dev)
{

	struct device_node *np = dev->of_node;
	const __be32 *list;
	int i, size;

	list = of_get_property(np, "cm-cap-remap-table", &size);
	if (!list || !size) {
		dev_err(dev, "%s  get cm-cap-remap-table fail\n", __func__);
		return 0;
	}
	desc->cap_remap_table_len = (u32)size / (3 * sizeof(__be32));
	desc->cap_remap_table = devm_kzalloc(dev, sizeof(struct cap_remap_table) *
				(desc->cap_remap_table_len + 1), GFP_KERNEL);
	if (!desc->cap_remap_table) {
		dev_err(dev, "%s, get cap_remap_table fail\n", __func__);
		return -ENOMEM;
	}
	for (i = 0; i < desc->cap_remap_table_len; i++) {
		desc->cap_remap_table[i].lcap = be32_to_cpu(*list++);
		desc->cap_remap_table[i].hcap = be32_to_cpu(*list++);
		desc->cap_remap_table[i].cnt = be32_to_cpu(*list++);

		cm_cap_remap_init_boundary(desc, i, dev);

		dev_info(dev, "cap_remap_table[%d].lcap= %d,cap_remap_table[%d].hcap = %d,"
			 "cap_remap_table[%d].cnt= %d\n", i, desc->cap_remap_table[i].lcap,
			 i, desc->cap_remap_table[i].hcap, i, desc->cap_remap_table[i].cnt);
	}

	if (desc->cap_remap_table[desc->cap_remap_table_len - 1].hcap != 100)
		desc->cap_remap_total_cnt +=
			(100 - desc->cap_remap_table[desc->cap_remap_table_len - 1].hcap);

	dev_info(dev, "cap_remap_total_cnt =%d, cap_remap_table_len = %d\n",
		 desc->cap_remap_total_cnt, desc->cap_remap_table_len);

	return 0;
}

static struct charger_desc *of_cm_parse_desc(struct device *dev)
{
	struct charger_desc *desc;
	struct device_node *np = dev->of_node;
	u32 poll_mode = CM_POLL_DISABLE;
	u32 battery_stat = CM_NO_BATTERY;
	int ret, i = 0, num_chgs = 0;
	int num_cp_psys = 0;

	desc = devm_kzalloc(dev, sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return ERR_PTR(-ENOMEM);

	of_property_read_string(np, "cm-name", &desc->psy_name);

	of_property_read_u32(np, "cm-poll-mode", &poll_mode);
	desc->polling_mode = poll_mode;

	desc->uvlo_shutdown_mode = CM_SHUTDOWN_MODE_ANDROID;
	of_property_read_u32(np, "cm-uvlo-shutdown-mode", &desc->uvlo_shutdown_mode);

	of_property_read_u32(np, "cm-poll-interval",
				&desc->polling_interval_ms);

	of_property_read_u32(np, "cm-fullbatt-vchkdrop-ms",
					&desc->fullbatt_vchkdrop_ms);
	of_property_read_u32(np, "cm-fullbatt-vchkdrop-volt",
					&desc->fullbatt_vchkdrop_uV);
	of_property_read_u32(np, "cm-fullbatt-soc", &desc->fullbatt_soc);
	of_property_read_u32(np, "cm-fullbatt-capacity",
					&desc->fullbatt_full_capacity);
	of_property_read_u32(np, "cm-shutdown-voltage", &desc->shutdown_voltage);
	of_property_read_u32(np, "cm-tickle-time-out", &desc->trickle_time_out);
	of_property_read_u32(np, "cm-one-cap-time", &desc->cap_one_time);
	of_property_read_u32(np, "cm-one-cap-time", &desc->default_cap_one_time);
	of_property_read_u32(np, "cm-wdt-interval", &desc->wdt_interval);

	of_property_read_u32(np, "cm-battery-stat", &battery_stat);
	desc->battery_present = battery_stat;

	/* chargers */
	num_chgs = of_property_count_strings(np, "cm-chargers");
	if (num_chgs > 0) {
		/* Allocate empty bin at the tail of array */
		desc->psy_charger_stat = devm_kcalloc(dev,
						      num_chgs + 1,
						      sizeof(char *),
						      GFP_KERNEL);
		if (!desc->psy_charger_stat)
			return ERR_PTR(-ENOMEM);

		for (i = 0; i < num_chgs; i++)
			of_property_read_string_index(np, "cm-chargers", i,
						      &desc->psy_charger_stat[i]);
	}

	desc->enable_alt_cp_adapt =
		device_property_read_bool(dev, "cm-alt-cp-adapt-enable");

	/* alternative charge pupms power supply */
	num_cp_psys = of_property_count_strings(np, "cm-alt-cp-power-supplys");
	dev_info(dev, "%s num_cp_psys = %d\n", __func__, num_cp_psys);
	if (num_cp_psys > 0) {
		desc->psy_cp_nums = num_cp_psys;
		/* Allocate empty bin at the tail of array */
		desc->psy_alt_cp_adpt_stat = devm_kzalloc(dev, sizeof(char *)
						* (num_cp_psys + 1), GFP_KERNEL);
		if (desc->psy_alt_cp_adpt_stat) {
			for (i = 0; i < num_cp_psys; i++)
				of_property_read_string_index(np, "cm-alt-cp-power-supplys",
						i, &desc->psy_alt_cp_adpt_stat[i]);
		} else {
			return ERR_PTR(-ENOMEM);
		}
	}

	/* charge pumps */
	num_chgs = of_property_count_strings(np, "cm-charge-pumps");
	if (num_chgs > 0) {
		/* Allocate empty bin at the tail of array */
		desc->cp_nums = num_chgs;
		desc->psy_cp_stat =
			devm_kzalloc(dev, sizeof(char *) * (u32)(num_chgs + 1), GFP_KERNEL);
		if (!desc->psy_cp_stat)
			return ERR_PTR(-ENOMEM);

		for (i = 0; i < num_chgs; i++)
			of_property_read_string_index(np, "cm-charge-pumps", i,
						      &desc->psy_cp_stat[i]);
	}

	/* wireless chargers */
	num_chgs = of_property_count_strings(np, "cm-wireless-chargers");
	if (num_chgs > 0) {
		/* Allocate empty bin at the tail of array */
		desc->psy_wl_charger_stat =
			devm_kzalloc(dev,  sizeof(char *) * (u32)(num_chgs + 1), GFP_KERNEL);
		if (desc->psy_wl_charger_stat) {
			for (i = 0; i < num_chgs; i++)
				of_property_read_string_index(np, "cm-wireless-chargers",
						i, &desc->psy_wl_charger_stat[i]);
		} else {
			return ERR_PTR(-ENOMEM);
		}
	}

	/* wireless charge pump converters */
	num_chgs = of_property_count_strings(np, "cm-wireless-charge-pump-converters");
	if (num_chgs > 0) {
		/* Allocate empty bin at the tail of array */
		desc->psy_cp_converter_stat =
			devm_kzalloc(dev, sizeof(char *) * (u32)(num_chgs + 1), GFP_KERNEL);
		if (desc->psy_cp_converter_stat) {
			for (i = 0; i < num_chgs; i++)
				of_property_read_string_index(np, "cm-wireless-charge-pump-converters",
						i, &desc->psy_cp_converter_stat[i]);
		} else {
			return ERR_PTR(-ENOMEM);
		}
	}

	of_property_read_string(np, "cm-fuel-gauge", &desc->psy_fuel_gauge);

	of_property_read_string(np, "cm-thermal-zone", &desc->thermal_zone);

	of_property_read_u32(np, "cm-battery-cold", &desc->temp_min);
	if (of_get_property(np, "cm-battery-cold-in-minus", NULL))
		desc->temp_min *= -1;
	of_property_read_u32(np, "cm-battery-hot", &desc->temp_max);
	of_property_read_u32(np, "cm-battery-temp-diff", &desc->temp_diff);

	of_property_read_u32(np, "cm-charging-max",
				&desc->charging_max_duration_ms);
	of_property_read_u32(np, "cm-discharging-max",
				&desc->discharging_max_duration_ms);
	of_property_read_u32(np, "cm-charge-voltage-max",
			     &desc->normal_charge_voltage_max);
	of_property_read_u32(np, "cm-charge-voltage-drop",
			     &desc->normal_charge_voltage_drop);
	of_property_read_u32(np, "cm-fast-charge-voltage-max",
			     &desc->fast_charge_voltage_max);
	of_property_read_u32(np, "cm-fast-charge-voltage-drop",
			     &desc->fast_charge_voltage_drop);
	of_property_read_u32(np, "cm-flash-charge-voltage-max",
			     &desc->flash_charge_voltage_max);
	of_property_read_u32(np, "cm-flash-charge-voltage-drop",
			     &desc->flash_charge_voltage_drop);
	of_property_read_u32(np, "cm-wireless-charge-voltage-max",
			     &desc->wireless_normal_charge_voltage_max);
	of_property_read_u32(np, "cm-wireless-charge-voltage-drop",
			     &desc->wireless_normal_charge_voltage_drop);
	of_property_read_u32(np, "cm-wireless-fast-charge-voltage-max",
			     &desc->wireless_fast_charge_voltage_max);
	of_property_read_u32(np, "cm-wireless-fast-charge-voltage-drop",
			     &desc->wireless_fast_charge_voltage_drop);
	of_property_read_u32(np, "cm-cp-taper-current",
			     &desc->cp.cp_taper_current);
	of_property_read_u32(np, "cm-cap-full-advance-percent",
			     &desc->cap_remap_full_percent);

	if (desc->psy_cp_stat && !desc->cp.cp_taper_current)
		desc->cp.cp_taper_current = CM_CP_DEFAULT_TAPER_CURRENT;

	ret = cm_init_cap_remap_table(desc, dev);
	if (ret)
		dev_err(dev, "%s init cap remap table fail\n", __func__);

	return desc;
}
static enum oplus_chg_mod_property oplus_chg_usb_props[] = {
	OPLUS_CHG_PROP_ONLINE,
};

static enum oplus_chg_mod_property oplus_chg_usb_uevent_props[] = {
	OPLUS_CHG_PROP_ONLINE,
};

static int oplus_chg_usb_get_prop(struct oplus_chg_mod *ocm,
			enum oplus_chg_mod_property prop,
			union oplus_chg_mod_propval *pval)
{
	return -EINVAL;
}

static int oplus_chg_usb_set_prop(struct oplus_chg_mod *ocm,
			enum oplus_chg_mod_property prop,
			const union oplus_chg_mod_propval *pval)
{
	return -EINVAL;
}

static int oplus_chg_usb_prop_is_writeable(struct oplus_chg_mod *ocm,
				enum oplus_chg_mod_property prop)
{
	return 0;
}

static const struct oplus_chg_mod_desc oplus_chg_usb_mod_desc = {
	.name = "usb",
	.type = OPLUS_CHG_MOD_USB,
	.properties = oplus_chg_usb_props,
	.num_properties = ARRAY_SIZE(oplus_chg_usb_props),
	.uevent_properties = oplus_chg_usb_uevent_props,
	.uevent_num_properties = ARRAY_SIZE(oplus_chg_usb_uevent_props),
	.exten_properties = NULL,
	.num_exten_properties = 0,
	.get_property = oplus_chg_usb_get_prop,
	.set_property = oplus_chg_usb_set_prop,
	.property_is_writeable	= oplus_chg_usb_prop_is_writeable,
};

static int oplus_chg_usb_event_notifier_call(struct notifier_block *nb,
		unsigned long val, void *v)
{
	struct oplus_chg_mod *owner_ocm = v;

	switch(val) {
	case OPLUS_CHG_EVENT_ONLINE:
	case OPLUS_CHG_EVENT_OFFLINE:
		if (owner_ocm == NULL) {
			pr_err("This event(=%d) does not support anonymous sending\n",
				val);
			return NOTIFY_BAD;
		}

		if (!strcmp(owner_ocm->desc->name, "wireless")) {
			pr_info("%s wls %s\n", __func__, val == OPLUS_CHG_EVENT_ONLINE ? "online" : "offline");
			oplus_chg_wake_update_work();
		}
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static int oplus_chg_usb_init_mod(struct charger_manager *chip)
{
	struct oplus_chg_mod_config ocm_cfg = {};
	int rc;

	ocm_cfg.drv_data = chip;
	ocm_cfg.of_node = chip->dev->of_node;
    chg_err("%s : %d\n",__func__,__LINE__);

	chip->usb_ocm = oplus_chg_mod_register(chip->dev,
					   &oplus_chg_usb_mod_desc,
					   &ocm_cfg);
	if (IS_ERR(chip->usb_ocm)) {
		pr_err("Couldn't register usb ocm\n");
		rc = PTR_ERR(chip->usb_ocm);
		return rc;
	}

	chip->usb_event_nb.notifier_call =
					oplus_chg_usb_event_notifier_call;
	rc = oplus_chg_reg_event_notifier(&chip->usb_event_nb);
	if (rc) {
		pr_err("register usb event notifier error, rc=%d\n", rc);
		return rc;
	}

	return 0;
}

static inline struct charger_desc *cm_get_drv_data(struct platform_device *pdev)
{
	if (pdev->dev.of_node)
		return of_cm_parse_desc(&pdev->dev);
	return dev_get_platdata(&pdev->dev);
}

int get_boot_mode(void)
{
	struct device_node *cmdline_node;
	const char *cmd_line;
	int ret;

	cmdline_node = of_find_node_by_path("/chosen");
	ret = of_property_read_string(cmdline_node, "bootargs", &cmd_line);
	if (ret)
		return ret;

	if (strstr(cmd_line, "androidboot.mode=cali") ||
	    strstr(cmd_line, "androidboot.mode=autotest")) {
		is_bbat_mode = true;
		ret = MSM_BOOT_MODE__FACTORY;
	} else if (strstr(cmd_line, "androidboot.mode=charger")) {
		ret = MSM_BOOT_MODE__CHARGE;
	}  else if (strstr(cmd_line, "androidboot.mode=normal")) {
		ret = MSM_BOOT_MODE__NORMAL;
	}

	return ret;
}
EXPORT_SYMBOL(get_boot_mode);

unsigned int get_eng_version(void)
{
   return 0;
}
EXPORT_SYMBOL(get_eng_version);

unsigned int get_PCB_Version(void)
{
   return 1;
}
EXPORT_SYMBOL(get_PCB_Version);

unsigned int  get_project(void)
{
	return -1;
}
EXPORT_SYMBOL(get_project);

int register_device_proc(char *name, char *version, char *vendor)
{
	return 1;
}
EXPORT_SYMBOL(register_device_proc);

int get_charger_ic_det(struct oplus_chg_chip *chip)
{
	int count = 0;
	int n = charger_ic__det_flag;

	if (!chip) {
		return charger_ic__det_flag;
	}

	while (n) {
		++count;
		n = (n - 1) & n;
	}

	/*chip->dual_charger_support = count > 1 ? true : false;*/

	chg_err("charger_ic__det_flag:%d,dual_charger_support=%d, count=%d\n",
		charger_ic__det_flag, chip->dual_charger_support, count);

	return charger_ic__det_flag;
}

void set_charger_ic(int sel)
{
	charger_ic__det_flag |= 1<<sel;
}
EXPORT_SYMBOL_GPL(set_charger_ic);

bool oplus_get_bc12_done_sprd(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		pr_err("oplus_chip is null\n");
		return false;
	}

	if (chip->dual_charger_support) {
		if ((charger_ic__det_flag == (1 << SGM41542 | 1 << BQ2591X)) ||
			(charger_ic__det_flag == (1 << SGM41542))) {
			return oplus_sgm41542_get_bc12_done();
		}
	} else {
		return oplus_sgm41512_get_bc12_done();
	}

	return false;
}
EXPORT_SYMBOL(oplus_get_bc12_done_sprd);

int oplus_get_charger_type_sprd(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		pr_err("oplus_chip is null\n");
		return false;
	}

	if (chip->dual_charger_support) {
		if ((charger_ic__det_flag == (1 << SGM41542 | 1 << BQ2591X)) ||
			(charger_ic__det_flag == (1 << SGM41542))) {
			return oplus_sgm41542_get_charger_type();
		}
	} else {
		return oplus_sgm41512_get_charger_type();
	}

	return POWER_SUPPLY_TYPE_UNKNOWN;
}
EXPORT_SYMBOL(oplus_get_charger_type_sprd);

bool oplus_get_otg_online_status_default(void)
{
		return false;
}
int oplus_chg_set_qc_config_forsvooc(void)
{
	int ret = -1;
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		pr_err("oplus_chip is null\n");
		return -1;
	}

	printk(KERN_ERR "%s: qc9v svooc [%d %d %d]", __func__, chip->limits.vbatt_pdqc_to_9v_thr, chip->limits.vbatt_pdqc_to_5v_thr, chip->batt_volt);
	if (!chip->calling_on && chip->charger_volt < 6500 && chip->soc < 90
		&& chip->temperature <= 530 && chip->cool_down_force_5v == false
		&& (chip->batt_volt < chip->limits.vbatt_pdqc_to_9v_thr)) {	//
		printk(KERN_ERR "%s: set qc to 9V", __func__);
		msleep(300);
		oplus_chg_suspend_charger();
		oplus_chg_config_charger_vsys_threshold(0x02);//set Vsys Skip threshold 104%
		oplus_chg_enable_burst_mode(false);
		msleep(300);
		oplus_chg_unsuspend_charger();
		ret = 0;
	} else {
		if (chip->charger_volt > 7500 &&
			(chip->calling_on || chip->soc >= 90
			|| chip->batt_volt >= chip->limits.vbatt_pdqc_to_5v_thr || chip->temperature > 530 || chip->cool_down_force_5v == true)) {
			printk(KERN_ERR "%s: set qc to 5V", __func__);
			chip->chg_ops->input_current_write(500);
			oplus_chg_suspend_charger();
			oplus_chg_config_charger_vsys_threshold(0x03);//set Vsys Skip threshold 101%
			msleep(400);
			printk(KERN_ERR "%s: charger voltage=%d", __func__, chip->charger_volt);
			oplus_chg_unsuspend_charger();
			ret = 0;
		}
		printk(KERN_ERR "%s: qc9v svooc  default[%d]", __func__, chip->batt_volt);
	}

	return ret;
}

int oplus_chg_set_qc_config(void)
{
	int ret = -1;

	struct oplus_chg_chip *chip = g_oplus_chip;

	pr_err("oplus_chg_set_qc_config\n");

	if (!chip) {
		pr_err("oplus_chip is null\n");
		return -1;
	}

	if (is_mtksvooc_project) {
		ret = oplus_chg_set_qc_config_forsvooc();
	} else {
		if (!chip->calling_on && !chip->camera_on && chip->charger_volt < 6500 && chip->soc < 90
				&& chip->temperature <= 420 && chip->cool_down_force_5v == false) {
			printk(KERN_ERR "%s: set qc to 9V", __func__);
			//mt6375_set_hvdcp_to_9v();
			ret = 0;
		} else {
			if (chip->charger_volt > 7500 &&
					(chip->calling_on || chip->camera_on || chip->soc >= 90 || chip->batt_volt >= 4450
					|| chip->temperature > 420 || chip->cool_down_force_5v == true)) {
				printk(KERN_ERR "%s: set qc to 5V", __func__);
				//mt6375_set_hvdcp_to_5v();
				ret = 0;
			}
		}
	}
        return ret;
}
EXPORT_SYMBOL(oplus_chg_set_qc_config);

int oplus_chg_get_charger_subtype(void)
{
	int charg_subtype = CHARGER_SUBTYPE_DEFAULT;

	if (!pinfo) {
		return charg_subtype;
	}

	return charg_subtype;
}
EXPORT_SYMBOL(oplus_chg_get_charger_subtype);
int oplus_chg_set_pd_config(void)
{
	return 0;
}

int get_rtc_spare_oplus_fg_value(void)
{
	int ret, ui_soc = -EINVAL;
	union power_supply_propval val;
	struct power_supply *fuel_gauge;

	fuel_gauge = power_supply_get_by_name("sc27xx-fgu");
	if (!fuel_gauge)
		return -ENODEV;

	val.intval = 2;//CM_UI_CAPACITY;
	ret = power_supply_get_property(fuel_gauge, POWER_SUPPLY_PROP_CAPACITY, &val);
	power_supply_put(fuel_gauge);
	if (ret)
		chg_err(" unisoc_get_rtc_ui_soc failed, ret=%d\n", ret);

	if (ret == 0)
		ui_soc = val.intval / 10;

	chg_err(" get ui_soc = %d\n", ui_soc);

	return ui_soc;

}

int set_rtc_spare_oplus_fg_value(int soc)
{
	union power_supply_propval val;
	struct power_supply *fuel_gauge;
	int ret,temp_soc;

	fuel_gauge = power_supply_get_by_name("sc27xx-fgu");
	if (!fuel_gauge)
		return -ENODEV;

	temp_soc = soc *10;
	val.intval = temp_soc;
	ret = power_supply_set_property(fuel_gauge, POWER_SUPPLY_PROP_CAPACITY, &val);
	power_supply_put(fuel_gauge);
	if (ret)
		chg_err("unisoc_set_rtc_ui_soc failed, ret=%d\n",  ret);

	chg_err(" set ui_soc = %d,temp_soc = %d\n", soc , temp_soc);

	return ret;

}
int oplus_battery_meter_get_battery_voltage(void)
{
	return 4000;
}
EXPORT_SYMBOL(oplus_battery_meter_get_battery_voltage);
static bool is_support_chargerid_check(void)
{
#ifdef CONFIG_OPLUS_CHECK_CHARGERID_VOLT
	return false;
#else
	return false;
#endif
}

int oplus_chg_get_subcurrent(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;
	int sub_ichg = 0;
	bool slave_chg_en = false;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return 0;
	}

	if (!chip->charger_exist) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: charger not exist!\n", __func__);
		return 0;
	}

	if (!chip->dual_charger_support) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: dual_charger_support is false!\n", __func__);
		return 0;
	}

	if ((charger_ic__det_flag == (1 << SGM41542 | 1 << BQ2591X)) ||
		(charger_ic__det_flag == (1 << SGM41542))) {
		slave_chg_en = oplus_sgm41542_get_slave_chg_en();
	}

	if (chip->slave_charger_enable || slave_chg_en) {
			if (chip->sub_chg_ops && chip->sub_chg_ops->get_charger_current) {
			sub_ichg = (-1 * chip->sub_chg_ops->get_charger_current());
		}
	}

	if (sub_ichg > 0) {
		sub_ichg = 0;
	}

	chg_err("charger_exist=%d, dual_charger_support=%d, slave_charger_enable=%d, slave_chg_en=%d, sub_ichg=%d\n",
		chip->charger_exist, chip->dual_charger_support, chip->slave_charger_enable, slave_chg_en, sub_ichg);

	return sub_ichg;
}
EXPORT_SYMBOL(oplus_chg_get_subcurrent);

static void set_usbswitch_to_rxtx(struct oplus_chg_chip *chip)
{
	//int ret = 0;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return;
	}

	gpio_direction_output(chip->normalchg_gpio.chargerid_switch_gpio, 1);
	//ret = pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.charger_gpio_as_output2);
	//if (ret < 0) {
	//	chg_err("failed to set pinctrl int\n");
	//}
	chg_err("set_usbswitch_to_rxtx gpio175 = %d \n",gpio_get_value(chip->normalchg_gpio.chargerid_switch_gpio));
	return;
}

static void set_usbswitch_to_dpdm(struct oplus_chg_chip *chip)
{
	//int ret = 0;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return;
	}

	gpio_direction_output(chip->normalchg_gpio.chargerid_switch_gpio, 0);
	//ret = pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.charger_gpio_as_output1);
	//if (ret < 0) {
	//	chg_err("failed to set pinctrl int\n");
	//	return;
	//}
	chg_err("set_usbswitch_to_dpdm gpio175 = %d \n",gpio_get_value(chip->normalchg_gpio.chargerid_switch_gpio));
}

void mt_set_chargerid_switch_val(int value)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return;
	}

	if (is_support_chargerid_check() == false)
		//return;

	if (chip->normalchg_gpio.chargerid_switch_gpio <= 0) {
		chg_err("chargerid_switch_gpio not exist, return\n");
		return;
	}
/*	if (IS_ERR_OR_NULL(chip->normalchg_gpio.pinctrl)
			|| IS_ERR_OR_NULL(chip->normalchg_gpio.charger_gpio_as_output1)
			|| IS_ERR_OR_NULL(chip->normalchg_gpio.charger_gpio_as_output2)) {
		chg_err("pinctrl null, return\n");
		return;
	}
*/
	if (value == 1) {
		set_usbswitch_to_rxtx(chip);
	} else if (value == 0) {
		set_usbswitch_to_dpdm(chip);
	} else {
		//do nothing
	}
	chg_debug("get_val=%d\n", gpio_get_value(chip->normalchg_gpio.chargerid_switch_gpio));

	return;
}
EXPORT_SYMBOL(mt_set_chargerid_switch_val);

int mt_get_chargerid_switch_val(void)
{
	int gpio_status = 0;
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return 0;
	}
	if (is_support_chargerid_check() == false)
		//return 0;

	gpio_status = gpio_get_value(chip->normalchg_gpio.chargerid_switch_gpio);

	chg_debug("mt_get_chargerid_switch_val=%d\n", gpio_status);

	return gpio_status;
}
EXPORT_SYMBOL(mt_get_chargerid_switch_val);

void oplus_ums9230_usbtemp_set_typec_sinkonly(void)
{
	sc27xx_typec_set_sinkonly();
	chg_err("set_typec_sinkonly\n");
}
EXPORT_SYMBOL(oplus_ums9230_usbtemp_set_typec_sinkonly);

void oplus_ums9230_usbtemp_set_cc_open(void)
{
	sc27xx_typec_set_cc_open();
	chg_err("set_cc_open\n");
}
EXPORT_SYMBOL(oplus_ums9230_usbtemp_set_cc_open);
void oplus_set_usb_props_type(enum power_supply_type type)
{
	//chg_err("old type[%d], new type[%d]\n", usb_psy_desc.type, type);
	//usb_psy_desc.type = type;
	return;
}
EXPORT_SYMBOL(oplus_set_usb_props_type);


static int oplus_usb_switch_gpio_gpio_init(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return -EINVAL;
	}
/*
	chip->normalchg_gpio.pinctrl = devm_pinctrl_get(chip->dev);
	if (IS_ERR_OR_NULL(chip->normalchg_gpio.pinctrl)) {
		chg_err("get normalchg_gpio.chargerid_switch_gpio pinctrl fail\n");
		return -EINVAL;
	}

	chip->normalchg_gpio.charger_gpio_as_output1 =
			pinctrl_lookup_state(chip->normalchg_gpio.pinctrl,
			"charger_gpio_as_output_low");
	if (IS_ERR_OR_NULL(chip->normalchg_gpio.charger_gpio_as_output1)) {
		chg_err("get charger_gpio_as_output_low fail\n");
		return -EINVAL;
	}

	chip->normalchg_gpio.charger_gpio_as_output2 =
			pinctrl_lookup_state(chip->normalchg_gpio.pinctrl,
			"charger_gpio_as_output_high");
	if (IS_ERR_OR_NULL(chip->normalchg_gpio.charger_gpio_as_output2)) {
		chg_err("get charger_gpio_as_output_high fail\n");
		return -EINVAL;
	}

	pinctrl_select_state(chip->normalchg_gpio.pinctrl,
			chip->normalchg_gpio.charger_gpio_as_output1);
			
*/
    gpio_direction_output(chip->normalchg_gpio.chargerid_switch_gpio, 0);

	return 0;
}
static bool chargerid_support = false;
static int oplus_chg_chargerid_parse_dt(struct oplus_chg_chip *chip)
{
	int rc = 0;
	struct device_node *node = NULL;

	if (chip != NULL)
		node = chip->dev->of_node;

	if (chip == NULL || node == NULL) {
		chg_err("oplus_chip or device tree info. missing\n");
		return -EINVAL;
	}

	chargerid_support = of_property_read_bool(node, "qcom,chargerid_support");
	if (chargerid_support == false){
		chg_err("not support chargerid\n");
		//return -EINVAL;
	}

	chip->normalchg_gpio.chargerid_switch_gpio =
			of_get_named_gpio(node, "qcom,chargerid_switch-gpio", 0);
	if (chip->normalchg_gpio.chargerid_switch_gpio <= 0) {
		chg_err("Couldn't read chargerid_switch-gpio rc=%d, chargerid_switch-gpio:%d\n",
				rc, chip->normalchg_gpio.chargerid_switch_gpio);
	} else {
		if (gpio_is_valid(chip->normalchg_gpio.chargerid_switch_gpio)) {
			rc = gpio_request(chip->normalchg_gpio.chargerid_switch_gpio, "charging_switch1-gpio");
			if (rc) {
				chg_err("unable to request chargerid_switch-gpio:%d\n",
						chip->normalchg_gpio.chargerid_switch_gpio);
			} else {
				rc = oplus_usb_switch_gpio_gpio_init();
				if (rc)
					chg_err("unable to init chargerid_switch-gpio:%d\n",
							chip->normalchg_gpio.chargerid_switch_gpio);
			}
		}
		chg_err("chargerid_switch-gpio:%d\n", chip->normalchg_gpio.chargerid_switch_gpio);
	}

	return rc;
}
static bool oplus_shortc_check_is_gpio(struct oplus_chg_chip *chip)
{
	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return false;
	}

/*	if (gpio_is_valid(chip->normalchg_gpio.shortc_gpio)) {
		return true;
	}*/

	return false;
}

static int oplus_shortc_gpio_init(struct oplus_chg_chip *chip)
{
	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return -EINVAL;
	}

	chip->normalchg_gpio.pinctrl = devm_pinctrl_get(chip->dev);

	chip->normalchg_gpio.shortc_active =
		pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, "shortc_active");
	if (IS_ERR_OR_NULL(chip->normalchg_gpio.shortc_active)) {
		chg_err("get shortc_active fail\n");
		return -EINVAL;
	}

	pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.shortc_active);

	return 0;
}

static int oplus_chg_shortc_hw_parse_dt(struct oplus_chg_chip *chip)
{
	int rc = 0;
	struct device_node *node = NULL;

        if (chip != NULL)
		node = chip->dev->of_node;

	if (chip == NULL || node == NULL) {
		chg_err("oplus_chip or device tree info. missing\n");
		return -EINVAL;
	}

	chip->normalchg_gpio.shortc_gpio = of_get_named_gpio(node, "qcom,shortc-gpio", 0);
	if (chip->normalchg_gpio.shortc_gpio <= 0) {
		chg_err("Couldn't read qcom,shortc-gpio rc=%d, qcom,shortc-gpio:%d\n",
				rc, chip->normalchg_gpio.shortc_gpio);
	} else {
		if (oplus_shortc_check_is_gpio(chip) == true) {
			rc = gpio_request(chip->normalchg_gpio.shortc_gpio, "shortc-gpio");
			if (rc) {
				chg_err("unable to request shortc-gpio:%d\n",
						chip->normalchg_gpio.shortc_gpio);
			} else {
				rc = oplus_shortc_gpio_init(chip);
				if (rc)
					chg_err("unable to init shortc-gpio:%d\n", chip->normalchg_gpio.ship_gpio);
			}
		}
		chg_err("shortc-gpio:%d\n", chip->normalchg_gpio.shortc_gpio);
	}

	return rc;
}

static int oplus_ship_gpio_init(struct oplus_chg_chip *chip)
{
	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return -EINVAL;
	}

	chip->normalchg_gpio.pinctrl = devm_pinctrl_get(chip->dev);
	chip->normalchg_gpio.ship_active = 
		pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, 
			"ship_active");

	if (IS_ERR_OR_NULL(chip->normalchg_gpio.ship_active)) {
		chg_err("get ship_active fail\n");
		return -EINVAL;
	}
	chip->normalchg_gpio.ship_sleep = 
			pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, 
				"ship_sleep");
	if (IS_ERR_OR_NULL(chip->normalchg_gpio.ship_sleep)) {
		chg_err("get ship_sleep fail\n");
		return -EINVAL;
	}

	pinctrl_select_state(chip->normalchg_gpio.pinctrl,
		chip->normalchg_gpio.ship_sleep);

	return 0;
}

static int oplus_chg_shipmode_parse_dt(struct oplus_chg_chip *chip)
{
	int rc = 0;
	struct device_node *node = NULL;

        if (chip != NULL)
        	node = chip->dev->of_node;

	if (chip == NULL || node == NULL) {
		chg_err("oplus_chip or device tree info. missing\n");
		return -EINVAL;
	}

	chip->normalchg_gpio.ship_gpio =
			of_get_named_gpio(node, "qcom,ship-gpio", 0);
	if (chip->normalchg_gpio.ship_gpio <= 0) {
		chg_err("Couldn't read qcom,ship-gpio rc = %d, qcom,ship-gpio:%d\n",
				rc, chip->normalchg_gpio.ship_gpio);
	} else {
		if (oplus_ship_check_is_gpio(chip) == true) {
			rc = gpio_request(chip->normalchg_gpio.ship_gpio, "ship-gpio");
			if (rc) {
				chg_err("unable to request ship-gpio:%d\n", chip->normalchg_gpio.ship_gpio);
			} else {
				rc = oplus_ship_gpio_init(chip);
				if (rc)
					chg_err("unable to init ship-gpio:%d\n", chip->normalchg_gpio.ship_gpio);
			}
		}
		chg_err("ship-gpio:%d\n", chip->normalchg_gpio.ship_gpio);
	}

	return rc;
}
static bool oplus_chg_get_vbus_status(struct oplus_chg_chip *chip)
{
	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return false;
	}
	return chip->charger_exist;
}

bool oplus_usbtemp_condition(void)
{
//	int level = -1;
//	int chg_volt = 0;
	struct oplus_chg_chip *chip = g_oplus_chip;

	if(!chip || !pinfo) {
		return false;
	}
	return oplus_chg_get_vbus_status(chip);
}

static bool oplus_usbtemp_check_is_gpio(struct oplus_chg_chip *chip)
{
	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return false;
	}

	if (gpio_is_valid(chip->normalchg_gpio.dischg_gpio))
		return true;

	return false;
}

static bool oplus_usbtemp_check_is_platpmic(struct oplus_chg_chip *chip)
{
	struct device_node *node = chip->dev->of_node;

	if (!node) {
		printk(KERN_ERR "device tree info missing\n", __func__);
		return false;
	}

	if (of_property_read_bool(node, "qcom,usbtemp_dischg_by_pmic"))
		return true;

	return false;
}

static bool oplus_usbtemp_check_is_support(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return false;
	}

	if (oplus_usbtemp_check_is_gpio(chip) == true)
		return true;

	if (oplus_usbtemp_check_is_platpmic(chip) == true)
		return true;

	chg_err("not support, return false\n");

	return false;
}

static int oplus_dischg_gpio_init(struct oplus_chg_chip *chip)
{
	if (!chip) {
		chg_err("oplus_chip not ready!\n");
		return -EINVAL;
	}
    
    gpio_direction_output(chip->normalchg_gpio.dischg_gpio, 0);
    chg_err("set dischg enable = %d \n",gpio_get_value(chip->normalchg_gpio.dischg_gpio));

/*
	chip->normalchg_gpio.pinctrl = devm_pinctrl_get(chip->dev);

	if (IS_ERR_OR_NULL(chip->normalchg_gpio.pinctrl)) {
		chg_err("get dischg_pinctrl fail\n");
		return -EINVAL;
	}

	chip->normalchg_gpio.dischg_enable = pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, "dischg_enable");
	if (IS_ERR_OR_NULL(chip->normalchg_gpio.dischg_enable)) {
		chg_err("get dischg_enable fail\n");
		return -EINVAL;
	}

	chip->normalchg_gpio.dischg_disable = pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, "dischg_disable");
	if (IS_ERR_OR_NULL(chip->normalchg_gpio.dischg_disable)) {
		chg_err("get dischg_disable fail\n");
		return -EINVAL;
	}

	pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.dischg_disable);
*/
	return 0;
}

#define USBTEMP_DEFAULT_VOLT_VALUE_MV 950
void oplus_get_usbtemp_volt(struct oplus_chg_chip *chip)
{
	int rc, usbtemp_volt = 0;
	static int usbtemp_volt_l_pre = USBTEMP_DEFAULT_VOLT_VALUE_MV;
	static int usbtemp_volt_r_pre = USBTEMP_DEFAULT_VOLT_VALUE_MV;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: smb5_chg not ready!\n", __func__);
		return ;
	}
	if (IS_ERR_OR_NULL(pinfo->usb_temp_v_l_chan)) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: pinfo->usb_temp_v_l_chan  is  NULL !\n", __func__);
		chip->usbtemp_volt_l = usbtemp_volt_l_pre;
		goto usbtemp_next;
	}

	rc = iio_read_channel_processed(pinfo->usb_temp_v_l_chan, &usbtemp_volt);
	if (rc < 0) {
		chg_err("[OPLUS_CHG][%s]: iio_read_channel_processed  get error\n", __func__);
		chip->usbtemp_volt_l = usbtemp_volt_l_pre;
		goto usbtemp_next;
	}

	chip->usbtemp_volt_l = usbtemp_volt;
	usbtemp_volt_l_pre = chip->usbtemp_volt_l;
usbtemp_next:
	usbtemp_volt = 0;
	if (IS_ERR_OR_NULL(pinfo->usb_temp_v_r_chan)) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: pinfo->usb_temp_v_r_chan  is  NULL !\n", __func__);
		chip->usbtemp_volt_r = usbtemp_volt_r_pre;
		return;
	}

	rc = iio_read_channel_processed(pinfo->usb_temp_v_r_chan, &usbtemp_volt);
	if (rc < 0) {
		chg_err("[OPLUS_CHG][%s]: iio_read_channel_processed  get error\n", __func__);
		chip->usbtemp_volt_r = usbtemp_volt_r_pre;
		return;
	}

	chip->usbtemp_volt_r = usbtemp_volt;
	usbtemp_volt_r_pre = chip->usbtemp_volt_r;

	/*chg_err("usbtemp_volt_l:%d, usbtemp_volt_r:%d\n",chip->usbtemp_volt_l, chip->usbtemp_volt_r);*/
	return;
}

int oplus_get_usbtemp_volt_l(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (chip == NULL) {
		return 0;
	}

	return chip->usbtemp_volt_l;
}

int oplus_get_usbtemp_volt_r(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (chip == NULL) {
		return 0;
	}

	return chip->usbtemp_volt_r;
}

static void oplus_usbtemp_thread_init(void)
{
	oplus_usbtemp_kthread =
			kthread_run(oplus_usbtemp_monitor_common_new_method, g_oplus_chip, "usbtemp_kthread");
	if (IS_ERR(oplus_usbtemp_kthread)) {
		chg_err("failed to cread oplus_usbtemp_kthread\n");
	}
}

void oplus_wake_up_usbtemp_thread(void)
{
	if (oplus_usbtemp_check_is_support() == true) {
		g_oplus_chip->usbtemp_check = oplus_usbtemp_condition();
		if (g_oplus_chip->usbtemp_check)
			wake_up_interruptible(&g_oplus_chip->oplus_usbtemp_wq_new_method);
	}
}

int oplus_chg_get_battery_btb_temp_cal(void)
{
	int temp_val = 25, rc = -EINVAL;

	Batt_BTB_thermal = thermal_zone_get_zone_by_name("pa-thmzone");
	if (IS_ERR(Batt_BTB_thermal)) {
		chg_err("Can't get Batt_BTB_thermal\n");
		return temp_val;
	}

	rc = thermal_zone_get_temp(Batt_BTB_thermal, &temp_val);
	if (rc) {
		chg_err("thermal_zone_get_temp get error");
		return temp_val;
	}

	temp_val = temp_val%1000 ? ((temp_val / 1000)+1) : (temp_val / 1000);
	if (get_eng_version() == HIGH_TEMP_AGING){
		return 25;
		}
	return temp_val;
}
EXPORT_SYMBOL(oplus_chg_get_battery_btb_temp_cal);

static int oplus_chg_usbtemp_parse_dt(struct oplus_chg_chip *chip)
{
	int rc = 0;
	struct device_node *node = NULL;

	if (chip)
		node = chip->dev->of_node;
	if (node == NULL) {
		chg_err("oplus_chip or device tree info. missing\n");
		return -EINVAL;
	}

	chip->normalchg_gpio.dischg_gpio = of_get_named_gpio(node, "qcom,dischg-gpio", 0);
	if (chip->normalchg_gpio.dischg_gpio <= 0) {
		chg_err("Couldn't read qcom,dischg-gpio rc=%d, qcom,dischg-gpio:%d\n",
				rc, chip->normalchg_gpio.dischg_gpio);
	} else {
		if (oplus_usbtemp_check_is_support() == true) {
			rc = gpio_request(chip->normalchg_gpio.dischg_gpio, "dischg-gpio");
			if (rc) {
				chg_err("unable to request dischg-gpio:%d\n",
						chip->normalchg_gpio.dischg_gpio);
			} else {
				rc = oplus_dischg_gpio_init(chip);
				if (rc)
					chg_err("unable to init dischg-gpio:%d\n",
							chip->normalchg_gpio.dischg_gpio);
			}
		}
		chg_err("dischg-gpio:%d\n", chip->normalchg_gpio.dischg_gpio);
	}

	return rc;
}

static int oplus_chg_parse_custom_dt(struct oplus_chg_chip *chip)
{
	int rc = 0;
	struct device_node *node = NULL;
	
	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return -EINVAL;
	}

	rc = oplus_chg_chargerid_parse_dt(chip);
	if (rc) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chg_chargerid_parse_dt fail!\n", __func__);
		return -EINVAL;
	}

	rc = oplus_chg_shipmode_parse_dt(chip);
	if (rc) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chg_shipmode_parse_dt fail!\n", __func__);
		return -EINVAL;
	}

	rc = oplus_chg_shortc_hw_parse_dt(chip);
	if (rc) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chg_shortc_hw_parse_dt fail!\n", __func__);
		return -EINVAL;
	}

	rc = oplus_chg_usbtemp_parse_dt(chip);
	if (rc) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chg_usbtemp_parse_dt fail!\n", __func__);
		return -EINVAL;
	}

/*	rc = oplus_chg_ccdetect_parse_dt(chip);
	if (rc) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chg_ccdetect_parse_dt fail!\n", __func__);
	}
	
	rc = oplus_mtk_hv_flashled_dt(chip);
	if (rc) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_mtk_hv_flashled_dt fail!\n", __func__);
		return -EINVAL;
	}

	rc = oplus_mtk_parse_wls_dt(chip);
	if (rc) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_mtk_parse_wls_dt fail!\n", __func__);
		return -EINVAL;
	}
*/
	node = chip->dev->of_node;

	return rc;
}

static int ac_get_property(struct power_supply *psy,
	enum power_supply_property psp, union power_supply_propval *val)
{
	int rc = 0;
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		return -EINVAL;
	}

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		if (chip->charger_exist && (get_boot_mode() == MSM_BOOT_MODE__CHARGE)) {
			chip->ac_online = true;
			val->intval = chip->ac_online;
			break;
		}
	default:
		rc = oplus_ac_get_property(psy, psp, val);
		break;
	}

	return rc;
}

static int usb_get_property(struct power_supply *psy,
	enum power_supply_property psp, union power_supply_propval *val)
{
	return oplus_usb_get_property(psy, psp, val);
}

static int battery_prop_is_writeable(struct power_supply *psy,
	enum power_supply_property psp)
{
	return oplus_battery_property_is_writeable(psy, psp);
}

static int battery_set_property(struct power_supply *psy,
	enum power_supply_property psp, const union power_supply_propval *val)
{
	int ret = 0;
	struct oplus_chg_chip *chip = g_oplus_chip;
	static int last_ap_current = 0;

	if (!chip) {
		return ret;
	}

	switch (psp) {
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		if (chip->dual_charger_support && chip->smart_charging_screenoff) {
			if ((charger_ic__det_flag == (1 << SGM41542 | 1 << BQ2591X)) ||
				(charger_ic__det_flag == (1 << SGM41542))) {
				oplus_sgm41542_set_ap_current(val->intval);

				if (last_ap_current != val->intval) {
					last_ap_current = val->intval;
					chip->cool_down_done = true;
				}
			}
			chg_err("ap_charge_current=%d, last_ap_current=%d, cool_down_done=%d\n",
						val->intval, last_ap_current, chip->cool_down_done);
			break;
		}
	default:
		ret = oplus_battery_set_property(psy, psp, val);
		break;
	}

	return ret;
}

static int battery_get_property(struct power_supply *psy,
	enum power_supply_property psp, union power_supply_propval *val)
{
	int rc = 0;
    
	if (!is_vooc_project()) {
		switch (psp) {
		case POWER_SUPPLY_PROP_CAPACITY_LEVEL:
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_NORMAL;
			if (g_oplus_chip && (g_oplus_chip->ui_soc == 0)) {
				val->intval = POWER_SUPPLY_CAPACITY_LEVEL_CRITICAL;
					chg_err("bat pro POWER_SUPPLY_CAPACITY_LEVEL_CRITICAL, should shutdown!!!\n");
				}
			break;
		case POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN:
			if (g_oplus_chip) {
				val->intval = g_oplus_chip->batt_fcc * 1000;
			}
			break;
		case POWER_SUPPLY_PROP_TIME_TO_FULL_NOW:
			val->intval = 0;
			break;
		default:
			rc = oplus_battery_get_property(psy, psp, val);
			break;
		}
	}

	return 0;
}

static enum power_supply_property ac_properties[] = {
	POWER_SUPPLY_PROP_ONLINE,
};

static enum power_supply_property usb_properties[] = {
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_CURRENT_MAX,
	POWER_SUPPLY_PROP_VOLTAGE_MAX,
};

static enum power_supply_property battery_properties[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_VOLTAGE_MIN,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CHARGE_NOW,
	POWER_SUPPLY_PROP_CHARGE_COUNTER,
	POWER_SUPPLY_PROP_CURRENT_MAX,
	POWER_SUPPLY_PROP_CHARGE_FULL,
	POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN,
	POWER_SUPPLY_PROP_TIME_TO_FULL_NOW,
	POWER_SUPPLY_PROP_CAPACITY_LEVEL,
};


static int set_batt_cap(struct charger_manager *cm, int cap)
{
	union power_supply_propval val;
	struct power_supply *fuel_gauge;
	int ret,temp_soc;


	fuel_gauge = power_supply_get_by_name(cm->desc->psy_fuel_gauge);
	if (!fuel_gauge) {
		chg_err("can not find fuel gauge device\n");
		return -ENODEV;
	}
	temp_soc = cap * 10;
	val.intval = temp_soc;
	chg_err("set_batt_cap temp_soc = %d,soc = %d\n",temp_soc,cap);
	ret = power_supply_set_property(fuel_gauge, POWER_SUPPLY_PROP_CAPACITY, &val);
	power_supply_put(fuel_gauge);
	if (ret)
		chg_err("failed to save current battery capacity\n");

	return ret;
}
static int cm_set_charging_status(struct charger_manager *cm, bool enable)
{
	union power_supply_propval val;
	struct power_supply *fuel_gauge;
	int ret = 0;

	val.intval = enable ? POWER_SUPPLY_STATUS_CHARGING : POWER_SUPPLY_STATUS_DISCHARGING;

	fuel_gauge = power_supply_get_by_name(cm->desc->psy_fuel_gauge);
	if (!fuel_gauge)
		return -ENOMEM;

	ret = power_supply_set_property(fuel_gauge, POWER_SUPPLY_PROP_STATUS, &val);
	power_supply_put(fuel_gauge);

	return ret;
}

int oplus_set_charging_status(bool enable){
	int ret= -1;
	static int pre_enable = -1;

	if(pre_enable != -1){
		if(pre_enable != enable){
			pre_enable = enable;
			if(pinfo)
				ret = cm_set_charging_status(pinfo, enable);
			else
				chg_err("pinfo = NULL\n");
		}else{
            return ret;
        }
	}else{
		pre_enable = enable;
		if(pinfo)
			ret = cm_set_charging_status(pinfo, enable);
		else
			chg_err("pinfo = NULL\n");
	}
    chg_err("set charging = %d ret = %d\n",enable,ret);
    return ret;
}
EXPORT_SYMBOL(oplus_set_charging_status);

static struct cm_power_supply_data ac_main = {
	.psd = {
		.name = "ac",
		.type = POWER_SUPPLY_TYPE_MAINS,
		.properties = ac_properties,
		.num_properties = ARRAY_SIZE(ac_properties),
		.get_property = ac_get_property,
	},
	.ONLINE = 0,
};
	
	/* usb_data initialization */
static struct cm_power_supply_data usb_main = {
	.psd = {
		.name = "usb",
		.type = POWER_SUPPLY_TYPE_USB,
		.properties = usb_properties,
		.num_properties = ARRAY_SIZE(usb_properties),
		.get_property = usb_get_property,
	},
	.ONLINE = 0,
};
static struct cm_power_supply_data battery_main = {
	.psd = {
		.name = "battery",
		.type = POWER_SUPPLY_TYPE_BATTERY,
		.properties = battery_properties,
		.num_properties = ARRAY_SIZE(battery_properties),
		.get_property = battery_get_property,
		.set_property = battery_set_property,
		.property_is_writeable	= battery_prop_is_writeable,
	},
	.ONLINE = 0,
};

void oplus_chg_default_method0(void)
{
	pr_err("charger ic default %d\n", charger_ic__det_flag);
}

int oplus_chg_default_method1(void)
{
	return 0;
}

int oplus_chg_default_method2(int n)
{
	return 0;
}

void oplus_chg_default_method3(int n)
{

}

bool oplus_chg_default_method4(void)
{
	return false;
}

struct oplus_chg_operations  oplus_chg_default_ops = {
	.dump_registers = oplus_chg_default_method0,
	.kick_wdt = oplus_chg_default_method1,
	.hardware_init = oplus_chg_default_method1,
	.charging_current_write_fast = oplus_chg_default_method2,
	.set_aicl_point = oplus_chg_default_method3,
	.input_current_write = oplus_chg_default_method2,
	.float_voltage_write = oplus_chg_default_method2,
	.term_current_set = oplus_chg_default_method2,
	.charging_enable = oplus_chg_default_method1,
	.charging_disable = oplus_chg_default_method1,
	.get_charging_enable = oplus_chg_default_method1,
	.charger_suspend = oplus_chg_default_method1,
	.charger_unsuspend = oplus_chg_default_method1,
	.set_rechg_vol = oplus_chg_default_method2,
	.reset_charger = oplus_chg_default_method1,
	.read_full = oplus_chg_default_method1,
	.otg_enable = oplus_chg_default_method1,
	.otg_disable = oplus_chg_default_method1,
	.set_charging_term_disable = oplus_chg_default_method1,
	.check_charger_resume = oplus_chg_default_method4,

	.get_charger_type = oplus_chg_default_method1,
	.get_charger_volt = oplus_chg_default_method1,
	/*int (*get_charger_current)(void);*/
	.get_chargerid_volt = NULL,
	.set_chargerid_switch_val = oplus_chg_default_method3,
	.get_chargerid_switch_val = oplus_chg_default_method1,
	.check_chrdet_status = oplus_chg_default_method4,

	.get_boot_mode = get_boot_mode,
	.get_boot_reason = oplus_chg_default_method1,
	.get_instant_vbatt = oplus_battery_meter_get_battery_voltage,
	.get_rtc_soc = get_rtc_spare_oplus_fg_value,
	.set_rtc_soc = set_rtc_spare_oplus_fg_value,

	.get_chg_current_step = oplus_chg_default_method1,
	.need_to_check_ibatt = oplus_chg_default_method4,
	.get_dyna_aicl_result = oplus_chg_default_method1,
	.get_shortc_hw_gpio_status = oplus_chg_default_method4,
	/*void (*check_is_iindpm_mode) (void);*/
	.oplus_chg_get_pd_type = NULL,
	.oplus_chg_pd_setup = NULL,
	.get_charger_subtype = oplus_chg_default_method1,
	.set_qc_config = NULL,
	.enable_qc_detect = NULL,
	.oplus_chg_set_high_vbus = NULL,
};

static int charger_manager_probe(struct platform_device *pdev)
{
//	struct device_node *np = pdev->dev.of_node;
	struct charger_desc *desc = cm_get_drv_data(pdev);
	struct charger_manager *cm;
	struct oplus_chg_chip *oplus_chip;
    int rc;


    chg_err("%s:num 2  =%d\n",__func__, __LINE__);

    
	if (IS_ERR(desc)) {
		dev_err(&pdev->dev, "No platform data (desc) found\n");
		return PTR_ERR(desc);
	}

	cm = devm_kzalloc(&pdev->dev, sizeof(*cm), GFP_KERNEL);
	if (!cm)
		return -ENOMEM;
	
	oplus_chip = devm_kzalloc(&pdev->dev, sizeof(*oplus_chip), GFP_KERNEL);
	if (!oplus_chip)
		return -ENOMEM;

	oplus_chip->dev = &pdev->dev;
	g_oplus_chip = oplus_chip;
    pinfo = cm;
	oplus_chg_parse_svooc_dt(oplus_chip);
	if (oplus_chip->vbatt_num == 1) {
		if (oplus_gauge_check_chip_is_null()) {
			g_oplus_chip = NULL;
			chg_err("[oplus_chg_init] gauge null, will do after bettery init.\n");
			return -EPROBE_DEFER;
		}

		oplus_chip->dual_charger_support =
			of_property_read_bool(oplus_chip->dev->of_node, "qcom,dual_charger_support");

		charger_ic__det_flag = get_charger_ic_det(oplus_chip);
		if (charger_ic__det_flag == 0) {
			chg_err("charger IC is null, will do after bettery init.\n");
			return -EPROBE_DEFER;
		}

		if (oplus_chip->dual_charger_support) {
			switch(charger_ic__det_flag) {
			case ((1 << SGM41542) | (1 << BQ2591X)):
				oplus_chip->chg_ops = &sgm41542_chg_ops;
				oplus_chip->sub_chg_ops = &bq25910_chg_ops;
				chg_err("charger IC match successful\n");
				break;
			case (1 << SGM41542):
				oplus_chip->chg_ops = &sgm41542_chg_ops;
				oplus_chip->sub_chg_ops = &oplus_chg_default_ops;
				chg_err("sub charger IC match failed\n");
				break;
			default:
				oplus_chip->chg_ops = &oplus_chg_default_ops;
				oplus_chip->sub_chg_ops = &oplus_chg_default_ops;
				chg_err("main & sub charger IC match failed\n");
				break;
			}
		} else {
			switch(charger_ic__det_flag) {
			case ((1 << SGM41512)):
				oplus_chip->chg_ops = &sgm41512_chg_ops;
				chg_err("sgm41512 charger IC match successful\n");
				break;
			default:
				oplus_chip->chg_ops = &oplus_chg_default_ops;
				chg_err("charger IC match failed\n");
				break;
			}
		}
	} else {
		chg_err("[oplus_chg_init] gauge[%d]vooc[%d]adapter[%d]\n",
				oplus_gauge_check_chip_is_null(),
				oplus_vooc_check_chip_is_null(),
				oplus_adapter_check_chip_is_null());
		if (oplus_gauge_check_chip_is_null() || oplus_vooc_check_chip_is_null() || oplus_adapter_check_chip_is_null()) {
			chg_err("[oplus_chg_init] gauge || vooc || adapter null, will do after bettery init.\n");
			return -EPROBE_DEFER;
		}
		//oplus_chip->chg_ops = oplus_get_chg_ops();

	//	is_vooc_cfg = true;
		is_mtksvooc_project = true;
	//	chg_err("%s is_vooc_cfg = %d\n", __func__, is_vooc_cfg);
	}
	cm->dev = &pdev->dev;
	cm->desc = desc;
	platform_set_drvdata(pdev, cm);

	ac_main.cm = cm;
	ac_main.psy = power_supply_register(&pdev->dev, &ac_main.psd, NULL);
        chg_err("%s:num =%d\n",__func__, __LINE__);
	if (IS_ERR(ac_main.psy)) {
		dev_err(&pdev->dev, "Cannot register usb_main.psy with name \"%s\"\n",
			ac_main.psd.name);
		return PTR_ERR(ac_main.psy);

	}

	usb_main.cm = cm;
	usb_main.psy = power_supply_register(&pdev->dev, &usb_main.psd, NULL);
	if (IS_ERR(usb_main.psy)) {
		dev_err(&pdev->dev, "Cannot register usb_main.psy with name \"%s\"\n",
			usb_main.psd.name);
		return PTR_ERR(usb_main.psy);

	}
	battery_main.cm = cm;
	battery_main.psy = power_supply_register(&pdev->dev, &battery_main.psd, NULL);
	if (IS_ERR(battery_main.psy)) {
		dev_err(&pdev->dev, "Cannot register usb_main.psy with name \"%s\"\n",
			battery_main.psd.name);
		return PTR_ERR(battery_main.psy);

	}
	cm->port = typec_register_port(cm->dev, &cm->typec_cap);
	if (!cm->port) {
		dev_err(cm->dev, "failed to register port!\n");
		return -ENODEV;
	}

	oplus_chg_parse_custom_dt(oplus_chip);
	oplus_chg_parse_charger_dt(oplus_chip);
	oplus_chip->chg_ops->hardware_init();
	oplus_chip->authenticate = true;//oplus_gauge_get_batt_authenticate();
	chg_err("oplus_chg_init!\n");
	oplus_chg_init(oplus_chip);

	if (get_boot_mode() != MSM_BOOT_MODE__CHARGE) {
		oplus_tbatt_power_off_task_init(oplus_chip);
	}

	cm->chargeric_temp_chan = devm_iio_channel_get(cm->dev, "chargeric_temp");
	if (IS_ERR(cm->chargeric_temp_chan)) {
		chg_err("Couldn't get chargeric_temp_chan...\n");
		cm->chargeric_temp_chan = NULL;
	}

	cm->charger_id_chan = devm_iio_channel_get(cm->dev, "charger_id");
	if (IS_ERR(cm->charger_id_chan)) {
		chg_err("Couldn't get charger_id_chan...\n");
	}	
	
	cm->usb_temp_v_l_chan = devm_iio_channel_get(cm->dev, "usb_temp_v_l");
	if (IS_ERR(cm->usb_temp_v_l_chan)) {
		chg_err("Couldn't get usb_temp_v_l_chan...\n");
		cm->usb_temp_v_l_chan = NULL;
	}

	cm->usb_temp_v_r_chan = devm_iio_channel_get(cm->dev, "usb_temp_v_r");
	if (IS_ERR(cm->usb_temp_v_r_chan)) {
		chg_err("Couldn't get usb_temp_v_r_chan...\n");
		cm->usb_temp_v_r_chan = NULL;
	}

	cm->charger_vbus_chan = devm_iio_channel_get(cm->dev, "charge_vbus");
	if (IS_ERR(cm->charger_vbus_chan)) {
		chg_err("Couldn't get charge_vbus...\n");
		cm->charger_vbus_chan = NULL;
	}

	oplus_chip->con_volt = con_volt_ums9230;
	oplus_chip->con_temp = con_temp_ums9230;
	oplus_chip->len_array = ARRAY_SIZE(con_temp_ums9230);
	    chg_err("%s : %d\n",__func__,__LINE__);
	if (oplus_usbtemp_check_is_support() == true)
		oplus_usbtemp_thread_init();

	oplus_chg_wake_update_work();
	oplus_chg_configfs_init(oplus_chip);
	rc = oplus_chg_usb_init_mod(cm);
	if (rc < 0) {
		pr_err("oplus_chg_usb_init_mod failed, rc=%d\n", rc);
	}

	probe_done = true;

	return 0;
}

static int charger_manager_remove(struct platform_device *pdev)
{
	struct charger_manager *cm = platform_get_drvdata(pdev);

	oplus_chg_mod_unregister(cm->usb_ocm);

	power_supply_unregister(cm->charger_psy);

	return 0;
}

static void charger_manager_shutdown(struct platform_device *pdev)
{

	struct charger_manager *cm = platform_get_drvdata(pdev);
	if (g_oplus_chip)
        set_batt_cap(cm, g_oplus_chip->ui_soc);
#ifdef OPLUS_FEATURE_CHG_BASIC
	if (g_oplus_chip) {
		enter_ship_mode_function(g_oplus_chip);
	}
#endif
}

static const struct platform_device_id charger_manager_id[] = {
	{ "charger-manager", 0 },
	{ },
};
MODULE_DEVICE_TABLE(platform, charger_manager_id);

static struct platform_driver charger_manager_driver = {
	.driver = {
		.name = "charger-manager",
		.of_match_table = charger_manager_match,
	},
	.probe = charger_manager_probe,
	.remove = charger_manager_remove,
	.shutdown = charger_manager_shutdown,
	.id_table = charger_manager_id,
};

static int __init charger_manager_init(void)
{
   chg_err("%s:num =%d\n",__func__, __LINE__);

   bq25910_driver_init();
   sgm41512_charger_init();
   sgm41542_charger_init();

   hl7138_subsys_init();

   sc8547_subsys_init();

	return platform_driver_register(&charger_manager_driver);
}

static void __exit charger_manager_exit(void)
{
	platform_driver_unregister(&charger_manager_driver);
}

oplus_chg_module_register(charger_manager);


MODULE_AUTHOR("MyungJoo Ham <myungjoo.ham@samsung.com>");
MODULE_DESCRIPTION("Charger Manager");
MODULE_LICENSE("GPL v2");
