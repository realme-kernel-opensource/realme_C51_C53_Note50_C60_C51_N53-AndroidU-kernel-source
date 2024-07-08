/*
 * BQ2589x battery charging driver
 *
 * Copyright (C) 2013 Texas Instruments
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 * THIS PACKAGE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/power_supply.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/err.h>
#include <linux/bitops.h>
#include <linux/math64.h>
#include <linux/power_supply.h>
#include <linux/iio/consumer.h>
#include <linux/pm_wakeup.h>

#ifdef CONFIG_OPLUS_CHARGER_MTK
#include <mt-plat/upmu_common.h>
#include <mt-plat/charger_class.h>
#include <mt-plat/charger_type.h>
#include <mt-plat/mtk_boot.h>
#include "../../supply/mediatek/charger/mtk_charger_intf.h"
#endif	/*CONFIG_OPLUS_CHARGER_MTK*/
#include <linux/regulator/driver.h>
#include <linux/regulator/of_regulator.h>
#include <linux/regulator/machine.h>

#include "../oplus_charger.h"
#include "../oplus_gauge.h"
#include "../oplus_vooc.h"
#include "../oplus_short.h"
#include "../oplus_adapter.h"
#include "../charger_ic/oplus_short_ic.h"
#include "../gauge_ic/oplus_bq27541.h"
#include <soc/oplus/boot_mode.h>

#define _BQ25890H_
#include "oplus_sy697x.h"
#include <linux/time.h>
#include "../voocphy/oplus_voocphy.h"
#include "../oplus_configfs.h"
#include <linux/rtc.h>

#undef pr_info
#define pr_info pr_err

enum hvdcp_type {
	HVDCP_5V,
	HVDCP_9V,
	HVDCP_12V,
	HVDCP_20V,
	HVDCP_CONTINOUS,
	HVDCP_DPF_DMF,
};

#define DEFAULT_CV 4435

#ifndef USB_TEMP_HIGH
#define USB_TEMP_HIGH 0x01
#endif

int chg_init_done = 0;
int typec_dir = 0;
static int debug_log_open = 0;

#undef pr_debug
#define pr_debug pr_err
struct task_struct *charger_type_kthread;
static DECLARE_WAIT_QUEUE_HEAD(oplus_chgtype_wq);

static int chg_thermal_temp = 25000;
static int bb_thermal_temp = 25000;
static int flash_thermal_temp = 25000;
static int board_thermal_temp = 25000;

/*ntc table*/
static int con_temp_855[] = {
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

static int con_volt_855[] = {
	1725,
	1716,
	1707,
	1697,
	1687,
	1677,
	1666,
	1655,
	1643,
	1631,
	1618,
	1605,
	1591,
	1577,
	1562,
	1547,
	1531,
	1515,
	1499,
	1482,
	1465,
	1447,
	1429,
	1410,
	1391,
	1372,
	1352,
	1332,
	1311,
	1291,
	1270,
	1248,
	1227,
	1205,
	1183,
	1161,
	1139,
	1117,
	1094,
	1072,
	1049,
	1027,
	1004,
	982,
	960,
	938,
	915,
	893,
	872,
	850,
	829,
	808,
	787,
	766,
	746,
	726,
	706,
	687,
	668,
	649,
	631,
	613,
	595,
	578,
	561,
	544,
	528,
	512,
	497,
	482,
	467,
	453,
	439,
	426,
	412,
	400,
	387,
	375,
	363,
	352,
	341,
	330,
	320,
	310,
	300,
	290,
	281,
	272,
	264,
	255,
	247,
	239,
	232,
	224,
	217,
	210,
	204,
	197,
	191,
	185,
	179,
	174,
	168,
	163,
	158,
	153,
	148,
	143,
	139,
	135,
	131,
	126,
	123,
	119,
	115,
	112,
	108,
	105,
	102,
	99,
	96,
	93,
	90,
	87,
	85,
	82,
	80,
	78,
	75,
	73,
	71,
	69,
	67,
	65,
	63,
	61,
	60,
	58,
	56,
	55,
	53,
	52,
	50,
	49,
	47,
	46,
};

#define OPLUS_DELAY_WORK_TIME_BASE        round_jiffies_relative(msecs_to_jiffies(100))
#define OPLUS_BC12_RETRY_TIME        round_jiffies_relative(msecs_to_jiffies(200))
#define OPLUS_BC12_RETRY_TIME_CDP        round_jiffies_relative(msecs_to_jiffies(400))

#define OPLUS_TYPEC_DETACH	0
#define OPLUS_TYPEC_SRC_DFP	1
#define OPLUS_TYPEC_SNK_UFP	2
#define OPLUS_TYPEC_ACCESSORY	3

//static bool disable_PE = 0;
static bool disable_QC = 0;
//static bool disable_PD = 0;
static bool dumpreg_by_irq = 0;
static int  current_percent = 70; //wdwdebug

static struct sy697x *g_sy;
static struct task_struct *oplushg_usbtemp_kthread;
int sy697x_get_input_current(void);
int oplus_sy697x_hardware_init(void);
int oplus_sy697x_charger_suspend(void);
int oplus_sy697x_charger_unsuspend(void);


extern int oplus_usbtemp_monitor_common(void *data);
extern bool oplus_chg_wake_update_work(void);
bool is_bq25890h(struct sy697x *sy);
#ifdef CONFIG_OPLUS_CHARGER_MTK
void oplus_wake_up_usbtemp_thread(void);
extern struct oplus_chg_chip *g_oplus_chip;
extern int oplus_battery_meter_get_battery_voltage(void);
extern int oplus_get_rtc_ui_soc(void);
extern int oplus_set_rtc_ui_soc(int value);
extern int set_rtc_spare_fg_value(int val);
extern void mt_power_off(void);
extern bool pmic_chrdet_status(void);
extern void mt_usb_connect(void);
extern void mt_usb_disconnect(void);

void Charger_Detect_Init(void);
void Charger_Detect_Release(void);
#else	/*CONFIG_OPLUS_CHARGER_MTK*/
#define Charger_Detect_Init()
#define Charger_Detect_Release()
#define META_BOOT	0
static int oplus_sy697x_get_vbus(void);
void oplus_sy697x_dump_registers(void);
static int oplus_register_extcon(struct sy697x *chip);
bool is_usb_rdy() {return true;}
struct oplus_chg_chip *g_oplus_chip;
#endif
extern void cpuboost_charge_event(int flag);
extern void oplus_chg_set_chargerid_switch_val(int value);
extern int oplus_vooc_get_adapter_update_real_status(void);
extern void oplus_chg_set_chargerid_switch_val(int value);
void oplus_sy697x_set_mivr_by_battery_vol(void);
static void sy697x_dump_regs(struct sy697x *sy);
int sy697x_enable_enlim(struct sy697x *sy);
int oplus_sy697x_set_aicr(int current_ma);
bool oplus_get_otg_enable(void);
int oplus_sy697x_enable_otg(void);
int oplus_sy697x_disable_otg(void);
extern bool oplus_voocphy_fastchg_ing(void);
int oplus_sy697x_get_charger_type(void);

#ifdef CONFIG_OPLUS_CHARGER_MTK
static const struct charger_properties sy697x_chg_props = {
	.alias_name = "sy697x",
};
#endif /*CONFIG_OPLUS_CHARGER_MTK*/


#ifdef OPLUS_FEATURE_CHG_BASIC
bool oplus_ccdetect_check_is_gpio(struct oplus_chg_chip *chip);
int oplus_ccdetect_gpio_init(struct oplus_chg_chip *chip);
void oplus_ccdetect_irq_init(struct oplus_chg_chip *chip);
void oplus_ccdetect_disable(void);
void oplus_ccdetect_enable(void);
int oplus_ccdetect_get_power_role(void);
bool oplus_sy697x_get_otg_switch_status(void);
void oplus_sy697x_set_otg_switch_status(bool value);
bool oplus_ccdetect_support_check(void);
int oplus_chg_ccdetect_parse_dt(struct oplus_chg_chip *chip);
int oplus_sy697x_get_otg_online_status(void);
bool oplus_get_otg_online_status_default(void);
irqreturn_t oplus_ccdetect_change_handler(int irq, void *data);

//====================================================================//
#define OPLUS_MODE_DRP	1
#define OPLUS_MODE_SNK	0
extern int oplus_sgm7220_set_mode(int mode);
extern void oplus_usbtemp_recover_func(struct oplus_chg_chip *chip);
extern int oplus_voocphy_get_cp_vbus(void);

int oplus_get_usb_status(void)
{
	if (g_oplus_chip && g_oplus_chip->usb_status == USB_TEMP_HIGH) {
		return g_oplus_chip->usb_status;
	} else {
		return 0;
	}
}
EXPORT_SYMBOL(oplus_get_usb_status);


int oplus_set_mode(int mode)
{
	int rc = 0;
	if (mode == OPLUS_MODE_DRP)
		rc = oplus_sgm7220_set_mode(3);	//drp
	else
		rc = oplus_sgm7220_set_mode(1);	//snk
	return rc;
}

bool oplus_ccdetect_check_is_gpio(struct oplus_chg_chip *chip)
{
	struct smb_charger *chg = NULL;
	int boot_mode = get_boot_mode();

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: discrete_charger not ready!\n", __func__);
		return false;
	}
	chg = &chip->pmic_spmi.smb5_chip->chg;

	/* HW engineer requirement */
	if (boot_mode == MSM_BOOT_MODE__RF || boot_mode == MSM_BOOT_MODE__WLAN
			|| boot_mode == MSM_BOOT_MODE__FACTORY)
		return false;

	if (gpio_is_valid(chg->ccdetect_gpio))
		return true;

	return false;
}



int oplus_ccdetect_gpio_init(struct oplus_chg_chip *chip)
{
	struct smb_charger *chg = NULL;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: discrete_charger not ready!\n", __func__);
		return -EINVAL;
	}
	chg = &chip->pmic_spmi.smb5_chip->chg;

	chg->ccdetect_pinctrl = devm_pinctrl_get(chip->dev);

	if (IS_ERR_OR_NULL(chg->ccdetect_pinctrl)) {
		chg_err("get ccdetect ccdetect_pinctrl fail\n");
		return -EINVAL;
	}

	chg->ccdetect_active = pinctrl_lookup_state(chg->ccdetect_pinctrl, "ccdetect_active");
	if (IS_ERR_OR_NULL(chg->ccdetect_active)) {
		chg_err("get ccdetect_active fail\n");
		return -EINVAL;
	}

	chg->ccdetect_sleep = pinctrl_lookup_state(chg->ccdetect_pinctrl, "ccdetect_sleep");
	if (IS_ERR_OR_NULL(chg->ccdetect_sleep)) {
		chg_err("get ccdetect_sleep fail\n");
		return -EINVAL;
	}

	if (chg->ccdetect_gpio > 0) {
		gpio_direction_input(chg->ccdetect_gpio);
	}

	pinctrl_select_state(chg->ccdetect_pinctrl, chg->ccdetect_active);

	return 0;
}


void oplus_ccdetect_irq_init(struct oplus_chg_chip *chip)
{
	struct smb_charger *chg = NULL;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: discrete_charger not ready!\n", __func__);
		return;
	}
	chg = &chip->pmic_spmi.smb5_chip->chg;

	chg->ccdetect_irq = gpio_to_irq(chg->ccdetect_gpio);
	printk(KERN_ERR "[OPLUS_CHG][%s]: chg->ccdetect_irq[%d]!\n", __func__, chg->ccdetect_irq);
}

void oplus_ccdetect_irq_register(struct oplus_chg_chip *chip)
{
	int ret = 0;
	struct smb_charger *chg = NULL;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: discrete_charger not ready!\n", __func__);
		return;
	}

	chg = &chip->pmic_spmi.smb5_chip->chg;

	ret = devm_request_threaded_irq(chip->dev, chg->ccdetect_irq,
			NULL, oplus_ccdetect_change_handler, IRQF_TRIGGER_FALLING
			| IRQF_TRIGGER_RISING | IRQF_ONESHOT, "ccdetect-change", chip);
	if (ret < 0) {
		chg_err("Unable to request ccdetect-change irq: %d\n", ret);
	}
	printk(KERN_ERR "%s: !!!!! irq register\n", __FUNCTION__);

	ret = enable_irq_wake(chg->ccdetect_irq);
	if (ret != 0) {
		chg_err("enable_irq_wake: ccdetect_irq failed %d\n", ret);
	}
}

void oplus_ccdetect_enable(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;
	struct smb_charger *chg = NULL;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: discrete_charger not ready!\n", __func__);
		return;
	}

	chg = &chip->pmic_spmi.smb5_chip->chg;

	if (oplus_ccdetect_check_is_gpio(chip) != true)
		return;

	/* set DRP mode */
	oplus_set_mode(OPLUS_MODE_DRP);
	pr_err("%s: set drp", __func__);

}

void oplus_ccdetect_disable(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;
	struct smb_charger *chg = NULL;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: discrete_charger not ready!\n", __func__);
		return;
	}

	chg = &chip->pmic_spmi.smb5_chip->chg;

	if (oplus_ccdetect_check_is_gpio(chip) != true)
		return;

	/* set SINK mode */
	oplus_set_mode(OPLUS_MODE_SNK);
	pr_err("%s: set sink", __func__);

}

int oplus_ccdetect_get_power_role(void)
{
	printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chg not ready!\n", __func__);
	return 0;
}

bool oplus_ccdetect_support_check(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return false;
	}

	if (oplus_ccdetect_check_is_gpio(chip) == true)
		return true;

	chg_err("not support, return false\n");

	return false;
}


int oplus_chg_ccdetect_parse_dt(struct oplus_chg_chip *chip)
{
	int rc = 0;
	struct device_node *node = NULL;
	struct smb_charger *chg =  NULL;

	if (chip && chip->pmic_spmi.smb5_chip)
		chg = &chip->pmic_spmi.smb5_chip->chg;
	else
		return -EINVAL;

	if (chg)
		node = chg->dev->of_node;
	if (node == NULL) {
		chg_err("oplus_chg or device tree info. missing\n");
		return -EINVAL;
	}
	chg->ccdetect_gpio = of_get_named_gpio(node, "qcom,ccdetect-gpio", 0);
	if (chg->ccdetect_gpio <= 0) {
		chg_err("Couldn't read qcom,ccdetect-gpio rc=%d, qcom,ccdetect-gpio:%d\n",
				rc, chg->ccdetect_gpio);
	} else {
		if (oplus_ccdetect_support_check() == true) {
			rc = gpio_request(chg->ccdetect_gpio, "ccdetect-gpio");
			if (rc) {
				chg_err("unable to request ccdetect_gpio:%d\n",
						chg->ccdetect_gpio);
			} else {
				rc = oplus_ccdetect_gpio_init(chip);
				if (rc){
					chg_err("unable to init ccdetect_gpio:%d\n",
							chg->ccdetect_gpio);
				}else{
					oplus_ccdetect_irq_init(chip);
					}
			}
		}
		chg_err("ccdetect-gpio:%d\n", chg->ccdetect_gpio);
	}

	return rc;
}

#define CCDETECT_DELAY_MS	50
struct delayed_work usbtemp_recover_work;
irqreturn_t oplus_ccdetect_change_handler(int irq, void *data)
{
	struct oplus_chg_chip *chip = data;
	struct smb_charger *chg = &chip->pmic_spmi.smb5_chip->chg;

	cancel_delayed_work_sync(&chg->ccdetect_work);
	printk(KERN_ERR "[OPLUS_CHG][%s]: Scheduling ccdetect work!\n", __func__);
	schedule_delayed_work(&chg->ccdetect_work,
			msecs_to_jiffies(CCDETECT_DELAY_MS));
	return IRQ_HANDLED;
}


#define DISCONNECT						0
#define STANDARD_TYPEC_DEV_CONNECT	BIT(0)
#define OTG_DEV_CONNECT				BIT(1)
bool oplus_get_otg_online_status_default(void)
{
	if (!g_sy) {
		chg_err("fail to init oplus_chg\n");
		return false;
	}

	return g_sy->otg_present;
}

int oplus_sy697x_get_otg_online_status(void)
{
	int online = 0;
	int level = 0;
	int typec_otg = 0;
	static int pre_level = 1;
	static int pre_typec_otg = 0;
	struct smb_charger *chg = NULL;

	if (!g_sy || !g_oplus_chip) {
		chg_err("[OPLUS_CHG][%s]: chg or g_oplus_chip ...\n", __func__);
		return false;
	}
	chg = &g_oplus_chip->pmic_spmi.smb5_chip->chg;

	if (oplus_ccdetect_check_is_gpio(g_oplus_chip) == true) {
		level = gpio_get_value(chg->ccdetect_gpio);
		if (level != gpio_get_value(chg->ccdetect_gpio)) {
			chg_err("[OPLUS_CHG][%s]: ccdetect_gpio is unstable, try again...\n", __func__);
			usleep_range(5000, 5100);
			level = gpio_get_value(chg->ccdetect_gpio);
		}
	} else {
		return oplus_get_otg_online_status_default();
	}
	online = (level == 1) ? DISCONNECT : STANDARD_TYPEC_DEV_CONNECT;

	typec_otg = oplus_get_otg_online_status_default();
	online = online | ((typec_otg == 1) ? OTG_DEV_CONNECT : DISCONNECT);

	if ((pre_level ^ level) || (pre_typec_otg ^ typec_otg)) {
		pre_level = level;
		pre_typec_otg = typec_otg;
		chg_err("[OPLUS_CHG][%s]: gpio[%s], c-otg[%d], otg_online[%d]\n",
				__func__, level ? "H" : "L", typec_otg, online);
	}

	g_oplus_chip->otg_online = online;
	printk(KERN_ERR "[OPLUS_CHG][%s]:otg_online[%d]\n", __func__, online);
	return online;
}
EXPORT_SYMBOL(oplus_sy697x_get_otg_online_status);


static bool oplus_usbtemp_check_is_gpio(struct oplus_chg_chip *chip)
{
	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: smb5_chg not ready!\n", __func__);
		return false;
	}

	if (gpio_is_valid(chip->normalchg_gpio.dischg_gpio))
		return true;

	return false;
}


static bool oplus_usbtemp_check_is_support(void)
{
	if(oplus_usbtemp_check_is_gpio(g_oplus_chip) == true)
		return true;

	chg_err("dischg return false\n");

	return false;
}


static bool oplus_usbtemp_condition(void)
{
	if (!g_oplus_chip) {
		chg_err("fail to init oplus_chip\n");
		return false;
	}

	g_oplus_chip->usbtemp_check = g_oplus_chip->chg_ops->check_chrdet_status();
	chg_err("check_chrdet_status is %d\n", g_oplus_chip->usbtemp_check);
	return g_oplus_chip->usbtemp_check;
}

static void oplus_wake_up_usbtemp_thread(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		return;
	}
	if (oplus_usbtemp_check_is_support() == true) {
		chip->usbtemp_check = oplus_usbtemp_condition();
		if (chip->usbtemp_check)
			wake_up_interruptible(&chip->oplus_usbtemp_wq);
	}
}

static void oplus_ccdetect_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
						ccdetect_work.work);
	int level;

	level = gpio_get_value(chg->ccdetect_gpio);
	if (level != 1) {
		oplus_ccdetect_enable();
		oplus_wake_up_usbtemp_thread();
	} else {
		if (g_oplus_chip)
			g_oplus_chip->usbtemp_check = oplus_usbtemp_condition();

		if (oplus_sy697x_get_otg_switch_status() == false)
			oplus_ccdetect_disable();
		if(g_oplus_chip->usb_status == USB_TEMP_HIGH) {
			schedule_delayed_work(&usbtemp_recover_work, 0);
		}
	}
}

static void oplus_usbtemp_recover_work(struct work_struct *work)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		return;
	}

	oplus_usbtemp_recover_func(g_oplus_chip);
	pr_err("%s: level []", __func__);
}

#endif /* OPLUS_FEATURE_CHG_BASIC */

static bool opluschg_get_typec_cc_orientation(union power_supply_propval *val)
{
	chg_err("typec_dir = %s\n", typec_dir == 1 ? "cc1 attach" : "cc2_attach");
	val->intval = typec_dir;
	return typec_dir;
}

static void oplus_chg_awake_init(struct sy697x *chip)
{
	chip->suspend_ws = NULL;
	if (!chip) {
		pr_err("[%s]chip is null\n", __func__);
		return;
	}
	chip->suspend_ws = wakeup_source_register(NULL, "split chg wakelock");
	return;
}

static void oplus_chg_wakelock(struct sy697x *chip, bool awake)
{
	static bool pm_flag = false;

	if (!chip || !chip->suspend_ws)
		return;

	if (awake && !pm_flag) {
		pm_flag = true;
		__pm_stay_awake(chip->suspend_ws);
		pr_err("[%s] true\n", __func__);
	} else if (!awake && pm_flag) {
		__pm_relax(chip->suspend_ws);
		pm_flag = false;
		pr_err("[%s] false\n", __func__);
	}
	return;
}

static void oplus_keep_resume_awake_init(struct sy697x *chip)
{
	chip->keep_resume_ws = NULL;
	if (!chip) {
		pr_err("[%s]chip is null\n", __func__);
		return;
	}
	chip->keep_resume_ws = wakeup_source_register(NULL, "split_chg_keep_resume");
	return;
}

static void oplus_keep_resume_wakelock(struct sy697x *chip, bool awake)
{
	static bool pm_flag = false;

	if (!chip || !chip->keep_resume_ws)
		return;

	if (awake && !pm_flag) {
		pm_flag = true;
		__pm_stay_awake(chip->keep_resume_ws);
		pr_err("[%s] true\n", __func__);
	} else if (!awake && pm_flag) {
		__pm_relax(chip->keep_resume_ws);
		pm_flag = false;
		pr_err("[%s] false\n", __func__);
	}
	return;
}


static void oplus_notify_extcon_props(struct sy697x *chg, int id)
{
	union extcon_property_value val;
	union power_supply_propval prop_val;

	opluschg_get_typec_cc_orientation(&prop_val);
	val.intval = ((prop_val.intval == 2) ? 1 : 0);
	extcon_set_property(chg->extcon, id,
			EXTCON_PROP_USB_TYPEC_POLARITY, val);
	val.intval = true;
	extcon_set_property(chg->extcon, id,
			EXTCON_PROP_USB_SS, val);
}

static void oplus_notify_device_mode(bool enable)
{
	struct sy697x *chg = g_sy;

	if (!chg) {
		pr_err("[%s] chg is null\n", __func__);
		return;
	}
	if (enable)
		oplus_notify_extcon_props(chg, EXTCON_USB);

	extcon_set_state_sync(chg->extcon, EXTCON_USB, enable);
	pr_err("[%s] enable[%d]\n", __func__, enable);
}

static void oplus_notify_usb_host(bool enable)
{
	struct sy697x *chg = g_sy;

	if (!chg || !g_oplus_chip) {
		pr_err("[%s] chg or g_oplus_chip is null\n", __func__);
		return;
	}
	if (enable) {
		pr_debug("enabling VBUS in OTG mode\n");
		oplus_sy697x_enable_otg();
		oplus_notify_extcon_props(chg, EXTCON_USB_HOST);
	} else {
		pr_debug("disabling VBUS in OTG mode\n");
		oplus_sy697x_disable_otg();
	}

	power_supply_changed(g_oplus_chip->usb_psy);
	extcon_set_state_sync(chg->extcon, EXTCON_USB_HOST, enable);
	pr_debug("[%s] enable[%d]\n", __func__, enable);
}

void oplus_sy697x_typec_sink_insertion(void)
{
	struct sy697x *chg = g_sy;

	if (!chg || !g_oplus_chip) {
		pr_err("[%s] chg or g_oplus_chip is null\n", __func__);
		return;
	}
	chg->otg_present = true;
	g_oplus_chip->otg_online = true;
	oplus_chg_wake_update_work();

	oplus_notify_usb_host(true);
	pr_debug("wakeup[%s] done!!!\n", __func__);
}

void oplus_typec_src_insertion(void)
{
	pr_debug("[%s] done!!!\n", __func__);
}

void oplus_typec_ra_ra_insertion(void)
{
	pr_debug("[%s] done!!!\n", __func__);
}

void oplus_sy697x_typec_sink_removal(void)
{
	struct sy697x *chg = g_sy;

	if (!chg) {
		pr_err("[%s] chg is null\n", __func__);
		return;
	}
	if (chg->otg_present)
		oplus_notify_usb_host(false);
	chg->otg_present = false;
	g_oplus_chip->otg_online = false;
	oplus_chg_wake_update_work();
	pr_debug("wakeup [%s] done!!!\n", __func__);
}

void oplus_sy697x_typec_src_removal(void)
{
	struct sy697x *chg = g_sy;

	if (!chg) {
		pr_err("[%s] chg is null\n", __func__);
		return;
	}
	oplus_notify_device_mode(false);
	pr_debug("[%s] done!!!\n", __func__);
}

void oplus_typec_mode_unattached(void)
{
	pr_debug("[%s] done!!!\n", __func__);
}

void oplus_for_cdp(void)
{
	int timeout = 40;
	if (is_usb_rdy() == false) {
		while (is_usb_rdy() == false && timeout > 0) {
			msleep(10);
			timeout--;
		}
		if (timeout == 0)
			pr_info("usb_rdy timeout\n");
		else
			pr_info("usb_rdy free\n");
	} else
			pr_info("rm cdp 400ms usb_rdy PASS\n");
}

static int g_sy697x_read_reg(struct sy697x *sy, u8 reg, u8 *data)
{
	s32 ret;

	ret = i2c_smbus_read_byte_data(sy->client, reg);
	if (ret < 0) {
		pr_err("i2c read fail: can't read from reg 0x%02X ret[%d]\n", reg, ret);
		return ret;
	}

	*data = (u8) ret;

	return 0;
}

static int g_sy697x_write_reg(struct sy697x *sy, int reg, u8 val)
{
	s32 ret;
	ret = i2c_smbus_write_byte_data(sy->client, reg, val);
	if (ret < 0) {
		pr_err("i2c write fail: can't write 0x%02X to reg 0x%02X: %d\n",
		       val, reg, ret);
		return ret;
	}
	return 0;
}

static int sy697x_read_byte(struct sy697x *sy, u8 reg, u8 *data)
{
	int ret;
	int retry = 20;

	mutex_lock(&sy->i2c_rw_lock);
	ret = g_sy697x_read_reg(sy, reg, data);
	if (ret < 0) {
		while(retry > 0 && atomic_read(&sy->driver_suspended) == 0) {
			usleep_range(10000, 10000);
			ret = g_sy697x_read_reg(sy, reg, data);
			pr_err("%s: ret = %d \n", __func__, ret);
			if (ret < 0) {
				retry--;
			} else {
				break;
			}
		}
	}
	mutex_unlock(&sy->i2c_rw_lock);

	return ret;
}

static int __sy697x_update_bits(struct sy697x *sy, u8 reg, u8 mask, u8 data)
{
	int ret;
	u8 tmp;

	//mutex_lock(&sy->i2c_rw_lock);
	ret = g_sy697x_read_reg(sy, reg, &tmp);
	if (ret) {
		pr_err("Failed: reg=%02X, ret=%d\n", reg, ret);
		goto out;
	}

	tmp &= ~mask;
	tmp |= data & mask;

	ret = g_sy697x_write_reg(sy, reg, tmp);
	if (ret)
		pr_err("Failed: reg=%02X, ret=%d\n", reg, ret);

out:
	//mutex_unlock(&sy->i2c_rw_lock);
	return ret;
}

static int sy697x_update_bits(struct sy697x *sy, u8 reg, u8 mask, u8 data)
{
	int ret;
	int retry = 20;

	mutex_lock(&sy->i2c_rw_lock);
	ret = __sy697x_update_bits(sy, reg, mask, data);
	if (ret < 0) {
		while(retry > 0 && atomic_read(&sy->driver_suspended) == 0) {
			usleep_range(10000, 10000);
			ret = __sy697x_update_bits(sy, reg, mask, data);
			pr_err("%s: ret = %d \n", __func__, ret);
			if (ret < 0) {
				retry--;
			} else {
				break;
			}
		}
	}
	mutex_unlock(&sy->i2c_rw_lock);
	return ret;
}

static int sy697x_enable_otg(struct sy697x *sy)
{

	u8 val = SY697X_OTG_ENABLE << SY697X_OTG_CONFIG_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_03,
				   SY697X_OTG_CONFIG_MASK, val);
}

static int sy697x_vmin_limit(struct sy697x *sy)
{

	u8 val = 4 << SY697X_SYS_MINV_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_03,
				   SY697X_SYS_MINV_MASK, val);
}

static int sy697x_disable_otg(struct sy697x *sy)
{
	u8 val = SY697X_OTG_DISABLE << SY697X_OTG_CONFIG_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_03,
				   SY697X_OTG_CONFIG_MASK, val);
}

static int sy697x_enable_hvdcp(struct sy697x *sy)
{
#ifdef ENABLE_HVDCP
	int ret;
	u8 val = SY697X_HVDCP_ENABLE << SY697X_HVDCPEN_SHIFT;
	printk("sy697x_enable_hvdcp do nothing\n");
	ret = sy697x_update_bits(sy, SY697X_REG_02, 
				SY697X_HVDCPEN_MASK, val);
	return ret;
#else
	return 0;
#endif
}
EXPORT_SYMBOL_GPL(sy697x_enable_hvdcp);

static int sy697x_disable_hvdcp(struct sy697x *sy)
{
	int ret = 0;
	u8 val = SY697X_HVDCP_DISABLE << SY697X_HVDCPEN_SHIFT;
	printk("sy697x_disable_hvdcp \n");
	ret = sy697x_update_bits(sy, SY697X_REG_02, 
				SY697X_HVDCPEN_MASK, val);
	return ret;
}
EXPORT_SYMBOL_GPL(sy697x_disable_hvdcp);

static int sy697x_disable_batfet_rst(struct sy697x *sy)
{
	int ret = 0;
	u8 val = SY697X_BATFET_RST_EN_DISABLE << SY697X_BATFET_RST_EN_SHIFT;
	printk("disable_batfet_rst \n");
	ret = sy697x_update_bits(sy, SY697X_REG_09, 
				SY697X_BATFET_RST_EN_MASK, val);
	return ret;
}

static int bq2589x_disable_maxc(struct sy697x *bq)
{
	int ret;
	u8 val = SY697X_MAXC_DISABLE << SY697X_MAXCEN_SHIFT;

	ret = sy697x_update_bits(bq, SY697X_REG_02, 
				SY697X_MAXCEN_MASK, val);
	return ret;
}


static int sy697x_disable_ico(struct sy697x *sy)
{
	int ret = 0;
	u8 val = SY697X_ICO_DISABLE << SY697X_ICOEN_SHIFT;
	printk("sy697x_disable_ico\n");
	ret = sy697x_update_bits(sy, SY697X_REG_02, 
				SY697X_ICOEN_MASK, val);
	return ret;
}
static int sy697x_enable_charger(struct sy697x *sy)
{
	int ret;

	u8 val = SY697X_CHG_ENABLE << SY697X_CHG_CONFIG_SHIFT;

	dev_info(sy->dev, "%s\n", __func__);
	ret = sy697x_update_bits(sy, SY697X_REG_03, 
				SY697X_CHG_CONFIG_MASK, val);
	return ret;
}

static int sy697x_disable_charger(struct sy697x *sy)
{
	int ret;

	u8 val = SY697X_CHG_DISABLE << SY697X_CHG_CONFIG_SHIFT;
	
	dev_info(sy->dev, "%s\n", __func__);
	ret = sy697x_update_bits(sy, SY697X_REG_03, 
				SY697X_CHG_CONFIG_MASK, val);
	return ret;
}
bool sy697x_adc_ready(struct sy697x *sy)
{
	u8 val;
	int ret;
	int retry = 10;

	while (retry--) {
		ret = sy697x_read_byte(sy, SY697X_REG_02, &val);
		if (ret < 0) {
			dev_err(sy->dev, "%s failed to read register 0x02:%d\n", __func__, ret);
			return ret;
		}
		if (!(val & SY697X_CONV_START_MASK))
			return true;
		mdelay(10);
	}

	return false;
}

int sy697x_adc_start(struct sy697x *sy, bool enable)
{
	//u8 val;
	int ret;
	//int retry = 10;

	if (enable) {
		ret = sy697x_update_bits(sy, SY697X_REG_02, SY697X_CONV_START_MASK,
				SY697X_CONV_START_ENABLE << SY697X_CONV_START_SHIFT);
	} else {
		ret = sy697x_update_bits(sy, SY697X_REG_02, SY697X_CONV_RATE_MASK,
				SY697X_ADC_CONTINUE_DISABLE << SY697X_CONV_RATE_SHIFT);
		ret = sy697x_update_bits(sy, SY697X_REG_02, SY697X_CONV_START_MASK,
				SY697X_ADC_CONTINUE_DISABLE << SY697X_CONV_START_SHIFT);
	}

	return ret;
}

EXPORT_SYMBOL_GPL(sy697x_adc_start);

int sy697x_adc_read_battery_volt(struct sy697x *sy)
{
	uint8_t val;
	int volt;
	int ret;
	ret = sy697x_read_byte(sy, SY697X_REG_0E, &val);
	if (ret < 0) {
		dev_err(sy->dev, "read battery voltage failed :%d\n", ret);
		return ret;
	} else{
		volt = SY697X_BATV_BASE + ((val & SY697X_BATV_MASK) >> SY697X_BATV_SHIFT) * SY697X_BATV_LSB ;
		return volt;
	}
}
EXPORT_SYMBOL_GPL(sy697x_adc_read_battery_volt);


int sy697x_adc_read_sys_volt(struct sy697x *sy)
{
	uint8_t val;
	int volt;
	int ret;
	ret = sy697x_read_byte(sy, SY697X_REG_0F, &val);
	if (ret < 0) {
		dev_err(sy->dev, "read system voltage failed :%d\n", ret);
		return ret;
	} else{
		volt = SY697X_SYSV_BASE + ((val & SY697X_SYSV_MASK) >> SY697X_SYSV_SHIFT) * SY697X_SYSV_LSB ;
		return volt;
	}
}
EXPORT_SYMBOL_GPL(sy697x_adc_read_sys_volt);

int sy697x_adc_read_vbus_volt(struct sy697x *sy)
{
	uint8_t val;
	int volt;
	int ret;
	int retry = 0;

	sy697x_adc_start(sy,true);
	while(!sy697x_adc_ready(sy) && retry <= 100) {
		mdelay(25);
		retry++;
	}
	ret = sy697x_read_byte(sy, SY697X_REG_11, &val);
	if (ret < 0) {
		dev_err(sy->dev, "read vbus voltage failed :%d\n", ret);
		return ret;
	} else{
		volt = SY697X_VBUSV_BASE + ((val & SY697X_VBUSV_MASK) >> SY697X_VBUSV_SHIFT) * SY697X_VBUSV_LSB ;
		if (volt == SY697X_VBUSV_BASE) {
			volt = 0;
		}
		//return volt;
	}
	if (retry >= 20) {
		dev_err(sy->dev, "sy697x_adc_read_vbus_volt mdelay retry, volt[%d, %d] times=retry x 25[%d]ms\n", retry, volt, retry * 25);
	}

	return volt;
}
EXPORT_SYMBOL_GPL(sy697x_adc_read_vbus_volt);

int sy697x_adc_read_temperature(struct sy697x *sy)
{
	uint8_t val;
	int temp;
	int ret;
	ret = sy697x_read_byte(sy, SY697X_REG_10, &val);
	if (ret < 0) {
		dev_err(sy->dev, "read temperature failed :%d\n", ret);
		return ret;
	} else{
		temp = SY697X_TSPCT_BASE + ((val & SY697X_TSPCT_MASK) >> SY697X_TSPCT_SHIFT) * SY697X_TSPCT_LSB ;
		return temp;
	}
}
EXPORT_SYMBOL_GPL(sy697x_adc_read_temperature);

int sy697x_adc_read_charge_current(void)
{
	uint8_t val;
	int curr;
	int ret;

	if(!g_sy)
		return 0;

	ret = sy697x_adc_ready(g_sy);
	if (ret)
		pr_err("sy697x_adc_ready\n");
	else
		return 0;

	ret = sy697x_read_byte(g_sy, SY697X_REG_12, &val);
	if (ret < 0) {
		dev_err(g_sy->dev, "read charge current failed :%d\n", ret);
	} else{
		curr = (int)(SY697X_ICHGR_BASE + ((val & SY697X_ICHGR_MASK) >> SY697X_ICHGR_SHIFT) * SY697X_ICHGR_LSB) ;
		return curr;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sy697x_adc_read_charge_current);
int sy697x_set_chargecurrent(struct sy697x *sy, int curr)
{
	u8 ichg;

	dev_info(sy->dev, "%s: ichg = %d\n", __func__, curr);

	if (curr < SY697X_ICHG_BASE)
		curr = SY697X_ICHG_BASE;

	ichg = (curr - SY697X_ICHG_BASE)/SY697X_ICHG_LSB;
	return sy697x_update_bits(sy, SY697X_REG_04, 
						SY697X_ICHG_MASK, ichg << SY697X_ICHG_SHIFT);

}

int sy697x_set_term_current(struct sy697x *sy, int curr)
{
	u8 iterm;

	if (curr < SY697X_ITERM_BASE)
		curr = SY697X_ITERM_BASE;

	iterm = (curr - SY697X_ITERM_BASE) / SY697X_ITERM_LSB;

	return sy697x_update_bits(sy, SY697X_REG_05, 
						SY697X_ITERM_MASK, iterm << SY697X_ITERM_SHIFT);

}
EXPORT_SYMBOL_GPL(sy697x_set_term_current);

int sy697x_set_prechg_current(struct sy697x *sy, int curr)
{
	u8 iprechg;

	if (curr < SY697X_IPRECHG_BASE)
		curr = SY697X_IPRECHG_BASE;

	iprechg = (curr - SY697X_IPRECHG_BASE) / SY697X_IPRECHG_LSB;

	return sy697x_update_bits(sy, SY697X_REG_05, 
						SY697X_IPRECHG_MASK, iprechg << SY697X_IPRECHG_SHIFT);

}
EXPORT_SYMBOL_GPL(sy697x_set_prechg_current);

int sy697x_set_chargevolt(struct sy697x *sy, int volt)
{
	u8 val;

	dev_info(sy->dev, "%s: volt = %d\n", __func__, volt);

	if (volt < SY697X_VREG_BASE)
		volt = SY697X_VREG_BASE;

	val = (volt - SY697X_VREG_BASE)/SY697X_VREG_LSB;
	return sy697x_update_bits(sy, SY697X_REG_06, 
						SY697X_VREG_MASK, val << SY697X_VREG_SHIFT);
}

int sy697x_set_input_volt_limit(struct sy697x *sy, int volt)
{
	u8 val;

	dev_info(sy->dev, "%s: volt = %d\n", __func__, volt);

	if (volt < SY697X_VINDPM_BASE)
		volt = SY697X_VINDPM_BASE;

	val = (volt - SY697X_VINDPM_BASE) / SY697X_VINDPM_LSB;

	sy697x_update_bits(sy, SY697X_REG_0D,
						SY697X_FORCE_VINDPM_MASK, SY697X_FORCE_VINDPM_ENABLE << SY697X_FORCE_VINDPM_SHIFT);

	return sy697x_update_bits(sy, SY697X_REG_0D,
						SY697X_VINDPM_MASK, val << SY697X_VINDPM_SHIFT);
}

int sy697x_set_input_current_limit(struct sy697x *sy, int curr)
{
	u8 val;
	int boot_mode = get_boot_mode();
	if(boot_mode == MSM_BOOT_MODE__RF || boot_mode == MSM_BOOT_MODE__WLAN){
		curr = 0;
		dev_info(sy->dev, "%s: boot_mode[%d] curr = %d\n", __func__, boot_mode, curr);
	}

	dev_info(sy->dev, "%s: curr = %d\n", __func__, curr);

	if (curr < SY697X_IINLIM_BASE)
		curr = SY697X_IINLIM_BASE;

	val = (curr - SY697X_IINLIM_BASE) / SY697X_IINLIM_LSB;

	return sy697x_update_bits(sy, SY697X_REG_00, SY697X_IINLIM_MASK,
						val << SY697X_IINLIM_SHIFT);
}

int sy697x_get_input_current(void)
{
	u8 reg_val = 0;
	int icl = 0;
	int ret = 0;
	if(!g_sy)
		return icl;

	ret = sy697x_read_byte(g_sy, SY697X_REG_00, &reg_val);
	if (!ret) {
		icl = (reg_val & SY697X_IINLIM_MASK) >> SY697X_IINLIM_SHIFT;
		icl = icl * SY697X_IINLIM_LSB + SY697X_IINLIM_BASE;
	}
	dev_info(g_sy->dev, "%s: icl = %d ma\n", __func__, icl);
	return icl;
}

int sy697x_set_watchdog_timer(struct sy697x *sy, u8 timeout)
{
	u8 val;

	val = (timeout - SY697X_WDT_BASE) / SY697X_WDT_LSB;
	val <<= SY697X_WDT_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_07, 
						SY697X_WDT_MASK, val); 
}
EXPORT_SYMBOL_GPL(sy697x_set_watchdog_timer);

int sy697x_disable_watchdog_timer(struct sy697x *sy)
{
	u8 val = SY697X_WDT_DISABLE << SY697X_WDT_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_07, 
						SY697X_WDT_MASK, val);
}
EXPORT_SYMBOL_GPL(sy697x_disable_watchdog_timer);

int sy697x_reset_watchdog_timer(struct sy697x *sy)
{
	u8 val = SY697X_WDT_RESET << SY697X_WDT_RESET_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_03, 
						SY697X_WDT_RESET_MASK, val);
}
EXPORT_SYMBOL_GPL(sy697x_reset_watchdog_timer);


int sy697x_force_dpdm(struct sy697x *sy, bool enable)
{
	int ret;
	u8 val;

	if (enable) {
		sy697x_enable_enlim(sy);
		val = SY697X_AUTO_DPDM_ENABLE << SY697X_FORCE_DPDM_SHIFT;
	}
	else
		val = SY697X_AUTO_DPDM_DISABLE << SY697X_FORCE_DPDM_SHIFT;

	ret = sy697x_update_bits(sy, SY697X_REG_02, 
						SY697X_FORCE_DPDM_MASK, val);

	pr_err("Force DPDM %s, enable=%d\n", !ret ?  "successfully" : "failed", enable);

	return ret;

}
EXPORT_SYMBOL_GPL(sy697x_force_dpdm);

int sy697x_reset_chip(struct sy697x *sy)
{
	int ret;
	u8 val = SY697X_RESET << SY697X_RESET_SHIFT;

	ret = sy697x_update_bits(sy, SY697X_REG_14, 
						SY697X_RESET_MASK, val);
	return ret;
}
EXPORT_SYMBOL_GPL(sy697x_reset_chip);

void sy697x_suspend_by_hz_mode(bool en)
{
	u8 val;
	struct sy697x *sy = g_sy;
	if (!sy) {
		printk("%s sy is null[%d]\n",__func__, val);
		return;
	}
	if(en)
		val = SY697X_HIZ_ENABLE << SY697X_ENHIZ_SHIFT;
	else
		val = SY697X_HIZ_DISABLE << SY697X_ENHIZ_SHIFT;
	printk("%s val[%d]\n",__func__, val);
	sy697x_update_bits(sy, SY697X_REG_00, SY697X_ENHIZ_MASK, val);
	return;
}


int sy697x_enter_hiz_mode(struct sy697x *sy)
{
	u8 val;
	int boot_mode = get_boot_mode();

	printk("%s disable hiz_mode boot_mode[%d]\n",__func__, boot_mode);

	if(!sy)
		return 0;

	if (atomic_read(&sy->driver_suspended) == 1) {
		return 0;
	}

	atomic_set(&sy->charger_suspended, 1);

	if (boot_mode == MSM_BOOT_MODE__RF || boot_mode == MSM_BOOT_MODE__WLAN) {
		if (!is_bq25890h(sy)) {
			val = SY697X_HIZ_DISABLE << SY697X_ENHIZ_SHIFT;
			sy697x_update_bits(sy, SY697X_REG_00, SY697X_ENHIZ_MASK, val);
		}
		sy697x_disable_charger(sy);
		sy697x_set_input_current_limit(sy, 0);
	} else {
		sy->before_suspend_icl = sy697x_get_input_current();
		sy697x_set_input_current_limit(sy, SY697X_IINLIM_BASE);
		sy697x_disable_charger(sy);
	}

	return 0;

}
EXPORT_SYMBOL_GPL(sy697x_enter_hiz_mode);

int sy697x_exit_hiz_mode(struct sy697x *sy)
{
	u8 val;
	int boot_mode = get_boot_mode();

	printk("%s boot_mode[%d]\n",__func__, boot_mode);
	if(!sy)
		return 0;

	if (atomic_read(&sy->driver_suspended) == 1) {
		return 0;
	}

	atomic_set(&sy->charger_suspended, 0);

	if (boot_mode ==  MSM_BOOT_MODE__RF || boot_mode == MSM_BOOT_MODE__WLAN) {
		val = SY697X_HIZ_DISABLE << SY697X_ENHIZ_SHIFT;
		sy697x_update_bits(sy, SY697X_REG_00, SY697X_ENHIZ_MASK, val);
	} else {
		sy->before_unsuspend_icl = sy697x_get_input_current();
		if (is_bq25890h(sy)) {
			val = SY697X_HIZ_DISABLE << SY697X_ENHIZ_SHIFT;
			sy697x_update_bits(sy, SY697X_REG_00, SY697X_ENHIZ_MASK, val);
		}
		sy697x_enable_charger(sy);
		if ((sy->before_unsuspend_icl == 0)
				|| (sy->before_suspend_icl == 0)
				|| (sy->before_unsuspend_icl != 100)
				|| (sy->before_unsuspend_icl == sy->before_suspend_icl))  {
				chg_err("ignore set icl [%d %d]\n", sy->before_suspend_icl, sy->before_unsuspend_icl);
		} else {
			sy697x_set_input_current_limit(sy, sy->before_suspend_icl);
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(sy697x_exit_hiz_mode);

int sy697x_disable_enlim(struct sy697x *sy)
{
	u8 val = SY697X_ENILIM_DISABLE << SY697X_ENILIM_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_00, 
						SY697X_ENILIM_MASK, val);

}
EXPORT_SYMBOL_GPL(sy697x_disable_enlim);

int sy697x_enable_enlim(struct sy697x *sy)
{
	u8 val = SY697X_ENILIM_ENABLE << SY697X_ENILIM_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_00, 
						SY697X_ENILIM_MASK, val);

}
EXPORT_SYMBOL_GPL(sy697x_enable_enlim);

int sy697x_get_hiz_mode(struct sy697x *sy, u8 *state)
{
	u8 val;
	int ret;

	ret = sy697x_read_byte(sy, SY697X_REG_00, &val);
	if (ret)
		return ret;
	*state = (val & SY697X_ENHIZ_MASK) >> SY697X_ENHIZ_SHIFT;

	printk("%s state[%d]\n",__func__, *state);

	return 0;
}
EXPORT_SYMBOL_GPL(sy697x_get_hiz_mode);

static int sy697x_enable_term(struct sy697x *sy, bool enable)
{
	u8 val;
	int ret;

	if (enable)
		val = SY697X_TERM_ENABLE << SY697X_EN_TERM_SHIFT;
	else
		val = SY697X_TERM_DISABLE << SY697X_EN_TERM_SHIFT;

	ret = sy697x_update_bits(sy, SY697X_REG_07, 
						SY697X_EN_TERM_MASK, val);

	return ret;
}
EXPORT_SYMBOL_GPL(sy697x_enable_term);

int sy697x_set_boost_current(struct sy697x *sy, int curr)
{
	u8 temp = 0;

	if (curr < 750)
		temp = SY697X_BOOST_LIM_500MA;
	else if (curr < 1200)
		temp = SY697X_BOOST_LIM_750MA;
	else if (curr < 1400)
		temp = SY697X_BOOST_LIM_1200MA;
	else if (curr < 1650)
		temp = SY697X_BOOST_LIM_1400MA;
	else if (curr < 1870)
		temp = SY697X_BOOST_LIM_1650MA;
	else if (curr < 2150)
		temp = SY697X_BOOST_LIM_1875MA;
	else if (curr < 2450)
		temp = SY697X_BOOST_LIM_2150MA;
	else
		temp= SY697X_BOOST_LIM_2450MA;
	printk("sy697x_set_boost_current temp=%d\n",temp);
	return sy697x_update_bits(sy, SY697X_REG_0A, 
				SY697X_BOOST_LIM_MASK, 
				temp << SY697X_BOOST_LIM_SHIFT);

}

static int sy697x_enable_auto_dpdm(struct sy697x* sy, bool enable)
{
	u8 val;
	int ret;

	if (enable)
		val = SY697X_AUTO_DPDM_ENABLE << SY697X_AUTO_DPDM_EN_SHIFT;
	else
		val = SY697X_AUTO_DPDM_DISABLE << SY697X_AUTO_DPDM_EN_SHIFT;

	ret = sy697x_update_bits(sy, SY697X_REG_02, 
						SY697X_AUTO_DPDM_EN_MASK, val);

	return ret;

}
EXPORT_SYMBOL_GPL(sy697x_enable_auto_dpdm);

int sy697x_set_boost_voltage(struct sy697x *sy, int volt)
{
	u8 val = 0;

	if (volt < SY697X_BOOSTV_BASE)
		volt = SY697X_BOOSTV_BASE;
	if (volt > SY697X_BOOSTV_BASE 
			+ (SY697X_BOOSTV_MASK >> SY697X_BOOSTV_SHIFT) 
			* SY697X_BOOSTV_LSB)
		volt = SY697X_BOOSTV_BASE 
			+ (SY697X_BOOSTV_MASK >> SY697X_BOOSTV_SHIFT) 
			* SY697X_BOOSTV_LSB;

	val = ((volt - SY697X_BOOSTV_BASE) / SY697X_BOOSTV_LSB) 
			<< SY697X_BOOSTV_SHIFT;

	printk("sy697x_set_boost_voltage val=%d\n",val);
	return sy697x_update_bits(sy, SY697X_REG_0A, 
				SY697X_BOOSTV_MASK, val);


}
EXPORT_SYMBOL_GPL(sy697x_set_boost_voltage);

static int sy697x_enable_ico(struct sy697x* sy, bool enable)
{
	u8 val;
	int ret;

	if (enable)
		val = SY697X_ICO_ENABLE << SY697X_ICOEN_SHIFT;
	else
		val = SY697X_ICO_DISABLE << SY697X_ICOEN_SHIFT;

	ret = sy697x_update_bits(sy, SY697X_REG_02, SY697X_ICOEN_MASK, val);

	return ret;

}
EXPORT_SYMBOL_GPL(sy697x_enable_ico);

static int sy697x_read_idpm_limit(struct sy697x *sy, int *icl)
{
	uint8_t val;
	int ret;

	ret = sy697x_read_byte(sy, SY697X_REG_13, &val);
	if (ret < 0) {
		dev_err(sy->dev, "read vbus voltage failed :%d\n", ret);
		return ret;
	} else{
		*icl = SY697X_IDPM_LIM_BASE + ((val & SY697X_IDPM_LIM_MASK) >> SY697X_IDPM_LIM_SHIFT) * SY697X_IDPM_LIM_LSB ;
		return 0;
	}
}
EXPORT_SYMBOL_GPL(sy697x_read_idpm_limit);

static int sy697x_enable_safety_timer(struct sy697x *sy)
{
	const u8 val = SY697X_CHG_TIMER_ENABLE << SY697X_EN_TIMER_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_07, SY697X_EN_TIMER_MASK,
				   val);
}
EXPORT_SYMBOL_GPL(sy697x_enable_safety_timer);

static int sy697x_disable_safety_timer(struct sy697x *sy)
{
	const u8 val = SY697X_CHG_TIMER_DISABLE << SY697X_EN_TIMER_SHIFT;

	return sy697x_update_bits(sy, SY697X_REG_07, SY697X_EN_TIMER_MASK,
				   val);

}
EXPORT_SYMBOL_GPL(sy697x_disable_safety_timer);

static int sy697x_switch_to_hvdcp(struct sy697x *sy, enum hvdcp_type type)
{

	int ret;
	u8 val;

	switch (type) {
		case HVDCP_5V:
		val = SY697X_HVDCP_DISABLE << SY697X_HVDCPEN_SHIFT;
		ret = sy697x_update_bits(sy, SY697X_REG_02, 
							8, val);
		Charger_Detect_Init();
		oplus_for_cdp();
		sy697x_force_dpdm(sy, true);
		dev_err(sy->dev, "set to 5v\n");
		break;
		case HVDCP_9V:
#ifdef ENABLE_HVDCP
			val = SY697X_HVDCP_DISABLE << SY697X_HVDCPHV_SHIFT;
			ret = sy697x_update_bits(sy, SY697X_REG_02,
							4, val);
#endif
			dev_err(sy->dev, "set to 9v\n");
			break;
		default:
		break;
	}

	return ret;
}

static int sy697x_check_charge_done(struct sy697x *sy, bool *done)
{
	int ret;
	u8 val;

	ret = sy697x_read_byte(sy, SY697X_REG_0B, &val);
	if (!ret) {
		val = val & SY697X_CHRG_STAT_MASK;
		val = val >> SY697X_CHRG_STAT_SHIFT;
		*done = (val == SY697X_CHRG_STAT_CHGDONE);
	}

	return ret;

}

static struct sy697x_platform_data *sy697x_parse_dt(struct device_node *np,
						      struct sy697x *sy)
{
	int ret;
	struct sy697x_platform_data *pdata;

	pdata = devm_kzalloc(sy->dev, sizeof(struct sy697x_platform_data), GFP_KERNEL);
	if (!pdata)
		return NULL;

	if (of_property_read_string(np, "charger_name", &sy->chg_dev_name) < 0) {
		sy->chg_dev_name = "primary_chg";
		pr_warn("no charger name\n");
	}

	if (of_property_read_string(np, "eint_name", &sy->eint_name) < 0) {
		sy->eint_name = "chr_stat";
		pr_warn("no eint name\n");
	}

	sy->chg_det_enable =
		of_property_read_bool(np, "sy,sy697x,charge-detect-enable");

	ret = of_property_read_u32(np, "sy,sy697x,usb-vlim", &pdata->usb.vlim);
	if (ret) {
		pdata->usb.vlim = 4500;
		pr_err("Failed to read node of sy,sy697x,usb-vlim\n");
	}

	ret = of_property_read_u32(np, "sy,sy697x,usb-ilim", &pdata->usb.ilim);
	if (ret) {
		pdata->usb.ilim = 2000;
		pr_err("Failed to read node of sy,sy697x,usb-ilim\n");
	}

	ret = of_property_read_u32(np, "sy,sy697x,usb-vreg", &pdata->usb.vreg);
	if (ret) {
		pdata->usb.vreg = 4200;
		pr_err("Failed to read node of sy,sy697x,usb-vreg\n");
	}

	ret = of_property_read_u32(np, "sy,sy697x,usb-ichg", &pdata->usb.ichg);
	if (ret) {
		pdata->usb.ichg = 2000;
		pr_err("Failed to read node of sy,sy697x,usb-ichg\n");
	}

	ret = of_property_read_u32(np, "sy,sy697x,precharge-current",
				   &pdata->iprechg);
	if (ret) {
		pdata->iprechg = 256;
		pr_err("Failed to read node of sy,sy697x,precharge-current\n");
	}

	ret = of_property_read_u32(np, "sy,sy697x,termination-current",
				   &pdata->iterm);
	if (ret) {
		pdata->iterm = 250;
		pr_err("Failed to read node of sy,sy697x,termination-current\n");
	}

	ret =
	    of_property_read_u32(np, "sy,sy697x,boost-voltage",
				 &pdata->boostv);
	if (ret) {
		pdata->boostv = 5000;
		pr_err("Failed to read node of sy,sy697x,boost-voltage\n");
	}

	ret =
		of_property_read_u32(np, "sy,sy697x,boost-current",
				 &pdata->boosti);
	if (ret) {
		pdata->boosti = 1200;
		pr_err("Failed to read node of sy,sy697x,boost-current\n");
	}

	return pdata;
}

static void sy697x_check_hvdcp_type(struct sy697x *sy)
{
	int ret;
	u8 reg_val = 0;
	int vbus_stat = 0;
	//enum charger_type chg_type = CHARGER_UNKNOWN;

	ret = sy697x_read_byte(sy, SY697X_REG_0B, &reg_val);
	if (ret)
		return ;

	vbus_stat = (reg_val & SY697X_VBUS_STAT_MASK);
	vbus_stat >>= SY697X_VBUS_STAT_SHIFT;
	sy->vbus_type = vbus_stat;
	pr_err("sy697x_get_charger_type:%d,reg0B = 0x%x\n",vbus_stat,reg_val);
	switch (vbus_stat) {
		case SY697X_VBUS_TYPE_HVDCP:
#ifdef ENABLE_HVDCP
			if(!disable_QC){
				sy->hvdcp_can_enabled = true;
			}
#endif
			break;
		default:
			break;
	}
}

static int opluschg_updata_usb_type(struct sy697x *sy)
{
	union power_supply_propval propval;
	int ret = 0;
	struct oplus_chg_chip *chgchip = g_oplus_chip;

	if (!sy) {
		pr_err("[%s] sy is null\n",__func__);
		return 0;
	}

	if (sy->power_good && (oplus_get_usb_status() != USB_TEMP_HIGH)
		&& ((sy->oplus_chg_type == POWER_SUPPLY_TYPE_USB) || (sy->oplus_chg_type == POWER_SUPPLY_TYPE_USB_CDP)))
		propval.intval = 1;
	else
		propval.intval = 0;

	pr_err("[%s] POWER_SUPPLY_PROP_ONLINE %d\n",__func__, propval.intval);
	ret = power_supply_set_property(chgchip->usb_psy, POWER_SUPPLY_PROP_ONLINE,
					&propval);

	propval.intval = sy->oplus_chg_type;
	pr_err("[%s] POWER_SUPPLY_PROP_TYPE %d\n",__func__, propval.intval);
	ret = power_supply_set_property(chgchip->usb_psy, POWER_SUPPLY_PROP_TYPE,
					&propval);
	if (ret < 0)
		pr_notice("inform power supply charge type failed:%d\n", ret);

	power_supply_changed(chgchip->usb_psy);
	pr_err("[%s] power_supply_changed POWER_SUPPLY_TYPE_USB done\n",__func__);
	return 1000;
}

static int sy697x_inform_charger_type(struct sy697x *sy)
{
	int ret = 0;
	union power_supply_propval propval;

	struct oplus_chg_chip *chgchip = g_oplus_chip;

	if (!sy || !chgchip) {
		pr_err("[%s] sy is null\n",__func__);
		return 0;
	}

#ifndef CONFIG_OPLUS_CHARGER_MTK
	if (sy->power_good)
		propval.intval = 1;
	else
		propval.intval = 0;
	ret = power_supply_set_property(chgchip->ac_psy, POWER_SUPPLY_PROP_ONLINE, &propval);
	if (ret < 0)
		pr_notice("inform power supply charge type failed:%d\n", ret);

	if (oplus_sy697x_get_charger_type() == POWER_SUPPLY_TYPE_USB_DCP) {
		power_supply_changed(chgchip->ac_psy);
	}
	power_supply_changed(chgchip->batt_psy);
	pr_debug("[%s] power_supply_changed ac or battery done power_good [%d] done\n",__func__, propval.intval);
#else
	if (!sy->psy) {
		sy->psy = power_supply_get_by_name("charger");
		if (!sy->psy)
			return -ENODEV;
	}

	if (sy->power_good)
		propval.intval = 1;
	else
		propval.intval = 0;
	ret = power_supply_set_property(sy->psy, POWER_SUPPLY_PROP_ONLINE,
					&propval);

	propval.intval = sy->chg_type;
	ret = power_supply_set_property(sy->psy, POWER_SUPPLY_PROP_CHARGE_TYPE,
					&propval);

	if (ret < 0)
		pr_notice("inform power supply charge type failed:%d\n", ret);
#endif
	return ret;
}

int sy_charger_type_recheck(struct sy697x *sy)
{
	int ret;

	u8 reg_val = 0;
	int vbus_stat = 0;
	//enum charger_type chg_type = CHARGER_UNKNOWN;
	if (!g_oplus_chip) {
		return 0;
	}

	ret = sy697x_read_byte(sy, SY697X_REG_0B, &reg_val);
	if (ret)
		return ret;

	vbus_stat = (reg_val & SY697X_VBUS_STAT_MASK);
	vbus_stat >>= SY697X_VBUS_STAT_SHIFT;
	sy->vbus_type = vbus_stat;

	switch (vbus_stat) {
	case SY697X_VBUS_TYPE_NONE:
		sy->chg_type = CHARGER_UNKNOWN;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_UNKNOWN;
		break;
	case SY697X_VBUS_TYPE_SDP:
		sy->chg_type = STANDARD_HOST;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB;
		g_oplus_chip->charger_type = POWER_SUPPLY_TYPE_USB;
		break;
	case SY697X_VBUS_TYPE_CDP:
		sy->chg_type = CHARGING_HOST;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_CDP;
		printk("%s g_oplus_chip->charger_type=%d\n",__func__,g_oplus_chip->charger_type);
		if (g_oplus_chip->charger_type != POWER_SUPPLY_TYPE_USB_CDP) {
			sy->cdp_retry_aicl = true;
			g_oplus_chip->charger_type = POWER_SUPPLY_TYPE_USB_CDP;
		}
		sy->cdp_retry_aicl = true;
		break;
	case SY697X_VBUS_TYPE_DCP:
		sy->chg_type = STANDARD_CHARGER;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
		break;
	case SY697X_VBUS_TYPE_HVDCP:
		sy->chg_type = STANDARD_CHARGER;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
		break;
	case SY697X_VBUS_TYPE_UNKNOWN:
		sy->chg_type = NONSTANDARD_CHARGER;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
		break;
	case SY697X_VBUS_TYPE_NON_STD:
		sy->chg_type = NONSTANDARD_CHARGER;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
		break;
	default:
		sy->chg_type = NONSTANDARD_CHARGER;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
		break;
	}
	printk("[%s]:chg_type = %d, %d, %d vbus_on[%d]\n", __func__, sy->chg_type, sy->oplus_chg_type, g_oplus_chip->charger_type, sy->vbus_on);
	if ((oplus_sy697x_get_charger_type() == POWER_SUPPLY_TYPE_USB) || (oplus_sy697x_get_charger_type() == POWER_SUPPLY_TYPE_USB_CDP)) {
		oplus_notify_device_mode(true);
	}

	sy697x_inform_charger_type(sy);
	opluschg_updata_usb_type(sy);
	sy697x_adc_start(sy,true);
	oplus_chg_wake_update_work();
	printk("oplus_chg_wake_update_work done\n");
	schedule_delayed_work(&sy->sy697x_aicl_work, OPLUS_DELAY_WORK_TIME_BASE*2);

	return 0;
}

static void opluschg_usbtemp_thread_init(struct oplus_chg_chip *oplus_chip)
{
	if (oplus_chip == NULL) {
		chg_err("failed to cread oplushg_usbtemp_kthread, oplus_chip == NULL\n");
		return;
	}
	if (oplus_usbtemp_check_is_support() == true) {
		oplushg_usbtemp_kthread = kthread_run(oplus_usbtemp_monitor_common, oplus_chip, "usbtemp_kthread");
		if (IS_ERR(oplushg_usbtemp_kthread)) {
			chg_err("failed to cread oplushg_usbtemp_kthread\n");
		}
	}
}

bool sy697x_vbus_good(struct sy697x* sy)
{
	u8 reg_val = 0;
	int ret = 0;
	if (!sy) {
		return false;
	}

	ret = sy697x_read_byte(sy, SY697X_REG_11, &reg_val);
	if (ret)
		return ret;
	if (reg_val & SY697X_VBUS_GD_MASK)
		return true;
	else
		return false;
}

static int oplus_splitchg_request_dpdm(struct sy697x *chg, bool enable)
{
	int rc = 0;

	if (!chg) {
		pr_err("[%s] chg is null\n", __func__);
		return 0;
	}

	/* fetch the DPDM regulator */
	pr_err("[%s] start enable[%d %d]\n", __func__, enable, chg->dpdm_enabled);
	if (!chg->dpdm_reg && of_get_property(chg->dev->of_node,
				"dpdm-supply", NULL)) {
		chg->dpdm_reg = devm_regulator_get(chg->dev, "dpdm");
		if (IS_ERR(chg->dpdm_reg)) {
			rc = PTR_ERR(chg->dpdm_reg);
			pr_err("Couldn't get dpdm regulator rc=%d\n", rc);
			chg->dpdm_reg = NULL;
			return rc;
		}
	}

	mutex_lock(&chg->dpdm_lock);
	if (enable) {
		if (chg->dpdm_reg && !chg->dpdm_enabled) {
			pr_err(" enabling DPDM regulator\n");
			rc = regulator_enable(chg->dpdm_reg);
			if (rc < 0)
				pr_err("Couldn't enable dpdm regulator rc=%d\n", rc);
			else {
				chg->dpdm_enabled = true;
				pr_err("enabling DPDM success\n");
			}
		}
	} else {
		if (chg->dpdm_reg && chg->dpdm_enabled) {
			pr_err(" disabling DPDM regulator\n");
			rc = regulator_disable(chg->dpdm_reg);
			if (rc < 0)
				pr_err("Couldn't disable dpdm regulator rc=%d\n", rc);
			else {
				chg->dpdm_enabled = false;
				pr_err("disabling DPDM success\n");
			}
		}
	}
	mutex_unlock(&chg->dpdm_lock);
	pr_err("[%s] done\n", __func__);

	return rc;
}

#define OPLUS_WAIT_RESUME_TIME	200
static irqreturn_t sy697x_irq_handler(int irq, void *data)
{
	struct sy697x *sy = (struct sy697x *)data;
	int ret;
	u8 reg_val;
	u8 hz_mode = 0;
	bool prev_pg, curr_pg;
	bool bus_gd = false;
	struct oplus_chg_chip *chip = g_oplus_chip;

	pr_notice(" sy697x_irq_handler:enter improve irq time\n");
	oplus_keep_resume_wakelock(sy, true);
	if (!chip) {
		oplus_keep_resume_wakelock(sy, false);
		return IRQ_HANDLED;
	}

	/*for check bus i2c/spi is ready or not*/
	if (atomic_read(&sy->driver_suspended)==1) {
		pr_notice(" sy697x_irq_handler:suspended and wait_event_interruptible %d\n", OPLUS_WAIT_RESUME_TIME);
		wait_event_interruptible_timeout(sy->wait, atomic_read(&sy->driver_suspended) == 0, msecs_to_jiffies(OPLUS_WAIT_RESUME_TIME));
	}

	if (sy->is_force_dpdm) {
		sy->is_force_dpdm = false;
		sy697x_force_dpdm(sy, false);
		pr_notice("sy697x_force_dpdm:false\n");
	}

	/*first start bc12*/
	if (irq == PROBE_PLUG_IN_IRQ) {
		sy->vbus_on = false;
		sy->vbus_on = sy697x_vbus_good(sy);
		pr_err("sy697x vbus_on[%d]\n", sy->vbus_on);
	}

	ret = sy697x_read_byte(sy, SY697X_REG_0B, &reg_val);
	if (ret) {
		pr_err("[%s] SY697X_REG_0B read failed ret[%d]\n", __func__, ret);
		oplus_keep_resume_wakelock(sy, false);
		return IRQ_HANDLED;
	}
	curr_pg = !!(reg_val & SY697X_PG_STAT_MASK);
	if (curr_pg) {
		oplus_chg_wakelock(sy, true);
	}
	prev_pg = sy->power_good;
	//oplus_sy697x_dump_registers();
	pr_notice("[%s]:(%d,%d %d, otg[%d])\n", __func__,
		prev_pg,sy->power_good, reg_val, oplus_get_otg_enable());

	if (oplus_vooc_get_fastchg_started() == true
			&& oplus_vooc_get_adapter_update_status() != 1) {
		chg_err("oplus_vooc_get_fastchg_started = true!(%d %d)\n", prev_pg, curr_pg);
		sy->power_good = curr_pg;
		goto POWER_CHANGE;
	} else {
		sy->power_good = curr_pg;
	}

	if (!prev_pg && sy->power_good) {
		sy->is_force_aicl = true;
		Charger_Detect_Init();
		oplus_splitchg_request_dpdm(sy, true);
		if (is_bq25890h(sy) == false) {
			sy697x_disable_hvdcp(sy);
		}
		pr_notice("adapter/usb inserted\n");
		oplus_for_cdp();
		sy697x_force_dpdm(sy, true);
		get_monotonic_boottime(&sy->st_ptime[0]);
		sy->chg_need_check = true;
		sy->chg_start_check = false;
		wake_up_interruptible(&oplus_chgtype_wq);

		if (oplus_vooc_get_fastchg_to_normal() == false
				&& oplus_vooc_get_fastchg_to_warm() == false
				&& g_oplus_chip->authenticate
				&& g_oplus_chip->mmi_chg
				&& oplus_vooc_get_allow_reading()
				&& !oplus_is_rf_ftm_mode()) {
			sy697x_enable_charger(g_sy);
		}

		goto POWER_CHANGE;
	} else if (prev_pg && !sy->power_good) {
		if (!is_bq25890h(sy)) {
			ret = sy697x_get_hiz_mode(sy,&hz_mode);
			if (!ret && hz_mode) {
				pr_notice("hiz mode ignore\n");
				goto POWER_CHANGE;
			}
		}
		oplus_splitchg_request_dpdm(sy, false);
		sy->is_force_aicl = false;
		sy->pre_current_ma = -1;
		sy->usb_connect_start = false;
		sy->hvdcp_can_enabled = false;
		sy->hvdcp_checked = false;
		sy->sdp_retry = false;
		sy->cdp_retry = false;
		sy->chg_type = CHARGER_UNKNOWN;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_UNKNOWN;
		memset(&sy->st_ptime[0], 0, sizeof(struct timespec));
		memset(&sy->st_ptime[1], 0, sizeof(struct timespec));
		if (chip) {
			chip->pd_chging = false;
			//chip->qc_chging = false;
		}
		if (chip->is_double_charger_support) {
			chip->sub_chg_ops->charging_disable();
		}
		sy697x_inform_charger_type(sy);
		opluschg_updata_usb_type(sy);

		sy697x_adc_start(sy,false);
		pr_notice("adapter/usb pg_good removed\n");

		bus_gd = sy697x_vbus_good(sy);
		oplus_vooc_reset_fastchg_after_usbout();
		if (oplus_vooc_get_fastchg_started() == false) {
			oplus_chg_set_chargerid_switch_val(0);
			oplus_vooc_switch_mode(NORMAL_CHARGER_MODE);
		}
		g_oplus_chip->chargerid_volt = 0;
		g_oplus_chip->chargerid_volt_got = false;
		printk(KERN_ERR "%s:chargerid_volt_got 1 false\n", __func__);
		g_oplus_chip->charger_type = POWER_SUPPLY_TYPE_UNKNOWN;
		oplus_chg_wake_update_work();
		chip->usbtemp_check = false;
		oplus_notify_device_mode(false);
		oplus_chg_wakelock(sy, false);
		goto POWER_CHANGE;
	} else if (!prev_pg && !sy->power_good) {
		pr_notice("prev_pg & now_pg is false\n");
		goto POWER_CHANGE;
	}

	if (g_sy->otg_enable) {
		oplus_keep_resume_wakelock(sy, false);
		return IRQ_HANDLED;
	}

	if (SY697X_VBUS_STAT_MASK & reg_val) {
		sy->is_force_aicl = false;
		sy697x_check_hvdcp_type(sy);
		if (sy->oplus_chg_type == POWER_SUPPLY_TYPE_USB ||
				sy->oplus_chg_type == POWER_SUPPLY_TYPE_USB_CDP) {
			pr_notice(" type usb %d\n",sy->usb_connect_start);
			if (sy->usb_connect_start == true) {
				Charger_Detect_Release();
				sy697x_inform_charger_type(sy);
				opluschg_updata_usb_type(sy);
			}
		} else if (sy->oplus_chg_type != POWER_SUPPLY_TYPE_UNKNOWN){
			pr_notice(" type cdp or dcp type=%d\n",sy->oplus_chg_type);
			Charger_Detect_Release();
			if (sy->oplus_chg_type != chip->charger_type) {
				pr_notice(" recheck charger type = %d pre=%d\n", sy->oplus_chg_type, chip->charger_type);
				sy->pdqc_setup_5v = true;
				sy->is_bc12_end = false;
				schedule_delayed_work(&sy->sy697x_vol_convert_work, OPLUS_BC12_RETRY_TIME);
			}
		}
		if (sy->chg_need_check && sy->chg_start_check == false) {
			printk("[%s 1]:chg_type = %d, %d, %d\n", __func__, sy->chg_type, sy->oplus_chg_type, g_oplus_chip->charger_type);
			sy_charger_type_recheck(sy);
			printk("[%s 2]:chg_type = %d, %d, %d\n", __func__, sy->chg_type, sy->oplus_chg_type, g_oplus_chip->charger_type);
			Charger_Detect_Release();
			pr_notice("charge type check thread is hung\n");
		}
	}

POWER_CHANGE:
	if(dumpreg_by_irq)
		sy697x_dump_regs(sy);
	oplus_keep_resume_wakelock(sy, false);
	return IRQ_HANDLED;
}

static oplus_chgirq_gpio_init(struct sy697x *sy)
{
	int rc;
	struct device_node *node = sy->dev->of_node;

	if (!node) {
		pr_err("device tree node missing\n");
		return -EINVAL;
	}
	sy->irq_gpio = of_get_named_gpio(node,
		"qcom,chg_irq_gpio", 0);
	if (sy->irq_gpio < 0) {
		pr_err("sy->irq_gpio not specified\n");
	} else {
		if (gpio_is_valid(sy->irq_gpio)) {
			rc = gpio_request(sy->irq_gpio,
				"chg_irq_gpio");
			if (rc) {
				pr_err("unable to request gpio [%d]\n",
					sy->irq_gpio);
			}
		}
		pr_err("sy->irq_gpio =%d\n", sy->irq_gpio);
	}

	sy->irq = gpio_to_irq(sy->irq_gpio);
	pr_err("irq way1 sy->irq =%d\n",sy->irq);

	sy->irq = irq_of_parse_and_map(node, 0);
	pr_err("irq way2 sy->irq =%d\n",sy->irq);


	/* set splitchg pinctrl*/
	sy->pinctrl = devm_pinctrl_get(sy->dev);
	if (IS_ERR_OR_NULL(sy->pinctrl)) {
		chg_err("get pinctrl fail\n");
		return -EINVAL;
	}

	sy->splitchg_inter_active =
		pinctrl_lookup_state(sy->pinctrl, "splitchg_inter_active");
	if (IS_ERR_OR_NULL(sy->splitchg_inter_active)) {
		chg_err(": %d Failed to get the state pinctrl handle\n", __LINE__);
		return -EINVAL;
	}

	sy->splitchg_inter_sleep =
		pinctrl_lookup_state(sy->pinctrl, "splitchg_inter_sleep");
	if (IS_ERR_OR_NULL(sy->splitchg_inter_sleep)) {
		chg_err(": %d Failed to get the state pinctrl handle\n", __LINE__);
		return -EINVAL;
	}

	gpio_direction_input(sy->irq_gpio);
	pinctrl_select_state(sy->pinctrl, sy->splitchg_inter_active); /* no_PULL */

	rc = gpio_get_value(sy->irq_gpio);
	pr_err("irq sy->irq_gpio input =%d irq_gpio_stat = %d\n",sy->irq_gpio, rc);

	return 0;
}


static int sy697x_register_interrupt(struct device_node *np,struct sy697x *sy)
{
	int ret = 0;

#ifdef CONFIG_OPLUS_CHARGER_MTK
	sy->irq = irq_of_parse_and_map(np, 0);
#else
	oplus_chgirq_gpio_init(sy);
#endif
	pr_err("irq = %d\n", sy->irq);

	ret = devm_request_threaded_irq(sy->dev, sy->irq, NULL,
					sy697x_irq_handler,
					IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
					sy->eint_name, sy);
	if (ret < 0) {
		pr_err("request thread irq failed:%d\n", ret);
		return ret;
	}

	enable_irq_wake(sy->irq);

	return 0;
}

static int bq2589x_init_device(struct sy697x *sy)
{
	int ret;

	sy697x_disable_watchdog_timer(sy);
	sy->is_force_dpdm = false;
	ret = sy697x_set_prechg_current(sy, sy->platform_data->iprechg);
	if (ret)
		pr_err("Failed to set prechg current, ret = %d\n", ret);

	ret = sy697x_set_term_current(sy, sy->platform_data->iterm);
	if (ret)
		pr_err("Failed to set termination current, ret = %d\n", ret);

	ret = sy697x_set_boost_voltage(sy, sy->platform_data->boostv);
	if (ret)
		pr_err("Failed to set boost voltage, ret = %d\n", ret);

	ret = sy697x_set_boost_current(sy, sy->platform_data->boosti);
	if (ret)
		pr_err("Failed to set boost current, ret = %d\n", ret);

	ret = sy697x_enable_auto_dpdm(sy,false);
	if (ret)
		pr_err("Failed to stop auto dpdm, ret = %d\n", ret);

	ret = sy697x_vmin_limit(sy);
	if (ret)
		pr_err("Failed to set vmin limit, ret = %d\n", ret);

	ret = sy697x_adc_start(sy,true);
	if (ret)
		pr_err("Failed to stop adc, ret = %d\n", ret);

	ret = sy697x_set_input_volt_limit(sy,4400);
	if (ret)
		pr_err("Failed to set input volt limit, ret = %d\n", ret);

	sy->boot_mode = get_boot_mode();
	if (sy->boot_mode == MSM_BOOT_MODE__RF || sy->boot_mode == MSM_BOOT_MODE__WLAN) {
		sy697x_enter_hiz_mode(sy);
	}

	return 0;
}


static int sy697x_init_device(struct sy697x *sy)
{
	int ret;

	sy697x_disable_watchdog_timer(sy);
	sy->is_force_dpdm = false;
	ret = sy697x_set_prechg_current(sy, sy->platform_data->iprechg);
	if (ret)
		pr_err("Failed to set prechg current, ret = %d\n", ret);

	ret = sy697x_set_chargevolt(sy, DEFAULT_CV);
	if (ret)
		pr_err("Failed to set default cv, ret = %d\n", ret);

	ret = sy697x_set_term_current(sy, sy->platform_data->iterm);
	if (ret)
		pr_err("Failed to set termination current, ret = %d\n", ret);

	ret = sy697x_set_boost_voltage(sy, sy->platform_data->boostv);
	if (ret)
		pr_err("Failed to set boost voltage, ret = %d\n", ret);

	ret = sy697x_set_boost_current(sy, sy->platform_data->boosti);
	if (ret)
		pr_err("Failed to set boost current, ret = %d\n", ret);
	ret = sy697x_disable_enlim(sy);
	if (ret)
		pr_err("Failed to sy697x_disable_enlim, ret = %d\n", ret);
	ret = sy697x_enable_auto_dpdm(sy,false);
	if (ret)
		pr_err("Failed to stop auto dpdm, ret = %d\n", ret);

	ret = sy697x_vmin_limit(sy);
	if (ret)
		pr_err("Failed to set vmin limit, ret = %d\n", ret);

	ret = sy697x_set_input_volt_limit(sy,4400);
	if (ret)
		pr_err("Failed to set input volt limit, ret = %d\n", ret);

	sy->boot_mode = get_boot_mode();
	if (sy->boot_mode == MSM_BOOT_MODE__RF || sy->boot_mode == MSM_BOOT_MODE__WLAN) {
		sy697x_enter_hiz_mode(sy);
	}
	return 0;
}
void sy697x_initial_status(bool is_charger_on)
{
	if(!g_sy)
		return;
	if (is_charger_on) {
		Charger_Detect_Init();
		oplus_for_cdp();
		sy697x_enable_auto_dpdm(g_sy,false);
		g_sy->is_force_aicl = true;
		g_sy->is_retry_bc12 = true;
		sy697x_force_dpdm(g_sy, true);
		g_sy->is_force_dpdm = true;
	} else {
		g_sy->is_force_dpdm = false;
	}
}
EXPORT_SYMBOL_GPL(sy697x_initial_status);

static int sy697x_detect_device(struct sy697x *sy)
{
	int ret;
	u8 data;

	ret = sy697x_read_byte(sy, SY697X_REG_14, &data);
	if (!ret) {
		sy->part_no = (data & SY697X_PN_MASK) >> SY697X_PN_SHIFT;
		sy->revision =
		    (data & SY697X_DEV_REV_MASK) >> SY697X_DEV_REV_SHIFT;
	}
	pr_info("part_no=%d,revision=%d\n",sy->part_no,sy->revision);
	if ( is_bq25890h(sy) == false) {
		pr_info("sy697x\n");
	} else {
		pr_info("bq25890h\n");
	}

	return 0;
}

static void sy697x_dump_regs(struct sy697x *sy)
{
	int addr;
	u8 val[25];
	int ret;
	char buf[400];
	char *s = buf;

	for (addr = 0x0; addr <= 0x14; addr++) {
		ret = sy697x_read_byte(sy, addr, &val[addr]);
		msleep(1);
	}

	s+=sprintf(s,"sy697x_dump_regs:");
	for (addr = 0x0; addr <= 0x14; addr++){
		s+=sprintf(s,"[0x%.2x,0x%.2x]", addr, val[addr]);
	}
	s+=sprintf(s,"\n");

	pr_err("%s",buf);
}

bool is_bq25890h(struct sy697x *sy)
{
	if ( sy->part_no == 1 && sy->revision == 0) /*chip is sy6970*/
		return false;
	else /*chip is bq25890h*/
		return true;
}

#ifdef CONFIG_OPLUS_CHARGER_MTK
static ssize_t
sy697x_show_registers(struct device *dev, struct device_attribute *attr,
		       char *buf)
{
	struct sy697x *sy = dev_get_drvdata(dev);
	u8 addr;
	u8 val;
	u8 tmpbuf[200];
	int len;
	int idx = 0;
	int ret;

	idx = snprintf(buf, PAGE_SIZE, "%s:\n", "sy697x Reg");
	for (addr = 0x0; addr <= 0x14; addr++) {
		ret = sy697x_read_byte(sy, addr, &val);
		if (ret == 0) {
			len = snprintf(tmpbuf, PAGE_SIZE - idx,
				       "Reg[%.2x] = 0x%.2x\n", addr, val);
			memcpy(&buf[idx], tmpbuf, len);
			idx += len;
		}
	}

	return idx;
}

static ssize_t
sy697x_store_registers(struct device *dev,
			struct device_attribute *attr, const char *buf,
			size_t count)
{
	//struct sy697x *sy = dev_get_drvdata(dev);
	int ret;
	unsigned int reg;
	unsigned int val;

	ret = sscanf(buf, "%x %x", &reg, &val);
	if (ret == 2 && reg < 0x14) {
		/*sy697x_write_byte(sy, (unsigned char) reg,
				   (unsigned char) val);*/
	}

	return count;
}


static DEVICE_ATTR(registers, S_IRUGO | S_IWUSR, sy697x_show_registers,
		   sy697x_store_registers);

static struct attribute *sy697x_attributes[] = {
	&dev_attr_registers.attr,
	NULL,
};

static const struct attribute_group sy697x_attr_group = {
	.attrs = sy697x_attributes,
};


static int sy697x_charging(struct charger_device *chg_dev, bool enable)
{

	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	int ret = 0;
	u8 val;

	if (enable)
		ret = sy697x_enable_charger(sy);
	else
		ret = sy697x_disable_charger(sy);

	pr_err("%s charger %s\n", enable ? "enable" : "disable",
	       !ret ? "successfully" : "failed");

	ret = sy697x_read_byte(sy, SY697X_REG_03, &val);

	if (!ret)
		sy->charge_enabled = !!(val & SY697X_CHG_CONFIG_MASK);

	return ret;
}

static int sy697x_plug_in(struct charger_device *chg_dev)
{
	int ret;

	ret = sy697x_charging(chg_dev, true);

	if (ret)
		pr_err("Failed to enable charging:%d\n", ret);

	return ret;
}

static int sy697x_plug_out(struct charger_device *chg_dev)
{
	int ret;

	ret = sy697x_charging(chg_dev, false);

	if (ret)
		pr_err("Failed to disable charging:%d\n", ret);

	return ret;
}

static int sy697x_dump_register(struct charger_device *chg_dev)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	sy697x_dump_regs(sy);

	return 0;
}

static int sy697x_is_charging_enable(struct charger_device *chg_dev, bool *en)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	*en = sy->charge_enabled;

	return 0;
}

static int sy697x_is_charging_done(struct charger_device *chg_dev, bool *done)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	int ret;

	ret = sy697x_check_charge_done(sy, done);

	return ret;
}

static int sy697x_set_ichg(struct charger_device *chg_dev, u32 curr)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	pr_err("charge curr = %d\n", curr);

	return sy697x_set_chargecurrent(sy, curr / 1000);
}
#endif /*CONFIG_OPLUS_CHARGER_MTK*/

static int _sy697x_get_ichg(struct sy697x *sy, u32 *curr)
{
	u8 reg_val;
	int ichg;
	int ret;

	ret = sy697x_read_byte(sy, SY697X_REG_04, &reg_val);
	if (!ret) {
		ichg = (reg_val & SY697X_ICHG_MASK) >> SY697X_ICHG_SHIFT;
		ichg = ichg * SY697X_ICHG_LSB + SY697X_ICHG_BASE;
		*curr = ichg * 1000;
	}

	return ret;
}

#ifdef CONFIG_OPLUS_CHARGER_MTK
static int sy697x_get_ichg(struct charger_device *chg_dev, u32 *curr)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	u8 reg_val;
	int ichg;
	int ret;

	ret = sy697x_read_byte(sy, SY697X_REG_04, &reg_val);
	if (!ret) {
		ichg = (reg_val & SY697X_ICHG_MASK) >> SY697X_ICHG_SHIFT;
		ichg = ichg * SY697X_ICHG_LSB + SY697X_ICHG_BASE;
		*curr = ichg * 1000;
	}

	return ret;
}

static int sy697x_get_min_ichg(struct charger_device *chg_dev, u32 *curr)
{
	*curr = 60 * 1000;

	return 0;
}

static int sy697x_set_vchg(struct charger_device *chg_dev, u32 volt)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	pr_err("charge volt = %d\n", volt);

	return sy697x_set_chargevolt(sy, volt / 1000);
}

static int sy697x_get_vchg(struct charger_device *chg_dev, u32 *volt)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	u8 reg_val;
	int vchg;
	int ret;

	ret = sy697x_read_byte(sy, SY697X_REG_06, &reg_val);
	if (!ret) {
		vchg = (reg_val & SY697X_VREG_MASK) >> SY697X_VREG_SHIFT;
		vchg = vchg * SY697X_VREG_LSB + SY697X_VREG_BASE;
		*volt = vchg * 1000;
	}

	return ret;
}

static int sy697x_set_ivl(struct charger_device *chg_dev, u32 volt)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	pr_err("vindpm volt = %d\n", volt);

	return sy697x_set_input_volt_limit(sy, volt / 1000);

}

static int sy697x_set_icl(struct charger_device *chg_dev, u32 curr)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	pr_err("indpm curr = %d\n", curr);
	return sy697x_set_input_current_limit(sy, curr / 1000);
}

static int sy697x_get_icl(struct charger_device *chg_dev, u32 *curr)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	u8 reg_val;
	int icl;
	int ret;

	ret = sy697x_read_byte(sy, SY697X_REG_00, &reg_val);
	if (!ret) {
		icl = (reg_val & SY697X_IINLIM_MASK) >> SY697X_IINLIM_SHIFT;
		icl = icl * SY697X_IINLIM_LSB + SY697X_IINLIM_BASE;
		*curr = icl * 1000;
	}

	return ret;

}

static int sy697x_kick_wdt(struct charger_device *chg_dev)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	return sy697x_reset_watchdog_timer(sy);
}

static int sy697x_set_otg(struct charger_device *chg_dev, bool en)
{
	int ret;
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	if (en)
		ret = sy697x_enable_otg(sy);
	else
		ret = sy697x_disable_otg(sy);

	if(!ret)
		sy->otg_enable = en;

	pr_err("%s OTG %s\n", en ? "enable" : "disable",
	       !ret ? "successfully" : "failed");

	return ret;
}

static int sy697x_set_safety_timer(struct charger_device *chg_dev, bool en)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	int ret;

	if (en)
		ret = sy697x_enable_safety_timer(sy);
	else
		ret = sy697x_disable_safety_timer(sy);

	return ret;
}

static int sy697x_is_safety_timer_enabled(struct charger_device *chg_dev,
					   bool *en)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	int ret;
	u8 reg_val;

	ret = sy697x_read_byte(sy, SY697X_REG_07, &reg_val);

	if (!ret)
		*en = !!(reg_val & SY697X_EN_TIMER_MASK);

	return ret;
}

static int sy697x_set_boost_ilmt(struct charger_device *chg_dev, u32 curr)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	int ret;

	pr_err("otg curr = %d\n", curr);

	ret = sy697x_set_boost_current(sy, curr / 1000);

	return ret;
}

static int sy697x_enable_chgdet(struct charger_device *chg_dev, bool en)
{
	int ret;
	u8 val;
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	struct oplus_chg_chip *chip = g_oplus_chip;
	if (chip == NULL)
		return -1;

	pr_notice("sy697x_enable_chgdet:%d\n",en);
	sy->chg_det_enable = en;
	if (!en) {
		sy->pre_current_ma = -1;
		sy->hvdcp_can_enabled = false;
		sy->hvdcp_checked = false;
		sy->sdp_retry = false;
		sy->cdp_retry = false;
		sy->usb_connect_start = false;
		Charger_Detect_Release();
		sy->chg_type = CHARGER_UNKNOWN;
		sy->oplus_chg_type = POWER_SUPPLY_TYPE_UNKNOWN;
		if (chip->is_double_charger_support) {
			chip->sub_chg_ops->charging_disable();
		}

		if (sy->power_good && battery_get_vbus() < 3300) {
			pr_notice("vbus off but pg is good\n");
			sy->power_good = false;
		}

		sy697x_inform_charger_type(sy);
		opluschg_updata_usb_type(sy);
		sy697x_adc_start(sy,false);
	}

	return ret;
}
#endif /*CONFIG_OPLUS_CHARGER_MTK*/

static int sy697x_enter_ship_mode(struct sy697x *sy, bool en)
{
	int ret;
	u8 val;

	if (en)
		val = SY697X_BATFET_OFF;
	else
		val = SY697X_BATFET_ON;
	val <<= SY697X_BATFET_DIS_SHIFT;

	ret = sy697x_update_bits(sy, SY697X_REG_09, 
						SY697X_BATFET_DIS_MASK, val);
	return ret;

}

static int sy697x_enable_shipmode(bool en)
{
	int ret;

	ret = sy697x_enter_ship_mode(g_sy, en);

	return 0;
}

#ifdef CONFIG_OPLUS_CHARGER_MTK
static int sy697x_set_pep20_efficiency_table(struct charger_device *chg_dev)
{
	int ret = 0;
	struct charger_manager *chg_mgr = NULL;

	chg_mgr = charger_dev_get_drvdata(chg_dev);
	if (!chg_mgr)
		return -EINVAL;

	chg_mgr->pe2.profile[0].vbat = 3400000;
	chg_mgr->pe2.profile[1].vbat = 3500000;
	chg_mgr->pe2.profile[2].vbat = 3600000;
	chg_mgr->pe2.profile[3].vbat = 3700000;
	chg_mgr->pe2.profile[4].vbat = 3800000;
	chg_mgr->pe2.profile[5].vbat = 3900000;
	chg_mgr->pe2.profile[6].vbat = 4000000;
	chg_mgr->pe2.profile[7].vbat = 4100000;
	chg_mgr->pe2.profile[8].vbat = 4200000;
	chg_mgr->pe2.profile[9].vbat = 4400000;

	chg_mgr->pe2.profile[0].vchr = 8000000;
	chg_mgr->pe2.profile[1].vchr = 8000000;
	chg_mgr->pe2.profile[2].vchr = 8000000;
	chg_mgr->pe2.profile[3].vchr = 8500000;
	chg_mgr->pe2.profile[4].vchr = 8500000;
	chg_mgr->pe2.profile[5].vchr = 8500000;
	chg_mgr->pe2.profile[6].vchr = 9000000;
	chg_mgr->pe2.profile[7].vchr = 9000000;
	chg_mgr->pe2.profile[8].vchr = 9000000;
	chg_mgr->pe2.profile[9].vchr = 9000000;

	return ret;
}

struct timespec st_ptime[13];
static int cptime[13][2];

static int dtime(int i)
{
	struct timespec time;

	time = timespec_sub(st_ptime[i], st_ptime[i-1]);
	return time.tv_nsec/1000000;
}

#define PEOFFTIME 40
#define PEONTIME 90

static int sy697x_set_pep20_current_pattern(struct charger_device *chg_dev,
	u32 chr_vol)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);
	int ret;
	int value;
	int i, j = 0;
	int flag;

	sy697x_set_input_volt_limit(sy, 4500);
	sy697x_set_chargecurrent(sy, 512);
	sy697x_enable_ico(sy, false);

	usleep_range(1000, 1200);
	value = (chr_vol - 5500000) / 500000;

	sy697x_set_input_current_limit(sy, 0);

	msleep(70);

	get_monotonic_boottime(&st_ptime[j++]);
	for (i = 4; i >= 0; i--) {
		flag = value & (1 << i);
		if (flag == 0) {
			sy697x_set_input_current_limit(sy, 700);
			msleep(PEOFFTIME);
			get_monotonic_boottime(&st_ptime[j]);
			cptime[j][0] = PEOFFTIME;
			cptime[j][1] = dtime(j);
			if (cptime[j][1] < 30 || cptime[j][1] > 65) {
				pr_info(
					"charging_set_ta20_current_pattern fail1: idx:%d target:%d actual:%d\n",
					i, PEOFFTIME, cptime[j][1]);
				return -EIO;
			}
			j++;
			sy697x_set_input_current_limit(sy, 0);
			msleep(PEONTIME);
			get_monotonic_boottime(&st_ptime[j]);
			cptime[j][0] = PEONTIME;
			cptime[j][1] = dtime(j);
			if (cptime[j][1] < 90 || cptime[j][1] > 115) {
				pr_info(
					"charging_set_ta20_current_pattern fail2: idx:%d target:%d actual:%d\n",
					i, PEOFFTIME, cptime[j][1]);
				return -EIO;
			}
			j++;

		} else {
			sy697x_set_input_current_limit(sy, 700);
			msleep(PEONTIME);
			get_monotonic_boottime(&st_ptime[j]);
			cptime[j][0] = PEONTIME;
			cptime[j][1] = dtime(j);
			if (cptime[j][1] < 90 || cptime[j][1] > 115) {
				pr_info(
					"charging_set_ta20_current_pattern fail3: idx:%d target:%d actual:%d\n",
					i, PEOFFTIME, cptime[j][1]);
				return -EIO;
			}
			j++;
			sy697x_set_input_current_limit(sy, 0);
			
			msleep(PEOFFTIME);
			get_monotonic_boottime(&st_ptime[j]);
			cptime[j][0] = PEOFFTIME;
			cptime[j][1] = dtime(j);
			if (cptime[j][1] < 30 || cptime[j][1] > 65) {
				pr_info(
					"charging_set_ta20_current_pattern fail4: idx:%d target:%d actual:%d\n",
					i, PEOFFTIME, cptime[j][1]);
				return -EIO;
			}
			j++;
		}
	}

	sy697x_set_input_current_limit(sy, 700);
	msleep(160);
	get_monotonic_boottime(&st_ptime[j]);
	cptime[j][0] = 160;
	cptime[j][1] = dtime(j);
	if (cptime[j][1] < 150 || cptime[j][1] > 240) {
		pr_info(
			"charging_set_ta20_current_pattern fail5: idx:%d target:%d actual:%d\n",
			i, PEOFFTIME, cptime[j][1]);
		return -EIO;
	}
	j++;
	sy697x_set_input_current_limit(sy, 0);
	msleep(30);
	sy697x_set_input_current_limit(sy, 700);

	pr_info(
	"[charging_set_ta20_current_pattern]:chr_vol:%d bit:%d time:%3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d!!\n",
	chr_vol, value,
	cptime[1][0], cptime[2][0], cptime[3][0], cptime[4][0], cptime[5][0],
	cptime[6][0], cptime[7][0], cptime[8][0], cptime[9][0], cptime[10][0], cptime[11][0]);

	pr_info(
	"[charging_set_ta20_current_pattern2]:chr_vol:%d bit:%d time:%3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d!!\n",
	chr_vol, value,
	cptime[1][1], cptime[2][1], cptime[3][1], cptime[4][1], cptime[5][1],
	cptime[6][1], cptime[7][1], cptime[8][1], cptime[9][1], cptime[10][1], cptime[11][1]);

	sy697x_enable_ico(sy, true);
	sy697x_set_input_current_limit(sy, 3250);

	sy->pre_current_ma = -1;
	return 0;
}

static int sy697x_set_pep20_reset(struct charger_device *chg_dev)
{
	struct sy697x *sy = dev_get_drvdata(&chg_dev->dev);

	sy697x_set_input_volt_limit(sy, 4500);
	sy697x_set_chargecurrent(sy, 512);
	sy697x_enable_ico(sy, false);
	sy697x_set_input_current_limit(sy, 0);
	msleep(250);
	sy697x_set_input_current_limit(sy, 700);
	sy697x_enable_ico(sy, true);
	sy->pre_current_ma = -1;

	return 0;
}
#endif /*CONFIG_OPLUS_CHARGER_MTK*/
bool oplus_check_chrdet_status(void);

#ifdef CONFIG_OPLUS_CHARGER_MTK
static struct charger_ops sy697x_chg_ops = {
	/* Normal charging */
	.plug_in = sy697x_plug_in,
	.plug_out = sy697x_plug_out,
	.dump_registers = sy697x_dump_register,
	.enable = sy697x_charging,
	.is_enabled = sy697x_is_charging_enable,
	.get_charging_current = sy697x_get_ichg,
	.set_charging_current = sy697x_set_ichg,
	.get_input_current = sy697x_get_icl,
	.set_input_current = sy697x_set_icl,
	.get_constant_voltage = sy697x_get_vchg,
	.set_constant_voltage = sy697x_set_vchg,
	.kick_wdt = sy697x_kick_wdt,
	.set_mivr = sy697x_set_ivl,
	.is_charging_done = sy697x_is_charging_done,
	.get_min_charging_current = sy697x_get_min_ichg,

	/* Safety timer */
	.enable_safety_timer = sy697x_set_safety_timer,
	.is_safety_timer_enabled = sy697x_is_safety_timer_enabled,

	/* Power path */
	.enable_powerpath = NULL,
	.is_powerpath_enabled = NULL,

	.enable_chg_type_det = sy697x_enable_chgdet,
	/* OTG */
	.enable_otg = sy697x_set_otg,
	.set_boost_current_limit = sy697x_set_boost_ilmt,
	.enable_discharge = NULL,

	/* PE+/PE+20 */
	.send_ta_current_pattern = NULL,
	.set_pe20_efficiency_table = sy697x_set_pep20_efficiency_table,
	.send_ta20_current_pattern = sy697x_set_pep20_current_pattern,
	.reset_ta = sy697x_set_pep20_reset,
	.enable_cable_drop_comp = NULL,

	/* ADC */
	.get_tchg_adc = NULL,
};
#endif /*CONFIG_OPLUS_CHARGER_MTK*/

static int oplus_get_iio_channel(struct sy697x *chip, const char *propname,
					struct iio_channel **chan)
{
	int rc = 0;

	rc = of_property_match_string(chip->dev->of_node,
					"io-channel-names", propname);
	if (rc < 0)
		return rc;

	*chan = iio_channel_get(chip->dev, propname);
	if (IS_ERR(*chan)) {
		rc = PTR_ERR(*chan);
		if (rc != -EPROBE_DEFER)
			pr_info(" %s channel unavailable, %d\n", propname, rc);
		*chan = NULL;
	}

	return rc;
}

#define NTC_DEFAULT_VOLT_VALUE_MV 950
#define THERMAL_TEMP_UNIT      1000
static int oplus_get_ntc_tmp(struct iio_channel *channel)
{
	int ntc_vol_cur = 0;
	struct sy697x *chip = g_sy;
	static int ntc_vol = NTC_DEFAULT_VOLT_VALUE_MV;
	static int ntc_vol_pre = NTC_DEFAULT_VOLT_VALUE_MV;
	int ntc_temp = 25;
	int ntc_vol1 = 0, ntc_temp1 = 0, ntc_vol2 = 0, ntc_temp2 = 0;
	int i = 0;
	int rc = 0;
	struct oplus_chg_chip *opluschg = g_oplus_chip;

	if (!chip || !opluschg) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: sy697x not ready!\n", __func__);
		return 25;
	}

	if (IS_ERR_OR_NULL(channel)) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: channel is  NULL !\n", __func__);
		ntc_vol = ntc_vol_pre;
		goto ntcvolt_get_done;
	}
	rc = iio_read_channel_processed(channel, &ntc_vol_cur);
	if (rc < 0) {
		pr_info("[%s]fail to read usb_temp1 adc rc = %d\n", __func__, rc);
		ntc_vol = ntc_vol_pre;
		goto ntcvolt_get_done;
	}

	if (ntc_vol_cur <= 0) {
		pr_info("[OPLUS_CHG][%s]:ntc_vol_cur iio_read_channel_processed  get error\n", __func__);
		ntc_vol = ntc_vol_pre;
		goto ntcvolt_get_done;
	}

	ntc_vol_cur = ntc_vol_cur / 1000;
	ntc_vol = ntc_vol_cur;
	ntc_vol_pre = ntc_vol_cur;
ntcvolt_get_done:
	/*map btb temp by usbtemp table*/

	if (opluschg->con_volt[opluschg->len_array- 1] >= ntc_vol) {
		ntc_temp = opluschg->con_temp[opluschg->len_array- 1] * THERMAL_TEMP_UNIT;
	} else if (opluschg->con_volt[0] <= ntc_vol) {
		ntc_temp = opluschg->con_temp[0] * THERMAL_TEMP_UNIT;
	} else {
		for (i = opluschg->len_array- 1; i >= 0; i--) {
			if (opluschg->con_volt[i] >= ntc_vol) {
				ntc_vol2 = opluschg->con_volt[i];
				ntc_temp2 = opluschg->con_temp[i];
				break;
			}
			ntc_vol1 = opluschg->con_volt[i];
			ntc_temp1 = opluschg->con_temp[i];
		}
		ntc_temp = (((ntc_vol - ntc_vol2) * ntc_temp1) + ((ntc_vol1 - ntc_vol) * ntc_temp2)) * THERMAL_TEMP_UNIT / (ntc_vol1 - ntc_vol2);
	}

	return ntc_temp;
}

static void oplus_sy697x_get_usbtemp_volt(struct oplus_chg_chip *chip)
{
	int usbtemp_volt = 0;
	struct sy697x *chg = g_sy;
	static int usbtemp_volt_l_pre = NTC_DEFAULT_VOLT_VALUE_MV;
	static int usbtemp_volt_r_pre = NTC_DEFAULT_VOLT_VALUE_MV;
	int rc = 0;

	if (!chip || !chg) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: smb5_chg not ready!\n", __func__);
		return ;
	}

	if (IS_ERR_OR_NULL(chg->iio.usb_temp_chan1)) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: chg->iio.usb_temp_chan1  is  NULL !\n", __func__);
		chip->usbtemp_volt_l = usbtemp_volt_l_pre;
		rc = oplus_get_iio_channel(chg, "usb_temp1", &chg->iio.usb_temp_chan1);
		if (rc < 0 && !chg->iio.usb_temp_chan1) {
			pr_err(" %s usb_temp_chan1 get failed\n", __func__);
		}

		goto usbtemp_next;
	}

	rc = iio_read_channel_processed(chg->iio.usb_temp_chan1, &usbtemp_volt);
	if (rc < 0) {
		chg_err("fail to read usb_temp1 adc rc = %d\n", rc);
		chip->usbtemp_volt_l = usbtemp_volt_l_pre;
		goto usbtemp_next;
	}
	if (usbtemp_volt <= 0) {
		chg_err("[OPLUS_CHG][%s]:USB_TEMPERATURE1 iio_read_channel_processed  get error\n", __func__);
		chip->usbtemp_volt_l = usbtemp_volt_l_pre;
		goto usbtemp_next;
	}

	usbtemp_volt = usbtemp_volt / 1000;
	chip->usbtemp_volt_l = usbtemp_volt;
	usbtemp_volt_l_pre = usbtemp_volt;
usbtemp_next:
	usbtemp_volt = 0;
	if (IS_ERR_OR_NULL(chg->iio.usb_temp_chan2)) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: chg->iio.usb_temp_chan2  is  NULL !\n", __func__);
		rc = oplus_get_iio_channel(chg, "usb_temp2", &chg->iio.usb_temp_chan2);
		if (rc < 0 && !chg->iio.usb_temp_chan2) {
			pr_err(" %s usb_temp_chan2 get failed\n", __func__);
		}

		chip->usbtemp_volt_r = usbtemp_volt_r_pre;
		return;
	}

	//usbtemp_volt = opluschg_read_adc(USB_TEMPERATURE2);
	rc = iio_read_channel_processed(chg->iio.usb_temp_chan2, &usbtemp_volt);
	if (rc < 0) {
		chg_err("fail to read usb_temp2 adc rc = %d\n", rc);
		chip->usbtemp_volt_r = usbtemp_volt_r_pre;
		return;
	}
	if (usbtemp_volt <= 0) {
		chg_err("[OPLUS_CHG][%s]:USB_TEMPERATURE2 iio_read_channel_processed  get error\n", __func__);
		chip->usbtemp_volt_r = usbtemp_volt_r_pre;
		return;
	}

	usbtemp_volt = usbtemp_volt / 1000;
	chip->usbtemp_volt_r = usbtemp_volt;
	usbtemp_volt_r_pre = usbtemp_volt;
}

#ifndef BATT_BTBTMP
#define BATT_BTBTMP 25000
#endif
int oplus_chg_get_battery_btb_temp_cal(void)
{
	int batt_btbntc_raw = 0;
	struct sy697x *chg = g_sy;
	static int batt_btbtmp = BATT_BTBTMP;
	static int batt_btbtmp_pre = BATT_BTBTMP;
	int rc = 0;

	if (!chg) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: chip or chg not ready!\n", __func__);
		return 25;
	}

	if (!chg->pinctrl
		|| !chg->iio.batt_btb_temp_chan) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: chip not ready!\n", __func__);

		rc = oplus_get_iio_channel(chg, "quiet_therm", &chg->iio.batt_btb_temp_chan);
		if (rc < 0 && !chg->iio.batt_btb_temp_chan) {
			pr_err(" %s batt_btb_temp_chan get failed\n", __func__);
			return -1;
		}
	}

	if (IS_ERR_OR_NULL(chg->iio.batt_btb_temp_chan)) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: chg->iio.batt_btb_temp_chan  is  NULL !\n", __func__);
		batt_btbtmp = batt_btbtmp_pre;
		goto btb_ntcvolt_get_done;
	}

	rc = iio_read_channel_processed(chg->iio.batt_btb_temp_chan, &batt_btbntc_raw);
	if (rc < 0) {
		chg_err("fail to read usb_temp1 adc rc = %d\n", rc);
		batt_btbtmp = batt_btbtmp_pre;
		goto btb_ntcvolt_get_done;
	}
	if (batt_btbntc_raw <= 0) {
		chg_err("[OPLUS_CHG][%s]:batt_btbntc_raw iio_read_channel_processed  get error\n", __func__);
		batt_btbtmp = batt_btbtmp_pre;
		goto btb_ntcvolt_get_done;
	}

	chg_err("[OPLUS_CHG][%s]:batt_btbntc_raw[%d]\n", __func__, batt_btbntc_raw);
	batt_btbtmp = batt_btbntc_raw / 1000;
	batt_btbtmp_pre = batt_btbntc_raw / 1000;

btb_ntcvolt_get_done:
	return batt_btbtmp;
}
EXPORT_SYMBOL(oplus_chg_get_battery_btb_temp_cal);



static int oplus_thermal_get_tmp(void)
{
	int ntcctrl_gpio_value = 0;
	int ret = 0;
	struct sy697x *chip = g_sy;
	//static int adc_switch_status = 0;

	if (!chip || !chip->pinctrl
		|| !chip->iio.ntc_switch1_chan || !chip->iio.ntc_switch2_chan) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: chip not ready!\n", __func__);

		ret = oplus_get_iio_channel(chip, "ntc_switch1_chan", &chip->iio.ntc_switch1_chan);
		if (ret < 0 && !chip->iio.ntc_switch1_chan) {
			pr_err(" %s ntc_switch1_chan get failed\n", __func__);
			return -1;
		}

		ret = oplus_get_iio_channel(chip, "ntc_switch2_chan", &chip->iio.ntc_switch2_chan);
		if (ret < 0 && !chip->iio.ntc_switch2_chan) {
			pr_err(" %s ntc_switch2_chan get failed\n", __func__);
			return -1;
		}
	}

	ntcctrl_gpio_value = gpio_get_value(chip->ntcctrl_gpio);
	if (ntcctrl_gpio_value == 0) {
		chg_thermal_temp = oplus_get_ntc_tmp(chip->iio.ntc_switch1_chan);
		bb_thermal_temp = oplus_get_ntc_tmp(chip->iio.ntc_switch2_chan);
		pinctrl_select_state(chip->pinctrl, chip->ntc_switch_high);
		msleep(100);
		ret = gpio_get_value(chip->ntcctrl_gpio);
		flash_thermal_temp = oplus_get_ntc_tmp(chip->iio.ntc_switch1_chan);
		board_thermal_temp = oplus_get_ntc_tmp(chip->iio.ntc_switch2_chan);
	} else if (ntcctrl_gpio_value == 1) {
		flash_thermal_temp = oplus_get_ntc_tmp(chip->iio.ntc_switch1_chan);
		board_thermal_temp = oplus_get_ntc_tmp(chip->iio.ntc_switch2_chan);
		pinctrl_select_state(chip->pinctrl, chip->ntc_switch_low);
		msleep(100);
		ret = gpio_get_value(chip->ntcctrl_gpio);
		chg_thermal_temp = oplus_get_ntc_tmp(chip->iio.ntc_switch1_chan);
		bb_thermal_temp = oplus_get_ntc_tmp(chip->iio.ntc_switch2_chan);
	} else {
		//do nothing
	}

	return 0;
}

int oplus_sy697x_thermal_tmp_get_chg(void)
{
	if (g_sy) {
		mutex_lock(&g_sy->ntc_lock);
		oplus_thermal_get_tmp();
		mutex_unlock(&g_sy->ntc_lock);
	}

	return chg_thermal_temp;
}

int oplus_sy697x_thermal_tmp_get_bb(void)
{
	if (g_sy) {
		mutex_lock(&g_sy->ntc_lock);
		oplus_thermal_get_tmp();
		mutex_unlock(&g_sy->ntc_lock);
	}

	return bb_thermal_temp;
}

int oplus_sy697x_thermal_tmp_get_flash(void)
{
	if (g_sy) {
		mutex_lock(&g_sy->ntc_lock);
		oplus_thermal_get_tmp();
		mutex_unlock(&g_sy->ntc_lock);
	}

	return flash_thermal_temp;
}

int oplus_sy697x_thermal_tmp_get_board(void)
{
	if (g_sy) {
		mutex_lock(&g_sy->ntc_lock);
		oplus_thermal_get_tmp();
		mutex_unlock(&g_sy->ntc_lock);
	}

	return board_thermal_temp;
}

static int oplus_ntc_switch_gpio_init(void)
{
	struct sy697x *chip = g_sy;

	if (!chip) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: ntc_switch not ready!\n", __func__);
		return -EINVAL;
	}

	chip->pinctrl = devm_pinctrl_get(chip->dev);
	if (IS_ERR_OR_NULL(chip->pinctrl)) {
		pr_info("get ntc_switch_gpio pinctrl fail\n");
		return -EINVAL;
	}

	chip->ntc_switch_high =
			pinctrl_lookup_state(chip->pinctrl,
			"ntc_switch_high");
	if (IS_ERR_OR_NULL(chip->ntc_switch_high)) {
		pr_info("get ntc_switch_high fail\n");
		return -EINVAL;
	}

	chip->ntc_switch_low =
			pinctrl_lookup_state(chip->pinctrl,
			"ntc_switch_low");
	if (IS_ERR_OR_NULL(chip->ntc_switch_low)) {
		pr_info("get ntc_switch_low fail\n");
		return -EINVAL;
	}

	/*default switch chg_thermal and bb_thermal*/
	pinctrl_select_state(chip->pinctrl, chip->ntc_switch_low);

	printk(KERN_ERR "[OPLUS_CHG][%s]: ntc_switch is ready!\n", __func__);
	return 0;
}

static int oplus_ntc_switch_parse_dt(void)
{
	struct sy697x *chip = g_sy;
	int rc = 0;
	struct device_node * node = NULL;

	if (!chip) {
		pr_err("chip null\n");
		return -1;
	}

	/* Parsing ntcctrl gpio*/
	node = chip->dev->of_node;
	chip->ntcctrl_gpio = of_get_named_gpio(node, "qcom,ntc-switch-gpio", 0);
	if (chip->ntcctrl_gpio < 0) {
		pr_err("chip->ntcctrl_gpio not specified\n");
	} else {
		if (gpio_is_valid(chip->ntcctrl_gpio)) {
			rc = gpio_request(chip->ntcctrl_gpio,
				"ntc-switch-gpio");
			if (rc) {
				pr_err("unable to request gpio [%d]\n",
					chip->ntcctrl_gpio);
			} else {
				rc = oplus_ntc_switch_gpio_init();
				if (rc)
					chg_err("unable to init charging_sw_ctrl2-gpio:%d\n",
							chip->ntcctrl_gpio);
			}
		}
		pr_info("chip->ntcctrl_gpio =%d\n", chip->ntcctrl_gpio);
	}

	return rc;
}

int oplus_chg_plt_init_for_qcom(struct sy697x *chg)
{
	int ret = -1;
	if (!chg) {
		pr_err("%s sy697x is null, %d\n", __func__, ret);
		return ret;
	}
	if (oplus_ntc_switch_parse_dt()) {
		pr_err("%s ntc gpio init failed\n", __func__);
		return -1;
	}
	pr_info("%s ntc channel init success, %d\n", __func__, ret);

	return 0;
}

void oplus_sy697x_dump_registers(void)
{
	if (debug_log_open != 0)
		sy697x_dump_regs(g_sy);
}

void oplus_extern_charger_usbtemp_action(void) {
	u8 val = SY697X_HIZ_ENABLE << SY697X_ENHIZ_SHIFT;
	if(!g_sy)
		return;
	sy697x_update_bits(g_sy, SY697X_REG_00,
						SY697X_ENHIZ_MASK, val);
	if (g_oplus_chip && g_oplus_chip->is_double_charger_support) {
		g_oplus_chip->slave_charger_enable = false;
	}
}

int oplus_sy697x_kick_wdt(void)
{
	oplus_check_chrdet_status();
	return sy697x_reset_watchdog_timer(g_sy);
}

int oplus_sy697x_set_ichg(int cur)
{
	struct oplus_chg_chip *chip = g_oplus_chip;
	u32 chg_curr = cur*1000;
	u32 main_cur,slave_cur;
	int ret = 0;
	int boot_mode = get_boot_mode();

	if(boot_mode == MSM_BOOT_MODE__RF || boot_mode == MSM_BOOT_MODE__WLAN){
		chg_curr = 0;
		cur = 0;
		dev_info(g_sy->dev, "%s: boot_mode[%d] curr = %d\n", __func__, boot_mode, chg_curr);
	}

	pr_err("oplus_sy697x_set_ichg curr = %d\n", cur);

	if (chip->em_mode) {
		chg_curr = chip->limits.temp_normal_phase2_fastchg_current_ma_high*1000;
	}
	if (chip->is_double_charger_support
			&& (chip->slave_charger_enable || chip->em_mode)) {
		main_cur = chg_curr  * current_percent / 100;
		ret = sy697x_set_chargecurrent(g_sy, main_cur/1000);
		if (ret < 0) {
			chg_debug("set fast charge current:%d fail\n", main_cur);
		}
		ret = _sy697x_get_ichg(g_sy, &main_cur);
		if (ret < 0) {
			chg_debug("get fast charge current:%d fail\n", main_cur);
			return ret;
		}
		slave_cur = chg_curr - main_cur;
		chip->sub_chg_ops->charging_current_write_fast(slave_cur/1000);
	} else {
		ret = sy697x_set_chargecurrent(g_sy, chg_curr/1000);
		if (ret < 0) {
			chg_debug("set fast charge current:%d fail\n", chg_curr);
		}
	}
	return 0;
}

void oplus_sy697x_set_mivr(int vbatt)
{

	u32 mV =0;

	if(vbatt > 4300){
		mV = vbatt + 400;
	}else if(vbatt > 4200){
		mV = vbatt + 300;
	}else{
		mV = vbatt + 200;
	}

	if(mV<4200)
		mV = 4200;

	sy697x_set_input_volt_limit(g_sy, mV);
}

void oplus_sy697x_set_mivr_by_battery_vol(void)
{

	u32 mV =0;
	int vbatt = 0;
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (chip) {
		vbatt = chip->batt_volt;
	}

	if(vbatt > 4300){
		mV = vbatt + 400;
	}else if(vbatt > 4200){
		mV = vbatt + 300;
	}else{
		mV = vbatt + 200;
	}

	if(mV<4400)
		mV = 4400;

	sy697x_set_input_volt_limit(g_sy, mV);
}

static int usb_icl[] = {
	100, 500, 900, 1200, 1500, 1750, 2000, 3000,
};

int oplus_sy697x_set_aicr(int current_ma)
{
	struct oplus_chg_chip *chip = g_oplus_chip;
	int rc = 0, i = 0;
	int chg_vol = 0;
	int aicl_point = 0;
	int aicl_point_temp = 0;
	int main_cur = 0;
	int slave_cur = 0;

	g_sy->pre_current_ma = current_ma;
	if (chip->is_double_charger_support) {
		rc = chip->sub_chg_ops->charging_disable();
		if (rc < 0) {
			chg_debug("disable sub charging fail\n");
		}
		dev_info(g_sy->dev, "%s disabel subchg\n", __func__);
	}

	dev_info(g_sy->dev, "%s usb input max current limit=%d\n", __func__,current_ma);
	if (chip && chip->is_double_charger_support == true) {
		chg_vol = oplus_sy697x_get_vbus();
		if (chg_vol > 7600) {
			aicl_point_temp = aicl_point = 7600;
		} else {
			if (chip->batt_volt > 4100 )
				aicl_point_temp = aicl_point = 4550;
			else
				aicl_point_temp = aicl_point = 4500;
		}
	} else {
		if (chip->batt_volt > 4100 )
			aicl_point_temp = aicl_point = 4550;
		else
			aicl_point_temp = aicl_point = 4500;
	}

	if (current_ma < 500) {
		i = 0;
		goto aicl_end;
	}

	i = 1; /* 500 */
	sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	msleep(90);
	sy697x_disable_enlim(g_sy);
	chg_vol = oplus_sy697x_get_vbus();
	if (chg_vol < aicl_point_temp) {
		pr_debug( "use 500 here\n");
		goto aicl_end;
	} else if (current_ma < 900)
		goto aicl_end;

	i = 2; /* 900 */
	sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	msleep(90);
	chg_vol = oplus_sy697x_get_vbus();
	if (chg_vol < aicl_point_temp) {
		i = i - 1;
		goto aicl_pre_step;
	} else if (current_ma < 1200)
		goto aicl_end;

	i = 3; /* 1200 */
	sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	msleep(90);
	chg_vol = oplus_sy697x_get_vbus();
	if (chg_vol < aicl_point_temp) {
		i = i - 1;
		goto aicl_pre_step;
	}

	i = 4; /* 1500 */
	aicl_point_temp = aicl_point + 50;
	sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	msleep(120);
	chg_vol = oplus_sy697x_get_vbus();
	if (chg_vol < aicl_point_temp) {
		i = i - 2; //We DO NOT use 1.2A here
		goto aicl_pre_step;
	} else if (current_ma < 1500) {
		i = i - 1; //We use 1.2A here
		goto aicl_end;
	} else if (current_ma < 2000)
		goto aicl_end;

	i = 5; /* 1750 */
	aicl_point_temp = aicl_point + 50;
	sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	msleep(120);
	chg_vol = oplus_sy697x_get_vbus();
	if (chg_vol < aicl_point_temp) {
		i = i - 2; //1.2
		goto aicl_pre_step;
	}

	i = 6; /* 2000 */
	aicl_point_temp = aicl_point;
	sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	msleep(90);
	if (chg_vol < aicl_point_temp) {
		i =  i - 2;//1.5
		goto aicl_pre_step;
	} else if (current_ma < 3000)
		goto aicl_end;

	i = 7; /* 3000 */
	sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	msleep(90);
	chg_vol = oplus_sy697x_get_vbus();
	if (chg_vol < aicl_point_temp) {
		i = i - 1;
		goto aicl_pre_step;
	} else if (current_ma >= 3000)
		goto aicl_end;

aicl_pre_step:
	if (chip->is_double_charger_support
			&& (chip->slave_charger_enable || chip->em_mode)) {
		chg_debug("enable sgm41511x for charging\n");

		main_cur = (usb_icl[i] * current_percent)/100;
		main_cur -= main_cur % 50;
		slave_cur = usb_icl[i] - main_cur;
		sy697x_set_input_current_limit(g_sy, main_cur);
		chip->sub_chg_ops->input_current_write(slave_cur);

		rc = chip->sub_chg_ops->charging_enable();
		if (rc < 0) {
			chg_debug("enable sub charging fail\n");
		}

		if (chip->em_mode && !chip->slave_charger_enable) {
			chip->slave_charger_enable = true;
		}

		chg_debug("usb input max current limit aicl: master and salve input current: %d, %d\n",
				main_cur, slave_cur);
	} else {
		sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	}

	dev_info(g_sy->dev, "%s:usb input max current limit aicl chg_vol=%d j[%d]=%d sw_aicl_point:%d aicl_pre_step\n",__func__, chg_vol, i, usb_icl[i], aicl_point_temp);
	return rc;
aicl_end:
	if (chip->is_double_charger_support
			&& (chip->slave_charger_enable || chip->em_mode)) {
		chg_debug("enable sgm41511x for charging\n");

		main_cur = (usb_icl[i] * current_percent)/100;
		main_cur -= main_cur % 50;
		slave_cur = usb_icl[i] - main_cur;
		sy697x_set_input_current_limit(g_sy, main_cur);
		chip->sub_chg_ops->input_current_write(slave_cur);
		rc = chip->sub_chg_ops->charging_enable();
		if (rc < 0) {
			chg_debug("enable sub charging fail\n");
		}

		if (chip->em_mode && !chip->slave_charger_enable) {
			chip->slave_charger_enable = true;
		}

		chg_debug("usb input max current limit aicl: master and salve input current: %d, %d\n", main_cur, slave_cur);
	} else {
		sy697x_set_input_current_limit(g_sy, usb_icl[i]);
	}

	if (chip->em_mode) {
		chip->charger_volt = chg_vol;
		power_supply_changed(chip->batt_psy);
	}
	dev_info(g_sy->dev, "%s:usb input max current limit aicl chg_vol=%d j[%d]=%d sw_aicl_point:%d aicl_end\n",__func__, chg_vol, i, usb_icl[i], aicl_point_temp);
	return rc;
}

int oplus_sy697x_set_input_current_limit(int current_ma)
{
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (g_sy == NULL || chip == NULL)
		return 0;

	if (chip && chip->mmi_chg == 0) {
		chg_debug("mmi_chg status and return\n");
		sy697x_set_input_current_limit(g_sy, 0);
		return 0;
	}

	if (atomic_read(&g_sy->driver_suspended) == 1) {
		return 0;
	}

	if (atomic_read(&g_sy->charger_suspended) == 1) {
		chg_err("suspend,ignore set current=%dmA\n", current_ma);
		return 0;
	}

	dev_info(g_sy->dev, " is_force_aicl false current=%d\n", current_ma);
	g_sy->aicr = current_ma;
	oplus_sy697x_set_aicr(g_sy->aicr);
	return 0;
}

int oplus_sy697x_set_cv(int cur)
{
	return sy697x_set_chargevolt(g_sy, cur);
}

int oplus_sy697x_set_ieoc(int cur)
{
	return sy697x_set_term_current(g_sy, cur);
}

int oplus_sy697x_charging_enable(void)
{
	return sy697x_enable_charger(g_sy); 
}

int oplus_sy697x_charging_disable(void)
{
#ifdef CONFIG_OPLUS_CHARGER_MTK
	struct charger_manager *info = NULL;
	
	if(g_sy->chg_consumer != NULL)
		info = g_sy->chg_consumer->cm;

	if(!info){
		dev_info(g_sy->dev, "%s:error\n", __func__);
		return false;
	}
#endif /*CONFIG_OPLUS_CHARGER_MTK*/
	return sy697x_disable_charger(g_sy);
}

int oplus_sy697x_hardware_init(void)
{
	int ret = 0;
	dev_info(g_sy->dev, "%s\n", __func__);
	pr_err("oplus_sy697x_hardware_init enter");

	/* Enable charging */
	if (strcmp(g_sy->chg_dev_name, "primary_chg") == 0) {
		oplus_sy697x_set_cv(DEFAULT_CV);
		oplus_sy697x_set_ichg(SY697X_CHARGING_INIT_CURRENT);
		sy697x_set_term_current(g_sy, g_sy->platform_data->iterm);
		sy697x_set_input_volt_limit(g_sy, SY697X_HW_AICL_POINT);
		if (oplus_is_rf_ftm_mode()) {
			oplus_sy697x_charger_suspend();
		} else {
			oplus_sy697x_charger_unsuspend();
			ret = sy697x_enable_charger(g_sy);
			if (ret < 0)
				dev_notice(g_sy->dev, "%s: en chg fail\n", __func__);
		}

		if (atomic_read(&g_sy->charger_suspended) == 1) {
			chg_err("suspend,ignore set current=500mA\n");
		} else {
			oplus_sy697x_set_aicr(SY697X_INPUT_INIT_CURRENT);
		}
	}
	return ret;

}

int oplus_sy697x_is_charging_enabled(void)
{
	int ret = 0;
	u8 val;
	struct sy697x *sy = g_sy;
	if (!sy) {
		return 0;
	}

	ret = sy697x_read_byte(sy, SY697X_REG_03, &val);
	if (!ret) {
		return !!(val & SY697X_CHG_CONFIG_MASK);
	}
	return 0;
}

int oplus_sy697x_is_charging_done(void)
{
	//int ret = 0;
	bool done;

	sy697x_check_charge_done(g_sy, &done);

	return done;

}

int oplus_sy697x_enable_otg(void)
{
	int ret = 0;

	ret = sy697x_set_boost_current(g_sy, g_sy->platform_data->boosti);
	dev_notice(g_sy->dev, "%s set boost curr %d ret %d\n", __func__, g_sy->platform_data->boosti, ret);
	ret = sy697x_enable_otg(g_sy);

	if (ret < 0) {
		dev_notice(g_sy->dev, "%s en otg fail(%d)\n", __func__, ret);
		return ret;
	}

	g_sy->otg_enable = true;
	return ret;
}

bool oplus_get_otg_enable(void)
{
	u8 data = 0;

	if (g_sy) {
		g_sy697x_read_reg(g_sy, SY697X_REG_03, &data);
	}
	dev_notice(g_sy->dev, "%s en otg (%d)\n", __func__, data);
	if (data & (SY697X_OTG_ENABLE << SY697X_OTG_CONFIG_SHIFT)) {
		dev_notice(g_sy->dev, "%s  otg enable (true)\n", __func__);
		return true;
	} else {
		dev_notice(g_sy->dev, "%s  otg disable (false)\n", __func__);
		return false;
	}
	return false;
}

int oplus_sy697x_disable_otg(void)
{
	int ret = 0;

	ret = sy697x_disable_otg(g_sy);

	if (ret < 0) {
		dev_notice(g_sy->dev, "%s disable otg fail(%d)\n", __func__, ret);
		return ret;
	}

	g_sy->otg_enable = false;
	return ret;

}

int oplus_sy697x_disable_te(void)
{
	return  sy697x_enable_term(g_sy, false);
}

int oplus_sy697x_get_chg_current_step(void)
{
	return SY697X_ICHG_LSB;
}

int oplus_sy697x_get_charger_type(void)
{
	pr_err("OPLUS_CHG:g_sy->oplus_chg_type=%d\n",g_sy->oplus_chg_type);
	return g_sy->oplus_chg_type;
}

int oplus_sy697x_charger_suspend(void)
{
	if(g_sy)
		sy697x_enter_hiz_mode(g_sy);
	if (g_oplus_chip && g_oplus_chip->is_double_charger_support) {
		g_oplus_chip->slave_charger_enable = false;
		g_oplus_chip->sub_chg_ops->charger_suspend();
	}
	printk("%s\n",__func__);
	return 0;
}

int oplus_sy697x_charger_unsuspend(void)
{
	if(g_sy)
		sy697x_exit_hiz_mode(g_sy);
	if (g_oplus_chip && g_oplus_chip->is_double_charger_support) {
		g_oplus_chip->sub_chg_ops->charger_unsuspend();
	}
	printk("%s\n",__func__);
	return 0;
}

int oplus_sy697x_set_rechg_vol(int vol)
{
	return 0;
}

int oplus_sy697x_reset_charger(void)
{
	return 0;
}

bool oplus_sy697x_check_charger_resume(void)
{
	return true;
}

static int oplus_register_extcon(struct sy697x *chip)
{
	int rc = 0;

	chip->extcon = devm_extcon_dev_allocate(chip->dev, smblib_extcon_cable);
	if (IS_ERR(chip->extcon)) {
		rc = PTR_ERR(chip->extcon);
		dev_err(chip->dev, "failed to allocate extcon device rc=%d\n",
				rc);
		goto cleanup;
	}

	rc = devm_extcon_dev_register(chip->dev, chip->extcon);
	if (rc < 0) {
		dev_err(chip->dev, "failed to register extcon device rc=%d\n",
				rc);
		goto cleanup;
	}

	/* Support reporting polarity and speed via properties */
	rc = extcon_set_property_capability(chip->extcon,
			EXTCON_USB, EXTCON_PROP_USB_TYPEC_POLARITY);
	rc |= extcon_set_property_capability(chip->extcon,
			EXTCON_USB, EXTCON_PROP_USB_SS);
	rc |= extcon_set_property_capability(chip->extcon,
			EXTCON_USB_HOST, EXTCON_PROP_USB_TYPEC_POLARITY);
	rc |= extcon_set_property_capability(chip->extcon,
			EXTCON_USB_HOST, EXTCON_PROP_USB_SS);

	dev_err(chip->dev, "oplus_register_extcon rc=%d\n",
			rc);
cleanup:
	return rc;
}

static int opluschg_parse_custom_dt(struct oplus_chg_chip *chip)
{
	struct device_node *node = chip->dev->of_node;
	int rc =0;

	if (!node) {
		pr_err("device tree node missing\n");
		return -EINVAL;
	}

	/* pinctrl */
	chip->normalchg_gpio.pinctrl = devm_pinctrl_get(chip->dev);
	pr_err("opluschg_parse_custom_dt 1\n");

	/* usb switch 1 gpio */
	chip->normalchg_gpio.chargerid_switch_gpio = of_get_named_gpio(node, "qcom,chargerid_switch-gpio", 0);
	if (chip->normalchg_gpio.chargerid_switch_gpio > 0){
		if (gpio_is_valid(chip->normalchg_gpio.chargerid_switch_gpio)) {
			rc = gpio_request(chip->normalchg_gpio.chargerid_switch_gpio,
				"chargerid-switch1-gpio");
			if (rc) {
				chg_err("unable to request gpio [%d]\n",
					chip->normalchg_gpio.chargerid_switch_gpio);
			}
		}

		pr_err("opluschg_parse_custom_dt 3\n");
		chip->normalchg_gpio.chargerid_switch_active =
			pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, "chargerid_switch_active");

		pr_err("opluschg_parse_custom_dt 4\n");
		chip->normalchg_gpio.chargerid_switch_sleep =
			pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, "chargerid_switch_sleep");
		pr_err("opluschg_parse_custom_dt 5\n");
		pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.chargerid_switch_sleep);
		chip->normalchg_gpio.chargerid_switch_default =
			pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, "chargerid_switch_default");
		pr_err("opluschg_parse_custom_dt 6\n");
		pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.chargerid_switch_default);

	}

	/* vbus short gpio */
	chip->normalchg_gpio.dischg_gpio = of_get_named_gpio(node, "qcom,dischg-gpio", 0);
	if (chip->normalchg_gpio.dischg_gpio > 0){
		chip->normalchg_gpio.dischg_enable = pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, "dischg_enable");
		chip->normalchg_gpio.dischg_disable = pinctrl_lookup_state(chip->normalchg_gpio.pinctrl, "dischg_disable");
		pinctrl_select_state(chip->normalchg_gpio.pinctrl, chip->normalchg_gpio.dischg_disable);
	}

	rc = oplus_chg_ccdetect_parse_dt(chip);
	if (rc) {
		pr_err("[OPLUS_CHG][%s]: oplus_chg_ccdetect_parse_dt fail!\n", __func__);
	}
	pr_debug("[oplus_chg_ccdetect_parse_dt] done\n", __func__);


	pr_debug("[%s] done\n", __func__);
	return 0;
}

static int oplus_sy697x_get_chargerid_switch(void)
{
	if (!g_oplus_chip) {
		chg_err("fail to init oplus_chip\n");
		return 0;
	}

	if (g_oplus_chip->normalchg_gpio.chargerid_switch_gpio <= 0) {
		chg_err("chargerid_switch_gpio not exist, return\n");
		return 0;
	}

	pr_debug("[%s] gpio[%d] done\n", __func__, g_oplus_chip->normalchg_gpio.chargerid_switch_gpio);
	return gpio_get_value(g_oplus_chip->normalchg_gpio.chargerid_switch_gpio);
}

static void oplus_sy697x_set_chargerid_switch(int value)
{
	pr_debug("[%s] val[%d]\n", __func__, value);

	if (!g_oplus_chip) {
		chg_err("fail to init oplus_chip\n");
		return;
	}

	if (g_oplus_chip->normalchg_gpio.chargerid_switch_gpio <= 0) {
		chg_err("chargerid_switch_gpio not exist, return\n");
		return;
	}

	if (IS_ERR_OR_NULL(g_oplus_chip->normalchg_gpio.pinctrl)
		|| IS_ERR_OR_NULL(g_oplus_chip->normalchg_gpio.chargerid_switch_active)
		|| IS_ERR_OR_NULL(g_oplus_chip->normalchg_gpio.chargerid_switch_sleep)
		|| IS_ERR_OR_NULL(g_oplus_chip->normalchg_gpio.chargerid_switch_default)) {
		chg_err("pinctrl null, return\n");
		return;
	}

	if (oplus_vooc_get_adapter_update_real_status() == ADAPTER_FW_NEED_UPDATE
		|| oplus_vooc_get_btb_temp_over() == true) {
		chg_err("adapter update or btb_temp_over, return\n");
		return;
	}

	if (g_oplus_chip->pmic_spmi.smb5_chip)
		mutex_lock(&g_oplus_chip->pmic_spmi.smb5_chip->chg.pinctrl_mutex);

	if (value){
		pinctrl_select_state(g_oplus_chip->normalchg_gpio.pinctrl,
			g_oplus_chip->normalchg_gpio.chargerid_switch_active);
		gpio_direction_output(g_oplus_chip->normalchg_gpio.chargerid_switch_gpio, 1);
		//dump_stack();
		chg_err("switch rxtx\n");
	}
	else{
		pinctrl_select_state(g_oplus_chip->normalchg_gpio.pinctrl,
			g_oplus_chip->normalchg_gpio.chargerid_switch_sleep);
		gpio_direction_output(g_oplus_chip->normalchg_gpio.chargerid_switch_gpio, 0);
		chg_err("switch dpdm\n");
	}

	if (g_oplus_chip->pmic_spmi.smb5_chip)
		mutex_unlock(&g_oplus_chip->pmic_spmi.smb5_chip->chg.pinctrl_mutex);

	chg_debug("set usb_switch_1 = %d, result = %d\n", value, oplus_sy697x_get_chargerid_switch());
}

static int opluschg_get_chargerid(void)
{
	return 0;
}

int oplus_sy697x_get_charger_subtype(void)
{
#ifdef CONFIG_OPLUS_CHARGER_MTK
	struct charger_manager *info = NULL;

	if(g_sy->chg_consumer != NULL)
		info = g_sy->chg_consumer->cm;

	if(!info){
		dev_info(g_sy->dev, "%s:error\n", __func__);
		return false;
	}
#endif /*CONFIG_OPLUS_CHARGER_MTK*/
	if(g_sy->hvdcp_can_enabled){
#ifdef ENABLE_HVDCP
		return CHARGER_SUBTYPE_QC;
#else
		return CHARGER_SUBTYPE_DEFAULT;
#endif
	}else{
		return CHARGER_SUBTYPE_DEFAULT;
	}
}

bool oplus_sy697x_need_to_check_ibatt(void)
{
	return false;
}

int oplus_sy697x_get_dyna_aicl_result(void)
{
	int mA = 0;

	sy697x_read_idpm_limit(g_sy, &mA);
	return mA;
}
static void vol_convert_work(struct work_struct *work)
{
	//struct oplus_chg_chip *chip = g_oplus_chip;
	int retry = 20;
	if (!g_sy->pdqc_setup_5v)
	{
		printk("%s,set_to_9v\n",__func__);
		if (oplus_sy697x_get_vbus() < 5800) {
			sy697x_enable_hvdcp(g_sy);
			sy697x_switch_to_hvdcp(g_sy, HVDCP_9V);
			Charger_Detect_Init();
			oplus_for_cdp();
			g_sy->is_force_aicl = true;
			g_sy->is_retry_bc12 = true;
			sy697x_force_dpdm(g_sy, true);
			msleep(500);
			while(retry--) {
				if(oplus_sy697x_get_vbus() > 7600) {
					printk("%s,set_to_9v success\n",__func__);
					break;
				}
				msleep(500);
			}
		} 
	} else {
		printk("%s,set_to_5v\n",__func__);
		if(oplus_sy697x_get_vbus() > 7500) {
			sy697x_disable_hvdcp(g_sy);
			Charger_Detect_Init();
			oplus_for_cdp();
			g_sy->is_force_aicl = true;
			g_sy->is_retry_bc12 = true;
			sy697x_force_dpdm(g_sy, true);
			msleep(500);
			while(retry--) {
				if(oplus_sy697x_get_vbus() < 5800) {
					printk("%s,set_to_5v success\n",__func__);
					break;
				}
				msleep(500);
			}
		}
	}
	g_sy->is_bc12_end = true;
}
int oplus_sy697x_set_qc_config(void)
{
	struct oplus_chg_chip *chip = g_oplus_chip;
	static int qc_to_9v_count = 0; /*for huawei quick charger*/
#ifdef CONFIG_OPLUS_CHARGER_MTK
	struct charger_manager *info = NULL;
	static int qc_to_9v_count = 0; /*for huawei quick charger*/

	if(g_sy->chg_consumer != NULL)
		info = g_sy->chg_consumer->cm;

	if(!info){
		dev_info(g_sy->dev, "%s:error\n", __func__);
		return false;
	}
#endif /*CONFIG_OPLUS_CHARGER_MTK*/
	if (!chip) {
		dev_info(g_sy->dev, "%s: error\n", __func__);
		return false;
	}

	if(disable_QC){
		dev_info(g_sy->dev, "%s:disable_QC\n", __func__);
		return false;
	}

	if(g_sy->disable_hight_vbus==1){
		dev_info(g_sy->dev, "%s:disable_hight_vbus\n", __func__);
		return false;
	}

	if (chip->calling_on || chip->camera_on || chip->ui_soc >= 90 || chip->cool_down_force_5v == true || 
		chip->limits.tbatt_pdqc_to_5v_thr == true) {
		dev_info(g_sy->dev, "++%s: set_qc_to 5V =%d,bc12=%d", __func__,g_sy->pdqc_setup_5v,g_sy->is_bc12_end);
		printk("%d,%d,%d,%d,%d,%d\n",chip->calling_on,chip->camera_on,chip->ui_soc,chip->cool_down_force_5v,chip->limits.tbatt_pdqc_to_5v_thr,chip->charger_volt);
		g_sy->pdqc_setup_5v = true;
		if (g_sy->is_bc12_end) {
			g_sy->is_bc12_end = false;
			schedule_delayed_work(&g_sy->sy697x_vol_convert_work, 0);
		}
		dev_info(g_sy->dev, "%s: set_qc_to 5V =%d,bc12=%d", __func__,g_sy->pdqc_setup_5v,g_sy->is_bc12_end);
	} else { // 9v
		g_sy->pdqc_setup_5v = false;
		if (g_sy->is_bc12_end) {
			g_sy->is_bc12_end = false;
			schedule_delayed_work(&g_sy->sy697x_vol_convert_work, 0);
		}
		/*add for huawei quick charge*/
		if(oplus_sy697x_get_vbus() < 5800) {
			if (qc_to_9v_count >= 5) {
				g_sy->hvdcp_can_enabled = false;
				qc_to_9v_count = 0;
			}
			if (g_sy->hvdcp_can_enabled) {
				qc_to_9v_count++;
			}
		}

		printk("%d,%d,%d,%d,%d,%d\n",chip->calling_on,chip->camera_on,chip->ui_soc,chip->cool_down_force_5v,chip->limits.tbatt_pdqc_to_5v_thr,chip->charger_volt);
		dev_info(g_sy->dev, "%s: set_qc_to 9V =%d,bc12=%d", __func__,g_sy->pdqc_setup_5v,g_sy->is_bc12_end);
	}

	return true;
}

int oplus_sy697x_enable_qc_detect(void)
{
	return 0;
}
bool oplus_sy697x_need_retry_aicl(void)
{
	static bool connect = false;
	if (!g_sy)
		return false;
	if ((g_sy->boot_mode == MSM_BOOT_MODE__RF || g_sy->boot_mode == MSM_BOOT_MODE__WLAN) && !connect) {
		if(g_oplus_chip->chg_ops->get_charger_volt() > 4400) {
			g_sy->chg_type = STANDARD_HOST;
			g_sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB;
			g_oplus_chip->charger_type = POWER_SUPPLY_TYPE_USB;
			g_oplus_chip->chg_ops->usb_connect();
			connect = true;
		}
	}
	if (g_sy->cdp_retry_aicl) {
		g_sy->cdp_retry_aicl = false;
		chg_err("retry aicl\n");
		return true;
	}
	return g_sy->cdp_retry_aicl;
}
bool oplus_check_chrdet_status(void)
{
	u8 reg_val;
	int ret;

	if (!g_sy)
		return false;

	if (g_sy->is_retry_bc12 == true && g_sy->is_force_aicl == false) {
		ret = sy697x_read_byte(g_sy, SY697X_REG_0B, &reg_val);
		if (!ret) {
			if (SY697X_VBUS_STAT_MASK & reg_val) {
				chg_err("bc12 succses\n");
				g_sy->is_retry_bc12 = false;
				printk("[%s 1]:chg_type = %d, %d, %d\n", __func__, g_sy->chg_type, g_sy->oplus_chg_type, g_oplus_chip->charger_type);
				sy_charger_type_recheck(g_sy);
				printk("[%s 2]:chg_type = %d, %d, %d\n", __func__, g_sy->chg_type, g_sy->oplus_chg_type, g_oplus_chip->charger_type);
			} else if(!g_sy->power_good) {
				g_sy->is_retry_bc12 = false;
			}
		}
	}
	return ret;
}


int oplus_sy697x_chg_set_high_vbus(bool en)
{
	int subtype;
	struct oplus_chg_chip *chip = g_oplus_chip;

	if (!chip) {
		dev_info(g_sy->dev, "%s: error\n", __func__);
		return false;
	}

	if(en){
		g_sy->disable_hight_vbus= 0;
		if(chip->charger_volt >7500){
			dev_info(g_sy->dev, "%s:charger_volt already 9v\n", __func__);
			return false;
		}

		if(g_sy->pdqc_setup_5v){
			dev_info(g_sy->dev, "%s:pdqc already setup5v no need 9v\n", __func__);
			return false;
		}

	}else{
		g_sy->disable_hight_vbus= 1;
		if(chip->charger_volt < 5400){
			dev_info(g_sy->dev, "%s:charger_volt already 5v\n", __func__);
			return false;
		}
	}

	subtype=oplus_sy697x_get_charger_subtype();
	if(subtype==CHARGER_SUBTYPE_QC){
		if(en){
			dev_info(g_sy->dev, "%s:QC Force output 9V\n",__func__);
			sy697x_switch_to_hvdcp(g_sy, HVDCP_9V);
		}else{
			sy697x_switch_to_hvdcp(g_sy, HVDCP_5V);
			dev_info(g_sy->dev, "%s: set qc to 5V", __func__);
		}
	}else{
		dev_info(g_sy->dev, "%s:do nothing\n", __func__);
	}

	return false;
}

int oplus_charger_type_thread(void *data)
{
	int ret;

	u8 reg_val = 0;
	int vbus_stat = 0;
	//enum charger_type chg_type = CHARGER_UNKNOWN;
	struct sy697x *sy = (struct sy697x *) data;
	int re_check_count = 0;

	while (1) {
		wait_event_interruptible(oplus_chgtype_wq,sy->chg_need_check == true);
		if (oplus_get_otg_enable()) {
			printk("[%s 1]:otg enable is break chg_type = %d, %d, %d\n", __func__, sy->chg_type, sy->oplus_chg_type, g_oplus_chip->charger_type);
			break;
		}

		re_check_count = 0;
		sy->chg_start_check = true;
		sy->chg_need_check = false;
RECHECK:
		ret = sy697x_read_byte(sy, SY697X_REG_0B, &reg_val);
		if (g_oplus_chip)
			printk("[%s 1]:vbus_stat: %d chg_type = %d, %d, %d\n", __func__, vbus_stat, sy->chg_type, sy->oplus_chg_type, g_oplus_chip->charger_type);
		if (ret)
			break;

		vbus_stat = (reg_val & SY697X_VBUS_STAT_MASK);
		vbus_stat >>= SY697X_VBUS_STAT_SHIFT;
		sy->vbus_type = vbus_stat;

		switch (vbus_stat) {
		case SY697X_VBUS_TYPE_NONE:
			sy->chg_type = CHARGER_UNKNOWN;
			sy->oplus_chg_type = POWER_SUPPLY_TYPE_UNKNOWN;
			msleep(20);
			re_check_count++;
			if(re_check_count == 75) {
				sy->chg_type = CHARGER_UNKNOWN;
				sy->oplus_chg_type = POWER_SUPPLY_TYPE_UNKNOWN;
				sy697x_inform_charger_type(sy);
				opluschg_updata_usb_type(sy);
				goto RECHECK;
			} else if (sy->power_good) {
				goto RECHECK;
			}
		case SY697X_VBUS_TYPE_SDP:
			sy->chg_type = STANDARD_HOST;
			sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB;
			if (!sy->sdp_retry) {
				sy->sdp_retry = true;
				schedule_delayed_work(&g_sy->sy697x_bc12_retry_work, OPLUS_BC12_RETRY_TIME);
			}
			break;
		case SY697X_VBUS_TYPE_CDP:
			sy->chg_type = CHARGING_HOST;
			sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_CDP;
#if 0
			if (!sy->cdp_retry) {
				sy->cdp_retry = true;
				schedule_delayed_work(&g_sy->sy697x_bc12_retry_work, OPLUS_BC12_RETRY_TIME_CDP);
			}
#endif
			break;
		case SY697X_VBUS_TYPE_DCP:
			sy->chg_type = STANDARD_CHARGER;
			sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
			break;
		case SY697X_VBUS_TYPE_HVDCP:
			sy->chg_type = STANDARD_CHARGER;
			sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
			//sy->hvdcp_can_enabled = true;
			break;
		case SY697X_VBUS_TYPE_UNKNOWN:
			sy->chg_type = NONSTANDARD_CHARGER;
			sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
			break;
		case SY697X_VBUS_TYPE_NON_STD:
			sy->chg_type = NONSTANDARD_CHARGER;
			sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
			break;
		default:
			sy->chg_type = NONSTANDARD_CHARGER;
			sy->oplus_chg_type = POWER_SUPPLY_TYPE_USB_DCP;
			break;
		}
		if (g_oplus_chip) {
			printk("[%s 2]: chg_type = %d, %d, %d vbus_on[%d]\n", __func__, sy->chg_type,
				sy->oplus_chg_type, g_oplus_chip->charger_type, sy->vbus_on);
				/*fix first poweron adb port*/
				if ((oplus_sy697x_get_charger_type() == POWER_SUPPLY_TYPE_USB) || (oplus_sy697x_get_charger_type() == POWER_SUPPLY_TYPE_USB_CDP)) {
					oplus_notify_device_mode(true);
				}
		}

		if ((sy->oplus_chg_type != POWER_SUPPLY_TYPE_USB) && (sy->oplus_chg_type != POWER_SUPPLY_TYPE_USB_CDP)) {
			sy697x_inform_charger_type(sy);
		} else {
			opluschg_updata_usb_type(sy);
		}
		oplus_chg_wake_update_work();
		printk("[%s] plus_chg_wake_update_work\n", __func__);
		//sy697x_adc_start(sy,true);
		schedule_delayed_work(&g_sy->sy697x_aicl_work, OPLUS_DELAY_WORK_TIME_BASE*2);
		msleep(2000);
		oplus_wake_up_usbtemp_thread();
		printk("[%s] oplus_wake_up_usbtemp_thread\n", __func__);
	}

	return 0;
}

static void charger_type_thread_init(void)
{
	g_sy->chg_need_check = false;
	charger_type_kthread =
			kthread_run(oplus_charger_type_thread, g_sy, "chgtype_kthread");
	if (IS_ERR(charger_type_kthread)) {
		chg_err("failed to cread oplus_usbtemp_kthread\n");
	}
}

extern int get_boot_mode(void);
static int opluschg_get_boot_reason(void)
{
	return 101;
}
static int opluschg_get_battery_voltage(void)
{
	return 3800;	/* Not use anymore */
}

static int oplus_get_rtc_ui_soc(void)
{
	if (!g_oplus_chip) {
		chg_err("chip not ready\n");
		return 0;
	}
	if (!g_oplus_chip->external_gauge) {
		return 50;
	} else {
		return 0;
	}
}

static int oplus_set_rtc_ui_soc(int backup_soc)
{
	return 0;
}

static bool oplus_sy697x_is_usb_present(void)
{
	u8 val = 0;
	if (g_sy) {
		if (sy697x_read_byte(g_sy, SY697X_REG_11, &val)) {
			pr_err("[%s] failed return false\n", __func__);
			return false;
		}
	} else {
		pr_err("[%s] g_sy is null return false\n", __func__);
		return false;
	}

	val = (val & SY697X_VBUS_GD_MASK);
	return val;
}

static bool oplus_sy697x_charger_detect(void)
{
	u8 val = 0;
	if (g_sy && g_oplus_chip) {
		if (sy697x_read_byte(g_sy, SY697X_REG_11, &val) || g_oplus_chip->otg_online) {
			pr_err("[%s] failed return false otg[%d]\n", __func__, g_oplus_chip->otg_online);
			return false;
		}
	} else {
		pr_err("[%s] g_sy/g_oplus_chip  is null return false\n", __func__);
		return false;
	}

	val = (val & SY697X_VBUS_GD_MASK);
	return val;
}


static int oplus_sy697x_get_vbus(void)
{
	int chg_vol = 5000;
	if (g_sy)
		chg_vol = sy697x_adc_read_vbus_volt(g_sy);
	else{
		pr_err("[%s] g_sy is null\n", __func__);
	}
	return chg_vol;
}

void sy6974b_vooc_timeout_callback(bool vbus_rising)
{
	struct oplus_chg_chip *chip = g_oplus_chip;
	u8 hz_mode = 0;
	int ret;

	if (!g_sy)
		return;

	if (chip == NULL)
		return;

	g_sy->power_good = vbus_rising;
	if (!vbus_rising) {
		ret = sy697x_get_hiz_mode(g_sy,&hz_mode);
		if (!ret && hz_mode) {
			pr_notice("hiz mode ignore\n");
			goto POWER_CHANGE;
		}
		g_sy->is_force_aicl = false;
		g_sy->pre_current_ma = -1;
		g_sy->usb_connect_start = false;
		g_sy->hvdcp_can_enabled = false;
		g_sy->hvdcp_checked = false;
		g_sy->sdp_retry = false;
		g_sy->cdp_retry = false;
		g_sy->chg_type = CHARGER_UNKNOWN;
		g_sy->oplus_chg_type = POWER_SUPPLY_TYPE_UNKNOWN;
		memset(&g_sy->st_ptime[0], 0, sizeof(struct timespec));
		memset(&g_sy->st_ptime[1], 0, sizeof(struct timespec));
		if (chip) {
		chip->pd_chging = false;
		//chip->qc_chging = false;
		}
		if (chip->is_double_charger_support) {
			chip->sub_chg_ops->charging_disable();
		}
		sy697x_inform_charger_type(g_sy);
		opluschg_updata_usb_type(g_sy);

		sy697x_adc_start(g_sy,false);
		pr_notice("adapter/usb pg_good removed\n");
		chip->usbtemp_check = false;
		oplus_splitchg_request_dpdm(g_sy, false);
		oplus_notify_device_mode(false);
		oplus_chg_wakelock(g_sy, false);
	}

POWER_CHANGE:
	if(dumpreg_by_irq)
		sy697x_dump_regs(g_sy);
}

struct oplus_chgic_operations oplus_chgic_sy697x_ops = {
	.typec_sink_removal = oplus_sy697x_typec_sink_removal,
	.typec_src_removal = oplus_sy697x_typec_src_removal,
	.typec_sink_insertion = oplus_sy697x_typec_sink_insertion,
	.get_otg_switch_status = oplus_sy697x_get_otg_switch_status,
	.set_otg_switch_status = oplus_sy697x_set_otg_switch_status,
	.get_otg_online_status = oplus_sy697x_get_otg_online_status,
	.thermal_tmp_get_chg = oplus_sy697x_thermal_tmp_get_chg,
	.thermal_tmp_get_bb = oplus_sy697x_thermal_tmp_get_bb,
	.thermal_tmp_get_flash = oplus_sy697x_thermal_tmp_get_flash,
	.thermal_tmp_get_board = oplus_sy697x_thermal_tmp_get_board,
};

struct oplus_chg_operations  oplus_chg_sy697x_ops = {
	.dump_registers = oplus_sy697x_dump_registers,
	.kick_wdt = oplus_sy697x_kick_wdt,
	.hardware_init = oplus_sy697x_hardware_init,
	.charging_current_write_fast = oplus_sy697x_set_ichg,
	.set_aicl_point = oplus_sy697x_set_mivr,
	.input_current_write = oplus_sy697x_set_input_current_limit,
	.float_voltage_write = oplus_sy697x_set_cv,
	.term_current_set = oplus_sy697x_set_ieoc,
	.charging_enable = oplus_sy697x_charging_enable,
	.charging_disable = oplus_sy697x_charging_disable,
	.get_charging_enable = oplus_sy697x_is_charging_enabled,
	.charger_suspend = oplus_sy697x_charger_suspend,
	.charger_unsuspend = oplus_sy697x_charger_unsuspend,
	.set_rechg_vol = oplus_sy697x_set_rechg_vol,
	.reset_charger = oplus_sy697x_reset_charger,
	.read_full = oplus_sy697x_is_charging_done,
	.otg_enable = oplus_sy697x_enable_otg,
	.otg_disable = oplus_sy697x_disable_otg,
	.set_charging_term_disable = oplus_sy697x_disable_te,
	.check_charger_resume = oplus_sy697x_check_charger_resume,
	.get_charger_type = oplus_sy697x_get_charger_type,
#ifdef CONFIG_OPLUS_CHARGER_MTK
	.get_charger_volt = battery_get_vbus,
	.get_chargerid_volt = NULL,
	.set_chargerid_switch_val = oplus_sy697x_set_chargerid_switch_val,
	.get_chargerid_switch_val = oplus_sy697x_get_chargerid_switch_val,
	.check_chrdet_status = (bool (*) (void)) pmic_chrdet_status,

	.get_boot_mode = (int (*)(void))get_boot_mode,
	.get_boot_reason = opluschg_get_boot_reason,
	.get_instant_vbatt = oplus_battery_meter_get_battery_voltage,
	.get_rtc_soc = oplus_get_rtc_ui_soc,
	.set_rtc_soc = oplus_set_rtc_ui_soc,
	.set_power_off = mt_power_off,
	.usb_connect = mt_usb_connect,
	.usb_disconnect = mt_usb_disconnect,
#else
	.get_charger_volt = oplus_sy697x_get_vbus,
	.get_chargerid_volt		= opluschg_get_chargerid,
	.set_chargerid_switch_val = oplus_sy697x_set_chargerid_switch,
	.get_chargerid_switch_val = oplus_sy697x_get_chargerid_switch,
	.check_chrdet_status = (bool (*) (void)) oplus_sy697x_charger_detect,

	.get_boot_mode = get_boot_mode,
	.get_boot_reason = (int (*)(void))opluschg_get_boot_reason,
	.get_instant_vbatt = opluschg_get_battery_voltage,
	.get_rtc_soc = oplus_get_rtc_ui_soc,
	.set_rtc_soc = oplus_set_rtc_ui_soc,
#endif /*CONFIG_OPLUS_CHARGER_MTK*/
	.get_chg_current_step = oplus_sy697x_get_chg_current_step,
	.need_to_check_ibatt = oplus_sy697x_need_to_check_ibatt,
	.get_dyna_aicl_result = oplus_sy697x_get_dyna_aicl_result,
	.get_shortc_hw_gpio_status = NULL,
	.oplus_chg_get_pd_type = NULL,
	.oplus_chg_pd_setup = NULL,
	.get_charger_subtype = oplus_sy697x_get_charger_subtype,
	.set_qc_config = oplus_sy697x_set_qc_config,
	.enable_qc_detect = oplus_sy697x_enable_qc_detect,
#ifdef CONFIG_OPLUS_CHARGER_MTK
	.oplus_chg_get_pe20_type = NULL,
	.oplus_chg_pe20_setup = NULL,
	.oplus_chg_reset_pe20 = NULL,
	.extern_charger_usbtemp = oplus_extern_charger_usbtemp_action,
#endif /*CONFIG_OPLUS_CHARGER_MTK*/
	.oplus_chg_set_high_vbus = oplus_sy697x_chg_set_high_vbus,
	.enable_shipmode = sy697x_enable_shipmode,
	.get_usbtemp_volt = oplus_sy697x_get_usbtemp_volt,
	.oplus_usbtemp_monitor_condition = oplus_usbtemp_condition,
	.vooc_timeout_callback = sy6974b_vooc_timeout_callback,
	.set_typec_cc_open = sgm7220_set_typec_cc_open,
	.set_typec_sinkonly = sgm7220_set_typec_sinkonly,
	.get_charger_current = sy697x_get_input_current,
	.suspend_for_usbtemp = sy697x_suspend_by_hz_mode,
};

static void aicl_work_callback(struct work_struct *work)
{
	int re_check_count = 0;
	if (!g_sy)
		return;
	if (g_sy->oplus_chg_type == POWER_SUPPLY_TYPE_USB_DCP && g_sy->is_force_aicl) {
		while (g_sy->is_force_aicl) {
			if (re_check_count++ < 200) {
				msleep(20);
			} else {
				break;
			}
		}
	}
	oplus_sy697x_set_aicr(g_sy->aicr);
}

static void bc12_retry_work_callback(struct work_struct *work)
{
	if (!g_sy)
		return;

	if (g_sy->sdp_retry || g_sy->cdp_retry) {
		Charger_Detect_Init();
		oplus_for_cdp();
		printk("usb/cdp start bc1.2 once\n");
		g_sy->usb_connect_start = true;
		g_sy->is_force_aicl = true;
		g_sy->is_retry_bc12 = true;
		sy697x_force_dpdm(g_sy, true);
	}
}

static struct of_device_id sy697x_charger_match_table[] = {
	{.compatible = "ti,sy6970",},
	{},
};

MODULE_DEVICE_TABLE(of, sy697x_charger_match_table);

static const struct i2c_device_id sy697x_i2c_device_id[] = {
	{ "sy6970", 0x05 },
	{ },
};

MODULE_DEVICE_TABLE(i2c, sy697x_i2c_device_id);

//add by for power_supply
static enum power_supply_property oplus_sy697x_usb_props[] = {
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_TYPE,
	POWER_SUPPLY_PROP_REAL_TYPE,
};

void oplus_sy697x_set_otg_switch_status(bool value)
{
	int rc;
	struct smb_charger *chg = NULL;
	if (!g_oplus_chip || !g_sy) {
		chg_err("oplus_chip is null\n");
		return;
	}
	chg = &g_oplus_chip->pmic_spmi.smb5_chip->chg;

	if(oplus_ccdetect_check_is_gpio(g_oplus_chip) == true) {
		if (gpio_get_value(chg->ccdetect_gpio) == 0) {
			printk(KERN_ERR "[OPLUS_CHG][oplus_set_otg_switch_status]: gpio[L], should set, return\n");
			return;
		}
	}

	g_oplus_chip->otg_switch = value;
	if (g_oplus_chip->otg_switch == true)
		rc = oplus_sgm7220_set_mode(3);	//drp
	else
		rc = oplus_sgm7220_set_mode(1);	//snk
	if (rc < 0)
		chg_err("fail to write register\n");


	chg_debug("otg_switch = %d, otg_online = %d, \n",
		g_oplus_chip->otg_switch, g_oplus_chip->otg_online);
}
EXPORT_SYMBOL(oplus_sy697x_set_otg_switch_status);

bool oplus_sy697x_get_otg_switch_status(void)
{
	if (!g_oplus_chip) {
		chg_err("fail to init oplus_chip\n");
		return false;
	}
	chg_err("otg_switch[%d]\n", g_oplus_chip->otg_switch);
	return g_oplus_chip->otg_switch;
}
EXPORT_SYMBOL(oplus_sy697x_get_otg_switch_status);


static int oplus_sy697x_usb_set_prop(struct power_supply *psy,
		enum power_supply_property psp,
		const union power_supply_propval *val)
{
	int rc = 0;
	switch (psp) {
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

int oplus_sy697x_get_usb_online(struct sy697x *chg,
			union power_supply_propval *val)
{
	int rc;

	if (!chg) {
		val->intval = 0;
		return 0;
	}

	if (g_oplus_chip) {
		if (chg->power_good && (oplus_get_usb_status() != USB_TEMP_HIGH)
			&& ((chg->oplus_chg_type == POWER_SUPPLY_TYPE_USB) || (chg->oplus_chg_type == POWER_SUPPLY_TYPE_USB_CDP)))
			val->intval = 1;
		else
			val->intval = 0;
	}

	return rc;
}



static int oplus_sy697x_usb_get_prop(struct power_supply *psy,
		enum power_supply_property psp,
		union power_supply_propval *val)
{
	int rc = 0;
	struct sy697x *chg = g_sy;
	val->intval = 0;

	if (!chg) {
		pr_err("oplus_sy697x_usb_get_prop return invalid\n");
		return -EINVAL;
	}

	switch (psp) {
	case POWER_SUPPLY_PROP_TYPE:
		val->intval = chg->oplus_chg_type;
		break;
	case POWER_SUPPLY_PROP_REAL_TYPE:
		val->intval = chg->oplus_chg_type;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = oplus_sy697x_is_usb_present();
		break;
	case POWER_SUPPLY_PROP_ONLINE:
		oplus_sy697x_get_usb_online(chg, val);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	if (rc < 0) {
		return -ENODATA;
	}

	return 0;
}

static int oplus_sy697x_usb_prop_is_writeable(struct power_supply *psy,
		enum power_supply_property psp)
{
	switch (psp) {
	default:
		break;
	}

	return 0;
}

static struct power_supply_desc usb_psy_desc = {
	.name = "usb",
#ifndef OPLUS_FEATURE_CHG_BASIC
/* Yichun.Chen  PSW.BSP.CHG  2019-04-08  for charge */
	.type = POWER_SUPPLY_TYPE_USB_PD,
#else
	.type = POWER_SUPPLY_TYPE_USB,
#endif
	.properties = oplus_sy697x_usb_props,
	.num_properties = ARRAY_SIZE(oplus_sy697x_usb_props),
	.get_property = oplus_sy697x_usb_get_prop,
	.set_property = oplus_sy697x_usb_set_prop,
	.property_is_writeable = oplus_sy697x_usb_prop_is_writeable,
};

static enum power_supply_property oplus_sy697x_batt_props[] = {
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
	POWER_SUPPLY_PROP_CHARGE_FULL,
	POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN,
	POWER_SUPPLY_PROP_TIME_TO_FULL_NOW,
	POWER_SUPPLY_PROP_CAPACITY_LEVEL,
};

static int oplus_sy697x_batt_get_prop(struct power_supply *psy,
		enum power_supply_property psp,
		union power_supply_propval *val)
{
	int rc = 0;

	switch (psp) {
#ifdef OPLUS_FEATURE_CHG_BASIC
	case POWER_SUPPLY_PROP_CAPACITY_LEVEL:
		val->intval = POWER_SUPPLY_CAPACITY_LEVEL_NORMAL;
		if (g_oplus_chip && (g_oplus_chip->ui_soc == 0)) {
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_CRITICAL;
			chg_err("bat pro POWER_SUPPLY_CAPACITY_LEVEL_CRITICAL, should shutdown!!!\n");
		}
		break;
	case POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN:
	case POWER_SUPPLY_PROP_CHARGE_FULL:
		val->intval = g_oplus_chip->batt_fcc * 1000;
		break;

	case POWER_SUPPLY_PROP_CHARGE_COUNTER:
		val->intval = g_oplus_chip->ui_soc * g_oplus_chip->batt_capacity_mah * 1000 / 100;
		break;

	case POWER_SUPPLY_PROP_TIME_TO_FULL_NOW:
		val->intval = 0;
		break;

	default:
		rc = oplus_battery_get_property(psy, psp, val);
#endif
	}
	if (rc < 0) {
		pr_debug("Couldn't get prop %d rc = %d\n", psp, rc);
		return -ENODATA;
	}
	return rc;
}

static int oplus_sy697x_batt_set_prop(struct power_supply *psy,
		enum power_supply_property prop,
		const union power_supply_propval *val)
{
	int rc = 0;
	rc = oplus_battery_set_property(psy, prop, val);
	return rc;
}

static int oplus_sy697x_batt_prop_is_writeable(struct power_supply *psy,
		enum power_supply_property psp)
{
	return oplus_battery_property_is_writeable(psy, psp); 
}

static struct power_supply_desc batt_psy_desc = {
	.name = "battery",
	.type = POWER_SUPPLY_TYPE_BATTERY,
	.properties = oplus_sy697x_batt_props,
	.num_properties = ARRAY_SIZE(oplus_sy697x_batt_props),
	.get_property = oplus_sy697x_batt_get_prop,
	.set_property = oplus_sy697x_batt_set_prop,
	.property_is_writeable = oplus_sy697x_batt_prop_is_writeable,
};

 static enum power_supply_property ac_props[] = {
/*OPLUS own ac props*/
        POWER_SUPPLY_PROP_ONLINE,
};

static int oplus_sy697x_ac_get_property(struct power_supply *psy,
	enum power_supply_property psp,
	union power_supply_propval *val)
{
	int rc = 0;

    rc = oplus_ac_get_property(psy, psp, val);

	return rc;
}

static struct power_supply_desc ac_psy_desc = {
	.name = "ac",
	.type = POWER_SUPPLY_TYPE_MAINS,
	.properties = ac_props,
	.num_properties = ARRAY_SIZE(ac_props),
	.get_property = oplus_sy697x_ac_get_property,
};

static int oplus_power_supply_init(struct oplus_chg_chip *chip)
{
	int ret = 0;
	struct oplus_chg_chip *chgchip = NULL;

	if (chip == NULL) {
		printk(KERN_ERR "[OPLUS_CHG][%s]: oplus_chip not ready!\n", __func__);
		return -EINVAL;
	}
	chgchip = chip;

	chgchip->ac_psd = ac_psy_desc;
	chgchip->ac_cfg.drv_data = chgchip;
	chgchip->usb_psd = usb_psy_desc;
	chgchip->usb_cfg.drv_data = chgchip;
	chgchip->battery_psd = batt_psy_desc;

	chgchip->ac_psy = power_supply_register(chgchip->dev, &chgchip->ac_psd,
			&chgchip->ac_cfg);
	if (IS_ERR(chgchip->ac_psy)) {
		dev_err(chgchip->dev, "Failed to register power supply ac: %ld\n",
			PTR_ERR(chgchip->ac_psy));
		ret = PTR_ERR(chgchip->ac_psy);
		goto err_ac_psy;
	}

	chgchip->usb_psy = power_supply_register(chgchip->dev, &chgchip->usb_psd,
			&chgchip->usb_cfg);
	if (IS_ERR(chgchip->usb_psy)) {
		dev_err(chgchip->dev, "Failed to register power supply usb: %ld\n",
			PTR_ERR(chgchip->usb_psy));
		ret = PTR_ERR(chgchip->usb_psy);
		goto err_usb_psy;
	}

	chgchip->batt_psy = power_supply_register(chgchip->dev, &chgchip->battery_psd,
			NULL);
	if (IS_ERR(chgchip->batt_psy)) {
		dev_err(chgchip->dev, "Failed to register power supply battery: %ld\n",
			PTR_ERR(chgchip->batt_psy));
		ret = PTR_ERR(chgchip->batt_psy);
		goto err_battery_psy;
	}

	chg_err("%s OK\n", __func__);
	return 0;

err_battery_psy:
	power_supply_unregister(chgchip->usb_psy);
err_usb_psy:
	power_supply_unregister(chgchip->ac_psy);
err_ac_psy:

	return ret;
}

struct oplus_chg_chip* oplus_sy697x_get_oplus_chip(void)
{
	return g_oplus_chip;
}

struct sy697x* oplus_sy697x_get_oplus_chg(void)
{
	return g_sy;
}

static int sy697x_charger_probe(struct i2c_client *client,
				 const struct i2c_device_id *id)
{
	struct sy697x *sy;
	//const struct of_device_id *match;
	struct device_node *node = client->dev.of_node;
	int ret = 0;
	struct oplus_chg_chip *oplus_chip = NULL;
	int level = 0;
	struct smb5 *chip;
	struct smb_charger *chg;

	pr_info("sy697x_charger_probe enter\n");

	/*oplus_chip register*/
	if (oplus_gauge_check_chip_is_null()) {
		chg_err("gauge chip null, will do after bettery init.\n");
		return -EPROBE_DEFER;
	}

	oplus_chip = devm_kzalloc(&client->dev, sizeof(*oplus_chip), GFP_KERNEL);
	if (!oplus_chip) {
		chg_err("oplus_chip null, will do after bettery init.\n");
		return -ENOMEM;
	}

	oplus_chip->dev = &client->dev;
	oplus_chg_parse_svooc_dt(oplus_chip);

	sy = devm_kzalloc(&client->dev, sizeof(struct sy697x), GFP_KERNEL);
	if (!sy)
		return -ENOMEM;

	chip = devm_kzalloc(&client->dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	oplus_chip->pmic_spmi.smb5_chip = chip;
	chg = &chip->chg;
	chg->dev = &client->dev;
	mutex_init(&chg->pinctrl_mutex);
	sy->dev = &client->dev;
	sy->client = client;
	g_sy = sy;
#ifdef CONFIG_OPLUS_CHARGER_MTK
	sy->chg_consumer =
		charger_manager_get_by_name(&client->dev, "sy697x");
#endif /*CONFIG_OPLUS_CHARGER_MTK*/
	i2c_set_clientdata(client, sy);
	mutex_init(&sy->i2c_rw_lock);
	mutex_init(&sy->ntc_lock);
	mutex_init(&sy->dpdm_lock);

	oplus_chg_awake_init(sy);
	init_waitqueue_head(&sy->wait);
	oplus_keep_resume_awake_init(sy);

	atomic_set(&sy->driver_suspended, 0);
	atomic_set(&sy->charger_suspended, 0);
	sy->before_suspend_icl = 0;
	sy->before_unsuspend_icl = 0;
	sy->chgic_ops = &oplus_chgic_sy697x_ops;

	ret = sy697x_detect_device(sy);
	if (ret) {
		pr_err("No sy697x device found!\n");
		ret = -ENODEV;
		goto err_nodev;
	}

	sy->platform_data = sy697x_parse_dt(node, sy);
	if (!sy->platform_data) {
		pr_err("No platform data provided.\n");
		ret = -EINVAL;
		goto err_parse_dt;
	}

	sy697x_reset_chip(sy);
	if ( is_bq25890h(sy) == false) {
		ret = sy697x_init_device(sy);
	}else{
		ret = bq2589x_init_device(sy);
	}
	if (ret) {
		pr_err("Failed to init device\n");
		goto err_init;
	}
	charger_type_thread_init();
	sy->is_bc12_end = true;

	sy->oplus_chg_type = POWER_SUPPLY_TYPE_UNKNOWN;
	sy->pre_current_ma = -1;
	sy->chg_start_check = true;
	sy->usb_connect_start = false;
	if ( is_bq25890h(sy) == false) {
		sy697x_switch_to_hvdcp(sy, HVDCP_9V);
		sy697x_enable_hvdcp(sy);
	}else{
		sy697x_disable_hvdcp(sy);
		bq2589x_disable_maxc(sy);
	}
	sy697x_disable_batfet_rst(sy);
	sy697x_disable_ico(sy);

	INIT_DELAYED_WORK(&sy->sy697x_aicl_work, aicl_work_callback);
	INIT_DELAYED_WORK(&sy->sy697x_bc12_retry_work, bc12_retry_work_callback);
	INIT_DELAYED_WORK(&sy->sy697x_vol_convert_work, vol_convert_work);

	sy697x_register_interrupt(node,sy);
#ifdef CONFIG_OPLUS_CHARGER_MTK
	sy->chg_dev = charger_device_register(sy->chg_dev_name,
					      &client->dev, sy,
					      &sy697x_chg_ops,
					      &sy697x_chg_props);
	if (IS_ERR_OR_NULL(sy->chg_dev)) {
		ret = PTR_ERR(sy->chg_dev);
		goto err_device_register;
	}

	ret = sysfs_create_group(&sy->dev->kobj, &sy697x_attr_group);
#endif /*CONFIG_OPLUS_CHARGER_MTK*/
	if ( is_bq25890h(sy) == false) {
		pr_err("sy697x\n");
	} else {
		pr_err("bq25890h\n");
	}

	g_oplus_chip = oplus_chip;
	oplus_chip->chg_ops = &oplus_chg_sy697x_ops;
	oplus_power_supply_init(oplus_chip);
	opluschg_parse_custom_dt(oplus_chip);
	oplus_chg_parse_charger_dt(oplus_chip);

	oplus_chip->con_volt = con_volt_855;
	oplus_chip->con_temp = con_temp_855;
	oplus_chip->len_array = ARRAY_SIZE(con_temp_855);

	/*platform init*/
	oplus_chg_plt_init_for_qcom(sy);

	/*add extcon register for usb emulation*/
	oplus_register_extcon(sy);

	oplus_chg_init(oplus_chip);

	if (oplus_ccdetect_support_check() == true){
		INIT_DELAYED_WORK(&chg->ccdetect_work,oplus_ccdetect_work);
		INIT_DELAYED_WORK(&usbtemp_recover_work,oplus_usbtemp_recover_work);
		oplus_ccdetect_irq_register(oplus_chip);
		level = gpio_get_value(chg->ccdetect_gpio);
		usleep_range(2000, 2100);
		if (level != gpio_get_value(chg->ccdetect_gpio)) {
			printk(KERN_ERR "[OPLUS_CHG][%s]: ccdetect_gpio is unstable, try again...\n", __func__);
			usleep_range(10000, 11000);
			level = gpio_get_value(chg->ccdetect_gpio);
		}
		if (level <= 0) {
			schedule_delayed_work(&chg->ccdetect_work, msecs_to_jiffies(6000));
		}
		printk(KERN_ERR "[OPLUS_CHG][%s]: ccdetect_gpio ..level[%d]  \n", __func__, level);
	}

	oplus_chg_configfs_init(oplus_chip);
	opluschg_usbtemp_thread_init(oplus_chip);
	oplus_tbatt_power_off_task_init(oplus_chip);
	sy697x_irq_handler(0, sy);

	pr_err("sy697x probe successfully Part Num:%d, Revision:%d\n!", sy->part_no, sy->revision);
	chg_init_done = 1;
	return 0;
err_init:
err_parse_dt:
err_nodev:
	mutex_destroy(&chg->pinctrl_mutex);
	mutex_destroy(&sy->ntc_lock);
	mutex_destroy(&sy->i2c_rw_lock);
	devm_kfree(sy->dev, sy);
	return ret;

}
static unsigned long suspend_tm_sec = 0;
static int get_rtc_time(unsigned long *rtc_time)
{
	struct rtc_time tm;
	struct rtc_device *rtc;
	int rc;

	rtc = rtc_class_open(CONFIG_RTC_HCTOSYS_DEVICE);
	if (rtc == NULL) {
		pr_err("Failed to open rtc device (%s)\n",
		CONFIG_RTC_HCTOSYS_DEVICE);
		return -EINVAL;
	}

	rc = rtc_read_time(rtc, &tm);
	if (rc) {
		pr_err("Failed to read rtc time (%s) : %d\n",
		CONFIG_RTC_HCTOSYS_DEVICE, rc);
		goto close_time;
	}

	rc = rtc_valid_tm(&tm);
	if (rc) {
		pr_err("Invalid RTC time (%s): %d\n",
		CONFIG_RTC_HCTOSYS_DEVICE, rc);
		goto close_time;
	}
	rtc_tm_to_time(&tm, rtc_time);

	close_time:
	rtc_class_close(rtc);
	return rc;
}


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
static int sy697x_pm_resume(struct device *dev)
{
	unsigned long resume_tm_sec = 0;
	unsigned long sleep_time = 0;
	int rc = 0;
	struct sy697x *chip = NULL;
	struct i2c_client *client = to_i2c_client(dev);

	if (client) {
	 chip = i2c_get_clientdata(client);
	 if (chip) {
		 atomic_set(&chip->driver_suspended, 0);
			 wake_up_interruptible(&g_sy->wait);
		 rc = get_rtc_time(&resume_tm_sec);
		 if (rc || suspend_tm_sec == -1) {
			 chg_err("RTC read failed\n");
			 sleep_time = 0;
		 } else {
			 sleep_time = resume_tm_sec - suspend_tm_sec;
		 }
		 if ((resume_tm_sec > suspend_tm_sec) && (sleep_time > 60)) {
			 oplus_chg_soc_update_when_resume(sleep_time);
		 }
	 }
	}

	 return 0;
}

static int sy6974x_pm_suspend(struct device *dev)
{
	struct sy697x *chip = NULL;
	struct i2c_client *client = to_i2c_client(dev);

	if (client) {
		chip = i2c_get_clientdata(client);
		if (chip) {
			atomic_set(&chip->driver_suspended, 1);
			if (get_rtc_time(&suspend_tm_sec)) {
				chg_err("RTC read failed\n");
				suspend_tm_sec = -1;
			}
		}
	}
	return 0;
}

static const struct dev_pm_ops sy697x_pm_ops = {
	 .resume		 = sy697x_pm_resume,
	 .suspend		 = sy6974x_pm_suspend,
 };
#else
static int sy6974x_resume(struct i2c_client *client)
{
	unsigned long resume_tm_sec = 0;
	unsigned long sleep_time = 0;
	int rc = 0;
	struct sy697x *chip = i2c_get_clientdata(client);

	if(!chip) {
		return 0;
	}

	atomic_set(&chip->driver_suspended, 0);
	wake_up_interruptible(&g_sy->wait);
	rc = get_rtc_time(&resume_tm_sec);
	if (rc || suspend_tm_sec == -1) {
		chg_err("RTC read failed\n");
		sleep_time = 0;
	} else {
		sleep_time = resume_tm_sec - suspend_tm_sec;
	}
	if ((resume_tm_sec > suspend_tm_sec) && (sleep_time > 60)) {
		oplus_chg_soc_update_when_resume(sleep_time);
	}

	return 0;
}

static int sy6974x_suspend(struct i2c_client *client, pm_message_t mesg)
{
	struct sy697x *chip = i2c_get_clientdata(client);

	if(!chip) {
		return 0;
	}

	atomic_set(&chip->driver_suspended, 1);
	if (get_rtc_time(&suspend_tm_sec)) {
		chg_err("RTC read failed\n");
		suspend_tm_sec = -1;
	}

	return 0;
}
#endif


static int sy697x_charger_remove(struct i2c_client *client)
{
	struct sy697x *sy = i2c_get_clientdata(client);

	mutex_destroy(&sy->i2c_rw_lock);

	//sysfs_remove_group(&sy->dev->kobj, &sy697x_attr_group);

	return 0;
}

static void sy697x_charger_shutdown(struct i2c_client *client)
{
	if (g_sy) {
		sy697x_adc_start(g_sy, false);
		if (!is_bq25890h(g_sy)) {
			sy697x_disable_otg(g_sy);
		}
		oplus_sy697x_charger_unsuspend();
		pr_err("sy697x_charger_shutdown disable adc and otg\n!");
	}
}

static struct i2c_driver sy697x_charger_driver = {
	.driver = {
		   .name = "sy697x-charger",
		   .owner = THIS_MODULE,
		   .of_match_table = sy697x_charger_match_table,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
		   .pm	  = &sy697x_pm_ops,
#endif
		   },

	.probe = sy697x_charger_probe,
	.remove = sy697x_charger_remove,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
	.resume 	= sy6974x_resume,
	.suspend	= sy6974x_suspend,
#endif
	.shutdown = sy697x_charger_shutdown,
	.id_table = sy697x_i2c_device_id,

};

module_i2c_driver(sy697x_charger_driver);

MODULE_DESCRIPTION("TI SY697X Charger Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Texas Instruments");


