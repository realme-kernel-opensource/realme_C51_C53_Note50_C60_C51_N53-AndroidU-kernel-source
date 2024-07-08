// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 MediaTek Inc.
 * Author Wy Chuang<wy.chuang@mediatek.com>
 */

#include <linux/cdev.h>		/* cdev */
#include <linux/err.h>	/* IS_ERR, PTR_ERR */
#include <linux/init.h>		/* For init/exit macros */
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>	/*irq_to_desc*/
#include <linux/kernel.h>
#include <linux/kthread.h>	/* For Kthread_run */
#include <linux/math64.h>
#include <linux/module.h>	/* For MODULE_ marcros  */
#include <linux/netlink.h>	/* netlink */
#include <linux/of_fdt.h>	/*of_dt API*/
#include <linux/of.h>
#include <linux/platform_device.h>	/* platform device */
#include <linux/proc_fs.h>
#include <linux/reboot.h>	/*kernel_power_off*/
#include <linux/sched.h>	/* For wait queue*/
#include <linux/skbuff.h>	/* netlink */
#include <linux/socket.h>	/* netlink */
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>		/* For wait queue*/
#include <net/sock.h>		/* netlink */
#include <linux/suspend.h>
#include "unisoc_battery.h"
/* Licheng@BSP.CHG.basic, 2022/08/01, Add for ctrl adc gpio */
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/hardware_info.h>
#include <linux/power/charger-manager.h>


#define OPLUS_FEATURE_CHG_BASIC 1
struct sc27xx_fgu_data *gauge_data;

#ifdef OPLUS_FEATURE_CHG_BASIC
/* ZhangKun@BSP.CHG.basic, 2021/12/25, Add for charger */
#include "../oplus/v1/oplus_gauge.h"
#endif

#ifdef OPLUS_FEATURE_CHG_BASIC
#define LOWEST_TEMP_FOR_NTC_DISCONNECT 10000000
#endif

#ifdef OPLUS_FEATURE_CHG_BASIC
/* ZhangKun@BSP.CHG.basic, 2021/12/25, Add for charger */
#include <linux/iio/consumer.h>
//extern void fg_int_event(struct mtk_battery *gm, enum gauge_event evt);
extern struct iio_channel *iio_channel_get(struct device *dev,const char *channel_name);
extern void oplus_gauge_init(struct oplus_gauge_chip *chip);
extern int oplus_chg_get_voocphy_support(void);
extern int oplus_force_get_subboard_temp(void);

struct iio_channel	*batt_id = NULL;
int fuelgauge_apply = 0;
int batt_id_fast_chcek = 0;
int g_ntc_switch_not_use = 0;
static int g_switch_ntc = 0;
int is_subboard_temp_support = 0;
int enable_is_force_full;
bool last_full = false;
static int first_get_ui_soc = false;


#define BAT_LIWEI_BATT_ID  1
#define BAT_GUANYU_BATT_ID  1
#define BAT_ATL_BATT_ID  0

#define BAT_TYPE__LIWEI_4450mV_NTC_MIN 70
#define BAT_TYPE__LIWEI_4450mV_NTC_MAX 270
#define BAT_TYPE__GUANYU_4450mV_NTC_MIN 310
#define BAT_TYPE__GUANYU_4450mV_NTC_MAX 510
#define BAT_TYPE__ATL_4450mV_NTC_MIN 630
#define BAT_TYPE__ATL_4450mV_NTC_MAX 810

#define BAT_TYPE__LIWEI_4480mV_NTC_MIN 70
#define BAT_TYPE__LIWEI_4480mV_NTC_MAX 270
#define BAT_TYPE__GUANYU_4480mV_NTC_MIN 310
#define BAT_TYPE__GUANYU_4480mV_NTC_MAX 510
#define BAT_TYPE__ATL_4480mV_NTC_MIN 630
#define BAT_TYPE__ATL_4480mV_NTC_MAX 810

enum {
	BAT_TYPE__UNKNOWN,
	BAT_TYPE__SDI_4350mV, //50mV~290mV
	BAT_TYPE__SDI_4400mV, //300mV~520mV
	BAT_TYPE__LG_4350mV, //NO use
	BAT_TYPE__LG_4400mV, //530mV~780mV
	BAT_TYPE__ATL_4350mV, //1110mV~1450mV
	BAT_TYPE__ATL_4400mV, //790mV~1100mV
	BAT_TYPE__TWS_4400mV,
	BAT_TYPE__LIWEI_4450mV,
	BAT_TYPE__GUANYU_4450mV,
	BAT_TYPE__ATL_4450mV, //550mV~790mV
	BAT_TYPE__XWD_4450mV, //50mv~200mv
	BAT_TYPE__LIWEI_4480mV,
	BAT_TYPE__GUANYU_4480mV,
	BAT_TYPE__ATL_4480mV,
};

bool is_fuelgauge_apply(void)
{
	return fuelgauge_apply;
}
//EXPORT_SYMBOL(is_fuelgauge_apply);

int is_batt_id_check(void)
{
	return batt_id_fast_chcek;
}

bool prj_is_subboard_temp_support(void)
{
	return is_subboard_temp_support;
}

int bat_get_debug_level(void)
{
	return BMLOG_DEBUG_LEVEL;
}

int battery_type_check(int *battery_type)
{
	int value = 0;
	int ret = 0;
	int ret_value = 0;
	int battery_id = 0;

	if (batt_id == NULL) {
		bm_debug("[battery_type_check]: batt_id is null\n");
		*battery_type = BAT_TYPE__ATL_4400mV;
		battery_id = 0;
		return battery_id;
	}

	if (is_batt_id_check() == 1) {
		if (gpio_is_valid(g_switch_ntc)) {
			gpio_direction_output(g_switch_ntc, 1);
			gpio_set_value(g_switch_ntc, 0);
			msleep(10);
		}
		ret = iio_read_channel_processed(batt_id, &ret_value);
		if (ret < 0) {
			bm_debug( "[battery_type_check] read channel err = %d,\n", ret);
		}
		if (!g_ntc_switch_not_use)
			gpio_set_value(g_switch_ntc, 1);

		bm_debug( "[battery_type_check] g_switch_ntc = %d,ret = %d,ret_value[%d]\n", gpio_get_value(g_switch_ntc),ret, ret_value);
		value = ret_value;

		if (is_fuelgauge_apply() == true) {
			if (value >= BAT_TYPE__LIWEI_4480mV_NTC_MIN && value <= BAT_TYPE__LIWEI_4480mV_NTC_MAX) {
				*battery_type = BAT_TYPE__LIWEI_4480mV;
				battery_id = BAT_LIWEI_BATT_ID;
				get_hardware_info_data(HWID_BATERY_ID,"LIWEI_5000MA_4P48V");
			} else if (value >= BAT_TYPE__GUANYU_4480mV_NTC_MIN && value < BAT_TYPE__GUANYU_4480mV_NTC_MAX) {
				*battery_type = BAT_TYPE__GUANYU_4480mV;
				battery_id = BAT_GUANYU_BATT_ID;
				get_hardware_info_data(HWID_BATERY_ID,"GUANYU_5000MA_4P48V");
			} else if (value >= BAT_TYPE__ATL_4480mV_NTC_MIN && value < BAT_TYPE__ATL_4480mV_NTC_MAX){
				*battery_type = BAT_TYPE__ATL_4480mV;
				battery_id = BAT_ATL_BATT_ID;
				get_hardware_info_data(HWID_BATERY_ID,"ALT_5000MA_4P48V");
			} else {
				*battery_type = BAT_TYPE__UNKNOWN;
				battery_id = 0;
				get_hardware_info_data(HWID_BATERY_ID,"UNKNOWN");
			}
		} else {
			*battery_type = BAT_TYPE__UNKNOWN;
			battery_id = 0;
			get_hardware_info_data(HWID_BATERY_ID,"UNKNOWN");
		}
	} else if (is_batt_id_check() == 2) {
		ret = iio_read_channel_processed(batt_id, &ret_value);
		if (ret < 0) {
			bm_debug( "[battery_type_check] read channel err = %d,\n", ret);
		}
		bm_debug( "[battery_type_check]: ret = %d,ret_value[%d]\n", ret, ret_value);
		value = ret_value;
		bm_debug("[battery_value= %d\n", value);

		if(is_fuelgauge_apply() == true){
			if (value >= BAT_TYPE__ATL_4450mV_NTC_MIN && value < BAT_TYPE__ATL_4450mV_NTC_MAX){
				*battery_type = BAT_TYPE__ATL_4450mV;
				battery_id = BAT_ATL_BATT_ID;
				get_hardware_info_data(HWID_BATERY_ID,"ALT_5000MA_4P45V");
			} else {
				*battery_type = BAT_TYPE__UNKNOWN;
				battery_id = 0;
				get_hardware_info_data(HWID_BATERY_ID,"UNKNOWN");
			}
		} else {
			*battery_type = BAT_TYPE__UNKNOWN;
			battery_id = 0;
			get_hardware_info_data(HWID_BATERY_ID,"UNKNOWN");
		}
	} else {
		ret = iio_read_channel_processed(batt_id, &ret_value);
		if (ret < 0) {
			bm_debug( "[battery_type_check] read channel err = %d,\n", ret);
		}
		bm_debug( "[battery_type_check]: ret = %d,ret_value[%d]\n", ret, ret_value);
		value = ret_value;
		bm_debug("[battery_value= %d\n", value);

		if(is_fuelgauge_apply() == true){
			if (value >= BAT_TYPE__LIWEI_4450mV_NTC_MIN && value <= BAT_TYPE__LIWEI_4450mV_NTC_MAX) {
				*battery_type = BAT_TYPE__LIWEI_4450mV;
				battery_id = BAT_LIWEI_BATT_ID;
				get_hardware_info_data(HWID_BATERY_ID,"LIWEI_5000MA_4P45V");
			} else if (value >= BAT_TYPE__GUANYU_4450mV_NTC_MIN && value < BAT_TYPE__GUANYU_4450mV_NTC_MAX) {
				*battery_type = BAT_TYPE__GUANYU_4450mV;
				battery_id = BAT_GUANYU_BATT_ID;
				get_hardware_info_data(HWID_BATERY_ID,"GUANYU_5000MA_4P45V");
			} else if (value >= BAT_TYPE__ATL_4450mV_NTC_MIN && value < BAT_TYPE__ATL_4450mV_NTC_MAX){
				*battery_type = BAT_TYPE__ATL_4450mV;
				battery_id = BAT_ATL_BATT_ID;
				get_hardware_info_data(HWID_BATERY_ID,"ALT_5000MA_4P45V");
			} else {
				*battery_type = BAT_TYPE__UNKNOWN;
				battery_id = 0;
				get_hardware_info_data(HWID_BATERY_ID,"UNKNOWN");
			}
		} else {
			*battery_type = BAT_TYPE__UNKNOWN;
			battery_id = 0;
			get_hardware_info_data(HWID_BATERY_ID,"UNKNOWN");
		}
	}

	printk(KERN_ERR "[battery_type_check]: adc_value[%d], battery_type[%d], g_fg_battery_id[%d]\n", value, *battery_type, battery_id);

	return battery_id;
}

int fgauge_get_profile_id(void)
{
	int battery_id = 0;
	int battery_type = BAT_TYPE__UNKNOWN;

	battery_id = battery_type_check(&battery_type);

	return battery_id;
}
EXPORT_SYMBOL_GPL(fgauge_get_profile_id);

#endif

#ifdef OPLUS_FEATURE_CHG_BASIC
#define OPLUS_BATON_NTC_01 10
#endif

static int gauge_get_property(enum power_supply_property psp, int *temp)
{
	struct power_supply *fuel_gauge;
	int ret;
	int64_t temp_val;

	fuel_gauge = power_supply_get_by_name("sc27xx-fgu");
	if (!fuel_gauge)
		return -ENODEV;
	ret = power_supply_get_property(fuel_gauge, psp, (union power_supply_propval *)&temp_val);
	power_supply_put(fuel_gauge);

	if (ret == 0)
		*temp = (int)temp_val;
	return ret;
}

#ifdef OPLUS_FEATURE_CHG_BASIC
#define OPLUS_TEMP_25 250

static bool battery_type_is_4450mv(void)
{
	int battery_type = BAT_TYPE__UNKNOWN;
	int retry_flag = 0;

try_again:
	battery_type_check(&battery_type);
	if (battery_type == BAT_TYPE__ATL_4450mV || battery_type == BAT_TYPE__GUANYU_4450mV) {
		return true;
	} else {
		if (retry_flag == 0) {
			retry_flag = 1;
			goto try_again;
		}
		//if (is_meta_mode() == true) {
		//	return false;
		//} else {
			return false;
		//}
	}
}

static bool battery_type_is_4480mv(void)
{
	int battery_type = BAT_TYPE__UNKNOWN;
	int retry_flag = 0;

try_again:
	battery_type_check(&battery_type);
	if (battery_type == BAT_TYPE__ATL_4480mV || battery_type == BAT_TYPE__LIWEI_4480mV) {
		return true;
	} else {
		if (retry_flag == 0) {
			retry_flag = 1;
			goto try_again;
		}
		//if (is_meta_mode() == true) {
		//	return false;
		//} else {
			return false;
		//}
	}
}

//lizhijie@BSP.CHG.Basic, 2020/04/30, lzj add for compatabling two fuelgauge.
bool is_battery_init_done(void)
{
	return gauge_data->is_probe_done;
}

int oplus_battery_get_bat_temperature(void)
{
	if (is_battery_init_done()) {
		//return (force_get_tbat(oplus_gm, true) * 10);
		return OPLUS_TEMP_25;
	} else {
		return -1270;
	}
}

static int unisoc_get_battery_mvolts(void)
{
	int bat_volt_mv = 0;
	int ret;

	ret = gauge_get_property(POWER_SUPPLY_PROP_VOLTAGE_AVG, &bat_volt_mv);
	if (ret)
		bm_err("%s, unisoc_get_battery_mvolts failed, ret=%d\n", __func__, ret);

	bat_volt_mv = bat_volt_mv / 1000;
	return bat_volt_mv;
}

static int unisoc_get_battery_temperature(void)
{
	int bat_temperature = 0;
	int ret;

	ret = gauge_get_property(POWER_SUPPLY_PROP_TEMP, &bat_temperature);
	if (ret)
		bm_err("%s, unisoc_get_battery_temperature failed, ret=%d\n", __func__, ret);

	return bat_temperature;
}

#define TEMP_WITHOUT_BAT_ID	-400
static int unisoc_get_battery_soc(void)
{
	int fuel_cap = 0;
	union power_supply_propval val;
	struct power_supply *fuel_gauge;
	int ret;
	int fuel_cap_init = 50;

	fuel_gauge = power_supply_get_by_name("sc27xx-fgu");
	if (!fuel_gauge)
		return -ENODEV;
	if(first_get_ui_soc) {
		bm_err("%s,  first_get_ui_soc=%d\n", __func__,first_get_ui_soc);
		val.intval = CM_BOOT_CAPACITY;
		first_get_ui_soc = false;
	}

	ret = power_supply_get_property(fuel_gauge, POWER_SUPPLY_PROP_CAPACITY, &val);
	power_supply_put(fuel_gauge);

	if (ret == 0){
		fuel_cap = val.intval;

	fuel_cap = DIV_ROUND_CLOSEST(fuel_cap, 10);

	if (fuel_cap > 100)
		fuel_cap = 100;
	else if (fuel_cap < 0)
		fuel_cap = 0;
}
	if (TEMP_WITHOUT_BAT_ID == gauge_data->bat_temp) {
		fuel_cap = fuel_cap_init;
		bm_err("%s, bat_temp is low than temp threshold, return 50 percent\n", __func__);
	}

	//bm_info("%s, eddyhua, fuel_cap = %d\n", __func__, fuel_cap);

	return fuel_cap;
}

static int unisoc_get_batt_remaining_capacity_uah(void)
{
	int fuel_cap = 0;
	//int ret;

	fuel_cap = unisoc_get_battery_soc();

	bm_err("%s, eddyhua, remain cap = %d\n", __func__, gauge_data->total_mah * fuel_cap * 1000);

	return gauge_data->total_mah * fuel_cap * 10;
}

static int unisoc_get_average_current(void)
{
	int bat_curr_ma = 0;
	int ret;

	ret = gauge_get_property(POWER_SUPPLY_PROP_CURRENT_AVG, &bat_curr_ma);
	if (ret)
		bm_err("%s, unisoc_get_average_current failed, ret=%d\n", __func__, ret);

	bat_curr_ma = (-1*(bat_curr_ma / 1000));


	//bm_info("%s, eddyhua, bat_curr_ma = %d\n", __func__, bat_curr_ma);

	return bat_curr_ma;
}

static int unisoc_get_prev_battery_fcc(void)
{
	bm_info("%s, eddyhua, total_mah = %d\n", __func__, gauge_data->total_mah);
	return gauge_data->total_mah;
}

static int unisoc_get_battery_fcc(void)
{
	return gauge_data->total_mah;
}

static int unisoc_get_battery_cc(void)
{
	return -1;
}

static int unisoc_get_battery_soh(void)
{
	return -1;
}

static int unisoc_get_prev_batt_remaining_capacity_uah(void)
{
	int fuel_cap = 0;
	//int ret;

	fuel_cap = unisoc_get_battery_soc();

	return gauge_data->total_mah * fuel_cap * 1000;
}

static int unisoc_modify_dod0(void)
{
	return -1;
}

static int unisoc_update_soc_smooth_parameter(void)
{
	return -1;
}

static int adjust_fuel_cap(int cap)
{
	union power_supply_propval val;
	struct power_supply *fuel_gauge;
	int ret;

	fuel_gauge = power_supply_get_by_name("sc27xx-fgu");
	if (!fuel_gauge)
		return -ENODEV;

	val.intval = cap * 10;
	ret = power_supply_set_property(fuel_gauge,
					POWER_SUPPLY_PROP_CALIBRATE, &val);
	power_supply_put(fuel_gauge);

	return ret;
}


static void unisoc_set_battery_full(bool full)
{
	int ret = -1;
	if(full)
		ret = adjust_fuel_cap(100);
	bm_err("last full = %d, full = %d ret = %d\n", last_full, full,ret);
}

bool unisoc_get_battery_authenticate(void)
{
		int battery_id = 0;

#ifdef OPLUS_FEATURE_CHG_BASIC
		battery_id = fgauge_get_profile_id();

		if (is_batt_id_check() == 1) {
			return battery_type_is_4480mv();
		} else if (is_batt_id_check() == 2) {
			return battery_type_is_4450mv();
		} else
			return battery_type_is_4450mv();
#endif

}

#if IS_ENABLED(CONFIG_OF)
static int fg_read_dts_val(const struct device_node *np,
		const char *node_srting,
		int *param, int unit)
{
	static unsigned int val;

	if (!of_property_read_u32(np, node_srting, &val)) {
		*param = (int)val * unit;
		bm_debug("Get %s: %d\n",
			 node_srting, *param);
	} else {
		bm_debug("Get %s no data\n", node_srting);
		return -1;
	}
	return 0;
}
#endif

static struct oplus_gauge_operations oplus_battery_gauge = {
	.get_battery_mvolts 		= unisoc_get_battery_mvolts,
	.get_battery_temperature		= unisoc_get_battery_temperature,
	.get_batt_remaining_capacity	= unisoc_get_batt_remaining_capacity_uah,
	.get_battery_soc				= unisoc_get_battery_soc,
	.get_average_current			= unisoc_get_average_current,
	.get_battery_fcc				= unisoc_get_battery_fcc,
	.get_battery_cc 			= unisoc_get_battery_cc,
	.get_battery_soh				= unisoc_get_battery_soh,
	.get_battery_authenticate		= unisoc_get_battery_authenticate,
	.set_battery_full				= unisoc_set_battery_full,
	.get_prev_battery_mvolts		= unisoc_get_battery_mvolts,
	.get_prev_battery_temperature	= unisoc_get_battery_temperature,
	.get_prev_battery_soc			= unisoc_get_battery_soc,
	.get_prev_average_current		= unisoc_get_average_current,
	.get_prev_batt_remaining_capacity	= unisoc_get_prev_batt_remaining_capacity_uah,
	.get_battery_mvolts_2cell_max		= unisoc_get_battery_mvolts,
	.get_battery_mvolts_2cell_min		= unisoc_get_battery_mvolts,
	.get_prev_battery_mvolts_2cell_max	= unisoc_get_battery_mvolts,
	.get_prev_battery_mvolts_2cell_min	= unisoc_get_battery_mvolts,
	.get_prev_batt_fcc				= unisoc_get_prev_battery_fcc,
	.update_battery_dod0				= unisoc_modify_dod0,
	.update_soc_smooth_parameter		= unisoc_update_soc_smooth_parameter,
};
#endif

int battery_init(struct platform_device *pdev)
{
#ifdef OPLUS_FEATURE_CHG_BASIC
/* ZhangKun@BSP.CHG.basic, 2021/12/25, Add for charger */
	struct oplus_gauge_chip *chip = NULL;
#endif
	gauge_data = dev_get_drvdata(&pdev->dev);

#ifdef OPLUS_FEATURE_CHG_BASIC
/*lizhijie@BSP.CHG.Basic 2020/04/30 lizhijie add for distinguish fuelgague and outlay-gague*/
	fg_read_dts_val(pdev->dev.of_node, "FUELGAGUE_APPLY", &(fuelgauge_apply), 1);
	bm_err("%s, fuelgauge_apply:%d\n", __func__, fuelgauge_apply);

	fg_read_dts_val(pdev->dev.of_node, "IS_SUBBOARD_TEMP_SUPPORT", &(is_subboard_temp_support), 1);
	bm_err("%s, is_subboard_temp_support:%d\n", __func__, is_subboard_temp_support);

	fg_read_dts_val(pdev->dev.of_node, "Enable_Is_Force_Full", &(enable_is_force_full), 1);
	bm_err("%s, enable_is_force_full:%d\n", __func__, enable_is_force_full);

	fg_read_dts_val(pdev->dev.of_node, "BATT_ID_FAST_CHECK", &(batt_id_fast_chcek), 1);
	bm_err("%s, batt_id_fast_chcek:%d\n", __func__, batt_id_fast_chcek);

	fg_read_dts_val(pdev->dev.of_node, "NTC_SWITCH_NOT_USE", &(g_ntc_switch_not_use), 1);
	bm_err("%s, g_ntc_switch_not_use:%d\n", __func__, g_ntc_switch_not_use);

	g_switch_ntc = of_get_named_gpio(pdev->dev.of_node, "ntc_switch_gpio", 0);
	if (g_switch_ntc < 0) {
		bm_err("ntc_switch_gpio < 0 !!!\r\n");
		g_switch_ntc = 0;
	}

	if(gpio_request(g_switch_ntc, "NTC_SWITCH_GPIO") < 0) {
		bm_err("ntc_switch_gpio gpio_request fail\r\n");
	}

	if(is_fuelgauge_apply() == true) {
		batt_id = devm_iio_channel_get(&pdev->dev, "batt_id");
		if (IS_ERR(batt_id)){
			bm_err("battery ID CHANNEL ERR\n");
			batt_id = NULL;
		}
	}

#endif

#ifdef OPLUS_FEATURE_CHG_BASIC
/* ZhangKun@BSP.CHG.basic, 2021/12/25, Add for charger */
	if(is_fuelgauge_apply() == true) {
		chip = (struct oplus_gauge_chip*) kzalloc(sizeof(struct oplus_gauge_chip),
					GFP_KERNEL);
		if (!chip) {
			bm_err("oplus_gauge_chip devm_kzalloc failed.\n");
			return -ENOMEM;
		}
	}
	if(is_fuelgauge_apply() == true) {
		chip->gauge_ops = &oplus_battery_gauge;
		oplus_gauge_init(chip);
		chip->gauge_ops->get_battery_authenticate();
	}
#endif
	first_get_ui_soc = true;

	return 0;
}
EXPORT_SYMBOL_GPL(battery_init);

