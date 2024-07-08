#ifndef __UNISOC_FUEL_GAUGE_INTF_H__
#define __UNISOC_FUEL_GAUGE_INTF_H__
#include <linux/power/sprd_battery_info.h>
/* PMIC global control registers definition */
#define SC27XX_MODULE_EN0		0xc08
#define SC27XX_CLK_EN0			0xc18
#define SC2730_MODULE_EN0		0x1808
#define SC2730_CLK_EN0			0x1810
#define UMP9620_MODULE_EN0		0x2008
#define UMP9620_CLK_EN0			0x2010
#define SC2720_MODULE_EN0		0xc08
#define SC2720_CLK_EN0			0xc10
#define SC27XX_FGU_EN			BIT(7)
#define SC27XX_FGU_RTC_EN		BIT(6)

/* FGU registers definition */
#define SC27XX_FGU_START		0x0
#define SC27XX_FGU_CONFIG		0x4
#define SC27XX_FGU_ADC_CONFIG		0x8
#define SC27XX_FGU_STATUS		0xc
#define SC27XX_FGU_INT_EN		0x10
#define SC27XX_FGU_INT_CLR		0x14
#define SC27XX_FGU_INT_STS		0x1c
#define SC27XX_FGU_VOLTAGE		0x20
#define SC27XX_FGU_OCV			0x24
#define SC27XX_FGU_POCV			0x28
#define SC27XX_FGU_CURRENT		0x2c
#define SC27XX_FGU_HIGH_OVERLOAD	0x30
#define SC27XX_FGU_LOW_OVERLOAD		0x34
#define SC27XX_FGU_CLBCNT_SETH		0x50
#define SC27XX_FGU_CLBCNT_SETL		0x54
#define SC27XX_FGU_CLBCNT_DELTH		0x58
#define SC27XX_FGU_CLBCNT_DELTL		0x5c
#define SC27XX_FGU_CLBCNT_VALH		0x68
#define SC27XX_FGU_CLBCNT_VALL		0x6c
#define SC27XX_FGU_CLBCNT_QMAXL		0x74
#define SC27XX_FGU_RELAX_CURT_THRE	0x80
#define SC27XX_FGU_RELAX_CNT_THRE	0x84
#define SC27XX_FGU_USER_AREA_SET	0xa0
#define SC27XX_FGU_USER_AREA_CLEAR	0xa4
#define SC27XX_FGU_USER_AREA_STATUS	0xa8
#define SC27XX_FGU_USER_AREA_SET1	0xc0
#define SC27XX_FGU_USER_AREA_CLEAR1	0xc4
#define SC27XX_FGU_USER_AREA_STATUS1	0xc8
#define SC27XX_FGU_VOLTAGE_BUF		0xd0
#define SC27XX_FGU_CURRENT_BUF		0xf0
#define SC27XX_FGU_REG_MAX		0x260

/* SC27XX_FGU_CONFIG */
#define SC27XX_FGU_LOW_POWER_MODE	BIT(1)
#define SC27XX_FGU_RELAX_CNT_MODE	0
#define SC27XX_FGU_DEEP_SLEEP_MODE	1

#define SC27XX_WRITE_SELCLB_EN		BIT(0)
#define SC27XX_FGU_CLBCNT_MASK		GENMASK(15, 0)
#define SC27XX_FGU_CLBCNT_SHIFT		16
#define SC27XX_FGU_HIGH_OVERLOAD_MASK	GENMASK(12, 0)
#define SC27XX_FGU_LOW_OVERLOAD_MASK	GENMASK(12, 0)

#define SC27XX_FGU_INT_MASK		GENMASK(9, 0)
#define SC27XX_FGU_LOW_OVERLOAD_INT	BIT(0)
#define SC27XX_FGU_HIGH_OVERLOAD_INT	BIT(1)
#define SC27XX_FGU_CLBCNT_DELTA_INT	BIT(2)
#define SC27XX_FGU_RELAX_CNT_INT	BIT(3)
#define SC27XX_FGU_RELAX_CNT_STS	BIT(3)
#define SC27XX_FGU_STATUS_INVALID_POCV  BIT(7)

#define SC27XX_FGU_MODE_AREA_MASK	GENMASK(15, 12)
#define SC27XX_FGU_CAP_AREA_MASK	GENMASK(11, 0)
#define SC27XX_FGU_MODE_AREA_SHIFT	12
#define SC27XX_FGU_CAP_INTEGER_MASK	GENMASK(7, 0)
#define SC27XX_FGU_CAP_DECIMAL_MASK	GENMASK(3, 0)
#define SC27XX_FGU_CAP_DECIMAL_SHIFT	8

#define SC27XX_FGU_FIRST_POWERON	GENMASK(3, 0)
#define SC27XX_FGU_DEFAULT_CAP		GENMASK(11, 0)
#define SC27XX_FGU_NORMAL_POWERON	0x5
#define SC27XX_FGU_RTC2_RESET_VALUE	0xA05

#define SC27XX_FGU_CUR_BASIC_ADC	8192
#define SC27XX_FGU_POCV_VOLT_THRESHOLD	3400
#define SC27XX_FGU_SAMPLE_HZ		2
#define SC27XX_FGU_TEMP_BUFF_CNT	10
#define SC27XX_FGU_LOW_TEMP_REGION	100

/* micro Ohms */
#define SC27XX_FGU_IDEAL_RESISTANCE	20000
#define SC27XX_FGU_LOW_VBAT_REGION	3400
#define SC27XX_FGU_LOW_VBAT_REC_REGION	3450
#define SC27XX_FGU_LOW_VBAT_UUSOC_STEP	7
#define SC27XX_FGU_RELAX_CNT_THRESHOLD	320
#define SC27XX_FGU_RELAX_CUR_THRESHOLD_MA	30
#define SC27XX_FGU_SLP_CAP_CALIB_SLP_TIME	300
#define SC27XX_FGU_CAP_CALIB_TEMP_LOW	100
#define SC27XX_FGU_CAP_CALIB_TEMP_HI	450
#define SC27XX_FGU_CAP_CALIB_ALARM_CAP	30

/* Efuse fgu calibration bit definition */
#define SC2720_FGU_CAL			GENMASK(8, 0)
#define SC2720_FGU_CAL_SHIFT		0
#define SC2730_FGU_CAL			GENMASK(8, 0)
#define SC2730_FGU_CAL_SHIFT		0
#define SC2731_FGU_CAL			GENMASK(8, 0)
#define SC2731_FGU_CAL_SHIFT		0
#define UMP9620_FGU_CAL			GENMASK(15, 7)
#define UMP9620_FGU_CAL_SHIFT		7

/* SC27XX_FGU_RELAX_CURT_THRE */
#define SC27XX_FGU_RELAX_CURT_THRE_MASK		GENMASK(13, 0)
#define SC27XX_FGU_RELAX_CURT_THRE_SHITF	0
/* SC27XX_FGU_RELAX_CNT_THRE */
#define SC27XX_FGU_RELAX_CNT_THRE_MASK		GENMASK(12, 0)
#define SC27XX_FGU_RELAX_CNT_THRE_SHITF		0

#define SC27XX_FGU_CURRENT_BUFF_CNT	8
#define SC27XX_FGU_DISCHG_CNT		4
#define SC27XX_FGU_VOLTAGE_BUFF_CNT	8
#define SC27XX_FGU_MAGIC_NUMBER		0x5a5aa5a5
#define SC27XX_FGU_DEBUG_EN_CMD		0x5a5aa5a5
#define SC27XX_FGU_DEBUG_DIS_CMD	0x5a5a5a5a
#define SC27XX_FGU_GOOD_HEALTH_CMD	0x7f7f7f7f
#define SC27XX_FGU_FCC_PERCENT		1000

#define SC27XX_FGU_TRACK_CAP_START_VOLTAGE		3650
#define SC27XX_FGU_TRACK_CAP_START_CURRENT		50
#define SC27XX_FGU_TRACK_HIGH_TEMP_THRESHOLD		450
#define SC27XX_FGU_TRACK_LOW_TEMP_THRESHOLD		150
#define SC27XX_FGU_TRACK_TIMEOUT_THRESHOLD		108000
#define SC27XX_FGU_TRACK_NEW_OCV_VALID_THRESHOLD	(SC27XX_FGU_TRACK_TIMEOUT_THRESHOLD / 60)
#define SC27XX_FGU_TRACK_START_CAP_HTHRESHOLD		200
#define SC27XX_FGU_TRACK_START_CAP_LTHRESHOLD		10
#define SC27XX_FGU_TRACK_START_CAP_SWOCV_HTHRESHOLD	100
#define SC27XX_FGU_TRACK_WAKE_UP_MS			16000
#define SC27XX_FGU_TRACK_UPDATING_WAKE_UP_MS		200
#define SC27XX_FGU_TRACK_DONE_WAKE_UP_MS		6000
#define SC27XX_FGU_TRACK_OCV_VALID_TIME			15

#define SC27XX_FGU_RESIST_ALG_REIST_CNT		40
#define SC27XX_FGU_RESIST_ALG_OCV_GAP_UV	20000
#define SC27XX_FGU_RESIST_ALG_OCV_CNT		10
#define SC27XX_FGU_RBAT_CMP_MOH			10

#define SC27XX_FGU_CAPACITY_TRACK_0S		0
#define SC27XX_FGU_CAPACITY_TRACK_3S		3
#define SC27XX_FGU_CAPACITY_TRACK_15S		15
#define SC27XX_FGU_CAPACITY_TRACK_100S		100
#define SC27XX_FGU_WORK_MS			msecs_to_jiffies(15000)

/* RTC OF 2021-08-06 15 : 44*/
#define SC27XX_FGU_MISCDATA_RTC_TIME		(1621355101)
#define SC27XX_FGU_SHUTDOWN_TIME		(15 * 60)

#define SC27XX_FGU_CAP_CALC_WORK_15S			15

struct power_supply_vol_temp_table {
	int vol;	/* microVolts */
	int temp;	/* celsius */
};

struct power_supply_capacity_temp_table {
	int temp;	/* celsius */
	int cap;	/* capacity percentage */
};

enum sc27xx_fgu_track_state {
	CAP_TRACK_INIT,
	CAP_TRACK_IDLE,
	CAP_TRACK_UPDATING,
	CAP_TRACK_DONE,
	CAP_TRACK_ERR,
};

enum sc27xx_fgu_track_mode {
	CAP_TRACK_MODE_UNKNOWN,
	CAP_TRACK_MODE_SW_OCV,
	CAP_TRACK_MODE_POCV,
	CAP_TRACK_MODE_LP_OCV,
};

struct sc27xx_fgu_ocv_info {
	s64 ocv_rtc_time;
	int ocv_uv;
	bool valid;
};

struct sc27xx_fgu_track_capacity {
	enum sc27xx_fgu_track_state state;
	bool clear_cap_flag;
	int start_clbcnt;
	int start_cap;
	int end_vol;
	int end_cur;
	s64 start_time;
	bool cap_tracking;
	int learned_mah;
	struct sc27xx_fgu_ocv_info lpocv_info;
	struct sc27xx_fgu_ocv_info pocv_info;
	density_ocv_table *dens_ocv_table;
	int dens_ocv_table_len;
	enum sc27xx_fgu_track_mode mode;
};

struct sc27xx_fgu_debug_info {
	bool temp_debug_en;
	bool vbat_now_debug_en;
	bool ocv_debug_en;
	bool cur_now_debug_en;
	bool batt_present_debug_en;
	bool chg_vol_debug_en;
	bool batt_health_debug_en;

	int debug_temp;
	int debug_vbat_now;
	int debug_ocv;
	int debug_cur_now;
	bool debug_batt_present;
	int debug_chg_vol;
	int debug_batt_health;

	int sel_reg_id;
};

struct sc27xx_fgu_sysfs {
	char *name;
	struct attribute_group attr_g;
	struct device_attribute attr_sc27xx_fgu_dump_info;
	struct device_attribute attr_sc27xx_fgu_sel_reg_id;
	struct device_attribute attr_sc27xx_fgu_reg_val;
	struct device_attribute attr_sc27xx_fgu_enable_sleep_calib;
	struct device_attribute attr_sc27xx_fgu_relax_cnt_th;
	struct device_attribute attr_sc27xx_fgu_relax_cur_th;
	struct attribute *attrs[7];

	struct sc27xx_fgu_data *data;
};

struct sc27xx_fgu_sleep_capacity_calibration {
	bool support_slp_calib;
	int suspend_ocv_uv;
	int resume_ocv_uv;
	int suspend_clbcnt;
	int resume_clbcnt;
	s64 suspend_time;
	s64 resume_time;
	int resume_ocv_cap;

	int relax_cnt_threshold;
	int relax_cur_threshold;

	bool relax_cnt_int_ocurred;
};

/*
 * struct sc27xx_fgu_data: describe the FGU device
 * @regmap: regmap for register access
 * @dev: platform device
 * @battery: battery power supply
 * @base: the base offset for the controller
 * @lock: protect the structure
 * @gpiod: GPIO for battery detection
 * @channel: IIO channel to get battery temperature
 * @charge_chan: IIO channel to get charge voltage
 * @internal_resist: the battery internal resistance in mOhm
 * @total_mah: the total capacity of the battery in mAh
 * @init_cap: the initial capacity of the battery in mAh
 * @alarm_cap: the alarm capacity
 * @normal_temp_cap: the normal temperature capacity
 * @init_clbcnt: the initial coulomb counter
 * @max_volt_uv: the maximum constant input voltage in millivolt
 * @min_volt_uv: the minimum drained battery voltage in microvolt
 * @boot_volt_uv: the voltage measured during boot in microvolt
 * @table_len: the capacity table length
 * @temp_table_len: temp_table length
 * @cap_table_len：the capacity temperature table length
 * @resist_table_len: the resistance table length
 * @cur_1000ma_adc: ADC value corresponding to 1000 mA
 * @vol_1000mv_adc: ADC value corresponding to 1000 mV
 * @calib_resist: the real resistance of coulomb counter chip in uOhm
 * @comp_resistance: the coulomb counter internal and the board ground resistance
 * @index: record temp_buff array index
 * @temp_buff: record the battery temperature for each measurement
 * @bat_temp: the battery temperature
 * @cap_table: capacity table with corresponding ocv
 * @temp_table: the NTC voltage table with corresponding battery temperature
 * @cap_temp_table: the capacity table with corresponding temperature
 * @resist_table: resistance percent table with corresponding temperature
 */
struct sc27xx_fgu_data {
	struct regmap *regmap;
	struct device *dev;
	struct power_supply *battery;
	u32 base;
	struct mutex lock;
	struct gpio_desc *gpiod;
	struct iio_channel *channel;
	struct iio_channel *charge_chan;
	bool bat_present;
	int bat_soc;
	int internal_resist;
	int total_mah;
	int design_mah;
	int init_cap;
	int alarm_cap;
	int boot_cap;
	int normal_temp_cap;
	int init_clbcnt;
	int uusoc_mah;
	int init_mah;
	int cc_mah;
	int max_volt_uv;
	int min_volt_uv;
	int boot_volt_uv;
	int table_len;
	int temp_table_len;
	int cap_table_len;
	int resist_table_len;
	int cap_calib_dens_ocv_table_len;
	int cur_1000ma_adc;
	int vol_1000mv_adc;
	int calib_resist;
	int first_calib_volt;
	int first_calib_cap;
	int uusoc_vbat;
	unsigned int comp_resistance;
	int batt_ovp_threshold;
	int index;
	int ocv_uv;
	int batt_mv;
	int temp_buff[SC27XX_FGU_TEMP_BUFF_CNT];
	int cur_now_buff[SC27XX_FGU_CURRENT_BUFF_CNT];
	bool dischg_trend[SC27XX_FGU_DISCHG_CNT];
	int last_clbcnt;
	int cur_clbcnt;
	int bat_temp;
	bool online;
	bool is_first_poweron;
	bool is_ovp;
	bool invalid_pocv;
	u32 chg_type;
	struct sc27xx_fgu_track_capacity track;
	struct power_supply_battery_ocv_table *cap_table;
	struct power_supply_vol_temp_table *temp_table;
	struct power_supply_capacity_temp_table *cap_temp_table;
	struct power_supply_resistance_temp_table *resist_table;
	struct usb_phy *usb_phy;
	struct notifier_block usb_notify;
	int chg_sts;
	const struct sc27xx_fgu_variant_data *pdata;
	struct sc27xx_fgu_debug_info debug_info;
	struct sc27xx_fgu_sleep_capacity_calibration slp_cap_calib;
	density_ocv_table *cap_calib_dens_ocv_table;

	struct sc27xx_fgu_sysfs *sysfs;
	struct delayed_work fgu_work;
	struct delayed_work cap_track_work;
	struct delayed_work cap_calculate_work;

	/* multi resistance */
	int *target_rbat_table;
	int **rbat_table;
	int rabat_table_len;
	int *rbat_temp_table;
	int rbat_temp_table_len;
	int *rbat_ocv_table;
	int rbat_ocv_table_len;
	bool support_multi_resistance;
	bool support_debug_log;

	/* boot capacity calibration */
	bool support_boot_calib;
	s64 shutdown_rtc_time;

	/* charge cycle */
	int charge_cycle;
	bool support_charge_cycle;

	/* basp */
	bool support_basp;
	int basp_volt_uv;
	struct sprd_battery_ocv_table **basp_ocv_table;
	int basp_ocv_table_len;
	int *basp_full_design_table;
	int basp_full_design_table_len;
	int *basp_voltage_max_table;
	int basp_voltage_max_table_len;
	bool is_probe_done;
};

#endif
