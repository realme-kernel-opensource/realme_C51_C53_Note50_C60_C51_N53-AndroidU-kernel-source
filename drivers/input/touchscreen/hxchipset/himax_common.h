/* SPDX-License-Identifier: GPL-2.0 */
/*  Himax Android Driver Sample Code for common functions
 *
 *  Copyright (C) 2019 Himax Corporation.
 *
 *  This software is licensed under the terms of the GNU General Public
 *  License version 2,  as published by the Free Software Foundation,  and
 *  may be copied,  distributed,  and modified under those terms.
 *
 *  This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifndef HIMAX_COMMON_H
#define HIMAX_COMMON_H

#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/async.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/input/mt.h>
#include <linux/firmware.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/pm_wakeup.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include "himax_platform.h"
#include <linux/kallsyms.h>
#include <linux/version.h>

#if defined(CONFIG_OF)
	#include <linux/of_gpio.h>
#endif

#define HIMAX_DRIVER_VER "2.1.0.4_Hulk_04"

#define FLASH_DUMP_FILE "/sdcard/HX_Flash_Dump.bin"

/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_DEBUG)
#define HX_TP_PROC_2T2R
/*if enable, selftest works in driver*/
/*#define HX_TP_SELF_TEST_DRIVER*/
#endif
/*===========Himax Option function=============*/
#define HX_RST_PIN_FUNC
#define HX_EXCP_RECOVERY
#define OPPO_PROC_NODE
/*#define HX_NEW_EVENT_STACK_FORMAT*/
/*#define HX_BOOT_UPGRADE*/
#define HX_SMART_WAKEUP
#define HX_GESTURE_TRACK
#define HX_RESUME_SEND_CMD	/*Need to enable on TDDI chipset*/
/*#define HX_HIGH_SENSE*/
/*#define HX_PALM_REPORT*/
/*#define HX_USB_DETECT_GLOBAL*/
#if defined(USER_DEBUG)
#define HX_RW_FILE
#endif
/* for MTK special platform.If turning on,
 * it will report to system by using specific format.
 */
/*#define HX_PROTOCOL_A*/
#define HX_PROTOCOL_B_3PA

#define HX_ZERO_FLASH

/*system suspend-chipset power off,
 *oncell chipset need to enable the definition
 */
/*#define HX_RESUME_HW_RESET*/

/*for Himax auto-motive chipset
 */
/*#define HX_PON_PIN_SUPPORT*/

/*#define HX_PARSE_FROM_DT*/

/*Enable this if testing suspend/resume
 *on nitrogen8m
 */
/*#define HX_CONFIG_DRM_PANEL*/

/*used for self test get dsram fail in stress test*/
/*#define HX_STRESS_SELF_TEST*/

/*=============================================*/

/* Enable it if driver go into suspend/resume twice */
/*#undef HX_CONFIG_FB*/

/* Enable it if driver go into suspend/resume twice */
#undef HX_CONFIG_DRM

#if defined(HX_CONFIG_DRM_PANEL)
#undef HX_CONFIG_FB
#include <drm/drm_panel.h>
extern struct drm_panel gNotifier_dummy_panel;
#elif defined(HX_CONFIG_FB)
#include <linux/notifier.h>
#include <linux/fb.h>
#elif defined(HX_CONFIG_DRM)
#include <linux/msm_drm_notify.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0))
#define KERNEL_VER_ABOVE_4_19
#endif

#if defined(HX_ZERO_FLASH)
/*zero flash case, you need to setup the fix_touch_info of module*/
/*Please set the size according to IC*/
#define DSRAM_SIZE HX_32K_SZ
#define HX_RESUME_SET_FW
/* used for 102p overlay */
/*#define HX_ALG_OVERLAY*/
/* used for 102d overlay */
/*#define HX_CODE_OVERLAY*/
/*Independent threads run the notification chain notification function resume*/
/*#define HX_CONTAINER_SPEED_UP*/
#else
#define HX_TP_PROC_GUEST_INFO
#endif

#if defined(HX_EXCP_RECOVERY) && defined(HX_ZERO_FLASH)
/* used for 102e/p zero flash */
/*#define HW_ED_EXCP_EVENT*/
#define DD_RECOV_EXCP_TE
#define DD_VSN_RECOV_EXCP
#endif

#if defined(HX_BOOT_UPGRADE) || defined(HX_ZERO_FLASH)
/* FW Auto upgrade case, you need to setup the fix_touch_info of module
 */
extern char *g_fw_boot_upgrade_name;
extern int g_firmware_id;
extern char *g_boot_upgrade_fwname;
extern char *g_mpap_fwname;
#define BOOT_UPGRADE_FWNAME_BOE_HX03 "Himax_firmware_BOE_HX03.bin"
#define BOOT_UPGRADE_FWNAME_HKC_HX03 "Himax_firmware_HKC_HX03.bin"
#define BOOT_UPGRADE_FWNAME_HKC_HX05 "Himax_firmware_HKC_HX05.bin"
#define BOOT_UPGRADE_FWNAME_HKC_HX05K "Himax_firmware_HKC_HX05K.bin"
#if defined(HX_ZERO_FLASH)
extern uint8_t *g_update_cfg_buf;
#define MPAP_FWNAME_BOE_HX03 "Himax_mpfw_BOE_HX03.bin"
#define MPAP_FWNAME_HKC_HX03 "Himax_mpfw_HKC_HX03.bin"
#define MPAP_FWNAME_HKC_HX05 "Himax_mpfw_HKC_HX05.bin"
#define MPAP_FWNAME_HKC_HX05K "Himax_mpfw_HKC_HX05K.bin"
#if defined(OPPO_PROC_NODE)
	#define FW_UPDATE_COMPLETE_TIMEOUT  msecs_to_jiffies(40*1000)
#endif
#define HX_OPT_HW_CRC
#ifdef HX_OPT_HW_CRC
struct zf_opt_crc;
extern struct zf_opt_crc g_zf_opt_crc;
#endif
extern char *g_fw_mp_upgrade_name;
#endif
#endif

#if defined(HX_PARSE_FROM_DT)
extern uint32_t g_proj_id;
#endif

#if defined(HX_SMART_WAKEUP)
/*This feature need P-sensor driver notified, and FW need to support*/
/*#define HX_ULTRA_LOW_POWER*/
#endif

#if defined(HX_SMART_WAKEUP) && defined(HX_RESUME_SET_FW)
/* decide whether reload FW after Smart Wake Up */
#define HX_SWU_RESUME_SET_FW
#endif

#define HX_DELAY_BOOT_UPDATE	200

#if defined(HX_CONTAINER_SPEED_UP)
/*Resume queue delay work time after LCM RST (unit:ms)
 */
#define DELAY_TIME 40
#endif

#if defined(HX_RST_PIN_FUNC)
/* origin is 20/50 */
#define RST_LOW_PERIOD_S 5000
#define RST_LOW_PERIOD_E 5100
#if defined(HX_ZERO_FLASH)
#define RST_HIGH_PERIOD_S 5000
#define RST_HIGH_PERIOD_E 5100
#else
#define RST_HIGH_PERIOD_S 50000
#define RST_HIGH_PERIOD_E 50100
#endif
#endif

#if defined(HX_CONFIG_FB)
int fb_notifier_callback(struct notifier_block *self,
	unsigned long event, void *data);
#elif defined(HX_CONFIG_DRM)
int drm_notifier_callback(struct notifier_block *self,
	unsigned long event, void *data);
#endif
#define HX_MAX_WRITE_SZ    (64 * 1024 + 6)
#define HX_MAX_READ_SZ		(1024)

#define HX_85XX_H_SERIES_PWON		"HX85xxH"
#define HX_85XX_J_SERIES_PWON		"HX85xxJ"
#define HX_83102D_SERIES_PWON		"HX83102D"
#define HX_83102E_SERIES_PWON		"HX83102E"
#define HX_83102J_SERIES_PWON		"HX83102J"
#define HX_83108A_SERIES_PWON		"HX83108A"
#define HX_83108B_SERIES_PWON		"HX83108B"
#define HX_83112A_SERIES_PWON		"HX83112A"
#define HX_83112F_SERIES_PWON		"HX83112F"
#define HX_83121A_SERIES_PWON		"HX83121A"

#define HX_TP_BIN_CHECKSUM_SW		1
#define HX_TP_BIN_CHECKSUM_HW		2
#define HX_TP_BIN_CHECKSUM_CRC		3

#define SHIFTBITS 5
#define RAW_DATA_HEADER_LENGTH 6
#define FW_SIZE_32k		32768
#define FW_SIZE_60k		61440
#define FW_SIZE_64k		65536
#define FW_SIZE_124k	126976
#define FW_SIZE_128k	131072
#define FW_SIZE_255k    261120

#define NO_ERR 0
#define READY_TO_SERVE 1
#define WORK_OUT	2
#define HX_EMBEDDED_FW 3
#define I2C_FAIL -1
#define BUS_FAIL -1
#define HX_INIT_FAIL -1
#define MEM_ALLOC_FAIL -2
#define CHECKSUM_FAIL -3
#define GESTURE_DETECT_FAIL -4
#define INPUT_REGISTER_FAIL -5
#define FW_NOT_READY -6
#define LENGTH_FAIL -7
#define OPEN_FILE_FAIL -8
#define PROBE_FAIL -9
#define ERR_WORK_OUT	-10
#define ERR_STS_WRONG	-11
#define ERR_TEST_FAIL	-12
#define HW_CRC_FAIL 1

#define HX_FINGER_ON	1
#define HX_FINGER_LEAVE	2

#if defined(HX_PALM_REPORT)
#define PALM_REPORT 1
#define NOT_REPORT -1
#endif

#define STYLUS_INFO_SZ 12

extern unsigned long himax_gesture;

enum HX_TS_PATH {
	HX_REPORT_COORD = 1,
	HX_REPORT_SMWP_EVENT,
	HX_REPORT_COORD_RAWDATA,
};
#define HX_ALL0_EXCPT_TIMES 2
#define HX_ALL0_EXCPT_DD_TIMES 3
enum HX_TS_STATUS {
	HX_TS_GET_DATA_FAIL = -6,
	HX_EXCP_EVENT,
	HX_EXCP_ZERO_EVENT,
	HX_EXCP_ZERO_DD_EVENT,
	HX_CHKSUM_FAIL,
	HX_PATH_FAIL,
	HX_TS_NORMAL_END = 0,
	HX_EXCP_REC_OK,
	HX_READY_SERVE,
	HX_REPORT_DATA,
	HX_EXCP_WARNING,
	HX_IC_RUNNING,
	HX_ZERO_EVENT_COUNT,
	HX_RST_OK,
};

enum cell_type {
	CHIP_IS_ON_CELL,
	CHIP_IS_IN_CELL
};

#if defined(HX_SMART_WAKEUP)
#define HX_KEY_DOUBLE_CLICK KEY_POWER
#define HX_KEY_UP           KEY_UP
#define HX_KEY_DOWN         KEY_DOWN
#define HX_KEY_LEFT         KEY_LEFT
#define HX_KEY_RIGHT        KEY_RIGHT
#define HX_KEY_C            KEY_C
#define HX_KEY_Z            KEY_Z
#define HX_KEY_M            KEY_M
#define HX_KEY_O            KEY_O
#define HX_KEY_S            KEY_S
#define HX_KEY_V            KEY_V
#define HX_KEY_W            KEY_W
#define HX_KEY_E            KEY_E
#define HX_KEY_LC_M         263
#define HX_KEY_AT           264
#define HX_KEY_RESERVE      265
#define HX_KEY_FINGER_GEST  266
#define HX_KEY_V_DOWN       267
#define HX_KEY_V_LEFT       268
#define HX_KEY_V_RIGHT      269
#define HX_KEY_F_RIGHT      270
#define HX_KEY_F_LEFT       271
#define HX_KEY_DF_UP        272
#define HX_KEY_DF_DOWN      273
#define HX_KEY_DF_LEFT      274
#define HX_KEY_DF_RIGHT     275
#endif

enum fix_touch_info {
	FIX_HX_RX_NUM = 32,
	FIX_HX_TX_NUM = 18,
	FIX_HX_BT_NUM = 0,
	FIX_HX_MAX_PT = 10,
	FIX_HX_INT_IS_EDGE = true,
	FIX_HX_STYLUS_FUNC = 0,
	FIX_HX_STYLUS_ID_V2 = 0,
	FIX_HX_STYLUS_RATIO = 0,
#if defined(HX_TP_PROC_2T2R)
	FIX_HX_RX_NUM_2 = 0,
	FIX_HX_TX_NUM_2 = 0,
#endif
};
#define HX_RB_FRAME_SIZE 30
struct frame_data {
	uint32_t index;
	uint8_t *mutual;
	uint8_t *self;
	uint32_t cnt_update;
	// struct timeval tv;
};

struct frame_ring_buf {
	struct frame_data *rawdata;
	uint32_t frame_idx[HX_RB_FRAME_SIZE];
	atomic_t p_update;
	atomic_t p_output;
	atomic_t length;
};
#define HX_STACK_ORG_LEN 128

#define HX_FULL_STACK_RAWDATA_SIZE \
	(HX_STACK_ORG_LEN +\
	(2 + FIX_HX_RX_NUM * FIX_HX_TX_NUM + FIX_HX_TX_NUM + FIX_HX_RX_NUM)\
	* 2)


#if defined(OPPO_PROC_NODE)
struct edge_limit {
	int in_which_area;
	int limit_area;
	int left_x1;
	int right_x1;
	int left_x2;
	int right_x2;
	int left_y1;
	int right_y1;
	int left_y2;
	int right_y2;
};

struct point_info {
	int x;
	int y;
	uint8_t type;
};

struct corner_info {
	int limit_area;
	struct point_info point;
	bool flag;
	uint8_t id;
};

enum area_type {
	AREA_NORMAL,
	AREA_CORNER,
};

typedef enum {
    CORNER_TOPLEFT,      /*When Phone Face you in portrait top left corner*/
    CORNER_TOPRIGHT,     /*When Phone Face you in portrait top right corner*/
    CORNER_BOTTOMLEFT,   /*When Phone Face you in portrait bottom left corner*/
    CORNER_BOTTOMRIGHT,  /*When Phone Face you in portrait bottom right corner*/
} corner_type;

typedef enum {
    TP_SUSPEND_EARLY_EVENT,
    TP_SUSPEND_COMPLETE,
    TP_RESUME_EARLY_EVENT,
    TP_RESUME_COMPLETE,
    TP_SPEEDUP_RESUME_COMPLETE,
}suspend_resume_state;

enum{
	MSM_BOOT_MODE__NORMAL,
	MSM_BOOT_MODE__FASTBOOT,
	MSM_BOOT_MODE__RECOVERY,
	MSM_BOOT_MODE__FACTORY,
	MSM_BOOT_MODE__RF,
	MSM_BOOT_MODE__WLAN,
	MSM_BOOT_MODE__MOS,
	MSM_BOOT_MODE__CHARGE,
	MSM_BOOT_MODE__SILENCE,
	MSM_BOOT_MODE__SAU,
   
};
#endif
#if defined(HX_ZERO_FLASH)
	#define HX_SPI_OPERATION
	#define HX_0F_DEBUG
#endif
struct himax_ic_data {
	int vendor_fw_ver;
	int vendor_config_ver;
	int vendor_touch_cfg_ver;
	int vendor_display_cfg_ver;
	int vendor_cid_maj_ver;
	int vendor_cid_min_ver;
	int vendor_panel_ver;
	int vendor_sensor_id;
	int ic_adc_num;
	uint8_t vendor_cus_info[12];
	uint8_t vendor_proj_info[12];
	uint8_t vendor_ic_id[13];
	uint32_t flash_size;
	uint32_t HX_RX_NUM;
	uint32_t HX_TX_NUM;
	uint32_t HX_BT_NUM;
	uint32_t HX_X_RES;
	uint32_t HX_Y_RES;
	uint32_t HX_MAX_PT;
	uint8_t HX_INT_IS_EDGE;
	uint8_t HX_STYLUS_FUNC;
	uint8_t HX_STYLUS_ID_V2;
	uint8_t HX_STYLUS_RATIO;
#if defined(HX_TP_PROC_2T2R)
	int HX_RX_NUM_2;
	int HX_TX_NUM_2;
#endif
};

struct himax_virtual_key {
	int index;
	int keycode;
	int x_range_min;
	int x_range_max;
	int y_range_min;
	int y_range_max;
};

struct himax_target_point_data {
	int x;
	int y;
	int w;
	int id;
};

struct himax_target_stylus_data {
	int32_t x;
	int32_t y;
	int32_t w;
	uint32_t hover;
	int32_t tilt_x;
	uint32_t btn;
	uint32_t btn2;
	int32_t tilt_y;
	uint32_t on;
	int pre_btn;
	int pre_btn2;
	uint8_t battery_info;
	uint64_t id;
};

struct himax_target_report_data {

	struct himax_target_point_data *p;

	int finger_on;
	int finger_num;

#if defined(HX_SMART_WAKEUP)
	int SMWP_event_chk;
#endif

	struct himax_target_stylus_data *s;

	int ig_count;
};

struct himax_report_data {
	int touch_all_size;
	int touch_all_size_normal;
	int touch_all_size_full_stack;
	int raw_cnt_max;
	int raw_cnt_rmd;
	int touch_info_size;
	uint8_t	finger_num;
	uint8_t	finger_on;
	uint8_t *hx_coord_buf;
	uint8_t hx_state_info[2];
#if defined(HX_SMART_WAKEUP)
	int event_size;
	uint8_t *hx_event_buf;
#endif

	int rawdata_size;
	int rawdata_size_full_stack;
	int rawdata_size_normal;
	uint8_t diag_cmd;
	uint8_t *hx_rawdata_buf;
	uint8_t rawdata_frame_size;
};
#if defined(OPPO_PROC_NODE)
struct firmware_head_struct {
        const uint8_t *data;
        size_t size;
};
#endif
struct himax_ts_data {
	bool initialized;
	bool suspended;
	int notouch_frame;
	int ic_notouch_frame;
	atomic_t suspend_mode;
	uint8_t x_channel;
	uint8_t y_channel;
	uint8_t useScreenRes;
	uint8_t diag_cmd;
	uint8_t diag_storage_type;
	bool diag_dirly;
	char chip_name[30];
	uint8_t chip_cell_type;
	uint32_t chip_max_dsram_size;

	uint8_t protocol_type;
	uint8_t first_pressed;
	uint8_t coord_data_size;
	uint8_t area_data_size;
	uint8_t coordInfoSize;
	uint8_t raw_data_frame_size;
	uint8_t raw_data_nframes;
	uint8_t nFinger_support;
	uint8_t irq_enabled;
	uint8_t diag_self[50];

#if defined(OPPO_PROC_NODE)
	uint8_t backup_flag;
	uint8_t psensor_stus;
	int 	gesture_bak;
	uint8_t	Freq_hop_test_stauts;
	uint8_t	Freq_hop_delay_work_start;
	struct  workqueue_struct *himax_Freq_hop_test_wq;
	struct  delayed_work himax_Freq_hop_test_wrok;
#if defined(SPREADTRUM_NOTIFY_MODE)
	struct notifier_block drm_notifier;
#endif
	uint8_t limit_enable;
	uint8_t limit_edge;
	uint8_t limit_corner;
	struct edge_limit edge_limit;
	int firmware_update_type;    /*firmware_update_type: 0=check firmware version 1=force update; 2=for FAE debug*/
	int force_update;
	struct completion      fw_complete;                 /*completion for control fw update*/
	struct work_struct     fw_update_work;             /*using for fw update*/
	struct firmware_head_struct firmware_headfile;
	u8 *g_fw_buf;
	size_t g_fw_len;
	bool g_fw_sta;
	bool  using_headfile;
	bool is_headset_checked;                            /*state of headset or usb*/
    bool is_usb_checked;                                /*state of charger or usb*/
	struct mutex mode_chg_lock;
    int boot_mode;
	bool recovery_mode;
	int noise_level;
	int touch_direction;
	int headset_mode;
	int charge_mode;
	suspend_resume_state suspend_state;
#if defined(HX_TP_USB_NOTIFIER)
	struct notifier_block notifier_tp_usb;
#endif
#if defined(HX_UPDATE_FW_NOTIFIER)
	struct notifier_block notifier_update_fw;
	struct work_struct resume_work_queue;
#endif
#if defined(HX_TP_HEADSET_NOTIFIER)
	struct notifier_block notifier_headset;
	struct work_struct headset_work_queue;

#endif
#endif
	uint16_t finger_pressed;
	uint16_t last_slot;
	uint16_t pre_finger_mask;
	uint16_t old_finger;
	int hx_point_num;
	uint8_t hx_stylus_num;

	uint32_t debug_log_level;
	uint32_t widthFactor;
	uint32_t heightFactor;
	uint32_t tw_x_min;
	uint32_t tw_x_max;
	uint32_t tw_y_min;
	uint32_t tw_y_max;
	uint32_t pl_x_min;
	uint32_t pl_x_max;
	uint32_t pl_y_min;
	uint32_t pl_y_max;

	int rst_gpio;
	int use_irq;
	int (*power)(int on);
	int pre_finger_data[10][2];

	struct device *dev;
	struct workqueue_struct *himax_wq;
	struct work_struct work;
	struct input_dev *input_dev;

	struct input_dev *stylus_dev;

	struct hrtimer timer;
	struct i2c_client *client;
	struct himax_platform_data *pdata;
	struct mutex reg_lock;
	struct mutex rw_lock;
	struct mutex fw_update_lock;
	atomic_t irq_state;
	spinlock_t irq_lock;

/******* SPI-start *******/
	struct spi_device	*spi;
	int hx_irq;
	uint8_t *xfer_buff;
/******* SPI-end *******/

	int in_self_test;
	int self_test_finished;
	int suspend_resume_done;
	int bus_speed;

#if defined(HX_CONFIG_FB) || defined(HX_CONFIG_DRM)
	struct notifier_block fb_notif;
	struct workqueue_struct *himax_att_wq;
	struct delayed_work work_att;
#endif

	struct workqueue_struct *dump_wq;
	struct work_struct dump_work;
	struct workqueue_struct *himax_boot_upgrade_wq;
	struct delayed_work work_boot_upgrade;

#if defined(HX_CONTAINER_SPEED_UP)
	struct workqueue_struct *ts_int_workqueue;
	struct delayed_work ts_int_work;
#endif

	struct workqueue_struct *himax_diag_wq;
	struct delayed_work himax_diag_delay_work;


	uint8_t SMWP_enable;
	uint8_t gesture_cust_en[26];
	struct wakeup_source *ts_SMWP_wake_lock;
#if defined(HX_ULTRA_LOW_POWER)
	bool psensor_flag;
#endif


#if defined(HX_HIGH_SENSE)
	uint8_t HSEN_enable;
#endif

#if defined(HX_USB_DETECT_GLOBAL)
	uint8_t usb_connected;
	uint8_t *cable_config;
#endif

#if defined(HX_TP_PROC_GUEST_INFO)
	struct workqueue_struct *guest_info_wq;
	struct work_struct guest_info_work;
#endif
#if defined(DD_VSN_RECOV_EXCP)
int update_fw_fail;
int update_fw_flag;
int vsn_flag;
#endif
	uint8_t slave_write_reg;
	uint8_t slave_read_reg;
	bool acc_slave_reg;
	bool select_slave_reg;

};

struct himax_debug {
	bool flash_dump_going;
	bool is_checking_irq;
	bool is_call_help;
	bool is_stack_full_raw;
	void (*fp_ts_dbg_func)(struct himax_ts_data *ts, int start);
	int (*_raw_full_stack)(struct himax_ic_data *hx_s_ic_data,
				struct himax_report_data *hx_touch_data);
	int (*fp_set_diag_cmd)(struct himax_ic_data *ic_data,
				struct himax_report_data *hx_touch_data);
};

enum input_protocol_type {
	PROTOCOL_TYPE_A	= 0x00,
	PROTOCOL_TYPE_B	= 0x01,
};

#if defined(HX_HIGH_SENSE)
	void himax_set_HSEN_func(uint8_t HSEN_enable);
#endif

#if defined(HX_SMART_WAKEUP)
void himax_set_SMWP_func(uint8_t SMWP_enable);

#define GEST_PTLG_ID_LEN	(4)
#define GEST_PTLG_HDR_LEN	(4)
#define GEST_PTLG_HDR_ID1	(0xCC)
#define GEST_PTLG_HDR_ID2	(0x44)
#define GEST_PT_MAX_NUM		(128)

extern uint8_t *wake_event_buffer;
#endif

extern int g_mmi_refcnt;
extern int *g_inspt_crtra_flag;
extern uint32_t g_hx_chip_inited;
extern bool g_has_alg_overlay;
/*void himax_HW_reset(uint8_t loadconfig,uint8_t int_off);*/
#if defined(HX_FIRMWARE_HEADER)
#include "himax_firmware.h"
extern int32_t g_hx_panel_id;
int32_t get_fw_index(int32_t fw_type);
void mapping_panel_id_from_dt(struct device_node *dt);
extern struct firmware g_embedded_fw;
#endif

int himax_chip_common_suspend(struct himax_ts_data *ts);
int himax_chip_common_resume(struct himax_ts_data *ts);
#if defined(HX_RW_FILE)
#if defined(KERNEL_VER_ABOVE_4_19)
#else
extern struct filename* (*kp_getname_kernel)(const char *filename);
extern void (*kp_putname_kernel)(struct filename *name);
extern struct file * (*kp_file_open_name)(struct filename *name,
			int flags, umode_t mode);
#endif
#endif
struct himax_core_fp;
extern struct himax_core_fp g_core_fp;
extern struct himax_ts_data *private_ts;
extern struct himax_ic_data *ic_data;
extern struct device *g_device;

/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_DEBUG)
	int himax_debug_init(void);
	int himax_debug_remove(void);
#endif

/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_INSPECT)
	extern char *g_rslt_data;
	extern uint32_t g_rslt_data_len;
	extern void (*fp_himax_self_test_init)(void);
#endif

#if defined(HX_CONFIG_DRM)
#if defined(HX_CONFIG_DRM_PANEL)
	extern struct drm_panel *active_panel;
#endif
#endif
extern int HX_TOUCH_INFO_POINT_CNT;

extern bool ic_boot_done;

int himax_parse_dt(struct himax_ts_data *ts, struct himax_platform_data *pdata);

extern void himax_parse_dt_ic_info(struct himax_ts_data *ts,
	struct himax_platform_data *pdata);

int himax_report_data(struct himax_ts_data *ts, int ts_path, int ts_status);

int himax_report_data_init(void);

int himax_dev_set(struct himax_ts_data *ts);
int himax_input_register_device(struct input_dev *input_dev);
#if defined(HX_RW_FILE)
extern int hx_open_file(char *file_name);
extern int hx_write_file(char *write_data, uint32_t write_size, loff_t pos);
extern int hx_close_file(void);
#endif

#if defined(OPPO_PROC_NODE)
extern void himax_headset_mode_switch(int headset_sate);
extern void himax_usb_mode_switch(int val);
#endif

#if defined(DD_VSN_RECOV_EXCP)
//extern int himax_vsn_reset_device(void)
// extern int himax_mcu_vsn_recovery(void);
#endif
#endif
