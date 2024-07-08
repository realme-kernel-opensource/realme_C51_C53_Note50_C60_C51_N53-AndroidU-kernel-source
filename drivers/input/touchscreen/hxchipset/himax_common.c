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

/*#include "himax_common.h"*/
/*#include "himax_ic_core.h"*/
#include "himax_inspection.h"
#include "himax_modular.h"

#if defined(__HIMAX_MOD__)
int (*hx_msm_drm_register_client)(struct notifier_block *nb);
int (*hx_msm_drm_unregister_client)(struct notifier_block *nb);
#endif

#if defined(OPPO_PROC_NODE)
static void tp_fw_update_work(struct work_struct *work);
/* screen HKC_HX03 & BOE_HX03 */
extern int g_firmware_id;
static const uint8_t fw_i_arr_HKC_HX03[]= {
	#include "HULK_LCE_HKC_HX03.i"
};
static const uint8_t fw_i_arr_BOE_HX03[]= {
	#include "HULK_LCE_BOE_HX03.i"
};
static const uint8_t fw_i_arr_HKC_HX05[]= {
	#include "HULK_LCE_HKC_HX05.i"
};
static const uint8_t fw_i_arr_HKC_HX05K[]= {
	#include "HULK_LCE_HKC_HX05K.i"
};

uint32_t g_oppo_debug_level = 3;
int use_i_file_flag = 0;
/* add for esd recovery */
#if defined(DD_VSN_RECOV_EXCP)
int himax_mcu_vsn_recovery_flag = 0;
EXPORT_SYMBOL(himax_mcu_vsn_recovery_flag);
#endif

/*for get bootmode*/
static int reboot_mode = 0;
// static int __init get_boot_mode(char *str)
// {
//     if (!str)
//     	return 0;

//     if (!strncmp(str, "factorytest", strlen("factorytest")))
//         reboot_mode = 1;

//     return 0;
// }
// __setup("androidboot.mode=", get_boot_mode);

#endif


#if defined(HX_SMART_WAKEUP)
#define GEST_SUP_NUM 26
/* Setting cust key define (DF = double finger) */
/* {Double Tap, Up, Down, Left, Right, C, Z, M,
 *	O, S, V, W, e, m, @, (reserve),
 *	Finger gesture, ^, >, <, f(R), f(L), Up(DF), Down(DF),
 *	Left(DF), Right(DF)}
 */
uint8_t gest_event[GEST_SUP_NUM] = {
	0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x81, 0x1D, 0x2D, 0x3D, 0x1F, 0x2F, 0x51, 0x52,
	0x53, 0x54};

/*gest_event mapping to gest_key_def*/
uint16_t gest_key_def[GEST_SUP_NUM] = {
	HX_KEY_DOUBLE_CLICK, HX_KEY_UP, HX_KEY_DOWN, HX_KEY_LEFT,
	HX_KEY_RIGHT,	HX_KEY_C, HX_KEY_Z, HX_KEY_M,
	HX_KEY_O, HX_KEY_S, HX_KEY_V, HX_KEY_W,
	HX_KEY_E, HX_KEY_LC_M, HX_KEY_AT, HX_KEY_RESERVE,
	HX_KEY_FINGER_GEST,	HX_KEY_V_DOWN, HX_KEY_V_LEFT, HX_KEY_V_RIGHT,
	HX_KEY_F_RIGHT,	HX_KEY_F_LEFT, HX_KEY_DF_UP, HX_KEY_DF_DOWN,
	HX_KEY_DF_LEFT,	HX_KEY_DF_RIGHT};

uint8_t *wake_event_buffer;
#endif

struct frame_ring_buf g_rb_frame;
#define SUPPORT_FINGER_DATA_CHECKSUM 0x0F
#define TS_WAKE_LOCK_TIMEOUT		(5000)
#define FRAME_COUNT 5

#if defined(HX_TP_PROC_GUEST_INFO)
struct hx_guest_info *g_guest_info_data;
EXPORT_SYMBOL(g_guest_info_data);

char *g_guest_info_item[] = {
	"projectID",
	"CGColor",
	"BarCode",
	"Reserve1",
	"Reserve2",
	"Reserve3",
	"Reserve4",
	"Reserve5",
	"VCOM",
	"Vcom-3Gar",
	NULL
};
#endif

uint32_t g_hx_chip_inited;


unsigned long himax_gesture;
#if defined(HX_FIRMWARE_HEADER)
struct firmware g_embedded_fw;
#endif

#if defined(HX_BOOT_UPGRADE) || defined(HX_ZERO_FLASH)
bool g_boot_upgrade_flag;
const struct firmware *hxfw;
int g_i_FW_VER;
int g_i_CFG_VER;
int g_i_CID_MAJ; /*GUEST ID*/
int g_i_CID_MIN; /*VER for GUEST*/
#if defined(HX_ZERO_FLASH)
int g_f_0f_updat;
uint8_t *g_update_cfg_buf;
EXPORT_SYMBOL(g_update_cfg_buf);
#endif
char *g_boot_upgrade_fwname;
EXPORT_SYMBOL(g_boot_upgrade_fwname);
char *g_mpap_fwname;
EXPORT_SYMBOL(g_mpap_fwname);
#ifdef HX_PARSE_FROM_DT
char *g_fw_boot_upgrade_name;
EXPORT_SYMBOL(g_fw_boot_upgrade_name);
#if defined(HX_ZERO_FLASH)
char *g_fw_mp_upgrade_name;
EXPORT_SYMBOL(g_fw_mp_upgrade_name);
#endif
#else
char *g_fw_boot_upgrade_name = BOOT_UPGRADE_FWNAME_BOE_HX03;
EXPORT_SYMBOL(g_fw_boot_upgrade_name);
#if defined(HX_ZERO_FLASH)
char *g_fw_mp_upgrade_name = MPAP_FWNAME_BOE_HX03;
EXPORT_SYMBOL(g_fw_mp_upgrade_name);
#endif
#endif
#endif

#ifdef HX_PARSE_FROM_DT
uint32_t g_proj_id = 0xffff;
EXPORT_SYMBOL(g_proj_id);
#endif
#if defined(OPPO_PROC_NODE)
	#define HIMAX_PROC_TOUCHPANEL_FOLDER "touchpanel"
	struct proc_dir_entry *himax_proc_touchpanel_dir;
	#define HIMAX_PROC_OPPO_REG_INFO_FILE	"oppo_register_info"
	struct proc_dir_entry *himax_proc_oppo_reg_info_file = NULL;
	#define HIMAX_PROC_TP_FW_UPDATE_FILE	"tp_fw_update"
	struct proc_dir_entry *himax_proc_tp_fw_update_file = NULL;

#ifdef HX_SMART_WAKEUP
	#define HIMAX_PROC_DOUBLE_TAP_EN_FILE	"double_tap_enable"
	struct proc_dir_entry *himax_proc_double_tap_en_file = NULL;
#ifdef HX_GESTURE_TRACK
	#define HIMAX_PROC_COORDINATE_FILE	"coordinate"
	struct proc_dir_entry *himax_proc_coordinate_file = NULL;	
#endif
#endif
	#define HIMAX_PROC_LIMIT_ENABLE_FILE	"oppo_tp_limit_enable"
	struct proc_dir_entry *himax_proc_limit_enable_file;
	#define HIMAX_PROC_LIMIT_AREA_FILE	"oppo_tp_limit_area"
	struct proc_dir_entry *himax_proc_limit_area_file;
	#define PAGESIZE 256
	#define HIMAX_PROC_GAME_SWITCH_FILE	"game_switch_enable"
	struct proc_dir_entry *himax_proc_game_switch_en_file;

	#define HIMAX_PROC_OPPO_TP_DIRECTION_FILE	"oppo_tp_direction"
	struct proc_dir_entry *himax_proc_oppo_tp_direction_file = NULL;

	#define HIMAX_PROC_OPPO_TP_USB_MODE_FILE	"oppo_usb_mode"
	struct proc_dir_entry *himax_proc_oppo_tp_usb_mode_file = NULL;

	#define HIMAX_PROC_OPPO_TP_HEADSET_MODE_FILE	"oppo_headset_mode"
	struct proc_dir_entry *himax_proc_oppo_tp_headset_mode_file = NULL;

	#define HIMAX_PROC_INCELL_PANEL_FILE	"incell_panel"
	struct proc_dir_entry *himax_proc_incell_panel_file = NULL;

	#define HIMAX_PROC_OPPO_TX_HOP_FILE	  "oppo_tp_hop_test"
	struct proc_dir_entry *himax_proc_oppo_tx_hop_file = NULL;

	#define HIMAX_PROC_BASELINE_TEST_FILE	"baseline_test"
	struct proc_dir_entry *himax_proc_baseline_test_file;

	#define HIMAX_PROC_BACKSCREEN_BASELINE_FILE	"black_screen_test"
	struct proc_dir_entry *himax_proc_backscreen_baseline_file;

	#define HIMAX_PROC_IRQ_DEPTH_FILE	"irq_depth"
	struct proc_dir_entry *himax_proc_irq_depth_file = NULL;

	#define HIMAX_PROC_OPPO_DEBUG_LEVEL_FILE	"debug_level"
	struct proc_dir_entry *himax_proc_oppo_debug_level_file = NULL;

	//proc/touchpanel/debug_infor node begin
	struct proc_dir_entry *himax_proc_debug_infor_dir = NULL;
	#define HIMAX_PROC_DEBUG_INFO_FOLDER	"debug_info"

	#define HIMAX_PROC_DELTA_O_FILE	"delta"
	struct proc_dir_entry *himax_proc_delta_o_file = NULL;
	#define HIMAX_PROC_BASELINE_O_FILE	"baseline"
	struct proc_dir_entry *himax_proc_baseline_O_file = NULL;
	#define HIMAX_PROC_MAIN_REG_FILE	"main_register"
	struct proc_dir_entry *himax_proc_main_reg_file = NULL;
	#define HIMAX_PROC_DATA_LIMIT_FILE	"data_limit"
	struct proc_dir_entry *himax_proc_data_limit_file = NULL;
	//proc/touchpanel/debug_infor node end
	extern uint8_t cmd_set[8];
	extern uint8_t cfg_flag;
	extern uint8_t byte_length;
	extern uint8_t reg_cmd[4];
	extern int oppo_baseline_read( struct seq_file *s );
	extern int oppo_delta_read_sub( struct seq_file *s );
	extern int himax_self_test_data_init(void);
	extern void himax_self_test_data_deinit(void);
	extern int **g_inspection_criteria;
	extern char *g_hx_inspt_crtra_name[];
	extern int HX_CRITERIA_SIZE;
	#if defined(HX_SMART_WAKEUP)
	extern int himax_black_chip_self_test(struct seq_file *s, void *v);
	extern int tp_gesture;
	#endif
	extern struct fw_operation *pfw_op;
	struct corner_info corner_info[4];
	struct point_info points_info[10];
#ifdef HX_TP_HEADSET_NOTIFIER
	static bool himax_tp_headset_state = 0;
#endif
/* zhanxun don`t use this */
	//extern int get_boot_mode(void);
#endif
struct himax_ts_data *private_ts;
EXPORT_SYMBOL(private_ts);

struct himax_ic_data *ic_data;
EXPORT_SYMBOL(ic_data);

struct himax_report_data *hx_touch_data;
EXPORT_SYMBOL(hx_touch_data);

struct himax_core_fp g_core_fp;
EXPORT_SYMBOL(g_core_fp);

struct himax_debug *debug_data;
EXPORT_SYMBOL(debug_data);

struct proc_dir_entry *himax_touch_proc_dir;
EXPORT_SYMBOL(himax_touch_proc_dir);

int g_mmi_refcnt;
EXPORT_SYMBOL(g_mmi_refcnt);

#if defined(HX_ZERO_FLASH) && defined(HX_OPT_HW_CRC)
struct zf_opt_crc g_zf_opt_crc;
EXPORT_SYMBOL(g_zf_opt_crc);
#endif

#if defined(HX_FIRMWARE_HEADER)
int32_t g_hx_panel_id;
#endif
#if defined(OPPO_PROC_NODE)
#define HIMAX_PROC_TOUCH_FOLDER "himax"
#else
#define HIMAX_PROC_TOUCH_FOLDER "android_touch"
#endif
/*ts_work about start*/
struct himax_target_report_data *g_target_report_data;
EXPORT_SYMBOL(g_target_report_data);

static void himax_report_all_leave_event(struct himax_ts_data *ts);
/*ts_work about end*/
#if defined(HX_RW_FILE)
mm_segment_t g_fs;
struct file *g_fn;
loff_t g_pos;
#if defined(KERNEL_VER_ABOVE_4_19)
#else
struct filename* (*kp_getname_kernel)(const char *filename);
void (*kp_putname_kernel)(struct filename *name);
struct file* (*kp_file_open_name)(struct filename *name,
		int flags, umode_t mode);
#endif
#endif
unsigned long FW_VER_MAJ_FLASH_ADDR;
EXPORT_SYMBOL(FW_VER_MAJ_FLASH_ADDR);

unsigned long FW_VER_MIN_FLASH_ADDR;
EXPORT_SYMBOL(FW_VER_MIN_FLASH_ADDR);

unsigned long CFG_VER_MAJ_FLASH_ADDR;
EXPORT_SYMBOL(CFG_VER_MAJ_FLASH_ADDR);

unsigned long CFG_VER_MIN_FLASH_ADDR;
EXPORT_SYMBOL(CFG_VER_MIN_FLASH_ADDR);

unsigned long CID_VER_MAJ_FLASH_ADDR;
EXPORT_SYMBOL(CID_VER_MAJ_FLASH_ADDR);

unsigned long CID_VER_MIN_FLASH_ADDR;
EXPORT_SYMBOL(CID_VER_MIN_FLASH_ADDR);
/*unsigned long	PANEL_VERSION_ADDR;*/
uint32_t CFG_TABLE_FLASH_ADDR;
EXPORT_SYMBOL(CFG_TABLE_FLASH_ADDR);

uint32_t CFG_TABLE_FLASH_ADDR_T;
EXPORT_SYMBOL(CFG_TABLE_FLASH_ADDR_T);

unsigned char IC_CHECKSUM;
EXPORT_SYMBOL(IC_CHECKSUM);

#if defined(HX_EXCP_RECOVERY)
u8 HX_EXCP_RESET_ACTIVATE;
EXPORT_SYMBOL(HX_EXCP_RESET_ACTIVATE);
u8 HX_EXCP_DD_RESET_ACTIVATE;
EXPORT_SYMBOL(HX_EXCP_DD_RESET_ACTIVATE);

int hx_EB_event_flag;
EXPORT_SYMBOL(hx_EB_event_flag);

int hx_EC_event_flag;
EXPORT_SYMBOL(hx_EC_event_flag);

#if defined(HW_ED_EXCP_EVENT)
int hx_EE_event_flag;
EXPORT_SYMBOL(hx_EE_event_flag);
#else
int hx_ED_event_flag;
EXPORT_SYMBOL(hx_ED_event_flag);
#endif

int g_zero_event_count;

#endif

static bool chip_test_r_flag;
u8 HX_HW_RESET_ACTIVATE;

static uint8_t AA_press;
static uint8_t EN_NoiseFilter;
static uint8_t Last_EN_NoiseFilter;

static int p_point_num = 0xFFFF;
static uint8_t p_stylus_num = 0xFF;
static int probe_fail_flag;
#if defined(HX_USB_DETECT_GLOBAL)
bool USB_detect_flag;
#endif

#if defined(HX_GESTURE_TRACK)
static int gest_pt_cnt;
static int gest_pt_x[GEST_PT_MAX_NUM];
static int gest_pt_y[GEST_PT_MAX_NUM];
static int gest_start_x, gest_start_y, gest_end_x, gest_end_y;
static int gest_width, gest_height, gest_mid_x, gest_mid_y;
static int hx_gesture_coor[16];
#endif

int g_ts_dbg;
EXPORT_SYMBOL(g_ts_dbg);

/* File node for Selftest, SMWP and HSEN - Start*/
#define HIMAX_PROC_SELF_TEST_FILE	"self_test"
struct proc_dir_entry *himax_proc_self_test_file;

uint8_t HX_PROC_SEND_FLAG;
EXPORT_SYMBOL(HX_PROC_SEND_FLAG);

#if defined(HX_SMART_WAKEUP)
#define HIMAX_PROC_SMWP_FILE "SMWP"
struct proc_dir_entry *himax_proc_SMWP_file;
#define HIMAX_PROC_GESTURE_FILE "GESTURE"
struct proc_dir_entry *himax_proc_GESTURE_file;
uint8_t HX_SMWP_EN;
#if defined(HX_ULTRA_LOW_POWER)
#define HIMAX_PROC_PSENSOR_FILE "Psensor"
struct proc_dir_entry *himax_proc_psensor_file;
#endif
#endif

#if defined(HX_HIGH_SENSE)
#define HIMAX_PROC_HSEN_FILE "HSEN"
struct proc_dir_entry *himax_proc_HSEN_file;
#endif

#define HIMAX_PROC_VENDOR_FILE "vendor"
struct proc_dir_entry *himax_proc_vendor_file;

#if defined(HX_PALM_REPORT)
static int himax_palm_detect(uint8_t *buf)
{
	struct himax_ts_data *ts = private_ts;
	int32_t i;
	int base = 0;
	int x = 0, y = 0, w = 0;

	i = 0;
	base = i * 4;
	x = buf[base] << 8 | buf[base + 1];
	y = (buf[base + 2] << 8 | buf[base + 3]);
	w = buf[(ts->nFinger_support * 4) + i];
	I(" %s HX_PALM_REPORT_loopi=%d,base=%x,X=%x,Y=%x,W=%x\n",
		__func__, i, base, x, y, w);
	if ((!atomic_read(&ts->suspend_mode))
	&& (x == 0xFA5A)
	&& (y == 0xFA5A)
	&& (w == 0x00))
		return PALM_REPORT;
	else
		return NOT_REPORT;
}
#endif

#if defined(HX_FIRMWARE_HEADER)
int32_t get_fw_index(int32_t fw_type)
{
	uint32_t i = 0;
	int ret = -1;

	for (i = 0; i < gTotal_N_firmware; i++) {
		if (gHimax_firmware_id[i] == g_hx_panel_id) {
			if (gHimax_firmware_type[i] == fw_type)
				return i;
		}
	}
	return ret;
}
#endif

#if defined(HX_RW_FILE)
int hx_open_file(char *file_name)
{
#if !defined(KERNEL_VER_ABOVE_4_19)
	struct filename *vts_name = NULL;
#endif
	int ret = -EFAULT;
	g_fn = NULL;
	g_pos = 0;
#if defined(KERNEL_VER_ABOVE_4_19)
	g_fn = filp_open(file_name,
			O_TRUNC|O_CREAT|O_RDWR, 0660);
		if (IS_ERR(g_fn))
			E("%s filp Open file failed!\n", __func__);
		else {
			ret = NO_ERR;
			g_fs = get_fs();
			set_fs(KERNEL_DS);
		}
#else
	if (!kp_getname_kernel) {
		E("kp_getname_kernel is NULL, not open file!\n");
	} else {
		vts_name = kp_getname_kernel(file_name);
		I("Now vts_name=%s\n", vts_name->name);
		g_fn = kp_file_open_name(vts_name,
			O_TRUNC|O_CREAT|O_RDWR, 0660);
		if (IS_ERR(g_fn))
			E("%s Open file failed!\n", __func__);
		else {
			ret = NO_ERR;
			g_fs = get_fs();
			set_fs(KERNEL_DS);
		}
	}
#endif
	return ret;
}
int hx_write_file(char *write_data, uint32_t write_size, loff_t pos)
{
	int ret = NO_ERR;

	g_pos = pos;
#if defined(KERNEL_VER_ABOVE_4_19)
	kernel_write(g_fn, write_data,
	write_size * sizeof(char), &g_pos);
#else
	vfs_write(g_fn, write_data,
	write_size * sizeof(char), &g_pos);	
#endif
	return ret;
}
int hx_close_file(void)
{
	int ret = NO_ERR;

	filp_close(g_fn, NULL);
	set_fs(g_fs);

	return ret;
}
#endif
static ssize_t himax_self_test(struct seq_file *s, void *v)
{

	size_t ret = 0;

	I("%s: enter, %d\n", __func__, __LINE__);

	if (private_ts->suspended == 1) {
		E("%s: please do self test in normal active mode\n", __func__);
		return HX_INIT_FAIL;
	}

	if (private_ts->in_self_test == 1) {
		W("%s: Self test is running now!\n", __func__);
		return ret;
	}
	private_ts->in_self_test = 1;

	himax_int_enable(0);/* disable irq */

	g_core_fp.fp_chip_self_test(s, v);
/*
 *#if defined(HX_EXCP_RECOVERY)
 *	HX_EXCP_RESET_ACTIVATE = 1;
 *#endif
 *	himax_int_enable(1); //enable irq
 */

#if defined(HX_EXCP_RECOVERY)
	HX_EXCP_RESET_ACTIVATE = 1;
#endif
	himax_int_enable(1);

	private_ts->in_self_test = 0;

	return ret;
}

static void *himax_self_test_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= 1)
		return NULL;


	return (void *)((unsigned long) *pos + 1);
}

static void *himax_self_test_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return NULL;
}

static void himax_self_test_seq_stop(struct seq_file *s, void *v)
{
}

static int himax_self_test_seq_read(struct seq_file *s, void *v)
{
	size_t ret = 0;

	if (chip_test_r_flag) {
/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_INSPECT)
		if (g_rslt_data) {
			if (s->size < g_rslt_data_len) {
				s->size = g_rslt_data_len;
				s->buf = kcalloc(s->size,
					sizeof(char), GFP_KERNEL);
				if (s->buf == NULL) {
					E("%s,%d: Memory allocation falied!\n",
						__func__, __LINE__);
					seq_puts(s, "Allocate Memory Fail!\n");
					return -ENOMEM;
				}
				memset(s->buf, 0, s->size * sizeof(char));
			}
			seq_printf(s, "%s", g_rslt_data);
		} else
#endif
			seq_puts(s, "No chip test data.\n");
	} else {
		himax_self_test(s, v);
	}

	return ret;
}

static const struct seq_operations himax_self_test_seq_ops = {
	.start	= himax_self_test_seq_start,
	.next	= himax_self_test_seq_next,
	.stop	= himax_self_test_seq_stop,
	.show	= himax_self_test_seq_read,
};

static int himax_self_test_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &himax_self_test_seq_ops);
};

static ssize_t himax_self_test_write(struct file *filp, const char __user *buff,
			size_t len, loff_t *data)
{
	char buf[80];

	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len))
		return -EFAULT;

	if (buf[0] == 'r') {
		chip_test_r_flag = true;
		I("%s: Start to read chip test data.\n", __func__);
	}	else {
		chip_test_r_flag = false;
		I("%s: Back to do self test.\n", __func__);
	}

	return len;
}

static const struct file_operations himax_proc_self_test_ops = {
	.owner = THIS_MODULE,
	.open = himax_self_test_proc_open,
	.read = seq_read,
	.write = himax_self_test_write,
	.release = seq_release,
};

// hoping test mode code begin
static void himax_Freq_hop_test_sub(struct work_struct *work)
{
	I("%s: Entering freq_hop sub! \n", __func__);
	 if(private_ts->Freq_hop_test_stauts == 1){
		private_ts->Freq_hop_test_stauts = 2;
	 	}
	 else{
	 	private_ts->Freq_hop_test_stauts = 1;
	 	}

	 I("%s: tx freq hop test start,MODE= %d \n", __func__, private_ts->Freq_hop_test_stauts);	
	g_core_fp.fp_tx_freq_chg_test(private_ts->Freq_hop_test_stauts);

	queue_delayed_work(private_ts->himax_Freq_hop_test_wq, &private_ts->himax_Freq_hop_test_wrok, msecs_to_jiffies(10000));
	private_ts->Freq_hop_delay_work_start =1;
	 
	return;
}
// himax_proc_data_limit_ops start
static ssize_t himax_data_limit_read(struct file *file, char *buf,
									size_t len, loff_t *pos)
{
	ssize_t ret = 0;
	uint8_t loop_i = 0;
	int item_i = 0;
	int item_data_max = -0x80000000;
	int item_data_min = 0x7FFFFFFF;
	int all_mut_len = ic_data->HX_TX_NUM*ic_data->HX_RX_NUM;
	char *temp_buf;

	if (!HX_PROC_SEND_FLAG) {

		ret = himax_self_test_data_init();
		if(ret)
		{
			I("read criteria file fail %s,here:%d\n", __func__, __LINE__);
			return 0;
		}

		temp_buf = kzalloc(len, GFP_KERNEL);
		if(temp_buf == NULL)
		{
			I("loc memory fail %s,here:%d\n", __func__, __LINE__);
			himax_self_test_data_deinit();
			return 0;
		}
		for (loop_i = 0; loop_i < HX_CRITERIA_SIZE; loop_i++)
		{
			item_data_max = -0x80000000;
			item_data_min = 0x7FFFFFFF;
			for(item_i = 0; item_i <all_mut_len; item_i++)
			{
				if(g_inspection_criteria[loop_i][item_i]>item_data_max)
				{
					item_data_max = g_inspection_criteria[loop_i][item_i];
				}

				if(g_inspection_criteria[loop_i][item_i]<item_data_min)
				{
					item_data_min = g_inspection_criteria[loop_i][item_i];
				}
			}
			ret += snprintf(temp_buf + ret, len - ret, "%s: (%d -- %d)\n", g_hx_inspt_crtra_name[loop_i], item_data_min, item_data_max);
		}

		//ret += snprintf(temp_buf + ret, len - ret, "\n");

		if (copy_to_user(buf, temp_buf, len))
			I("%s,here:%d\n", __func__, __LINE__);

		kfree(temp_buf);
		himax_self_test_data_deinit();
		HX_PROC_SEND_FLAG = 1;
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return ret;
}


static struct file_operations himax_proc_data_limit_ops = {
	.owner = THIS_MODULE,
	.read = himax_data_limit_read,
};

// himax_proc_data_limit_ops end
//himax_proc_main_reg_ops start
static ssize_t himax_main_reg_read(struct file *file, char *buf, /*main_register*/
									size_t len, loff_t *pos)
{
	ssize_t ret = 0;
	size_t reg_ary_len;
	uint8_t loop_i = 0;
	uint8_t addr[4] = {0};
	uint8_t data[4] = {0};
	char *temp_buf;

	if (!HX_PROC_SEND_FLAG) {
		temp_buf = kzalloc(len, GFP_KERNEL);
		reg_ary_len = (size_t)(sizeof(dbg_reg_ary)/sizeof(uint32_t));

		for (loop_i = 0; loop_i < reg_ary_len; loop_i++) {
			himax_parse_assign_cmd(dbg_reg_ary[loop_i], addr, 4);
			g_core_fp.fp_register_read(addr, data, DATA_LEN_4);

			ret += snprintf(temp_buf + ret, len - ret,
			"reg[0-3] : 0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
			dbg_reg_ary[loop_i], data[0], data[1], data[2], data[3]);
			I("reg[0-3] : 0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
			dbg_reg_ary[loop_i], data[0], data[1], data[2], data[3]);
		}
		if (copy_to_user(buf, temp_buf, len))
			I("%s,here:%d\n", __func__, __LINE__);

		kfree(temp_buf);
		HX_PROC_SEND_FLAG = 1;
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return ret;
}

static struct file_operations himax_proc_main_reg_ops = {
	.owner = THIS_MODULE,
	.read = himax_main_reg_read,
};
//himax_proc_main_reg_ops end
// himax_proc_baseline_ops start

static void *himax_oppo_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= 1) {
		return NULL;
	}
	return (void *)((unsigned long) *pos + 1);
}

static void *himax_oppo_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return NULL;
}

static void himax_oppo_seq_stop(struct seq_file *s, void *v)
{
}
static int himax_oppo_baseline_read(struct seq_file *s, void *v) /*baseline*/
{
	size_t ret = 0;

	ret = oppo_baseline_read ( s );
	return ret;
}

static struct seq_operations himax_oppo_baseline_seq_ops = {
	.start	= himax_oppo_seq_start,
	.next	= himax_oppo_seq_next,
	.stop	= himax_oppo_seq_stop,
	.show	= himax_oppo_baseline_read,
};

static int himax_oppo_baseline_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &himax_oppo_baseline_seq_ops);
};

static struct file_operations himax_proc_baseline_ops = {
	.owner = THIS_MODULE,
	.open = himax_oppo_baseline_proc_open,
	.read = seq_read,
};
// himax_proc_baseline_ops end

//himax_proc_delta_ops start

static int himax_oppo_delta_read(struct seq_file *s, void *v) /*delta*/
{
	size_t ret = 0;

	ret = oppo_delta_read_sub( s );

	return ret;
}
static struct seq_operations himax_oppo_delta_seq_ops = {
	.start	= himax_oppo_seq_start,
	.next	= himax_oppo_seq_next,
	.stop	= himax_oppo_seq_stop,
	.show	= himax_oppo_delta_read,
};

static int himax_oppo_delta_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &himax_oppo_delta_seq_ops);
};

static struct file_operations himax_proc_delta_ops = {
	.owner = THIS_MODULE,
	.open = himax_oppo_delta_proc_open,
	.read = seq_read,
};
//himax_proc_delta_ops end

#if defined(HX_SMART_WAKEUP)
// himax_black_screen_test_fops start

extern int touch_black_test;

int himax_get_black_screentest_status(void)
{
	return touch_black_test;
}

static ssize_t himax_black_screen_test(struct seq_file *s, void *v)
{
	int val = 0x00;
	size_t ret = 0;
	I("%s: enter, %d\n", __func__, __LINE__);
	touch_black_test = 1;
	//msleep(4000);

	if (private_ts->suspended == 0) {
		E("%s: please do self test in black screen mode\n", __func__);
	//	return HX_INIT_FAIL;
	}

	// msleep(2000);

	himax_int_enable(0);/* disable irq */

	private_ts->in_self_test = 1;

	val = himax_black_chip_self_test(s, v);

	private_ts->in_self_test = 0;

	himax_int_enable(1);

	touch_black_test = 0;

	tp_gesture = private_ts->gesture_bak;
    private_ts->SMWP_enable = private_ts->backup_flag;
	return ret;
}

static void *himax_black_screen_test_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= 1)
		return NULL;


	return (void *)((unsigned long) *pos + 1);
}

static void *himax_black_screen_test_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return NULL;
}

static void himax_black_screen_test_seq_stop(struct seq_file *s, void *v)
{
}

static int himax_black_screen_test_seq_read(struct seq_file *s, void *v)
{
	size_t ret = 0;

	if ( private_ts->self_test_finished == 1 ) {
		return ret;
	}
	private_ts->self_test_finished = 1;
	himax_black_screen_test(s, v);
	
	if (chip_test_r_flag) {
/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_INSPECT)
		if (g_rslt_data)
			seq_printf(s, "%s", g_rslt_data);
		else
#endif
		seq_puts(s, "No chip test data.\n");
	} 	
	private_ts->self_test_finished = 0;
	return ret;
}

static const struct seq_operations himax_black_screen_test_seq_ops = {
	.start	= himax_black_screen_test_seq_start,
	.next	= himax_black_screen_test_seq_next,
	.stop	= himax_black_screen_test_seq_stop,
	.show	= himax_black_screen_test_seq_read,
};

static int himax_black_screen_test_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &himax_black_screen_test_seq_ops);
};

static ssize_t himax_black_screen_test_write(struct file *filp, const char __user *userbuf,
			size_t len, loff_t *data)
{
	int value = 0;
	char buf[4] = {0};
	struct himax_ts_data *ts = private_ts;

	if ( copy_from_user(buf, userbuf, len) ) {
		E("%s: copy from user error.", __func__);
		return -1;
	}
	sscanf(buf, "%d", &value);

	I("value ============%d\n",value);

    ts->backup_flag = ts->SMWP_enable;
	ts->gesture_bak = tp_gesture;
    ts->SMWP_enable = 1;
	tp_gesture = 1;
    ts->in_self_test = value;
	return len;
}

static const struct file_operations himax_black_screen_test_fops = {
	.owner = THIS_MODULE,
	.open = himax_black_screen_test_open,
	.read = seq_read,
	.write = himax_black_screen_test_write,
	.release = seq_release,
};
// himax_black_screen_test_fops end
#endif
// himax_proc_baseline_test_ops start
static ssize_t himax_baseline_test(struct seq_file *s, void *v)
{
	int val = 0x00;
	size_t ret = 0;

	I("%s: enter, %d\n", __func__, __LINE__);

	if (private_ts->suspended == 1) {
		E("%s: please do self test in normal active mode\n", __func__);
		return HX_INIT_FAIL;
	}

	himax_int_enable(0);/* disable irq */

	private_ts->in_self_test = 1;

	val = g_core_fp.fp_chip_self_test(s, v);

	//private_ts->in_self_test = 0;

	himax_int_enable(1);

	return ret;
}

static void *himax_baseline_test_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= 1)
		return NULL;


	return (void *)((unsigned long) *pos + 1);
}

static void *himax_baseline_test_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return NULL;
}

static void himax_baseline_test_seq_stop(struct seq_file *s, void *v)
{
}

static int himax_baseline_test_seq_read(struct seq_file *s, void *v)
{
	size_t ret = 0;

	if ( private_ts->self_test_finished == 1 ) {
		return ret;
	}
	private_ts->self_test_finished = 1;
	himax_baseline_test(s, v);
	if (chip_test_r_flag) {
/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_INSPECT)
		if (g_rslt_data)
			seq_printf(s, "%s", g_rslt_data);
		else
#endif
		seq_puts(s, "No chip test data.\n");
	} 
	private_ts->self_test_finished = 0;

	return ret;
}

static const struct seq_operations himax_baseline_test_seq_ops = {
	.start	= himax_baseline_test_seq_start,
	.next	= himax_baseline_test_seq_next,
	.stop	= himax_baseline_test_seq_stop,
	.show	= himax_baseline_test_seq_read,
};

static int himax_proc_baseline_test_open(struct inode *inode, struct file *file)
{	
	return seq_open(file, &himax_baseline_test_seq_ops);
};

static ssize_t himax_proc_baseline_write(struct file *filp, const char __user *buff,
			size_t len, loff_t *data)
{
	char buf[80];

	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len))
		return -EFAULT;

	if (buf[0] == 'r') {
		chip_test_r_flag = true;
		I("%s: Start to read chip test data.\n", __func__);
	}	else {
		chip_test_r_flag = false;
		I("%s: Back to do self test.\n", __func__);
	}

	return len;
}

static const struct file_operations himax_proc_baseline_test_ops = {
	.owner = THIS_MODULE,
	.open = himax_proc_baseline_test_open,
	.read = seq_read,
	.write = himax_proc_baseline_write,
	.release = seq_release,
};

// himax_proc_baseline_test_ops end

//himax_proc_oppo_tx_hop_op start
static ssize_t oppo_io_ctrl_read(struct file *file, char *buf,
							   size_t len, loff_t *pos)
{
	size_t count = 0;
	struct himax_ts_data *ts = private_ts;
	char *temp_buf;

	if (!HX_PROC_SEND_FLAG) {
		temp_buf = kzalloc(len, GFP_KERNEL);
		count = snprintf(temp_buf, PAGE_SIZE, "%d\n", ts->Freq_hop_test_stauts);

		if (copy_to_user(buf, temp_buf, len))
			I("%s,here:%d\n", __func__, __LINE__);

		kfree(temp_buf);
		HX_PROC_SEND_FLAG = 1;
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return count;
}

static ssize_t himax_oppo_hop_test_write(struct file *file, const char *buff,/*oppo_io_ctrl*/
								size_t len, loff_t *pos)
{
	
	char buf[80] = {0};
	
	if ( *pos ) {
    	E("is already read the file\n");
    	return 0;
	}
    *pos += len;
	
	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len)) {
		return -EFAULT;
	}

	if (buf[0] == '1') {
		if ( private_ts->Freq_hop_delay_work_start == 0) {
		private_ts->Freq_hop_delay_work_start =1;
		private_ts->Freq_hop_test_stauts = 1;
		queue_delayed_work(private_ts->himax_Freq_hop_test_wq, &private_ts->himax_Freq_hop_test_wrok, msecs_to_jiffies(10000));
		I("%s: tx freq hop test start,status= %c \n", __func__, buf[0]);
		}
		
		
	} else{

		if ( private_ts->Freq_hop_delay_work_start == 1 ) {
		cancel_delayed_work_sync(&private_ts->himax_Freq_hop_test_wrok);
		flush_workqueue(private_ts->himax_Freq_hop_test_wq); 
		g_core_fp.fp_tx_freq_chg_test(0);
		I("%s: tx freq hop test close,status= %c \n", __func__, buf[0]);
		private_ts->Freq_hop_delay_work_start = 0; 
		private_ts->Freq_hop_test_stauts = 0;
		}
	}

	
	return len;
}

static struct file_operations himax_proc_oppo_tx_hop_ops = {
	.owner = THIS_MODULE,
	.read = oppo_io_ctrl_read,
	.write = himax_oppo_hop_test_write,
};
//himax_proc_oppo_tx_hop_op end


/* incell_panel	Start*/

static ssize_t himax_incell_panel_read(struct file	*file, char	__user *user_buf,	size_t count,	loff_t *ppos)
{
	ssize_t	ret	=	0;
	char* temp_buf = NULL;
	unsigned char temp_data =0;

	if(count < 3)
	{
		I("%s,here:%d count=%d < 3\n", __func__, __LINE__,(int)count);
		return count;
	}

	if (!HX_PROC_SEND_FLAG) {
		if(strncmp (private_ts->chip_name,  HX_83102D_SERIES_PWON,  30))
		{
			temp_data=0;
		}
		else
		{
			temp_data=1;//is incell
		}

		temp_buf = kzalloc(count, GFP_KERNEL);
		if(temp_buf ==NULL)
		{
			return -1;
		}
		ret = snprintf(temp_buf, PAGE_SIZE, "%d\n", temp_data);

		if (copy_to_user(user_buf, temp_buf, count))
			I("%s,here:%d\n", __func__, __LINE__);

		kfree(temp_buf);
		HX_PROC_SEND_FLAG = 1;
	} else {
		HX_PROC_SEND_FLAG = 0;
	}
	return ret;
}


static struct file_operations himax_proc_incell_panel_ops = {
	.owner = THIS_MODULE,
	.open	 = simple_open,
	.read = himax_incell_panel_read,
};

/* incell_panel	End*/
/* irq depth	Start*/
static ssize_t himax_irq_depth_read(struct file *file, char *buf,
								  size_t len, loff_t *pos)
{
	size_t ret = 0;
	char *temp_buf;
	struct irq_desc *desc = irq_to_desc(private_ts->pdata->gpio_irq);//wdd modify
	//extern unsigned int himax_touch_irq;
	//struct irq_desc *desc = irq_to_desc(himax_touch_irq);
	I("%s: enter, %d \n", __func__, __LINE__);

	if (!HX_PROC_SEND_FLAG) {
		temp_buf = kzalloc(len, GFP_KERNEL);
		ret += snprintf(temp_buf + ret, len - ret, "now depth=%d\n", desc->depth);

		if (copy_to_user(buf, temp_buf, len))
			I("%s,here:%d\n", __func__, __LINE__);

		kfree(temp_buf);
		HX_PROC_SEND_FLAG = 1;
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return ret;
}

static ssize_t himax_irq_depth_write(struct file *file, const char *buff,
								   size_t len, loff_t *pos)
{

	I("%s:Nothing to be done!\n", __func__);
	return len;
}

static struct file_operations himax_proc_irq_depth_ops = {
	.owner = THIS_MODULE,
	.read = himax_irq_depth_read,
	.write = himax_irq_depth_write,
};

/* irq depth	End*/

/*oppo debug level 	Start*/
static ssize_t himax_oppo_debug_level_read(struct file *file, char *buf,
								  size_t len, loff_t *pos)
{
	size_t ret = 0;
	char temp_buf[8];
	I("%s: enter, %d \n", __func__, __LINE__);

	if (!HX_PROC_SEND_FLAG) {
		ret = snprintf(temp_buf, sizeof(temp_buf), "%d\n", g_oppo_debug_level);
		if (copy_to_user(buf, temp_buf, ret))
			I("%s,here:%d\n", __func__, __LINE__);

		HX_PROC_SEND_FLAG = 1;
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return ret;
}


static ssize_t himax_oppo_debug_level_write(struct file *file, const char *buff,
								   size_t len, loff_t *pos)
{

    char buf[80] = {0};
    int32_t dbgLevel = 0;
    int32_t ret = 0;

    if (len >= 80)
    {
        I("%s: no command exceeds 80 chars.\n", __func__);
        return -EFAULT;
    }
    if (copy_from_user(buf, buff, len))
    {
        return -EFAULT;
    }

    ret = sscanf(buf, "%d", &dbgLevel);

    if (ret >= 1) {
        g_oppo_debug_level = 0;
        switch(dbgLevel) {
            case 2:
                g_oppo_debug_level	= dbgLevel & BIT(1);
                break;
            case 1:
            case 0:
                g_oppo_debug_level = dbgLevel & BIT(0);
                break;
            default:
            g_oppo_debug_level = 0;
        };
    }
    I("%s: buf = %s, debug_level = %d\n", __func__, buf, g_oppo_debug_level);

    return len;
}

static struct file_operations himax_proc_oppo_debug_level_ops = {
	.owner = THIS_MODULE,
	.read = himax_oppo_debug_level_read,
	.write = himax_oppo_debug_level_write,
};

/* oppo debug level	End*/

/* oppo_tp_direction	Start*/
static ssize_t himax_oppo_tp_direction_write(struct file *file, const char *buff,
									size_t len, loff_t *pos)
{
	char buf_tmp[4] = {0};
	int ret = 0;
	struct himax_ts_data *ts = private_ts;
	if (len >= 4) {
		I("%s: no command exceeds 4 chars.\n", __func__);
		return -EFAULT;
	}
    if (ts == NULL){
        return len;
	}
	if (copy_from_user(buf_tmp, buff, len)) {
		return -EFAULT;
	}

	I("%s: ap send %c.\n", __func__, buf_tmp[0]);
	 ret = sscanf(buf_tmp, "%d", &ts->touch_direction);
	 if (ret == 0) {
		I("%s: char to int fail.\n", __func__);
	 }

	if (buf_tmp[0] == '1') {
		himax_parse_assign_cmd(fw_oppo_tp_direction_0_pwd, buf_tmp, sizeof(buf_tmp));
		g_core_fp.fp_register_write(pfw_op->addr_oppo_tp_direction/*0x10007f3c*/, buf_tmp, DATA_LEN_4);
		I("%s: vertical state \n", __func__);
	}
	else if(buf_tmp[0] == '4')
	{
		himax_parse_assign_cmd(fw_oppo_tp_direction_1_pwd, buf_tmp, sizeof(buf_tmp));
		g_core_fp.fp_register_write(pfw_op->addr_oppo_tp_direction, buf_tmp, DATA_LEN_4);
		I("%s: horizontal and norch is at left state.\n", __func__);
	}
	else if(buf_tmp[0] == '3')
	{
		himax_parse_assign_cmd(fw_oppo_tp_direction_2_pwd, buf_tmp, sizeof(buf_tmp));
		g_core_fp.fp_register_write(pfw_op->addr_oppo_tp_direction,buf_tmp, DATA_LEN_4);
		I("%s: horizontal and norch in at right state.\n", __func__);
	}
	else {
		I("%s: tp_direction wrong parameter .\n", __func__);
		return -EINVAL;
	}

	return len;
}


static ssize_t proc_dir_control_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
    ssize_t ret = 0;
    char page[PAGESIZE];
    struct himax_ts_data *ts = private_ts;

    if (!ts)
        return count;

    sprintf(page, "%d\n", ts->touch_direction);
    ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));

    return ret;
}

static struct file_operations himax_proc_oppo_tp_direction_ops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = proc_dir_control_read,
	.write = himax_oppo_tp_direction_write,
};
/* oppo_tp_direction	End*/

/* oppo usb_mode start*/
static ssize_t himax_oppo_tp_usb_mode_write(struct file *file, const char *buff,
									size_t len, loff_t *pos)
{
	char buf_tmp[4] = {0};
	int ret = 0;

	struct himax_ts_data *ts = private_ts;
	if (len >= 4) {
		I("%s: no command exceeds 4 chars.\n", __func__);
		return -EFAULT;
	}
    if (ts == NULL){
        return len;
	}
	if (copy_from_user(buf_tmp, buff, len)) {
		return -EFAULT;
	}

	I("%s: ap send %c.\n", __func__, buf_tmp[0]);
	 ret = sscanf(buf_tmp, "%d", &ts->charge_mode);
	 if (ret == 0) {
		I("%s: char to int fail.\n", __func__);
	 }
	himax_usb_mode_switch(ts->charge_mode);

	return len;
}
static ssize_t proc_dir_usb_mode_control_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
    ssize_t ret = 0;
    char page[PAGESIZE];
    struct himax_ts_data *ts = private_ts;

    if (!ts)
        return count;

    sprintf(page, "%d\n", ts->charge_mode);
    ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));

    return ret;
}
static struct file_operations himax_proc_oppo_tp_usb_mode_ops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = proc_dir_usb_mode_control_read,
	.write = himax_oppo_tp_usb_mode_write,
};
/* oppo usb_mode start*/

/* oppo headset_mode start*/
static ssize_t himax_oppo_tp_headset_mode_write(struct file *file, const char *buff,
									size_t len, loff_t *pos)
{
	char buf_tmp[4] = {0};
	int ret = 0;
	struct himax_ts_data *ts = private_ts;
	if (len >= 4) {
		I("%s: no command exceeds 4 chars.\n", __func__);
		return -EFAULT;
	}
    if (ts == NULL){
        return len;
	}
	if (copy_from_user(buf_tmp, buff, len)) {
		return -EFAULT;
	}

	I("%s: ap send %c.\n", __func__, buf_tmp[0]);
	 ret = sscanf(buf_tmp, "%d", &ts->headset_mode);
	 if (ret == 0) {
		I("%s: char to int fail.\n", __func__);
	 }
	himax_headset_mode_switch(ts->headset_mode);
	return len;
}
static ssize_t proc_dir_headset_mode_control_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
    ssize_t ret = 0;
    char page[PAGESIZE];
    struct himax_ts_data *ts = private_ts;

    if (!ts)
        return count;

    sprintf(page, "%d\n", ts->headset_mode);
    ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));

    return ret;
}

static struct file_operations himax_proc_oppo_tp_headset_mode_ops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = proc_dir_headset_mode_control_read,
	.write = himax_oppo_tp_headset_mode_write,
};
/* oppo headset_mode start*/

/* Game Switch Enable Start*/
static ssize_t hx_game_switch_write(struct file	*file, const char	__user *buffer,	size_t count,	loff_t *ppos)
{
	char buf[8]	={0};
	int	temp;
	bool ret;
	struct himax_ts_data *ts = private_ts;

	if (!ts)
			return count;

	if (count	>	3)
			count	=	3;
	if (copy_from_user(buf,	buffer,	count))	{
			E("%s: read	proc input error.\n",	__func__);
			return count;
	}

	sscanf(buf,"%x",&temp);
	
	ts->noise_level = temp;

	if (temp !=	0) {
		I("%s:Touchpanel game switch enable%d\n",__func__,temp);
		ret	=g_core_fp.fp_no_jiter_en(1);
			if (ret	== false)	{
					I("%s: Touchpanel enable game switch failed\n",	__func__);
			}
	}	else {
		I("%s:Touchpanel game switch disable %d\n", __func__, temp);
		ret	=g_core_fp.fp_no_jiter_en(0);
			if (ret	== false)	{
					I("%s:Touchpanel disable game switch failed\n", __func__);
			}
	}

	return count;
}


//Game Switch Enable read start
static ssize_t proc_game_switch_read(struct file	*file, char	__user *user_buf,	size_t count,	loff_t *ppos)
{
	ssize_t	ret	=	0;
	char page[PAGESIZE];
	struct himax_ts_data *ts = private_ts;

	if (!ts)
		return count;
	I("noise_level is:%d\n", ts->noise_level);
	ret	=	snprintf(page, PAGESIZE,"noise level=%d\n", ts->noise_level);
	ret	=	simple_read_from_buffer(user_buf,count, ppos, page, strlen(page));

	return ret;
}

static const struct	file_operations	hx_proc_game_switch_ops	= {
	.write 	 = hx_game_switch_write,
	.read	 = proc_game_switch_read,
	.open	 = simple_open,
	.owner = THIS_MODULE,
};
/* Game	Switch Enable	End*/

//proc_limit_area_ops_start
static ssize_t proc_limit_area_read(struct file	*file, char	__user *user_buf,	size_t count,	loff_t *ppos)
{
	ssize_t	ret	=	0;
	char page[PAGESIZE];
	struct himax_ts_data *ts = private_ts;

	if (!ts)
		return count;
	I("limit_area is: %d\n", ts->edge_limit.limit_area);
	ret	=	snprintf(page, sizeof(page),"limit_area=%d left_x1=%d right_x1=%d left_x2=%d right_x2=%d left_y1=%d right_y1=%d left_y2=%d right_y2=%d\n",
					ts->edge_limit.limit_area, ts->edge_limit.left_x1, ts->edge_limit.right_x1,	ts->edge_limit.left_x2,	ts->edge_limit.right_x2,
					ts->edge_limit.left_y1,	ts->edge_limit.right_y1, ts->edge_limit.left_y2, ts->edge_limit.right_y2);
	ret	=	simple_read_from_buffer(user_buf,count, ppos, page, strlen(page));

	return ret;
}

static ssize_t proc_limit_area_write(struct	file *file,	const	char __user	*buffer, size_t	count, loff_t	*ppos)
{
	char buf[8];
	int	temp;
	struct himax_ts_data *ts = private_ts;

	if (!ts)
			return count;

	if (copy_from_user(buf,	buffer,	count))	{
			I("%s: read	proc input error.\n",__func__);
			return count;
	}

	sscanf(buf,"%d",&temp);
	if (temp < 0 ||	temp > 10)
		return count;

	ts->edge_limit.limit_area	=	temp;
	ts->edge_limit.left_x1		=	(ts->edge_limit.limit_area*1000)/100;
	ts->edge_limit.right_x1		=	ic_data->HX_X_RES	-	ts->edge_limit.left_x1;
	ts->edge_limit.left_x2		=	2	*	ts->edge_limit.left_x1;
	ts->edge_limit.right_x2		=	ic_data->HX_X_RES	-	(2 * ts->edge_limit.left_x1);
	/*ts->edge_limit.right_x1		=	ic_data->HX_X_RES	-	ts->edge_limit.left_x1;
	ts->edge_limit.left_x2		=	2	*	ts->edge_limit.left_x1;
	ts->edge_limit.right_x2		=	ic_data->HX_X_RES	-	(2 * ts->edge_limit.left_x1);*/

	I("limit_area	=	%d;	left_x1	=	%d;	right_x1 = %d; left_x2 = %d; right_x2	=	%d\n",
				 ts->edge_limit.limit_area,	ts->edge_limit.left_x1,	ts->edge_limit.right_x1, ts->edge_limit.left_x2, ts->edge_limit.right_x2);

	ts->edge_limit.left_y1		=	(ts->edge_limit.limit_area*1000)/100;
	ts->edge_limit.right_y1		=	ts->edge_limit.left_y1;
	ts->edge_limit.left_y2		=	ic_data->HX_Y_RES	-	2	*	ts->edge_limit.left_y1;
	ts->edge_limit.right_y2		=	ic_data->HX_Y_RES	-	(2 * ts->edge_limit.left_y1);
	/*ts->edge_limit.right_y1		=	ic_data->HX_Y_RES	-	ts->edge_limit.left_y1;
	ts->edge_limit.left_y2		=	2	*	ts->edge_limit.left_y1;
	ts->edge_limit.right_y2		=	ic_data->HX_Y_RES	-	(2 * ts->edge_limit.left_y1);*/

	I("limit_area =%d; left_y1=%d; right_y1 =%d; left_y2 =%d; right_y2=%d\n",ts->edge_limit.limit_area, ts->edge_limit.left_y1, ts->edge_limit.right_y1,ts->edge_limit.left_y2,ts->edge_limit.right_y2);
	return count;
}

static const struct	file_operations	proc_limit_area_ops	= {
		.read	 = proc_limit_area_read,
		.write = proc_limit_area_write,
		.open	 = simple_open,
		.owner = THIS_MODULE,
};

//proc_limit_area_ops_end


//hx_proc_limit_control_ops_start
static ssize_t hx_limit_ctrl_read(struct file	*file, char	__user *user_buf,	size_t count,	loff_t *ppos)
{
	ssize_t	ret	=0;
	char page[PAGESIZE];
	struct himax_ts_data *ts = private_ts;

	if (!ts)
			return count;

	I("touch_direction:%d", ts->touch_direction);
	ret	= sprintf(page, "%d\n", ts->touch_direction);
    ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

static ssize_t hx_limit_ctrl_write(struct	file *file,	const	char __user	*buffer, size_t	count, loff_t	*ppos)
{
	char buf[4]	=	{0};
	bool ret;
	struct himax_ts_data *ts = private_ts;

	if (!ts)
			return count;

	if (count > 3)
			count=3;
	if (copy_from_user(buf,	buffer,	count))	{
			E("%s: read	proc input error.\n",__func__);
			return count;
	}

	
	I("%s: ap send %c.\n", __func__, buf[0]);
	 ret = sscanf(buf, "%d", &ts->touch_direction);
	 if (ret == 0) {
		I("%s: char to int fail.\n", __func__); 
	 }

	if (buf[0] == '0') {
		himax_parse_assign_cmd(fw_oppo_tp_direction_0_pwd, buf, sizeof(buf));
		g_core_fp.fp_register_write(pfw_op->addr_oppo_tp_direction/*0x10007f3c*/,  buf, DATA_LEN_4);
		I("%s: oppo_tp_direction disable .\n", __func__);
	}
	else if(buf[0] == '1')
	{
		himax_parse_assign_cmd(fw_oppo_tp_direction_1_pwd, buf, sizeof(buf));
		g_core_fp.fp_register_write(pfw_op->addr_oppo_tp_direction,  buf, DATA_LEN_4);
		I("%s: oppo_tp_direction enable .\n", __func__);
	}
	else if(buf[0] == '2')
	{
		himax_parse_assign_cmd(fw_oppo_tp_direction_2_pwd, buf, sizeof(buf));
		g_core_fp.fp_register_write(pfw_op->addr_oppo_tp_direction,  buf, DATA_LEN_4);
		I("%s: oppo_tp_direction enable .\n", __func__);
	}
	else {
		I("%s: oppo_tp_direction wrong parameter .\n", __func__);
		return -EINVAL;
	}
	return count;
}

static const struct	file_operations	hx_proc_limit_control_ops	= {
	.read	 = hx_limit_ctrl_read,
	.write = hx_limit_ctrl_write,
	.open	 = simple_open,
	.owner = THIS_MODULE,
};
//hx_proc_limit_control_ops_end
//himax_double_tap_en start
#ifdef HX_SMART_WAKEUP
static ssize_t himax_double_tap_en_read(struct file	*file, char	__user *user_buf,	size_t count,	loff_t *ppos)
{
	struct himax_ts_data *ts = private_ts;
	size_t ret = 0;
	char page[PAGESIZE];
	if (!ts)
			return count;
	I("SMWP_enabl =: %d\n", (ts->SMWP_enable|| himax_gesture));
	ret	=snprintf(page, PAGESIZE,"%d\n", (ts->SMWP_enable|| himax_gesture));
	ret	=simple_read_from_buffer(user_buf,count, ppos, page, strlen(page));

	return ret;

}

static ssize_t himax_double_tap_en_write(struct file *file, const char *buff,/*double_tap_enable*/
								size_t len, loff_t *pos)
{
	struct himax_ts_data *ts = private_ts;
	char buf[80] = {0};
	int i = 0;
	/*if(ts->suspended) {
		I("%s: is already suspend\n", __func__);
		return -1;
	}*/

	if ( *pos ) {
    	E("is already read the file\n");
    	return 0;
	}
    *pos += len;
	
	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len)) {
		return -EFAULT;
	}

	if (buf[0] == '0') {
			if( ts->psensor_stus == 1 && ts->suspended == true ){
			return -EINVAL;
		} else {
			ts->SMWP_enable = 0;
			tp_gesture = 0;
			ts->gesture_cust_en[0] = 0;
		}

	} else if (buf[0] == '1') {
		if (ts->SMWP_enable == 1 && ts->psensor_stus == 1) {
			mutex_lock(&private_ts->fw_update_lock);
			I("%s: Psensor far away +++++.\n", __func__);
			ts->SMWP_enable = 1;
			tp_gesture = 1;
			ts->psensor_stus = 0;
			g_core_fp.fp_black_gest_en(true);
			mutex_unlock(&private_ts->fw_update_lock);
			return len;
		}
		ts->SMWP_enable = 1;
		tp_gesture = 1;
		for (i = 0; i < 16; i++) {
			ts->gesture_cust_en[i] = 1;
		}
	}	else if (buf[0] == '2') {
			if (ts->SMWP_enable == 1 && ts->psensor_stus == 0) {
				mutex_lock(&private_ts->fw_update_lock);
				I("%s: Psensor near by ----.\n", __func__);
				//ts->SMWP_enable = 0;
				ts->psensor_stus = 1;
				g_core_fp.fp_black_gest_en(false);
				mutex_unlock(&private_ts->fw_update_lock);
				return len;
			}else {
				return len;
			}
	}	else

		return -EINVAL;

	g_core_fp.fp_set_SMWP_enable(ts->SMWP_enable || himax_gesture, ts->suspended);
	I("%s: SMART_WAKEUP_enable = %d\n", __func__, (ts->SMWP_enable|| himax_gesture));
	return len;
}

static struct file_operations himax_proc_double_tap_en_ops = {
	.owner = THIS_MODULE,
	.read = himax_double_tap_en_read,
	.write = himax_double_tap_en_write,
};
//himax_double_tap_en end
// himax_proc_coor_start
#ifdef HX_GESTURE_TRACK
/*oppo*/
static void *himax_coor_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}
static void *himax_coor_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}
static void himax_coor_stop(struct seq_file *m, void *v)
{
	return;
}

static int32_t himax_coor_show(struct seq_file *m, void *v)
{
    int i = 0;
    //size_t ret = 0;
	char temp_buf[256] = {0};
    //uint16_t len = sizeof(temp_buf);

	I("%s enter.\n",__func__);//,len);

		for (i = 0; i < 8; i++) {
			if (i == 0) {
				//ret += snprintf(temp_buf + ret, len - ret, "%d,", hx_gesture_coor[i]);
				I("hx_gesture_coor[%d] = %d \n",i,hx_gesture_coor[i]);
			} else if (i == 7) {
				//ret += snprintf(temp_buf + ret, len - ret, "%d\n", hx_gesture_coor[i * 2 - 1]);
				I("hx_gesture_coor[%d] = %d \n",i * 2 - 1,hx_gesture_coor[i * 2 - 1]);
			} else {
				//ret += snprintf(temp_buf + ret, len - ret, "%d:", hx_gesture_coor[i * 2 - 1]);
				//ret += snprintf(temp_buf + ret, len - ret, "%d,", hx_gesture_coor[i * 2]);
				I("hx_gesture_coor[%d] = %d \n",i * 2 - 1,hx_gesture_coor[i * 2 - 1]);
				I("hx_gesture_coor[%d] = %d \n",i * 2,hx_gesture_coor[i * 2]);
			}
		}

		sprintf(temp_buf, "%d,%d:%d,%d:%d,%d:%d,%d:%d,%d:%d,%d:%d,%d",
			hx_gesture_coor[0],
			hx_gesture_coor[1], hx_gesture_coor[2],
			hx_gesture_coor[3], hx_gesture_coor[4],
			hx_gesture_coor[5], hx_gesture_coor[6],
			hx_gesture_coor[7], hx_gesture_coor[8],
			hx_gesture_coor[9], hx_gesture_coor[10],
			hx_gesture_coor[11], hx_gesture_coor[12],
			hx_gesture_coor[13]);

		/* oppo gesture formate */
		seq_printf(m, "%s\n", temp_buf);
	I("%s end.\n",__func__);
	return 0;
}

const struct seq_operations oppo_coord_seq_ops =
{
    .start  = himax_coor_start,
    .next   = himax_coor_next,
    .stop   = himax_coor_stop,
    .show   = himax_coor_show,
};

static int32_t himax_diag_coor_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &oppo_coord_seq_ops);
}

static struct file_operations himax_proc_coor_ops = {
	.owner = THIS_MODULE,
	.open = himax_diag_coor_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif
#endif


static ssize_t himax_tp_fw_update_write(struct file *file, const char __user *page, size_t size, loff_t *lo)
{
	struct himax_ts_data *ts = private_ts;
    int val = 0;
    int ret = 0;
    char buf[4] = {0};
    if (!ts)
        return size;
    if (size > 2)
        return size;

 #ifdef CONFIG_TOUCHPANEL_MTK_PLATFORM
    if (ts->boot_mode == KERNEL_POWER_OFF_CHARGING_BOOT)
#else
    if (ts->boot_mode == MSM_BOOT_MODE__CHARGE)
#endif
    {
        I("boot mode is MSM_BOOT_MODE__CHARGE,not need update tp firmware\n");
        return size;
    } 

    if (copy_from_user(buf, page, size)) {
        I("%s: read proc input error.\n", __func__);
        return size;
    }

    sscanf(buf, "%d", &val);
    ts->firmware_update_type = val;
    if ( !g_boot_upgrade_flag && ts->firmware_update_type != 2)
		 ts->force_update = !!val;

    schedule_work(&ts->fw_update_work);

    ret = wait_for_completion_killable_timeout(&ts->fw_complete, FW_UPDATE_COMPLETE_TIMEOUT);
    if (ret < 0) {
        I("kill signal interrupt\n");
    }

    I("fw update finished\n");
    return size;
}
static struct file_operations himax_proc_tp_fw_update_ops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = himax_tp_fw_update_write,
};
static ssize_t himax_oppo_reg_read_read(struct file *file, char *buf, size_t len, loff_t *pos)
{
	int ret = 0;
	uint16_t loop_i;
	uint8_t data[128];
	char *temp_buf;
	
	if ( *pos ) {
    	E("%s,is already read the file\n",__func__);
    	return 0;
	}
    *pos += len;
	memset(data, 0x00, sizeof(data));
	temp_buf = kzalloc(len, GFP_KERNEL);
	if (temp_buf == NULL) {
		E("%s: allocate memory fail!!!\n", __func__);
		return 0;
	}
	
	I("himax_register_show: %02X,%02X,%02X,%02X\n", reg_cmd[3], reg_cmd[2], reg_cmd[1], reg_cmd[0]);
	g_core_fp.fp_register_read(reg_cmd, data, 128);
	ret += snprintf(temp_buf + ret, len - ret, "command:  %02X,%02X,%02X,%02X\n", reg_cmd[3], reg_cmd[2], reg_cmd[1], reg_cmd[0]);

	for (loop_i = 0; loop_i < 128; loop_i++) {
		ret += snprintf(temp_buf + ret, len - ret, "0x%2.2X ", data[loop_i]);
		if ((loop_i % 16) == 15)
			ret += snprintf(temp_buf + ret, len - ret, "\n");
	}

	ret += snprintf(temp_buf + ret, len - ret, "\n");

	if (copy_to_user(buf, temp_buf, len))
		I("%s,here:%d\n", __func__, __LINE__);
	kfree(temp_buf);
	return ret;
}
static ssize_t himax_oppo_reg_read_write(struct file *file, const char *buff,
		size_t len, loff_t *pos)
{
	char buf[80] = {0};
	char buf_tmp[16];
	uint8_t length = 0;
	unsigned long result	= 0;
	uint8_t loop_i			= 0;
	uint16_t base			= 2;
	char *data_str = NULL;
	uint8_t w_data[20];
	uint8_t x_pos[20];
	uint8_t count = 0;
	
	if ( *pos ) {
    	E("%s,is already read the file\n",__func__);
    	return 0;
	}

	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len)) {
		return -EFAULT;
	}

	memset(buf_tmp, 0x0, sizeof(buf_tmp));
	memset(w_data, 0x0, sizeof(w_data));
	memset(x_pos, 0x0, sizeof(x_pos));
	memset(reg_cmd, 0x0, sizeof(reg_cmd));

	I("himax %s \n", buf);

	if ((buf[0] == 'r' || buf[0] == 'w') && buf[1] == ':' && buf[2] == 'x') {
		length = strlen(buf);

		/* I("%s: length = %d.\n", __func__,length); */
		for (loop_i = 0; loop_i < length; loop_i++) { /* find postion of 'x' */
			if (buf[loop_i] == 'x') {
				x_pos[count] = loop_i;
				count++;
			}
		}

		data_str = strrchr(buf, 'x');
		I("%s: %s.\n", __func__, data_str);
		length = strlen(data_str + 1) - 1;

		if (buf[0] == 'r') {
			if (buf[3] == 'F' && buf[4] == 'E' && length == 4) {
				length = length - base;
				cfg_flag = 1;
				memcpy(buf_tmp, data_str + base + 1, length);
			} else {
				cfg_flag = 0;
				memcpy(buf_tmp, data_str + 1, length);
			}

			byte_length = length / 2;

			if (!kstrtoul(buf_tmp, 16, &result)) {
				for (loop_i = 0 ; loop_i < byte_length ; loop_i++) {
					reg_cmd[loop_i] = (uint8_t)(result >> loop_i * 8);
				}
			}

			if (strcmp(HX_85XX_H_SERIES_PWON, private_ts->chip_name) == 0 && cfg_flag == 0)
				cfg_flag = 2;
		} else if (buf[0] == 'w') {
			if (buf[3] == 'F' && buf[4] == 'E') {
				cfg_flag = 1;
				memcpy(buf_tmp, buf + base + 3, length);
			} else {
				cfg_flag = 0;
				memcpy(buf_tmp, buf + 3, length);
			}

			if (count < 3) {
				byte_length = length / 2;

				if (!kstrtoul(buf_tmp, 16, &result)) { /* command */
					for (loop_i = 0 ; loop_i < byte_length ; loop_i++) {
						reg_cmd[loop_i] = (uint8_t)(result >> loop_i * 8);
					}
				}

				if (!kstrtoul(data_str + 1, 16, &result)) { /* data */
					for (loop_i = 0 ; loop_i < byte_length ; loop_i++) {
						w_data[loop_i] = (uint8_t)(result >> loop_i * 8);
					}
				}

				g_core_fp.fp_register_write(reg_cmd,  w_data, byte_length);
			} else {
				for (loop_i = 0; loop_i < count; loop_i++) { /* parsing addr after 'x' */
					memset(buf_tmp, 0x0, sizeof(buf_tmp));
					if (cfg_flag != 0 && loop_i != 0)
						byte_length = 2;
					else
						byte_length = x_pos[1] - x_pos[0] - 2; /* original */

					memcpy(buf_tmp, buf + x_pos[loop_i] + 1, byte_length);

					/* I("%s: buf_tmp = %s\n", __func__,buf_tmp); */
					if (!kstrtoul(buf_tmp, 16, &result)) {
						if (loop_i == 0) {
							reg_cmd[loop_i] = (uint8_t)(result);
							/* I("%s: reg_cmd = %X\n", __func__,reg_cmd[0]); */
						} else {
							w_data[loop_i - 1] = (uint8_t)(result);
							/* I("%s: w_data[%d] = %2X\n", __func__,loop_i - 1,w_data[loop_i - 1]); */
						}
					}
				}

				byte_length = count - 1;
				if (strcmp(HX_85XX_H_SERIES_PWON, private_ts->chip_name) == 0 && cfg_flag == 0)
					cfg_flag = 2;
				g_core_fp.fp_register_write(reg_cmd, &w_data[0], byte_length);
			}
		} else {
			return len;
		}
	}

	return len;
}
static struct file_operations himax_proc_oppo_reg_read_ops = {
	.owner = THIS_MODULE,
	.read = himax_oppo_reg_read_read,
	.write = himax_oppo_reg_read_write,
};

int OPPO_proc_node_init(void)
{
			
	himax_proc_touchpanel_dir = proc_mkdir(HIMAX_PROC_TOUCHPANEL_FOLDER, NULL);

		if (himax_proc_touchpanel_dir == NULL) {
			E(" %s: himax_proc_touchpanel_dir file create failed!\n", __func__);
			return -ENOMEM;
		}
	
	himax_proc_oppo_reg_info_file = proc_create(HIMAX_PROC_OPPO_REG_INFO_FILE, (S_IWUSR | S_IRUGO),
								  himax_proc_touchpanel_dir, &himax_proc_oppo_reg_read_ops);
	if (himax_proc_oppo_reg_info_file == NULL) {
		E(" %s: proc oppo_reg_info file create failed!\n", __func__);
		goto fail_oppo_proc_0;
	}
	
	himax_proc_tp_fw_update_file = proc_create(HIMAX_PROC_TP_FW_UPDATE_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_tp_fw_update_ops);
	if (himax_proc_tp_fw_update_file == NULL) {
		E(" %s: proc tp_fw_update file create failed!\n", __func__);
		goto fail_oppo_proc_1;
	}
	
#ifdef HX_SMART_WAKEUP
#ifdef HX_GESTURE_TRACK
	himax_proc_coordinate_file = proc_create(HIMAX_PROC_COORDINATE_FILE, (S_IWUSR | S_IRUGO),
									  himax_proc_touchpanel_dir, &himax_proc_coor_ops);
	if (himax_proc_coordinate_file == NULL) {
		E(" %s: himax_proc_coordinate_file create failed!\n", __func__);
		goto fail_oppo_proc_2;
	}
#endif
	himax_proc_double_tap_en_file = proc_create(HIMAX_PROC_DOUBLE_TAP_EN_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_double_tap_en_ops);
	if (himax_proc_double_tap_en_file == NULL) {
		E(" %s: proc double_tap_en file create failed!\n", __func__);
		goto fail_oppo_proc_3;
	}
#endif	
	himax_proc_limit_enable_file = proc_create(HIMAX_PROC_LIMIT_ENABLE_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
										  himax_proc_touchpanel_dir, &hx_proc_limit_control_ops);

	if (himax_proc_limit_enable_file == NULL) {
		E(" %s: proc limit enable file create failed!\n", __func__);
		goto fail_oppo_proc_4;
	}
	himax_proc_limit_area_file = proc_create(HIMAX_PROC_LIMIT_AREA_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
										  himax_proc_touchpanel_dir, &proc_limit_area_ops);

	if (himax_proc_limit_area_file == NULL) {
		E(" %s: proc limit area file create failed!\n", __func__);
		goto fail_oppo_proc_5;
	}
	himax_proc_game_switch_en_file = proc_create(HIMAX_PROC_GAME_SWITCH_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
										  himax_proc_touchpanel_dir, &hx_proc_game_switch_ops);

	if (himax_proc_game_switch_en_file == NULL) {
		E(" %s: proc game switch en file create failed!\n", __func__);
		goto fail_oppo_proc_6;
	}
	
	himax_proc_oppo_tp_direction_file = proc_create(HIMAX_PROC_OPPO_TP_DIRECTION_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_oppo_tp_direction_ops);
	if (himax_proc_oppo_tp_direction_file == NULL) {
		E(" %s: proc oppo_tp_direction file create failed!\n", __func__);
		goto fail_oppo_proc_7;
	}

	himax_proc_incell_panel_file = proc_create(HIMAX_PROC_INCELL_PANEL_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_incell_panel_ops);
	if (himax_proc_incell_panel_file == NULL) {
		E(" %s: proc incell_panel file create failed!\n", __func__);
		goto fail_oppo_proc_8;
	}

	himax_proc_oppo_tx_hop_file = proc_create(HIMAX_PROC_OPPO_TX_HOP_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_oppo_tx_hop_ops);
	if (himax_proc_oppo_tx_hop_file == NULL) {
		E(" %s: proc tx freq change test create failed!\n", __func__);
		goto fail_oppo_proc_9;
	}	
	
	himax_proc_baseline_test_file = proc_create(HIMAX_PROC_BASELINE_TEST_FILE, (S_IRUGO), himax_proc_touchpanel_dir, &himax_proc_baseline_test_ops);
	if (himax_proc_baseline_test_file == NULL) {
		E(" %s: proc baseline_test file create failed!\n", __func__);
		goto fail_oppo_proc_10;
	}
	#if defined(HX_SMART_WAKEUP)
	himax_proc_backscreen_baseline_file = proc_create(HIMAX_PROC_BACKSCREEN_BASELINE_FILE, (S_IRUGO | S_IWUGO), himax_proc_touchpanel_dir, &himax_black_screen_test_fops);
	if (himax_proc_backscreen_baseline_file == NULL) {
		E(" %s create proc/touchpanel/blackscreen_test Failed!\n", __func__);
		goto fail_oppo_proc_11;
	}
	#endif
	himax_proc_irq_depth_file = proc_create(HIMAX_PROC_IRQ_DEPTH_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_irq_depth_ops);
	if (himax_proc_irq_depth_file == NULL) {
		E(" %s: proc incell_panel file create failed!\n", __func__);
		goto fail_oppo_proc_12;
	}

	himax_proc_oppo_debug_level_file = proc_create(HIMAX_PROC_OPPO_DEBUG_LEVEL_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_oppo_debug_level_ops);
	if (himax_proc_oppo_debug_level_file == NULL) {
		E(" %s: proc incell_panel file create failed!\n", __func__);
		goto fail_oppo_proc_13;
	}

	himax_proc_oppo_tp_usb_mode_file = proc_create(HIMAX_PROC_OPPO_TP_USB_MODE_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_oppo_tp_usb_mode_ops);
	if (himax_proc_oppo_tp_usb_mode_file == NULL) {
		E(" %s: proc oppo_tp_direction file create failed!\n", __func__);
		goto fail_oppo_proc_14;
	}

	himax_proc_oppo_tp_headset_mode_file = proc_create(HIMAX_PROC_OPPO_TP_HEADSET_MODE_FILE, (S_IWUSR | S_IRUGO | S_IWUGO),
								  himax_proc_touchpanel_dir, &himax_proc_oppo_tp_headset_mode_ops);
	if (himax_proc_oppo_tp_headset_mode_file == NULL) {
		E(" %s: proc oppo_tp_direction file create failed!\n", __func__);
		goto fail_oppo_proc_15;
	}
	himax_proc_debug_infor_dir = proc_mkdir(HIMAX_PROC_DEBUG_INFO_FOLDER, himax_proc_touchpanel_dir);

	if (himax_proc_debug_infor_dir!= NULL) {
		himax_proc_delta_o_file = proc_create(HIMAX_PROC_DELTA_O_FILE, (S_IWUSR | S_IRUGO),
									  himax_proc_debug_infor_dir, &himax_proc_delta_ops);
		if (himax_proc_delta_o_file == NULL) {
			E(" %s: proc dbg_info file create failed!\n", __func__);
			goto fail_oppo_proc_dbg_1;
		}

		himax_proc_baseline_O_file = proc_create(HIMAX_PROC_BASELINE_O_FILE, (S_IWUSR | S_IRUGO),
									  himax_proc_debug_infor_dir, &himax_proc_baseline_ops);
		if (himax_proc_baseline_O_file == NULL) {
			E(" %s: proc baseline file create failed!\n", __func__);
			goto fail_oppo_proc_dbg_2;
		}

		himax_proc_main_reg_file = proc_create(HIMAX_PROC_MAIN_REG_FILE, (S_IWUSR | S_IRUGO),
									  himax_proc_debug_infor_dir, &himax_proc_main_reg_ops);
		if (himax_proc_main_reg_file == NULL) {
			E(" %s: proc main_register file create failed!\n", __func__);
			goto fail_oppo_proc_dbg_3;
		}

		himax_proc_data_limit_file = proc_create(HIMAX_PROC_DATA_LIMIT_FILE, (S_IWUSR | S_IRUGO),
									  himax_proc_debug_infor_dir, &himax_proc_data_limit_ops);
		if (himax_proc_data_limit_file == NULL) {
			E(" %s: proc data_limit file create failed!\n", __func__);
			goto fail_oppo_proc_dbg_4;
		}
	} else {
		E(" %s: himax_proc_debug_infor_dir create failed!\n", __func__);
		goto fail_oppo_proc_dbg_0;
	}
	return 0;
fail_oppo_proc_dbg_4:
	remove_proc_entry(HIMAX_PROC_MAIN_REG_FILE, himax_proc_debug_infor_dir);
fail_oppo_proc_dbg_3:
	remove_proc_entry(HIMAX_PROC_BASELINE_O_FILE, himax_proc_debug_infor_dir);
fail_oppo_proc_dbg_2:
	remove_proc_entry(HIMAX_PROC_DELTA_O_FILE, himax_proc_debug_infor_dir);
fail_oppo_proc_dbg_1:
	remove_proc_entry(HIMAX_PROC_DEBUG_INFO_FOLDER, himax_proc_touchpanel_dir);
fail_oppo_proc_dbg_0:
	remove_proc_entry(HIMAX_PROC_OPPO_TP_HEADSET_MODE_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_15:
	remove_proc_entry(HIMAX_PROC_OPPO_TP_USB_MODE_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_14:
	remove_proc_entry(HIMAX_PROC_OPPO_DEBUG_LEVEL_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_13:
	remove_proc_entry(HIMAX_PROC_IRQ_DEPTH_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_12:
#if defined(HX_SMART_WAKEUP)
	remove_proc_entry(HIMAX_PROC_BACKSCREEN_BASELINE_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_11:
#endif
	remove_proc_entry(HIMAX_PROC_BASELINE_TEST_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_10:
	remove_proc_entry(HIMAX_PROC_OPPO_TX_HOP_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_9:
	remove_proc_entry(HIMAX_PROC_INCELL_PANEL_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_8:
	remove_proc_entry(HIMAX_PROC_OPPO_TP_DIRECTION_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_7:
	remove_proc_entry(HIMAX_PROC_GAME_SWITCH_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_6:
	remove_proc_entry(HIMAX_PROC_LIMIT_AREA_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_5:
	remove_proc_entry(HIMAX_PROC_LIMIT_ENABLE_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_4:
#ifdef HX_SMART_WAKEUP
	remove_proc_entry(HIMAX_PROC_DOUBLE_TAP_EN_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_3:
#ifdef HX_GESTURE_TRACK
	remove_proc_entry(HIMAX_PROC_COORDINATE_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_2:
#endif
#endif
	remove_proc_entry(HIMAX_PROC_TP_FW_UPDATE_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_1:
	remove_proc_entry(HIMAX_PROC_OPPO_REG_INFO_FILE, himax_proc_touchpanel_dir);
fail_oppo_proc_0:
	if( strcmp( HIMAX_PROC_TOUCHPANEL_FOLDER, HIMAX_PROC_TOUCH_FOLDER)!= 0  ){
		remove_proc_entry(HIMAX_PROC_TOUCHPANEL_FOLDER, NULL);
	}
	return -ENOMEM;

}

int OPPO_proc_node_deinit(void)
{
	remove_proc_entry(HIMAX_PROC_MAIN_REG_FILE, himax_proc_debug_infor_dir);
	remove_proc_entry(HIMAX_PROC_BASELINE_O_FILE, himax_proc_debug_infor_dir);
	remove_proc_entry(HIMAX_PROC_DELTA_O_FILE, himax_proc_debug_infor_dir);
	remove_proc_entry(HIMAX_PROC_DATA_LIMIT_FILE, himax_proc_debug_infor_dir);
	remove_proc_entry(HIMAX_PROC_DEBUG_INFO_FOLDER, himax_proc_touchpanel_dir);
	#if defined(HX_SMART_WAKEUP)
	remove_proc_entry(HIMAX_PROC_BACKSCREEN_BASELINE_FILE, himax_proc_touchpanel_dir);
	#endif
	remove_proc_entry(HIMAX_PROC_OPPO_DEBUG_LEVEL_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_IRQ_DEPTH_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_BASELINE_TEST_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_OPPO_TX_HOP_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_INCELL_PANEL_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_OPPO_TP_DIRECTION_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_GAME_SWITCH_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_LIMIT_AREA_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_LIMIT_ENABLE_FILE, himax_proc_touchpanel_dir);
#ifdef HX_SMART_WAKEUP
	remove_proc_entry(HIMAX_PROC_DOUBLE_TAP_EN_FILE, himax_proc_touchpanel_dir);
#ifdef HX_GESTURE_TRACK
	remove_proc_entry(HIMAX_PROC_COORDINATE_FILE, himax_proc_touchpanel_dir);
#endif
#endif
	remove_proc_entry(HIMAX_PROC_TP_FW_UPDATE_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_OPPO_REG_INFO_FILE, himax_proc_touchpanel_dir);
	remove_proc_entry(HIMAX_PROC_TOUCHPANEL_FOLDER, NULL);
	return -ENOMEM;
}

#if defined(HX_HIGH_SENSE)
static ssize_t himax_HSEN_read(struct file *file, char *buf,
		size_t len, loff_t *pos)
{
	struct himax_ts_data *ts = private_ts;
	size_t count = 0;
	char *temp_buf = NULL;

	if (!HX_PROC_SEND_FLAG) {
		temp_buf = kcalloc(len, sizeof(char), GFP_KERNEL);
		if (temp_buf != NULL) {
			count = snprintf(temp_buf, PAGE_SIZE, "%d\n",
					ts->HSEN_enable);

			if (copy_to_user(buf, temp_buf, len))
				I("%s, here:%d\n", __func__, __LINE__);

			kfree(temp_buf);
			HX_PROC_SEND_FLAG = 1;
		} else {
			E("%s, Failed to allocate memory\n", __func__);
		}
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return count;
}

static ssize_t himax_HSEN_write(struct file *file, const char *buff,
		size_t len, loff_t *pos)
{
	struct himax_ts_data *ts = private_ts;
	char buf[80] = {0};

	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len))
		return -EFAULT;

	if (buf[0] == '0')
		ts->HSEN_enable = 0;
	else if (buf[0] == '1')
		ts->HSEN_enable = 1;
	else
		return -EINVAL;

	g_core_fp.fp_set_HSEN_enable(ts->HSEN_enable, ts->suspended);
	I("%s: HSEN_enable = %d.\n", __func__, ts->HSEN_enable);
	return len;
}

static const struct file_operations himax_proc_HSEN_ops = {
	.owner = THIS_MODULE,
	.read = himax_HSEN_read,
	.write = himax_HSEN_write,
};
#endif

#if defined(HX_SMART_WAKEUP)
static ssize_t himax_SMWP_read(struct file *file, char *buf,
		size_t len, loff_t *pos)
{
	size_t count = 0;
	struct himax_ts_data *ts = private_ts;
	char *temp_buf = NULL;

	if (!HX_PROC_SEND_FLAG) {
		temp_buf = kcalloc(len, sizeof(char), GFP_KERNEL);
		if (temp_buf != NULL) {
			count = snprintf(temp_buf, PAGE_SIZE, "%d\n",
					ts->SMWP_enable);

			if (copy_to_user(buf, temp_buf, len))
				I("%s, here:%d\n", __func__, __LINE__);

			kfree(temp_buf);
			HX_PROC_SEND_FLAG = 1;
		} else {
			E("%s, Failed to allocate memory\n", __func__);
		}
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return count;
}

static ssize_t himax_SMWP_write(struct file *file, const char *buff,
		size_t len, loff_t *pos)
{
	struct himax_ts_data *ts = private_ts;
	char buf[80] = {0};

	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len))
		return -EFAULT;

	if (buf[0] == '0')
		ts->SMWP_enable = 0;
	else if (buf[0] == '1')
		ts->SMWP_enable = 1;
	else
		return -EINVAL;

	g_core_fp.fp_set_SMWP_enable(ts->SMWP_enable, ts->suspended);
	HX_SMWP_EN = ts->SMWP_enable;
	I("%s: SMART_WAKEUP_enable = %d.\n", __func__, HX_SMWP_EN);
	return len;
}

static const struct file_operations himax_proc_SMWP_ops = {
	.owner = THIS_MODULE,
	.read = himax_SMWP_read,
	.write = himax_SMWP_write,
};

static ssize_t himax_GESTURE_read(struct file *file, char *buf,
		size_t len, loff_t *pos)
{
	struct himax_ts_data *ts = private_ts;
	int i = 0;
	size_t ret = 0;
	char *temp_buf = NULL;

	if (!HX_PROC_SEND_FLAG) {
		temp_buf = kcalloc(len, sizeof(char), GFP_KERNEL);
		if (temp_buf != NULL) {
			for (i = 0; i < GEST_SUP_NUM; i++)
				ret += snprintf(temp_buf + ret, len - ret,
						"ges_en[%d]=%d\n",
						i, ts->gesture_cust_en[i]);

			if (copy_to_user(buf, temp_buf, len))
				I("%s, here:%d\n", __func__, __LINE__);

			kfree(temp_buf);
			HX_PROC_SEND_FLAG = 1;
		} else {
			E("%s, Failed to allocate memory\n", __func__);
		}
	} else {
		HX_PROC_SEND_FLAG = 0;
		ret = 0;
	}

	return ret;
}

static ssize_t himax_GESTURE_write(struct file *file, const char *buff,
		size_t len, loff_t *pos)
{
	struct himax_ts_data *ts = private_ts;
	int i = 0;
	int j = 0;
	char buf[80] = {0};

	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len))
		return -EFAULT;

	I("himax_GESTURE_store= %s, len = %d\n", buf, (int)len);

	for (i = 0; i < len; i++) {
		if (buf[i] == '0' && j < GEST_SUP_NUM) {
			ts->gesture_cust_en[j] = 0;
			I("gesture en[%d]=%d\n", j, ts->gesture_cust_en[j]);
			j++;
		} else if (buf[i] == '1' && j < GEST_SUP_NUM) {
			ts->gesture_cust_en[j] = 1;
			I("gesture en[%d]=%d\n", j, ts->gesture_cust_en[j]);
			j++;
		} else
			I("Not 0/1 or >=GEST_SUP_NUM : buf[%d] = %c\n",
				i, buf[i]);
	}

	return len;
}

static const struct file_operations himax_proc_Gesture_ops = {
	.owner = THIS_MODULE,
	.read = himax_GESTURE_read,
	.write = himax_GESTURE_write,
};

#if defined(HX_ULTRA_LOW_POWER)
static ssize_t himax_psensor_read(struct file *file, char *buf,
		size_t len, loff_t *pos)
{
	size_t count = 0;
	struct himax_ts_data *ts = private_ts;
	char *temp_buf = NULL;

	if (!HX_PROC_SEND_FLAG) {
		temp_buf = kcalloc(len, sizeof(char), GFP_KERNEL);
		if (temp_buf != NULL) {
			count = snprintf(temp_buf, PAGE_SIZE,
					"p-sensor flag = %d\n",
					ts->psensor_flag);

			if (copy_to_user(buf, temp_buf, len))
				I("%s, here:%d\n", __func__, __LINE__);

			kfree(temp_buf);
			HX_PROC_SEND_FLAG = 1;
		} else {
			E("%s, Failed to allocate memory\n", __func__);
		}
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return count;
}

static ssize_t himax_psensor_write(struct file *file, const char *buff,
		size_t len, loff_t *pos)
{
	struct himax_ts_data *ts = private_ts;
	char buf[80] = {0};

	if (len >= 80) {
		I("%s: no command exceeds 80 chars.\n", __func__);
		return -EFAULT;
	}

	if (copy_from_user(buf, buff, len))
		return -EFAULT;

	if (buf[0] == '0' && ts->SMWP_enable == 1) {
		ts->psensor_flag = false;
		g_core_fp.fp_black_gest_ctrl(false);
	} else if (buf[0] == '1' && ts->SMWP_enable == 1) {
		ts->psensor_flag = true;
		g_core_fp.fp_black_gest_ctrl(true);
	} else if (ts->SMWP_enable == 0) {
		I("%s: SMWP is disable, not supprot to ctrl p-sensor.\n",
			__func__);
	} else
		return -EINVAL;

	I("%s: psensor_flag = %d.\n", __func__, ts->psensor_flag);
	return len;
}

static const struct file_operations himax_proc_psensor_ops = {
	.owner = THIS_MODULE,
	.read = himax_psensor_read,
	.write = himax_psensor_write,
};
#endif
#endif

static ssize_t himax_vendor_read(struct file *file, char *buf,
				size_t len, loff_t *pos)
{
	ssize_t ret = 0;
	char *temp_buf = NULL;

	if (!HX_PROC_SEND_FLAG) {
		temp_buf = kcalloc(len, sizeof(char), GFP_KERNEL);
		ret += snprintf(temp_buf + ret, len - ret,
				"IC = %s\n", private_ts->chip_name);

		ret += snprintf(temp_buf + ret, len - ret,
				"FW_VER = 0x%2.2X\n", ic_data->vendor_fw_ver);

		if (private_ts->chip_cell_type == CHIP_IS_ON_CELL) {
			ret += snprintf(temp_buf + ret, len - ret,
					"CONFIG_VER = 0x%2.2X\n",
					ic_data->vendor_config_ver);
		} else {
			ret += snprintf(temp_buf + ret, len - ret,
					"TOUCH_VER = 0x%2.2X\n",
					ic_data->vendor_touch_cfg_ver);
			ret += snprintf(temp_buf + ret, len - ret,
					"DISPLAY_VER = 0x%2.2X\n",
					ic_data->vendor_display_cfg_ver);
		}

		if (ic_data->vendor_cid_maj_ver < 0
		&& ic_data->vendor_cid_min_ver < 0) {
			ret += snprintf(temp_buf + ret, len - ret,
					"CID_VER = NULL\n");
		} else {
			ret += snprintf(temp_buf + ret, len - ret,
					"CID_VER = 0x%2.2X\n",
					(ic_data->vendor_cid_maj_ver << 8 |
					ic_data->vendor_cid_min_ver));
		}

		if (ic_data->vendor_panel_ver < 0) {
			ret += snprintf(temp_buf + ret, len - ret,
					"PANEL_VER = NULL\n");
		} else {
			ret += snprintf(temp_buf + ret, len - ret,
					"PANEL_VER = 0x%2.2X\n",
					ic_data->vendor_panel_ver);
		}
		if (private_ts->chip_cell_type == CHIP_IS_IN_CELL) {
			ret += snprintf(temp_buf + ret, len - ret,
					"Cusomer = %s\n",
					ic_data->vendor_cus_info);
			ret += snprintf(temp_buf + ret, len - ret,
					"Project = %s\n",
					ic_data->vendor_proj_info);
		}
		ret += snprintf(temp_buf + ret, len - ret, "\n");
		ret += snprintf(temp_buf + ret, len - ret,
				"Himax Touch Driver Version:\n");
		ret += snprintf(temp_buf + ret, len - ret, "%s\n",
				HIMAX_DRIVER_VER);

		if (copy_to_user(buf, temp_buf, len))
			I("%s,here:%d\n", __func__, __LINE__);

		kfree(temp_buf);
		HX_PROC_SEND_FLAG = 1;
	} else {
		HX_PROC_SEND_FLAG = 0;
	}

	return ret;
}
static const struct file_operations himax_proc_vendor_ops = {
	.owner = THIS_MODULE,
	.read = himax_vendor_read,
};

int himax_common_proc_init(void)
{
#if defined(OPPO_PROC_NODE)	
		himax_touch_proc_dir = proc_mkdir(HIMAX_PROC_TOUCH_FOLDER, himax_proc_debug_infor_dir);

		if (himax_touch_proc_dir == NULL) {
			E(" %s: oppo himax_touch_proc_dir file create failed!\n", __func__);
			return -ENOMEM;
		}
#else
	himax_touch_proc_dir = proc_mkdir(HIMAX_PROC_TOUCH_FOLDER, NULL);

	if (himax_touch_proc_dir == NULL) {
		E(" %s: himax_touch_proc_dir file create failed!\n", __func__);
		return -ENOMEM;
	}
#endif	
	if (himax_touch_proc_dir == NULL) {
		E(" %s: himax_touch_proc_dir file create failed!\n", __func__);
		return -ENOMEM;
	}
/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_INSPECT)
	if (fp_himax_self_test_init != NULL)
		fp_himax_self_test_init();
#endif

	himax_proc_self_test_file = proc_create(HIMAX_PROC_SELF_TEST_FILE, 0444,
		himax_touch_proc_dir, &himax_proc_self_test_ops);
	if (himax_proc_self_test_file == NULL) {
		E(" %s: proc self_test file create failed!\n", __func__);
		goto fail_1;
	}

#if defined(HX_HIGH_SENSE)
	himax_proc_HSEN_file = proc_create(HIMAX_PROC_HSEN_FILE, 0666,
			himax_touch_proc_dir, &himax_proc_HSEN_ops);

	if (himax_proc_HSEN_file == NULL) {
		E(" %s: proc HSEN file create failed!\n", __func__);
		goto fail_2;
	}

#endif
#if defined(HX_SMART_WAKEUP)
	himax_proc_SMWP_file = proc_create(HIMAX_PROC_SMWP_FILE, 0666,
			himax_touch_proc_dir, &himax_proc_SMWP_ops);

	if (himax_proc_SMWP_file == NULL) {
		E(" %s: proc SMWP file create failed!\n", __func__);
		goto fail_3;
	}

	himax_proc_GESTURE_file = proc_create(HIMAX_PROC_GESTURE_FILE, 0666,
			himax_touch_proc_dir, &himax_proc_Gesture_ops);

	if (himax_proc_GESTURE_file == NULL) {
		E(" %s: proc GESTURE file create failed!\n", __func__);
		goto fail_4;
	}
#if defined(HX_ULTRA_LOW_POWER)
	himax_proc_psensor_file = proc_create(HIMAX_PROC_PSENSOR_FILE, 0666,
			himax_touch_proc_dir, &himax_proc_psensor_ops);

	if (himax_proc_psensor_file == NULL) {
		E(" %s: proc GESTURE file create failed!\n", __func__);
		goto fail_5;
	}
#endif
#endif
	himax_proc_vendor_file = proc_create(HIMAX_PROC_VENDOR_FILE, 0444,
		himax_touch_proc_dir, &himax_proc_vendor_ops);
	if (himax_proc_vendor_file == NULL) {
		E(" %s: proc vendor file create failed!\n", __func__);
		goto fail_6;
	}

	return 0;

	remove_proc_entry(HIMAX_PROC_VENDOR_FILE, himax_touch_proc_dir);
fail_6:
#if defined(HX_SMART_WAKEUP)
#if defined(HX_ULTRA_LOW_POWER)
	remove_proc_entry(HIMAX_PROC_PSENSOR_FILE, himax_touch_proc_dir);
fail_5:
#endif
	remove_proc_entry(HIMAX_PROC_GESTURE_FILE, himax_touch_proc_dir);
fail_4:
	remove_proc_entry(HIMAX_PROC_SMWP_FILE, himax_touch_proc_dir);
fail_3:
#endif
#if defined(HX_HIGH_SENSE)
	remove_proc_entry(HIMAX_PROC_HSEN_FILE, himax_touch_proc_dir);
fail_2:
#endif
	remove_proc_entry(HIMAX_PROC_SELF_TEST_FILE, himax_touch_proc_dir);
fail_1:
	return -ENOMEM;
}

void himax_common_proc_deinit(void)
{
	remove_proc_entry(HIMAX_PROC_VENDOR_FILE, himax_touch_proc_dir);
#if defined(HX_SMART_WAKEUP)
#if defined(HX_ULTRA_LOW_POWER)
	remove_proc_entry(HIMAX_PROC_PSENSOR_FILE, himax_touch_proc_dir);
#endif
	remove_proc_entry(HIMAX_PROC_GESTURE_FILE, himax_touch_proc_dir);
	remove_proc_entry(HIMAX_PROC_SMWP_FILE, himax_touch_proc_dir);
#endif
#if defined(HX_HIGH_SENSE)
	remove_proc_entry(HIMAX_PROC_HSEN_FILE, himax_touch_proc_dir);
#endif
	remove_proc_entry(HIMAX_PROC_SELF_TEST_FILE, himax_touch_proc_dir);

#if defined(OPPO_PROC_NODE)
	remove_proc_entry(HIMAX_PROC_TOUCH_FOLDER, himax_proc_touchpanel_dir);
#else
	remove_proc_entry(HIMAX_PROC_TOUCH_FOLDER, NULL);
#endif
}

/* File node for SMWP and HSEN - End*/

void himax_parse_assign_cmd(uint32_t addr, uint8_t *cmd, int len)
{
	/*I("%s: Entering!\n", __func__);*/

	switch (len) {
	case 1:
		cmd[0] = addr;
		/*I("%s: cmd[0] = 0x%02X\n", __func__, cmd[0]);*/
		break;

	case 2:
		cmd[0] = addr & 0xFF;
		cmd[1] = (addr >> 8) & 0xFF;
		/*I("%s: cmd[0] = 0x%02X,cmd[1] = 0x%02X\n",*/
		/*	__func__, cmd[0], cmd[1]);*/
		break;

	case 4:
		cmd[0] = addr & 0xFF;
		cmd[1] = (addr >> 8) & 0xFF;
		cmd[2] = (addr >> 16) & 0xFF;
		cmd[3] = (addr >> 24) & 0xFF;
		/*  I("%s: cmd[0] = 0x%02X,cmd[1] = 0x%02X,*/
		/*cmd[2] = 0x%02X,cmd[3] = 0x%02X\n", */
		/* __func__, cmd[0], cmd[1], cmd[2], cmd[3]);*/
		break;

	default:
		E("%s: input length fault,len = %d!\n", __func__, len);
	}
}
EXPORT_SYMBOL(himax_parse_assign_cmd);

int himax_input_register(struct himax_ts_data *ts)
{
	int ret = 0;
#if defined(HX_SMART_WAKEUP)
	int i = 0;
#endif
	ret = himax_dev_set(ts);
	if (ret < 0) {
		I("%s, input device register fail!\n", __func__);
		return INPUT_REGISTER_FAIL;
	}

	set_bit(EV_SYN, ts->input_dev->evbit);
	set_bit(EV_ABS, ts->input_dev->evbit);
	set_bit(EV_KEY, ts->input_dev->evbit);
	set_bit(KEY_BACK, ts->input_dev->keybit);
	set_bit(KEY_HOME, ts->input_dev->keybit);
	set_bit(KEY_MENU, ts->input_dev->keybit);
	set_bit(KEY_SEARCH, ts->input_dev->keybit);

#if defined(HX_SMART_WAKEUP)
	for (i = 0; i < GEST_SUP_NUM; i++)
		set_bit(gest_key_def[i], ts->input_dev->keybit);
/* for gki */
#elif (1) || defined(HX_PALM_REPORT)
// #elif defined(CONFIG_TOUCHSCREEN_HIMAX_INSPECT) || defined(HX_PALM_REPORT)
	set_bit(KEY_POWER, ts->input_dev->keybit);
#endif
	set_bit(BTN_TOUCH, ts->input_dev->keybit);
	set_bit(KEY_APPSELECT, ts->input_dev->keybit);
	set_bit(INPUT_PROP_DIRECT, ts->input_dev->propbit);
#if defined(HX_PROTOCOL_A)
	/*ts->input_dev->mtsize = ts->nFinger_support;*/
	input_set_abs_params(ts->input_dev, ABS_MT_TRACKING_ID, 1, 10, 0, 0);
#else
	set_bit(MT_TOOL_FINGER, ts->input_dev->keybit);
#if defined(HX_PROTOCOL_B_3PA)
	input_mt_init_slots(ts->input_dev, ts->nFinger_support,
			INPUT_MT_DIRECT);
#else
	input_mt_init_slots(ts->input_dev, ts->nFinger_support);
#endif
#endif
	I("input_set_abs_params: mix_x %d, max_x %d, min_y %d, max_y %d\n",
			ts->pdata->abs_x_min,
			ts->pdata->abs_x_max,
			ts->pdata->abs_y_min,
			ts->pdata->abs_y_max);
	input_set_abs_params(ts->input_dev, ABS_MT_POSITION_X,
			ts->pdata->abs_x_min, ts->pdata->abs_x_max,
			ts->pdata->abs_x_fuzz, 0);
	input_set_abs_params(ts->input_dev, ABS_MT_POSITION_Y,
			ts->pdata->abs_y_min, ts->pdata->abs_y_max,
			ts->pdata->abs_y_fuzz, 0);
	input_set_abs_params(ts->input_dev, ABS_MT_TOUCH_MAJOR,
			ts->pdata->abs_pressure_min,
			ts->pdata->abs_pressure_max,
			ts->pdata->abs_pressure_fuzz, 0);
#if !defined(HX_PROTOCOL_A)
	input_set_abs_params(ts->input_dev, ABS_MT_PRESSURE,
			ts->pdata->abs_pressure_min,
			ts->pdata->abs_pressure_max,
			ts->pdata->abs_pressure_fuzz, 0);
	input_set_abs_params(ts->input_dev, ABS_MT_WIDTH_MAJOR,
			ts->pdata->abs_width_min,
			ts->pdata->abs_width_max,
			ts->pdata->abs_pressure_fuzz, 0);
#endif
/*	input_set_abs_params(ts->input_dev, ABS_MT_AMPLITUDE, 0,*/
/*			((ts->pdata->abs_pressure_max << 16)*/
/*			| ts->pdata->abs_width_max),*/
/*			0, 0);*/
/*	input_set_abs_params(ts->input_dev, ABS_MT_POSITION,*/
/*			0, (BIT(31)*/
/*			| (ts->pdata->abs_x_max << 16)*/
/*			| ts->pdata->abs_y_max),*/
/*			0, 0);*/

	if (himax_input_register_device(ts->input_dev) == 0) {
		ret = NO_ERR;
	} else {
		E("%s: input register fail\n", __func__);
		input_free_device(ts->input_dev);
		return INPUT_REGISTER_FAIL;
	}

	if (!ic_data->HX_STYLUS_FUNC)
		goto skip_stylus_operation;

	set_bit(EV_SYN, ts->stylus_dev->evbit);
	set_bit(EV_ABS, ts->stylus_dev->evbit);
	set_bit(EV_KEY, ts->stylus_dev->evbit);
	set_bit(BTN_TOUCH, ts->stylus_dev->keybit);
	set_bit(INPUT_PROP_DIRECT, ts->stylus_dev->propbit);

	set_bit(BTN_TOOL_PEN, ts->stylus_dev->keybit);
	set_bit(BTN_TOOL_RUBBER, ts->stylus_dev->keybit);

	input_set_abs_params(ts->stylus_dev, ABS_PRESSURE, 0, 4095, 0, 0);
	input_set_abs_params(ts->stylus_dev, ABS_DISTANCE, 0, 1, 0, 0);
	input_set_abs_params(ts->stylus_dev, ABS_TILT_X, -60, 60, 0, 0);
	input_set_abs_params(ts->stylus_dev, ABS_TILT_Y, -60, 60, 0, 0);
	/*input_set_capability(ts->hx_pen_dev, EV_SW, SW_PEN_INSERT);*/
	input_set_capability(ts->stylus_dev, EV_KEY, BTN_TOUCH);
	input_set_capability(ts->stylus_dev, EV_KEY, BTN_STYLUS);
	input_set_capability(ts->stylus_dev, EV_KEY, BTN_STYLUS2);

	input_set_abs_params(ts->stylus_dev, ABS_X, ts->pdata->abs_x_min,
			((ts->pdata->abs_x_max+1)*ic_data->HX_STYLUS_RATIO-1),
			ts->pdata->abs_x_fuzz, 0);
	input_set_abs_params(ts->stylus_dev, ABS_Y, ts->pdata->abs_y_min,
			((ts->pdata->abs_y_max+1)*ic_data->HX_STYLUS_RATIO-1),
			ts->pdata->abs_y_fuzz, 0);

	if (himax_input_register_device(ts->stylus_dev) == 0) {
		ret = NO_ERR;
	} else {
		E("%s: input register stylus fail\n", __func__);
		input_unregister_device(ts->input_dev);
		input_free_device(ts->stylus_dev);
		return INPUT_REGISTER_FAIL;
	}

skip_stylus_operation:

	I("%s, input device registered.\n", __func__);

	return ret;
}
EXPORT_SYMBOL(himax_input_register);

#if defined(HX_BOOT_UPGRADE)
static int himax_get_fw_ver_bin(void)
{
	I("%s: use default incell address.\n", __func__);
	if (hxfw != NULL) {
		I("Catch fw version in bin file!\n");
		g_i_FW_VER = (hxfw->data[FW_VER_MAJ_FLASH_ADDR] << 8)
				| hxfw->data[FW_VER_MIN_FLASH_ADDR];
/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_INCELL)
		g_i_CFG_VER = (hxfw->data[CFG_VER_MAJ_FLASH_ADDR] << 8)
				| hxfw->data[CFG_VER_MIN_FLASH_ADDR];
#else
		g_i_CFG_VER = hxfw->data[CFG_VER_MAJ_FLASH_ADDR];
#endif
		g_i_CID_MAJ = hxfw->data[CID_VER_MAJ_FLASH_ADDR];
		g_i_CID_MIN = hxfw->data[CID_VER_MIN_FLASH_ADDR];
	} else {
		I("FW data is null!\n");
		return 1;
	}
	return NO_ERR;
}

static int himax_auto_update_check(void)
{
	int32_t ret;

	I("%s: Entering!\n", __func__);
	if (himax_get_fw_ver_bin() == 0) {
		if (((ic_data->vendor_fw_ver < g_i_FW_VER)
		|| (ic_data->vendor_config_ver < g_i_CFG_VER))) {
			I("%s: Need update\n", __func__);
			ret = 0;
		} else {
			I("%s: Need not update!\n", __func__);
			ret = 1;
		}
	} else {
		E("%s: FW bin fail!\n", __func__);
		ret = 1;
	}

	return ret;
}
#endif

#if defined(HX_BOOT_UPGRADE) || defined(HX_ZERO_FLASH)
static int i_get_FW(void)
{
	int ret = -1;
	int result = NO_ERR;
#if defined(OPPO_PROC_NODE)
	struct firmware *tmp_fw_entry = NULL;
	if (tmp_fw_entry == NULL) {
			tmp_fw_entry = kzalloc(sizeof(struct firmware), GFP_KERNEL);
		}
    if(tmp_fw_entry == NULL) {
        I("%s kzalloc is failed!\n", __func__);
		ret = MEM_ALLOC_FAIL;
        return ret;
    }
	if(!private_ts->recovery_mode){

                 I("%s:request fw ,name= %s\n", __func__,g_boot_upgrade_fwname);
                 ret = request_firmware(&hxfw, g_boot_upgrade_fwname, private_ts->dev);
                 if (ret < 0) {
                    E("%s,%d: request fw fail,and use i file , error code = %d\n", __func__, __LINE__, ret);
                    goto to_i_get_FW;
                 }
            private_ts->using_headfile = false;
            if (hxfw) {
                if (private_ts->g_fw_buf !=NULL) {
                private_ts->g_fw_len = hxfw->size;
                memcpy(private_ts->g_fw_buf, hxfw->data, hxfw->size);
                private_ts->g_fw_sta = true;
            	}
            }
	} else
to_i_get_FW:
	{
			if(private_ts->firmware_headfile.data != NULL){
				tmp_fw_entry->data = private_ts->firmware_headfile.data;
				tmp_fw_entry->size = private_ts->firmware_headfile.size;
				private_ts->using_headfile = true;
				hxfw = tmp_fw_entry;
				use_i_file_flag = 1;
				I("%s: recovery mode  ,so use i file!\n", __func__);
			} else {
				I("%s: firmware_data is NULL!!\n", __func__);
				result= OPEN_FILE_FAIL; 
				goto i_get_FW_FAIL;
			}
	}
#else
	ret = request_firmware(&hxfw, g_fw_boot_upgrade_name, private_ts->dev);
	I("%s: request file %s finished\n", __func__, g_fw_boot_upgrade_name);
	if (ret < 0) {
#if defined(HX_FIRMWARE_HEADER)
		if (get_fw_index(HX_FWTYPE_NORMAL) >= 0) {
			g_embedded_fw.data = gHimax_firmware_list[
					get_fw_index(HX_FWTYPE_NORMAL)];
			g_embedded_fw.size = gHimax_firmware_size[
					get_fw_index(HX_FWTYPE_NORMAL)];
			hxfw = &g_embedded_fw;
			I("%s: Not find FW, use Header FW(size:%zu)",
				__func__, g_embedded_fw.size);
			result = HX_EMBEDDED_FW;
		} else {
			E("%s,%d: error code = %d\n", __func__, __LINE__, ret);
			result = OPEN_FILE_FAIL;
		}
#else
		E("%s,%d: error code = %d\n", __func__, __LINE__, ret);
		result = OPEN_FILE_FAIL;
#endif
	}
#endif

i_get_FW_FAIL:
	return result;
}

static int i_update_FW(void)
{
	int upgrade_times = 0;
	int8_t ret = 0;
	int8_t result = 0;

update_retry:
#if defined(HX_ZERO_FLASH)
	ret = g_core_fp.fp_firmware_update_0f(hxfw, 0);
	if (ret != 0) {
		upgrade_times++;
		E("%s: TP upgrade error, upgrade_times = %d\n",
				__func__, upgrade_times);

		if (upgrade_times < 3)
			goto update_retry;
		else
			result = -1;

	} else {
		result = 1;/*upgrade success*/
		I("%s: TP upgrade OK\n", __func__);
	}

#else
	if (hxfw->size == FW_SIZE_32k)
		ret = g_core_fp.fp_fts_ctpm_fw_upgrade_with_sys_fs_32k(
			(unsigned char *)hxfw->data, hxfw->size, false);
	else if (hxfw->size == FW_SIZE_60k)
		ret = g_core_fp.fp_fts_ctpm_fw_upgrade_with_sys_fs_60k(
			(unsigned char *)hxfw->data, hxfw->size, false);
	else if (hxfw->size == FW_SIZE_64k)
		ret = g_core_fp.fp_fts_ctpm_fw_upgrade_with_sys_fs_64k(
			(unsigned char *)hxfw->data, hxfw->size, false);
	else if (hxfw->size == FW_SIZE_124k)
		ret = g_core_fp.fp_fts_ctpm_fw_upgrade_with_sys_fs_124k(
			(unsigned char *)hxfw->data, hxfw->size, false);
	else if (hxfw->size == FW_SIZE_128k)
		ret = g_core_fp.fp_fts_ctpm_fw_upgrade_with_sys_fs_128k(
			(unsigned char *)hxfw->data, hxfw->size, false);
	else if (hxfw->size == FW_SIZE_255k)
		ret = g_core_fp.fp_fts_ctpm_fw_upgrade_with_sys_fs_255k(
			(unsigned char *)hxfw->data, hxfw->size, false);

	if (ret == 0) {
		upgrade_times++;
		E("%s: TP upgrade error, upgrade_times = %d\n",
				__func__, upgrade_times);

		if (upgrade_times < 3)
			goto update_retry;
		else
			result = -1;

	} else {
		result = 1;/*upgrade success*/
		I("%s: TP upgrade OK\n", __func__);
	}
#endif
	return result;
}
#endif
/*
 *static int himax_loadSensorConfig(struct himax_platform_data *pdata)
 *{
 *	I("%s: initialization complete\n", __func__);
 *	return NO_ERR;
 *}
 */
#if defined(HX_EXCP_RECOVERY)
static void himax_excp_hw_reset(void)
{
#if defined(HX_ZERO_FLASH)
	int result = 0;
#endif
	I("%s: START EXCEPTION Reset\n", __func__);
#if defined(HX_ZERO_FLASH)
#if defined(HX_RST_PIN_FUNC)
			g_core_fp.fp_ic_reset(false, false);
#else
			g_core_fp.fp_system_reset();
#endif

	result = g_core_fp.fp_0f_op_file_dirly(g_fw_boot_upgrade_name);
#if defined(DD_VSN_RECOV_EXCP)	
if (result) {
		private_ts->update_fw_fail++;
		private_ts->update_fw_flag = 0;
		I("%s:himax  TP upgrade error, update_fw_fail = %d, update_fw_flag = %d\n", __func__, private_ts->update_fw_fail, private_ts->update_fw_flag);
	} else {
		private_ts->update_fw_fail = 0;
		private_ts->update_fw_flag++;
		I("%s: himax TP upgrade OK, update_fw_fail = %d, update_fw_flag = %d\n", __func__, private_ts->update_fw_fail, private_ts->update_fw_flag);
	}
#else
	if (result)
		E("%s: update FW fail, code[%d]!!\n", __func__, result);
#endif	
#else
	g_core_fp.fp_excp_ic_reset();
#endif
	himax_report_all_leave_event(private_ts);
	if (private_ts->diag_cmd != 0)
		g_core_fp.fp_diag_register_set(private_ts->diag_cmd,
			private_ts->diag_storage_type,
			private_ts->diag_dirly);
	I("%s: END EXCEPTION Reset\n", __func__);
}
#endif

#if defined(HX_SMART_WAKEUP)
#if defined(HX_GESTURE_TRACK)
static void gest_pt_log_coordinate(int rx, int tx)
{
	/*driver report x y with range 0 - 255 , we scale it up to x/y pixel*/
	gest_pt_x[gest_pt_cnt] = rx * (ic_data->HX_X_RES) / 255;
	gest_pt_y[gest_pt_cnt] = tx * (ic_data->HX_Y_RES) / 255;
}
#endif
static int himax_wake_event_parse(struct himax_ts_data *ts, int ts_status)
{
	uint8_t *buf = wake_event_buffer;
#if defined(HX_GESTURE_TRACK)
	int tmp_max_x = 0x00;
	int tmp_min_x = 0xFFFF;
	int tmp_max_y = 0x00;
	int tmp_min_y = 0xFFFF;
	int gest_len;
#endif
	int i = 0, check_FC = 0, ret;
	int j = 0, gesture_pos = 0, gesture_flag = 0;

	if (g_ts_dbg != 0)
		I("%s: Entering!, ts_status=%d\n", __func__, ts_status);

	if (buf == NULL) {
		ret = -ENOMEM;
		goto END;
	}

	memcpy(buf, hx_touch_data->hx_event_buf, hx_touch_data->event_size);

	for (i = 0; i < GEST_PTLG_ID_LEN; i++) {
		for (j = 0; j < GEST_SUP_NUM; j++) {
			if (buf[i] == gest_event[j]) {
				gesture_flag = buf[i];
				gesture_pos = j;
				break;
			}
		}
		I("0x%2.2X ", buf[i]);
		if (buf[i] == gesture_flag) {
			check_FC++;
		} else {
			I("ID START at %x , value = 0x%2X skip the event\n",
					i, buf[i]);
			break;
		}
	}

	I("Himax gesture_flag= %x\n", gesture_flag);
	I("Himax check_FC is %d\n", check_FC);

	if (check_FC != GEST_PTLG_ID_LEN) {
		ret = 0;
		goto END;
	}

	if (buf[GEST_PTLG_ID_LEN] != GEST_PTLG_HDR_ID1
	|| buf[GEST_PTLG_ID_LEN + 1] != GEST_PTLG_HDR_ID2) {
		ret = 0;
		goto END;
	}

#if defined(HX_GESTURE_TRACK)

	if (buf[GEST_PTLG_ID_LEN] == GEST_PTLG_HDR_ID1
	&& buf[GEST_PTLG_ID_LEN + 1] == GEST_PTLG_HDR_ID2) {
		gest_len = buf[GEST_PTLG_ID_LEN + 2];
		I("gest_len = %d\n", gest_len);
		i = 0;
		gest_pt_cnt = 0;
		I("gest doornidate start\n %s", __func__);

		while (i < (gest_len + 1) / 2) {
			gest_pt_log_coordinate(
					buf[GEST_PTLG_ID_LEN + 4 + i * 2],
					buf[GEST_PTLG_ID_LEN + 4 + i * 2 + 1]);
			i++;
			I("gest_pt_x[%d]=%d,gest_pt_y[%d]=%d\n",
				gest_pt_cnt,
				gest_pt_x[gest_pt_cnt],
				gest_pt_cnt,
				gest_pt_y[gest_pt_cnt]);
			gest_pt_cnt += 1;
		}

		if (gest_pt_cnt) {
			for (i = 0; i < gest_pt_cnt; i++) {
				if (tmp_max_x < gest_pt_x[i])
					tmp_max_x = gest_pt_x[i];
				if (tmp_min_x > gest_pt_x[i])
					tmp_min_x = gest_pt_x[i];
				if (tmp_max_y < gest_pt_y[i])
					tmp_max_y = gest_pt_y[i];
				if (tmp_min_y > gest_pt_y[i])
					tmp_min_y = gest_pt_y[i];
			}

			I("gest_point x_min=%d,x_max=%d,y_min=%d,y_max=%d\n",
				tmp_min_x, tmp_max_x, tmp_min_y, tmp_max_y);

			gest_start_x = gest_pt_x[0];
			hx_gesture_coor[0] = gest_start_x;
			gest_start_y = gest_pt_y[0];
			hx_gesture_coor[1] = gest_start_y;
			gest_end_x = gest_pt_x[gest_pt_cnt - 1];
			hx_gesture_coor[2] = gest_end_x;
			gest_end_y = gest_pt_y[gest_pt_cnt - 1];
			hx_gesture_coor[3] = gest_end_y;
			gest_width = tmp_max_x - tmp_min_x;
			hx_gesture_coor[4] = gest_width;
			gest_height = tmp_max_y - tmp_min_y;
			hx_gesture_coor[5] = gest_height;
			gest_mid_x = (tmp_max_x + tmp_min_x) / 2;
			hx_gesture_coor[6] = gest_mid_x;
			gest_mid_y = (tmp_max_y + tmp_min_y) / 2;
			hx_gesture_coor[7] = gest_mid_y;
			/*gest_up_x*/
			hx_gesture_coor[8] = gest_mid_x;
			/*gest_up_y*/
			hx_gesture_coor[9] = gest_mid_y - gest_height / 2;
			/*gest_down_x*/
			hx_gesture_coor[10] = gest_mid_x;
			/*gest_down_y*/
			hx_gesture_coor[11] = gest_mid_y + gest_height / 2;
			/*gest_left_x*/
			hx_gesture_coor[12] = gest_mid_x - gest_width / 2;
			/*gest_left_y*/
			hx_gesture_coor[13] = gest_mid_y;
			/*gest_right_x*/
			hx_gesture_coor[14] = gest_mid_x + gest_width / 2;
			/*gest_right_y*/
			hx_gesture_coor[15] = gest_mid_y;
		}
	}

#endif

	if (!ts->gesture_cust_en[gesture_pos]) {
		I("%s NOT report key [%d] = %d\n", __func__,
				gesture_pos, gest_key_def[gesture_pos]);
		g_target_report_data->SMWP_event_chk = 0;
		ret = 0;
	} else {
		g_target_report_data->SMWP_event_chk =
				gest_key_def[gesture_pos];
		ret = gesture_pos;
	}
END:
	return ret;
}

static void himax_wake_event_report(void)
{
	int KEY_EVENT = g_target_report_data->SMWP_event_chk;

	if (g_ts_dbg != 0)
		I("%s: Entering!\n", __func__);

	if (KEY_EVENT) {
		I("%s SMART WAKEUP KEY event %d press\n", __func__, KEY_EVENT);
		input_report_key(private_ts->input_dev, KEY_EVENT, 1);
		input_sync(private_ts->input_dev);
		I("%s SMART WAKEUP KEY event %d release\n",
				__func__, KEY_EVENT);
		input_report_key(private_ts->input_dev, KEY_EVENT, 0);
		input_sync(private_ts->input_dev);
#if defined(HX_GESTURE_TRACK)
		I("gest_start_x=%d,start_y=%d,end_x=%d,end_y=%d\n",
			gest_start_x,
			gest_start_y,
			gest_end_x,
			gest_end_y);
		I("gest_width=%d,height=%d,mid_x=%d,mid_y=%d\n",
			gest_width,
			gest_height,
			gest_mid_x,
			gest_mid_y);
		I("gest_up_x=%d,up_y=%d,down_x=%d,down_y=%d\n",
			hx_gesture_coor[8],
			hx_gesture_coor[9],
			hx_gesture_coor[10],
			hx_gesture_coor[11]);
		I("gest_left_x=%d,left_y=%d,right_x=%d,right_y=%d\n",
			hx_gesture_coor[12],
			hx_gesture_coor[13],
			hx_gesture_coor[14],
			hx_gesture_coor[15]);
#endif
		g_target_report_data->SMWP_event_chk = 0;
	}
}

#endif

int himax_report_data_init(void)
{
	if (hx_touch_data->hx_coord_buf != NULL) {
		kfree(hx_touch_data->hx_coord_buf);
		hx_touch_data->hx_coord_buf = NULL;
	}

	if (hx_touch_data->hx_rawdata_buf != NULL) {
		kfree(hx_touch_data->hx_rawdata_buf);
		hx_touch_data->hx_rawdata_buf = NULL;
	}

#if defined(HX_SMART_WAKEUP)
	hx_touch_data->event_size = g_core_fp.fp_get_touch_data_size();

	if (hx_touch_data->hx_event_buf != NULL) {
		kfree(hx_touch_data->hx_event_buf);
		hx_touch_data->hx_event_buf = NULL;
	}

	if (wake_event_buffer != NULL) {
		kfree(wake_event_buffer);
		wake_event_buffer = NULL;
	}

#endif

	if (g_target_report_data != NULL) {
		if (ic_data->HX_STYLUS_FUNC) {
			kfree(g_target_report_data->s);
			g_target_report_data->s = NULL;
		}

		kfree(g_target_report_data->p);
		g_target_report_data->p = NULL;
		kfree(g_target_report_data);
		g_target_report_data = NULL;
	}
	hx_touch_data->touch_all_size = HX_FULL_STACK_RAWDATA_SIZE;
	hx_touch_data->touch_all_size_full_stack =
		HX_FULL_STACK_RAWDATA_SIZE;
	hx_touch_data->touch_all_size_normal = g_core_fp.fp_get_touch_data_size();

	hx_touch_data->raw_cnt_max = ic_data->HX_MAX_PT / 4;
	hx_touch_data->raw_cnt_rmd = ic_data->HX_MAX_PT % 4;
	/* more than 4 fingers */
	if (hx_touch_data->raw_cnt_rmd != 0x00) {
		hx_touch_data->rawdata_size =
			g_core_fp.fp_cal_data_len(
				hx_touch_data->raw_cnt_rmd,
				ic_data->HX_MAX_PT,
				hx_touch_data->raw_cnt_max);

		hx_touch_data->touch_info_size = (ic_data->HX_MAX_PT
				+ hx_touch_data->raw_cnt_max + 2) * 4;
	} else { /* less than 4 fingers */
		hx_touch_data->rawdata_size =
			g_core_fp.fp_cal_data_len(
				hx_touch_data->raw_cnt_rmd,
				ic_data->HX_MAX_PT,
				hx_touch_data->raw_cnt_max);

		hx_touch_data->touch_info_size = (ic_data->HX_MAX_PT
				+ hx_touch_data->raw_cnt_max + 1) * 4;
	}

	if (ic_data->HX_STYLUS_FUNC) {
		hx_touch_data->touch_info_size += STYLUS_INFO_SZ;
		hx_touch_data->rawdata_size -= STYLUS_INFO_SZ;
	}
	hx_touch_data->rawdata_size_normal =
		hx_touch_data->rawdata_size;
	hx_touch_data->rawdata_size =
		hx_touch_data->touch_all_size - HX_STACK_ORG_LEN;
	hx_touch_data->rawdata_size_full_stack =
		hx_touch_data->touch_all_size - HX_STACK_ORG_LEN;

	if ((ic_data->HX_TX_NUM
	* ic_data->HX_RX_NUM
	+ ic_data->HX_TX_NUM
	+ ic_data->HX_RX_NUM)
	% hx_touch_data->rawdata_size == 0)
		hx_touch_data->rawdata_frame_size =
			(ic_data->HX_TX_NUM
			* ic_data->HX_RX_NUM
			+ ic_data->HX_TX_NUM
			+ ic_data->HX_RX_NUM)
			/ hx_touch_data->rawdata_size;
	else
		hx_touch_data->rawdata_frame_size =
			(ic_data->HX_TX_NUM
			* ic_data->HX_RX_NUM
			+ ic_data->HX_TX_NUM
			+ ic_data->HX_RX_NUM)
			/ hx_touch_data->rawdata_size
			+ 1;

	I("%s:rawdata_fsz = %d,HX_MAX_PT:%d,hx_raw_cnt_max:%d\n",
		__func__,
		hx_touch_data->rawdata_frame_size,
		ic_data->HX_MAX_PT,
		hx_touch_data->raw_cnt_max);
	I("%s:hx_raw_cnt_rmd:%d,g_hx_rawdata_size:%d,touch_info_size:%d\n",
		__func__,
		hx_touch_data->raw_cnt_rmd,
		hx_touch_data->rawdata_size,
		hx_touch_data->touch_info_size);

	hx_touch_data->hx_coord_buf = kzalloc(sizeof(uint8_t)
			* (hx_touch_data->touch_info_size),
			GFP_KERNEL);

	if (hx_touch_data->hx_coord_buf == NULL)
		goto mem_alloc_fail_coord_buf;

#if defined(HX_SMART_WAKEUP)
	wake_event_buffer = kcalloc(hx_touch_data->event_size,
			sizeof(uint8_t), GFP_KERNEL);
	if (wake_event_buffer == NULL)
		goto mem_alloc_fail_smwp;

	hx_touch_data->hx_event_buf = kzalloc(sizeof(uint8_t)
			* (hx_touch_data->event_size), GFP_KERNEL);
	if (hx_touch_data->hx_event_buf == NULL)
		goto mem_alloc_fail_event_buf;
#endif

	hx_touch_data->hx_rawdata_buf = kzalloc(sizeof(uint8_t)
		* (hx_touch_data->touch_all_size
		- HX_STACK_ORG_LEN),
		GFP_KERNEL);
	if (hx_touch_data->hx_rawdata_buf == NULL)
		goto mem_alloc_fail_rawdata_buf;

	if (g_target_report_data == NULL) {
		g_target_report_data =
			kzalloc(sizeof(struct himax_target_report_data),
			GFP_KERNEL);
		if (g_target_report_data == NULL)
			goto mem_alloc_fail_report_data;
/*
 *#if defined(HX_SMART_WAKEUP)
 *		g_target_report_data->SMWP_event_chk = 0;
 *#endif
 *		I("%s: SMWP_event_chk = %d\n", __func__,
 *			g_target_report_data->SMWP_event_chk);
 */

		g_target_report_data->p = kzalloc(
			sizeof(struct himax_target_point_data)
			*(ic_data->HX_MAX_PT), GFP_KERNEL);
		if (g_target_report_data->p == NULL)
			goto mem_alloc_fail_report_data_p;

		if (!ic_data->HX_STYLUS_FUNC)
			goto skip_stylus_operation;

		g_target_report_data->s = kzalloc(
			sizeof(struct himax_target_stylus_data)*2, GFP_KERNEL);
		if (g_target_report_data->s == NULL)
			goto mem_alloc_fail_report_data_s;
	}

skip_stylus_operation:
	hx_touch_data->touch_all_size =
		hx_touch_data->touch_all_size_normal;
	hx_touch_data->rawdata_size =
		hx_touch_data->rawdata_size_normal;
	return NO_ERR;

mem_alloc_fail_report_data_s:
	kfree(g_target_report_data->p);
	g_target_report_data->p = NULL;
mem_alloc_fail_report_data_p:
	kfree(g_target_report_data);
	g_target_report_data = NULL;
mem_alloc_fail_report_data:
	kfree(hx_touch_data->hx_rawdata_buf);
	hx_touch_data->hx_rawdata_buf = NULL;
mem_alloc_fail_rawdata_buf:
#if defined(HX_SMART_WAKEUP)
	kfree(hx_touch_data->hx_event_buf);
	hx_touch_data->hx_event_buf = NULL;
mem_alloc_fail_event_buf:
	kfree(wake_event_buffer);
	wake_event_buffer = NULL;
mem_alloc_fail_smwp:
#endif
	kfree(hx_touch_data->hx_coord_buf);
	hx_touch_data->hx_coord_buf = NULL;
mem_alloc_fail_coord_buf:

	E("%s: Failed to allocate memory\n", __func__);
	return MEM_ALLOC_FAIL;
}
EXPORT_SYMBOL(himax_report_data_init);

void himax_report_data_deinit(void)
{
	if (ic_data->HX_STYLUS_FUNC) {
		kfree(g_target_report_data->s);
		g_target_report_data->s = NULL;
	}

	kfree(g_target_report_data->p);
	g_target_report_data->p = NULL;
	kfree(g_target_report_data);
	g_target_report_data = NULL;

#if defined(HX_SMART_WAKEUP)
	kfree(wake_event_buffer);
	wake_event_buffer = NULL;
	kfree(hx_touch_data->hx_event_buf);
	hx_touch_data->hx_event_buf = NULL;
#endif
	kfree(hx_touch_data->hx_rawdata_buf);
	hx_touch_data->hx_rawdata_buf = NULL;
	kfree(hx_touch_data->hx_coord_buf);
	hx_touch_data->hx_coord_buf = NULL;
}

/*start ts_work*/
#if defined(HX_USB_DETECT_GLOBAL)
void himax_cable_detect_func(bool force_renew)
{
	struct himax_ts_data *ts;

	/*u32 connect_status = 0;*/
	uint8_t connect_status = 0;

	connect_status = USB_detect_flag;/* upmu_is_chr_det(); */
	ts = private_ts;

	/* I("Touch: cable status=%d, cable_config=%p, usb_connected=%d\n",*/
	/*		connect_status, ts->cable_config, ts->usb_connected); */
	if (ts->cable_config) {
		if ((connect_status != ts->usb_connected) || force_renew) {
			if (connect_status) {
				ts->cable_config[1] = 0x01;
				ts->usb_connected = 0x01;
			} else {
				ts->cable_config[1] = 0x00;
				ts->usb_connected = 0x00;
			}

			g_core_fp.fp_usb_detect_set(ts->cable_config);
			I("%s: Cable status change: 0x%2.2X\n", __func__,
					ts->usb_connected);
		}

		/*else*/
		/*	I("%s: Cable status is the same as*/
		/*		previous one, ignore.\n", __func__);*/
	}
}
#endif

static int himax_ts_work_status(struct himax_ts_data *ts)
{
	/* 1: normal, 2:SMWP */
	int result = HX_REPORT_COORD;

	hx_touch_data->diag_cmd = ts->diag_cmd;
	if (hx_touch_data->diag_cmd)
		result = HX_REPORT_COORD_RAWDATA;

#if defined(HX_SMART_WAKEUP)
	if (atomic_read(&ts->suspend_mode)
	&& (ts->SMWP_enable)
	&& (!hx_touch_data->diag_cmd))
		result = HX_REPORT_SMWP_EVENT;
#endif
	/* I("Now Status is %d\n", result); */
	return result;
}

static int himax_touch_get(struct himax_ts_data *ts, uint8_t *buf,
		int ts_path, int ts_status)
{
	uint32_t read_size = 0;

	if (g_ts_dbg != 0){
		I("%s: Entering, ts_status=%d!\n", __func__, ts_status);
		I("%s: Max Size=%d\n", __func__, hx_touch_data->touch_all_size);
	}


	switch (ts_path) {
	/*normal*/
	case HX_REPORT_COORD:
		if ((HX_HW_RESET_ACTIVATE)
#if defined(HX_EXCP_RECOVERY)
			|| (HX_EXCP_RESET_ACTIVATE)
#endif
			) {
			read_size = hx_touch_data->touch_all_size;
		} else {
			read_size = hx_touch_data->touch_info_size;
		}
		break;
#if defined(HX_SMART_WAKEUP)

	/*SMWP*/
	case HX_REPORT_SMWP_EVENT:
		__pm_wakeup_event(ts->ts_SMWP_wake_lock, TS_WAKE_LOCK_TIMEOUT);
		msleep(20);

		read_size = hx_touch_data->event_size;
		break;
#endif
	case HX_REPORT_COORD_RAWDATA:
		read_size = hx_touch_data->touch_all_size;
		break;
	default:
		break;
	}
	if (read_size == 0) {
		E("%s: Read size fault!\n", __func__);
		ts_status = HX_TS_GET_DATA_FAIL;
	} else {
		if (!g_core_fp.fp_read_event_stack(buf, read_size)) {
			E("%s: can't read data from chip!\n", __func__);
			ts_status = HX_TS_GET_DATA_FAIL;
		}
	}
	return ts_status;
}

/* start error_control*/
static int himax_checksum_cal(struct himax_ts_data *ts, uint8_t *buf,
		int ts_path, int ts_status)
{
	uint16_t check_sum_cal = 0;
	int32_t	i = 0;
	int length = 0;
	int zero_cnt = 0;
	int raw_data_sel = 0;
	int ret_val = ts_status;

	if (g_ts_dbg != 0)
		I("%s: Entering, ts_status=%d!\n", __func__, ts_status);

	/* Normal */
	switch (ts_path) {
	case HX_REPORT_COORD:
		length = hx_touch_data->touch_info_size;
		break;
#if defined(HX_SMART_WAKEUP)
/* SMWP */
	case HX_REPORT_SMWP_EVENT:
		length = (GEST_PTLG_ID_LEN + GEST_PTLG_HDR_LEN);
		break;
#endif
	case HX_REPORT_COORD_RAWDATA:
		length = hx_touch_data->touch_info_size;
		break;
	default:
		I("%s, Neither Normal Nor SMWP error!\n", __func__);
		ret_val = HX_PATH_FAIL;
		goto END_FUNCTION;
	}

	for (i = 0; i < length; i++) {
		check_sum_cal += buf[i];
		if (buf[i] == 0x00)
			zero_cnt++;
	}

	if (check_sum_cal % 0x100 != 0) {
		I("point data_checksum not match check_sum_cal: 0x%02X",
			check_sum_cal);
		ret_val = HX_CHKSUM_FAIL;
	} else if (zero_cnt == length) {
		if (ts->use_irq)
			I("[HIMAX TP MSG] All Zero event\n");

		ret_val = HX_CHKSUM_FAIL;
	} else {
		raw_data_sel = buf[HX_TOUCH_INFO_POINT_CNT]>>4 & 0x0F;
		/*I("%s:raw_out_sel=%x , hx_touch_data->diag_cmd=%x.\n",*/
		/*		__func__, raw_data_sel,*/
		/*		hx_touch_data->diag_cmd);*/
		/*raw data out not match skip it*/
		if (!debug_data->
			is_stack_full_raw) {
		if ((raw_data_sel != 0x0F)
		&& (raw_data_sel != hx_touch_data->diag_cmd)) {
			/*I("%s:raw data out not match.\n", __func__);*/
			if (!hx_touch_data->diag_cmd) {
				/*Need to clear event stack here*/
				g_core_fp.fp_read_event_stack(buf,
					(128-hx_touch_data->touch_info_size));
				/*I("%s: size =%d, buf[0]=%x ,buf[1]=%x,*/
				/*	buf[2]=%x, buf[3]=%x.\n",*/
				/*	__func__,*/
				/*	(128-hx_touch_data->touch_info_size),*/
				/*	buf[0], buf[1], buf[2], buf[3]);*/
				/*I("%s:also clear event stack.\n", __func__);*/
			}
			ret_val = HX_READY_SERVE;
			}
		}
	}

END_FUNCTION:
	if (g_ts_dbg != 0)
		I("%s: END, ret_val=%d!\n", __func__, ret_val);
	return ret_val;
}

#if defined(HX_EXCP_RECOVERY)
#if defined(HW_ED_EXCP_EVENT)
static int himax_ts_event_check(struct himax_ts_data *ts,
		uint8_t *buf, int ts_path, int ts_status)
{
	uint32_t hx_EB_event = 0;
	uint32_t hx_EC_event = 0;
	uint32_t hx_EE_event = 0;
	uint32_t hx_ED_event = 0;
	uint32_t hx_excp_event = 0;
	int shaking_ret = 0;

	uint32_t i = 0;
	uint32_t length = 0;
	int ret_val = ts_status;

	if (g_ts_dbg != 0)
		I("%s: Entering, ts_status=%d!\n", __func__, ts_status);

	/* Normal */
	switch (ts_path) {
	case HX_REPORT_COORD:
		length = hx_touch_data->touch_info_size;
		break;
#if defined(HX_SMART_WAKEUP)
	/* SMWP */
	case HX_REPORT_SMWP_EVENT:
		length = (GEST_PTLG_ID_LEN + GEST_PTLG_HDR_LEN);
		break;
#endif
	case HX_REPORT_COORD_RAWDATA:
		length = hx_touch_data->touch_info_size;
		break;
	default:
		I("%s, Neither Normal Nor SMWP error!\n", __func__);
		ret_val = HX_PATH_FAIL;
		goto END_FUNCTION;
	}

	if (g_ts_dbg != 0)
		I("Now Path=%d, Now status=%d, length=%d\n",
				ts_path, ts_status, length);

	if (ts_path == HX_REPORT_COORD || ts_path == HX_REPORT_COORD_RAWDATA) {
		if (ic_data->HX_STYLUS_FUNC)
			length -= STYLUS_INFO_SZ;
		for (i = 0; i < length; i++) {
			/* case 1 EXCEEPTION recovery flow */
			if (buf[i] == 0xEB) {
				hx_EB_event++;
			} else if (buf[i] == 0xEC) {
				hx_EC_event++;
			} else if (buf[i] == 0xEE) {
				hx_EE_event++;
			/* case 2 EXCEPTION recovery flow-Disable */
			} else if (buf[i] == 0xED) {
				hx_ED_event++;
			} else {
				g_zero_event_count = 0;
				break;
			}
		}
	}

	if (hx_EB_event == length) {
		hx_excp_event = length;
		hx_EB_event_flag++;
		I("[HIMAX TP MSG]: EXCEPTION event checked - ALL 0xEB.\n");
	} else if (hx_EC_event == length) {
		hx_excp_event = length;
		hx_EC_event_flag++;
		I("[HIMAX TP MSG]: EXCEPTION event checked - ALL 0xEC.\n");
	} else if (hx_EE_event == length) {
		hx_excp_event = length;
		hx_EE_event_flag++;
		I("[HIMAX TP MSG]: EXCEPTION event checked - ALL 0xEE.\n");
	} else if (hx_ED_event == length) {
		g_core_fp.fp_0f_reload_to_active();
	}

	if ((hx_excp_event == length || hx_ED_event == length)
		&& (HX_HW_RESET_ACTIVATE == 0)
		&& (HX_EXCP_RESET_ACTIVATE == 0)
		&& (HX_EXCP_DD_RESET_ACTIVATE == 0)
		&& (hx_touch_data->diag_cmd == 0)) {
		shaking_ret = g_core_fp.fp_ic_excp_recovery(
			hx_excp_event, hx_ED_event, length);

		if (shaking_ret == HX_EXCP_EVENT) {
			g_core_fp.fp_read_FW_status();
			himax_excp_hw_reset();
			ret_val = HX_EXCP_EVENT;
		} else if (shaking_ret == HX_ZERO_EVENT_COUNT) {
			g_core_fp.fp_read_FW_status();
			ret_val = HX_ZERO_EVENT_COUNT;
		} else {
			I("IC is running. Nothing to be done!\n");
			ret_val = HX_IC_RUNNING;
		}

	/* drop 1st interrupts after chip reset */
	} else if (HX_EXCP_RESET_ACTIVATE) {
		HX_EXCP_RESET_ACTIVATE = 0;
		I("%s: Skip by HX_EXCP_RESET_ACTIVATE.\n", __func__);
		ret_val = HX_EXCP_REC_OK;
	}

END_FUNCTION:
	if (g_ts_dbg != 0)
		I("%s: END, ret_val=%d!\n", __func__, ret_val);

	return ret_val;
}

#else
static int himax_ts_event_check(struct himax_ts_data *ts,
		uint8_t *buf, int ts_path, int ts_status)
{
	uint32_t hx_EB_event = 0;
	uint32_t hx_EC_event = 0;
	uint32_t hx_ED_event = 0;
	uint32_t hx_excp_event = 0;
	uint32_t hx_zero_event = 0;
	int shaking_ret = 0;

	uint32_t i = 0;
	uint32_t length = 0;
	int ret_val = ts_status;

	if (g_ts_dbg != 0)
		I("%s: Entering, ts_status=%d!\n", __func__, ts_status);

	/* Normal */
	switch (ts_path) {
	case HX_REPORT_COORD:
		length = hx_touch_data->touch_info_size;
		break;
#if defined(HX_SMART_WAKEUP)
/* SMWP */
	case HX_REPORT_SMWP_EVENT:
		length = (GEST_PTLG_ID_LEN + GEST_PTLG_HDR_LEN);
		break;
#endif
	case HX_REPORT_COORD_RAWDATA:
		length = hx_touch_data->touch_info_size;
		break;
	default:
		I("%s, Neither Normal Nor SMWP error!\n", __func__);
		ret_val = HX_PATH_FAIL;
		goto END_FUNCTION;
	}

	if (g_ts_dbg != 0)
		I("Now Path=%d, Now status=%d, length=%d\n",
				ts_path, ts_status, length);

	if (ts_path == HX_REPORT_COORD || ts_path == HX_REPORT_COORD_RAWDATA) {
		if (ic_data->HX_STYLUS_FUNC)
			length -= STYLUS_INFO_SZ;
		for (i = 0; i < length; i++) {
			/* case 1 EXCEEPTION recovery flow */
			if (buf[i] == 0xEB) {
				hx_EB_event++;
			} else if (buf[i] == 0xEC) {
				hx_EC_event++;
			} else if (buf[i] == 0xED) {
				hx_ED_event++;

			/* case 2 EXCEPTION recovery flow-Disable */
			} else if (buf[i] == 0x00) {
				hx_zero_event++;
			} else {
				g_zero_event_count = 0;
				break;
			}
		}
	}

	if (hx_EB_event == length) {
		hx_excp_event = length;
		hx_EB_event_flag++;
		I("[HIMAX TP MSG]: EXCEPTION event checked - ALL 0xEB.\n");
	} else if (hx_EC_event == length) {
		hx_excp_event = length;
		hx_EC_event_flag++;
		I("[HIMAX TP MSG]: EXCEPTION event checked - ALL 0xEC.\n");
	} else if (hx_ED_event == length) {
		hx_excp_event = length;
		hx_ED_event_flag++;
		I("[HIMAX TP MSG]: EXCEPTION event checked - ALL 0xED.\n");
	}
/*#if defined(HX_ZERO_FLASH)
 *	//This is for previous version(a, b) because HW pull TSIX
 *		low continuely after watchdog timeout reset
 *	else if (hx_zero_event == length) {
 *		//check zero flash status
 *		if (g_core_fp.fp_0f_esd_check() < 0) {
 *			g_zero_event_count = 6;
 *			I("[HIMAX TP MSG]: ESD event checked
				- ALL Zero in ZF.\n");
 *		} else {
 *			I("[HIMAX TP MSG]: Status check pass in ZF.\n");
 *		}
 *	}
 *#endif
 */

	if ((hx_excp_event == length || hx_zero_event == length)
		&& (HX_HW_RESET_ACTIVATE == 0)
		&& (HX_EXCP_DD_RESET_ACTIVATE == 0)
		&& (HX_EXCP_RESET_ACTIVATE == 0)) {
		shaking_ret = g_core_fp.fp_ic_excp_recovery(
			hx_excp_event, hx_zero_event, length);

		if (shaking_ret == HX_EXCP_EVENT ||
			shaking_ret == HX_EXCP_ZERO_EVENT ) {
			g_core_fp.fp_read_FW_status();
			himax_excp_hw_reset();
#if defined(DD_VSN_RECOV_EXCP)
			if (private_ts->update_fw_fail == 3) {
				private_ts->update_fw_fail = 0;
				private_ts->vsn_flag = 1;
				// himax_mcu_vsn_recovery();//VSN OFF
				himax_mcu_vsn_recovery_flag = 1;
			}

			if (private_ts->vsn_flag == 1) {
				//vsn_flag = 0;
				if (private_ts->update_fw_flag == 4) {
					private_ts->update_fw_flag = 0;
					g_core_fp._ic_excp_dd_recovery();
				}
			}
#endif
			ret_val = HX_EXCP_EVENT;
		// } else if (shaking_ret == HX_EXCP_ZERO_DD_EVENT) {
		// 	g_core_fp._ic_excp_dd_recovery();
		// 	ret_val = HX_EXCP_EVENT;
		} else if (shaking_ret == HX_ZERO_EVENT_COUNT) {
			g_core_fp.fp_read_FW_status();
			ret_val = HX_ZERO_EVENT_COUNT;
		} else {
			I("IC is running. Nothing to be done!\n");
			ret_val = HX_IC_RUNNING;
		}

	/* drop 1st interrupts after chip reset */
	} else if (HX_EXCP_RESET_ACTIVATE) {
		HX_EXCP_RESET_ACTIVATE = 0;
		I("%s: Skip by HX_EXCP_RESET_ACTIVATE.\n", __func__);
		ret_val = HX_EXCP_REC_OK;
	}

END_FUNCTION:
	if (g_ts_dbg != 0)
		I("%s: END, ret_val=%d!\n", __func__, ret_val);

	return ret_val;
}
#endif
#endif

static int himax_err_ctrl(struct himax_ts_data *ts,
		uint8_t *buf, int ts_path, int ts_status)
{
#if defined(HX_RST_PIN_FUNC)
	if (HX_HW_RESET_ACTIVATE) {
		/* drop 1st interrupts after chip reset */
		HX_HW_RESET_ACTIVATE = 0;
		I("[HX_HW_RESET_ACTIVATE]%s:Back from reset,ready to serve.\n",
				__func__);
		ts_status = HX_RST_OK;
		goto END_FUNCTION;
	}
#endif

	ts_status = himax_checksum_cal(ts, buf, ts_path, ts_status);
	if (ts_status == HX_CHKSUM_FAIL) {
		goto CHK_FAIL;
	} else {
#if defined(HX_EXCP_RECOVERY)
		/* continuous N times record, not total N times. */
		g_zero_event_count = 0;
#endif
		goto END_FUNCTION;
	}

CHK_FAIL:
#if defined(HX_EXCP_RECOVERY)
	ts_status = himax_ts_event_check(ts, buf, ts_path, ts_status);
#endif

END_FUNCTION:
	if (g_ts_dbg != 0)
		I("%s: END, ts_status=%d!\n", __func__, ts_status);
	return ts_status;
}
/* end error_control*/

/* start distribute_data*/
static int himax_distribute_touch_data(uint8_t *buf,
		int ts_path, int ts_status)
{
	uint8_t hx_state_info_pos = hx_touch_data->touch_info_size - 3;

	if (ic_data->HX_STYLUS_FUNC)
		hx_state_info_pos -= STYLUS_INFO_SZ;

	if (g_ts_dbg != 0)
		I("%s: Entering, ts_status=%d!\n", __func__, ts_status);

	if (ts_path == HX_REPORT_COORD) {
		memcpy(hx_touch_data->hx_coord_buf, &buf[0],
				hx_touch_data->touch_info_size);

		if (buf[hx_state_info_pos] != 0xFF
		&& buf[hx_state_info_pos + 1] != 0xFF)
			memcpy(hx_touch_data->hx_state_info,
					&buf[hx_state_info_pos], 2);
		else
			memset(hx_touch_data->hx_state_info, 0x00,
					sizeof(hx_touch_data->hx_state_info));

		if ((HX_HW_RESET_ACTIVATE)
#if defined(HX_EXCP_RECOVERY)
		|| (HX_EXCP_RESET_ACTIVATE)
#endif
		) {
			if (!debug_data->
				is_stack_full_raw) {
			memcpy(hx_touch_data->hx_rawdata_buf,
					&buf[hx_touch_data->touch_info_size],
					hx_touch_data->touch_all_size
					- hx_touch_data->touch_info_size);
			}else{
				memcpy(hx_touch_data->hx_rawdata_buf,
						&buf[HX_STACK_ORG_LEN],
						hx_touch_data->touch_all_size
						- HX_STACK_ORG_LEN);
			}
		}
	} else if (ts_path == HX_REPORT_COORD_RAWDATA) {
		memcpy(hx_touch_data->hx_coord_buf, &buf[0],
				hx_touch_data->touch_info_size);

		if (buf[hx_state_info_pos] != 0xFF
		&& buf[hx_state_info_pos + 1] != 0xFF)
			memcpy(hx_touch_data->hx_state_info,
					&buf[hx_state_info_pos], 2);
		else
			memset(hx_touch_data->hx_state_info, 0x00,
					sizeof(hx_touch_data->hx_state_info));
		if (!debug_data->
			is_stack_full_raw) {
		memcpy(hx_touch_data->hx_rawdata_buf,
				&buf[hx_touch_data->touch_info_size],
				hx_touch_data->touch_all_size
				- hx_touch_data->touch_info_size);
		} else {
			memcpy(hx_touch_data->hx_rawdata_buf,
					&buf[HX_STACK_ORG_LEN],
					hx_touch_data->touch_all_size
					- HX_STACK_ORG_LEN);
		}
		if (g_ts_dbg != 0)
			I("%s:Assign rawdata done!\n", __func__);
#if defined(HX_SMART_WAKEUP)
	} else if (ts_path == HX_REPORT_SMWP_EVENT) {
		memcpy(hx_touch_data->hx_event_buf, buf,
				hx_touch_data->event_size);
#endif
	} else {
		E("%s, Fail Path!\n", __func__);
		ts_status = HX_PATH_FAIL;
	}

	if (g_ts_dbg != 0)
		I("%s: End, ts_status=%d!\n", __func__, ts_status);
	return ts_status;
}
/* end assign_data*/

#define READ_VAR_BIT(var, nb)			(((var) >> (nb)) & 0x1)

static bool wgp_pen_id_crc(uint8_t *p_id)
{
	uint64_t pen_id, input;
	uint8_t hash_id, devidend;
	uint8_t pol = 0x43;
	int i = 0;

	if (g_ts_dbg != 0) {
		for (i = 0; i < 8; i++)
			I("%s:pen id[%d]= %x\n", __func__,
				i, p_id[i]);
	}
	pen_id = (uint64_t)p_id[0] | ((uint64_t)p_id[1] << 8) |
		((uint64_t)p_id[2] << 16) | ((uint64_t)p_id[3] << 24) |
		((uint64_t)p_id[4] << 32) | ((uint64_t)p_id[5] << 40) |
		((uint64_t)p_id[6] << 48);
	hash_id = p_id[7];
	if (g_ts_dbg != 0)
		I("%s:pen id=%llx, hash id=%x\n", __func__,
			pen_id, hash_id);

	input = pen_id << 6;
	devidend = input >> (44 + 6);

	for (i = (44 + 6 - 1); i >= 0; i--)	{
		if (READ_VAR_BIT(devidend, 6))
			devidend = devidend ^ pol;
		devidend = devidend << 1 | READ_VAR_BIT(input, i);
	}
	if (READ_VAR_BIT(devidend, 6))
		devidend = devidend ^ pol;
	if (g_ts_dbg != 0)
		I("%s:devidend=%x\n", __func__, devidend);

	if (devidend == hash_id) {
		g_target_report_data->s[0].id = pen_id;
		return 1;
	}

	g_target_report_data->s[0].id = 0;
	return 0;
}

/* start parse_report_data*/
static	uint8_t p_id[8];

int himax_parse_report_points(struct himax_ts_data *ts,
		int ts_path, int ts_status)
{
	int x = 0, y = 0, w = 0;
	uint8_t p_hover = 0, p_btn = 0, p_btn2 = 0;
	uint8_t ratio = ic_data->HX_STYLUS_RATIO;
	uint8_t p_id_en = 0, p_id_sel = 0;
	int8_t p_tilt_x = 0, p_tilt_y = 0;
	int p_x = 0, p_y = 0, p_w = 0;
	bool ret;
	static uint8_t p_p_on;

	int base = 0;
	int32_t	i = 0;

	if (g_ts_dbg != 0)
		I("%s: start!\n", __func__);

	base = hx_touch_data->touch_info_size;

	if (!ic_data->HX_STYLUS_FUNC)
		goto skip_stylus_operation;

	p_p_on = 0;
	base -= STYLUS_INFO_SZ;
	if (ic_data->HX_STYLUS_ID_V2) {/*Pen format ver2*/
		p_x = hx_touch_data->hx_coord_buf[base] << 8
			| hx_touch_data->hx_coord_buf[base + 1];
		p_y = (hx_touch_data->hx_coord_buf[base + 2] << 8
			| hx_touch_data->hx_coord_buf[base + 3]);
		p_w = (hx_touch_data->hx_coord_buf[base + 4] << 8
			| hx_touch_data->hx_coord_buf[base + 5]);
		p_tilt_x = (int8_t)hx_touch_data->hx_coord_buf[base + 6];
		p_tilt_y = (int8_t)hx_touch_data->hx_coord_buf[base + 7];
		p_hover = hx_touch_data->hx_coord_buf[base + 8] & 0x01;
		p_btn = hx_touch_data->hx_coord_buf[base + 8] & 0x02;
		p_btn2 = hx_touch_data->hx_coord_buf[base + 8] & 0x04;
		p_id_en = hx_touch_data->hx_coord_buf[base + 8] & 0x08;
		if (!p_id_en) {
			g_target_report_data->s[0].battery_info =
				hx_touch_data->hx_coord_buf[base + 9];
			if (g_ts_dbg != 0) {
				I("%s:update battery info = %x\n", __func__,
				g_target_report_data->s[0].battery_info);
			}
		} else {
			p_id_sel =
			(hx_touch_data->hx_coord_buf[base + 8] & 0xF0) >> 4;
			p_id[p_id_sel*2] =
			hx_touch_data->hx_coord_buf[base + 9];
			p_id[p_id_sel*2 + 1] =
			hx_touch_data->hx_coord_buf[base + 10];
			if (g_ts_dbg != 0) {
				I("%s:update pen id, p_id_sel = %d\n", __func__,
				p_id_sel);
			}
			if (p_id_sel == 3) {
				ret = wgp_pen_id_crc(p_id);
				if (!ret)
					I("Pen_ID CRC not match\n");
			}
		}
	} else {/*Pen format ver1*/
		p_x = hx_touch_data->hx_coord_buf[base] << 8
			| hx_touch_data->hx_coord_buf[base + 1];
		p_y = (hx_touch_data->hx_coord_buf[base + 2] << 8
			| hx_touch_data->hx_coord_buf[base + 3]);
		p_w = (hx_touch_data->hx_coord_buf[base + 4] << 8
			| hx_touch_data->hx_coord_buf[base + 5]);
		p_tilt_x = (int8_t)hx_touch_data->hx_coord_buf[base + 6];
		p_hover = hx_touch_data->hx_coord_buf[base + 7];
		p_btn = hx_touch_data->hx_coord_buf[base + 8];
		p_btn2 = hx_touch_data->hx_coord_buf[base + 9];
		p_tilt_y = (int8_t)hx_touch_data->hx_coord_buf[base + 10];
	}
	if (g_ts_dbg != 0) {
		D("%s: p_x=%d, p_y=%d, p_w=%d,p_tilt_x=%d, p_hover=%d\n",
			__func__, p_x, p_y, p_w, p_tilt_x, p_hover);
		D("%s: p_btn=%d, p_btn2=%d, p_tilt_y=%d\n",
			__func__, p_btn, p_btn2, p_tilt_y);
	}

	if (p_x >= 0
	&& p_x <= ((ts->pdata->abs_x_max+1)*ratio-1)
	&& p_y >= 0
	&& p_y <= ((ts->pdata->abs_y_max+1)*ratio-1)) {
		g_target_report_data->s[0].x = p_x;
		g_target_report_data->s[0].y = p_y;
		g_target_report_data->s[0].w = p_w;
		g_target_report_data->s[0].hover = p_hover;
		g_target_report_data->s[0].btn = p_btn;
		g_target_report_data->s[0].btn2 = p_btn2;
		g_target_report_data->s[0].tilt_x = p_tilt_x;
		g_target_report_data->s[0].tilt_y = p_tilt_y;
		g_target_report_data->s[0].on = 1;
		ts->hx_stylus_num++;
	} else {/* report coordinates */
		g_target_report_data->s[0].x = 0;
		g_target_report_data->s[0].y = 0;
		g_target_report_data->s[0].w = 0;
		g_target_report_data->s[0].hover = 0;
		g_target_report_data->s[0].btn = 0;
		g_target_report_data->s[0].btn2 = 0;
		g_target_report_data->s[0].tilt_x = 0;
		g_target_report_data->s[0].tilt_y = 0;
		g_target_report_data->s[0].on = 0;
	}

	if (g_ts_dbg != 0) {
		if (p_p_on != g_target_report_data->s[0].on) {
			I("s[0].on = %d, hx_stylus_num=%d\n",
				g_target_report_data->s[0].on,
				ts->hx_stylus_num);
			p_p_on = g_target_report_data->s[0].on;
		}
	}
skip_stylus_operation:

	ts->old_finger = ts->pre_finger_mask;
	if (ts->hx_point_num == 0) {
		if (g_ts_dbg != 0)
			I("%s: hx_point_num = 0!\n", __func__);
		return ts_status;
	}
	ts->pre_finger_mask = 0;
	hx_touch_data->finger_num =
		hx_touch_data->hx_coord_buf[base - 4] & 0x0F;
	hx_touch_data->finger_on = 1;
	AA_press = 1;

	g_target_report_data->finger_num = hx_touch_data->finger_num;
	g_target_report_data->finger_on = hx_touch_data->finger_on;
	g_target_report_data->ig_count =
		hx_touch_data->hx_coord_buf[base - 5];

	if (g_ts_dbg != 0)
		I("%s:finger_num = 0x%2X, finger_on = %d\n", __func__,
				g_target_report_data->finger_num,
				g_target_report_data->finger_on);

	for (i = 0; i < ts->nFinger_support; i++) {
		base = i * 4;
		x = hx_touch_data->hx_coord_buf[base] << 8
			| hx_touch_data->hx_coord_buf[base + 1];
		y = (hx_touch_data->hx_coord_buf[base + 2] << 8
			| hx_touch_data->hx_coord_buf[base + 3]);
		w = hx_touch_data->hx_coord_buf[(ts->nFinger_support * 4) + i];

		if (g_ts_dbg != 0)
			D("%s: now parsing[%d]:x=%d, y=%d, w=%d\n", __func__,
					i, x, y, w);

		if (x >= 0
		&& x <= ts->pdata->abs_x_max
		&& y >= 0
		&& y <= ts->pdata->abs_y_max) {
			hx_touch_data->finger_num--;

			g_target_report_data->p[i].x = x;
			g_target_report_data->p[i].y = y;
			g_target_report_data->p[i].w = w;
			g_target_report_data->p[i].id = 1;

			/*I("%s: g_target_report_data->x[loop_i]=%d,*/
			/*g_target_report_data->y[loop_i]=%d,*/
			/*g_target_report_data->w[loop_i]=%d",*/
			/*__func__, g_target_report_data->x[loop_i],*/
			/*g_target_report_data->y[loop_i],*/
			/*g_target_report_data->w[loop_i]); */

			if (!ts->first_pressed) {
				ts->first_pressed = 1;
				I("S1@%d, %d\n", x, y);
			}

			ts->pre_finger_data[i][0] = x;
			ts->pre_finger_data[i][1] = y;

			ts->pre_finger_mask = ts->pre_finger_mask + (1<<i);
		} else {/* report coordinates */
			g_target_report_data->p[i].x = x;
			g_target_report_data->p[i].y = y;
			g_target_report_data->p[i].w = w;
			g_target_report_data->p[i].id = 0;

			if (i == 0 && ts->first_pressed == 1) {
				ts->first_pressed = 2;
				I("E1@%d, %d\n", ts->pre_finger_data[0][0],
						ts->pre_finger_data[0][1]);
			}
		}
	}

	if (g_ts_dbg != 0) {
		for (i = 0; i < ts->nFinger_support; i++)
			D("DBG X=%d  Y=%d ID=%d\n",
				g_target_report_data->p[i].x,
				g_target_report_data->p[i].y,
				g_target_report_data->p[i].id);

		D("DBG finger number %d\n", g_target_report_data->finger_num);
	}

	if (g_ts_dbg != 0)
		I("%s: end!\n", __func__);
	return ts_status;
}

static int himax_parse_report_data(struct himax_ts_data *ts,
		int ts_path, int ts_status)
{

	if (g_ts_dbg != 0)
		I("%s: start now_status=%d!\n", __func__, ts_status);


	EN_NoiseFilter =
		(hx_touch_data->hx_coord_buf[HX_TOUCH_INFO_POINT_CNT + 2] >> 3);
	/* I("EN_NoiseFilter=%d\n", EN_NoiseFilter); */
	EN_NoiseFilter = EN_NoiseFilter & 0x01;
	/* I("EN_NoiseFilter2=%d\n", EN_NoiseFilter); */
	p_point_num = ts->hx_point_num;

	if (hx_touch_data->hx_coord_buf[HX_TOUCH_INFO_POINT_CNT] == 0xff)
		ts->hx_point_num = 0;
	else
		ts->hx_point_num =
			hx_touch_data->hx_coord_buf[HX_TOUCH_INFO_POINT_CNT]
			& 0x0f;

	if (ic_data->HX_STYLUS_FUNC) {
		p_stylus_num = ts->hx_stylus_num;
		ts->hx_stylus_num = 0;
	}

	switch (ts_path) {
	case HX_REPORT_COORD:
		ts_status = himax_parse_report_points(ts, ts_path, ts_status);
		break;
	case HX_REPORT_COORD_RAWDATA:
		/* touch monitor rawdata */
		if (debug_data != NULL) {
			if (debug_data->is_stack_full_raw) {
				if (g_ts_dbg != 0)
					I("%s: full stack raw!\n", __func__);
				if (debug_data->_raw_full_stack(ic_data,
					hx_touch_data))
					I("%s:raw data_checksum not match\n", __func__);
			} else {
				if (g_ts_dbg != 0)
					I("%s: event stack raw!\n", __func__);
			if (debug_data->fp_set_diag_cmd(ic_data, hx_touch_data))
				I("%s:raw data_checksum not match\n", __func__);
			}
		} else {
			E("%s,There is no init set_diag_cmd\n", __func__);
		}
		ts_status = himax_parse_report_points(ts, ts_path, ts_status);
		break;
#if defined(HX_SMART_WAKEUP)
	case HX_REPORT_SMWP_EVENT:
		himax_wake_event_parse(ts, ts_status);
		break;
#endif
	default:
		E("%s:Fail Path!\n", __func__);
		ts_status = HX_PATH_FAIL;
		break;
	}
	if (g_ts_dbg != 0)
		I("%s: end now_status=%d!\n", __func__, ts_status);
	return ts_status;
}

/* end parse_report_data*/

static void himax_report_all_leave_event(struct himax_ts_data *ts)
{
	int i = 0;

	for (i = 0; i < ts->nFinger_support; i++) {
#if !defined(HX_PROTOCOL_A)
		input_mt_slot(ts->input_dev, i);
		input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0);
		input_report_abs(ts->input_dev, ABS_MT_WIDTH_MAJOR, 0);
		input_report_abs(ts->input_dev, ABS_MT_PRESSURE, 0);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 0);
#endif
	}
	input_report_key(ts->input_dev, BTN_TOUCH, 0);
	input_sync(ts->input_dev);
}

/* start report_point*/
static void himax_point_report(struct himax_ts_data *ts)
{
	int i = 0;
	bool valid = false;


	if (g_ts_dbg != 0) {
		I("%s:start hx_touch_data->finger_num=%d\n",
			__func__, hx_touch_data->finger_num);
	}
	for (i = 0; i < ts->nFinger_support; i++) {
		if (g_target_report_data->p[i].x >= 0
		&& g_target_report_data->p[i].x <= ts->pdata->abs_x_max
		&& g_target_report_data->p[i].y >= 0
		&& g_target_report_data->p[i].y <= ts->pdata->abs_y_max)
			valid = true;
		else
			valid = false;
		if (g_ts_dbg != 0)
			I("valid=%d\n", valid);
		if (valid) {
			if (g_ts_dbg != 0) {
				I("report_data->x[i]=%d,y[i]=%d,w[i]=%d",
					g_target_report_data->p[i].x,
					g_target_report_data->p[i].y,
					g_target_report_data->p[i].w);
			}
#if !defined(HX_PROTOCOL_A)
			input_mt_slot(ts->input_dev, i);
#else
			input_report_key(ts->input_dev, BTN_TOUCH, 1);
#endif
			input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR,
					g_target_report_data->p[i].w);
#if !defined(HX_PROTOCOL_A)
			input_report_abs(ts->input_dev, ABS_MT_WIDTH_MAJOR,
					g_target_report_data->p[i].w);
			input_report_abs(ts->input_dev, ABS_MT_PRESSURE,
					g_target_report_data->p[i].w);
#else
			input_report_abs(ts->input_dev, ABS_MT_TRACKING_ID,
					i + 1);
#endif
			input_report_abs(ts->input_dev, ABS_MT_POSITION_X,
					g_target_report_data->p[i].x);
			input_report_abs(ts->input_dev, ABS_MT_POSITION_Y,
					g_target_report_data->p[i].y);
#if !defined(HX_PROTOCOL_A)
			ts->last_slot = i;
			input_mt_report_slot_state(ts->input_dev,
					MT_TOOL_FINGER, 1);
#else
			input_mt_sync(ts->input_dev);
#endif
		} else {
#if !defined(HX_PROTOCOL_A)
			input_mt_slot(ts->input_dev, i);
			input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0);
			input_report_abs(ts->input_dev, ABS_MT_WIDTH_MAJOR, 0);
			input_report_abs(ts->input_dev, ABS_MT_PRESSURE, 0);
			input_mt_report_slot_state(ts->input_dev,
					MT_TOOL_FINGER, 0);
#endif
		}
	}
#if !defined(HX_PROTOCOL_A)
	input_report_key(ts->input_dev, BTN_TOUCH, 1);
#endif
	input_sync(ts->input_dev);

	if (g_ts_dbg != 0)
		I("%s:end\n", __func__);
}

static void himax_point_leave(struct himax_ts_data *ts)
{
#if !defined(HX_PROTOCOL_A)
	int32_t i = 0;
#endif

	if (g_ts_dbg != 0)
		I("%s: start!\n", __func__);
#if defined(HX_PALM_REPORT)
	if (himax_palm_detect(hx_touch_data->hx_coord_buf) == PALM_REPORT) {
		I(" %s HX_PALM_REPORT KEY power event press\n", __func__);
		input_report_key(ts->input_dev, KEY_POWER, 1);
		input_sync(ts->input_dev);
		msleep(100);

		I(" %s HX_PALM_REPORT KEY power event release\n", __func__);
		input_report_key(ts->input_dev, KEY_POWER, 0);
		input_sync(ts->input_dev);
		return;
	}
#endif

	hx_touch_data->finger_on = 0;
	g_target_report_data->finger_on  = 0;
	g_target_report_data->finger_num = 0;
	AA_press = 0;

#if defined(HX_PROTOCOL_A)
	input_mt_sync(ts->input_dev);
#endif
#if !defined(HX_PROTOCOL_A)
	for (i = 0; i < ts->nFinger_support; i++) {
		input_mt_slot(ts->input_dev, i);
		input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0);
		input_report_abs(ts->input_dev, ABS_MT_WIDTH_MAJOR, 0);
		input_report_abs(ts->input_dev, ABS_MT_PRESSURE, 0);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 0);
	}
#endif
	if (ts->pre_finger_mask > 0)
		ts->pre_finger_mask = 0;

	if (ts->first_pressed == 1) {
		ts->first_pressed = 2;
		I("E1@%d, %d\n", ts->pre_finger_data[0][0],
				ts->pre_finger_data[0][1]);
	}

	/*if (ts->debug_log_level & BIT(1))*/
	/*	himax_log_touch_event(x, y, w, loop_i, EN_NoiseFilter,*/
	/*			HX_FINGER_LEAVE); */

	input_report_key(ts->input_dev, BTN_TOUCH, 0);
	input_sync(ts->input_dev);

	if (g_ts_dbg != 0)
		I("%s: end!\n", __func__);
}

static void himax_stylus_report(struct himax_ts_data *ts)
{
	bool valid = false;
	uint8_t ratio = ic_data->HX_STYLUS_RATIO;

	if (g_ts_dbg != 0) {
		I("%s:start hx_touch_data->stylus_num=%d\n",
			__func__, ts->hx_stylus_num);
	}

	if (g_target_report_data->s[0].x >= 0
	&& g_target_report_data->s[0].x <= ((ts->pdata->abs_x_max+1)*ratio-1)
	&& g_target_report_data->s[0].y >= 0
	&& g_target_report_data->s[0].y <= ((ts->pdata->abs_y_max+1)*ratio-1)
	&& (g_target_report_data->s[0].on == 1))
		valid = true;
	else
		valid = false;

	if (g_ts_dbg != 0)
		I("stylus valid=%d\n", valid);

	if (valid) {/*stylus down*/
		if (g_ts_dbg != 0)
			I("s[i].x=%d, s[i].y=%d, s[i].w=%d\n",
					g_target_report_data->s[0].x,
					g_target_report_data->s[0].y,
					g_target_report_data->s[0].w);

		input_report_abs(ts->stylus_dev, ABS_X,
				g_target_report_data->s[0].x);
		input_report_abs(ts->stylus_dev, ABS_Y,
				g_target_report_data->s[0].y);

		if (g_target_report_data->s[0].btn !=
		g_target_report_data->s[0].pre_btn) {
			if (g_ts_dbg != 0)
				I("BTN_STYLUS:%d\n",
					g_target_report_data->s[0].btn);

			input_report_key(ts->stylus_dev, BTN_STYLUS,
					g_target_report_data->s[0].btn);

			g_target_report_data->s[0].pre_btn =
					g_target_report_data->s[0].btn;
		} else {
			if (g_ts_dbg != 0)
				I("BTN_STYLUS status is %d!\n",
						g_target_report_data->s[0].btn);
		}

		if (g_target_report_data->s[0].btn2
		!= g_target_report_data->s[0].pre_btn2) {
			if (g_ts_dbg != 0)
				I("BTN_STYLUS2:%d\n",
					g_target_report_data->s[0].btn2);

			input_report_key(ts->stylus_dev, BTN_STYLUS2,
					g_target_report_data->s[0].btn2);

			g_target_report_data->s[0].pre_btn2 =
					g_target_report_data->s[0].btn2;
		} else {
			if (g_ts_dbg != 0)
				I("BTN_STYLUS2 status is %d!\n",
					g_target_report_data->s[0].btn2);
		}
		input_report_abs(ts->stylus_dev, ABS_TILT_X,
				g_target_report_data->s[0].tilt_x);

		input_report_abs(ts->stylus_dev, ABS_TILT_Y,
				g_target_report_data->s[0].tilt_y);

		input_report_key(ts->stylus_dev, BTN_TOOL_PEN, 1);

		if (g_target_report_data->s[0].hover == 0) {
			input_report_key(ts->stylus_dev, BTN_TOUCH, 1);
			input_report_abs(ts->stylus_dev, ABS_DISTANCE, 0);
			input_report_abs(ts->stylus_dev, ABS_PRESSURE,
					g_target_report_data->s[0].w);
		} else {
			input_report_key(ts->stylus_dev, BTN_TOUCH, 0);
			input_report_abs(ts->stylus_dev, ABS_DISTANCE, 1);
			input_report_abs(ts->stylus_dev, ABS_PRESSURE, 0);
		}
	} else {/*Pen up*/
		g_target_report_data->s[0].pre_btn = 0;
		g_target_report_data->s[0].pre_btn2 = 0;
		input_report_key(ts->stylus_dev, BTN_STYLUS, 0);
		input_report_key(ts->stylus_dev, BTN_STYLUS2, 0);
		input_report_key(ts->stylus_dev, BTN_TOUCH, 0);
		input_report_abs(ts->stylus_dev, ABS_PRESSURE, 0);
		input_sync(ts->stylus_dev);

		input_report_abs(ts->stylus_dev, ABS_DISTANCE, 0);
		input_report_key(ts->stylus_dev, BTN_TOOL_RUBBER, 0);
		input_report_key(ts->stylus_dev, BTN_TOOL_PEN, 0);
		input_report_abs(ts->stylus_dev, ABS_PRESSURE, 0);
	}
	input_sync(ts->stylus_dev);

	if (g_ts_dbg != 0)
		I("%s:end\n", __func__);
}

static void himax_stylus_leave(struct himax_ts_data *ts)
{
	if (g_ts_dbg != 0)
		I("%s: start!\n", __func__);

	g_target_report_data->s[0].pre_btn = 0;
	g_target_report_data->s[0].pre_btn2 = 0;
	input_report_key(ts->stylus_dev, BTN_STYLUS, 0);
	input_report_key(ts->stylus_dev, BTN_STYLUS2, 0);
	input_report_key(ts->stylus_dev, BTN_TOUCH, 0);
	input_report_abs(ts->stylus_dev, ABS_PRESSURE, 0);
	input_sync(ts->stylus_dev);

	input_report_abs(ts->stylus_dev, ABS_DISTANCE, 0);
	input_report_abs(ts->stylus_dev, ABS_TILT_X, 0);
	input_report_abs(ts->stylus_dev, ABS_TILT_Y, 0);
	input_report_key(ts->stylus_dev, BTN_TOOL_RUBBER, 0);
	input_report_key(ts->stylus_dev, BTN_TOOL_PEN, 0);
	input_sync(ts->stylus_dev);

	if (g_ts_dbg != 0)
		I("%s: end!\n", __func__);
}

int himax_report_data(struct himax_ts_data *ts, int ts_path, int ts_status)
{
	if (g_ts_dbg != 0)
		I("%s: Entering, ts_status=%d!\n", __func__, ts_status);

	if (ts_path == HX_REPORT_COORD || ts_path == HX_REPORT_COORD_RAWDATA) {
		/* Touch Point information */

		if (ts->hx_point_num != 0)
			himax_point_report(ts);
		else if (ts->hx_point_num == 0 && p_point_num != 0)
			himax_point_leave(ts);

		if (ic_data->HX_STYLUS_FUNC) {
			if (ts->hx_stylus_num != 0)
				himax_stylus_report(ts);
			else if (ts->hx_stylus_num == 0 && p_stylus_num != 0)
				himax_stylus_leave(ts);
		}

		Last_EN_NoiseFilter = EN_NoiseFilter;

#if defined(HX_SMART_WAKEUP)
	} else if (ts_path == HX_REPORT_SMWP_EVENT) {
		himax_wake_event_report();
#endif
	} else {
		E("%s:Fail Path!\n", __func__);
		ts_status = HX_PATH_FAIL;
	}

	if (g_ts_dbg != 0)
		I("%s: END, ts_status=%d!\n", __func__, ts_status);
	return ts_status;
}
/* end report_data */

static int himax_ts_operation(struct himax_ts_data *ts,
		int ts_path, int ts_status)
{
	uint8_t hw_reset_check[2];

	memset(ts->xfer_buff, 0x00, hx_touch_data->touch_all_size * sizeof(uint8_t));
	memset(hw_reset_check, 0x00, sizeof(hw_reset_check));
	ts_status = himax_touch_get(ts, ts->xfer_buff, ts_path, ts_status);
	if (ts_status == HX_TS_GET_DATA_FAIL)
		goto END_FUNCTION;

	ts_status = himax_distribute_touch_data(ts->xfer_buff,
			ts_path, ts_status);
	ts_status = himax_err_ctrl(ts, ts->xfer_buff, ts_path, ts_status);
	if (ts_status == HX_REPORT_DATA || ts_status == HX_TS_NORMAL_END)
		ts_status = himax_parse_report_data(ts, ts_path, ts_status);
	else
		goto END_FUNCTION;


	ts_status = himax_report_data(ts, ts_path, ts_status);


END_FUNCTION:
	return ts_status;
}

void himax_ts_work(struct himax_ts_data *ts)
{

	int ts_status = HX_TS_NORMAL_END;
	int ts_path = 0;

	if (debug_data != NULL) {
		if (debug_data->is_checking_irq) {
			if (g_ts_dbg != 0)
				I("Now checking IRQ, skip it!\n");
			return;
		}
		debug_data->fp_ts_dbg_func(ts, HX_FINGER_ON);
	}
	if (ts->notouch_frame > 0) {
		if (g_ts_dbg != 0)
			I("Skipit=%d\n", ts->notouch_frame--);
		else
			ts->notouch_frame--;
		return;
	}

#if defined(HX_USB_DETECT_GLOBAL)
	himax_cable_detect_func(false);
#endif

	ts_path = himax_ts_work_status(ts);
	switch (ts_path) {
	case HX_REPORT_COORD:
		ts_status = himax_ts_operation(ts, ts_path, ts_status);
		break;
	case HX_REPORT_SMWP_EVENT:
		ts_status = himax_ts_operation(ts, ts_path, ts_status);
		break;
	case HX_REPORT_COORD_RAWDATA:
		ts_status = himax_ts_operation(ts, ts_path, ts_status);
		break;
	default:
		E("%s:Path Fault! value=%d\n", __func__, ts_path);
		goto END_FUNCTION;
	}

	if (ts_status == HX_TS_GET_DATA_FAIL)
		goto GET_TOUCH_FAIL;
	else
		goto END_FUNCTION;

GET_TOUCH_FAIL:
	I("%s: Now reset the Touch chip.\n", __func__);
#if defined(HX_RST_PIN_FUNC)
	g_core_fp.fp_ic_reset(false, true);
#else
	g_core_fp.fp_system_reset();
#endif
#if defined(HX_ZERO_FLASH)
	if (g_core_fp.fp_0f_reload_to_active)
		g_core_fp.fp_0f_reload_to_active();
#endif
END_FUNCTION:
	if (debug_data != NULL)
		debug_data->fp_ts_dbg_func(ts, HX_FINGER_LEAVE);

}
/*end ts_work*/
enum hrtimer_restart himax_ts_timer_func(struct hrtimer *timer)
{
	struct himax_ts_data *ts;


	ts = container_of(timer, struct himax_ts_data, timer);
	queue_work(ts->himax_wq, &ts->work);
	hrtimer_start(&ts->timer, ktime_set(0, 12500000), HRTIMER_MODE_REL);
	return HRTIMER_NORESTART;
}

#if !defined(HX_ZERO_FLASH)
static int hx_chk_flash_sts(uint32_t size)
{
	int rslt = 0;

	I("%s: Entering, %d\n", __func__, size);

	rslt = (!g_core_fp.fp_calculateChecksum(false, size));
	/*avoid the FW is full of zero*/
	rslt |= g_core_fp.fp_flash_lastdata_check(size);

	return rslt;
}
#endif
#ifdef OPPO_PROC_NODE
static void tp_fw_update_work(struct work_struct *work)
{
	struct himax_ts_data *ts = private_ts;
	int ret = 0, count_tmp = 0,retry = 5;
	const struct firmware *fw_entry = NULL;


	if ( g_core_fp.fp_firmware_update_0f != NULL) {
		mutex_lock(&private_ts->fw_update_lock);
		do {
			 I("%s:request fw ,name= %s\n", __func__,g_boot_upgrade_fwname);
			 ret = request_firmware(&fw_entry, g_boot_upgrade_fwname, ts->dev);
			 if (ret < 0) {
				 I("%s: fw request fail \n", __func__);
			 }else {
				break;
			 }
		} while((ret < 0) && (--retry > 0));

		I("retry times %d\n", 5 - retry);

		if (fw_entry) {
			if (ts->g_fw_buf !=NULL) {
				ts->g_fw_len = fw_entry->size;
				memcpy(ts->g_fw_buf, fw_entry->data, fw_entry->size);
				ts->g_fw_sta = true;
			}
			g_core_fp.fp_bin_desc_get((unsigned char *)fw_entry->data, HX1K);

			himax_int_enable(0);
			do {
                count_tmp++;
				ret = g_core_fp.fp_firmware_update_0f(fw_entry,0);
				if (ret == 0) {
                    break;
                }
			} while((count_tmp < 2) && (ret != 0));

			if ( ret == 0) {
				I("%s: fw update ok \n", __func__);
			} else {
				I("%s: fw update fail \n", __func__);
			}

			g_core_fp.fp_reload_disable(0);
			g_core_fp.fp_read_FW_ver();
			g_core_fp.fp_touch_information();
			g_core_fp.fp_sense_on(0x00);
			himax_int_enable(1);

		} else {
			I("%s: fw failed \n", __func__);
			goto EXIT;
		}

		if(fw_entry != NULL) {
			release_firmware(fw_entry);
		}
	} else {
			I("%s: fw_name request failed %s %d\n", __func__, g_boot_upgrade_fwname, ret);
		}
		goto EXIT;

EXIT:
	mutex_unlock(&private_ts->fw_update_lock);
	complete(&ts->fw_complete); //notify to init.rc that fw update finished
	  return;
}
#endif
static void himax_boot_upgrade(struct work_struct *work)
{
#if defined(HX_BOOT_UPGRADE) || defined(HX_ZERO_FLASH)
	int fw_sts = -1;
#endif

#if defined(HX_ZERO_FLASH)
	g_boot_upgrade_flag = true;
#else
	if (hx_chk_flash_sts(ic_data->flash_size) == 1) {
		E("%s: check flash fail, please upgrade FW\n", __func__);
	#if defined(HX_BOOT_UPGRADE)
		g_boot_upgrade_flag = true;
	#else
		goto END;
	#endif
	} else {
		g_core_fp.fp_reload_disable(0);
		g_core_fp.fp_power_on_init();
		g_core_fp.fp_read_FW_ver();
		g_core_fp.fp_tp_info_check();
	}
#endif

#if defined(HX_BOOT_UPGRADE) || defined(HX_ZERO_FLASH)
	fw_sts = i_get_FW();
	if (fw_sts < NO_ERR)
		goto END;

	g_core_fp.fp_bin_desc_get((unsigned char *)hxfw->data, HX1K);

#if defined(HX_BOOT_UPGRADE)
	if (g_boot_upgrade_flag == false) {
		if (himax_auto_update_check() == 0)
			g_boot_upgrade_flag = true;
	}
#endif

	if (g_boot_upgrade_flag == true) {
		if (i_update_FW() <= 0) {
			E("%s: Update FW fail\n", __func__);
		} else {
			I("%s: Update FW success\n", __func__);
			if (!g_has_alg_overlay) {
				g_core_fp.fp_reload_disable(0);
				g_core_fp.fp_power_on_init();
			}
				g_core_fp.fp_read_FW_ver();
				g_core_fp.fp_tp_info_check();
		}
	}

	if (fw_sts == NO_ERR)
		release_firmware(hxfw);
	hxfw = NULL;
#endif

END:
	ic_boot_done = 1;
	himax_int_enable(1);
}

#if defined(HX_CONFIG_FB) || defined(HX_CONFIG_DRM) \
	|| defined(HX_CONFIG_DRM_PANEL)
static void himax_fb_register(struct work_struct *work)
{
	int ret = 0;

	struct himax_ts_data *ts = container_of(work, struct himax_ts_data,
			work_att.work);

	I("%s in\n", __func__);
#if defined(HX_CONFIG_FB)
	ts->fb_notif.notifier_call = fb_notifier_callback;
	ret = fb_register_client(&ts->fb_notif);
#elif defined(HX_CONFIG_DRM_PANEL)
	ts->fb_notif.notifier_call = drm_notifier_callback;
	if (active_panel)
		ret = drm_panel_notifier_register(active_panel,
			&ts->fb_notif);
	else
		ret = drm_panel_notifier_register(&gNotifier_dummy_panel,
			&ts->fb_notif);
#elif defined(HX_CONFIG_DRM)
#if defined(__HIMAX_MOD__)
	hx_msm_drm_register_client =
		(void *)kallsyms_lookup_name("msm_drm_register_client");
	if (hx_msm_drm_register_client != NULL) {
		ts->fb_notif.notifier_call = drm_notifier_callback;
		ret = hx_msm_drm_register_client(&ts->fb_notif);
	}	else
		E("hx_msm_drm_register_client is NULL\n");
#else
	ts->fb_notif.notifier_call = drm_notifier_callback;
	ret = msm_drm_register_client(&ts->fb_notif);
#endif
#endif
	if (ret)
		E("Unable to register fb_notifier: %d\n", ret);
}
#endif

#if defined(HX_CONTAINER_SPEED_UP)
static void himax_resume_work_func(struct work_struct *work)
{
	himax_chip_common_resume(private_ts);
}

#endif
int hx_ic_register(void)
{
	int ret = !NO_ERR;

	I("%s:Entering!\n", __func__);

#if defined(CONFIG_TOUCHSCREEN_HIMAX_IC_HX852xJ)
	if (_hx852xJ_init()) {
		ret = NO_ERR;
		goto END;
	}
#endif
#if defined(CONFIG_TOUCHSCREEN_HIMAX_IC_HX83102)
	if (_hx83102_init()) {
		ret = NO_ERR;
		goto END;
	}
#endif
/* for gki */
#if (1)
//#if defined(CONFIG_TOUCHSCREEN_HIMAX_IC_HX83108)
	if (_hx83108_init()) {
		ret = NO_ERR;
		goto END;
	}
#endif
#if defined(CONFIG_TOUCHSCREEN_HIMAX_IC_HX83112)
	if (_hx83112_init()) {
		ret = NO_ERR;
		goto END;
	}
#endif
#if defined(CONFIG_TOUCHSCREEN_HIMAX_IC_HX83121)
	if (_hx83121_init()) {
		ret = NO_ERR;
		goto END;
	}
#endif

END:
	if (ret == NO_ERR)
		I("%s: detect IC!\n", __func__);
	else
		E("%s: There is no IC!\n", __func__);
	I("%s:END!\n", __func__);

	return ret;
}

#if defined(HX_FIRMWARE_HEADER)
void mapping_panel_id_from_dt(struct device_node *dt)
{
	const char *panel_id_dt = "panel_id";
	uint32_t data = 0;

	if (of_property_read_u32(dt, panel_id_dt, &data) == 0) {
		I(" Found %s = %d\n", panel_id_dt, data);
		g_hx_panel_id = data;
	} else {
		I(" %s not found! set to default 0\n", panel_id_dt);
		g_hx_panel_id = 0;
	}
	I(" DT:panel_id = %d\n", g_hx_panel_id);
}
#endif

int himax_chip_common_init(void)
{
	int ret = 0;
	int err = PROBE_FAIL;
	struct himax_ts_data *ts = private_ts;
	struct himax_platform_data *pdata;

	/* screen HKC_HX03 & BOE_HX03 */
	if (g_firmware_id == 0){
		g_boot_upgrade_fwname = BOOT_UPGRADE_FWNAME_HKC_HX03;
		g_mpap_fwname = MPAP_FWNAME_HKC_HX03;
	} else if (g_firmware_id == 1) {
		g_boot_upgrade_fwname = BOOT_UPGRADE_FWNAME_BOE_HX03;
		g_mpap_fwname = MPAP_FWNAME_BOE_HX03;
	} else if (g_firmware_id == 2) {
		g_boot_upgrade_fwname = BOOT_UPGRADE_FWNAME_HKC_HX05;
		g_mpap_fwname = MPAP_FWNAME_HKC_HX05;
	} else if (g_firmware_id == 12) {
		g_boot_upgrade_fwname = BOOT_UPGRADE_FWNAME_HKC_HX05K;
		g_mpap_fwname = MPAP_FWNAME_HKC_HX05K;
	}
	g_fw_boot_upgrade_name = g_boot_upgrade_fwname;
	g_fw_mp_upgrade_name = g_mpap_fwname;

#if defined(HX_RW_FILE)
#if defined(KERNEL_VER_ABOVE_4_19)
#else
	I("Prepare kernel fp\n");
	kp_getname_kernel = (void *)kallsyms_lookup_name("getname_kernel");
	if (!kp_getname_kernel) {
		E("prepare kp_getname_kernel failed!\n");
		/*goto err_xfer_buff_fail;*/
	}

	kp_putname_kernel = (void *)kallsyms_lookup_name("putname");
	if (!kp_putname_kernel) {
		E("prepare kp_putname_kernel failed!\n");
		/*goto err_xfer_buff_fail;*/
	}

	kp_file_open_name = (void *)kallsyms_lookup_name("file_open_name");
	if (!kp_file_open_name) {
		E("prepare kp_file_open_name failed!\n");
		goto err_xfer_buff_fail;
	}
#endif
#endif
	ts->xfer_buff = devm_kzalloc(ts->dev, HX_FULL_STACK_RAWDATA_SIZE * sizeof(uint8_t),
			GFP_KERNEL);
	if (ts->xfer_buff == NULL) {
		err = -ENOMEM;
		goto err_xfer_buff_fail;
	}

	I("PDATA START\n");
	pdata = kzalloc(sizeof(struct himax_platform_data), GFP_KERNEL);

	if (pdata == NULL) { /*Allocate Platform data space*/
		err = -ENOMEM;
		goto err_dt_platform_data_fail;
	}

	I("ic_data START\n");
	ic_data = kzalloc(sizeof(struct himax_ic_data), GFP_KERNEL);
	if (ic_data == NULL) { /*Allocate IC data space*/
		err = -ENOMEM;
		goto err_dt_ic_data_fail;
	}
	memset(ic_data, 0xFF, sizeof(struct himax_ic_data));
	/* default 128k, different size please follow HX83121A style */
	ic_data->flash_size = 131072;

	/* allocate report data */
	hx_touch_data = kzalloc(sizeof(struct himax_report_data), GFP_KERNEL);
	if (hx_touch_data == NULL) {
		err = -ENOMEM;
		goto err_alloc_touch_data_failed;
	}
#if defined(OPPO_PROC_NODE)
	ts->recovery_mode = false;
    
	/*Judge whether it is factory test mode */
	if(reboot_mode == 1)
	    ts->boot_mode = MSM_BOOT_MODE__FACTORY;
	else
	    ts->boot_mode = MSM_BOOT_MODE__NORMAL;
	
	I("==========ts->boot_mode = %d\n",ts->boot_mode);
#ifdef CONFIG_TOUCHPANEL_MTK_PLATFORM
    if ((ts->boot_mode == META_BOOT || ts->boot_mode == FACTORY_BOOT))
#else
    if ((ts->boot_mode == MSM_BOOT_MODE__FACTORY || ts->boot_mode == MSM_BOOT_MODE__RF || ts->boot_mode == MSM_BOOT_MODE__WLAN))
#endif
	{
		I("boot_mode is FACTORY,RF and WLAN not need to add tp driver\n");
		return -1;
	} else if (ts->boot_mode == 2) {
		ts->recovery_mode = true;
		I("boot_mode is recovery\n");
	} else {
		I("boot_mode is %d\n",ts->boot_mode);
	}
#endif
	ts->pdata = pdata;

	if (himax_parse_dt(ts, pdata) < 0) {
		I(" pdata is NULL for DT\n");
		goto err_alloc_dt_pdata_failed;
	}

#if defined(HX_RST_PIN_FUNC)
	ts->rst_gpio = pdata->gpio_reset;
#endif

	if (himax_gpio_power_config(pdata) < 0) {
		E("%s: gpio config fail, exit!\n", __func__);
		goto err_alloc_dt_pdata_failed;
	}

#if !defined(CONFIG_OF)
	if (pdata->power) {
		ret = pdata->power(1);
		if (ret < 0) {
			E("%s: power on failed\n", __func__);
			goto err_power_failed;
		}
	}
#endif

#if defined(CONFIG_OF)
	ts->power = pdata->power;
#endif

	g_hx_chip_inited = 0;

	if (hx_ic_register() != NO_ERR) {
		E("%s: can't detect IC!\n", __func__);
		goto error_ic_detect_failed;
	}

	private_ts->notouch_frame = 0;
	private_ts->ic_notouch_frame = 0;

	if (g_core_fp.fp_chip_init != NULL) {
		g_core_fp.fp_chip_init();
	} else {
		E("%s: function point of chip_init is NULL!\n", __func__);
		goto error_ic_detect_failed;
	}
#ifdef HX_PARSE_FROM_DT
	himax_parse_dt_ic_info(ts, pdata);
#endif
	g_core_fp.fp_touch_information();

	spin_lock_init(&ts->irq_lock);

	if (himax_ts_register_interrupt()) {
		E("%s: register interrupt failed\n", __func__);
		goto err_register_interrupt_failed;
	}
#if defined(DD_VSN_RECOV_EXCP)
	private_ts->update_fw_fail = 0;
	private_ts->update_fw_flag = 0;
	private_ts->vsn_flag = 0;
#endif
	himax_int_enable(0);
#if defined(HX_ZERO_FLASH)
	g_update_cfg_buf = kzalloc(private_ts->chip_max_dsram_size *
		sizeof(uint8_t),
		GFP_KERNEL);
	if (g_update_cfg_buf == NULL) {
		I("cfg_buf vmalloc error\n");
		goto err_g_update_cfg_buf;
	}
#endif
#if defined(OPPO_PROC_NODE)

	/* screen HKC_HX03 & BOE_HX03 */
	if (g_firmware_id == 0) {
		ts->firmware_headfile.data = fw_i_arr_HKC_HX03;
		ts->firmware_headfile.size = sizeof(fw_i_arr_HKC_HX03);
	} else if (g_firmware_id == 1) {
		ts->firmware_headfile.data = fw_i_arr_BOE_HX03;
		ts->firmware_headfile.size = sizeof(fw_i_arr_BOE_HX03);
	} else if (g_firmware_id == 2) {
		ts->firmware_headfile.data = fw_i_arr_HKC_HX05;
		ts->firmware_headfile.size = sizeof(fw_i_arr_HKC_HX05);
	} else if (g_firmware_id == 12) {
		ts->firmware_headfile.data = fw_i_arr_HKC_HX05K;
		ts->firmware_headfile.size = sizeof(fw_i_arr_HKC_HX05K);
	}
	ts->g_fw_sta = false;
	ts->using_headfile = false;
	ts->g_fw_buf = kzalloc(sizeof(uint8_t) * (128 * 1024), GFP_KERNEL);
	if (ts->g_fw_buf == NULL) {
		I("fw buf vmalloc error\n");
		goto err_g_fw_buf;
	}
	init_completion(&ts->fw_complete);
	INIT_WORK(&ts->fw_update_work, tp_fw_update_work);
#endif
	ts->himax_boot_upgrade_wq =
		create_singlethread_workqueue("HX_boot_upgrade");
	if (!ts->himax_boot_upgrade_wq) {
		E("allocate himax_boot_upgrade_wq failed\n");
		err = -ENOMEM;
		goto err_boot_upgrade_wq_failed;
	}
	INIT_DELAYED_WORK(&ts->work_boot_upgrade, himax_boot_upgrade);
	queue_delayed_work(ts->himax_boot_upgrade_wq, &ts->work_boot_upgrade,
			msecs_to_jiffies(HX_DELAY_BOOT_UPDATE));

	g_core_fp.fp_calc_touch_data_size();

	/*Himax Power On and Load Config*/
/*	if (himax_loadSensorConfig(pdata)) {
 *		E("%s: Load Sesnsor configuration failed, unload driver.\n",
 *				__func__);
 *		goto err_detect_failed;
 *	}
 */

#if defined(CONFIG_OF)
	ts->pdata->abs_pressure_min        = 0;
	ts->pdata->abs_pressure_max        = 200;
	ts->pdata->abs_width_min           = 0;
	ts->pdata->abs_width_max           = 200;
	pdata->cable_config[0]             = 0xF0;
	pdata->cable_config[1]             = 0x00;
#endif

	ts->suspended                      = false;

#if defined(HX_USB_DETECT_GLOBAL)
	ts->usb_connected = 0x00;
	ts->cable_config = pdata->cable_config;
#endif

#if defined(HX_PROTOCOL_A)
	ts->protocol_type = PROTOCOL_TYPE_A;
#else
	ts->protocol_type = PROTOCOL_TYPE_B;
#endif
	I("%s: Use Protocol Type %c\n", __func__,
		ts->protocol_type == PROTOCOL_TYPE_A ? 'A' : 'B');

#if defined(HX_SMART_WAKEUP)
	ts->SMWP_enable = 1;
#if defined(KERNEL_VER_ABOVE_4_19)
	ts->ts_SMWP_wake_lock =
		wakeup_source_register(ts->dev, HIMAX_common_NAME);
#else
	if (!ts->ts_SMWP_wake_lock)
		ts->ts_SMWP_wake_lock = kzalloc(sizeof(struct wakeup_source),
			GFP_KERNEL);

	if (!ts->ts_SMWP_wake_lock) {
		E("%s: allocate ts_SMWP_wake_lock failed\n", __func__);
		goto err_smwp_wake_lock_failed;
	}

	wakeup_source_init(ts->ts_SMWP_wake_lock, HIMAX_common_NAME);
#endif
#endif

#if defined(HX_HIGH_SENSE)
	ts->HSEN_enable = 0;
#endif
#if defined(OPPO_PROC_NODE)
	if (OPPO_proc_node_init()) {
		E(" %s:OPPO_proc_node_init failed!\n", __func__);
		goto err_creat_oppo_proc_failed;
	}
	ts->himax_Freq_hop_test_wq = create_singlethread_workqueue("HIMAX_FREQ_hop_test_wq");

	if (!ts->himax_Freq_hop_test_wq) {
		E(" allocate himax_Freq_hop_test_wq failed\n");
		goto err_get_Freq_hop_test_wq_failed;
	}

	INIT_DELAYED_WORK(&ts->himax_Freq_hop_test_wrok, himax_Freq_hop_test_sub);
	ts->Freq_hop_delay_work_start = 0;

#ifdef HX_UPDATE_FW_NOTIFIER
	INIT_WORK(&ts->resume_work_queue, himax_notifie_resume_workqueue);
	himax_update_fw_notifier_init();
#endif

#ifdef HX_TP_USB_NOTIFIER
	//INIT_WORK(&ts->usb_detect_work_queue, himax_usb_detect_workqueue);
	himax_tp_usb_notifier_init();
#endif

#ifdef HX_TP_HEADSET_NOTIFIER
	INIT_WORK(&ts->headset_work_queue, himax_tp_headset_workqueue);
	himax_tp_headset_notifier_init();
#endif
#endif
	if (himax_common_proc_init()) {
		E(" %s: himax_common proc_init failed!\n", __func__);
		goto err_creat_proc_file_failed;
	}
/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_DEBUG)
	if (himax_debug_init()) {
		E(" %s: debug initial failed!\n", __func__);
		goto err_debug_init_failed;
	}
#endif

	ret = himax_input_register(ts);
	if (ret) {
		E("%s: Unable to register %s input device\n",
			__func__, ts->input_dev->name);
		goto err_input_register_device_failed;
	}
mutex_init(&ts->fw_update_lock);
#if defined(HX_CONTAINER_SPEED_UP)
	ts->ts_int_workqueue =
			create_singlethread_workqueue("himax_ts_resume_wq");
	if (!ts->ts_int_workqueue) {
		E("create ts_resume workqueue failed\n");
		goto err_create_ts_resume_wq_failed;
	}
	INIT_DELAYED_WORK(&ts->ts_int_work, himax_resume_work_func);
#endif

	ts->initialized = true;

#if defined(HX_CONFIG_FB) || defined(HX_CONFIG_DRM)
	ts->himax_att_wq = create_singlethread_workqueue("HMX_ATT_request");
	if (!ts->himax_att_wq) {
		E(" allocate himax_att_wq failed\n");
		err = -ENOMEM;
		goto err_get_intr_bit_failed;
	}

	INIT_DELAYED_WORK(&ts->work_att, himax_fb_register);
	queue_delayed_work(ts->himax_att_wq, &ts->work_att,
			msecs_to_jiffies(0));
#endif

	g_hx_chip_inited = true;
	return 0;

#if defined(HX_CONFIG_FB) || defined(HX_CONFIG_DRM)
	cancel_delayed_work_sync(&ts->work_att);
	destroy_workqueue(ts->himax_att_wq);
err_get_intr_bit_failed:
#endif
#if defined(HX_CONTAINER_SPEED_UP)
	cancel_delayed_work_sync(&ts->ts_int_work);
	destroy_workqueue(ts->ts_int_workqueue);
err_create_ts_resume_wq_failed:
#endif
	input_unregister_device(ts->input_dev);
	if (ic_data->HX_STYLUS_FUNC)
		input_unregister_device(ts->stylus_dev);
err_input_register_device_failed:
/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_DEBUG)
	himax_debug_remove();
err_debug_init_failed:
#endif
	himax_common_proc_deinit();
err_creat_proc_file_failed:
#if defined(HX_SMART_WAKEUP)
#if defined(KERNEL_VER_ABOVE_4_19)
	wakeup_source_unregister(ts->ts_SMWP_wake_lock);
#else
	wakeup_source_trash(ts->ts_SMWP_wake_lock);
	kfree(ts->ts_SMWP_wake_lock);
	ts->ts_SMWP_wake_lock = NULL;
err_smwp_wake_lock_failed:
#endif
#endif
#if defined(OPPO_PROC_NODE)
	cancel_delayed_work_sync(&ts->himax_Freq_hop_test_wrok);
	destroy_workqueue(ts->himax_Freq_hop_test_wq);
err_get_Freq_hop_test_wq_failed:
	OPPO_proc_node_deinit();
err_creat_oppo_proc_failed:
#endif
	cancel_delayed_work_sync(&ts->work_boot_upgrade);
	destroy_workqueue(ts->himax_boot_upgrade_wq);
err_boot_upgrade_wq_failed:
	himax_ts_unregister_interrupt();
err_register_interrupt_failed:
#if defined(OPPO_PROC_NODE)
	if (ts->g_fw_buf) {
        kfree(ts->g_fw_buf);
    }
 err_g_fw_buf:
#endif
#if defined(HX_ZERO_FLASH)
	if (g_update_cfg_buf) {
        kfree(g_update_cfg_buf);
    }
err_g_update_cfg_buf:
#endif
/*err_detect_failed:*/
error_ic_detect_failed:
#if !defined(CONFIG_OF)
err_power_failed:
#endif
	himax_gpio_power_deconfig(pdata);
err_alloc_dt_pdata_failed:
	kfree(hx_touch_data);
	hx_touch_data = NULL;
err_alloc_touch_data_failed:
	kfree(ic_data);
	ic_data = NULL;
err_dt_ic_data_fail:
	kfree(pdata);
	pdata = NULL;
err_dt_platform_data_fail:
	devm_kfree(ts->dev, ts->xfer_buff);
	ts->xfer_buff = NULL;
err_xfer_buff_fail:
	probe_fail_flag = 1;
	return err;
}

void himax_chip_common_deinit(void)
{
	struct himax_ts_data *ts = private_ts;

#if defined(HX_ZERO_FLASH)
	if (g_update_cfg_buf != NULL)
		kfree(g_update_cfg_buf);
#endif
	himax_ts_unregister_interrupt();

/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_INSPECT)
	himax_inspect_data_clear();
#endif

/* for gki */
#if (1)
// #if defined(CONFIG_TOUCHSCREEN_HIMAX_DEBUG)
	himax_debug_remove();
#endif

	himax_common_proc_deinit();
#if defined(OPPO_PROC_NODE)		
	OPPO_proc_node_deinit();
#endif
	himax_report_data_deinit();

#if defined(HX_SMART_WAKEUP)
#if defined(KERNEL_VER_ABOVE_4_19)
	wakeup_source_unregister(ts->ts_SMWP_wake_lock);
#else
	wakeup_source_trash(ts->ts_SMWP_wake_lock);
	kfree(ts->ts_SMWP_wake_lock);
	ts->ts_SMWP_wake_lock = NULL;
#endif
#endif
#if defined(HX_CONFIG_FB)
	if (fb_unregister_client(&ts->fb_notif))
		E("Error occurred while unregistering fb_notifier.\n");
	cancel_delayed_work_sync(&ts->work_att);
	destroy_workqueue(ts->himax_att_wq);
#elif defined(HX_CONFIG_DRM_PANEL)
if (active_panel)
	if (drm_panel_notifier_unregister(active_panel,
		&ts->fb_notif))
		E("Error occurred while unregistering active_panel.\n");
else
	if (drm_panel_notifier_unregister(&gNotifier_dummy_panel,
		&ts->fb_notif))
		E("Error occurred while unregistering dummy_panel.\n");
	cancel_delayed_work_sync(&ts->work_att);
	destroy_workqueue(ts->himax_att_wq);
#elif defined(HX_CONFIG_DRM)
#if defined(__HIMAX_MOD__)
	hx_msm_drm_unregister_client =
		(void *)kallsyms_lookup_name("msm_drm_unregister_client");
	if (hx_msm_drm_unregister_client != NULL) {
		if (hx_msm_drm_unregister_client(&ts->fb_notif))
			E("Error occurred while unregistering drm_notifier.\n");
	} else
		E("hx_msm_drm_unregister_client is NULL\n");
#else
	if (msm_drm_unregister_client(&ts->fb_notif))
		E("Error occurred while unregistering drm_notifier.\n");
#endif
	cancel_delayed_work_sync(&ts->work_att);
	destroy_workqueue(ts->himax_att_wq);
#endif
	input_unregister_device(ts->input_dev);
	if (ic_data->HX_STYLUS_FUNC)
		input_unregister_device(ts->stylus_dev);
#if defined(HX_CONTAINER_SPEED_UP)
	cancel_delayed_work_sync(&ts->ts_int_work);
	destroy_workqueue(ts->ts_int_workqueue);
#endif

#if defined(HX_BOOT_UPGRADE) || defined(HX_ZERO_FLASH)
	cancel_delayed_work_sync(&ts->work_boot_upgrade);
	destroy_workqueue(ts->himax_boot_upgrade_wq);
#endif
	himax_gpio_power_deconfig(ts->pdata);
	if (himax_mcu_cmd_struct_free)
		himax_mcu_cmd_struct_free();

	kfree(hx_touch_data);
	hx_touch_data = NULL;
	kfree(ic_data);
	ic_data = NULL;
	devm_kfree(ts->dev, ts->xfer_buff);
	ts->xfer_buff = NULL;
	kfree(ts->pdata);
	ts->pdata = NULL;
	kfree(ts);
	ts = NULL;
	probe_fail_flag = 0;
#if defined(HX_USE_KSYM)
	hx_release_chip_entry();
#endif

	I("%s: Common section deinited!\n", __func__);
}

void resend_cmd(struct himax_ts_data *ts){
	char buf[4]	=	{0};
	himax_parse_assign_cmd(fw_oppo_tp_direction_0_pwd, buf, sizeof(buf));
	g_core_fp.fp_register_write(pfw_op->addr_oppo_tp_direction/*0x10007f3c*/,  buf, DATA_LEN_4);
	ts->touch_direction = 0;
	I("%s: oppo_tp_direction disable .\n", __func__);
}

int himax_chip_common_suspend(struct himax_ts_data *ts)
{
	if (ts->suspended) {
		I("%s: Already suspended, skip...\n", __func__);
		goto END;
	} else {
		ts->suspended = true;
	}

	if (debug_data != NULL && debug_data->flash_dump_going == true) {
		I("%s: It is dumping flash, reject suspend\n", __func__);
		goto END;
	}

	I("%s: enter\n", __func__);

	if (ts->in_self_test == 1) {
		atomic_set(&ts->suspend_mode, 1);
		ts->pre_finger_mask = 0;
		if (g_core_fp._ap_notify_fw_sus != NULL)
			g_core_fp._ap_notify_fw_sus(1);
		ts->suspend_resume_done = 1;
		goto END;
	}

	g_core_fp.fp_suspend_proc(ts->suspended);

	if (ts->SMWP_enable) {
		himax_report_all_leave_event(ts);
		if (g_core_fp.fp_0f_overlay != NULL)
			g_core_fp.fp_0f_overlay(2, 0);

		if (g_core_fp._ap_notify_fw_sus != NULL)
			g_core_fp._ap_notify_fw_sus(1);
		atomic_set(&ts->suspend_mode, 1);
		ts->pre_finger_mask = 0;
		I("%s: SMART WAKE UP enable, reject suspend\n", __func__);
		goto END;
	}

	himax_int_enable(0);
	himax_report_all_leave_event(ts);
	if (g_core_fp.fp_suspend_ic_action != NULL)
		g_core_fp.fp_suspend_ic_action();

	if (!ts->use_irq) {
		int32_t cancel_state;

		cancel_state = cancel_work_sync(&ts->work);
		if (cancel_state)
			himax_int_enable(1);
	}

	/*ts->first_pressed = 0;*/
	atomic_set(&ts->suspend_mode, 1);
	ts->pre_finger_mask = 0;

	if (ts->pdata)
		if (ts->pdata->powerOff3V3 && ts->pdata->power)
			ts->pdata->power(0);

END:
#if defined(OPPO_PROC_NODE)
	ts->suspend_state = TP_SUSPEND_COMPLETE;
#endif
	I("%s: END\n", __func__);

	return 0;
}

int himax_chip_common_resume(struct himax_ts_data *ts)
{
	if (ts->suspended == false) {
		I("%s: Already resumed, skip...\n", __func__);
		goto END;
	} else {
		ts->suspended = false;
	}
#if defined(DD_VSN_RECOV_EXCP)		
	private_ts->vsn_flag = 0;
	private_ts->update_fw_fail = 0;
	private_ts->update_fw_flag = 0;	
#endif
	I("%s: enter\n", __func__);

	if (ts->in_self_test == 1) {
		atomic_set(&ts->suspend_mode, 0);
		ts->diag_cmd = 0;
		if (g_core_fp._ap_notify_fw_sus != NULL)
			g_core_fp._ap_notify_fw_sus(0);
		ts->suspend_resume_done = 1;
		goto END;
	}

#if defined(HX_EXCP_RECOVERY)
	/* continuous N times record, not total N times. */
	g_zero_event_count = 0;
	HX_EXCP_DD_RESET_ACTIVATE = 0;
#endif

	atomic_set(&ts->suspend_mode, 0);
	ts->diag_cmd = 0;
	if (ts->SMWP_enable)
		himax_int_enable(0);
	if (ts->pdata)
		if (ts->pdata->powerOff3V3 && ts->pdata->power)
			ts->pdata->power(1);
#if defined(HX_RST_PIN_FUNC) && defined(HX_RESUME_HW_RESET)
	if (g_core_fp.fp_ic_reset != NULL)
		g_core_fp.fp_ic_reset(false, false);
#endif

	g_core_fp.fp_resume_proc(ts->suspended);
	/* Direction to 0 */
	resend_cmd(ts);
	/* headset_mode and usb_mode resend */
	himax_headset_mode_switch(ts->headset_mode);
	himax_usb_mode_switch(ts->charge_mode);
	himax_report_all_leave_event(ts);
	himax_int_enable(1);
/*
 *#if defined(HX_ZERO_FLASH) && defined(HX_RESUME_SET_FW)
 *ESCAPE_0F_UPDATE:
 *#*endif
 */
END:
#if defined(OPPO_PROC_NODE)
    ts->suspend_state = TP_SPEEDUP_RESUME_COMPLETE;
#endif

	I("%s: END\n", __func__);
	return 0;
}
