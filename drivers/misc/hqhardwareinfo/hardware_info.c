/* Huaqin  Inc. (C) 2011. All rights reserved.
 *
 * BY OPENING THIS FILE, RECEIVER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND AGREES
 * THAT THE SOFTWARE/FIRMWARE AND ITS DOCUMENTATIONS ("HUAQIN SOFTWARE")
 * RECEIVED FROM HUAQIN AND/OR ITS REPRESENTATIVES ARE PROVIDED TO RECEIVER ON
 * AN "AS-IS" BASIS ONLY. HUAQIN EXPRESSLY DISCLAIMS ANY AND ALL WARRANTIES,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NONINFRINGEMENT.
 * NEITHER DOES HUAQIN PROVIDE ANY WARRANTY WHATSOEVER WITH RESPECT TO THE
 * SOFTWARE OF ANY THIRD PARTY WHICH MAY BE USED BY, INCORPORATED IN, OR
 * SUPPLIED WITH THE HUAQIN SOFTWARE, AND RECEIVER AGREES TO LOOK ONLY TO SUCH
 * THIRD PARTY FOR ANY WARRANTY CLAIM RELATING THERETO. RECEIVER EXPRESSLY ACKNOWLEDGES
 * THAT IT IS RECEIVER'S SOLE RESPONSIBILITY TO OBTAIN FROM ANY THIRD PARTY ALL PROPER LICENSES
 * CONTAINED IN HUAQIN SOFTWARE. HUAQIN SHALL ALSO NOT BE RESPONSIBLE FOR ANY HUAQIN
 * SOFTWARE RELEASES MADE TO RECEIVER'S SPECIFICATION OR TO CONFORM TO A PARTICULAR
 * STANDARD OR OPEN FORUM. RECEIVER'S SOLE AND EXCLUSIVE REMEDY AND HUAQIN'S ENTIRE AND
 * CUMULATIVE LIABILITY WITH RESPECT TO THE HUAQIN SOFTWARE RELEASED HEREUNDER WILL BE,
 * AT HUAQIN'S OPTION, TO REVISE OR REPLACE THE HUAQIN SOFTWARE AT ISSUE,
 * OR REFUND ANY SOFTWARE LICENSE FEES OR SERVICE CHARGE PAID BY RECEIVER TO
 * HUAQIN FOR SUCH HUAQIN SOFTWARE AT ISSUE.
 *
 */

/*******************************************************************************
* Dependency
*******************************************************************************/

#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <drm/drm_atomic_helper.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/hardware_info.h>
#include <linux/regulator/consumer.h>

#include <linux/mm.h>
#include <linux/genhd.h>

#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/export.h>

//liukangping add hardinfo sensor begin
#if defined(CONFIG_NANOHUB) && defined(CONFIG_CUSTOM_KERNEL_SENSORHUB)
#include "../mediatek/sensors-1.0/sensorHub/inc_v1/SCP_sensorHub.h"
#include "../mediatek/sensors-1.0/hwmon/include/hwmsensor.h"
#endif
//liukangping add hardinfo sensor end

const char *dfy;

#define CMDLINE_PATH "/proc/cmdline"
#define CMDLINE_LEN 4096
static char cmdline[CMDLINE_LEN]= {0};
char rst[128] = {0};

//extern int chipid_num;
//int sim1_card_slot = -1;
//int sim2_card_slot = -1;
int sdcard_gpio_value = -1;
int nicky_gpio_value = -1;
#define HARDWARE_INFO_NICO_A "oplus C31"
#define HARDWARE_INFO_NICO_B "oplus 50i Prime"
#define HARDWARE_INFO_NICO_C "oplus C30"
#define HARDWARE_INFO_NICKY "oplus C35"
#define HARDWARE_INFO_NICKY_A "narzo 50A Prime"
/*暂用机型名代替*/
#define HARDWARE_INFO_HULK "oplus C51"
#define HARDWARE_INFO_HULK_A "oplus C51"
#define HARDWARE_INFO_HULK_B "oplus C53"
#define HARDWARE_INFO_HULK_C "oplus narzo N53"
#define HARDWARE_INFO_HULK_D "oplus C53"
#define HARDWARE_INFO_HULK_E "rmx3763"
#define HARDWARE_INFO_HULK_K "oplus Note 50"
#define HARDWARE_INFO_HULK_M "oplus C51s"

char emmc_buf_size[16];
int prj_name_flag = -1;

/******************************************************************************
 * EMMC Configuration
*******************************************************************************/
#define DDR_TYPE "LPDDR4X"

static int current_type_value = 0;

static BOARD_TYPE_TABLE pcba_type_table[] =
{
    { .type_value = 0,  .pcba_type_name = "QN1613A", },
    { .type_value = 1,  .pcba_type_name = "QN1613B", },
    { .type_value = 2,  .pcba_type_name = "QN1613C", },
    { .type_value = 3,  .pcba_type_name = "QN1613D", },
    { .type_value = 4,  .pcba_type_name = "QN3265", },
    { .type_value = -1, .pcba_type_name = "UNKNOWN", },
};

static EMMC_ID emmc_id[] = {
	{.size = 32,  .id = "YMUS6A4TB1A2C1",},
	{.size = 64,  .id = "YMUS7A4TB2A2C1",},
	{.size = 128, .id = "YMUS8A4TB3A2C1",},
	{.size = 256, .id = "YMUS9A4TB4A2C1",},
};
//static struct delayed_work psSetSensorConf_work;

/******************************************************************************
 * Hardware Info Driver
*************************`*****************************************************/
struct global_otp_struct hw_info_main_otp;
struct global_otp_struct hw_info_main2_otp;
struct global_otp_struct hw_info_main3_otp;
struct global_otp_struct hw_info_sub_otp;
static HARDWARE_INFO hwinfo_data;
const char * pcb_name = NULL;
/*
void do_psSetSensorConf_work(struct work_struct *work)
{
    printk("%s: current_stage_value = %d\n",__func__,current_stage_value);
    sensor_set_cmd_to_hub(ID_PROXIMITY, CUST_ACTION_SET_SENSOR_CONF, &current_stage_value);
}
*/

int search_str(char* str, char **result)
{
	char* pstr = str;
	int i = 0;
	int j = 0;
	int n = 0;
	int m = 0;

	memset(rst, 0, sizeof(rst));
	if(cmdline == NULL)
	{
		return -1;
	}

	while(i <= strlen(cmdline) - 1 && j <= strlen(pstr) - 1) {
		if(cmdline[i] == pstr[j]) {
			i++;
			j++;
		} else {
			i = i - j + 1;
			j = 0;
		}
	}

	if(i >= strlen(cmdline) - 1) {
		return -1;
	}

	m = n = i;

	if(cmdline[i] != '"') {
		while(cmdline[i] != ' ' && cmdline[i] != '\0')
			i++;
		n = i - n;
		if (n > 0)
			memcpy(rst, cmdline + m, n);
	} else {
		i = i + 1;
		while(cmdline[i] != '"')
			i++;
		n = i - (n + 1);
		if (n > 0)
			memcpy(rst, cmdline + m + 1, n);
	}

	*result = rst;
	return 0;
}
EXPORT_SYMBOL(search_str);

static int hq_prj_name_setup()
{
	char *prj_name = NULL;

	search_str("prj_name=", &prj_name);
	if (prj_name == NULL) {
		return -1;
	}

	if ((strncmp(prj_name, "22716", 5) == 0) || (strncmp(prj_name, "22717", 5) == 0) ||
		(strncmp(prj_name, "22718", 5) == 0)){
		prj_name_flag = 1;
	} else if ((strncmp(prj_name, "22720", 5) == 0) || (strncmp(prj_name, "22721", 5) == 0) ||
		(strncmp(prj_name, "22729", 5) == 0)){
		prj_name_flag = 2;
	} else if ((strncmp(prj_name, "22722", 5) == 0) || (strncmp(prj_name, "22723", 5) == 0) ||
		(strncmp(prj_name, "22724", 5) == 0)){
		prj_name_flag = 3;
	}else if (strncmp(prj_name, "22726", 5) == 0){
		prj_name_flag = 4;
	}else if (strncmp(prj_name, "22734", 5) == 0){
		prj_name_flag = 5;
	} else if ((strncmp(prj_name, "23665", 5) == 0) || (strncmp(prj_name, "23666", 5) == 0)){
		prj_name_flag = 6;
	} else if ((strncmp(prj_name, "23711", 5) == 0) || (strncmp(prj_name, "23712", 5) == 0) ||
		(strncmp(prj_name, "23713", 5) == 0)){
		prj_name_flag = 7;
	} else if (strncmp(prj_name, "23633", 5) == 0){
		prj_name_flag = 8;
	}
	return 0;
}

void write_cam_otp_info(enum hardware_id id,struct global_otp_struct *cam_otp)
{
    if(NULL == cam_otp){
            printk("[HWINFO] %s the data of hwid %d is NULL\n", __func__, id);
    } else {
        switch(id){
            case  HWID_MAIN_OTP:
                hw_info_main_otp = *cam_otp;
                break;
            case HWID_SUB_OTP:
                hw_info_sub_otp = *cam_otp;
                break;
            case HWID_MAIN_OTP_2:
                hw_info_main2_otp = *cam_otp;
                break;
            case HWID_MAIN_OTP_3:
                hw_info_main3_otp = *cam_otp;
                break;
            default:
                printk("[HWINFO] %s Invalid HWID\n", __func__);
                break;
        }
    }
}

void get_hardware_info_data(enum hardware_id id, const void *data)
{
    if (NULL == data) {
        printk("[HWINFO] %s the data of hwid %d is NULL\n", __func__, id);
    } else {
        switch (id) {
        case HWID_CTP_DRIVER:
            hwinfo_data.ctp_driver = data;
		    dfy = data;
		printk("dfy=:%s,%s,%s,%d",dfy,hwinfo_data.ctp_driver,__func__,__LINE__);
            break;
        case HWID_CTP_MODULE:
            hwinfo_data.ctp_module = data;
            break;
        case HWID_CTP_FW_VER:
            strcpy(hwinfo_data.ctp_fw_version,data);
            break;
		#if 0
        case HWID_CTP_COLOR_INFO:
            hwinfo_data.ctp_color_info = data;
            break;
        case HWID_CTP_LOCKDOWN_INFO:
            hwinfo_data.ctp_lockdown_info = data;
            break;
		#endif
        case HWID_CTP_FW_INFO:
		    hwinfo_data.ctp_fw_info = data;
            break;
        case HWID_MAIN_CAM:
            hwinfo_data.main_camera = data;
            break;
        case HWID_MAIN_CAM_2:
            hwinfo_data.main_camera2 = data;
            break;
        case HWID_MAIN_CAM_3:
            hwinfo_data.main_camera3 = data;
            break;
        case HWID_SUB_CAM:
            hwinfo_data.sub_camera = data;
            break;
		#if 0
        case HWId_HIFI_NAME:
            hwinfo_data.hifi_name= data;
            break;
		#endif
        case HWID_FLASH:
            hwinfo_data.flash = data;
            break;
        case HWID_FLASH_SLOT:
            strcpy(hwinfo_data.flash_slot,data);
            break;
        case HWID_PS:
            hwinfo_data.ps = data;
            break;
        case HWID_GSENSOR:
            hwinfo_data.gsensor = data;
            break;
        case HWID_GYROSCOPE:
            hwinfo_data.gyroscope = data;
            break;
        case HWID_MSENSOR:
            hwinfo_data.msensor = data;
            break;
        case HWID_SAR_SENSOR_1:
            hwinfo_data.sar_sensor_1 = data;
            break;
        case HWID_SAR_SENSOR_2:
            hwinfo_data.sar_sensor_2 = data;
            break;
        case HWID_BATERY_ID:
            hwinfo_data.bat_id = data;
            break;
        case HWID_NFC:
            hwinfo_data.nfc = data;
            break;
        case HWID_FINGERPRINT:
            hwinfo_data.fingerprint = data;
            break;
        //fanjiafeng5 add for pdx213 fingerprint sn add begin
        case HWID_FINGERPRINT_SN:
            hwinfo_data.fingerprint_sn = (unsigned char *)data;
            break;
        //fanjiafeng5  add end
        case HWID_MAIN_CAM_SN:
            strcpy(hwinfo_data.main_cam_sn, data);
            break;
        case HWID_MAIN_CAM_2_SN:
            strcpy(hwinfo_data.main_cam_2_sn, data);
            break;
        case HWID_MAIN_CAM_3_SN:
            strcpy(hwinfo_data.main_cam_3_sn, data);
            break;
        case HWID_SUB_CAM_SN:
            strcpy(hwinfo_data.sub_cam_sn, data);
            break;
		#if 0
        case HWID_SMARTPA:
            hwinfo_data.smartpa = data;
            break;
		#endif
        case HWID_ALS:
            hwinfo_data.als = data;
            break;

        default:
            printk("[HWINFO] %s Invalid HWID\n", __func__);
            break;
        }
    }
}
EXPORT_SYMBOL(get_hardware_info_data);

static ssize_t show_lcm(struct device *dev, struct device_attribute *attr, char *buf)
{
	char *lcd_hardware_name = NULL;

    search_str("lcd_name=", &lcd_hardware_name);
	printk("lcd_name : %s", lcd_hardware_name);
    if (NULL != lcd_hardware_name) {
        return sprintf(buf, "lcd name :%s\n", lcd_hardware_name);
    } else {
        return sprintf(buf, "lcd name :Not Found\n");
    }
}
#if 0
static ssize_t show_hifi(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.hifi_name) {
        return sprintf(buf, "hifi_name: %s\n", hwinfo_data.hifi_name);
    } else {
       return sprintf(buf, "hifi :Not Found\n");
    }
}
#endif
static ssize_t show_ctp(struct device *dev, struct device_attribute *attr, char *buf)
{
   printk("dfy=:%s,%s,%s,%d",dfy,hwinfo_data.ctp_driver,__func__,__LINE__);
   hwinfo_data.ctp_driver=dfy;
    if ((NULL != hwinfo_data.ctp_driver) || (NULL != hwinfo_data.ctp_module) || (NULL != hwinfo_data.ctp_fw_version)) {
        return sprintf(buf, "ctp name :%s\n", hwinfo_data.ctp_driver);
    } else {
        return sprintf(buf, "ctp name :Not Found\n");
    }
}

static ssize_t show_fingerprint(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.fingerprint) {
        return sprintf(buf, "fingerprint name :%s\n", hwinfo_data.fingerprint);
    } else {
        return sprintf(buf, "fingerprint name :Not Found\n");
    }
}
//fanjiafeng5 add for pdx213 fingerprint sn add begin
static ssize_t show_fingerprint_sn(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.fingerprint_sn) {
        return sprintf(buf, "fingerprint_sn :%x%x%x%x%x%x\n", hwinfo_data.fingerprint_sn[0],hwinfo_data.fingerprint_sn[1],hwinfo_data.fingerprint_sn[2],hwinfo_data.fingerprint_sn[3],hwinfo_data.fingerprint_sn[4],hwinfo_data.fingerprint_sn[5]);
    } else {
        return sprintf(buf, "fingerprint_sn :Not Found\n");
    }
}
//fanjiafeng5  add end
static ssize_t show_fw_info(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.ctp_fw_info) {
        return sprintf(buf,"fw_ver: %s\n", hwinfo_data.ctp_fw_info);
    } else {
        return sprintf(buf, "Invalid\n");
    }
}

#if 0
static ssize_t show_color_info(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.ctp_color_info) {
        return sprintf(buf, "%s\n", hwinfo_data.ctp_color_info);
    } else {
        return sprintf(buf, "Invalid\n");
    }
}

static ssize_t show_lockdown_info(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.ctp_lockdown_info) {
        return sprintf(buf, "%s\n", hwinfo_data.ctp_lockdown_info);
    } else {
        return sprintf(buf, "Invalid\n");
    }
}
#endif

static ssize_t store_main_camera(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.main_camera = name;
    if (ret) {
        printk("[store_main_camera] %s success .%s\n", __func__, buf);
    } else {
        hwinfo_data.main_camera = "Not found";
        printk("[store_main_camera] %s failed.\n", __func__);
    }
    return count;
}
static ssize_t show_main_camera(struct device *dev, struct device_attribute *attr, char *buf)
{
/*simon modified to show source camera for factory camera mixture in zal1806 start*/
    if (NULL != hw_info_main_otp.sensor_name)
		hwinfo_data.main_camera = hw_info_main_otp.sensor_name;
/*simon modified to show source camera for factory camera mixture in zal1806 end*/
    if (NULL != hwinfo_data.main_camera) {
        return sprintf(buf , "main camera :%s\n", hwinfo_data.main_camera);
    } else {
        return sprintf(buf , "main camera :Not Found\n");
    }
}

static ssize_t store_main_camera2(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.main_camera2 = name;
    if (ret) {
        printk("[store_main_camera2] %s success .%s\n", __func__, buf);
    } else {
        hwinfo_data.main_camera2 = "Not found";
        printk("[store_main_camera2] %s failed.\n", __func__);
    }
    return count;
}

static ssize_t show_main_camera2(struct device *dev, struct device_attribute *attr, char *buf)
{
    /*simon modified to show source camera for factory camera mixture in zal1806 start*/
    if (NULL != hw_info_main2_otp.sensor_name)
		hwinfo_data.main_camera2 = hw_info_main2_otp.sensor_name;
    /*simon modified to show source camera for factory camera mixture in zal1806 end*/
    if (NULL != hwinfo_data.main_camera2) {
        return sprintf(buf , "main camera 2 :%s\n", hwinfo_data.main_camera2);
    } else {
        return sprintf(buf , "main camera :Not Found\n");
    }
}

static ssize_t store_main_camera3(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.main_camera3 = name;
    if (ret) {
        printk("[store_main_camera3] %s success .%s\n", __func__, buf);
    } else {
        hwinfo_data.main_camera3 = "Not found";
        printk("[store_main_camera3] %s failed.\n", __func__);
    }
    return count;
}

static ssize_t show_main_camera3(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.main_camera3) {
        return sprintf(buf , "main camera 3 :%s\n", hwinfo_data.main_camera3);
    } else {
        return sprintf(buf , "main camera :Not Found\n");
    }
}

static ssize_t store_sub_camera(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.sub_camera = name;
    if (ret) {
        printk("[store_sub_camera] %s success .%s\n", __func__, buf);
    } else {
        hwinfo_data.sub_camera = "Not found";
        printk("[store_sub_camera] %s failed.\n", __func__);
    }
    return count;
}

static ssize_t show_sub_camera(struct device *dev, struct device_attribute *attr, char *buf)
{
    /*simon modified to show source camera for factory camera mixture in zal1806 start*/
    if (NULL != hw_info_sub_otp.sensor_name)
		hwinfo_data.sub_camera = hw_info_sub_otp.sensor_name;
    /*simon modified to show source camera for factory camera mixture in zal1806 end*/
    if (NULL != hwinfo_data.sub_camera) {
        return sprintf(buf , "sub camera :%s\n", hwinfo_data.sub_camera);
    } else {
        return sprintf(buf , "sub camera :Not Found\n");
    }
}
/*
static ssize_t show_main_otp(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (hw_info_main_otp.otp_valid) {
        return sprintf(buf, "main otp :Vendor 0x%0x, ModuleCode 0x%x, ModuleVer 0x%x, SW_ver 0x%x, Date %d-%d-%d, VcmVendor 0x%0x, VcmModule 0x%x \n",
                            hw_info_main_otp.vendor_id, hw_info_main_otp.module_code, hw_info_main_otp.module_ver, hw_info_main_otp.sw_ver, hw_info_main_otp.year,
                            hw_info_main_otp.month, hw_info_main_otp.day, hw_info_main_otp.vcm_vendorid, hw_info_main_otp.vcm_moduleid);
    } else {
        return sprintf(buf, "main otp :No Valid OTP\n");
    }
}

static ssize_t show_main2_otp(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (hw_info_main2_otp.otp_valid) {
        return sprintf(buf, "main otp :Vendor 0x%0x, ModuleCode 0x%x, ModuleVer 0x%x, SW_ver 0x%x, Date %d-%d-%d, VcmVendor 0x%0x, VcmModule 0x%x \n",
                            hw_info_main2_otp.vendor_id, hw_info_main2_otp.module_code, hw_info_main2_otp.module_ver, hw_info_main2_otp.sw_ver, hw_info_main2_otp.year,
                            hw_info_main2_otp.month, hw_info_main2_otp.day, hw_info_main2_otp.vcm_vendorid, hw_info_main2_otp.vcm_moduleid);
    } else {
        return sprintf(buf, "main otp :No Valid OTP\n");
    }
}

static ssize_t show_main3_otp(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (hw_info_main3_otp.otp_valid) {
        return sprintf(buf, "main otp :Vendor 0x%0x, ModuleCode 0x%x, ModuleVer 0x%x, SW_ver 0x%x, Date %d-%d-%d, VcmVendor 0x%0x, VcmModule 0x%x \n",
                            hw_info_main3_otp.vendor_id, hw_info_main3_otp.module_code, hw_info_main3_otp.module_ver, hw_info_main3_otp.sw_ver, hw_info_main3_otp.year,
                            hw_info_main3_otp.month, hw_info_main3_otp.day, hw_info_main3_otp.vcm_vendorid, hw_info_main3_otp.vcm_moduleid);
    } else {
        return sprintf(buf, "main otp :No Valid OTP\n");
    }
}

static ssize_t show_sub_otp(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (hw_info_sub_otp.otp_valid) {
        return sprintf(buf, "sub otp :Vendor 0x%0x, ModuleCode 0x%x, ModuleVer 0x%x, SW_ver 0x%x, Date %d-%d-%d, VcmVendor 0x%0x, VcmModule 0x%0x \n",
                            hw_info_sub_otp.vendor_id, hw_info_sub_otp.module_code, hw_info_sub_otp.module_ver, hw_info_sub_otp.sw_ver, hw_info_sub_otp.year,
                            hw_info_sub_otp.month, hw_info_sub_otp.day, hw_info_sub_otp.vcm_vendorid, hw_info_sub_otp.vcm_moduleid);
    } else {
        return sprintf(buf, "sub otp :No Valid OTP\n");
    }
}
*/
#define EMMC_VENDOR_NAME "/sys/bus/platform/drivers/ufshcd-sprd/20200000.ufs/string_descriptors/manufacturer_name"
static int get_emmc_vendor_name(char* buff_name)
{
    struct file *pfile = NULL;
    mm_segment_t old_fs;

    ssize_t ret = 0;
    char vendor_name[EMMC_LEN];
    memset(vendor_name, 0, sizeof(vendor_name));

    if(buff_name == NULL){
        return -1;
    }

    pfile = filp_open(EMMC_VENDOR_NAME, O_RDONLY, 0);
    if (IS_ERR(pfile)) {
        printk("[HWINFO]: open EMMC_VENDOR_NAME file failed!\n");
        goto ERR_0;
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    ret = pfile->f_op->read(pfile, vendor_name, EMMC_LEN, &pfile->f_pos);
    if(ret < 0) {
        printk("[HWINFO]: read EMMC_VENDOR_NAME  file failed!\n");
        goto ERR_1;
    }

	sprintf(buff_name,"%s",vendor_name);
ERR_1:

    set_fs(old_fs);
    filp_close(pfile, NULL);

    return 0;

ERR_0:
    return -1;
}
#define EMMC_VENDOR_VERSION "/sys/bus/platform/drivers/ufshcd-sprd/20200000.ufs/string_descriptors/product_revision"

static unsigned long long get_emmc_version(void)
{
    struct file *pfile = NULL;
    mm_segment_t old_fs;
    ssize_t ret = 0;
    char emmc_buf_size[EMMC_LEN];

    unsigned long long Size_buf = 0;
    memset(emmc_buf_size, 0, sizeof(emmc_buf_size));

    pfile = filp_open(EMMC_VENDOR_VERSION, O_RDONLY, 0);
    if (IS_ERR(pfile)) {
        printk("[HWINFO]: open emmc size file failed!\n");
        goto ERR_0;
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    ret = pfile->f_op->read(pfile, emmc_buf_size, EMMC_LEN, &pfile->f_pos);
    if(ret < 0) {
        printk("[HWINFO]: read emmc size file failed!\n");
        goto ERR_1;
    }
	printk("Emmc_version %s",emmc_buf_size);

ERR_1:

    set_fs(old_fs);
    filp_close(pfile, NULL);

    return Size_buf;

ERR_0:
    return Size_buf;
}


static unsigned int get_emmc_size(void)
{
	unsigned int emmc_size = 32;
	struct file *pfile = NULL;
	mm_segment_t old_fs;
	ssize_t ret = 0;

	unsigned long long Size_buf=0;
	char buf_size_temp[EMMC_LEN];
	char buf_size[19];
	memset(buf_size_temp, 0, sizeof(buf_size_temp));
	memset(buf_size, 0, sizeof(buf_size));

	pfile = filp_open(emmc_file, O_RDONLY, 0);
	if (IS_ERR(pfile)) {
		printk("[HWINFO]: open emmc size file failed!\n");
		goto ERR_0;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	ret = pfile->f_op->read(pfile, buf_size_temp, EMMC_LEN, &pfile->f_pos);
	if(ret < 0) {
		printk("[HWINFO]: read emmc size file failed!\n");
		goto ERR_1;
	}
	strncpy(buf_size,buf_size_temp,18);
	buf_size[18] = '\0';

	Size_buf = simple_strtoull(buf_size, NULL, 0);
	Size_buf >>= 1; //Switch to KB
	emmc_size = (((unsigned int)Size_buf) / 1024) / 1024;

	if (emmc_size > 128) {
		emmc_size = 256;
	} else if (emmc_size > 64) {
		emmc_size = 128;
	} else if (emmc_size > 32) {
		emmc_size = 64;
	} else if (emmc_size > 16) {
		emmc_size = 32;
	} else if (emmc_size > 8) {
		emmc_size = 16;
	} else if (emmc_size > 6) {
		emmc_size = 8;
	} else if (emmc_size > 4) {
		emmc_size = 6;
	} else if (emmc_size > 3) {
		emmc_size = 4;
	} else {
		emmc_size = 0;
	}

ERR_1:

    set_fs(old_fs);
    filp_close(pfile, NULL);

    return emmc_size;

ERR_0:
    return emmc_size;
}

#define K(x) ((x) << (PAGE_SHIFT - 10))
static unsigned int get_ram_size(void)
{
    unsigned int ram_size, temp_size;
    struct sysinfo info;

    si_meminfo(&info);

    temp_size = K(info.totalram) / 1024;
    if (temp_size > 7168) {
        ram_size = 8;
    }  else if (temp_size > 5120) {
        ram_size = 6;
    } else if (temp_size > 3072) {
        ram_size = 4;
    } else if (temp_size > 2048) {
        ram_size = 3;
    } else if (temp_size > 1024) {
        ram_size = 2;
    } else if(temp_size > 512) {
        ram_size = 1;
    } else {
        ram_size = 0;
    }

    return ram_size;
}

static ssize_t show_emmc_size(struct device *dev, struct device_attribute *attr, char *buf)
{
	int emmc_size = 0;
    unsigned long long Size_buf = 0;
	emmc_size = get_emmc_size();
	Size_buf = get_emmc_version();
    return sprintf(buf, "EMMC:%dGB %s\n", emmc_size,emmc_buf_size);
}

static ssize_t show_emmc_version(struct device *dev, struct device_attribute *attr, char *buf)
{
    unsigned long long Size_buf = 0;
	Size_buf = get_emmc_version();
    return sprintf(buf, "EMMC_Version:%s\n", emmc_buf_size);
}

static ssize_t show_ram_size(struct device *dev, struct device_attribute *attr, char *buf)
{
	int ram_size = 0;
	ram_size = get_ram_size();
    return sprintf(buf, "RAM_Size:%dGB\n", ram_size);
}

static ssize_t show_prj_name(struct device *dev, struct device_attribute *attr, char *buf)
{
	char *ptr = NULL;

	search_str("prj_name=", &ptr);
	printk("prj_name: %s", ptr);
	if (ptr == NULL) {
		return -1;
	}
	return sprintf(buf, "%s\n", ptr);
}

static ssize_t show_modem_id(struct device *dev, struct device_attribute *attr, char *buf)
{
	char *ptr = NULL;

	search_str("rfboard.id=", &ptr);
	printk("rfboard_id id: %s", ptr);
	if (ptr == NULL) {
		return -1;
	}
	return sprintf(buf, "modem_id:%s\n", ptr);
}

unsigned int slot_gpio = -1;

static ssize_t show_flash_slot(struct device *dev, struct device_attribute *attr, char *buf)
{
   int value = 1;

   value =  gpio_get_value(slot_gpio);

   if(value != 0) {
       return sprintf(buf, "Card Slot:Yes");
   }else {
       return sprintf(buf, "Card Slot:No");
   }
}


static ssize_t show_stage_id(struct device *dev, struct device_attribute *attr, char *buf)
{
	char *ptr = NULL;

	search_str("pcb_version=", &ptr);
	printk("pcb_version : %s", ptr);
	if (ptr == NULL) {
		return -1;
	}
	return sprintf(buf, "stage_id:%s\n", ptr);
}

char* get_emmc_id(void)
{
	unsigned int size;
	int i;
	char *result = "unknown";
	size=get_emmc_size();

	for (i = 0; i < ARRAY_SIZE(emmc_id); i ++) {
		if (size == emmc_id[i].size) {
			result = emmc_id[i].id;
			break;
		}
	}
	return result;
}


static ssize_t show_flash(struct device *dev, struct device_attribute *attr, char *buf)
{
    char emmc_vendor_name[32] = {0};
    int emmc_size = 0;
    get_emmc_vendor_name(emmc_vendor_name);
    emmc_size = get_emmc_size();
	return sprintf(buf, "flash name :%s %dGB+%dGB %s" , DDR_TYPE, get_ram_size(), emmc_size,emmc_vendor_name);
}

static ssize_t show_ufs_id(struct device *dev, struct device_attribute *attr, char *buf)
{
    return sprintf(buf, "ufs_id:%s\n " , get_emmc_id());
}

static ssize_t show_wifi(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (prj_name_flag == 1) {
        return sprintf(buf, "wifi name :%s\n", HARDWARE_INFO_HULK);
    } else if (prj_name_flag == 2) {
        return sprintf(buf, "wifi name :%s\n", HARDWARE_INFO_HULK_A);
    } else if (prj_name_flag == 3) {
        return sprintf(buf, "wifi name :%s\n", HARDWARE_INFO_HULK_B);
    } else if (prj_name_flag == 4) {
        return sprintf(buf, "wifi name :%s\n", HARDWARE_INFO_HULK_C);
    } else if (prj_name_flag == 5){
        return sprintf(buf, "wifi name :%s\n", HARDWARE_INFO_HULK_D);
    } else if (prj_name_flag == 6){
        return sprintf(buf, "wifi name :%s\n", HARDWARE_INFO_HULK_E);
    } else if (prj_name_flag == 7){
        return sprintf(buf, "wifi name :%s\n", HARDWARE_INFO_HULK_K);
    } else if (prj_name_flag == 8){
        return sprintf(buf, "wifi name :%s\n", HARDWARE_INFO_HULK_M);
    }else{
        return sprintf(buf, "wifi name :%s\n", "unknown");
    }
}

static ssize_t show_bt(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (prj_name_flag == 1) {
        return sprintf(buf, "bt name :%s\n", HARDWARE_INFO_HULK);
    } else if (prj_name_flag == 2) {
        return sprintf(buf, "bt name :%s\n", HARDWARE_INFO_HULK_A);
    } else if (prj_name_flag == 3) {
        return sprintf(buf, "bt name :%s\n", HARDWARE_INFO_HULK_B);
    } else if (prj_name_flag == 4) {
        return sprintf(buf, "bt name :%s\n", HARDWARE_INFO_HULK_C);
    } else if (prj_name_flag == 5){
        return sprintf(buf, "bt name :%s\n", HARDWARE_INFO_HULK_D);
    } else if (prj_name_flag == 6){
        return sprintf(buf, "bt name :%s\n", HARDWARE_INFO_HULK_E);
    } else if (prj_name_flag == 7){
        return sprintf(buf, "bt name :%s\n", HARDWARE_INFO_HULK_K);
    } else if (prj_name_flag == 8){
        return sprintf(buf, "bt name :%s\n", HARDWARE_INFO_HULK_M);
    }else{
        return sprintf(buf, "bt name :%s\n", "unknown");
    }
}

static ssize_t show_gps(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (prj_name_flag == 1) {
        return sprintf(buf, "gps name :%s\n", HARDWARE_INFO_HULK);
    } else if (prj_name_flag == 2) {
        return sprintf(buf, "gps name :%s\n", HARDWARE_INFO_HULK_A);
    } else if (prj_name_flag == 3) {
        return sprintf(buf, "gps name :%s\n", HARDWARE_INFO_HULK_B);
    } else if (prj_name_flag == 4) {
        return sprintf(buf, "gps name :%s\n", HARDWARE_INFO_HULK_C);
    } else if (prj_name_flag == 5){
        return sprintf(buf, "gps name :%s\n", HARDWARE_INFO_HULK_D);
    } else if (prj_name_flag == 6){
        return sprintf(buf, "gps name :%s\n", HARDWARE_INFO_HULK_E);
    } else if (prj_name_flag == 7){
        return sprintf(buf, "gps name :%s\n", HARDWARE_INFO_HULK_K);
    } else if (prj_name_flag == 8){
        return sprintf(buf, "gps name :%s\n", HARDWARE_INFO_HULK_M);
    }else{
        return sprintf(buf, "gps name :%s\n", "unknown");
    }
}

static ssize_t show_fm(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (prj_name_flag == 1) {
        return sprintf(buf, "fm name :%s\n", HARDWARE_INFO_HULK);
    } else if (prj_name_flag == 2) {
        return sprintf(buf, "fm name :%s\n", HARDWARE_INFO_HULK_A);
    } else if (prj_name_flag == 3) {
        return sprintf(buf, "fm name :%s\n", HARDWARE_INFO_HULK_B);
    } else if (prj_name_flag == 4) {
        return sprintf(buf, "fm name :%s\n", HARDWARE_INFO_HULK_C);
    } else if (prj_name_flag == 5){
        return sprintf(buf, "fm name :%s\n", HARDWARE_INFO_HULK_D);
    } else if (prj_name_flag == 6){
        return sprintf(buf, "fm name :%s\n", HARDWARE_INFO_HULK_E);
    } else if (prj_name_flag == 7){
        return sprintf(buf, "fm name :%s\n", HARDWARE_INFO_HULK_K);
    } else if (prj_name_flag == 8){
        return sprintf(buf, "fm name :%s\n", HARDWARE_INFO_HULK_M);
    }else{
        return sprintf(buf, "fm name :%s\n", "unknown");
    }
}

static ssize_t show_ps(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.ps) {
        return sprintf(buf, "ps name :%s\n", hwinfo_data.ps);
    } else {
        return sprintf(buf, "ps name :Not Found\n");
    }
}

static ssize_t store_ps(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.ps = name;
    if (ret) {
        printk("[HWINFO] %s success. %s\n", __func__, buf);
    } else {
        hwinfo_data.ps = "Not found";
        printk("[HWINFO] %s failed.\n", __func__);
    }
    return count;
}

static ssize_t show_als(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.als) {
        return sprintf(buf, "als name :%s\n", hwinfo_data.als);
    } else {
        return sprintf(buf, "als name :Not Found\n");
    }
}

static ssize_t store_als(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.als = name;
    if (ret) {
        printk("[HWINFO] %s success. %s\n", __func__, buf);
    } else {
        hwinfo_data.als = "Not found";
        printk("[HWINFO] %s failed.\n", __func__);
    }
    return count;
}

static ssize_t show_gsensor(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.gsensor) {
        return sprintf(buf, "gsensor name :%s\n", hwinfo_data.gsensor);
    } else {
        return sprintf(buf, "gsensor name :Not Found\n");
    }
}

static ssize_t store_gsensor(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.gsensor = name;
    if (ret) {
        printk("[HWINFO] %s success .%s\n", __func__, buf);
    } else {
        hwinfo_data.gsensor = "Not found";
        printk("[HWINFO] %s failed.\n", __func__);
    }
    return count;
}

static ssize_t show_msensor(struct device *dev, struct device_attribute *attr, char *buf)
{

    if (NULL != hwinfo_data.msensor) {
        return sprintf(buf, "msensor name :%s\n", hwinfo_data.msensor);
    } else {
        return sprintf(buf, "msensor name :Not Found\n");
    }
}
static ssize_t store_msensor(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{

    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.msensor = name;
    if (ret) {
        printk("[HWINFO] %s success. %s\n", __func__, buf);
    } else {
        hwinfo_data.msensor = "Not found";
        printk("[HWINFO] %s failed.\n", __func__);
    }
    return count;
}

static ssize_t show_gyro(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.gyroscope) {
        return sprintf(buf, "gyro name :%s\n", hwinfo_data.gyroscope);
    } else {
        return sprintf(buf, "gyro name :Not Found\n");
    }
}

static ssize_t store_gyro(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.gyroscope = name;
    if (ret) {
        printk("[HWINFO] %s success. %s\n", __func__, buf);
    } else {
        hwinfo_data.gyroscope = "Not found";
        printk("[HWINFO] %s failed.\n", __func__);
    }
    return count;
}

static ssize_t show_sar_sensor_1(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.sar_sensor_1) {
        return sprintf(buf, "sar_sensor_1 name :%s\n", hwinfo_data.sar_sensor_1);
    } else {
        return sprintf(buf, "sar_sensor_1 name :Not Found\n");
    }
}

static ssize_t show_sar_sensor_2(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.sar_sensor_2) {
        return sprintf(buf, "sar_sensor_2 name :%s\n", hwinfo_data.sar_sensor_2);
    } else {
        return sprintf(buf, "sar_sensor_2 name :Not Found\n");
    }
}
static ssize_t store_sar_sensor_1(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
#ifdef QCOM_SENSOR_INFO_NEED_SET
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.sar_sensor_1 = name;
    if (ret) {
        printk("[HWINFO] %s success. %s\n", __func__, buf);
    } else {
        hwinfo_data.sar_sensor_1 = "Not found";
        printk("[HWINFO] %s failed.\n", __func__);
    }
#else
    hwinfo_data.sar_sensor_1 = "Not found";
#endif
    return count;
}

static ssize_t store_sar_sensor_2(struct device *dev, struct device_attribute *attr,\
        const char *buf, size_t count)
{
#ifdef QCOM_SENSOR_INFO_NEED_SET
    int ret;
    static char name[100] = "Not found";
    ret = snprintf(name, 100, "%s", buf);
    hwinfo_data.sar_sensor_2 = name;
    if (ret) {
        printk("[HWINFO] %s success. %s\n", __func__, buf);
    } else {
        hwinfo_data.sar_sensor_2 = "Not found";
        printk("[HWINFO] %s failed.\n", __func__);
    }
#else
    hwinfo_data.sar_sensor_2 = "Not found";
#endif
    return count;
}

static ssize_t show_version(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (prj_name_flag == 1) {
        return sprintf(buf, "version :%s\n", HARDWARE_INFO_HULK);
    } else if (prj_name_flag == 2) {
        return sprintf(buf, "version :%s\n", HARDWARE_INFO_HULK_A);
    } else if (prj_name_flag == 3) {
        return sprintf(buf, "version :%s\n", HARDWARE_INFO_HULK_B);
    } else if (prj_name_flag == 4) {
        return sprintf(buf, "version :%s\n", HARDWARE_INFO_HULK_C);
    } else if (prj_name_flag == 5){
        return sprintf(buf, "version :%s\n", HARDWARE_INFO_HULK_D);
    } else if (prj_name_flag == 6){
        return sprintf(buf, "version :%s\n", HARDWARE_INFO_HULK_E);
    } else if (prj_name_flag == 7){
        return sprintf(buf, "version :%s\n", HARDWARE_INFO_HULK_K);
    } else if (prj_name_flag == 8){
        return sprintf(buf, "version :%s\n", HARDWARE_INFO_HULK_M);
    } else{
        return sprintf(buf, "version :%s\n", "unknown");
    }
}
#if 0
/* hongzhenglong@ODM.HQ.Charger 2021/02/07 add hardinfo for charger_ic */
static ssize_t show_charger_ic(struct device *dev, struct device_attribute *attr, char *buf)
{
    if(chipid_num == 0x02){
       return sprintf(buf, "charger_ic_name:sgm41511\n");
    } else if(chipid_num == 0x8){
       return sprintf(buf, "charger_ic_name:bq21120\n");
	} else if(chipid_num == 0x9){
       return sprintf(buf, "charger_ic_name:SY6974\n");
    } else {
       return sprintf(buf, "charger_ic_name:NotFound\n");
    }
}
#endif
static ssize_t show_bat_id(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.bat_id) {
        return sprintf(buf, "bat_id name :%s\n", hwinfo_data.bat_id);
    } else {
        return sprintf(buf, "bat_id name :Not found\n");
    }
}

static ssize_t show_nfc(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (NULL != hwinfo_data.nfc) {
        return sprintf(buf, "nfc chip_hwid :%s\n", hwinfo_data.nfc);
    } else {
        return sprintf(buf, "nfc name :Not found\n");
    }
}


char* get_type_name(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(pcba_type_table); i ++) {
        if (current_type_value == pcba_type_table[i].type_value) {
            return pcba_type_table[i].pcba_type_name;
        }
    }

    return pcba_type_table[ARRAY_SIZE(pcba_type_table) - 1].pcba_type_name;
}


EXPORT_SYMBOL(get_type_name);

#if 0
static ssize_t show_hw_id(struct device *dev, struct device_attribute *attr, char *buf)
{
    char *chstageid = NULL;

	search_str("pcb_stage_id=", &chstageid);

	if(chstageid == NULL) {
		return sprintf(buf, "%s\n", "pcb_stage_id=NULL");
	} else {
		return sprintf(buf, "PCBA_%s_%s\n", get_type_name(),chstageid);
	}
}
#endif

static ssize_t show_main_cam_sn(struct device *dev, struct device_attribute *attr, char *buf)
{
    printk("[HWINFO] %s:%s\n", __func__, hwinfo_data.main_cam_sn);
    if (hwinfo_data.main_cam_sn != NULL) {
        return sprintf(buf, "%s\n", hwinfo_data.main_cam_sn);
    } else {
        return sprintf(buf, "Not found\n");
    }
}

static ssize_t show_main_cam_2_sn(struct device *dev, struct device_attribute *attr, char *buf)
{
    printk("[HWINFO] %s:%s\n", __func__, hwinfo_data.main_cam_2_sn);
    if (hwinfo_data.main_cam_2_sn != NULL)
        return sprintf(buf, "%s\n", hwinfo_data.main_cam_2_sn);
    else
        return sprintf(buf, "Not_found\n");
}

static ssize_t show_main_cam_3_sn(struct device *dev, struct device_attribute *attr, char *buf)
{
    printk("[HWINFO] %s:%s\n", __func__, hwinfo_data.main_cam_3_sn);
    if (hwinfo_data.main_cam_3_sn != NULL)
        return sprintf(buf, "%s\n", hwinfo_data.main_cam_3_sn);
    else
        return sprintf(buf, "Not found\n");
}

static ssize_t show_sub_cam_sn(struct device *dev, struct device_attribute *attr, char *buf)
{
    printk("[HWINFO] %s:%s\n", __func__, hwinfo_data.sub_cam_sn);
    if (hwinfo_data.sub_cam_sn != NULL)
        return sprintf(buf, "%s\n", hwinfo_data.sub_cam_sn);
    else
        return sprintf(buf, "Not found\n");
}

#if 0
static ssize_t show_sim1_card_slot_status(struct device *dev, struct device_attribute *attr, char *buf)
{
    int sim1_card_slot_status;
    sim1_card_slot_status = gpio_get_value(sim1_card_slot);
    if (sim1_card_slot_status)
        return sprintf(buf, "SIM1 SLOT :%s\n", "1");
    else
        return sprintf(buf, "SIM1 SLOT :%s\n", "0");
}

static ssize_t show_sim2_card_slot_status(struct device *dev, struct device_attribute *attr, char *buf)
{
    int sim2_card_slot_status;
    sim2_card_slot_status = gpio_get_value(sim2_card_slot);
    if (sim2_card_slot_status)
        return sprintf(buf, "SIM2 SLOT :%s%s\n", "1");
    else
        return sprintf(buf, "SIM2 SLOT :%s%s\n", "0");
}

static ssize_t show_smartpa_type(struct device *dev, struct device_attribute *attr, char *buf)
{
    if (hwinfo_data.smartpa != NULL)
        return sprintf(buf, "smartpa:%s\n", hwinfo_data.smartpa);
    else
        return sprintf(buf, "smartpa:Not_found\n");
}
#endif

static ssize_t show_fuseflag(struct device *dev, struct device_attribute *attr, char *buf)
{
	char *fuse_flag = NULL;

	search_str("isfuse=", &fuse_flag);
	if (fuse_flag != NULL) {
		return sprintf(buf, "Fuse flag :%s\n", fuse_flag);
	} else
		return sprintf(buf, "Fuse flag : Not_found\n");
}

static ssize_t show_sdcard_detect(struct device *dev, struct device_attribute *attr, char *buf)
{
    int value = 0;
    value =  gpio_get_value(sdcard_gpio_value);
    printk("sdcard value =%d\n",value);
    return sprintf(buf, "sdcard:%d\n", value);
}

static ssize_t show_version_flag(struct device *dev, struct device_attribute *attr, char *buf)
{
    printk("version flag = %d\n",nicky_gpio_value);
    return sprintf(buf, "version flag:%d\n", nicky_gpio_value);
}

static DEVICE_ATTR(version, 0444, show_version, NULL);
static DEVICE_ATTR(lcm, 0444, show_lcm, NULL);
static DEVICE_ATTR(ctp, 0444, show_ctp, NULL);
static DEVICE_ATTR(ctp_fw, 0444, show_fw_info, NULL);
//static DEVICE_ATTR(ctp_color, 0444, show_color_info, NULL);
//static DEVICE_ATTR(ctp_lockdown, 0444, show_lockdown_info, NULL);
static DEVICE_ATTR(main_camera, 0644, show_main_camera, store_main_camera);
static DEVICE_ATTR(main_camera2, 0644, show_main_camera2, store_main_camera2);
static DEVICE_ATTR(main_camera3, 0644, show_main_camera3, store_main_camera3);
static DEVICE_ATTR(sub_camera, 0644, show_sub_camera, store_sub_camera);
static DEVICE_ATTR(flash, 0444, show_flash, NULL);
static DEVICE_ATTR(ufs_id, 0444, show_ufs_id, NULL);
static DEVICE_ATTR(flash_slot, 0444, show_flash_slot, NULL);
//static DEVICE_ATTR(hifi_name, 0444, show_hifi, NULL);
static DEVICE_ATTR(emmc_size, 0444, show_emmc_size, NULL);
static DEVICE_ATTR(emmc_version, 0444, show_emmc_version, NULL);
static DEVICE_ATTR(ram_size, 0444, show_ram_size, NULL);
static DEVICE_ATTR(modem_id, 0444, show_modem_id, NULL);
static DEVICE_ATTR(prj_name, 0444, show_prj_name, NULL);
static DEVICE_ATTR(stage_id, 0444, show_stage_id, NULL);
static DEVICE_ATTR(gsensor, 0644, show_gsensor, store_gsensor);
static DEVICE_ATTR(msensor, 0644, show_msensor, store_msensor);
static DEVICE_ATTR(ps, 0644, show_ps, store_ps);
static DEVICE_ATTR(als, 0644, show_als, store_als);
static DEVICE_ATTR(gyro, 0644, show_gyro, store_gyro);
static DEVICE_ATTR(wifi, 0444, show_wifi, NULL);
static DEVICE_ATTR(bt, 0444, show_bt, NULL);
static DEVICE_ATTR(gps, 0444, show_gps, NULL);
static DEVICE_ATTR(fm, 0444, show_fm, NULL);
//static DEVICE_ATTR(main_otp, 0444, show_main_otp, NULL);
//static DEVICE_ATTR(main2_otp, 0444, show_main2_otp, NULL);
//static DEVICE_ATTR(main3_otp, 0444, show_main3_otp, NULL);
//static DEVICE_ATTR(sub_otp, 0444, show_sub_otp, NULL);
static DEVICE_ATTR(sar_sensor_1, 0644, show_sar_sensor_1, store_sar_sensor_1);
static DEVICE_ATTR(sar_sensor_2, 0644, show_sar_sensor_2, store_sar_sensor_2);
static DEVICE_ATTR(bat_id, 0444, show_bat_id,NULL );
//static DEVICE_ATTR(charger_ic, 0444, show_charger_ic,NULL );
static DEVICE_ATTR(nfc, 0444, show_nfc,NULL );
//static DEVICE_ATTR(hw_id, 0444, show_hw_id, NULL);
static DEVICE_ATTR(fingerprint, 0444, show_fingerprint, NULL);
//fanjiafeng5 add for pdx213 fingerprint sn add begin
static DEVICE_ATTR(fingerprint_sn, 0444, show_fingerprint_sn, NULL);
//fanjiafeng5 add end
static DEVICE_ATTR(main_cam_sn, 0444, show_main_cam_sn, NULL);
static DEVICE_ATTR(main_cam_2_sn, 0444, show_main_cam_2_sn, NULL);
static DEVICE_ATTR(main_cam_3_sn, 0444, show_main_cam_3_sn, NULL);
static DEVICE_ATTR(sub_cam_sn, 0444, show_sub_cam_sn, NULL);
//static DEVICE_ATTR(sim1_card_slot_status, 0444, show_sim1_card_slot_status, NULL);
//static DEVICE_ATTR(sim2_card_slot_status, 0444, show_sim2_card_slot_status, NULL);
//static DEVICE_ATTR(smartpa, 0444, show_smartpa_type, NULL);
static DEVICE_ATTR(sdcard_detect, 0444, show_sdcard_detect, NULL);
static DEVICE_ATTR(Fuse_flag, 0444, show_fuseflag, NULL);
static DEVICE_ATTR(version_flag, 0444, show_version_flag, NULL);

static struct attribute *hdinfo_attributes[] = {
    &dev_attr_version.attr,
    &dev_attr_lcm.attr,
    &dev_attr_ctp.attr,
    &dev_attr_ctp_fw.attr,
    //&dev_attr_ctp_color.attr,
    //&dev_attr_ctp_lockdown.attr,
    &dev_attr_main_camera.attr,
    &dev_attr_main_camera2.attr,
    &dev_attr_main_camera3.attr,
    &dev_attr_sub_camera.attr,
    &dev_attr_flash.attr,
    &dev_attr_flash_slot.attr,
    &dev_attr_ufs_id.attr,
    //&dev_attr_hifi_name.attr,
    &dev_attr_emmc_size.attr,
	&dev_attr_emmc_version.attr,
    &dev_attr_ram_size.attr,
    &dev_attr_modem_id.attr,
    &dev_attr_prj_name.attr,
    &dev_attr_stage_id.attr,
    &dev_attr_gsensor.attr,
    &dev_attr_msensor.attr,
    &dev_attr_ps.attr,
    &dev_attr_als.attr,
    &dev_attr_gyro.attr,
    &dev_attr_wifi.attr,
    &dev_attr_bt.attr,
    &dev_attr_gps.attr,
    &dev_attr_fm.attr,
    //&dev_attr_main_otp.attr,
    //&dev_attr_main2_otp.attr,
   // &dev_attr_main3_otp.attr,
    //&dev_attr_sub_otp.attr,
    &dev_attr_sar_sensor_1.attr,
    &dev_attr_sar_sensor_2.attr,
    &dev_attr_bat_id.attr,
    //&dev_attr_charger_ic.attr,
    &dev_attr_nfc.attr,
    //&dev_attr_hw_id.attr,
    &dev_attr_fingerprint.attr,
    //fanjiafeng5  add for pdx213 fingerprint sn add begin
    &dev_attr_fingerprint_sn.attr,
    //fanjiafeng5  add end
    &dev_attr_main_cam_sn.attr,
    &dev_attr_main_cam_2_sn.attr,
    &dev_attr_main_cam_3_sn.attr,
    &dev_attr_sub_cam_sn.attr,
    //&dev_attr_sim1_card_slot_status.attr,
    //&dev_attr_sim2_card_slot_status.attr,
    //&dev_attr_smartpa.attr,
    &dev_attr_sdcard_detect.attr,
    &dev_attr_Fuse_flag.attr,
    &dev_attr_version_flag.attr,
    NULL
};

static struct attribute_group hdinfo_attribute_group = {
    .attrs = hdinfo_attributes
};

static int hw_info_parse_dt(struct device_node *np)
{
	int ret = 0;
	int gpio_sdcard = -1;
	int nicky_gpio = -1;
	if (np) {
		gpio_sdcard = of_get_named_gpio(np, "sdcard-gpio", 0);
		if (gpio_sdcard < 0) {
			printk("[HWINFO] sdcard-gpio not available (gpio_sdcard = %d)\n", gpio_sdcard);
			return gpio_sdcard;
		}
		sdcard_gpio_value = gpio_sdcard;
		printk("[HWINFO](gpio_sdcard = %d)\n", gpio_sdcard);

		nicky_gpio = of_get_named_gpio(np, "nicky-gpio", 0);
		if (nicky_gpio < 0) {
			printk("[HWINFO] nicky-gpio not available (nicky_gpio = %d)\n", nicky_gpio);
		} else {
			nicky_gpio_value = gpio_get_value(nicky_gpio);
		}
	}
	return ret;
}

static int HardwareInfo_driver_probe(struct platform_device *pdev)
{
    int ret = -1;
	struct file *cmd_file;
	mm_segment_t fs;
	int error;

    memset(&hwinfo_data, 0, sizeof(hwinfo_data));
    memset(&hw_info_main_otp, 0, sizeof(hw_info_main_otp));
    memset(&hw_info_main2_otp, 0, sizeof(hw_info_main2_otp));
    memset(&hw_info_main3_otp, 0, sizeof(hw_info_main3_otp));

    printk("[HWINFO] HardwareInfo_driver_probe!\n", ret);
    ret = hw_info_parse_dt(pdev->dev.of_node);
    if (ret < 0) {
        printk("[HWINFO] hw_info_parse_dt failed! (ret=%d)\n", ret);
        goto err;
    }

	cmd_file = filp_open(CMDLINE_PATH, O_RDONLY, 0);
	if (IS_ERR(cmd_file)) {
		error = PTR_ERR(cmd_file);
		return -ENOENT;
	} else {
		fs = get_fs();
		set_fs(KERNEL_DS);
		ret = cmd_file->f_op->read(cmd_file, cmdline, CMDLINE_LEN, &cmd_file->f_pos);
		if (ret < 0) {
			printk("%s: read error, ret=%d\n", __func__, (int)ret);
			filp_close(cmd_file, NULL);
			return -EIO;
		}
		set_fs(fs);
	}
	filp_close(cmd_file, NULL);

	cmdline[strlen(cmdline)-1] = '\0';
	//printk("read %d:%s\n",(int)strlen(cmdline),cmdline);

	hq_prj_name_setup();

    ret = sysfs_create_group(&(pdev->dev.kobj), &hdinfo_attribute_group);
    if (ret < 0) {
        printk("[HWINFO] sysfs_create_group failed! (ret=%d)\n", ret);
        goto err;
    }

    //INIT_DELAYED_WORK(&psSetSensorConf_work, do_psSetSensorConf_work);

    pcb_name = get_type_name();
    if(pcb_name && strcmp(pcb_name, "UNKNOWN") == 0){
        printk("[HWINFO] UNKNOWN pcb name \n");
    }

    return 0;
err:
    return ret;
}

static int HardwareInfo_driver_remove(struct platform_device *pdev)
{
    sysfs_remove_group(&(pdev->dev.kobj), &hdinfo_attribute_group);

    return 0;
}

static const struct of_device_id hwinfo_dt_match[] = {
    {.compatible = "huaqin,hardware_info"},
    {}
};

static struct platform_driver HardwareInfo_driver = {
    .probe = HardwareInfo_driver_probe,
    .remove = HardwareInfo_driver_remove,
    .driver = {
        .name = "HardwareInfo",
        .of_match_table = hwinfo_dt_match,
    },
};

static int __init HardwareInfo_mod_init(void)
{
    int ret = -1;

    ret = platform_driver_register(&HardwareInfo_driver);
    if (ret) {
        printk("[HWINFO] HardwareInfo_driver registed failed! (ret=%d)\n", ret);
    }

    return ret;
}

static void __exit HardwareInfo_mod_exit(void)
{
    platform_driver_unregister(&HardwareInfo_driver);
}


fs_initcall(HardwareInfo_mod_init);
module_exit(HardwareInfo_mod_exit);

MODULE_AUTHOR("Oly Peng ");
MODULE_DESCRIPTION("Hareware Info driver");
MODULE_LICENSE("GPL");
