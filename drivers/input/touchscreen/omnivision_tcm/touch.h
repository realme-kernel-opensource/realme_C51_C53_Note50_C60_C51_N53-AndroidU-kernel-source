/************************************************************************
*
* File Name: touch.h
*
* Author: likaoshan
*
* Created: 2021-02-19
*
* Abstract: for tp Compatibility
*
************************************************************************/

#ifndef __LINUX_TOUCH_H__
#define __LINUX_TOUCH_H__

enum tp_ic_type
{
   TD4160 = 1,
   HX83108 = 2,
   ICNL9916C =3,
   FT8057P = 4,
};

struct touch_panel {
	void (*headset_switch_status)(int status);
	void (*charger_mode_switch_status)(int status);
	void (*tp_inferface_fw_upgrade)(char *fw_name,int count);
	void (*tp_inferface_edge_mode)(char *buf,int count);
	enum tp_ic_type tp_type;
};

#define TP_INFO(fmt, args...) do { \
    printk(KERN_INFO "[TP_interface/I]%s:"fmt"\n", __func__, ##args); \
} while (0)

#define TP_ERROR(fmt, args...) do { \
    printk(KERN_ERR "[TP_interface/E]%s:"fmt"\n", __func__, ##args); \
} while (0)

#endif
