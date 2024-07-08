/************************************************************************
*
* File Name: touch.c
*
* Author: likaoshan
*
* Created: 2021-02-19
*
* Abstract: for tp Compatibility
*
************************************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/of.h>


#include "touch.h"

struct touch_panel tp_interface;
EXPORT_SYMBOL(tp_interface);

void tp_charge_status_switch(int status)
{
    if (tp_interface.charger_mode_switch_status) {
        printk("dfy tp charge status switch status = %d \n",status);
        tp_interface.charger_mode_switch_status(status);
    } else {
        printk("dfy tp charge status switch not func\n");
    }
}
EXPORT_SYMBOL(tp_charge_status_switch);

void tp_headset_status_switch(int status)
{
    if (tp_interface.headset_switch_status) {
        printk("dfy tp headset status switch status =%d \n",status);
        tp_interface.headset_switch_status(status);
    } else {
        printk(" dfy tp headset status switch not func\n");
    }
}
EXPORT_SYMBOL(tp_headset_status_switch);


/* xiazhiping@BSP.TP.Function, 2023/11/27, add for Hulk K */
static char *get_project_name()
{
	struct device_node *cmdline_node;
	const char *cmd_line = 0;
	char *temp_name = 0;
	int ret = 0;
	cmdline_node = of_find_node_by_path("/chosen");
	ret = of_property_read_string(cmdline_node,"bootargs",&cmd_line);
	if(!ret){
		temp_name = strstr(cmd_line,"prj_name=");
		if(temp_name != NULL){
		temp_name += strlen("prj_name=");
		//pr_info("prj_name_hw_param=%s\n",temp_name);
	    }else{
		    pr_err("read prj_name_hw_param err");
	    }
	}
	//pr_info("temp_name=%s\n",temp_name);
	return temp_name;
}

int  get_ishulk_10w(void)
{
    char *prj_name = get_project_name();
    if (prj_name !=NULL && (strncmp(prj_name,"23711",5) ==0 ||strncmp(prj_name,"23712",5) ==0 \
             || strncmp(prj_name,"23713",5) ==0 || strncmp(prj_name,"23633",5) ==0  )) {
            printk("[TP_]  HULK 10W hulk-K  hulk-M: 23711 23712 23713 ,23633 \n");
            return 1;
    }
	return 0;
}
EXPORT_SYMBOL(get_ishulk_10w);
//end


// #define FW_NAME_LEN                    128
// /*add tp interface */
// static ssize_t tp_fw_upgrade_show(
//     struct device *dev, struct device_attribute *attr, char *buf)
// {
//     return -EPERM;
// }

// static ssize_t tp_fw_upgrade_store(
//     struct device *dev,
//     struct device_attribute *attr, const char *buf, size_t count)
// {
//    char fwname[FW_NAME_LEN];
//    int cnt = count;
//    memset(fwname, 0, sizeof(fwname));

//    snprintf(fwname, count, "%s", buf);

//    TP_INFO("fw_name = %s ",fwname);

//    if(tp_interface.tp_inferface_fw_upgrade)
//       tp_interface.tp_inferface_fw_upgrade(fwname,cnt);
//    else
//    	  TP_INFO("tp_inferface_fw_upgrade not func\n");

//    return -EPERM;

// }

// static ssize_t tp_edge_mode_show(
//     struct device *dev, struct device_attribute *attr, char *buf)
// {
//     return -EPERM;
// }

// static ssize_t tp_edge_mode_store(
//     struct device *dev,
//     struct device_attribute *attr, const char *buf, size_t count)
// {
//    char buf_edge_mode[4];
//    int cnt = count;
//    memset(buf_edge_mode, 0, sizeof(buf_edge_mode));

//    snprintf(buf_edge_mode, 4, "%s", buf);

//    TP_INFO("buf = %s ",buf);

//    TP_INFO("buf_edge_mode = %s ",buf_edge_mode);

//    if(tp_interface.tp_inferface_edge_mode)
//       tp_interface.tp_inferface_edge_mode(buf_edge_mode,cnt);
//    else
//    	  TP_INFO("tp_inferface_fw_upgrade not func\n");

//    return -EPERM;

// }

// static DEVICE_ATTR(tp_fw_upgrade, S_IRUGO | S_IWUSR, tp_fw_upgrade_show, tp_fw_upgrade_store);
// static DEVICE_ATTR(tp_edge_mode, S_IRUGO | S_IWUSR, tp_edge_mode_show,tp_edge_mode_store);

// static struct attribute *tp_attributes[] = {
//     &dev_attr_tp_fw_upgrade.attr,
// 	&dev_attr_tp_edge_mode.attr,
//     NULL
// };

// static struct attribute_group tp_attribute_group = {
//     .attrs = tp_attributes
// };

// int tp_create_sysfs( struct device *dev)
// {
//     int ret = 0;

//     ret = sysfs_create_group(&dev->kobj, &tp_attribute_group);
//     if (ret) {
//         TP_ERROR("[EX]: sysfs_create_group() failed!!");
//         sysfs_remove_group(&dev->kobj, &tp_attribute_group);
//         return -ENOMEM;
//     } else {
//         TP_INFO("[EX]: sysfs_create_group() succeeded!!");
//     }

//     return ret;
// }

// int tp_remove_sysfs( struct device *dev)
// {
//     sysfs_remove_group(&dev->kobj, &tp_attribute_group);
//     return 0;
// }
