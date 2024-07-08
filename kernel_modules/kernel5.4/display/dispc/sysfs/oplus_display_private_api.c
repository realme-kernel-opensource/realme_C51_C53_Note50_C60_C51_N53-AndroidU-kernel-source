/***************************************************************
** Copyright (C),  2018,  oplus Mobile Comm Corp.,  Ltd
** VENDOR_EDIT
** File : oplus_display_private_api.h
** Description : oplus display private api implement
** Version : 1.0
** Date : 2018/03/20
** Author : Jie.Hu@PSW.MM.Display.Stability
**
** ------------------------------- Revision History: -----------
**  <author>        <data>        <version >        <desc>
**   Hu.Jie          2018/03/20        1.0           Build this moudle
******************************************************************/
#include "oplus_display_private_api.h"

#include <linux/fb.h>
#include <linux/time.h>
#include <linux/timekeeping.h>

#include "disp_lib.h"
#include "sprd_dsi.h"
#include "sprd_dsi_panel.h"
#include "sysfs_display.h"


/*
 * we will create a sysfs which called /sys/kernel/oplus_display,
 * In that directory, oplus display private api can be called
 */

unsigned long cabc_mode = 0;
/* wangcheng@ODM.Multimedia.LCD  2021/04/12 solve cabc dump  start*/
extern unsigned int flag_bl;
/* wangcheng@ODM.Multimedia.LCD  2021/04/12 solve cabc dump  end*/

unsigned long tp_gesture_private = 0;

#define host_to_dsi(host) \
	container_of(host, struct sprd_dsi, host)

/*add /sys/class/display/panel0/cabc_private*/
extern int private_panel_cabc(unsigned int level);

static ssize_t cabc_private_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	//printk("[drm] %s cabc_mode=%d \n", __func__, cabc_mode);
	return snprintf(buf, PAGE_SIZE, "%u\n", cabc_mode);
}

static ssize_t cabc_private_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	int ret = 0;
	struct sprd_panel *panel = dev_get_drvdata(dev);
	struct mipi_dsi_host *host = panel->slave->host;
	struct sprd_dsi *dsi = host_to_dsi(host);

    ret = kstrtoul(buf, 10, &cabc_mode);
	mutex_lock(&panel->lock);
	if ((!dsi->ctx.enabled) || (!panel->enabled)) {
		mutex_unlock(&panel->lock);
		DRM_ERROR("dsi is suspended, skip cabc work\n");
		return -EINVAL;
	}
	if (flag_bl == 0) {
		mutex_unlock(&panel->lock);
		printk("[drm] %s flag_bl=0 ,skip cabc work\n", __func__);
		return -EINVAL;
	}
	ret = private_panel_cabc((unsigned int)cabc_mode);
	if (ret) {
		mutex_unlock(&panel->lock);
		pr_err("[drm] invalid input for setting cabc mode error!\n");
		return -EINVAL;
	}
	mutex_unlock(&panel->lock);
	printk("[drm] %s cabc_mode=%u \n", __func__, cabc_mode);
	return count;
}
static DEVICE_ATTR_RW(cabc_private);



/*add /sys/class/display/panel0/tp_gesture_private*/
static ssize_t tp_gesture_private_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	int ret ;
	ret = sprintf(buf, "%ld\n", tp_gesture_private);
    printk("[drm] %s tp_gesture_private=%ld\n", __func__, tp_gesture_private);
	return ret;
}

static ssize_t tp_gesture_private_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
    int ret = 0;
    ret = kstrtoul(buf, 10, &tp_gesture_private);
	printk("[drm] %s tp_gesture_private_mode=%ld  ret=%d\n", __func__, tp_gesture_private , ret);
	if (ret) {
		pr_err("[drm] tp_gesture_private_store error! \n");
		return -EINVAL;
	}
	return count;
}

static DEVICE_ATTR_RW(tp_gesture_private);


/*
 * Create a group of attributes so that we can create and destroy them all
 * at once.
 */
static struct attribute *oplus_display_attrs[] = {
	&dev_attr_cabc_private.attr,
	&dev_attr_tp_gesture_private.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group oplus_display_attr_group = {
	.attrs = oplus_display_attrs,
};

 int oplus_display_private_api_init(struct device *dev)
{
	int retval;

	/* Create the files associated with this kobject */
	retval = sysfs_create_group(&(dev->kobj), &oplus_display_attr_group);
	if (retval)
		pr_err("create  oplus_display_private_api_init node failed, retval=%d.\n", retval);

	return retval;
}
EXPORT_SYMBOL(oplus_display_private_api_init);




//module_init(oplus_display_private_api_init);
//module_exit(oplus_display_private_api_exit);
//MODULE_LICENSE("GPL v2");
//MODULE_AUTHOR("Hujie <hujie@oplus.com>");
