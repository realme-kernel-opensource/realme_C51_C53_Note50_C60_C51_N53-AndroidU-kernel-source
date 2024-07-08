/***************************************************************
** Copyright (C),  2018,  OPLUS Mobile Comm Corp.,  Ltd
** VENDOR_EDIT
** File : oplus_display_private_api.h
** Description : oppo display private api implement
** Version : 1.0
** Date : 2018/03/20
** Author : Jie.Hu@PSW.MM.Display.Stability
**
** ------------------------------- Revision History: -----------
**  <author>        <data>        <version >        <desc>
**   Hu.Jie          2018/03/20        1.0           Build this moudle
**   Guo.Ling        2018/10/11        1.1           Modify for SDM660
**   Guo.Ling        2018/11/27        1.2           Modify for mt6779
**   Lin.Hao         2019/10/31        1.3           Modify for MT6779_Q
**   xiazhiping      2023/2/9          1.4           Modify for ums9230
******************************************************************/
#ifndef _oplus_DISPLAY_PRIVATE_API_H_
#define _oplus_DISPLAY_PRIVATE_API_H_
#include <drm/drm_mipi_dsi.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/of.h>
#include <linux/err.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/leds.h>

int oplus_display_private_api_init(struct device *dev);

#endif /* _oplus_DISPLAY_PRIVATE_API_H_ */

