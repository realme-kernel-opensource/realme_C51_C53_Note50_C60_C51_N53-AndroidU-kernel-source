/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 MediaTek Inc.
 * Author Wy Chuang<wy.chuang@mediatek.com>
 */

#ifndef __UNISOC_BATTERY_INTF_H__
#define __UNISOC_BATTERY_INTF_H__

#include <linux/alarmtimer.h>
#include <linux/atomic.h>
#include <linux/extcon.h>
#include <linux/hrtimer.h>
#include <linux/nvmem-consumer.h>
#include <linux/power_supply.h>
#include <linux/sysfs.h>
#include <linux/wait.h>
#include <linux/ktime.h>
#include "sc27xx_fuel_gauge.h"


#define NETLINK_FGD 26
#define UNIT_TRANS_10	10
#define UNIT_TRANS_100	100
#define UNIT_TRANS_1000	1000
#define UNIT_TRANS_60	60
#define MAX_TABLE		10
#define MAX_CHARGE_RDC 5

#define BMLOG_ERROR_LEVEL   3
#define BMLOG_WARNING_LEVEL 4
#define BMLOG_NOTICE_LEVEL  5
#define BMLOG_INFO_LEVEL    6
#define BMLOG_DEBUG_LEVEL   7
#define BMLOG_TRACE_LEVEL   8

#define BMLOG_DEFAULT_LEVEL BMLOG_DEBUG_LEVEL

#define bm_err(fmt, args...)   \
do {\
	if (bat_get_debug_level() >= BMLOG_ERROR_LEVEL) {\
		pr_notice(fmt, ##args); \
	} \
} while (0)

#define bm_warn(fmt, args...)   \
do {\
	if (bat_get_debug_level() >= BMLOG_ERROR_LEVEL) {\
		pr_notice(fmt, ##args); \
	}								   \
} while (0)

#define bm_notice(fmt, args...)   \
do {\
	if (bat_get_debug_level() >= BMLOG_ERROR_LEVEL) {\
		pr_notice(fmt, ##args); \
	}								   \
} while (0)

#define bm_info(fmt, args...)   \
do {\
	if (bat_get_debug_level() >= BMLOG_ERROR_LEVEL) {\
		pr_notice(fmt, ##args); \
	}								   \
} while (0)

#define bm_debug(fmt, args...)   \
do {\
	if (bat_get_debug_level() >= BMLOG_DEBUG_LEVEL) {\
		pr_notice(fmt, ##args); \
	}								   \
} while (0)

#define bm_trace(fmt, args...)\
do {\
	if (bat_get_debug_level() >= BMLOG_ERROR_LEVEL) {\
		pr_notice(fmt, ##args);\
	}						\
} while (0)

#define BAT_SYSFS_FIELD_RW(_name, _prop)	\
{									 \
	.attr	= __ATTR(_name, 0644, bat_sysfs_show, bat_sysfs_store),\
	.prop	= _prop,	\
	.set	= _name##_set,						\
	.get	= _name##_get,						\
}

#define BAT_SYSFS_FIELD_RO(_name, _prop)	\
{			\
	.attr   = __ATTR(_name, 0444, bat_sysfs_show, bat_sysfs_store),\
	.prop   = _prop,				  \
	.get	= _name##_get,						\
}

#define BAT_SYSFS_FIELD_WO(_name, _prop)	\
{								   \
	.attr	= __ATTR(_name, 0200, bat_sysfs_show, bat_sysfs_store),\
	.prop	= _prop,	\
	.set	= _name##_set,						\
}

/* ============================================================ */
/* power misc related */
/* ============================================================ */
#define BAT_VOLTAGE_LOW_BOUND 3400
#define BAT_VOLTAGE_HIGH_BOUND 3450
#define LOW_TMP_BAT_VOLTAGE_LOW_BOUND 3350
#define SHUTDOWN_TIME 40
#define AVGVBAT_ARRAY_SIZE 30
#define INIT_VOLTAGE 3450
#define BATTERY_SHUTDOWN_TEMPERATURE 90

extern int battery_init(struct platform_device *pdev);
extern int fgauge_get_profile_id(void);
#endif
