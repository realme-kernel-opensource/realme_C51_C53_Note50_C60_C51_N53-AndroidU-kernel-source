/*
 * create in 2021/1/7.
 * create emmc node in  /proc/bootdevice
 */
#ifndef _SPRD_PROC_MMC_HEALTH_H_
#define _SPRD_PROC_MMC_HEALTH_H_
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/mmc/mmc.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/mmc/card.h>
#define MAX_NAME_LEN 32

struct __mmchealthdata {
	u8 buf[512];
};

void set_mmchealth_data(u8 *data);
int sprd_create_mmc_health_init(int flag);
#endif
