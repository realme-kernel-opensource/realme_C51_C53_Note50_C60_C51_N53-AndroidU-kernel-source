#ifndef __WCN_CHR_H
#define	__WCN_CHR_H

#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <uapi/linux/in.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <uapi/asm-generic/errno.h>
#include <linux/delay.h>
#include <linux/types.h>

#include "wcn_dbg.h"
#include "sysfs.h"

#define BUF_SIZE	512

#define MIN(a, b)		(a > b ? b : a)

#define WCN_CHR_SOCKET_CMD_ENABLE		"wcn_chr_enable"
#define WCN_CHR_SOCKET_CMD_DISABLE	"wcn_chr_disable"

#define WCN_CHR_SET_EVENT_HEAD		"wcn_chr_set_event"

typedef struct wcn_bsp_chr_cp2_assert_struct {
	u32 cp_log_level;
	u32 ap_log_level;
	char cp_version[128];
	char error_dscp[128];
} wcn_bsp_chr_cp2_assert_t;

struct wcn_chr_event_list {
	char name[32];
	u32 event_id;
	bool enable;
};

extern struct wcn_sysfs_info sysfs_info;

#endif	//__WCN_CHR_H
