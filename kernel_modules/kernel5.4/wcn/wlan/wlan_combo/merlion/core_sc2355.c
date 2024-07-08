/*
 * Copyright (C) 2016 Spreadtrum Communications Inc.
 *
 * Authors	:
 * star.liu <star.liu@spreadtrum.com>
 * yifei.li <yifei.li@spreadtrum.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/platform_device.h>
#include <linux/utsname.h>
#include <linux/debugfs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <misc/marlin_platform.h>
#else
#include <linux/marlin_platform.h>
#endif
#include "sprdwl.h"
#include "if_sc2355.h"
#include "core_sc2355.h"
#include "tx_msg_sc2355.h"
#include "rx_msg_sc2355.h"
#include "msg.h"
#include "txrx.h"
#include "debug.h"
#include "tcp_ack.h"
#include "edma_test.h"
#include "cmdevt.h"
#include <linux/of_address.h>
#include <linux/io.h>
#include <linux/regmap.h>
#include <linux/mfd/syscon.h>
#include <linux/interrupt.h>
#include "work.h"
#include <linux/irq.h>
#include "txrx_buf_mm.h"
#ifdef SIPC_SUPPORT
#include "sipc_txrx_mm.h"
#include "sipc_debug.h"
#endif

/* chr_sock*/
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/linux/in.h>

#ifdef CONFIG_SPRD_WCN_DEBUG
int sprdwl_debug_level = L_INFO;
#else
int sprdwl_debug_level = L_WARN;
#endif
struct device *sprdwl_dev;

extern struct sprdwl_intf *g_intf;
extern unsigned int g_max_fw_tx_dscr;
extern struct throughput_sta g_tp_config;

bool sprdwl_chip_is_on(struct sprdwl_intf *intf)
{
	return (atomic_read(&intf->power_cnt) == 0 ? false : true);
}

int sprdwl_chip_power_on(struct sprdwl_intf *intf)
{
	atomic_add(1, &intf->power_cnt);

	if (atomic_read(&intf->power_cnt) != 1)
		return 0;

	if (start_marlin(MARLIN_WIFI)) {
		atomic_sub(1, &intf->power_cnt);
		return -ENODEV;
	}

	if (unlikely(intf->exit) || unlikely(intf->cp_asserted)) {
		wl_err("%s assert or exit!", __func__);
		goto out;
	}

	if (sprdwl_intf_init(intf)) {
		atomic_sub(1, &intf->power_cnt);
		return -ENODEV;
	}
out:
	/* need reset intf->exit falg, if wcn reset happened */
	if (unlikely(intf->exit) || unlikely(intf->cp_asserted)) {
		wl_info("assert happened!, need reset paras!\n");
		sprdwl_sc2355_reset(intf);
	}

	if (sprdwl_sync_version(intf->priv)) {
		atomic_sub(1, &intf->power_cnt);
		return -EIO;
	}
	sprdwl_download_ini(intf->priv);

	return 0;
}

void sprdwl_chip_power_off(struct sprdwl_intf *intf)
{
	atomic_sub(1, &intf->power_cnt);

	if (atomic_read(&intf->power_cnt) != 0)
		return;

	sprdwl_clean_work(intf->priv);

	if (unlikely(intf->exit) || unlikely(intf->cp_asserted)) {
		wl_err("%s assert or exit!", __func__);
		goto out;
	}

	sprdwl_intf_deinit();
out:
	if (stop_marlin(MARLIN_WIFI))
		wl_err("stop marlin failed!!!\n");
}

int sprdwl_chip_set_power(struct sprdwl_intf *intf, bool val)
{
	int ret = 0;

	if (val) {
		ret = sprdwl_chip_power_on(intf);
		if (ret) {
			if (ret == -ENODEV)
				wl_err("failed to power on wcn!\n");
			else if (ret == -EIO)
				wl_err("SYNC cmd error!\n");
			intf->priv->chr->open_err_flag = OPEN_ERR_POWER_ON;
			return ret;
		}
		if (atomic_read(&intf->power_cnt) == 1)
			sprdwl_get_fw_info(intf->priv);
	} else
		sprdwl_chip_power_off(intf);
	return ret;
}

void adjust_debug_level(char *buf, unsigned char offset)
{
	int level = buf[offset] - '0';

	wl_err("input debug level: %d!\n", level);
	switch (level) {
	case L_ERR:
		sprdwl_debug_level = L_ERR;
		break;
	case L_WARN:
		sprdwl_debug_level = L_WARN;
		break;
	case L_INFO:
		sprdwl_debug_level = L_INFO;
		break;
	case L_DBG:
		sprdwl_debug_level = L_DBG;
		break;
	default:
		sprdwl_debug_level = L_ERR;
		wl_err("input wrong debug level\n");
	}

	wl_err("set sprdwl_debug_level: %d\n", sprdwl_debug_level);
}

extern unsigned int vo_ratio;
extern unsigned int vi_ratio;
extern unsigned int be_ratio;
extern unsigned int wmmac_ratio;

void adjust_qos_ratio(char *buf, unsigned char offset)
{
	unsigned int qos_ratio =
		(buf[offset+3] - '0')*10 + (buf[offset+4] - '0');

	if (buf[offset] == 'v') {
		if (buf[offset+1] == 'o')
			vo_ratio = qos_ratio;
		else if (buf[offset+1] == 'i')
			vi_ratio = qos_ratio;
	} else if (buf[offset] == 'b' && buf[offset+1] == 'e') {
		be_ratio = qos_ratio;
	} else if (buf[offset] == 'a' && buf[offset+1] == 'm') {
		wmmac_ratio = qos_ratio;
	}

	wl_err("vo ratio:%u, vi ratio:%u, be ratio:%u, wmmac_ratio:%u\n",
	       vo_ratio, vi_ratio, be_ratio, wmmac_ratio);
}

extern unsigned int drop_time;
void adjust_wmm_vo_drop_time(char *buf, unsigned char offset)
{
	unsigned int value = 0;
	unsigned int i = 0;
	unsigned int len = strlen(buf) - strlen("drop_time=");

	for (i = 0; i < len; (value *= 10), i++) {
		if ((buf[offset + i] >= '0') &&
		   (buf[offset + i] <= '9')) {
			value += (buf[offset + i] - '0');
		} else {
			value /= 10;
			break;
		}
	}
	drop_time = value;
	wl_err("%s, change wmm_vo_drop_time to %d\n", __func__, value);
}

unsigned int new_threshold;
void adjust_tdls_threshold(char *buf, unsigned char offset)
{
	unsigned int value = 0;
	unsigned int i = 0;
	unsigned int len = strlen(buf) - strlen("tdls_threshold=");

	for (i = 0; i < len; (value *= 10), i++) {
		if ((buf[offset + i] >= '0') &&
		   (buf[offset + i] <= '9')) {
			value += (buf[offset + i] - '0');
		} else {
			value /= 10;
			break;
		}
	}
	new_threshold = value;
	wl_err("%s, change tdls_threshold to %d\n", __func__, value);
}

void adjust_tsq_shift(char *buf, unsigned char offset)
{
	unsigned int value = 0;
	unsigned int i = 0;
	unsigned int len = strlen(buf) - strlen("tsq_shift=");

	for (i = 0; i < len; (value *= 10), i++) {
		if ((buf[offset + i] >= '0') &&
		   (buf[offset + i] <= '9')) {
			value += (buf[offset + i] - '0');
		} else {
			value /= 10;
			break;
		}
	}
	g_intf->tsq_shift = value;
	wl_err("%s, change tsq_shift to %d\n", __func__, value);
}

void adjust_tcpack_th_in_mb(char *buf, unsigned char offset)
{
#define MAX_LEN 4
	unsigned int cnt = 0;
	unsigned int i = 0;

	for (i = 0; i < MAX_LEN; (cnt *= 10), i++) {
		if ((buf[offset + i] >= '0') &&
		   (buf[offset + i] <= '9')) {
			cnt += (buf[offset + i] - '0');
		} else {
			cnt /= 10;
			break;
		}
	}

	if (cnt > 9999)
		cnt = DROPACK_TP_TH_IN_M;
	g_intf->tcpack_delay_th_in_mb = cnt;
	wl_info("tcpack_delay_th_in_mb: %d\n", g_intf->tcpack_delay_th_in_mb);
#undef MAX_LEN
}

void adjust_tcpack_time_in_ms(char *buf, unsigned char offset)
{
#define MAX_LEN 4
	unsigned int cnt = 0;
	unsigned int i = 0;

	for (i = 0; i < MAX_LEN; (cnt *= 10), i++) {
		if ((buf[offset + i] >= '0') &&
		   (buf[offset + i] <= '9')) {
			cnt += (buf[offset + i] - '0');
		} else {
			cnt /= 10;
			break;
		}
	}

	if (cnt > 9999)
		cnt = RX_TP_COUNT_IN_MS;
	g_intf->tcpack_time_in_ms = cnt;
	wl_info("tcpack_time_in_ms: %d\n", g_intf->tcpack_time_in_ms);
#undef MAX_LEN
}

void adjust_sipc_max_fw_tx_dscr(char *buf, unsigned char offset)
{
	unsigned int value = 0;
	unsigned int i = 0;
	unsigned int len = strlen(buf) - strlen("max_fw_tx_dscr=");

	for (i = 0; i < len; (value *= 10), i++) {
		if ((buf[offset + i] >= '0') &&
			(buf[offset + i] <= '9')) {
			value += (buf[offset + i] - '0');
		} else {
			value /= 10;
			break;
			}
	}

	g_max_fw_tx_dscr = value;
	wl_err("%s, change max_fw_tx_dscr to %d\n", __func__, value);
}
#ifdef SIPC_SUPPORT
void sipc_txrx_debug(char *buf, unsigned char offset)
{
    int item = buf[offset] - '0';

	wl_err("input sipc debug : %d!\n", item);
	switch (item) {
	case SPRDWL_SIPC_DBG_TX:
		sipc_tx_list_dump();
		break;
	case SPRDWL_SIPC_DBG_RX:
		sipc_rx_list_dump();
		break;
	case SPRDWL_SIPC_DBG_MEM:
		sipc_tx_mem_dump();
		sipc_rx_mem_dump();
		break;
	case SPRDWL_SIPC_DBG_CMD_TX:
		sipc_tx_cmd_test();
		break;
	case SPRDWL_SIPC_DBG_DATA_TX:
		sipc_tx_data_test();
		break;
	case SPRDWL_SIPC_DBG_ALL:
/* TODO */
		break;

	default:
		wl_err("%s, unknown sipc debug type.", __func__);
	}
}
#endif

struct debuginfo_s {
	void (*func)(char *, unsigned char offset);
	char str[30];
} debuginfo[] = {
	{adjust_debug_level, "debug_level="},
	{adjust_qos_ratio, "qos_ratio:"},
	{adjust_wmm_vo_drop_time, "drop_time="},
	{adjust_ts_cnt_debug, "debug_info="},
	{enable_tcp_ack_delay, "tcpack_delay_en="},
	{adjust_tcp_ack_delay, "tcpack_delay_cnt="},
	{adjust_tdls_threshold, "tdls_threshold="},
	{adjust_tcp_ack_delay_win, "tcpack_delay_win="},
	{adjust_tsq_shift, "tsq_shift="},
	{adjust_tcpack_th_in_mb, "tcpack_delay_th_in_mb="},
	{adjust_tcpack_time_in_ms, "tcpack_time_in_ms="},
	{adjust_sipc_max_fw_tx_dscr, "max_fw_tx_dscr="},
#ifdef SIPC_SUPPORT
    {sipc_txrx_debug, "sipc_txrx_dbg="},
#endif
};

/* TODO: Could we use netdev_alloc_frag instead of kmalloc?
 *       So we did not need to distinguish buffer type
 *       Maybe it could speed up alloc process, too
 */
void sprdwl_free_data(void *data, int buffer_type)
{
	if (SPRDWL_DEFRAG_MEM == buffer_type) { /* Fragment page buffer */
		put_page(virt_to_head_page(data));
	} else if (SPRDWL_RSERVE_MEM == buffer_type) {
		if (data)
			kfree(data);
	} else { /* Normal buffer */
		kfree(data);
	}
}

void sprdwl_tdls_flow_flush(struct sprdwl_vif *vif, const u8 *peer, u8 oper)
{
	struct sprdwl_intf *intf = vif->priv->hw_priv;
	u8 i;

	if (oper == NL80211_TDLS_SETUP || oper == NL80211_TDLS_ENABLE_LINK) {
		for (i = 0; i < MAX_TDLS_PEER; i++) {
			if (ether_addr_equal(intf->tdls_flow_count[i].da,
					     peer)) {
				memset(&intf->tdls_flow_count[i],
				       0,
				       sizeof(struct tdls_flow_count_para));
				break;
			}
		}
	}
}

void sprdwl_event_tdls_flow_count(struct sprdwl_vif *vif, u8 *data, u16 len)
{
	struct sprdwl_intf *intf = vif->priv->hw_priv;
	u8 i;
	u8 found = 0;
	struct tdls_update_peer_infor *peer_info =
		(struct tdls_update_peer_infor *)data;
	ktime_t kt;

	if (len < sizeof(struct tdls_update_peer_infor)) {
		wl_err("%s, event data len not in range\n", __func__);
			return;
	}
	for (i = 0; i < MAX_TDLS_PEER; i++) {
		if (ether_addr_equal(intf->tdls_flow_count[i].da,
				     peer_info->da)) {
			found = 1;
			break;
		}
	}
	/*0 to delete entry*/
	if (peer_info->valid == 0) {
		if (found == 0) {
			wl_err("%s, invalid da, fail to del\n", __func__);
			return;
		}
		memset(&intf->tdls_flow_count[i],
		       0,
		       sizeof(struct tdls_flow_count_para));

		for (i = 0; i < MAX_TDLS_PEER; i++) {
			if (intf->tdls_flow_count[i].valid == 1)
				found++;
		}
		if (found == 1)
			intf->tdls_flow_count_enable = 0;
	} else if (peer_info->valid == 1) {
		if (found == 0) {
			for (i = 0; i < MAX_TDLS_PEER; i++) {
				if (intf->tdls_flow_count[i].valid == 0) {
					found = 1;
					break;
				}
			}
		}
		if (found == 0) {
			wl_err("%s, no free TDLS entry\n", __func__);
			i = 0;
		}

		intf->tdls_flow_count_enable = 1;
		intf->tdls_flow_count[i].valid = 1;
		ether_addr_copy(intf->tdls_flow_count[i].da, peer_info->da);
		intf->tdls_flow_count[i].threshold = peer_info->txrx_len;
		intf->tdls_flow_count[i].data_len_counted = 0;

		wl_info("%s,%d, tdls_id=%d,threshold=%d, timer=%d, da=(%pM)\n",
			__func__, __LINE__, i,
			intf->tdls_flow_count[i].threshold,
			peer_info->timer, peer_info->da);

		kt = ktime_get();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		intf->tdls_flow_count[i].start_mstime =
			(u32)(div_u64(kt, NSEC_PER_MSEC));
#else
		intf->tdls_flow_count[i].start_mstime =
			(u32)(div_u64(kt.tv64, NSEC_PER_MSEC));
#endif
		intf->tdls_flow_count[i].timer =
			peer_info->timer;
		wl_info("%s,%d, tdls_id=%d,start_time:%u\n",
			__func__, __LINE__, i,
			intf->tdls_flow_count[i].start_mstime);
	}
}

void count_tdls_flow(struct sprdwl_vif *vif, u8 *data, u16 len)
{
	u8 i, found = 0;
	u32 msec;
	u8 elapsed_time;
	u8 unit_time;
	ktime_t kt;
	struct sprdwl_intf *intf = (struct sprdwl_intf *)vif->priv->hw_priv;
	int ret = 0;

	for (i = 0; i < MAX_TDLS_PEER; i++) {
		if ((intf->tdls_flow_count[i].valid == 1) &&
		    (ether_addr_equal(data, intf->tdls_flow_count[i].da)))
			goto count_it;
	}
	return;

count_it:
	if (new_threshold != 0)
		intf->tdls_flow_count[i].threshold = new_threshold;
	kt = ktime_get();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	msec = (u32)(div_u64(kt, NSEC_PER_MSEC));
#else
	msec = (u32)(div_u64(kt.tv64, NSEC_PER_MSEC));
#endif
	elapsed_time =
		(msec - intf->tdls_flow_count[i].start_mstime) / MSEC_PER_SEC;
	unit_time = elapsed_time / intf->tdls_flow_count[i].timer;
	wl_info("%s,%d, tdls_id=%d, len_counted=%d, len=%d, threshold=%dK\n",
		__func__, __LINE__, i,
		intf->tdls_flow_count[i].data_len_counted, len,
		intf->tdls_flow_count[i].threshold);
	wl_info("currenttime=%u, elapsetime=%d, unit_time=%d\n",
		msec, elapsed_time, unit_time);

	if ((intf->tdls_flow_count[i].data_len_counted == 0 &&
	     len > (intf->tdls_flow_count[i].threshold * 1024)) ||
	    (intf->tdls_flow_count[i].data_len_counted > 0 &&
	    ((intf->tdls_flow_count[i].data_len_counted + len) >
	     intf->tdls_flow_count[i].threshold * 1024 *
	     ((unit_time == 0) ? 1 : unit_time)))) {
		ret = sprdwl_send_tdls_cmd(vif, vif->ctx_id,
					   (u8 *)intf->tdls_flow_count[i].da,
					   SPRDWL_TDLS_CMD_CONNECT);
		memset(&intf->tdls_flow_count[i], 0,
			       sizeof(struct tdls_flow_count_para));
	} else {
		if (intf->tdls_flow_count[i].data_len_counted == 0) {
			intf->tdls_flow_count[i].start_mstime = msec;
			intf->tdls_flow_count[i].data_len_counted += len;
		}
		if ((intf->tdls_flow_count[i].data_len_counted > 0) &&
		    unit_time > 1) {
			intf->tdls_flow_count[i].start_mstime = msec;
			intf->tdls_flow_count[i].data_len_counted = len;
		}
		if ((intf->tdls_flow_count[i].data_len_counted > 0) &&
		    unit_time <= 1) {
			intf->tdls_flow_count[i].data_len_counted += len;
		}
	}
	for (i = 0; i < MAX_TDLS_PEER; i++) {
		if (intf->tdls_flow_count[i].valid == 1)
			found++;
	}
	if (found == 0)
		intf->tdls_flow_count_enable = 0;
}

#define SPRDWL_SDIO_DEBUG_BUFLEN 128
static ssize_t sprdwl_intf_read_info(struct file *file,
				     char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	size_t ret = 0;
	unsigned int buflen, len;
	unsigned char *buf;
	struct sprdwl_intf *sdev;
	struct sprdwl_tx_msg *tx_msg;

	sdev = (struct sprdwl_intf *)file->private_data;
	tx_msg = (struct sprdwl_tx_msg *)sdev->sprdwl_tx;
	buflen = SPRDWL_SDIO_DEBUG_BUFLEN;
	buf = kzalloc(buflen, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len = 0;
	len += scnprintf(buf, buflen,
			 "net: stop %lu, start %lu\n drop cnt:\n"
			 "cmd %lu, sta %lu, p2p %lu,\n"
			 "ring_ap:%lu ring_cp:%lu red_flow:%u,\n"
			 "green_flow:%u blue_flow:%u white_flow:%u\n",
			 tx_msg->net_stop_cnt, tx_msg->net_start_cnt,
			 tx_msg->drop_cmd_cnt, tx_msg->drop_data1_cnt,
			 tx_msg->drop_data2_cnt,
			 tx_msg->ring_ap, tx_msg->ring_cp,
			 atomic_read(&tx_msg->flow_ctrl[0].flow),
			 atomic_read(&tx_msg->flow_ctrl[1].flow),
			 atomic_read(&tx_msg->flow_ctrl[2].flow),
			 atomic_read(&tx_msg->flow_ctrl[3].flow));
	if (len > buflen)
		len = buflen;

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return ret;
}

static ssize_t sprdwl_intf_write(struct file *file,
				 const char __user *__user_buf,
				 size_t count, loff_t *ppos)
{
	char buf[30];
	struct sprdwl_intf *sdev;
	int type = 0;
	int debug_size = sizeof(debuginfo)/sizeof(struct debuginfo_s);

	sdev = (struct sprdwl_intf *)file->private_data;

	if (!count || count >= sizeof(buf)) {
		wl_err("write len too long:%zu >= %zu\n", count, sizeof(buf));
		return -EINVAL;
	}
	if (copy_from_user(buf, __user_buf, count))
		return -EFAULT;
	buf[count] = '\0';
	wl_err("write info:%s\n", buf);
	for (type = 0; type < debug_size; type++)
		if (!strncmp(debuginfo[type].str, buf,
			     strlen(debuginfo[type].str))) {
			wl_err("write info:type %d\n", type);
			debuginfo[type].func(buf, strlen(debuginfo[type].str));
			break;
		}

	return count;
}

static const struct file_operations sprdwl_intf_debug_fops = {
	.read = sprdwl_intf_read_info,
	.write = sprdwl_intf_write,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek
};

static int txrx_debug_show(struct seq_file *s, void *p)
{
	unsigned int i = 0;

	for (i = 0; i < MAX_DEBUG_CNT_INDEX; i++)
		debug_cnt_show(s, i);

	for (i = 0; i < MAX_DEBUG_TS_INDEX; i++)
		debug_ts_show(s, i);

	for (i = 0; i < MAX_DEBUG_RECORD_INDEX; i++)
		debug_record_show(s, i);

	return 0;
}

static int txrx_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, txrx_debug_show, inode->i_private);
}

static ssize_t txrx_debug_write(struct file *file,
				const char __user *__user_buf,
				size_t count, loff_t *ppos)
{
	char buf[20] = "debug_info=";
	unsigned char len = strlen(buf);

	if (!count || (count + len) >= sizeof(buf)) {
		wl_err("write len too long:%zu >= %zu\n", count, sizeof(buf));
		return -EINVAL;
	}

	if (copy_from_user((buf + len), __user_buf, count))
		return -EFAULT;

	buf[count + len] = '\0';
	wl_err("write info:%s\n", buf);

	adjust_ts_cnt_debug(buf, len);

	return count;
}

static const struct file_operations txrx_debug_fops = {
	.owner = THIS_MODULE,
	.open = txrx_debug_open,
	.read = seq_read,
	.write = txrx_debug_write,
	.llseek = seq_lseek,
	.release = single_release,
};

void sprdwl_debugfs(void *spdev, struct dentry *dir)
{
	struct sprdwl_intf *intf;

	intf = (struct sprdwl_intf *)spdev;
	debugfs_create_file("sprdwlinfo", S_IRUSR,
			    dir, intf, &sprdwl_intf_debug_fops);
}

static struct dentry *sprdwl_debug_root;

void sprdwl_debugfs_init(struct sprdwl_intf *intf)
{
	/* create debugfs */
	sprdwl_debug_root = debugfs_create_dir("sprdwl_debug", NULL);
	if (sprdwl_debug_root == NULL ||  IS_ERR(sprdwl_debug_root)) {
		wl_err("%s, create dir fail!\n", __func__);
		sprdwl_debug_root = NULL;
		return;
	}

	if (!debugfs_create_file("log_level", 0444,
		sprdwl_debug_root, intf, &sprdwl_intf_debug_fops))
		wl_err("%s, create file fail!\n", __func__);

	if (!debugfs_create_file("txrx_dbg", S_IRUGO,
		sprdwl_debug_root, intf, &txrx_debug_fops))
		wl_err("%s, %d, create_file fail!\n", __func__, __LINE__);
	else
		debug_ctrl_init();
}

void sprdwl_debugfs_deinit(void)
{
	/* remove debugfs */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	debugfs_remove(sprdwl_debug_root);
#else
	debugfs_remove_recursive(sprdwl_debug_root);
#endif
}

static int sprdwl_ini_download_status(void)
{
	/*disable download ini function, just return 1*/
	/*	return 1; */
	/*fw is ready for receive ini file*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return 0;
#else
	return !cali_ini_need_download(MARLIN_WIFI);
#endif
}

static void sprdwl_force_exit(void *spdev)
{
	struct sprdwl_intf *intf;
	struct sprdwl_tx_msg *tx_msg;

	intf = (struct sprdwl_intf *)spdev;
	tx_msg = (struct sprdwl_tx_msg *)intf->sprdwl_tx;
	intf->exit = 1;
}

static int sprdwl_is_exit(void *spdev)
{
	struct sprdwl_intf *intf;

	intf = (struct sprdwl_intf *)spdev;
	return intf->exit;
}

static void sprdwl_tcp_drop_msg(void *spdev, struct sprdwl_msg_buf *msgbuf)
{
	enum sprdwl_mode mode;
	struct sprdwl_msg_list *list;
	struct sprdwl_intf *intf = (struct sprdwl_intf *)spdev;

	if (msgbuf->skb)
		dev_kfree_skb(msgbuf->skb);
	mode = msgbuf->mode;
	list = msgbuf->msglist;
	sprdwl_free_msg_buf(msgbuf, list);
	sprdwl_wake_net_ifneed(intf, list, mode);
}

static struct sprdwl_if_ops sprdwl_core_ops = {
	.get_msg_buf = sprdwl_get_msg_buf,
	.free_msg_buf = sprdwl_tx_free_msg_buf,
#ifdef SPRDWL_TX_SELF
	.tx = sprdwl_tx_self_msg,
#else
	.tx = sprdwl_tx_msg_func,
#endif
	.force_exit = sprdwl_force_exit,
	.is_exit = sprdwl_is_exit,
	.debugfs = sprdwl_debugfs,
	.tcp_drop_msg = sprdwl_tcp_drop_msg,
	.ini_download_status = sprdwl_ini_download_status
};

enum sprdwl_hw_type sprd_core_get_hwintf_mode(void)
{
	/*It's better that BSP layer can provide a API interface for this.*/
#ifdef SIPC_SUPPORT
	return SPRDWL_HW_SIPC;
#else
	return SPRDWL_HW_SC2355_PCIE;
#endif
}

static void tp_recovery_timer_func(struct timer_list *t)
{
	if(time_before(jiffies, g_tp_config.last_time +  msecs_to_jiffies(1500))
		|| time_before(jiffies, g_tp_config.rx_last_time +  msecs_to_jiffies(1500))){
		/*during data transfer, restart timer to check after 3s*/
		mod_timer(&g_tp_config.tp_recovery_timer, jiffies + (TP_RECOVERY_TIMEOUT * HZ / 1000));
	}else{
		/*duing 1.5s last_time and rx_last_time not update, its means not in data transfer, set cpu freq to normal now*/
		if(g_tp_config.disable_pd_flag || g_tp_config.rx_disable_pd_flag){
			spin_lock_bh(&g_tp_config.lock);
			g_tp_config.tx_bytes = 0;
			g_tp_config.disable_pd_flag = false;
			g_tp_config.rx_bytes = 0;
			g_tp_config.rx_disable_pd_flag = false;
			sprdwcn_bus_pm_qos_set(WIFI_TX_HIGH_THROUGHPUT, false);
			sprdwcn_bus_pm_qos_set(WIFI_RX_HIGH_THROUGHPUT, false);
			spin_unlock_bh(&g_tp_config.lock);
		}
	}
}

void sc2355_sipc_throughput_static_init(void)
{
	spin_lock_init(&g_tp_config.lock);
	spin_lock_bh(&g_tp_config.lock);
	g_tp_config.tx_bytes = 0;
	g_tp_config.last_time = jiffies;
	g_tp_config.disable_pd_flag = false;
	g_tp_config.rx_bytes = 0;
	g_tp_config.rx_last_time = jiffies;
	g_tp_config.rx_disable_pd_flag = false;
	pm_qos_add_request(&g_tp_config.pm_qos_request_idle,
			   PM_QOS_CPU_DMA_LATENCY, PM_QOS_CPU_DMA_LAT_DEFAULT_VALUE);
        timer_setup(&g_tp_config.tp_recovery_timer,
		tp_recovery_timer_func, 0);
	spin_unlock_bh(&g_tp_config.lock);
}

void sc2355_sipc_throughput_static_deinit(void)
{
	spin_lock_bh(&g_tp_config.lock);
	pm_qos_remove_request(&g_tp_config.pm_qos_request_idle);
	del_timer_sync(&g_tp_config.tp_recovery_timer);
	spin_unlock_bh(&g_tp_config.lock);
}

void config_wifi_ddr_priority(struct platform_device *pdev)
{
	struct resource *res;
	unsigned long long ipa_qos_remap = 0;
	unsigned char temp;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "wifi_ipaqos");
	if (!res) {
		wl_err("wifi_ipaqos get_resource fail!\n");
		return;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	ipa_qos_remap = (unsigned long long)ioremap(res->start, resource_size(res));
#else
	ipa_qos_remap = (unsigned long long)devm_ioremap_nocache(sprdwl_dev, res->start, resource_size(res));
#endif
	wl_debug("ipa_qos_remap=0x%llx\n", ipa_qos_remap);

	/*IPA: 0x21040064*/
	/*11:8 arqos_m1(PCIE2), 15:12 awqos_m1(PCIE2)*/
	/*set arqos_m1 and  awqos_m1 to 0x0A*/
	/*other byte by default set to 0x09*/

	temp = readb_relaxed((void *)(ipa_qos_remap + 1));
	wl_info("%s read ipa_qos: %x\n", __func__, temp);
	writeb_relaxed(HIGHER_DDR_PRIORITY, (void *)(ipa_qos_remap + 1));
	temp = readb_relaxed((void *)(ipa_qos_remap + 1));
	wl_info("%s write ipa_qos: %x\n", __func__, temp);
}

/* This function is used to get the key val from string */
void sprdwl_chr_get_cmdval(u32 *val, u8 *pos, u8 *key, int octal)
{
	u8 *temp = strstr(pos, key);

	if (!temp) {
		wl_info("CHR: %s,%s failed\n", __func__, key);
		return;
	}
	temp += strlen(key);

	*val = simple_strtoul(temp, NULL, octal);
}

/* this function is used to decode string */
int sprdwl_chr_decode_str(struct chr_cmd *cmd_set, u8 *data)
{
	char temp_str[CHR_BUF_SIZE] = {0};
	u8 *pos = data;

	if (strstr(pos, "wcn_chr_set_event")) {
		memcpy(cmd_set->evt_type, pos, strlen("wcn_chr_set_event"));
		pos += strlen("wcn_chr_set_event,");
	}
	if (strstr(pos, "module=WIFI")) {
		memcpy(cmd_set->module, pos + strlen("module="), strlen("WIFI"));
		pos += strlen("module=WIFI,");
	}

	sprdwl_chr_get_cmdval(&cmd_set->evt_id, pos, "event_id=", 16);
	sprdwl_chr_get_cmdval(&cmd_set->set, pos, "set=", 10);
	sprdwl_chr_get_cmdval(&cmd_set->maxcount, pos, "maxcount=", 16);
	sprdwl_chr_get_cmdval(&cmd_set->timerlimit, pos, "tlimit=", 16);

	wl_info("CHR: decode_str: %s, %s, %#x, %d, %#x, %#x\n",
		cmd_set->evt_type, cmd_set->module, cmd_set->evt_id,
		cmd_set->set, cmd_set->maxcount, cmd_set->timerlimit);

	snprintf(temp_str, CHR_BUF_SIZE, "wcn_chr_set_event,module=WIFI,"
		"event_id=0x%x,set=%d,maxcount=0x%x,tlimit=0x%x", cmd_set->evt_id,
		cmd_set->set, cmd_set->maxcount, cmd_set->timerlimit);

	return strlen(temp_str);
}

/* This function is used to fill chr_driver_params and sendbuf */
void sprdwl_fill_chr_driver(struct chr_driver_params *chr_driver, u16 refcnt, u32 id,
			  u8 version, u8 content_len, u8 *content, u8 *buf)
{
	char temp[64] = {0};
	chr_driver->refcnt = refcnt;
	chr_driver->evt_id = id;
	chr_driver->version = version;
	chr_driver->evt_content_len = content_len;
	chr_driver->evt_content = content;

	if (id == EVT_CHR_DISC_LINK_LOSS || id == EVT_CHR_DISC_SYS_ERR
		|| id == EVT_CHR_OPEN_ERR) {
		snprintf(temp, sizeof(temp), "%u", (*content));
		snprintf(buf, CHR_BUF_SIZE, "wcn_chr_ind_event,module=WIFI,"
			"ref_count=%u,event_id=0x%x,version=0x%x,event_content_len=%d,"
			"char_info=%s", refcnt, id, version, (int)strlen(temp), temp);
	}
	return;
}

/* This function is used to report chr_disconnect evt from CP2 */
void sprdwl_report_chr_disconnection(struct sprdwl_vif *vif, u8 version,
				   u32 evt_id, u32 evt_id_subtype,
				   u8 evt_content_len, u8 *evt_content)
{
	int ret;
	u16 refcnt = 0;
	struct chr_linkloss_disc_error link_loss = {0};
	struct chr_system_disc_error system_err = {0};
	struct chr_driver_params chr_driver = {0};
	struct sprdwl_chr *chr = vif->priv->chr;

	u8 sendbuf[CHR_BUF_SIZE] = {0};
	u8 *pos = evt_content;

	if (*pos >= CHR_ARR_SIZE) {
		wl_info("%s, CHR: the content: %u is invalid, reporting not allowed",
			__func__, *pos);
		return;
	}

	if (evt_id == EVT_CHR_DISC_LINK_LOSS) {
		refcnt = ++chr->chr_refcnt->disc_linkloss_cnt[*pos];
		memcpy(&link_loss.reason_code, pos, sizeof(link_loss.reason_code));
		wl_info("%s: CHR: %s, ref_cnt=%u\n", __func__,
			link_loss.reason_code == 1 ? "Power off AP" : "Beacon Loss",
			refcnt);
	} else if (evt_id == EVT_CHR_DISC_SYS_ERR) {
		refcnt = ++chr->chr_refcnt->disc_systerr_cnt[*pos];
		memcpy(&system_err.reason_code, pos, sizeof(system_err.reason_code));
		wl_info("%s: CHR: SYSTEM_ERR_DISCONNECT, ref_cnt=%u\n", __func__, refcnt);
	}

	sprdwl_fill_chr_driver(&chr_driver, refcnt, evt_id, version,
			     evt_content_len, evt_content, sendbuf);

	if (chr->chr_sock) {
		ret = sprdwl_chr_sock_sendmsg(chr, sendbuf);
		if (ret)
			wl_err("CHR: wifi_driver_sendmsg failed with 0x%x\n", evt_id);
	} else {
		wl_err("%s, CHR: socket had been disconnected", __func__);
	}

	return;
}

/* This function is used to report chr_open_error evt from driver */
void sc2355_sipc_report_chr_open_error(struct sprdwl_chr *chr, u32 evt_id, u8 err_code)
{
	{
	int ret;
	u16 refcnt = 0;
	struct chr_open_error open_error = {0};
	struct chr_driver_params chr_driver = {0};
	u8 sendbuf[CHR_BUF_SIZE] = {0};

	if (err_code >= CHR_ARR_SIZE) {
		wl_info("%s, CHR: the err_code: %u is invalid, reporting not allowed",
			__func__, err_code);
		return;
	}

	refcnt = ++chr->chr_refcnt->open_err_cnt[err_code];
	open_error.reason_code = err_code;

	sprdwl_fill_chr_driver(&chr_driver, refcnt, evt_id, CHR_VERSION, 1, &err_code, sendbuf);

	if (chr->chr_sock) {
		ret = sprdwl_chr_sock_sendmsg(chr, sendbuf);
		if (ret)
			wl_err("CHR: wifi_driver_sendmsg failed with 0x%x\n", evt_id);
	} else {
		wl_err("CHR: connect been closed, can not send msg to server");
	}

	wl_info("%s: %s, ref_cnt=%u\n", __func__,
		open_error.reason_code == 0 ? "Power_on Err" : "Download_ini Err",
		refcnt);
	return;
}
}

/*   Sendmsg style is as follows:
 *   "wcn_chr_ind_event,module=WIFI,refcnt=%d,
 *   event_id=0x%x,version=0x%x,
 *   event_content_len=%d,
 *   char_info=*********"
*/
int sc2355_sipc_chr_sock_sendmsg(struct sprdwl_chr *chr, u8 *data)
{
	int ret;
	struct msghdr send_msg = {0};
	struct kvec send_vec = {0};

	send_vec.iov_base = data;
	send_vec.iov_len = 1024;

	wl_info("CHR: ready to sendmsg: %s\n", data);
	ret = kernel_sendmsg(chr->chr_sock, &send_msg, &send_vec, 1, CHR_BUF_SIZE);
	if (ret < 0) {
		wl_err("%s, CHR: sendmsg failed, release socket");
		if (chr->chr_sock)
			sock_release(chr->chr_sock);
		return -EINVAL;
	}

	return 0;
}

/* this function is used to reset chr->cmd_list*/
void sprdwl_chr_rebuild_cmdlist(struct sprdwl_chr *chr, struct chr_cmd *cmd_set)
{
	u32 index;

	if (cmd_set->evt_id >= EVT_CHR_DRV_MIN && cmd_set->evt_id <= EVT_CHR_DRV_MAX) {
		index = cmd_set->evt_id - EVT_CHR_DRV_MIN;

		if (index >= CHR_ARR_SIZE || index < 0) {
			wl_err("%s, CHR: index:%u is invalid\n", __func__, index);
			return;
		}

		if (cmd_set->set == 1 && !chr->drv_cmd_list[index].set) {
			chr->drv_len = chr->drv_len + 1;
			wl_info("%s, CHR: start monitoring evt_id:%#x, drv_len: %u",
				__func__, cmd_set->evt_id, chr->drv_len);
		} else if (cmd_set->set == 0 && chr->drv_cmd_list[index].set) {
			chr->drv_len = chr->drv_len - 1;
			wl_info("%s, CHR: stop monitoring evt_id:%#x, drv_len: %u",
				__func__, cmd_set->evt_id, chr->drv_len);
		} else {
			wl_info("%s, CHR: adjust evt's params evt_id:%#x, drv_len: %u",
				__func__, cmd_set->evt_id, chr->drv_len);
		}
		memcpy(&chr->drv_cmd_list[index], cmd_set, sizeof(struct chr_cmd));

	} else if (cmd_set->evt_id >= EVT_CHR_FW_MIN && cmd_set->evt_id <= EVT_CHR_FW_MAX) {
		index = cmd_set->evt_id - EVT_CHR_FW_MIN;

		if (index >= CHR_ARR_SIZE || index < 0) {
			wl_err("%s, CHR: index:%u is invalid\n", __func__, index);
			return;
		}

		if (cmd_set->set == 1 && !chr->fw_cmd_list[index].set) {
			chr->fw_len = chr->fw_len + 1;
			wl_info("%s, CHR: start monitoring evt_id:%#x, fw_len: %u",
				__func__, cmd_set->evt_id, chr->fw_len);
		} else if (cmd_set->set == 0 && chr->fw_cmd_list[index].set) {
			chr->fw_len = chr->fw_len - 1;
			wl_info("%s, CHR: stop monitoring evt_id:%#x, fw_len: %u",
				__func__, cmd_set->evt_id, chr->fw_len);
		} else {
			wl_info("%s, CHR: adjust evt's params evt_id:%#x, fw_len: %u",
				__func__, cmd_set->evt_id, chr->fw_len);
		}
		memcpy(&chr->fw_cmd_list[index], cmd_set, sizeof(struct chr_cmd));
	}

	return;
}

static int sprdwl_chr_set_sockflag(struct sprdwl_chr *chr, u8 *data)
{
	if (!strcmp("wcn_chr_disable", data)) {
		chr->fw_len = 0;
		chr->drv_len = 0;
		chr->sock_flag = 2;
		memset(&chr->fw_cmd_list, 0, sizeof(chr->fw_cmd_list));
		memset(&chr->drv_cmd_list, 0, sizeof(chr->drv_cmd_list));
		wl_info("CHR: disable all chr_evt, sock_flag set %u", chr->sock_flag);
		return -1;
	}
	chr->sock_flag = 1;
	wl_info("CHR: enable chr_evt, sock_flag set %u", chr->sock_flag);
	return 0;
}

/* This funtions is equivalent to "in_aton", using  "in_aton" can't pass google's whitelist check */
__be32 sprdwl_transform_aton(const char *str)
{
       unsigned int l;
       unsigned int val;
       int i;

       l = 0;
       for (i = 0; i < 4; i++) {
               l <<= 8;
               if (*str != '\0') {
                       val = 0;
                       while (*str != '\0' && *str != '.' && *str != '\n') {
                               val *= 10;
                               val += *str - '0';
                               str++;
                       }
                       l |= val;
                       if (*str != '\0')
                               str++;
               }
       }
       return htonl(l);
}

extern struct sprdwl_intf *g_intf;
static int sprdwl_chr_client_thread(void *params)
{
	int ret, sbuf_len, buf_pos;
	struct sockaddr_in s_addr;
	char recv_buf[CHR_BUF_SIZE] = {0};
	struct msghdr recv_msg = {0};
	struct kvec recv_vec = {0};
	struct chr_cmd command = {0};
	struct sprdwl_chr *chr;
	struct sprdwl_priv *priv;
	struct sprdwl_intf *intf = g_intf;

	chr = (struct sprdwl_chr *)params;
	priv = chr->priv;

	chr->chr_sock = kzalloc(sizeof(struct socket), GFP_KERNEL);
	if (!chr->chr_sock) {
		return -ENOMEM;
	}

/* After receiving disable_chr each time, it's necessary to establish
a new connection with the upper */
retry:

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &chr->chr_sock);
	if (ret < 0) {
		wl_err("CHR: sock_client create failed %d\n", ret);
		sock_release(chr->chr_sock);
		kfree(chr->chr_sock);
		chr->chr_sock = NULL;
		return -EINVAL;
	}

	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(4758);
	s_addr.sin_addr.s_addr = sprdwl_transform_aton("127.0.0.1");

	/* optimize:block here while server not ready */
	while (chr->chr_sock->ops->connect(chr->chr_sock, (struct sockaddr *)&s_addr, sizeof(s_addr), 0)) {
		msleep(1000);
	}

	wl_info("CHR: wifi client connected\n");

	recv_vec.iov_base = recv_buf;
	recv_vec.iov_len = CHR_BUF_SIZE;

	/* sock_flag = 2 means have recevied disable_chr, it will break out here to establish
	a new connection with upper */
	while (!kthread_should_stop() && chr->sock_flag != 2) {
		buf_pos = 0;
		memset(recv_buf, 0, sizeof(recv_buf));
		memset(&recv_msg, 0, sizeof(recv_msg));
		wl_info("CHR: wait for recv_msg");
		ret = kernel_recvmsg(chr->chr_sock, &recv_msg, &recv_vec, 1, CHR_BUF_SIZE, 0);

		if (unlikely(chr->thread_exit))
			goto exit;

		wl_info("%s, CHR: recvmsg: %s", __func__, recv_buf);
		wl_info("CHR: msg_len is %d", (int)strlen(recv_buf));

		/* Multiple chr_evt may be sended through a single string */
		while (ret && recv_buf[buf_pos]) {
			if (sprdwl_chr_set_sockflag(chr, recv_buf))
				break;

			sbuf_len = sprdwl_chr_decode_str(&command, recv_buf + buf_pos);

			sprdwl_chr_rebuild_cmdlist(chr, &command);

			buf_pos += sbuf_len;
			memset(&command, 0, sizeof(command));
		}

		/* Only when Wi-Fi is open,  will cmd be sent to CP2, otherwise cmd will be saved */
		if (sprdwl_chip_is_on(intf)) {
			ret = sprdwl_set_chr(chr);
			if (ret)
				wl_err("%s, CHR: set chr_cmd to CP2 failed", __func__);
		} else {
			wl_info("%s, CHR: Drop set_chr_cmd in case of power off, save buf in chr_cmdlist",
				__func__);
		}
	}

	if (chr->chr_sock)
		sock_release(chr->chr_sock);
	chr->sock_flag = 0;
	wl_info("%s, CHR: init socket, try to connect server\n", __func__);

	goto retry;

exit:

	chr->thread_exit = 0;
	usleep_range(50, 100);
	pr_info("%s, CHR: exit client_thread\n", __func__);

	return 0;
}

int sc2355_sipc_init_chr(struct sprdwl_chr *chr)
{
	struct chr_refcnt_arr *refcnt = NULL;

	/* Only init chr_refcnt one time */
	if (!chr->chr_refcnt) {
		refcnt = kzalloc(sizeof(*refcnt), GFP_KERNEL);
		if (!refcnt) {
			wl_info("%s, kzalloc refcnt failed", __func__);
			return -ENOMEM;
		}
		chr->chr_refcnt = refcnt;
	}

	chr->chr_client_thread = NULL;
	chr->chr_sock = NULL;

	wl_info("%s, CHR: ready to init the chr_client_thread", __func__);
	chr->chr_client_thread = kthread_create(sprdwl_chr_client_thread, chr, "wifi_driver_chr");
	if (IS_ERR_OR_NULL(chr->chr_client_thread)) {
		wl_err("CHR: client thread create failed\n");
		return -1;
	}
	wake_up_process(chr->chr_client_thread);

	return 0;
}

void sc2355_sipc_deinit_chr(struct sprdwl_chr *chr)
{
	if (chr->chr_client_thread) {
		chr->thread_exit = 1;

		if (chr->chr_sock) {
			if (chr->chr_sock->ops) {
				chr->chr_sock->ops->shutdown(chr->chr_sock, SHUT_RDWR);
				kthread_stop(chr->chr_client_thread);
				chr->chr_client_thread = NULL;
				sock_release(chr->chr_sock);
				chr->chr_sock = NULL;
			}
		}
		pr_info("%s, CHR: stop chr_client_thread!\n", __func__);
	}

	kfree(chr);
	return;
}

struct sprdwl_chr_ops sc2355_sipc_chr_ops = {
	.init_chr = sc2355_sipc_init_chr,
	.deinit_chr = sc2355_sipc_deinit_chr,
	.chr_sock_sendmsg = sc2355_sipc_chr_sock_sendmsg,
	.chr_report_openerr = sc2355_sipc_report_chr_open_error,
};

int sprdwl_probe(struct platform_device *pdev)
{
	struct sprdwl_intf *intf;
	struct sprdwl_priv *priv;
	struct sprdwl_chr *chr = NULL;
	int ret;
	u32 ker_len;
	u8 i;

	sprdwl_dev = &pdev->dev;
	wl_err("%s enter, printk=%d\n", __func__, console_loglevel);
	intf = kzalloc(sizeof(*intf), GFP_ATOMIC);
	if (!intf) {
		ret = -ENOMEM;
		wl_err("%s alloc intf fail: %d\n", __func__, ret);
		return ret;
	}

	platform_set_drvdata(pdev, intf);
	intf->pdev = pdev;
	//sprdwl_dev = &pdev->dev;
	dma_coerce_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(39));
	for (i = 0; i < MAX_LUT_NUM; i++)
		intf->peer_entry[i].ctx_id = 0xff;

	priv = sprdwl_core_create(sprd_core_get_hwintf_mode(),
				  &sprdwl_core_ops);
	if (!priv) {
		wl_err("%s core create fail\n", __func__);
		ret = -ENXIO;
		kfree(intf);
		return ret;
	}
        ker_len = (strlen(utsname()->release) >7)? 7: strlen(utsname()->release);
	memcpy(priv->wl_ver.kernel_ver, utsname()->release,ker_len);
	memcpy(priv->wl_ver.drv_ver, SPRDWL_DRIVER_VERSION,
			strlen(SPRDWL_DRIVER_VERSION));
	memcpy(priv->wl_ver.update, SPRDWL_UPDATE, strlen(SPRDWL_UPDATE));
	memcpy(priv->wl_ver.reserve, SPRDWL_RESERVE, strlen(SPRDWL_RESERVE));
	wl_info("Spreadtrum WLAN Version:");
	wl_info("Kernel:%s,Driver:%s,update:%s,reserved:%s\n",
			 utsname()->release, SPRDWL_DRIVER_VERSION,
			 SPRDWL_UPDATE, SPRDWL_RESERVE);

	if (priv->hw_type == SPRDWL_HW_SC2355_SDIO) {
		intf->hif_offset = sizeof(struct sdiohal_puh);
		intf->rx_cmd_port = SDIO_RX_CMD_PORT;
		intf->rx_data_port = SDIO_RX_DATA_PORT;
		intf->tx_cmd_port = SDIO_TX_CMD_PORT;
		intf->tx_data_port = SDIO_TX_DATA_PORT;
	} else if (priv->hw_type == SPRDWL_HW_SIPC) {
#ifdef SIPC_SUPPORT
		intf->hif_offset = 0;
		intf->rx_cmd_port = SIPC_WIFI_CMD_RX;
		intf->rx_data_port = SIPC_WIFI_DATA0_RX;
		intf->tx_cmd_port = SIPC_WIFI_CMD_TX;
		intf->tx_data_port = SIPC_WIFI_DATA0_TX;
		if (sipc_txrx_buf_init(pdev, intf)) {
			ret = -ENOMEM;
			wl_err("%s sipc txrx init failed.\n", __func__);
			sprdwl_core_free((struct sprdwl_priv *)intf->priv);
			kfree(intf);
			return ret;
		}
		wl_info("%s txrx buf init success.\n", __func__);
#endif
	} else {
		intf->hif_offset = 0;
		intf->rx_cmd_port = PCIE_RX_CMD_PORT;
		intf->rx_data_port = PCIE_RX_ADDR_DATA_PORT;
		intf->tx_cmd_port = PCIE_TX_CMD_PORT;
		intf->tx_data_port = PCIE_TX_ADDR_DATA_PORT;
		if (sprdwl_txrx_buf_init()) {
			ret = -ENOMEM;
			wl_err("%s txrx buf init failed.\n", __func__);
			sprdwl_core_free((struct sprdwl_priv *)intf->priv);
			kfree(intf);
			return ret;
		}
	}

	sprdwl_sipc_init(priv, intf);
	ret = sprdwl_rx_init(intf);
	if (ret) {
		wl_err("%s rx init failed: %d\n", __func__, ret);
#ifdef SIPC_SUPPORT
		sprdwl_sipc_txrx_buf_deinit(intf);
#endif
		sprdwl_txrx_buf_deinit();
		sprdwl_sipc_deinit(intf);
		sprdwl_core_free((struct sprdwl_priv *)intf->priv);
		kfree(intf);
		return ret;
	}

	ret = sprdwl_tx_init(intf);
	if (ret) {
		wl_err("%s tx_list init failed\n", __func__);
		sprdwl_rx_deinit(intf);
#ifdef SIPC_SUPPORT
		sprdwl_sipc_txrx_buf_deinit(intf);
#endif
		sprdwl_txrx_buf_deinit();
		sprdwl_sipc_deinit(intf);
		sprdwl_core_free((struct sprdwl_priv *)intf->priv);
		kfree(intf);
		return ret;
	}
	
	sc2355_sipc_throughput_static_init();

	/* Int the chr struct and bind its ops*/
	chr = kzalloc(sizeof(*chr), GFP_KERNEL);
	if (!chr) {
		wl_info("%s, kzalloc chr failed", __func__);
		return -ENOMEM;
	}
	priv->chr = chr;
	chr->priv = priv;
	chr->ops = &sc2355_sipc_chr_ops;

	if (!chr->chr_sock) {
		wl_info("CHR: Creating chr_client_thread\n");
		ret = sprdwl_init_chr(chr);
		if (ret) {
			wl_err("%s chr init failed: %d\n", __func__, ret);
		}
	}
	
	wl_info("%s Power on wcn (%d time)\n", __func__, atomic_read(&intf->power_cnt));
	ret = sprdwl_chip_set_power(intf, true);
	if (ret) {
		sprdwl_deinit_chr(chr);
		sprdwl_tx_deinit(intf);
		sprdwl_rx_deinit(intf);
#ifdef SIPC_SUPPORT
		sprdwl_sipc_txrx_buf_deinit(intf);
#endif
		sprdwl_txrx_buf_deinit();
		sprdwl_chip_set_power(intf, false);
		sprdwl_sipc_deinit(intf);
		sprdwl_core_free((struct sprdwl_priv *)intf->priv);
		kfree(intf);
		return ret;
	}

	ret = sprdwl_core_init(&pdev->dev, priv);
	if (ret) {
		wl_err("%s sprdwl_core_init failed!\n", __func__);
		sprdwl_deinit_chr(chr);
		sprdwl_tx_deinit(intf);
		sprdwl_rx_deinit(intf);
#ifdef SIPC_SUPPORT
		sprdwl_sipc_txrx_buf_deinit(intf);
#endif
		sprdwl_txrx_buf_deinit();
		sprdwl_chip_set_power(intf, false);
		sprdwl_sipc_deinit(intf);
		sprdwl_core_free((struct sprdwl_priv *)intf->priv);
		kfree(intf);
		return ret;
	}

	ret = sprdwl_notify_init(priv);
	if (ret) {
		wl_err("%s sprdwl_notify failed!\n", __func__);
		sprdwl_core_deinit((struct sprdwl_priv *)intf->priv);
		sprdwl_deinit_chr(chr);
		sprdwl_tx_deinit(intf);
		sprdwl_rx_deinit(intf);
#ifdef SIPC_SUPPORT
		sprdwl_sipc_txrx_buf_deinit(intf);
#endif
		sprdwl_txrx_buf_deinit();
		sprdwl_chip_set_power(intf, false);
		sprdwl_sipc_deinit(intf);
		sprdwl_core_free((struct sprdwl_priv *)intf->priv);
		kfree(intf);
		return ret;
	}
#if defined FPGA_LOOPBACK_TEST
	intf->loopback_n = 0;
	sprdwl_intf_tx_data_fpga_test(intf, NULL, 0);
#endif

	sprdwl_debugfs_init(intf);

	wl_info("%s power off on wcn (%d time)\n", __func__, atomic_read(&intf->power_cnt));
	sprdwl_chip_set_power(intf, false);

	return ret;
}

int sprdwl_remove(struct platform_device *pdev)
{
	struct sprdwl_intf *intf = platform_get_drvdata(pdev);
	struct sprdwl_priv *priv = intf->priv;
	int ret = 0;

	wl_info("%s power on wcn (%d time)\n", __func__, atomic_read(&intf->power_cnt));
	ret = sprdwl_chip_set_power(intf, true);
	if (ret)
		return ret;
	sprdwl_debugfs_deinit();
	sprdwl_notify_deinit(priv);
	sprdwl_core_deinit(priv);
    sc2355_sipc_throughput_static_deinit();

	sprdwl_deinit_chr(priv->chr);
	sprdwl_tx_deinit(intf);
	sprdwl_rx_deinit(intf);
#ifdef SIPC_SUPPORT
	sprdwl_sipc_txrx_buf_deinit(intf);
#endif
	sprdwl_txrx_buf_deinit();
	wl_info("%s power off on wcn (%d time)\n", __func__, atomic_read(&intf->power_cnt));
	sprdwl_chip_set_power(intf, false);
	sprdwl_sipc_deinit(intf);
	sprdwl_core_free(priv);
	kfree(intf);
	wl_warn("%s, %d\n", __func__, __LINE__);

	return ret;
}
#if 0
static const struct of_device_id sprdwl_of_match[] = {
	{.compatible = "sprd,sc2355-sipc-wifi",},
	{}
};
MODULE_DEVICE_TABLE(of, sprdwl_of_match);

static struct platform_driver sprdwl_driver = {
	.probe = sprdwl_probe,
	.remove = sprdwl_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "sc2355",
		.of_match_table = sprdwl_of_match,
	}
};

module_platform_driver(sprdwl_driver);

MODULE_DESCRIPTION("Spreadtrum Wireless LAN Driver");
MODULE_AUTHOR("Spreadtrum WCN Division");
MODULE_LICENSE("GPL");
#endif
