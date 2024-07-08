/*
* SPDX-FileCopyrightText: 2021-2022 Unisoc (Shanghai) Technologies Co., Ltd
* SPDX-License-Identifier: GPL-2.0
*
* Copyright 2021-2022 Unisoc (Shanghai) Technologies Co., Ltd
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of version 2 of the GNU General Public License
* as published by the Free Software Foundation.
*/

#ifndef __HIF_H__
#define __HIF_H__

#include <linux/platform_device.h>
#include <misc/marlin_platform.h>

#include "debug.h"
#include "msg.h"
#include "qos.h"
#include "tdls.h"

#define MAX_TDLS_PEER		32
#define MAX_LUT_NUM		32
#define SPRD_TX_CMD_TIMEOUT	3000
#define SPRD_TX_DATA_TIMEOUT	4000

#define SPRD_PS_SUSPENDING	1
#define SPRD_PS_SUSPENDED	2
#define SPRD_PS_RESUMING	3
#define SPRD_PS_RESUMED		0

#ifdef ENABLE_CHR
#define CHR_ARR_SIZE		64

struct chr_cmd {
	u8 evt_type[18];
	u8 module[12];
	u32 evt_id;
	u32 set;
	u32 maxcount;
	u32 timerlimit;
};
#endif

enum sprd_hif_type {
	SPRD_HW_SC2332_SDIO,
	SPRD_HW_SC2332_SIPC,
	SPRD_HW_SC2355_SDIO,
	SPRD_HW_SC2355_PCIE,
	SPRD_HW_SC2355_USB,
	SPRD_HW_SC2355_SIPC,
};

struct tx_address {
	u8 da[ETH_ALEN];
	u8 sa[ETH_ALEN];
};

struct rx_address {
	u8 sa[ETH_ALEN];
	u8 da[ETH_ALEN];
};

#if defined(MORE_DEBUG)
/* tx/rx states and performance statistics */
struct txrx_stats {
	unsigned long rx_packets;
	/* tx success packets num */
	unsigned long tx_packets;
	unsigned long rx_bytes;
	/* tx success bytes num */
	unsigned long tx_bytes;
	unsigned long rx_errors;
	unsigned long tx_errors;
	unsigned int tx_nomem_errors;
	unsigned int tx_fail_errors;
	unsigned long rx_dropped;
	unsigned long tx_dropped;
	/* alloc pkt fail */
	unsigned long rx_pktgetfail;
	unsigned long tx_pktgetfail;
	/* Number of tx packets we had to realloc for headroom */
	unsigned long tx_realloc;
	/* multicast packets received */
	unsigned long rx_multicast;
	unsigned long tx_multicast;
	unsigned long tx_cost_time;
	unsigned long tx_avg_time;
	unsigned long tx_arp_num;
	/* qos ac stream1 sent num */
	unsigned long ac1_num;
	/* qos ac stream2 sent num */
	unsigned long ac2_num;
	unsigned long tx_filter_num;
	/* statistical sample count */
	unsigned int gap_num;
};
#endif

struct sprd_peer_entry {
	union {
		struct rx_address rx;
		struct tx_address tx;
	};

	u8 lut_index;
	u8 ctx_id;
	u8 cipher_type;
	u8 pending_num;
	u8 ht_enable;
	u8 vht_enable;
	u8 ip_acquired;
	/* tx ba done based on tid */
	unsigned long ba_tx_done_map;
	u8 vowifi_enabled;
	u8 vowifi_pkt_cnt;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	struct timespec64 time[6 + 1];
#else
	struct timespec time[6 + 1];
#endif
};

#ifdef ENABLE_CHR
struct chr_refcnt_arr {
	u16 open_err_cnt[CHR_ARR_SIZE];
	u16 disc_linkloss_cnt[CHR_ARR_SIZE];
	u16 disc_systerr_cnt[CHR_ARR_SIZE];
};

/* The flag just used in sprd_iface_set_power to determine open_err evt*/
enum OPEN_ERR_LIST {
	OPEN_ERR_INIT = 0,
	OPEN_ERR_POWER_ON,
	OPEN_ERR_DOWNLOAD_INI
};

struct sprd_chr {
	/* 0 means haven't received any messages,
	* 1 is have received messages about open chr_evt,
	* 2 is have received messages about close all chr_evt
	*/
	u8 sock_flag;
	u8 thread_exit;
	u8 open_err_flag;
	const struct sprd_chr_ops *ops;
	struct sprd_priv *priv;
	struct sprd_hif *hif;

	struct task_struct *chr_client_thread;
	/* this struct saves all chr_evt_refcnt*/
	struct chr_refcnt_arr *chr_refcnt;
	struct socket *chr_sock;

	/* this val only stores the chr_buf for CP2*/
	struct chr_cmd fw_cmd_list[CHR_ARR_SIZE];
	u32 fw_len;
	/* this val only stores the chr_buf for drv */
	struct chr_cmd drv_cmd_list[CHR_ARR_SIZE];
	u32 drv_len;
};

struct sprd_chr_ops {
	int (*init_chr)(struct sprd_chr *chr);
	void (*deinit_chr)(struct sprd_chr *chr);
	int (*chr_sock_sendmsg)(struct sprd_chr *chr, u8 *data);
	void (*chr_report_openerr)(struct sprd_chr *chr, u32 evt_id, u8 err_code);
};
#endif

struct sprd_hif {
	struct platform_device *pdev;
	const struct sprd_hif_ops *ops;
	struct sprd_priv *priv;
#ifdef ENABLE_CHR
	struct sprd_chr *chr;
#endif
	netdev_features_t feature;

	int exit;
	atomic_t power_cnt;
	int flag;
	int lastflag;
	u8 cp_asserted;
	enum sprd_hif_type hw_type;

	/* SC2332 */
	unsigned long cmd_timeout;
	unsigned long data_timeout;
	/* lock for do_tx */
	spinlock_t lock;
	unsigned long do_tx;
	wait_queue_head_t waitq;
	unsigned int net_stop_cnt;
	unsigned int net_start_cnt;
	unsigned int drop_cmd_cnt;
	/* sta */
	unsigned int drop_data1_cnt;
	/* p2p */
	unsigned int drop_data2_cnt;
	unsigned int ring_cp;
	unsigned int ring_ap;
	atomic_t flow0;
	atomic_t flow1;
	atomic_t flow2;
	struct sprd_qos_t qos0;
	struct sprd_qos_t qos1;
	struct sprd_qos_t qos2;

	/* 1 for send data; 0 for not send data */
	int driver_status;

	/* lists are not included in struct sprd_vif
	 * while sprd wifi driver uses less cmd ports
	 */
	struct sprd_msg_list tx_list0;
	/* for STA/SOFTAP data */
	struct sprd_msg_list tx_list1;
	/* for P2P data */
	struct sprd_msg_list tx_list2;
	struct wakeup_source *tx_wakelock;
	/* tx may go into deepsleep while screen is off */
	struct wakeup_source *keep_wake;
	unsigned long wake_last_time;
	unsigned long wake_timeout;
	unsigned long wake_pre_timeout;

	struct work_struct tx_work;
	struct workqueue_struct *tx_queue;

	/* SC2355 */
	int tx_mode;
	int rx_mode;

	/* Manage tx function */
	void *tx_mgmt;
	/* Manage rx function */
	void *rx_mgmt;

	struct sprd_peer_entry peer_entry[MAX_LUT_NUM];
	unsigned long tx_num[MAX_LUT_NUM];
	unsigned char skb_da[ETH_ALEN];

	int hif_offset;
	unsigned char rx_cmd_port;
	unsigned char rx_data_port;
	unsigned char tx_cmd_port;
	unsigned char tx_data_port;
#if defined(MORE_DEBUG)
	struct txrx_stats stats;
#endif

	u8 tdls_flow_count_enable;
	struct tdls_flow_count_para tdls_flow_count[MAX_TDLS_PEER];
	int suspend_mode;

	int fw_power_down;
	int fw_awake;

	/* for pkt log function */
	loff_t lp;
	struct file *pfile;
	/* for suspend resume time count */
	unsigned long sleep_time;

	/* wifi bt coex mode, 1: BT is on, 0: BT is off */
	u8 coex_bt_on;
	void *mbuf_head;
	void *mbuf_tail;
	int mbuf_num;
	int pushfail_count;
	int remove_flag;

	/* block command before stop marlin */
	atomic_t block_cmd_after_close;
	/* block command while change iface */
	atomic_t change_iface_block_cmd;
#ifdef DRV_RESET_SELF
	u8 drv_resetting;
#endif
};

struct sprd_hif_ops {
	int (*init)(struct sprd_hif *hif);
	void (*deinit)(struct sprd_hif *hif);
	int (*post_init)(struct sprd_hif *hif);
	void (*post_deinit)(struct sprd_hif *hif);
	int (*reserv_len)(struct sprd_hif *hif);
	int (*sync_version)(struct sprd_priv *priv);
	void (*download_hw_param)(struct sprd_priv *priv);
	void (*fill_all_buffer)(struct sprd_hif *hif);
	int (*tx_special_data)(struct sk_buff *skb,
			       struct net_device *ndev);
	void (*free_msg_content)(struct sprd_msg *msg);
	int (*tx_free_data)(struct sprd_priv *priv, unsigned char *data);
	int (*tx_addr_trans)(struct sprd_hif *hif,
			     unsigned char *data, int len,
			     bool send_now);
	int (*reset)(struct sprd_hif *hif);
	void (*throughput_ctl_pd)(unsigned int len);
#ifdef DRV_RESET_SELF
	int (*reset_self)(struct sprd_priv *priv);
#endif
	void (*tx_flush)(struct sprd_hif *hif, struct sprd_vif *vif);
};

void sprd_clean_work(struct sprd_priv *priv);

static inline int sprd_hif_post_init(struct sprd_hif *hif)
{
	if (hif->ops->post_init)
		return hif->ops->post_init(hif);
	return 0;
}

static inline void sprd_hif_post_deinit(struct sprd_hif *hif)
{
	if (hif->ops->post_deinit)
		hif->ops->post_deinit(hif);
}

static inline bool sprd_hif_is_on(struct sprd_hif *hif)
{
	return (atomic_read(&hif->power_cnt) == 0 ? false : true);
}

static inline int sprd_sync_version(struct sprd_hif *hif)
{
	if (hif->ops->sync_version)
		return hif->ops->sync_version(hif->priv);

	return 0;
}

static inline void sprd_download_hw_param(struct sprd_hif *hif)
{
	if (hif->ops->download_hw_param)
		hif->ops->download_hw_param(hif->priv);
}

static inline int sprd_hif_power_on(struct sprd_hif *hif)
{
	atomic_add(1, &hif->power_cnt);

	if (atomic_read(&hif->power_cnt) != 1)
		return 0;

	if (start_marlin(MARLIN_WIFI)) {
		atomic_sub(1, &hif->power_cnt);
		return -ENODEV;
	}

	if (sprd_hif_post_init(hif)) {
		atomic_sub(1, &hif->power_cnt);
		return -ENODEV;
	}

	/* need reset hif->exit flag, if wcn reset happened */
	if (unlikely(hif->exit) || unlikely(hif->cp_asserted)) {
		pr_info("assert happended! need reset paras!\n");
		if (hif->ops->reset)
			hif->ops->reset(hif);
	}

	if (sprd_sync_version(hif)) {
		atomic_sub(1, &hif->power_cnt);
		return -EIO;
	}

	sprd_download_hw_param(hif);

	return 0;
}

static inline void sprd_hif_power_off(struct sprd_hif *hif)
{
	atomic_sub(1, &hif->power_cnt);

	if (atomic_read(&hif->power_cnt) != 0)
		return;

	sprd_clean_work(hif->priv);
	sprd_hif_post_deinit(hif);

	if (stop_marlin(MARLIN_WIFI))
		pr_err("stop_marlin failed!!\n");
}

static inline int sprd_hif_init(struct sprd_hif *hif)
{
	return hif->ops->init(hif);
}

static inline void sprd_hif_deinit(struct sprd_hif *hif)
{
	hif->ops->deinit(hif);
}

static inline int sprd_hif_reserve_len(struct sprd_hif *hif)
{
	if (hif->ops->reserv_len)
		return hif->ops->reserv_len(hif);

	return 0;
}

static inline void sprd_hif_fill_all_buffer(struct sprd_hif *hif)
{
	if (hif->ops->fill_all_buffer)
		hif->ops->fill_all_buffer(hif);
}

static inline int sprd_hif_tx_special_data(struct sprd_hif *hif,
					   struct sk_buff *skb,
					   struct net_device *ndev)
{
	if (hif->ops->tx_special_data)
		return hif->ops->tx_special_data(skb, ndev);
	return -1;
}

static inline void sprd_hif_throughput_ctl_pd(struct sprd_hif *hif, unsigned int len)
{
	if (hif->ops->throughput_ctl_pd)
		hif->ops->throughput_ctl_pd(len);
}

static inline void sprd_hif_tx_flush(struct sprd_hif *hif, struct sprd_vif *vif)
{
	if (hif->ops->tx_flush)
		hif->ops->tx_flush(hif, vif);
}

#ifdef ENABLE_CHR
static inline int sprd_init_chr(struct sprd_chr *chr)
{
	if (chr->ops->init_chr)
		return chr->ops->init_chr(chr);
	return -1;
}

static inline void sprd_deinit_chr(struct sprd_chr *chr)
{
	if (chr->ops->deinit_chr)
		chr->ops->deinit_chr(chr);
}

static inline int sprd_chr_sock_sendmsg(struct sprd_chr *chr, u8 *data)
{
	if (chr->ops->chr_sock_sendmsg)
		return chr->ops->chr_sock_sendmsg(chr, data);
	return -1;
}

static inline void sprd_report_chr_open_error(struct sprd_chr *chr, u32 evt_id,
					      u8 err_code)
{
	if (chr->ops->chr_report_openerr)
		chr->ops->chr_report_openerr(chr, evt_id, err_code);
}
#endif

#endif
