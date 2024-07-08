/*
 * Copyright (C) 2015 Spreadtrum Communications Inc.
 *
 * Authors	:
 * Keguang Zhang <keguang.zhang@spreadtrum.com>
 * Jingxiang Li <Jingxiang.li@spreadtrum.com>
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

#ifndef __SPRDWL_CORE_SC2355_H__
#define __SPRDWL_CORE_SC2355_H__

#include <linux/types.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>
#include <linux/etherdevice.h>
#include "cfg80211.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define SPRDWL_NORMAL_MEM	0
#define SPRDWL_DEFRAG_MEM	1
#define SPRDWL_RSERVE_MEM	2


#define SPRDWL_TX_CMD_TIMEOUT	3000
#define SPRDWL_TX_DATA_TIMEOUT	4000

#define SPRDWL_TX_MSG_CMD_NUM 128
#define SPRDWL_TX_QOS_POOL_SIZE 20000
#define SPRDWL_TX_DATA_START_NUM (SPRDWL_TX_QOS_POOL_SIZE - 3)
#define SPRDWL_RX_MSG_NUM 20000

/* tx len less than cp len 4 byte as sdiom 4 bytes align */
/* set MAX CMD length to 1600 on firmware side*/
#define SPRDWL_MAX_CMD_TXLEN	1596
#define SPRDWL_MAX_CMD_RXLEN	1092
#define SPRDWL_MAX_DATA_TXLEN	1672
#define SPRDWL_MAX_DATA_RXLEN	1676

#define SAVE_ADDR(data, buf, len) memcpy((data - len), &buf, len)
#define RESTORE_ADDR(buf, data, len) memcpy(&buf, (data - len), len)
#define CLEAR_ADDR(data, len) memset((data - len), 0x0, len)

#define MAX_LUT_NUM 32

#define HIGHER_DDR_PRIORITY	0xAA

#define CHR_VERSION			1
#define CHR_BUF_SIZE		1024
#define CHR_ARR_SIZE		64
#define CHR_CP2_DATA_LEN	11

struct tx_address {
	u8 da[ETH_ALEN];
	u8 sa[ETH_ALEN];
};

struct rx_address {
	u8 sa[ETH_ALEN];
	u8 da[ETH_ALEN];
};

struct sprdwl_peer_entry {
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
	/*tx ba done based on tid*/
	unsigned long ba_tx_done_map;
	u8 vowifi_enabled;
	u8 vowifi_pkt_cnt;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	struct timespec64 time[6 + 1];
#else
	struct timespec time[6 + 1];
#endif
};

#if defined(MORE_DEBUG)
/*tx/rx states and performance statistics*/
struct txrx_stats {
	unsigned long	rx_packets;
	/*tx success packets num*/
	unsigned long	tx_packets;
	unsigned long	rx_bytes;
	/*tx success bytes num*/
	unsigned long	tx_bytes;
	unsigned long	rx_errors;
	unsigned long	tx_errors;
	unsigned int tx_nomem_errors;
	unsigned int tx_fail_errors;
	unsigned long	rx_dropped;
	unsigned long	tx_dropped;
	/*alloc pkt fail*/
	unsigned long rx_pktgetfail;
	unsigned long tx_pktgetfail;
	/* Number of tx packets we had to realloc for headroom */
	unsigned long tx_realloc;
	/* multicast packets received */
	unsigned long	rx_multicast;
	unsigned long	tx_multicast;
	unsigned long tx_cost_time;
	unsigned long tx_avg_time;
	unsigned long tx_arp_num;
	/*qos ac stream1 sent num*/
	unsigned long ac1_num;
	/*qos ac stream2 sent num*/
	unsigned long ac2_num;
	unsigned long tx_filter_num;
	/*statistical sample count*/
	unsigned int gap_num;
};
#endif

struct tdls_flow_count_para {
	u8 valid;
	u8 da[ETH_ALEN];
	/*u8 timer;seconds*/
	u16 threshold;/*KBytes*/
	u32 data_len_counted;/*bytes*/
	u32 start_mstime;/*ms*/
	u8 timer;/*seconds*/
};

#define MAX_TDLS_PEER 32

struct chr_cmd {
	u8 evt_type[18];
	u8 module[12];
	u32 evt_id;
	u32 set;
	u32 maxcount;
	u32 timerlimit;
};

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

struct sprdwl_chr {
	/* 0 means haven't received any messages,
	* 1 is have received messages about open chr_evt,
	* 2 is have received messages about close all chr_evt
	*/
	u8 sock_flag;
	u8 thread_exit;
	u8 open_err_flag;
	const struct sprdwl_chr_ops *ops;
	struct sprdwl_priv *priv;

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

struct sprdwl_chr_ops {
	int (*init_chr)(struct sprdwl_chr *chr);
	void (*deinit_chr)(struct sprdwl_chr *chr);
	int (*chr_sock_sendmsg)(struct sprdwl_chr *chr, u8 *data);
	void (*chr_report_openerr)(struct sprdwl_chr *chr, u32 evt_id, u8 err_code);
};

/* format negotiated with CP2 */
struct evt_chr {
	u8 version; /* reserve for future */
	u32 evt_id;
	u32 evt_id_subtype; /* reserve for future */
	u8 evt_content_len;
	u8 *evt_content; /* CP2 define the event_content size is 100byte */
} __packed;

/* used by driver to store CHR params*/
struct chr_driver_params {
	u16 refcnt;
	u32 evt_id;
	u8 version;
	u8 evt_content_len;
	u8 *evt_content;
};

struct chr_open_error {
	u8 reason_code; /* 0 is power_on err, 1 is download_ini err*/
};

struct chr_linkloss_disc_error {
	u8 reason_code; /* 1 is device power off, 2 is beacon loss */
};

struct chr_system_disc_error {
	u8 reason_code;
};

struct sprdwl_priv;
struct sprdwl_intf {
	struct platform_device *pdev;
	/* priv use void *, after MCC adn priv->flags,
	 * and change txrx intf pass priv to void later
	 */
	struct sprdwl_priv *priv;

	/* if nedd more flags which not only exit, fix it*/
	/* unsigned int exit:1; */
	int exit;
	atomic_t power_cnt;

	int flag;
	int lastflag;

	int tx_mode;
	int rx_mode;

	/*point to hif interface(sdio/pcie)*/
	void *hw_intf;

	/* Manage tx function */
	void *sprdwl_tx;
	/* Manage rx function */
	void *sprdwl_rx;

	struct sprdwl_peer_entry peer_entry[MAX_LUT_NUM];
	unsigned long tx_num[MAX_LUT_NUM];
	unsigned char skb_da[ETH_ALEN];
#if defined FPGA_LOOPBACK_TEST
	int loopback_n;
#endif

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
	/*suspend_mode:ap suspend/resumed status
	  resumed:cp suspend/resumed status*/
#define SPRDWL_PS_SUSPENDING  1
#define SPRDWL_PS_SUSPENDED  2
#define SPRDWL_PS_RESUMING  3
#define SPRDWL_PS_RESUMED  0
	int suspend_mode;

	int fw_power_down;
	int fw_awake;

	/*for pkt log function*/
	loff_t lp;
	struct file *pfile;
	/*for suspend resume time count*/
	unsigned long sleep_time;

	u8 cp_asserted;

	void *mbuf_head;
	void *mbuf_tail;
	int mbuf_num;
	int remove_flag;
	/*lock to ensure L1SS status change ok*/
	spinlock_t l1ss_lock;
	u8 tsq_shift;
	unsigned int tcpack_delay_th_in_mb;
	unsigned int tcpack_time_in_ms;
	unsigned long pushfail_count;
#ifdef WMMAC_WFA_CERTIFICATION
	unsigned char wmm_special_flag;
#endif
#ifdef SIPC_SUPPORT
	struct sipc_txrx_mm  *sipc_mm;
#endif
	atomic_t block_cmd_after_close;
	atomic_t change_iface_block_cmd;
};

/* The following is about CHR */
enum REPORT_CHR_LIST {
	EVT_CHR_WIFI_MIN = 0x11501,

	/* Error From Driver */
	EVT_CHR_DRV_MIN = EVT_CHR_WIFI_MIN,

	EVT_CHR_OPEN_ERR = EVT_CHR_DRV_MIN,

	EVT_CHR_DRV_MAX = 0X13000,
	/* Wi-Fi Disconnect */
	EVT_CHR_FW_MIN = 0X13001,

	EVT_CHR_DISC_LINK_LOSS = EVT_CHR_FW_MIN,
	EVT_CHR_DISC_SYS_ERR,

	EVT_CHR_FW_MAX = 0X15000,

	REPORT_CHR_WIFI_MAX = 0X15000
};

void sprdwl_free_data(void *data, int buffer_type);
enum sprdwl_hw_type sprd_core_get_hwintf_mode(void);

void sprdwl_event_tdls_flow_count(struct sprdwl_vif *vif, u8 *data, u16 len);
void count_tdls_flow(struct sprdwl_vif *vif, u8 *data, u16 len);
void sprdwl_tdls_flow_flush(struct sprdwl_vif *vif, const u8 *peer, u8 oper);
bool sprdwl_chip_is_on(struct sprdwl_intf *intf);
int sprdwl_chip_power_on(struct sprdwl_intf *intf);
void sprdwl_chip_power_off(struct sprdwl_intf *intf);
int sprdwl_chip_set_power(struct sprdwl_intf *intf, bool val);

static inline int sprdwl_init_chr(struct sprdwl_chr *chr)
{
	if (chr->ops->init_chr)
		return chr->ops->init_chr(chr);
	return -1;
}

static inline void sprdwl_deinit_chr(struct sprdwl_chr *chr)
{
	if (chr->ops->deinit_chr)
		chr->ops->deinit_chr(chr);
}

static inline int sprdwl_chr_sock_sendmsg(struct sprdwl_chr *chr, u8 *data)
{
	if (chr->ops->chr_sock_sendmsg)
		return chr->ops->chr_sock_sendmsg(chr, data);
	return -1;
}

static inline void sprdwl_report_chr_open_error(struct sprdwl_chr *chr, u32 evt_id,
													u8 err_code)
{
	if (chr->ops->chr_report_openerr)
		chr->ops->chr_report_openerr(chr, evt_id, err_code);
}
#endif
