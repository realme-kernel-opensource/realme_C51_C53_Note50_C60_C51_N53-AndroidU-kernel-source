/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  linux/drivers/mmc/core/mmc_ops.h
 *
 *  Copyright 2006-2007 Pierre Ossman
 */

#ifndef _MMC_MMC_OPS_H
#define _MMC_MMC_OPS_H

#include <linux/types.h>

struct mmc_host;
struct mmc_card;

int mmc_select_card(struct mmc_card *card);
int mmc_deselect_cards(struct mmc_host *host);
int mmc_set_dsr(struct mmc_host *host);
int mmc_go_idle(struct mmc_host *host);
int mmc_send_op_cond(struct mmc_host *host, u32 ocr, u32 *rocr);
int mmc_set_relative_addr(struct mmc_card *card);
int mmc_send_csd(struct mmc_card *card, u32 *csd);
int __mmc_send_status(struct mmc_card *card, u32 *status, unsigned int retries);
int mmc_send_status(struct mmc_card *card, u32 *status);
int mmc_send_cid(struct mmc_host *host, u32 *cid);
int mmc_spi_read_ocr(struct mmc_host *host, int highcap, u32 *ocrp);
int mmc_spi_set_crc(struct mmc_host *host, int use_crc);
int mmc_bus_test(struct mmc_card *card, u8 bus_width);
int mmc_interrupt_hpi(struct mmc_card *card);
int mmc_can_ext_csd(struct mmc_card *card);
int mmc_get_ext_csd(struct mmc_card *card, u8 **new_ext_csd);
int mmc_switch_status(struct mmc_card *card);
int __mmc_switch_status(struct mmc_card *card, bool crc_err_fatal);
int __mmc_switch(struct mmc_card *card, u8 set, u8 index, u8 value,
		unsigned int timeout_ms, unsigned char timing,
		bool use_busy_signal, bool send_status,	bool retry_crc_err);
int mmc_switch(struct mmc_card *card, u8 set, u8 index, u8 value,
		unsigned int timeout_ms);
void mmc_run_bkops(struct mmc_card *card);
int mmc_flush_cache(struct mmc_card *card);
int mmc_cmdq_enable(struct mmc_card *card);
int mmc_cmdq_disable(struct mmc_card *card);

#ifdef CONFIG_MMC_SPRD_MMCHEALTH
#define YMTC_EC110_eMMC 1  //cjcc changjiangcunchu 32G
#define HFCS_32G_eMMC1 2 //zhaoxin 32G
#define HFCS_32G_eMMC2 3 //zhaoxin 32G
//#define HFCS_64G_eMMC1 4 //zhaoxin 64G
#define HFCS_64G_eMMC2 4 //zhaoxin 64G
#define Western_Digital_eMMC 5 //sandisk shandi
#define YMTC_EC110_eMMC1 6 //cjcc changjiangcunchu 128G
#define YMTC_EC110_eMMC2 7 //cjcc changjiangcunchu 64G
#define Micron_64G_eMMC 8 //Micron 64G
#define Micron_128G_eMMC 9 //Micron 128G
#define Foresee_64G_eMMC 10 //Jiangbolong 64G
#define Foresee_128G_eMMC 11 //Jiangbolong 128G
#define Phison_64G_eMMC 12 //Qunlian 64G
#define Phison_128G_eMMC 13 //Qunlian 64G
#define YMTC_EC230_eMMC 14 //cjcc changjiangcunchu 256G
int mmc_health(struct mmc_card *card);
int get_emmc_mode(void);
#endif
#endif

