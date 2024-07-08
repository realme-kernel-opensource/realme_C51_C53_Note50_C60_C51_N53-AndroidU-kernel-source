/*
 * Copyright (C) 2018 Spreadtrum Communications Inc.
 *
 * File:		wcn_misc.c
 * Description:	WCN misc file for drivers. Some feature or function
 * isn't easy to classify, then write it in this file.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the	1
 * GNU General Public License for more details.
 */

#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/sched/clock.h>
#include <asm/div64.h>

#include "wcn_misc.h"
#include "wcn_procfs.h"
#include "wcn_txrx.h"
#include "mdbg_type.h"
#include "../include/wcn_dbg.h"
#if IS_ENABLED(CONFIG_SPRD_POWER_DEBUG)
#include "sysfs.h"
#include <linux/soc/sprd/sprd_pdbg.h>
#endif
static struct atcmd_fifo s_atcmd_owner;
static struct wcn_tm tm;
static unsigned long long s_marlin_bootup_time;

#if IS_ENABLED(CONFIG_SPRD_POWER_DEBUG)
struct wcn_slpinfo_desc g_slpinfo;

static struct wcn_slpinfo_desc *wcn_get_slpinfo_data(void)
{
	return &g_slpinfo;
}
#endif

void mdbg_atcmd_owner_init(void)
{
	memset(&s_atcmd_owner, 0, sizeof(s_atcmd_owner));
	mutex_init(&s_atcmd_owner.lock);
}

void mdbg_atcmd_owner_deinit(void)
{
	mutex_destroy(&s_atcmd_owner.lock);
}

static void mdbg_atcmd_owner_add(enum atcmd_owner owner)
{
	mutex_lock(&s_atcmd_owner.lock);
	s_atcmd_owner.owner[s_atcmd_owner.tail % ATCMD_FIFO_MAX] = owner;
	s_atcmd_owner.tail++;
	mutex_unlock(&s_atcmd_owner.lock);
}

enum atcmd_owner mdbg_atcmd_owner_peek(void)
{
	enum atcmd_owner owner;

	mutex_lock(&s_atcmd_owner.lock);
	owner = s_atcmd_owner.owner[s_atcmd_owner.head % ATCMD_FIFO_MAX];
	s_atcmd_owner.head++;
	mutex_unlock(&s_atcmd_owner.lock);

	WCN_INFO("owner=%d, head=%d\n", owner, s_atcmd_owner.head - 1);
	return owner;
}

void mdbg_atcmd_clean(void)
{
	mutex_lock(&s_atcmd_owner.lock);
	memset(&s_atcmd_owner.owner[0], 0, ARRAY_SIZE(s_atcmd_owner.owner));
	s_atcmd_owner.tail = 0;
	s_atcmd_owner.head = 0;
	mutex_unlock(&s_atcmd_owner.lock);
}

/*
 * Until now, CP2 response every AT CMD to AP side
 * without owner-id.AP side transfer every ATCMD
 * response info to WCND.If AP send AT CMD on kernel layer,
 * and the response info transfer to WCND,
 * WCND deal other owner's response CMD.
 * We'll not modify CP2 codes because some
 * products already released to customer.
 * We will save all of the owner-id to the atcmd fifo.
 * and dispatch the response ATCMD info to the matched owner.
 * We'd better send all of the ATCMD with this function
 * or caused WCND error
 */
long int mdbg_send_atcmd(char *buf, size_t len, enum atcmd_owner owner)
{
	long int sent_size = 0;

	mdbg_atcmd_owner_add(owner);

	/* confirm write finish */
	mutex_lock(&s_atcmd_owner.lock);
	sent_size = mdbg_send(buf, len, MDBG_SUBTYPE_AT);
	mutex_unlock(&s_atcmd_owner.lock);

	WCN_INFO("%s, owner=%d\n", buf, owner);

	return sent_size;
}

/* copy from function: kdb_gmtime */
static void wcn_gmtime(struct timespec64 *tv, struct wcn_tm *tm)
{
	uint64_t result = 0;
	uint64_t divisor = 0;
	/* This will work from 1970-2099, 2100 is not a leap year */
	static int mon_day[] = { 31, 29, 31, 30, 31, 30, 31,
				 31, 30, 31, 30, 31 };
	memset(tm, 0, sizeof(*tm));
	result = tv->tv_nsec;
	divisor = 1000000;
	do_div(result, divisor);
	tm->tm_msec = result;

	result = tv->tv_sec;
	divisor = 24 * 60 * 60;
	tm->tm_sec = do_div(result, divisor);
	tm->tm_mday = result + (2 * 365 + 1);

	result = tm->tm_sec;
	divisor = 60;
	tm->tm_sec = do_div(result, divisor);

	tm->tm_min = do_div(result, divisor);
	tm->tm_hour = result;

	result = tm->tm_mday;
	divisor = 4 * 365 + 1;
	tm->tm_mday = do_div(result, divisor);
	tm->tm_year = 68 + 4 * result;

	mon_day[1] = 29;
	while (tm->tm_mday >= mon_day[tm->tm_mon]) {
		tm->tm_mday -= mon_day[tm->tm_mon];
		if (++tm->tm_mon == 12) {
			tm->tm_mon = 0;
			++tm->tm_year;
			mon_day[1] = 28;
		}
	}
	++tm->tm_mday;
}

char *wcn_get_kernel_time(void)
{
	struct timespec64 now;
	static char aptime[64];

	/* get ap kernel time and transfer to China-BeiJing Time */
	ktime_get_real_ts64(&now);
	wcn_gmtime(&now, &tm);
	tm.tm_hour = (tm.tm_hour + WCN_BTWF_TIME_OFFSET) % 24;

	/* save time with string: month,day,hour,min,sec,mili-sec */
	memset(aptime, 0, 64);
	sprintf(aptime, "at+aptime=%ld,%ld,%ld,%ld,%ld,%ld\r\n",
		tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_msec);

	return aptime;
}

/* AP notify BTWF time by at+aptime=... cmd */
long int wcn_ap_notify_btwf_time(void)
{
	char *aptime;
	long int send_cnt = 0;

	aptime = wcn_get_kernel_time();

	/* send to BTWF CP2 */
	send_cnt = mdbg_send_atcmd((void *)aptime, strlen(aptime),
				   WCN_ATCMD_KERNEL);
	WCN_INFO("%s, send_cnt=%ld", aptime, send_cnt);

	return send_cnt;
}

/*
 * Only marlin poweron and marlin starts to run,
 * it can call this function.
 * The time will be sent to marlin with loopcheck CMD.
 * NOTES:If marlin power off, and power on again, it
 * should call this function again.
 */
void marlin_bootup_time_update(void)
{
	s_marlin_bootup_time = local_clock();
	WCN_INFO("s_marlin_bootup_time=%llu",
		 s_marlin_bootup_time);
}

unsigned long long marlin_bootup_time_get(void)
{
	return s_marlin_bootup_time;
}

#define WCN_VMAP_RETRY_CNT (20)
static void *wcn_mem_ram_vmap(phys_addr_t start, size_t size,
			      int noncached, unsigned int *count)
{
	struct page **pages;
	phys_addr_t page_start;
	unsigned int page_count;
	pgprot_t prot;
	unsigned int i;
	void *vaddr;
	phys_addr_t addr;
	int retry = 0;

	page_start = start - offset_in_page(start);
	page_count = DIV_ROUND_UP(size + offset_in_page(start), PAGE_SIZE);
	*count = page_count;
	if (noncached)
		prot = pgprot_noncached(PAGE_KERNEL);
	else
		prot = PAGE_KERNEL;

retry1:
	pages = kmalloc_array(page_count, sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		if (retry++ < WCN_VMAP_RETRY_CNT) {
			usleep_range(8000, 10000);
			goto retry1;
		} else {
			WCN_ERR("malloc err\n");
			return NULL;
		}
	}

	for (i = 0; i < page_count; i++) {
		addr = page_start + i * PAGE_SIZE;
		pages[i] = pfn_to_page(addr >> PAGE_SHIFT);
	}
retry2:
	vaddr = vm_map_ram(pages, page_count, -1, prot);
	if (!vaddr) {
		if (retry++ < WCN_VMAP_RETRY_CNT) {
			usleep_range(8000, 10000);
			goto retry2;
		} else {
			WCN_ERR("vmap err\n");
			goto out;
		}
	} else {
		vaddr += offset_in_page(start);
	}
out:
	kfree(pages);

	return vaddr;
}

void wcn_mem_ram_unmap(const void *mem, unsigned int count)
{
	vm_unmap_ram(mem - offset_in_page(mem), count);
}

void *wcn_mem_ram_vmap_nocache(phys_addr_t start, size_t size,
			       unsigned int *count)
{
	return wcn_mem_ram_vmap(start, size, 1, count);
}

#ifdef CONFIG_ARM64
static inline void wcn_unalign_memcpy(void *to, const void *from, u32 len)
{
	if (((unsigned long)to & 7) == ((unsigned long)from & 7)) {
		while (((unsigned long)from & 7) && len) {
			*(char *)(to++) = *(char *)(from++);
			len--;
		}
		memcpy(to, from, len);
	} else if (((unsigned long)to & 3) == ((unsigned long)from & 3)) {
		while (((unsigned long)from & 3) && len) {
			*(char *)(to++) = *(char *)(from++);
			len--;
		}
		while (len >= 4) {
			*(u32 *)(to) = *(u32 *)(from);
			to += 4;
			from += 4;
			len -= 4;
		}
		while (len) {
			*(char *)(to++) = *(char *)(from++);
			len--;
		}
	} else {
		while (len) {
			*(char *)(to++) = *(char *)(from++);
			len--;
		}
	}
}
#else
static inline void wcn_unalign_memcpy(void *to, const void *from, u32 len)
{
	memcpy(to, from, len);
}
#endif

int wcn_write_zero_to_phy_addr(phys_addr_t phy_addr, u32 size)
{
	char *virt_addr;
	unsigned int cnt;
	unsigned char zero = 0x00;
	unsigned int loop = 0;

	virt_addr = (char *)wcn_mem_ram_vmap_nocache(phy_addr, size, &cnt);
	if (virt_addr) {
		for (loop = 0; loop < size; loop++)
			wcn_unalign_memcpy((void *)(virt_addr + loop), &zero, 1);

		wcn_mem_ram_unmap(virt_addr, cnt);
		return 0;
	}

	WCN_ERR("%s fail\n", __func__);
	return -1;
}

int wcn_write_data_to_phy_addr(phys_addr_t phy_addr,
			       void *src_data, u32 size)
{
	char *virt_addr, *src;
	unsigned int cnt;

	src = (char *)src_data;
	virt_addr = (char *)wcn_mem_ram_vmap_nocache(phy_addr, size, &cnt);
	if (virt_addr) {
		wcn_unalign_memcpy((void *)virt_addr, (void *)src, size);
		wcn_mem_ram_unmap(virt_addr, cnt);
		return 0;
	}

	WCN_ERR("wcn_mem_ram_vmap_nocache fail\n");
	return -1;
}
EXPORT_SYMBOL_GPL(wcn_write_data_to_phy_addr);

int wcn_read_data_from_phy_addr(phys_addr_t phy_addr,
				void *tar_data, u32 size)
{
	char *virt_addr, *tar;
	unsigned int cnt;

	tar = (char *)tar_data;
	virt_addr = wcn_mem_ram_vmap_nocache(phy_addr, size, &cnt);
	if (virt_addr) {
		wcn_unalign_memcpy((void *)tar, (void *)virt_addr, size);
		wcn_mem_ram_unmap(virt_addr, cnt);
		return 0;
	}

	WCN_ERR("wcn_mem_ram_vmap_nocache fail\n");
	return -1;
}
EXPORT_SYMBOL_GPL(wcn_read_data_from_phy_addr);

#if IS_ENABLED(CONFIG_SPRD_POWER_DEBUG)
static char *wcn_slpinfo_irq_type_to_str(enum wcn_source_type type, enum intc_wakeup_irq irq_type)
{
	char *irq_type_str_by_btwf[WAKEUP_BY_INVALID] = {
		"BTWF_SDIO_128BIT_AP_WAKE_CP2",
		"BTWF_TOP_AON",
		"BTWF_SDIO_INT",
		"BTWF_TMR0_TMR0_INTC",
		"BTWF_WIFI_MAC_INTC",
		"BTWF_BT_MASKED_AUX_TMR",
		"BTWF_FM_INTC",
		"BTWF_BT_TIM",
		"BTWF_BT_ACCELERATOR",
		"BTWF_OTHERS",
	};

	if (type == WCN_SOURCE_GNSS)
		return "GNSS_WAKEUP_IRQ";

	if (irq_type < WAKEUP_BY_EIC_LATCH_SDIO_AP_WAKE_PULSE || irq_type >= WAKEUP_BY_INVALID)
		return "INVALID";

	return irq_type_str_by_btwf[irq_type];
}

static uint64_t wcn_slpinfo_ns_to_clk32k(uint64_t ns)
{
	uint32_t remainder = 0;
	uint32_t clk32k_union_per_ns = 30517;

	/* 32K(32768HZ), count value = 30.517 us */
	remainder = do_div(ns, clk32k_union_per_ns);
	if (remainder * 2 > clk32k_union_per_ns)
		ns++;

	return ns;
}

static void wcn_slpinfo_derive(struct wcn_slpinfo_desc *slpinfo,
		struct subsys_slp_info *sys_slpinfo, enum wcn_source_type type, bool is_ns)
{
	int irq_type_num = 0;
	struct wcn_slpinfo_firmware *wcn_slpinfo = NULL;

	if (type == WCN_SOURCE_BTWF) {
		wcn_slpinfo = &slpinfo->btwf_general;
		sys_slpinfo->boot_cnt = slpinfo->btwf_reboot_cnt;
	} else if (type == WCN_SOURCE_GNSS) {
		wcn_slpinfo = &slpinfo->gnss_general;
		sys_slpinfo->boot_cnt = slpinfo->gnss_reboot_cnt;
	} else
		return;

	sys_slpinfo->total_time =
		is_ns ? wcn_slpinfo_ns_to_clk32k(wcn_slpinfo->total_time) :
		wcn_slpinfo->total_time;
	sys_slpinfo->total_slp_time = is_ns ?
		wcn_slpinfo_ns_to_clk32k(wcn_slpinfo->total_slp_time) :
		wcn_slpinfo->total_slp_time;
	sys_slpinfo->last_enter_time = is_ns ?
		wcn_slpinfo_ns_to_clk32k(wcn_slpinfo->last_enter_time) :
		wcn_slpinfo->last_enter_time;
	sys_slpinfo->last_exit_time = is_ns ?
		wcn_slpinfo_ns_to_clk32k(wcn_slpinfo->last_exit_time) :
		wcn_slpinfo->last_exit_time;
	sys_slpinfo->total_slp_cnt = wcn_slpinfo->total_slp_cnt;
	sys_slpinfo->cur_slp_state = wcn_slpinfo->cur_slp_state;
	sys_slpinfo->last_ws = wcn_slpinfo->last_wakeup_irq;

	irq_type_num = min(ARRAY_SIZE(sys_slpinfo->ws_cnt),
			ARRAY_SIZE(wcn_slpinfo->top_wakeup_irq_cnt));
	memcpy(sys_slpinfo->ws_cnt, wcn_slpinfo->top_wakeup_irq_cnt,
			irq_type_num * sizeof(sys_slpinfo->ws_cnt[0]));
}

static void wcn_slpinfo_show(enum wcn_source_type type,
	struct wcn_slpinfo_desc *slpinfo, size_t read_len, bool is_ns)
{
	int i = 0;
	struct wcn_slpinfo_firmware *slp_infocp2 = NULL;

	if (type == WCN_SOURCE_BTWF)
		slp_infocp2 = &slpinfo->btwf_general;
	else if (type == WCN_SOURCE_GNSS)
		slp_infocp2 = &slpinfo->gnss_general;
	else
		return;

	WCN_INFO("%s: SLP INFO (%lu-%lu)[time unit-%s]:\n", slp_infocp2->name,
		sizeof(*slp_infocp2), read_len, is_ns ? "ns" : "32k count");
	WCN_INFO("EXT[CP2 START TIME:%llu, REBOOT_CNT:%llu]\n",
		slp_infocp2->priv_info.irq.system_enter_time,
		type == WCN_SOURCE_BTWF ? slpinfo->btwf_reboot_cnt : slpinfo->gnss_reboot_cnt);
	WCN_INFO("DURATION TIME[TOTAL :%llu, DEEPSLEEP:%llu, ACTIVE(work+idle):%llu]\n",
		slp_infocp2->total_time, slp_infocp2->total_slp_time,
		slp_infocp2->total_time - slp_infocp2->total_slp_time);
	WCN_INFO("DEEPSLEEP[CUR_STATE:%u, COUNTER:%llu, ENTER:%llu, EXIT:%llu]\n",
		slp_infocp2->cur_slp_state, slp_infocp2->total_slp_cnt,
		slp_infocp2->last_enter_time, slp_infocp2->last_exit_time);
	WCN_INFO("LAST WAKEUP BY IRQ:%u\n", slp_infocp2->last_wakeup_irq);
	for (i = 0; i < ARRAY_SIZE(slp_infocp2->top_wakeup_irq_cnt); i++)
		WCN_INFO("WAKEUP BY-%s:%u\n", wcn_slpinfo_irq_type_to_str(type, i),
			slp_infocp2->top_wakeup_irq_cnt[i]);

	for (i = 0; i < ARRAY_SIZE(slp_infocp2->priv_info.irq.wakeup_by_intnum); i++)
		WCN_INFO("WAKE IRQ List:%u", slp_infocp2->priv_info.irq.wakeup_by_intnum[i]);
}

static int wcn_slpinfo_get_for_btwf(struct subsys_slp_info *info)
{
	char at_cmd_getslpinfo[] = "at+debug=12\r";
	size_t slp_info_len = WCN_AT_RSP_RAW_FLAG;
	int ret = 0;
	struct wcn_slpinfo_desc *slpinfo = wcn_get_slpinfo_data();
	struct wcn_slpinfo_firmware *slp_infocp2 = &slpinfo->btwf_general;

	memset(&slpinfo->btwf_general, 0, sizeof(slpinfo->btwf_general));
	ret = wcn_send_atcmd(at_cmd_getslpinfo, strlen(at_cmd_getslpinfo),
			(void *)slp_infocp2, &slp_info_len);
	if (ret) {
		if (!IS_ERR_OR_NULL(info))
			memset(info, 0, sizeof(*info));
		WCN_ERR("%s: BTFW is closed %d\n", __func__, ret);
		return -ENODATA;
	}

	if (strncmp(slp_infocp2->name, WCN_SLP_INFO_SYNC_LABEL, sizeof(WCN_SLP_INFO_SYNC_LABEL))) {
		WCN_WARN("%s: firmware cannot capture\n", __func__);
		return -ENODATA;
	}
	slp_infocp2->name[ARRAY_SIZE(slp_infocp2->name) - 1] = 0;

	print_hex_dump(KERN_INFO, "SLPINFO-", DUMP_PREFIX_OFFSET, 16, 4,
			(void *)slp_infocp2, slp_info_len, true);
	wcn_slpinfo_show(WCN_SOURCE_BTWF, slpinfo, slp_info_len, false);

	if (!IS_ERR_OR_NULL(info))
		wcn_slpinfo_derive(slpinfo, info, WCN_SOURCE_BTWF, false);

	return 0;
}

static int wcn_slpinfo_get_for_gnss(struct subsys_slp_info *info)
{
	struct wcn_slpinfo_desc *slpinfo = wcn_get_slpinfo_data();

	if (slpinfo->gnss_general.cur_slp_state == WCN_POWER_OFF) {
		if (!IS_ERR_OR_NULL(info))
			memset(info, 0, sizeof(*info));
		WCN_ERR("%s: GNSS is closed[TOTALTIME:%llu,REBOOT_CNT=%llu]\n", __func__,
		slpinfo->gnss_general.total_time, slpinfo->gnss_reboot_cnt);
		return 0;
	}

	slpinfo->gnss_general.total_time = ktime_get_boottime_ns() -
		slpinfo->gnss_general.priv_info.irq.system_enter_time;

	wcn_slpinfo_show(WCN_SOURCE_GNSS, slpinfo, sizeof(slpinfo->gnss_general), true);
	if (!IS_ERR_OR_NULL(info))
		wcn_slpinfo_derive(slpinfo, info, WCN_SOURCE_GNSS, true);

	return 0;
}

void wcn_slpinfo_statistics(enum wcn_source_type type, bool poweron)
{
	struct wcn_slpinfo_desc *slpinfo = wcn_get_slpinfo_data();

	if (type == WCN_SOURCE_BTWF) {
		if (!poweron)
			memset(&slpinfo->btwf_general, 0, sizeof(slpinfo->btwf_general));
		else
			slpinfo->btwf_reboot_cnt++;
	} else if (type == WCN_SOURCE_GNSS) {
		/* Currently, GNSS only calculates the power up and down parameters on the AP */
		if (!poweron) {
			memset(&slpinfo->gnss_general, 0, sizeof(slpinfo->gnss_general));
			slpinfo->gnss_general.priv_info.irq.system_enter_time = 0;
			slpinfo->gnss_general.cur_slp_state = WCN_POWER_OFF;
		} else {
			memset(&slpinfo->gnss_general, 0, sizeof(slpinfo->gnss_general));
			slpinfo->gnss_general.priv_info.irq.system_enter_time =
				ktime_get_boottime_ns();
			slpinfo->gnss_general.cur_slp_state = WCN_ACTIVE;
			slpinfo->gnss_reboot_cnt++;
		}
	}

}

int wcn_slpinfo_get(enum wcn_source_type subsys, void *info)
{
	if (subsys == WCN_SOURCE_BTWF)
		return wcn_slpinfo_get_for_btwf((struct subsys_slp_info *)info);
	else if (subsys == WCN_SOURCE_GNSS)
		return wcn_slpinfo_get_for_gnss((struct subsys_slp_info *)info);
	else
		return -EINVAL;
}

static int wcn_slpinfo_notifier_fn(struct notifier_block *nb,
			unsigned long action, void *data)
{
	int ret = 0;
	enum wcn_source_type src_type = WCN_SOURCE_BTWF;

	if (IS_ERR_OR_NULL(data))
		return -EINVAL;

	if (action == PDBG_NB_SYS_WCN_BTWF_SLP_GET)
		src_type = WCN_SOURCE_BTWF;
	else if (action == PDBG_NB_SYS_WCN_GNSS_SLP_GET)
		src_type = WCN_SOURCE_GNSS;
	else {
		WCN_WARN("%s: Unexpected commands\n", __func__);
		return 0;
	}

	ret = wcn_slpinfo_get(src_type, data);
	if (ret)
		WCN_INFO("%s: %s sleep info request failed %d\n", __func__,
			src_type == WCN_SOURCE_BTWF ? "BTWF" : "GNSS", ret);

	return ret;
}

static struct notifier_block wcn_slpinfo_notifier = {
	.notifier_call = wcn_slpinfo_notifier_fn,
};
#endif

int wcn_misc_init(void)
{
	int ret = 0;
#if IS_ENABLED(CONFIG_SPRD_POWER_DEBUG)
	struct wcn_slpinfo_desc *slpinfo = wcn_get_slpinfo_data();

	snprintf(slpinfo->gnss_general.name, ARRAY_SIZE(slpinfo->gnss_general.name), "GNSS");

	ret = sprd_pdbg_notify_register(&wcn_slpinfo_notifier);
	if (ret) {
		WCN_ERR("%s: failed to register pdbg_notify\n", __func__, ret);
		return 0;
	}
#endif
	return ret;
}

void wcn_misc_exit(void)
{
#if IS_ENABLED(CONFIG_SPRD_POWER_DEBUG)
	if (sprd_pdbg_notify_unregister(&wcn_slpinfo_notifier))
		WCN_ERR("%s: failed to unregister pdbg_notify\n", __func__);
#endif
}
