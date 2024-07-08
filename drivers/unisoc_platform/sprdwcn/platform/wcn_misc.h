#ifndef __WCN_MISC_H__
#define __WCN_MISC_H__

#include <linux/mutex.h>
#include <linux/types.h>
#include <asm-generic/div64.h>
#include <misc/wcn_bus.h>

/* Hours offset for GM and China-BeiJing */
#define WCN_BTWF_TIME_OFFSET (8)

#define ATCMD_FIFO_MAX	(16)

/*
 * AP use 64 bit for ns time.
 * marlin use 32 bit for ms time
 * we change ns to ms, and remove high bit value.
 * 32bit ms is more than 42days, it's engough
 * for loopcheck debug.
 */
#define NS_TO_MS                    1000000
#define MARLIN_64B_NS_TO_32B_MS(ns) do_div(ns, NS_TO_MS)
//#define MARLIN_64B_NS_TO_32B_MS(ns) ((unsigned int)(ns / 1000000))

enum atcmd_owner {
	/* default AT CMD reply to WCND */
	WCN_ATCMD_WCND = 0x0,
	/* Kernel not deal response info from CP2. 20180515 */
	WCN_ATCMD_KERNEL,
	WCN_ATCMD_LOG,
};

/*
 * Until now, CP2 response every AT CMD to AP side
 * without owner-id.
 * AP side transfer every ATCMD response info to WCND.
 * If AP send AT CMD on kernel layer, and the response
 * info transfer to WCND and caused WCND deal error
 * response CMD.
 * We will save all of the owner-id to the fifo.
 * and dispatch the response ATCMD info to the matched owner.
 */
struct atcmd_fifo {
	enum atcmd_owner owner[ATCMD_FIFO_MAX];
	unsigned int head;
	unsigned int tail;
	struct mutex lock;
};

struct wcn_tm {
	long tm_msec;    /* mili seconds */
	long tm_sec;     /* seconds */
	long tm_min;     /* minutes */
	long tm_hour;    /* hours */
	long tm_mday;    /* day of the month */
	long tm_mon;     /* month */
	long tm_year;    /* year */
};

#if IS_ENABLED(CONFIG_SPRD_POWER_DEBUG)
enum intc_wakeup_irq {
	WAKEUP_BY_EIC_LATCH_SDIO_AP_WAKE_PULSE, /* SD_CLK_DSlp_Handler */
	WAKEUP_BY_AON_INTC_TOP_AON_INT_IRQ_REQ_BB_TS, /* top_aon_isr */
	WAKEUP_BY_TB_SDIO_INTC_SRC_INT, /* Enable before deepsleep */
	WAKEUP_BY_TB_TMR0_TMR0_INTC_INT, /* Enable before deepsleep */
	WAKEUP_BY_TB_MAC_INTC_INT, /* Enable before deepsleep */
	WAKEUP_BY_TB_FIQ_BT_MASKED_AUX_TMR, /* Enable before deepsleep */
	WAKEUP_BY_TB_FM_INTC_SRC_INT, /* Enable before deepsleep */
	WAKEUP_BY_BT_TIM, /* BT_TIM, PKD, PKA */
	WAKEUP_BY_BT_ACCELERATOR, /* BT_ACCELERATOR, BT_MODEM */
	WAKEUP_BY_OTHERS,
	WAKEUP_BY_INVALID,
};

enum {
	WCN_ACTIVE,
	WCN_DEEPSLEEP,
	WCN_POWER_OFF,
};

#define WCN_SLP_INFO_SYNC_LABEL "BTWFSYS"
#define WAKEUP_SOURCE_IRQ_MAX WAKEUP_BY_INVALID

/**
 * struct subsys_sleep_info - sleep information structure from firmware(128 byte)
 * @total_time: CP2 system power on duration(32K clock count)
 * @total_slp_time: CP2 system deepsleep duration(32K clock count)
 * @last_enter_time: The last time enter deepsleep(32K clock count)
 * @last_exit_time: The last time exit deepsleep(32K clock count)
 * @total_slp_cnt: Number of times entering deepsleep
 * @name: subsys name
 * @last_wakeup_irq: The interrupt source for the last wakeup of the CP2
 * @cur_slp_state: 0 - active or idle, 1 - SYS deepsleep
 * @top_wakeup_irq_cnt: The number of times an interrupt type wakeup the CP2 system,
 *  which is not the actual interrupt number, but a type of interrupts, see intc_wakeup_irq
 * @wakeup_by_idx: current array wakeup_by_intnum array index
 * @check_irq_wakeup: CP2 exits deepsleep, preparing to save wakeup interrupt
 * @wakeup_by_intnum: wakeup the interrupt logic number of the system
 * @system_enter_time: CP2 system startup time(32K clock count)
 */

struct wcn_slpinfo_firmware {
    char name[8];
    uint8_t last_wakeup_irq;
    uint8_t cur_slp_state;
    uint64_t total_time;
    uint64_t total_slp_time;
    uint64_t last_enter_time;
    uint64_t last_exit_time;

    uint64_t total_slp_cnt;
    uint32_t top_wakeup_irq_cnt[WAKEUP_SOURCE_IRQ_MAX];

    union {
        struct priv_irq_info {
            uint8_t wakeup_by_idx;
            uint8_t check_irq_wakeup;
            uint16_t wakeup_by_intnum[10];
            uint64_t system_enter_time;
        } irq;
        uint32_t reserve[8];
    } priv_info;
} __aligned(4);

struct wcn_slpinfo_desc {
	struct wcn_slpinfo_firmware gnss_general;
	struct wcn_slpinfo_firmware btwf_general;
	uint64_t btwf_reboot_cnt, gnss_reboot_cnt;
};
void wcn_slpinfo_statistics(enum wcn_source_type type, bool poweron);
int wcn_slpinfo_get(enum wcn_source_type subsys, void *info);
#else
static inline void wcn_slpinfo_statistics(enum wcn_source_type type, bool poweron) {}
static inline int wcn_slpinfo_get(enum wcn_source_type subsys, void *info) { return -1; }
#endif

int wcn_misc_init(void);
void wcn_misc_exit(void);
void mdbg_atcmd_owner_init(void);
void mdbg_atcmd_owner_deinit(void);
long int mdbg_send_atcmd(char *buf, size_t len, enum atcmd_owner owner);
enum atcmd_owner mdbg_atcmd_owner_peek(void);
void mdbg_atcmd_clean(void);
/* AP notify BTWF time by at+aptime=... cmd */
long int wcn_ap_notify_btwf_time(void);
/*
 * Only marlin poweron, CP2 CPU tick starts to run,
 * It can call this function.
 * The time will be sent to marlin with loopcheck CMD.
 * NOTES:If marlin power off, and power on again, it
 * should call this function also.
 */
void marlin_bootup_time_update(void);
unsigned long long marlin_bootup_time_get(void);
char *wcn_get_kernel_time(void);

int wcn_write_zero_to_phy_addr(phys_addr_t phy_addr, u32 size);
int wcn_write_data_to_phy_addr(phys_addr_t phy_addr,
			       void *src_data, u32 size);
int wcn_read_data_from_phy_addr(phys_addr_t phy_addr,
				void *tar_data, u32 size);
void *wcn_mem_ram_vmap_nocache(phys_addr_t start, size_t size,
			       unsigned int *count);
void wcn_mem_ram_unmap(const void *mem, unsigned int count);

#endif
