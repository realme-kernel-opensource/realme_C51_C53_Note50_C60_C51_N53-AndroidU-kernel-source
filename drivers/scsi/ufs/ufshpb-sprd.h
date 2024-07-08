#ifndef _UFS_HPB_SPRD_H_
#define _UFS_HPB_SPRD_H_
#define UFS_VENDOR_HFCS 0xa6b
#define UFS_VENDOR_YMTC 0xa9b

#define UFSHCD_QUIRK_BROKEN_HPB_READ_CMD	0x70
struct ufs_cmd_trace {
	ktime_t start;//for 0x28 0xf8
};

#if  defined(CONFIG_SCSI_UFS_HPB) && defined(CONFIG_SPRD_DEBUG)
#define RECORD_CMD_NO_ADD_TO_TRACE 0x0
#define RECORD_CMD_NO_ADD_TO_TRACE_ALL 0x100
extern u32 ufshpb_follow;
extern int ufshpb_prep_disable_ufshpb;
extern u32 record_cmd[RECORD_CMD_NO_ADD_TO_TRACE_ALL];
extern void ufshcd_hpb_add_command_trace(struct ufs_hba *hba,
		unsigned int tag, const char *str);
extern u64 global_ufs_cmd_trace_single_0x28_count;
extern u64 global_ufs_cmd_trace_single_0xf8_count;
extern u64 global_ufs_cmd_trace_single_0x88_count;
extern u64 global_ufs_cmd_trace_single_0x28_all_start_to_end_us;
extern u64 global_ufs_cmd_trace_single_0xf8_all_start_to_end_us;
extern u64 global_ufs_cmd_trace_single_0x88_all_start_to_end_us;
extern u64 global_ufs_cmd_trace_single_0x28_ave_start_to_end_us;
extern u64 global_ufs_cmd_trace_single_0xf8_ave_start_to_end_us;
extern u64 global_ufs_cmd_trace_single_0x88_ave_start_to_end_us;
extern struct ufs_cmd_trace global_ufs_cmd_trace_single[32];
#endif

/*
 * Some UFS devices require using read_16 command for HPB data reading
 * instead of the HPB_READ command.
 */
#define UFS_DEVICE_QUIRK_CMD_READ16_REPLACE_HPB_READ	(1 << 12)

/*Some Micron chip HPB function is transitional*/
#define UFS_DEVICE_QUIRK_MICRON_HPB	(1 << 13)

/*
 * Some UFS devices require L2P entry should be swapped before being sent to the
 * UFS device for HPB READ command.
 */
#define UFS_DEVICE_QUIRK_SWAP_L2P_ENTRY_FOR_HPB_READ (1 << 14)

/*
 * Some UFS devices NO SUPPORT HPB READ command,When hardware crypto enable.
 */
#define UFS_DEVICE_QUIRK_NO_SUPPORT_HPB_READ_WHEN_HARDWARE_CRYPTO_ENABLE (1 << 15)

/*
 * Some UFS devices hardware crypto enable ,When SUPPORT HPB READ command.
 */
#define UFS_DEVICE_QUIRK_DISABLE_HARDWARE_CRYPTO_WHEN_SUPPORT_HPB_READ (1 << 16)


#define	QUERY_FLAG_IDN_HPB_RESET				0x11
#define	QUERY_FLAG_IDN_HPB_EN					0x12

#define	QUERY_ATTR_IDN_MAX_HPB_SINGLE_CMD		1

#define	UNIT_DESC_PARAM_HPB_LU_MAX_ACTIVE_RGNS	0x23
#define	UNIT_DESC_PARAM_HPB_PIN_RGN_START_OFF	0x25
#define	UNIT_DESC_PARAM_HPB_NUM_PIN_RGNS		0x27

#define	DEVICE_DESC_PARAM_HPB_VER				0x40
#define	DEVICE_DESC_PARAM_HPB_CONTROL			0x42

#define	GEOMETRY_DESC_PARAM_HPB_REGION_SIZE		0x48
#define	GEOMETRY_DESC_PARAM_HPB_NUMBER_LU		0x49
#define	GEOMETRY_DESC_PARAM_HPB_SUBREGION_SIZE	0x4A
#define	GEOMETRY_DESC_PARAM_HPB_MAX_ACTIVE_REGS	0x4B

#define	UFS_DEV_HPB_SUPPORT						BIT(7)
#define UFS_DEV_HPB_SUPPORT_VERSION				0x220
#define UTP_HPB_RSP_SIZE						40

#define HPB_ACT_FIELD_SIZE 						4


/**
 * struct ufshpb_dev_info - UFSHPB device related info
 * @num_lu: the number of user logical unit to check whether all lu finished
 *          initialization
 * @rgn_size: device reported HPB region size
 * @srgn_size: device reported HPB sub-region size
 * @slave_conf_cnt: counter to check all lu finished initialization
 * @hpb_disabled: flag to check if HPB is disabled
 * @max_hpb_single_cmd: device reported bMAX_DATA_SIZE_FOR_SINGLE_CMD value
 * @is_legacy: flag to check HPB 1.0
 * @control_mode: either host or device
 */
struct ufshpb_dev_info {
	int num_lu;
	int rgn_size;
	int srgn_size;
	atomic_t slave_conf_cnt;
	bool hpb_disabled;
	u8 max_hpb_single_cmd;
	bool is_legacy;
	u8 control_mode;
	bool hpb_enabled;
	u16 hpb_version;
};
#endif
