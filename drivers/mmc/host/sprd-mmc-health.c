/*
 * create in 2021/1/7.
 * create emmc node in  /proc/bootdevice
 */

#include <linux/mmc/sprd-mmc-health.h>
#include "../core/mmc_ops.h"
#define PROC_MODE 0444

struct __mmchealthdata mmchealthdata;

void set_mmchealth_data(u8 *data)
{
	memcpy(&mmchealthdata.buf[0], data, 512);
}

/**********************************************************/
static int sprd_health_data_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < 512; i++)
		seq_printf(m, "%02x", mmchealthdata.buf[i]);

	return 0;
}

static int sprd_health_data_open(struct inode *inode, struct file *file)
{
	return single_open(file, sprd_health_data_show, inode->i_private);
}

static const struct file_operations health_data_fops = {
	.open = sprd_health_data_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*********************  YMTC_EC110_eMMC  *****************************************/
//Factory bad block count
static int sprd_fbbc_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[0]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int fbbc_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_fbbc_show, inode->i_private);
}

static const struct file_operations fbbc_fops = {
	.open = fbbc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//TLC Reserved Block Num
static int sprd_trbn_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[4]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int trbn_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_trbn_show, inode->i_private);
}

static const struct file_operations trbn_fops = {
	.open = trbn_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//SLC Reserved Block Num
static int sprd_srbn_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[8]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int srbn_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_srbn_show, inode->i_private);
}

static const struct file_operations srbn_fops = {
	.open = srbn_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int YMTC_Run_time_bad_block_count_TLC_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[12]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int YMTC_Run_time_bad_block_count_TLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_Run_time_bad_block_count_TLC_show, inode->i_private);
}

static const struct file_operations YMTC_Run_time_bad_block_count_TLC_fops = {
    .open = YMTC_Run_time_bad_block_count_TLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

//Run time bad block count (erase fail)
static int sprd_rtbbcef_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[20]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int rtbbcef_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_rtbbcef_show, inode->i_private);
}

static const struct file_operations rtbbcef_fops = {
	.open = rtbbcef_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Run time bad block count (program fail)
static int sprd_rtbbcpf_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[24]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int rtbbcpf_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_rtbbcpf_show, inode->i_private);
}

static const struct file_operations rtbbcpf_fops = {
	.open = rtbbcpf_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Run time bad block count (read uecc)
static int sprd_rtbbcru_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[28]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int rtbbcru_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_rtbbcru_show, inode->i_private);
}

static const struct file_operations rtbbcru_fops = {
	.open = rtbbcru_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//UECC Count
static int sprd_uc_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[32]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int uc_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_uc_show, inode->i_private);
}

static const struct file_operations uc_fops = {
	.open = uc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Read reclaim SLC block count
static int sprd_rrsbc_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[44]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int rrsbc_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_rrsbc_show, inode->i_private);
}

static const struct file_operations rrsbc_fops = {
	.open = rrsbc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Read reclaim TLC block count
static int sprd_rrtbc_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[48]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int rrtbc_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_rrtbc_show, inode->i_private);
}

static const struct file_operations rrtbc_fops = {
	.open = rrtbc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//VDT drop count
static int sprd_vdc_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[52]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int vdc_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_vdc_show, inode->i_private);
}

static const struct file_operations vdc_fops = {
	.open = vdc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Sudden power off recovery success count
static int sprd_sporsc_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[64]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sporsc_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_sporsc_show, inode->i_private);
}

static const struct file_operations sporsc_fops = {
	.open = sporsc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Sudden power off recovery fail count
static int sprd_sporfc_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[68]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sporfc_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_sporfc_show, inode->i_private);
}

static const struct file_operations sporfc_fops = {
	.open = sporfc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Min_EC_Num_SLC (EC: erase count)
static int sprd_minens_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[92]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int minens_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_minens_show, inode->i_private);
}

static const struct file_operations minens_fops = {
	.open = minens_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Max_EC_Num_SLC
static int sprd_maxens_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[96]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int maxens_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_maxens_show, inode->i_private);
}

static const struct file_operations maxens_fops = {
	.open = maxens_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Ave_EC_Num_SLC
static int sprd_aens_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[100]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int aens_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_aens_show, inode->i_private);
}

static const struct file_operations aens_fops = {
	.open = aens_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Min_EC_Num_TLC
static int sprd_minent_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[104]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int minent_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_minent_show, inode->i_private);
}

static const struct file_operations minent_fops = {
	.open = minent_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Max_EC_Num_TLC
static int sprd_maxent_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[108]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int maxent_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_maxent_show, inode->i_private);
}

static const struct file_operations maxent_fops = {
	.open = maxent_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Ave_EC_Num_TLC
static int sprd_aent_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[112]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int aent_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_aent_show, inode->i_private);
}

static const struct file_operations aent_fops = {
	.open = aent_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total byte read(MB)
static int sprd_tbr_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[116]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int tbr_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_tbr_show, inode->i_private);
}

static const struct file_operations tbr_fops = {
	.open = tbr_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total byte write(MB)
static int sprd_tbw_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[120]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int tbw_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_tbw_show, inode->i_private);
}

static const struct file_operations tbw_fops = {
	.open = tbw_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total initialization count
static int sprd_tic_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[124]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int tic_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_tic_show, inode->i_private);
}

static const struct file_operations tic_fops = {
	.open = tic_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//SLC used life
static int sprd_sul_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[176]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sul_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_sul_show, inode->i_private);
}

static const struct file_operations sul_fops = {
	.open = sul_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//TLC used life
static int sprd_tul_show(struct seq_file *m, void *v)
{
	u32 temp = *((u32 *)(&mmchealthdata.buf[180]));

	temp = be32_to_cpu(temp);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int tul_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_tul_show, inode->i_private);
}

static const struct file_operations tul_fops = {
	.open = tul_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int YMTC_FFU_fail_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[188]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int YMTC_FFU_fail_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_FFU_fail_count_show, inode->i_private);
}

static const struct file_operations YMTC_FFU_fail_count_fops = {
    .open = YMTC_FFU_fail_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/**********************************************/
static const struct file_operations *proc_fops_list1[] = {
	&fbbc_fops,
	&trbn_fops,
	&srbn_fops,
	&YMTC_Run_time_bad_block_count_TLC_fops,
	&rtbbcef_fops,
	&rtbbcpf_fops,
	&rtbbcru_fops,
	&uc_fops,
	&rrsbc_fops,
	&rrtbc_fops,
	&vdc_fops,
	&sporsc_fops,
	&sporfc_fops,
	&minens_fops,
	&maxens_fops,
	&aens_fops,
	&minent_fops,
	&maxent_fops,
	&aent_fops,
	&tbr_fops,
	&tbw_fops,
	&tic_fops,
	&sul_fops,
	&tul_fops,
	&YMTC_FFU_fail_count_fops,
	&health_data_fops,
};

static char * const sprd_emmc_node_info1[] = {
	"Factory_bad_block_count",
	"TLC_Reserved_Block_Num",
	"SLC_Reserved_Block_Num",
	"Run_time_bad_block_count_TLC",
	"Run_time_bad_block_count(erase_fail)",
	"Run_time_bad_block_count(program_fail)",
	"Run_time_bad_block_count(read_UECC)",
	"UECC_Count",
	"Read_reclaim_SLC_block_count",
	"Read_reclaim_TLC_block_count",
	"VDT_drop_count",
	"Sudden_power_off_recovery_success_count",
	"Sudden_power_off_recovery_fail_count",
	"Min_EC_Num_SLC",
	"Max_EC_Num_SLC",
	"Ave_EC_Num_SLC",
	"Min_EC_Num_TLC",
	"Max_EC_Num_TLC",
	"Ave_EC_Num_TLC",
	"Total_byte_read(MB)",
	"Total_byte_write(MB)",
	"Total_initialization_count",
	"SLC_used_life",
	"TLC_used_life",
	"FFU_fail_count",
	"health_data",
};

/***************** YMTC ********************/
int sprd_create_mmc_health_init1(void)
{
	struct proc_dir_entry *mmchealthdir;
	struct proc_dir_entry *prEntry;
	int i, node;

	mmchealthdir = proc_mkdir("mmchealth", NULL);
	if (!mmchealthdir) {
		pr_err("%s: failed to create /proc/mmchealth\n",
			__func__);
		return -1;
	}

	node = ARRAY_SIZE(sprd_emmc_node_info1);
	for (i = 0; i < node; i++) {
		prEntry = proc_create(sprd_emmc_node_info1[i], PROC_MODE,
				      mmchealthdir, proc_fops_list1[i]);
		if (!prEntry) {
			pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
				__func__, sprd_emmc_node_info1[i]);
			return -1;
		}
	}

	return 0;
}

/***************** HFCS 32G   ********************/
//Factory bad block count
static int sprd_factory_bad_block_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[0] << 8) & 0xff00) |
			(mmchealthdata.buf[1] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_factory_bad_block_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_factory_bad_block_count_show, inode->i_private);
}

static const struct file_operations factory_bad_block_count_fops = {
	.open = sprd_factory_bad_block_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Run time bad block count
static int sprd_Run_time_bad_block_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[2] << 8) & 0xff00) |
			(mmchealthdata.buf[3] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Run_time_bad_block_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Run_time_bad_block_count_show, inode->i_private);
}

static const struct file_operations Run_time_bad_block_count_fops = {
	.open = sprd_Run_time_bad_block_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Min_EC_Num_TLC
static int sprd_Min_EC_Num_TLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[16] << 24) & 0xff000000) |
			((mmchealthdata.buf[17] << 16) & 0xff0000) |
			((mmchealthdata.buf[18] << 8) & 0xff00) |
			(mmchealthdata.buf[19] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Min_EC_Num_TLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Min_EC_Num_TLC_show, inode->i_private);
}

static const struct file_operations Min_EC_Num_TLC_fops = {
	.open = sprd_Min_EC_Num_TLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Max_EC_Num_TLC
static int sprd_Max_EC_Num_TLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[20] << 24) & 0xff000000) |
			((mmchealthdata.buf[21] << 16) & 0xff0000) |
			((mmchealthdata.buf[22] << 8) & 0xff00) |
			(mmchealthdata.buf[23] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Max_EC_Num_TLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Max_EC_Num_TLC_show, inode->i_private);
}

static const struct file_operations Max_EC_Num_TLC_fops = {
	.open = sprd_Max_EC_Num_TLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Ave_EC_Num_TLC
static int sprd_Ave_EC_Num_TLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[24] << 24) & 0xff000000) |
			((mmchealthdata.buf[25] << 16) & 0xff0000) |
			((mmchealthdata.buf[26] << 8) & 0xff00) |
			(mmchealthdata.buf[27] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Ave_EC_Num_TLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Ave_EC_Num_TLC_show, inode->i_private);
}

static const struct file_operations Ave_EC_Num_TLC_fops = {
	.open = sprd_Ave_EC_Num_TLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total_EC_Num_TLC
static int sprd_Total_EC_Num_TLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[28] << 24) & 0xff000000) |
			((mmchealthdata.buf[29] << 16) & 0xff0000) |
			((mmchealthdata.buf[30] << 8) & 0xff00) |
			(mmchealthdata.buf[31] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Total_EC_Num_TLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Total_EC_Num_TLC_show, inode->i_private);
}

static const struct file_operations Total_EC_Num_TLC_fops = {
	.open = sprd_Total_EC_Num_TLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Min_EC_Num_SLC
static int sprd_Min_EC_Num_SLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[32] << 24) & 0xff000000) |
			((mmchealthdata.buf[33] << 16) & 0xff0000) |
			((mmchealthdata.buf[34] << 8) & 0xff00) |
			(mmchealthdata.buf[35] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Min_EC_Num_SLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Min_EC_Num_SLC_show, inode->i_private);
}

static const struct file_operations Min_EC_Num_SLC_fops = {
	.open = sprd_Min_EC_Num_SLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Max_EC_Num_SLC
static int sprd_Max_EC_Num_SLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[36] << 24) & 0xff000000) |
			((mmchealthdata.buf[37] << 16) & 0xff0000) |
			((mmchealthdata.buf[38] << 8) & 0xff00) |
			(mmchealthdata.buf[39] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Max_EC_Num_SLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Max_EC_Num_SLC_show, inode->i_private);
}

static const struct file_operations Max_EC_Num_SLC_fops = {
	.open = sprd_Max_EC_Num_SLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Ave_EC_Num_SLC
static int sprd_Ave_EC_Num_SLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[40] << 24) & 0xff000000) |
			((mmchealthdata.buf[41] << 16) & 0xff0000) |
			((mmchealthdata.buf[42] << 8) & 0xff00) |
			(mmchealthdata.buf[43] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Ave_EC_Num_SLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Ave_EC_Num_SLC_show, inode->i_private);
}

static const struct file_operations Ave_EC_Num_SLC_fops = {
	.open = sprd_Ave_EC_Num_SLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total_EC_Num_SLC
static int sprd_Total_EC_Num_SLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[44] << 24) & 0xff000000) |
			((mmchealthdata.buf[45] << 16) & 0xff0000) |
			((mmchealthdata.buf[46] << 8) & 0xff00) |
			(mmchealthdata.buf[47] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Total_EC_Num_SLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Total_EC_Num_SLC_show, inode->i_private);
}

static const struct file_operations Total_EC_Num_SLC_fops = {
	.open = sprd_Total_EC_Num_SLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total_initialization_count
static int sprd_Total_initialization_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[83] << 24) & 0xff000000) |
			((mmchealthdata.buf[82] << 16) & 0xff0000) |
			((mmchealthdata.buf[81] << 8) & 0xff00) |
			(mmchealthdata.buf[80] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Total_initialization_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Total_initialization_count_show, inode->i_private);
}

static const struct file_operations Total_initialization_count_fops = {
	.open = sprd_Total_initialization_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total_write_size(MB)/100
static int sprd_Total_write_size_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[103] << 24) & 0xff000000) |
			((mmchealthdata.buf[102] << 16) & 0xff0000) |
			((mmchealthdata.buf[101] << 8) & 0xff00) |
			(mmchealthdata.buf[100] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Total_write_size_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Total_write_size_show, inode->i_private);
}

static const struct file_operations Total_write_size_fops = {
	.open = sprd_Total_write_size_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//FFU successful count
static int sprd_FFU_successful_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[119] << 8) & 0xff00) |
			(mmchealthdata.buf[118] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_FFU_successful_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_FFU_successful_count_show, inode->i_private);
}

static const struct file_operations FFU_successful_count_fops = {
	.open = sprd_FFU_successful_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Power loss count
static int sprd_Power_loss_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[195] << 24) & 0xff000000) |
			((mmchealthdata.buf[194] << 16) & 0xff0000) |
			((mmchealthdata.buf[193] << 8) & 0xff00) |
			(mmchealthdata.buf[192] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Power_loss_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Power_loss_count_show, inode->i_private);
}

static const struct file_operations Power_loss_count_fops = {
	.open = sprd_Power_loss_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total CE count
static int sprd_Total_CE_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[257] << 8) & 0xff00) |
			(mmchealthdata.buf[256] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Total_CE_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Total_CE_count_show, inode->i_private);
}

static const struct file_operations Total_CE_count_fops = {
	.open = sprd_Total_CE_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Plane count per CE
static int sprd_Plane_count_per_CE_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[259] << 8) & 0xff00) |
			(mmchealthdata.buf[258] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Plane_count_per_CE_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Plane_count_per_CE_show, inode->i_private);
}

static const struct file_operations Plane_count_per_CE_fops = {
	.open = sprd_Plane_count_per_CE_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//CEO plane0 total bad block count
static int sprd_plane0_total_bad_block_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[272] << 8) & 0xff00) |
			(mmchealthdata.buf[273] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_plane0_total_bad_block_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_plane0_total_bad_block_count_show, inode->i_private);
}

static const struct file_operations plane0_total_bad_block_count_fops = {
	.open = sprd_plane0_total_bad_block_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//CEO plane1 total bad block count
static int sprd_plane1_total_bad_block_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[274] << 8) & 0xff00) |
			(mmchealthdata.buf[275] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_plane1_total_bad_block_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_plane1_total_bad_block_count_show, inode->i_private);
}

static const struct file_operations plane1_total_bad_block_count_fops = {
	.open = sprd_plane1_total_bad_block_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total read size(MB)/100
static int sprd_Total_read_size_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[395] << 24) & 0xff000000) |
			((mmchealthdata.buf[394] << 16) & 0xff0000) |
			((mmchealthdata.buf[393] << 8) & 0xff00) |
			(mmchealthdata.buf[392] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Total_read_size_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Total_read_size_show, inode->i_private);
}

static const struct file_operations Total_read_size_fops = {
	.open = sprd_Total_read_size_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
/*****************************************************************/
static const struct file_operations *proc_fops_list2[] = {
	&health_data_fops,
    &factory_bad_block_count_fops,
    &Run_time_bad_block_count_fops,
    &Min_EC_Num_TLC_fops,
    &Max_EC_Num_TLC_fops,
    &Ave_EC_Num_TLC_fops,
    &Total_EC_Num_TLC_fops,
    &Min_EC_Num_SLC_fops,
    &Max_EC_Num_SLC_fops,
    &Ave_EC_Num_SLC_fops,
    &Total_EC_Num_SLC_fops,
    &Total_initialization_count_fops,
    &Total_write_size_fops,
    &FFU_successful_count_fops,
    &Power_loss_count_fops,
    &Total_CE_count_fops,
    &Plane_count_per_CE_fops,
    &plane0_total_bad_block_count_fops,
    &plane1_total_bad_block_count_fops,
    &Total_read_size_fops,
};

static char * const sprd_emmc_node_info2[] = {
	"health_data",
	"factory_bad_block_count",
    "Run_time_bad_block_count",
    "Min_EC_Num_TLC",
    "Max_EC_Num_TLC",
    "Ave_EC_Num_TLC",
    "Total_EC_Num_TLC",
    "Min_EC_Num_SLC",
    "Max_EC_Num_SLC",
    "Ave_EC_Num_SLC",
    "Total_EC_Num_SLC",
    "Total_initialization_count",
    "Total_write_size",
    "FFU_successful_count",
    "Power_loss_count",
    "Total_CE_count",
    "Plane_count_per_CE",
    "plane0_total_bad_block_count",
    "plane1_total_bad_block_count",
    "Total_read_size",
};

int sprd_create_mmc_health_init2(void)
{
	struct proc_dir_entry *mmchealthdir;
	struct proc_dir_entry *prEntry;
	int i, node;

	mmchealthdir = proc_mkdir("mmchealth", NULL);
	if (!mmchealthdir) {
		pr_err("%s: failed to create /proc/mmchealth\n",
			__func__);
		return -1;
	}

	node = ARRAY_SIZE(sprd_emmc_node_info2);
	for (i = 0; i < node; i++) {
		prEntry = proc_create(sprd_emmc_node_info2[i], PROC_MODE,
				      mmchealthdir, proc_fops_list2[i]);
		if (!prEntry) {
			pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
				__func__, sprd_emmc_node_info2[i]);
			return -1;
		}
	}

	return 0;
}

/*********************** HFCS 64G  ***********************************/
//FBB factory bad block
static int sprd_FBB_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[0] << 24) & 0xff000000) |
			((mmchealthdata.buf[1] << 16) & 0xff0000) |
			((mmchealthdata.buf[2] << 8) & 0xff00) |
			(mmchealthdata.buf[3] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_FBB_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_FBB_show, inode->i_private);
}

static const struct file_operations FBB_fops = {
	.open = sprd_FBB_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//RTBB_TLC
static int sprd_RTBB_TLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[12] << 24) & 0xff000000) |
			((mmchealthdata.buf[13] << 16) & 0xff0000) |
			((mmchealthdata.buf[14] << 8) & 0xff00) |
			(mmchealthdata.buf[15] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_RTBB_TLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_RTBB_TLC_show, inode->i_private);
}

static const struct file_operations RTBB_TLC_fops = {
	.open = sprd_RTBB_TLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//RTBB_SLC
static int sprd_RTBB_SLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[16] << 24) & 0xff000000) |
			((mmchealthdata.buf[17] << 16) & 0xff0000) |
			((mmchealthdata.buf[18] << 8) & 0xff00) |
			(mmchealthdata.buf[19] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_RTBB_SLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_RTBB_SLC_show, inode->i_private);
}

static const struct file_operations RTBB_SLC_fops = {
	.open = sprd_RTBB_SLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//RTBB_ESF(Erase status fail)
static int sprd_RTBB_ESF_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[20] << 24) & 0xff000000) |
			((mmchealthdata.buf[21] << 16) & 0xff0000) |
			((mmchealthdata.buf[22] << 8) & 0xff00) |
			(mmchealthdata.buf[23] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_RTBB_ESF_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_RTBB_ESF_show, inode->i_private);
}

static const struct file_operations RTBB_ESF_fops = {
	.open = sprd_RTBB_ESF_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//RTBB_PSF(Program status fail)
static int sprd_RTBB_PSF_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[24] << 24) & 0xff000000) |
			((mmchealthdata.buf[25] << 16) & 0xff0000) |
			((mmchealthdata.buf[26] << 8) & 0xff00) |
			(mmchealthdata.buf[27] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_RTBB_PSF_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_RTBB_PSF_show, inode->i_private);
}

static const struct file_operations RTBB_PSF_fops = {
	.open = sprd_RTBB_PSF_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//RTBB_UECC(Read UECC)
static int sprd_RTBB_UECC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[28] << 24) & 0xff000000) |
			((mmchealthdata.buf[29] << 16) & 0xff0000) |
			((mmchealthdata.buf[30] << 8) & 0xff00) |
			(mmchealthdata.buf[31] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_RTBB_UECC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_RTBB_UECC_show, inode->i_private);
}

static const struct file_operations RTBB_UECC_fops = {
	.open = sprd_RTBB_UECC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//Min_EC_Num_SLC_64G
static int sprd_Min_EC_Num_SLC_64G_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[92] << 24) & 0xff000000) |
			((mmchealthdata.buf[93] << 16) & 0xff0000) |
			((mmchealthdata.buf[94] << 8) & 0xff00) |
			(mmchealthdata.buf[95] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Min_EC_Num_SLC_64G_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Min_EC_Num_SLC_64G_show, inode->i_private);
}

static const struct file_operations Min_EC_Num_SLC_64G_fops = {
	.open = sprd_Min_EC_Num_SLC_64G_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//Max_EC_Num_SLC_64G
static int sprd_Max_EC_Num_SLC_64G_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[96] << 24) & 0xff000000) |
			((mmchealthdata.buf[97] << 16) & 0xff0000) |
			((mmchealthdata.buf[98] << 8) & 0xff00) |
			(mmchealthdata.buf[99] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Max_EC_Num_SLC_64G_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Max_EC_Num_SLC_64G_show, inode->i_private);
}

static const struct file_operations Max_EC_Num_SLC_64G_fops = {
	.open = sprd_Max_EC_Num_SLC_64G_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//Ave_EC_Num_SLC_64G
static int sprd_Ave_EC_Num_SLC_64G_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[100] << 24) & 0xff000000) |
			((mmchealthdata.buf[101] << 16) & 0xff0000) |
			((mmchealthdata.buf[102] << 8) & 0xff00) |
			(mmchealthdata.buf[103] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Ave_EC_Num_SLC_64G_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Ave_EC_Num_SLC_64G_show, inode->i_private);
}

static const struct file_operations Ave_EC_Num_SLC_64G_fops = {
	.open = sprd_Ave_EC_Num_SLC_64G_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//Min_EC_Num_TLC_64G
static int sprd_Min_EC_Num_TLC_64G_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[104] << 24) & 0xff000000) |
			((mmchealthdata.buf[105] << 16) & 0xff0000) |
			((mmchealthdata.buf[106] << 8) & 0xff00) |
			(mmchealthdata.buf[107] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Min_EC_Num_TLC_64G_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Min_EC_Num_TLC_64G_show, inode->i_private);
}

static const struct file_operations Min_EC_Num_TLC_64G_fops = {
	.open = sprd_Min_EC_Num_TLC_64G_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//Max_EC_Num_TLC_64G
static int sprd_Max_EC_Num_TLC_64G_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[108] << 24) & 0xff000000) |
			((mmchealthdata.buf[109] << 16) & 0xff0000) |
			((mmchealthdata.buf[110] << 8) & 0xff00) |
			(mmchealthdata.buf[111] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Max_EC_Num_TLC_64G_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Max_EC_Num_TLC_64G_show, inode->i_private);
}

static const struct file_operations Max_EC_Num_TLC_64G_fops = {
	.open = sprd_Max_EC_Num_TLC_64G_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//Ave_EC_Num_TLC_64G
static int sprd_Ave_EC_Num_TLC_64G_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[112] << 24) & 0xff000000) |
			((mmchealthdata.buf[113] << 16) & 0xff0000) |
			((mmchealthdata.buf[114] << 8) & 0xff00) |
			(mmchealthdata.buf[115] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Ave_EC_Num_TLC_64G_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Ave_EC_Num_TLC_64G_show, inode->i_private);
}

static const struct file_operations Ave_EC_Num_TLC_64G_fops = {
	.open = sprd_Ave_EC_Num_TLC_64G_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//Cumulative_Host_Read_64G
static int sprd_Cumulative_Host_Read_64G_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[116] << 24) & 0xff000000) |
			((mmchealthdata.buf[117] << 16) & 0xff0000) |
			((mmchealthdata.buf[118] << 8) & 0xff00) |
			(mmchealthdata.buf[119] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Cumulative_Host_Read_64G_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Cumulative_Host_Read_64G_show, inode->i_private);
}

static const struct file_operations Cumulative_Host_Read_64G_fops = {
	.open = sprd_Cumulative_Host_Read_64G_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
//Cumulative_Host_Write_64G
static int sprd_Cumulative_Host_Write_64G_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[120] << 24) & 0xff000000) |
			((mmchealthdata.buf[121] << 16) & 0xff0000) |
			((mmchealthdata.buf[122] << 8) & 0xff00) |
			(mmchealthdata.buf[123] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_Cumulative_Host_Write_64G_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_Cumulative_Host_Write_64G_show, inode->i_private);
}

static const struct file_operations Cumulative_Host_Write_64G_fops = {
	.open = sprd_Cumulative_Host_Write_64G_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
/*****************************************************************/
static const struct file_operations *proc_fops_list3[] = {
	&health_data_fops,
	&FBB_fops,
	&RTBB_TLC_fops,
	&RTBB_SLC_fops,
	&RTBB_ESF_fops,
	&RTBB_PSF_fops,
	&RTBB_UECC_fops,
	&Min_EC_Num_SLC_64G_fops,
	&Max_EC_Num_SLC_64G_fops,
	&Ave_EC_Num_SLC_64G_fops,
	&Min_EC_Num_TLC_64G_fops,
	&Max_EC_Num_TLC_64G_fops,
	&Ave_EC_Num_TLC_64G_fops,
	&Cumulative_Host_Read_64G_fops,
	&Cumulative_Host_Write_64G_fops,
};

static char * const sprd_emmc_node_info3[] = {
	"health_data",
	"factory_bad_block",
    "Run_time_bad_block_TLC",
	"Run_time_bad_block_SLC",
	"Run_time_bad_block_ESF",
	"Run_time_bad_block_PSF",
	"Run_time_bad_block_UECC",
    "Min_EC_Num_SLC",
    "Max_EC_Num_SLC",
    "Ave_EC_Num_SLC",
    "Min_EC_Num_TLC",
    "Max_EC_Num_TLC",
    "Ave_EC_Num_TLC",
    "Cumulative_Host_Read",
	"Cumulative_Host_Write",
};

int sprd_create_mmc_health_init3(void)
{
	struct proc_dir_entry *mmchealthdir;
	struct proc_dir_entry *prEntry;
	int i, node;

	mmchealthdir = proc_mkdir("mmchealth", NULL);
	if (!mmchealthdir) {
		pr_err("%s: failed to create /proc/mmchealth\n",
			__func__);
		return -1;
	}

	node = ARRAY_SIZE(sprd_emmc_node_info3);
	for (i = 0; i < node; i++) {
		prEntry = proc_create(sprd_emmc_node_info3[i], PROC_MODE,
				      mmchealthdir, proc_fops_list3[i]);
		if (!prEntry) {
			pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
				__func__, sprd_emmc_node_info3[i]);
			return -1;
		}
	}

	return 0;
}

/*****************Western-Digital-iNAND**************/
//Average Erase Cycles Type A(SLC)
static int sprd_average_erase_cycles_typeA_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[7] << 24) & 0xff000000) |
			((mmchealthdata.buf[6] << 16) & 0xff0000) |
			((mmchealthdata.buf[5] << 8) & 0xff00) |
			(mmchealthdata.buf[4] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_average_erase_cycles_typeA_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_average_erase_cycles_typeA_show, inode->i_private);
}

static const struct file_operations average_erase_cycles_typeA_fops = {
	.open = sprd_average_erase_cycles_typeA_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Average Erase Cycles Type B(TLC)
static int sprd_average_erase_cycles_typeB_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[11] << 24) & 0xff000000) |
			((mmchealthdata.buf[10] << 16) & 0xff0000) |
			((mmchealthdata.buf[9] << 8) & 0xff00) |
			(mmchealthdata.buf[8] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_average_erase_cycles_typeB_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_average_erase_cycles_typeB_show, inode->i_private);
}

static const struct file_operations average_erase_cycles_typeB_fops = {
	.open = sprd_average_erase_cycles_typeB_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Read reclaim count Type A (SLC)
static int sprd_read_reclaim_count_typeA_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[19] << 24) & 0xff000000) |
			((mmchealthdata.buf[18] << 16) & 0xff0000) |
			((mmchealthdata.buf[17] << 8) & 0xff00) |
			(mmchealthdata.buf[16] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_read_reclaim_count_typeA_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_read_reclaim_count_typeA_show, inode->i_private);
}

static const struct file_operations read_reclaim_count_typeA_fops = {
	.open = sprd_read_reclaim_count_typeA_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Read reclaim count Type B (TLC)
static int sprd_read_reclaim_count_typeB_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[23] << 24) & 0xff000000) |
			((mmchealthdata.buf[22] << 16) & 0xff0000) |
			((mmchealthdata.buf[21] << 8) & 0xff00) |
			(mmchealthdata.buf[20] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_read_reclaim_count_typeB_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_read_reclaim_count_typeB_show, inode->i_private);
}

static const struct file_operations read_reclaim_count_typeB_fops = {
	.open = sprd_read_reclaim_count_typeB_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Bad Block Manufactory
static int sprd_bad_block_manufactory_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[27] << 24) & 0xff000000) |
			((mmchealthdata.buf[26] << 16) & 0xff0000) |
			((mmchealthdata.buf[25] << 8) & 0xff00) |
			(mmchealthdata.buf[24] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_bad_block_manufactory_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_bad_block_manufactory_show, inode->i_private);
}

static const struct file_operations bad_block_manufactory_fops = {
	.open = sprd_bad_block_manufactory_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Bad Block Runtime Type A (SLC)
static int sprd_bad_block_runtime_typeA_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[35] << 24) & 0xff000000) |
			((mmchealthdata.buf[34] << 16) & 0xff0000) |
			((mmchealthdata.buf[33] << 8) & 0xff00) |
			(mmchealthdata.buf[32] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_bad_block_runtime_typeA_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_bad_block_runtime_typeA_show, inode->i_private);
}

static const struct file_operations bad_block_runtime_typeA_fops = {
	.open = sprd_bad_block_runtime_typeA_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Bad Block Runtime Type B(TLC)
static int sprd_bad_block_runtime_typeB_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[39] << 24) & 0xff000000) |
			((mmchealthdata.buf[38] << 16) & 0xff0000) |
			((mmchealthdata.buf[37] << 8) & 0xff00) |
			(mmchealthdata.buf[36] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_bad_block_runtime_typeB_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_bad_block_runtime_typeB_show, inode->i_private);
}

static const struct file_operations bad_block_runtime_typeB_fops = {
	.open = sprd_bad_block_runtime_typeB_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Field FW Updates Count
static int sprd_field_fw_updates_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[43] << 24) & 0xff000000) |
			((mmchealthdata.buf[42] << 16) & 0xff0000) |
			((mmchealthdata.buf[41] << 8) & 0xff00) |
			(mmchealthdata.buf[40] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_field_fw_updates_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_field_fw_updates_count_show, inode->i_private);
}

static const struct file_operations field_fw_updates_count_fops = {
	.open = sprd_field_fw_updates_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//FW Release date
static int sprd_fw_release_date_show(struct seq_file *m, void *v)
{
	u32 temp1 = ((mmchealthdata.buf[47] << 24) & 0xff000000) |
			((mmchealthdata.buf[46] << 16) & 0xff0000) |
			((mmchealthdata.buf[45] << 8) & 0xff00) |
			(mmchealthdata.buf[44] & 0xff);

	u32 temp2 = ((mmchealthdata.buf[51] << 24) & 0xff000000) |
			((mmchealthdata.buf[50] << 16) & 0xff0000) |
			((mmchealthdata.buf[49] << 8) & 0xff00) |
			(mmchealthdata.buf[48] & 0xff);

	u32 temp3 = ((mmchealthdata.buf[55] << 24) & 0xff000000) |
			((mmchealthdata.buf[54] << 16) & 0xff0000) |
			((mmchealthdata.buf[53] << 8) & 0xff00) |
			(mmchealthdata.buf[52] & 0xff);

	seq_printf(m, "0x%x%x%x\n", temp3, temp2, temp1);

	return 0;
}

static int sprd_fw_release_date_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_fw_release_date_show, inode->i_private);
}

static const struct file_operations fw_release_date_fops = {
	.open = sprd_fw_release_date_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//FW Release Time
static int sprd_fw_release_time_show(struct seq_file *m, void *v)
{
	u32 temp1 = ((mmchealthdata.buf[59] << 24) & 0xff000000) |
			((mmchealthdata.buf[58] << 16) & 0xff0000) |
			((mmchealthdata.buf[57] << 8) & 0xff00) |
			(mmchealthdata.buf[56] & 0xff);

	u32 temp2 = ((mmchealthdata.buf[63] << 24) & 0xff000000) |
			((mmchealthdata.buf[62] << 16) & 0xff0000) |
			((mmchealthdata.buf[61] << 8) & 0xff00) |
			(mmchealthdata.buf[60] & 0xff);

	seq_printf(m, "0x%x%x\n", temp2, temp1);

	return 0;
}

static int sprd_fw_release_time_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_fw_release_time_show, inode->i_private);
}

static const struct file_operations fw_release_time_fops = {
	.open = sprd_fw_release_time_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Cumulative Host Write data size
static int sprd_cumulative_host_write_data_size_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[67] << 24) & 0xff000000) |
			((mmchealthdata.buf[66] << 16) & 0xff0000) |
			((mmchealthdata.buf[65] << 8) & 0xff00) |
			(mmchealthdata.buf[64] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_cumulative_host_write_data_size_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_cumulative_host_write_data_size_show, inode->i_private);
}

static const struct file_operations cumulative_host_write_data_size_fops = {
	.open = sprd_cumulative_host_write_data_size_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Number Vcc Voltage Drops Occurrences
static int sprd_number_vcc_voltage_drops_occurrences_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[71] << 24) & 0xff000000) |
			((mmchealthdata.buf[70] << 16) & 0xff0000) |
			((mmchealthdata.buf[69] << 8) & 0xff00) |
			(mmchealthdata.buf[68] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_number_vcc_voltage_drops_occurrences_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_number_vcc_voltage_drops_occurrences_show, inode->i_private);
}

static const struct file_operations number_vcc_voltage_drops_occurrences_fops = {
	.open = sprd_number_vcc_voltage_drops_occurrences_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Number Vcc Voltage Droops Occurrences
static int sprd_number_vcc_voltage_droops_occurrences_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[75] << 24) & 0xff000000) |
			((mmchealthdata.buf[74] << 16) & 0xff0000) |
			((mmchealthdata.buf[73] << 8) & 0xff00) |
			(mmchealthdata.buf[72] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_number_vcc_voltage_droops_occurrences_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_number_vcc_voltage_droops_occurrences_show, inode->i_private);
}

static const struct file_operations number_vcc_voltage_droops_occurrences_fops = {
	.open = sprd_number_vcc_voltage_droops_occurrences_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Number of failures recover new host data(After Write Abort)
static int sprd_number_of_failures_recover_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[79] << 24) & 0xff000000) |
			((mmchealthdata.buf[78] << 16) & 0xff0000) |
			((mmchealthdata.buf[77] << 8) & 0xff00) |
			(mmchealthdata.buf[76] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_number_of_failures_recover_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_number_of_failures_recover_show, inode->i_private);
}

static const struct file_operations number_of_failures_recover_fops = {
	.open = sprd_number_of_failures_recover_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Total Recovery Operation After VDET
static int sprd_total_recovery_operation_after_vdet_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[83] << 24) & 0xff000000) |
			((mmchealthdata.buf[82] << 16) & 0xff0000) |
			((mmchealthdata.buf[81] << 8) & 0xff00) |
			(mmchealthdata.buf[80] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_total_recovery_operation_after_vdet_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_total_recovery_operation_after_vdet_show, inode->i_private);
}

static const struct file_operations total_recovery_operation_after_vdet_fops = {
	.open = sprd_total_recovery_operation_after_vdet_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Cumulative SmartSLC write payload
static int sprd_cumulative_smartslc_write_payload_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[87] << 24) & 0xff000000) |
			((mmchealthdata.buf[86] << 16) & 0xff0000) |
			((mmchealthdata.buf[85] << 8) & 0xff00) |
			(mmchealthdata.buf[84] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_cumulative_smartslc_write_payload_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_cumulative_smartslc_write_payload_show, inode->i_private);
}

static const struct file_operations cumulative_smartslc_write_payload_fops = {
	.open = sprd_cumulative_smartslc_write_payload_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Cumulative SmartSLC Bigfile mode write payload
static int sprd_cumulative_smartslc_bigfile_mode_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[91] << 24) & 0xff000000) |
			((mmchealthdata.buf[90] << 16) & 0xff0000) |
			((mmchealthdata.buf[89] << 8) & 0xff00) |
			(mmchealthdata.buf[88] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_cumulative_smartslc_bigfile_mode_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_cumulative_smartslc_bigfile_mode_show, inode->i_private);
}

static const struct file_operations cumulative_smartslc_bigfile_mode_fops = {
	.open = sprd_cumulative_smartslc_bigfile_mode_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Number of times SmartSLC BigFile mode was operated during device lifetime
static int sprd_number_of_times_smartSLC_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[95] << 24) & 0xff000000) |
			((mmchealthdata.buf[94] << 16) & 0xff0000) |
			((mmchealthdata.buf[93] << 8) & 0xff00) |
			(mmchealthdata.buf[92] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_number_of_times_smartSLC_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_number_of_times_smartSLC_show, inode->i_private);
}

static const struct file_operations number_of_times_smartSLC_fops = {
	.open = sprd_number_of_times_smartSLC_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Average Erase Cycles of SmartSLC Bigfile mode
static int sprd_average_erase_cycles_of_smartslc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[99] << 24) & 0xff000000) |
			((mmchealthdata.buf[98] << 16) & 0xff0000) |
			((mmchealthdata.buf[97] << 8) & 0xff00) |
			(mmchealthdata.buf[96] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_average_erase_cycles_of_smartslc_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_average_erase_cycles_of_smartslc_show, inode->i_private);
}

static const struct file_operations average_erase_cycles_of_smartslc_fops = {
	.open = sprd_average_erase_cycles_of_smartslc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Cumulative initialization count
static int sprd_cumulative_initialization_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[103] << 24) & 0xff000000) |
			((mmchealthdata.buf[102] << 16) & 0xff0000) |
			((mmchealthdata.buf[101] << 8) & 0xff00) |
			(mmchealthdata.buf[100] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_cumulative_initialization_count_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_cumulative_initialization_count_show, inode->i_private);
}

static const struct file_operations cumulative_initialization_count_fops = {
	.open = sprd_cumulative_initialization_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Max Erase Cycles Type A (SLC)
static int sprd_max_erase_cycles_typeA_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[111] << 24) & 0xff000000) |
			((mmchealthdata.buf[110] << 16) & 0xff0000) |
			((mmchealthdata.buf[109] << 8) & 0xff00) |
			(mmchealthdata.buf[108] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_max_erase_cycles_typeA_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_max_erase_cycles_typeA_show, inode->i_private);
}

static const struct file_operations max_erase_cycles_typeA_fops = {
	.open = sprd_max_erase_cycles_typeA_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Max Erase Cycles Type B (TLC)
static int sprd_max_erase_cycles_typeB_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[115] << 24) & 0xff000000) |
			((mmchealthdata.buf[114] << 16) & 0xff0000) |
			((mmchealthdata.buf[113] << 8) & 0xff00) |
			(mmchealthdata.buf[112] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_max_erase_cycles_typeB_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_max_erase_cycles_typeB_show, inode->i_private);
}

static const struct file_operations max_erase_cycles_typeB_fops = {
	.open = sprd_max_erase_cycles_typeB_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Min Erase Cycles Type A (SLC)
static int sprd_min_erase_cycles_typeA_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[123] << 24) & 0xff000000) |
			((mmchealthdata.buf[122] << 16) & 0xff0000) |
			((mmchealthdata.buf[121] << 8) & 0xff00) |
			(mmchealthdata.buf[120] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_min_erase_cycles_typeA_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_min_erase_cycles_typeA_show, inode->i_private);
}

static const struct file_operations min_erase_cycles_typeA_fops = {
	.open = sprd_min_erase_cycles_typeA_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Min Erase Cycles Type B (TLC)
static int sprd_min_erase_cycles_typeB_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[127] << 24) & 0xff000000) |
			((mmchealthdata.buf[126] << 16) & 0xff0000) |
			((mmchealthdata.buf[125] << 8) & 0xff00) |
			(mmchealthdata.buf[124] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_min_erase_cycles_typeB_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_min_erase_cycles_typeB_show, inode->i_private);
}

static const struct file_operations min_erase_cycles_typeB_fops = {
	.open = sprd_min_erase_cycles_typeB_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Pre EOL warning level Type B(TLC)
static int sprd_pre_eol_warning_typeB_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[159] << 24) & 0xff000000) |
			((mmchealthdata.buf[158] << 16) & 0xff0000) |
			((mmchealthdata.buf[157] << 8) & 0xff00) |
			(mmchealthdata.buf[156] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_pre_eol_warning_typeB_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_pre_eol_warning_typeB_show, inode->i_private);
}

static const struct file_operations pre_eol_warning_typeB_fops = {
	.open = sprd_pre_eol_warning_typeB_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Uncorrectable Error Correction Code
static int sprd_uncorrectable_error_correction_code_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[163] << 24) & 0xff000000) |
			((mmchealthdata.buf[162] << 16) & 0xff0000) |
			((mmchealthdata.buf[161] << 8) & 0xff00) |
			(mmchealthdata.buf[160] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_uncorrectable_error_correction_code_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_uncorrectable_error_correction_code_show, inode->i_private);
}

static const struct file_operations uncorrectable_error_correction_code_fops = {
	.open = sprd_uncorrectable_error_correction_code_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Current temperature
static int sprd_current_temperature_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[167] << 24) & 0xff000000) |
			((mmchealthdata.buf[166] << 16) & 0xff0000) |
			((mmchealthdata.buf[165] << 8) & 0xff00) |
			(mmchealthdata.buf[164] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_current_temperature_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_current_temperature_show, inode->i_private);
}

static const struct file_operations current_temperature_fops = {
	.open = sprd_current_temperature_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Min temperature
static int sprd_min_temperature_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[171] << 24) & 0xff000000) |
			((mmchealthdata.buf[170] << 16) & 0xff0000) |
			((mmchealthdata.buf[169] << 8) & 0xff00) |
			(mmchealthdata.buf[168] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_min_temperature_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_min_temperature_show, inode->i_private);
}

static const struct file_operations min_temperature_fops = {
	.open = sprd_min_temperature_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Max temperature
static int sprd_max_temperature_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[175] << 24) & 0xff000000) |
			((mmchealthdata.buf[174] << 16) & 0xff0000) |
			((mmchealthdata.buf[173] << 8) & 0xff00) |
			(mmchealthdata.buf[172] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_max_temperature_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_max_temperature_show, inode->i_private);
}

static const struct file_operations max_temperature_fops = {
	.open = sprd_max_temperature_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Reserved 1 4Bytes
static int sprd_reserved1_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[179] << 24) & 0xff000000) |
			((mmchealthdata.buf[178] << 16) & 0xff0000) |
			((mmchealthdata.buf[177] << 8) & 0xff00) |
			(mmchealthdata.buf[176] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_reserved1_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_reserved1_show, inode->i_private);
}

static const struct file_operations reserved1_fops = {
	.open = sprd_reserved1_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Enriched Device Health Type B(TLC)
static int sprd_enrich_device_health_typeB_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[187] << 24) & 0xff000000) |
			((mmchealthdata.buf[186] << 16) & 0xff0000) |
			((mmchealthdata.buf[185] << 8) & 0xff00) |
			(mmchealthdata.buf[184] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_enrich_device_health_typeB_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_enrich_device_health_typeB_show, inode->i_private);
}

static const struct file_operations enrich_device_health_typeB_fops = {
	.open = sprd_enrich_device_health_typeB_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Reserved 2 3Bytes
static int sprd_reserved2_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[190] << 16) & 0xff0000) |
			((mmchealthdata.buf[189] << 8) & 0xff00) |
			(mmchealthdata.buf[188] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_reserved2_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_reserved2_show, inode->i_private);
}

static const struct file_operations reserved2_fops = {
	.open = sprd_reserved2_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Current Power mode
static int sprd_current_power_mode_show(struct seq_file *m, void *v)
{
	u8 temp = mmchealthdata.buf[191];

	seq_printf(m, "0x%x\n", temp);
	return 0;
}

static int sprd_current_power_mode_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_current_power_mode_show, inode->i_private);
}

static const struct file_operations current_power_mode_fops = {
	.open = sprd_current_power_mode_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Enriched Device Health Type A(SLC)
static int sprd_enrich_device_health_typeA_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[195] << 24) & 0xff000000) |
			((mmchealthdata.buf[194] << 16) & 0xff0000) |
			((mmchealthdata.buf[193] << 8) & 0xff00) |
			(mmchealthdata.buf[192] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int sprd_enrich_device_health_typeA_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_enrich_device_health_typeA_show, inode->i_private);
}

static const struct file_operations enrich_device_health_typeA_fops = {
	.open = sprd_enrich_device_health_typeA_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

//Pre EOL warning level Type A(SLC)
static int sprd_pre_eol_warning_level_typeA_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[199] << 24) & 0xff000000) |
			((mmchealthdata.buf[198] << 16) & 0xff0000) |
			((mmchealthdata.buf[197] << 8) & 0xff00) |
			(mmchealthdata.buf[196] & 0xff);

	seq_printf(m, "0x%x\n", temp);
	return 0;
}

static int sprd_pre_eol_warning_level_typeA_open(struct inode *inode,
		struct file *file)
{
	return single_open(file, sprd_pre_eol_warning_level_typeA_show, inode->i_private);
}

static const struct file_operations pre_eol_warning_level_typeA_fops = {
	.open = sprd_pre_eol_warning_level_typeA_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

////////////////////////////////////
static const struct file_operations *proc_fops_list4[] = {
	&health_data_fops,
	&average_erase_cycles_typeA_fops,
	&average_erase_cycles_typeB_fops,
	&read_reclaim_count_typeA_fops,
	&read_reclaim_count_typeB_fops,
	&bad_block_manufactory_fops,
	&bad_block_runtime_typeA_fops,
	&bad_block_runtime_typeB_fops,
	&field_fw_updates_count_fops,
	&fw_release_date_fops,
	&fw_release_time_fops,
	&cumulative_host_write_data_size_fops,
	&number_vcc_voltage_drops_occurrences_fops,
	&number_vcc_voltage_droops_occurrences_fops,
	&number_of_failures_recover_fops,
	&total_recovery_operation_after_vdet_fops,
	&cumulative_smartslc_write_payload_fops,
	&cumulative_smartslc_bigfile_mode_fops,
	&number_of_times_smartSLC_fops,
	&average_erase_cycles_of_smartslc_fops,
	&cumulative_initialization_count_fops,
	&max_erase_cycles_typeA_fops,
	&max_erase_cycles_typeB_fops,
	&min_erase_cycles_typeA_fops,
	&min_erase_cycles_typeB_fops,
	&pre_eol_warning_typeB_fops,
	&uncorrectable_error_correction_code_fops,
	&current_temperature_fops,
	&min_temperature_fops,
	&max_temperature_fops,
	&reserved1_fops,
	&enrich_device_health_typeB_fops,
	&reserved2_fops,
	&current_power_mode_fops,
	&enrich_device_health_typeA_fops,
	&pre_eol_warning_level_typeA_fops,
};

static char * const sprd_emmc_node_info4[] = {
	"health_data",
	"average_erase_cycles_typeA",
	"average_erase_cycles_typeB",
	"read_reclaim_count_typeA",
	"read_reclaim_count_typeB",
	"bad_block_manufactory",
	"bad_block_runtime_typeA",
	"bad_block_runtime_typeB",
	"field_fw_updates_count",
	"fw_release_date",
	"fw_release_time",
	"cumulative_host_write_data_size",
	"number_vcc_voltage_drops_occurrences",
	"number_vcc_voltage_droops_occurrences",
	"number_of_failures_recover",
	"total_recovery_operation_after_vdet",
	"cumulative_smartslc_write_payload",
	"cumulative_smartslc_bigfile_mode",
	"number_of_times_smartSLC",
	"average_erase_cycles_of_smartslc",
	"cumulative_initialization_count",
	"max_erase_cycles_typeA",
	"max_erase_cycles_typeB",
	"min_erase_cycles_typeA",
	"min_erase_cycles_typeB",
	"pre_eol_warning_typeB",
	"uncorrectable_error_correction_code",
	"current_temperature",
	"min_temperature",
	"max_temperature",
	"reserved1",
	"enrich_device_health_typeB",
	"reserved2",
	"current_power_mode",
	"enrich_device_health_typeA",
	"pre_eol_warning_level_typeA",
};

int sprd_create_mmc_health_init4(void)
{
	struct proc_dir_entry *mmchealthdir;
	struct proc_dir_entry *prEntry;
	int i, node;

	mmchealthdir = proc_mkdir("mmchealth", NULL);
	if (!mmchealthdir) {
		pr_err("%s: failed to create /proc/mmchealth\n",
			__func__);
		return -1;
	}

	node = ARRAY_SIZE(sprd_emmc_node_info4);
	for (i = 0; i < node; i++) {
		prEntry = proc_create(sprd_emmc_node_info4[i], PROC_MODE,
				      mmchealthdir, proc_fops_list4[i]);
		if (!prEntry) {
			pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
				__func__, sprd_emmc_node_info4[i]);
			return -1;
		}
	}

	return 0;
}

/*********************  Micron_eMMC  *****************************************/
//Factory bad block count
static int Micron_Inital_bad_block_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u16 *)(&mmchealthdata.buf[0]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Inital_bad_block_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Inital_bad_block_count_show, inode->i_private);
}

static const struct file_operations Micron_Inital_bad_block_count_fops = {
    .open = Micron_Inital_bad_block_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Runtime_bad_block_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u16 *)(&mmchealthdata.buf[2]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Runtime_bad_block_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Runtime_bad_block_count_show, inode->i_private);
}

static const struct file_operations Micron_Runtime_bad_block_count_fops = {
    .open = Micron_Runtime_bad_block_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Run_time_bad_block_count_TLC_show(struct seq_file *m, void *v)
{
    u32 temp = *((u16 *)(&mmchealthdata.buf[2]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Run_time_bad_block_count_TLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Run_time_bad_block_count_TLC_show, inode->i_private);
}

static const struct file_operations Micron_Run_time_bad_block_count_TLC_fops = {
    .open = Micron_Run_time_bad_block_count_TLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Remaining_spare_block_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u16 *)(&mmchealthdata.buf[4]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Remaining_spare_block_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Remaining_spare_block_count_show, inode->i_private);
}

static const struct file_operations Micron_Remaining_spare_block_count_fops = {
    .open = Micron_Remaining_spare_block_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Minimum_MLC_block_erase_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[16]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Minimum_MLC_block_erase_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Minimum_MLC_block_erase_show, inode->i_private);
}

static const struct file_operations Micron_Minimum_MLC_block_erase_fops = {
    .open = Micron_Minimum_MLC_block_erase_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Maximum_MLC_block_erase_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[20]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Maximum_MLC_block_erase_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Maximum_MLC_block_erase_show, inode->i_private);
}

static const struct file_operations Micron_Maximum_MLC_block_erase_fops = {
    .open = Micron_Maximum_MLC_block_erase_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Average_MLC_block_erase_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[24]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Average_MLC_block_erase_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Average_MLC_block_erase_show, inode->i_private);
}

static const struct file_operations Micron_Average_MLC_block_erase_fops = {
    .open = Micron_Average_MLC_block_erase_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Ave_EC_Num_TLC_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[24]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Ave_EC_Num_TLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Ave_EC_Num_TLC_show, inode->i_private);
}

static const struct file_operations Micron_Ave_EC_Num_TLC_fops = {
    .open = Micron_Ave_EC_Num_TLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Total_MLC_block_erase_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[28]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Total_MLC_block_erase_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Total_MLC_block_erase_show, inode->i_private);
}

static const struct file_operations Micron_Total_MLC_block_erase_fops = {
    .open = Micron_Total_MLC_block_erase_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Minimum_SLC_block_erase_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[32]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Minimum_SLC_block_erase_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Minimum_SLC_block_erase_show, inode->i_private);
}

static const struct file_operations Micron_Minimum_SLC_block_erase_fops = {
    .open = Micron_Minimum_SLC_block_erase_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Maximum_SLC_block_erase_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[36]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Maximum_SLC_block_erase_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Maximum_SLC_block_erase_show, inode->i_private);
}

static const struct file_operations Micron_Maximum_SLC_block_erase_fops = {
    .open = Micron_Maximum_SLC_block_erase_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Average_SLC_block_erase_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[40]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Average_SLC_block_erase_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Average_SLC_block_erase_show, inode->i_private);
}

static const struct file_operations Micron_Average_SLC_block_erase_fops = {
    .open = Micron_Average_SLC_block_erase_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Ave_EC_Num_SLC_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[40]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Ave_EC_Num_SLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Ave_EC_Num_SLC_show, inode->i_private);
}

static const struct file_operations Micron_Ave_EC_Num_SLC_fops = {
    .open = Micron_Ave_EC_Num_SLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Total_SLC_block_erase_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[44]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Total_SLC_block_erase_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Total_SLC_block_erase_show, inode->i_private);
}

static const struct file_operations Micron_Total_SLC_block_erase_fops = {
    .open = Micron_Total_SLC_block_erase_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Cumulative_initialization_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[48]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Cumulative_initialization_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Cumulative_initialization_count_show, inode->i_private);
}

static const struct file_operations Micron_Cumulative_initialization_count_fops = {
    .open = Micron_Cumulative_initialization_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Read_reclaim_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[52]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Read_reclaim_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Read_reclaim_count_show, inode->i_private);
}

static const struct file_operations Micron_Read_reclaim_count_fops = {
    .open = Micron_Read_reclaim_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Read_reclaim_SLC_block_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[52]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Read_reclaim_SLC_block_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Read_reclaim_SLC_block_count_show, inode->i_private);
}

static const struct file_operations Micron_Read_reclaim_SLC_block_count_fops = {
    .open = Micron_Read_reclaim_SLC_block_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Written_data_100MB_fops_show(struct seq_file *m, void *v)
{
    u32 temp = *((u32 *)(&mmchealthdata.buf[68]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Written_data_100MB_fops_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Written_data_100MB_fops_show, inode->i_private);
}

static const struct file_operations Micron_Written_data_100MB_fops = {
    .open = Micron_Written_data_100MB_fops_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Firmware_patch_trial_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u16 *)(&mmchealthdata.buf[116]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Firmware_patch_trial_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Firmware_patch_trial_count_show, inode->i_private);
}

static const struct file_operations Micron_Firmware_patch_trial_count_fops = {
    .open = Micron_Firmware_patch_trial_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int Micron_Firmware_patch_success_count_show(struct seq_file *m, void *v)
{
    u32 temp = *((u16 *)(&mmchealthdata.buf[118]));

    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int Micron_Firmware_patch_success_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, Micron_Firmware_patch_success_count_show, inode->i_private);
}

static const struct file_operations Micron_Firmware_patch_success_count_fops = {
    .open = Micron_Firmware_patch_success_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/**********************************************/
static const struct file_operations *proc_fops_list5[] = {
    &Micron_Inital_bad_block_count_fops,
    &Micron_Runtime_bad_block_count_fops,
    &Micron_Remaining_spare_block_count_fops,
    &Micron_Minimum_MLC_block_erase_fops,
    &Micron_Maximum_MLC_block_erase_fops,
    &Micron_Average_MLC_block_erase_fops,
    &Micron_Total_MLC_block_erase_fops,
    &Micron_Minimum_SLC_block_erase_fops,
    &Micron_Maximum_SLC_block_erase_fops,
    &Micron_Average_SLC_block_erase_fops,
    &Micron_Total_SLC_block_erase_fops,
    &Micron_Cumulative_initialization_count_fops,
    &Micron_Read_reclaim_count_fops,
    &Micron_Written_data_100MB_fops,
    &Micron_Firmware_patch_trial_count_fops,
    &Micron_Firmware_patch_success_count_fops,
    //add for upload
    &Micron_Read_reclaim_SLC_block_count_fops,
    &Micron_Ave_EC_Num_TLC_fops,
    &Micron_Run_time_bad_block_count_TLC_fops,
    &Micron_Ave_EC_Num_SLC_fops,
};

static char * const sprd_emmc_node_info5[] = {
    "Inital_bad_block_count",
    "Runtime_bad_block_count",
    "Remaining_spare_block_count",
    "Minimum_MLC_block_erase",
    "Maximum_MLC_block_erase",
    "Average_MLC_block_erase",
    "Total_MLC_block_erase",
    "Minimum_SLC_block_erase",
    "Maximum_SLC_block_erase",
    "Average_SLC_block_erase",
    "Total_SLC_block_erase",
    "Cumulative_initialization_count",
    "Read_reclaim_count",
    "Written_data_100MB",
    "Firmware_patch_trial_count",
    "Firmware_patch_success_count",
    //add for upload
    "Read_reclaim_SLC_block_count",//Read_reclaim_count
    "Ave_EC_Num_TLC",//Average_MLC_block_erase
    "Run_time_bad_block_count_TLC",//Runtime_bad_block_count
    "Ave_EC_Num_SLC",//Average_SLC_block_erase
};

int sprd_create_mmc_health_init5(void)
{
    struct proc_dir_entry *mmchealthdir;
    struct proc_dir_entry *prEntry;
    int i, node;

    mmchealthdir = proc_mkdir("mmchealth", NULL);
    if (!mmchealthdir) {
        pr_err("%s: failed to create /proc/mmchealth\n",
            __func__);
        return -1;
    }

    node = ARRAY_SIZE(sprd_emmc_node_info5);
    for (i = 0; i < node; i++) {
        prEntry = proc_create(sprd_emmc_node_info5[i], PROC_MODE,
                      mmchealthdir, proc_fops_list5[i]);
        if (!prEntry) {
            pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
                __func__, sprd_emmc_node_info5[i]);
            return -1;
        }
    }

    return 0;
}

static int foresee_original_bad_block_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[25] << 8) & 0xff00) |
			(mmchealthdata.buf[26] & 0xff);

	seq_printf(m, "0x%x\n", temp);

    return 0;
}

static int foresee_original_bad_block_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, foresee_original_bad_block_show, inode->i_private);
}

static const struct file_operations foresee_original_bad_block_fops = {
	.open = foresee_original_bad_block_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int foresee_increase_bad_block_show(struct seq_file *m, void *v)
{
	u32 temp = *((u16 *)(&mmchealthdata.buf[27]));

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int foresee_increase_bad_block_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, foresee_increase_bad_block_show, inode->i_private);
}

static const struct file_operations foresee_increase_bad_block_fops = {
	.open = foresee_increase_bad_block_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int foresee_max_wear_number_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[36] << 24) & 0xff000000) |
			((mmchealthdata.buf[37] << 16) & 0xff0000) |
			((mmchealthdata.buf[38] << 8) & 0xff00) |
			(mmchealthdata.buf[39] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int foresee_max_wear_number_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, foresee_max_wear_number_show, inode->i_private);
}

static const struct file_operations foresee_max_wear_number_fops = {
	.open = foresee_max_wear_number_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int foresee_degree_of_wear_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[44] << 24) & 0xff000000) |
			((mmchealthdata.buf[45] << 16) & 0xff0000) |
			((mmchealthdata.buf[46] << 8) & 0xff00) |
			(mmchealthdata.buf[47] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int foresee_degree_of_wear_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, foresee_degree_of_wear_show, inode->i_private);
}

static const struct file_operations foresee_degree_of_wear_fops = {
	.open = foresee_degree_of_wear_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int foresee_write_all_sector_number_show(struct seq_file *m, void *v)
{
	u8 temp[8];
	int i;
	int k;

	for (i = 0; i < 8; i++){
		temp[i] = mmchealthdata.buf[112+i];
	}

	for (k = 0; k < 8; k++){
		seq_printf(m, "%02x", temp[k]);
	}

	return 0;
}

static int foresee_write_all_sector_number_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, foresee_write_all_sector_number_show, inode->i_private);
}

static const struct file_operations foresee_write_all_sector_number_fops = {
	.open = foresee_write_all_sector_number_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static char * const foresee_sprd_emmc_node_info[] = {
	"Original_bad_block",
	"Increase_bad_block",
	"Max_wear_number",
	"Degree_of_wear",
	"Write_all_sector_number",
};

static const struct file_operations *foresee_proc_fops_list[] = {
	&foresee_original_bad_block_fops,
	&foresee_increase_bad_block_fops,
	&foresee_max_wear_number_fops,
	&foresee_degree_of_wear_fops,
	&foresee_write_all_sector_number_fops,
};

int foresee_sprd_create_mmc_health_init(void)
{
	struct proc_dir_entry *mmchealthdir;
	struct proc_dir_entry *prEntry;
	int i, node;

	mmchealthdir = proc_mkdir("mmchealth", NULL);
	if (!mmchealthdir) {
		pr_err("%s: failed to create /proc/mmchealth\n", __func__);
		return -1;
	}

	node = ARRAY_SIZE(foresee_sprd_emmc_node_info);
	for (i = 0; i < node; i++) {
		prEntry = proc_create(foresee_sprd_emmc_node_info[i], PROC_MODE,
			mmchealthdir, foresee_proc_fops_list[i]);
		if (!prEntry) {
			pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
				__func__, foresee_sprd_emmc_node_info[i]);
			return -1;
		}
	}

	return 0;
}

/*phison_64G EMMC*/

static int phison_64G_factory_bad_block_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[0] << 8) & 0xff00) |
			(mmchealthdata.buf[1] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_factory_bad_block_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_factory_bad_block_count_show, inode->i_private);
}

static const struct file_operations phison_64G_factory_bad_block_count_fops = {
	.open = phison_64G_factory_bad_block_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_run_time_bad_block_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[2] << 8) & 0xff00) |
			(mmchealthdata.buf[3] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_run_time_bad_block_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_run_time_bad_block_count_show, inode->i_private);
}

static const struct file_operations phison_64G_run_time_bad_block_count_fops = {
	.open = phison_64G_run_time_bad_block_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_reserved_block_num_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[4] << 8) & 0xff00) |
			(mmchealthdata.buf[5] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_reserved_block_num_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_reserved_block_num_show, inode->i_private);
}

static const struct file_operations phison_64G_reserved_block_num_fops = {
	.open = phison_64G_reserved_block_num_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_min_ec_num_tlc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[16] << 24) & 0xff000000) |
			((mmchealthdata.buf[17] << 16) & 0xff0000) |
			((mmchealthdata.buf[18] << 8) & 0xff00) |
			(mmchealthdata.buf[19] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_min_ec_num_tlc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_min_ec_num_tlc_show, inode->i_private);
}

static const struct file_operations phison_64G_min_ec_num_tlc_fops = {
	.open = phison_64G_min_ec_num_tlc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_max_ec_num_tlc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[20] << 24) & 0xff000000) |
			((mmchealthdata.buf[21] << 16) & 0xff0000) |
			((mmchealthdata.buf[22] << 8) & 0xff00) |
			(mmchealthdata.buf[23] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_max_ec_num_tlc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_max_ec_num_tlc_show, inode->i_private);
}

static const struct file_operations phison_64G_max_ec_num_tlc_fops = {
	.open = phison_64G_max_ec_num_tlc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_ave_ec_num_tlc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[24] << 24) & 0xff000000) |
			((mmchealthdata.buf[25] << 16) & 0xff0000) |
			((mmchealthdata.buf[26] << 8) & 0xff00) |
			(mmchealthdata.buf[27] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_ave_ec_num_tlc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_ave_ec_num_tlc_show, inode->i_private);
}

static const struct file_operations phison_64G_ave_ec_num_tlc_fops = {
	.open = phison_64G_ave_ec_num_tlc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_tal_ec_num_tlc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[28] << 24) & 0xff000000) |
			((mmchealthdata.buf[29] << 16) & 0xff0000) |
			((mmchealthdata.buf[30] << 8) & 0xff00) |
			(mmchealthdata.buf[31] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_tal_ec_num_tlc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_tal_ec_num_tlc_show, inode->i_private);
}

static const struct file_operations phison_64G_tal_ec_num_tlc_fops = {
	.open = phison_64G_tal_ec_num_tlc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_min_ec_num_slc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[32] << 24) & 0xff000000) |
			((mmchealthdata.buf[33] << 16) & 0xff0000) |
			((mmchealthdata.buf[34] << 8) & 0xff00) |
			(mmchealthdata.buf[35] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_min_ec_num_slc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_min_ec_num_slc_show, inode->i_private);
}

static const struct file_operations phison_64G_min_ec_num_slc_fops = {
	.open = phison_64G_min_ec_num_slc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_max_ec_num_slc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[36] << 24) & 0xff000000) |
			((mmchealthdata.buf[37] << 16) & 0xff0000) |
			((mmchealthdata.buf[38] << 8) & 0xff00) |
			(mmchealthdata.buf[39] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_max_ec_num_slc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_max_ec_num_slc_show, inode->i_private);
}

static const struct file_operations phison_64G_max_ec_num_slc_fops = {
	.open = phison_64G_max_ec_num_slc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_ave_ec_num_slc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[40] << 24) & 0xff000000) |
			((mmchealthdata.buf[41] << 16) & 0xff0000) |
			((mmchealthdata.buf[42] << 8) & 0xff00) |
			(mmchealthdata.buf[43] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_ave_ec_num_slc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_ave_ec_num_slc_show, inode->i_private);
}

static const struct file_operations phison_64G_ave_ec_num_slc_fops = {
	.open = phison_64G_ave_ec_num_slc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_tal_ec_num_slc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[44] << 24) & 0xff000000) |
			((mmchealthdata.buf[45] << 16) & 0xff0000) |
			((mmchealthdata.buf[46] << 8) & 0xff00) |
			(mmchealthdata.buf[47] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_tal_ec_num_slc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_tal_ec_num_slc_show, inode->i_private);
}

static const struct file_operations phison_64G_tal_ec_num_slc_fops = {
	.open = phison_64G_tal_ec_num_slc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_power_init_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[83] << 24) & 0xff000000) |
			((mmchealthdata.buf[82] << 16) & 0xff0000) |
			((mmchealthdata.buf[81] << 8) & 0xff00) |
			(mmchealthdata.buf[80] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_power_init_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_power_init_count_show, inode->i_private);
}

static const struct file_operations phison_64G_power_init_count_fops = {
	.open = phison_64G_power_init_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_read_reclaim_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[87] << 24) & 0xff000000) |
			((mmchealthdata.buf[86] << 16) & 0xff0000) |
			((mmchealthdata.buf[85] << 8) & 0xff00) |
			(mmchealthdata.buf[84] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_read_reclaim_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_read_reclaim_count_show, inode->i_private);
}

static const struct file_operations phison_64G_read_reclaim_count_fops = {
	.open = phison_64G_read_reclaim_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_total_write_unit_num_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[95] << 24) & 0xff000000) |
			((mmchealthdata.buf[94] << 16) & 0xff0000) |
			((mmchealthdata.buf[93] << 8) & 0xff00) |
			(mmchealthdata.buf[92] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_total_write_unit_num_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_total_write_unit_num_show, inode->i_private);
}

static const struct file_operations phison_64G_total_write_unit_num_fops = {
	.open = phison_64G_total_write_unit_num_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_total_write_cnt_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[99] << 24) & 0xff000000) |
			((mmchealthdata.buf[98] << 16) & 0xff0000) |
			((mmchealthdata.buf[97] << 8) & 0xff00) |
			(mmchealthdata.buf[96] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_total_write_cnt_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_total_write_cnt_show, inode->i_private);
}

static const struct file_operations phison_64G_total_write_cnt_fops = {
	.open = phison_64G_total_write_cnt_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_ffu_successful_count_show(struct seq_file *m, void *v)
{
	u16 temp = ((mmchealthdata.buf[119] << 8) & 0xff00) |
			(mmchealthdata.buf[118] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_ffu_successful_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_ffu_successful_count_show, inode->i_private);
}

static const struct file_operations phison_64G_ffu_successful_count_fops = {
	.open = phison_64G_ffu_successful_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_64G_power_loss_cnt_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[195] << 24) & 0xff000000) |
			((mmchealthdata.buf[194] << 16) & 0xff0000) |
			((mmchealthdata.buf[193] << 8) & 0xff00) |
			(mmchealthdata.buf[192] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_64G_power_loss_cnt_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_64G_power_loss_cnt_show, inode->i_private);
}

static const struct file_operations phison_64G_power_loss_cnt_fops = {
	.open = phison_64G_power_loss_cnt_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static char * const phison_64G_sprd_emmc_node_info[] = {
	"Factory_bad_block_count",
	"Run_time_bad_block_count",
	"Reserved_block_num",
	"Min_ec_num_tlc",
	"Max_ec_num_tlc",
	"Ave_ec_num_tlc",
	"Tal_ec_num_tlc",
	"Min_ec_num_slc",
	"Max_ec_num_slc",
	"Ave_ec_num_slc",
	"Tal_ec_num_slc",
	"Power_init_count",
	"Read_reclaim_count",
	"Total_write_unit_num",
	"Total_write_cnt",
	"ffu_successful_count",
	"Power_loss_cnt",
};

static const struct file_operations *phison_64G_proc_fops_list[] = {
	&phison_64G_factory_bad_block_count_fops,
	&phison_64G_run_time_bad_block_count_fops,
	&phison_64G_reserved_block_num_fops,
	&phison_64G_min_ec_num_tlc_fops,
	&phison_64G_max_ec_num_tlc_fops,
	&phison_64G_ave_ec_num_tlc_fops,
	&phison_64G_tal_ec_num_tlc_fops,
	&phison_64G_min_ec_num_slc_fops,
	&phison_64G_max_ec_num_slc_fops,
	&phison_64G_ave_ec_num_slc_fops,
	&phison_64G_tal_ec_num_slc_fops,
	&phison_64G_power_init_count_fops,
	&phison_64G_read_reclaim_count_fops,
	&phison_64G_total_write_unit_num_fops,
	&phison_64G_total_write_cnt_fops,
	&phison_64G_ffu_successful_count_fops,
	&phison_64G_power_loss_cnt_fops,
};

int phison_64G_sprd_create_mmc_health_init(void)
{
	struct proc_dir_entry *mmchealthdir;
	struct proc_dir_entry *prEntry;
	int i, node;

	mmchealthdir = proc_mkdir("mmchealth", NULL);
	if (!mmchealthdir) {
		pr_err("%s: failed to create /proc/mmchealth\n", __func__);
		return -1;
	}

	node = ARRAY_SIZE(phison_64G_sprd_emmc_node_info);
	for (i = 0; i < node; i++) {
		prEntry = proc_create(phison_64G_sprd_emmc_node_info[i], PROC_MODE,
			mmchealthdir, phison_64G_proc_fops_list[i]);
		if (!prEntry) {
			pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
				__func__, phison_64G_sprd_emmc_node_info[i]);
			return -1;
		}
	}

	return 0;
}

/*phison_128G EMMC*/

static int phison_128G_factory_bad_block_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[0] << 24) & 0xff000000) |
			((mmchealthdata.buf[1] << 16) & 0xff0000) |
			((mmchealthdata.buf[2] << 8) & 0xff00) |
			(mmchealthdata.buf[3] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_factory_bad_block_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_factory_bad_block_count_show, inode->i_private);
}

static const struct file_operations phison_128G_factory_bad_block_count_fops = {
	.open = phison_128G_factory_bad_block_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_run_time_bad_block_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[12] << 24) & 0xff000000) |
			((mmchealthdata.buf[13] << 16) & 0xff0000) |
			((mmchealthdata.buf[14] << 8) & 0xff00) |
			(mmchealthdata.buf[15] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_run_time_bad_block_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_run_time_bad_block_count_show, inode->i_private);
}

static const struct file_operations phison_128G_run_time_bad_block_count_fops = {
	.open = phison_128G_run_time_bad_block_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_reserved_block_num_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[4] << 24) & 0xff000000) |
			((mmchealthdata.buf[5] << 16) & 0xff0000) |
			((mmchealthdata.buf[6] << 8) & 0xff00) |
			(mmchealthdata.buf[7] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_reserved_block_num_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_reserved_block_num_show, inode->i_private);
}

static const struct file_operations phison_128G_reserved_block_num_fops = {
	.open = phison_128G_reserved_block_num_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_min_ec_num_tlc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[104] << 24) & 0xff000000) |
			((mmchealthdata.buf[105] << 16) & 0xff0000) |
			((mmchealthdata.buf[106] << 8) & 0xff00) |
			(mmchealthdata.buf[107] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_min_ec_num_tlc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_min_ec_num_tlc_show, inode->i_private);
}

static const struct file_operations phison_128G_min_ec_num_tlc_fops = {
	.open = phison_128G_min_ec_num_tlc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_max_ec_num_tlc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[108] << 24) & 0xff000000) |
			((mmchealthdata.buf[109] << 16) & 0xff0000) |
			((mmchealthdata.buf[110] << 8) & 0xff00) |
			(mmchealthdata.buf[111] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_max_ec_num_tlc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_max_ec_num_tlc_show, inode->i_private);
}

static const struct file_operations phison_128G_max_ec_num_tlc_fops = {
	.open = phison_128G_max_ec_num_tlc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_ave_ec_num_tlc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[112] << 24) & 0xff000000) |
			((mmchealthdata.buf[113] << 16) & 0xff0000) |
			((mmchealthdata.buf[114] << 8) & 0xff00) |
			(mmchealthdata.buf[115] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_ave_ec_num_tlc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_ave_ec_num_tlc_show, inode->i_private);
}

static const struct file_operations phison_128G_ave_ec_num_tlc_fops = {
	.open = phison_128G_ave_ec_num_tlc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_cumulative_host_write_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[123] << 24) & 0xff000000) |
			((mmchealthdata.buf[122] << 16) & 0xff0000) |
			((mmchealthdata.buf[121] << 8) & 0xff00) |
			(mmchealthdata.buf[120] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_cumulative_host_write_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_cumulative_host_write_show, inode->i_private);
}

static const struct file_operations phison_128G_cumulative_host_write_fops = {
	.open = phison_128G_cumulative_host_write_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_min_ec_num_slc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[92] << 24) & 0xff000000) |
			((mmchealthdata.buf[93] << 16) & 0xff0000) |
			((mmchealthdata.buf[94] << 8) & 0xff00) |
			(mmchealthdata.buf[95] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_min_ec_num_slc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_min_ec_num_slc_show, inode->i_private);
}

static const struct file_operations phison_128G_min_ec_num_slc_fops = {
	.open = phison_128G_min_ec_num_slc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_max_ec_num_slc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[96] << 24) & 0xff000000) |
			((mmchealthdata.buf[97] << 16) & 0xff0000) |
			((mmchealthdata.buf[98] << 8) & 0xff00) |
			(mmchealthdata.buf[99] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_max_ec_num_slc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_max_ec_num_slc_show, inode->i_private);
}

static const struct file_operations phison_128G_max_ec_num_slc_fops = {
	.open = phison_128G_max_ec_num_slc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_ave_ec_num_slc_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[100] << 24) & 0xff000000) |
			((mmchealthdata.buf[101] << 16) & 0xff0000) |
			((mmchealthdata.buf[102] << 8) & 0xff00) |
			(mmchealthdata.buf[103] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_ave_ec_num_slc_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_ave_ec_num_slc_show, inode->i_private);
}

static const struct file_operations phison_128G_ave_ec_num_slc_fops = {
	.open = phison_128G_ave_ec_num_slc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_power_init_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[127] << 24) & 0xff000000) |
			((mmchealthdata.buf[126] << 16) & 0xff0000) |
			((mmchealthdata.buf[125] << 8) & 0xff00) |
			(mmchealthdata.buf[124] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_power_init_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_power_init_count_show, inode->i_private);
}

static const struct file_operations phison_128G_power_init_count_fops = {
	.open = phison_128G_power_init_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_read_reclaim_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[155] << 24) & 0xff000000) |
			((mmchealthdata.buf[154] << 16) & 0xff0000) |
			((mmchealthdata.buf[153] << 8) & 0xff00) |
			(mmchealthdata.buf[152] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_read_reclaim_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_read_reclaim_count_show, inode->i_private);
}

static const struct file_operations phison_128G_read_reclaim_count_fops = {
	.open = phison_128G_read_reclaim_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_ffu_successful_count_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[187] << 24) & 0xff000000) |
			((mmchealthdata.buf[186] << 16) & 0xff0000) |
			((mmchealthdata.buf[185] << 8) & 0xff00) |
			(mmchealthdata.buf[184] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_ffu_successful_count_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_ffu_successful_count_show, inode->i_private);
}

static const struct file_operations phison_128G_ffu_successful_count_fops = {
	.open = phison_128G_ffu_successful_count_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int phison_128G_power_loss_cnt_show(struct seq_file *m, void *v)
{
	u32 temp = ((mmchealthdata.buf[63] << 24) & 0xff000000) |
			((mmchealthdata.buf[62] << 16) & 0xff0000) |
			((mmchealthdata.buf[61] << 8) & 0xff00) |
			(mmchealthdata.buf[60] & 0xff);

	seq_printf(m, "0x%x\n", temp);

	return 0;
}

static int phison_128G_power_loss_cnt_open(struct inode *inode,
        struct file *file)
{
	return single_open(file, phison_128G_power_loss_cnt_show, inode->i_private);
}

static const struct file_operations phison_128G_power_loss_cnt_fops = {
	.open = phison_128G_power_loss_cnt_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static char * const phison_128G_sprd_emmc_node_info[] = {
	"Factory_bad_block_count",
	"Run_time_bad_block_count",
	"Reserved_block_num",
	"Min_ec_num_tlc",
	"Max_ec_num_tlc",
	"Ave_ec_num_tlc",
	"Min_ec_num_slc",
	"Max_ec_num_slc",
	"Ave_ec_num_slc",
	"Cumulative_host_write",
	"Power_init_count",
	"Read_reclaim_count",
	"ffu_successful_count",
	"Power_loss_cnt",
};

static const struct file_operations *phison_128G_proc_fops_list[] = {
	&phison_128G_factory_bad_block_count_fops,
	&phison_128G_run_time_bad_block_count_fops,
	&phison_128G_reserved_block_num_fops,
	&phison_128G_min_ec_num_tlc_fops,
	&phison_128G_max_ec_num_tlc_fops,
	&phison_128G_ave_ec_num_tlc_fops,
	&phison_128G_min_ec_num_slc_fops,
	&phison_128G_max_ec_num_slc_fops,
	&phison_128G_ave_ec_num_slc_fops,
	&phison_128G_cumulative_host_write_fops,
	&phison_128G_power_init_count_fops,
	&phison_128G_read_reclaim_count_fops,
	&phison_128G_ffu_successful_count_fops,
	&phison_128G_power_loss_cnt_fops,
};

int phison_128G_sprd_create_mmc_health_init(void)
{
	struct proc_dir_entry *mmchealthdir;
	struct proc_dir_entry *prEntry;
	int i, node;

	mmchealthdir = proc_mkdir("mmchealth", NULL);
	if (!mmchealthdir) {
		pr_err("%s: failed to create /proc/mmchealth\n", __func__);
		return -1;
	}

	node = ARRAY_SIZE(phison_128G_sprd_emmc_node_info);
	for (i = 0; i < node; i++) {
		prEntry = proc_create(phison_128G_sprd_emmc_node_info[i], PROC_MODE,
			mmchealthdir, phison_128G_proc_fops_list[i]);
		if (!prEntry) {
			pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
				__func__, phison_128G_sprd_emmc_node_info[i]);
			return -1;
		}
	}

	return 0;
}

/*********************YMTC_EC230_256G*****************************************/
static int YMTC_EC230_FBB_Factory_bad_block_count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[0] << 24) & 0xff000000) |
			((mmchealthdata.buf[1] << 16) & 0xff0000) |
			((mmchealthdata.buf[2] << 8) & 0xff00) |
			(mmchealthdata.buf[3] & 0xff);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_FBB_Factory_bad_block_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_FBB_Factory_bad_block_count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_FBB_Factory_bad_block_count_fops = {
    .open = YMTC_EC230_FBB_Factory_bad_block_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
static int YMTC_EC230_Run_time_bad_block_count_TLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[12] << 24) & 0xff000000) |
			((mmchealthdata.buf[13] << 16) & 0xff0000) |
			((mmchealthdata.buf[14] << 8) & 0xff00) |
			(mmchealthdata.buf[15] & 0xff);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Run_time_bad_block_count_TLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Run_time_bad_block_count_TLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Run_time_bad_block_count_TLC_fops = {
    .open = YMTC_EC230_Run_time_bad_block_count_TLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Run_time_bad_block_count_SLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[16] << 24) & 0xff000000) |
			((mmchealthdata.buf[17] << 16) & 0xff0000) |
			((mmchealthdata.buf[18] << 8) & 0xff00) |
			(mmchealthdata.buf[19] & 0xff);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Run_time_bad_block_count_SLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Run_time_bad_block_count_SLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Run_time_bad_block_count_SLC_fops = {
    .open = YMTC_EC230_Run_time_bad_block_count_SLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Run_time_bad_block_count_erase_fail_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[20] << 24) & 0xff000000) |
			((mmchealthdata.buf[21] << 16) & 0xff0000) |
			((mmchealthdata.buf[22] << 8) & 0xff00) |
			(mmchealthdata.buf[23] & 0xff);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Run_time_bad_block_count_erase_fail_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Run_time_bad_block_count_erase_fail_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Run_time_bad_block_count_erase_fail_fops = {
    .open = YMTC_EC230_Run_time_bad_block_count_erase_fail_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Run_time_bad_block_count_program_fail_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[24] << 24) & 0xff000000) |
			((mmchealthdata.buf[25] << 16) & 0xff0000) |
			((mmchealthdata.buf[26] << 8) & 0xff00) |
			(mmchealthdata.buf[27] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Run_time_bad_block_count_program_fail_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Run_time_bad_block_count_program_fail_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Run_time_bad_block_count_program_fail_fops = {
    .open = YMTC_EC230_Run_time_bad_block_count_program_fail_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Run_time_bad_block_count_read_UECC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[28] << 24) & 0xff000000) |
			((mmchealthdata.buf[29] << 16) & 0xff0000) |
			((mmchealthdata.buf[30] << 8) & 0xff00) |
			(mmchealthdata.buf[31] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Run_time_bad_block_count_read_UECC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Run_time_bad_block_count_read_UECC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Run_time_bad_block_count_read_UECC_fops = {
    .open = YMTC_EC230_Run_time_bad_block_count_read_UECC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_UECC_count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[32] << 24) & 0xff000000) |
			((mmchealthdata.buf[33] << 16) & 0xff0000) |
			((mmchealthdata.buf[34] << 8) & 0xff00) |
			(mmchealthdata.buf[35] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_UECC_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_UECC_count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_UECC_count_fops = {
    .open = YMTC_EC230_UECC_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Vcc_Voltage_Drop_Detect_count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[52] << 24) & 0xff000000) |
			((mmchealthdata.buf[53] << 16) & 0xff0000) |
			((mmchealthdata.buf[54] << 8) & 0xff00) |
			(mmchealthdata.buf[55] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Vcc_Voltage_Drop_Detect_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Vcc_Voltage_Drop_Detect_count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Vcc_Voltage_Drop_Detect_count_fops = {
    .open = YMTC_EC230_Vcc_Voltage_Drop_Detect_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Vccq_Voltage_Drop_Detect_count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[56] << 24) & 0xff000000) |
			((mmchealthdata.buf[57] << 16) & 0xff0000) |
			((mmchealthdata.buf[58] << 8) & 0xff00) |
			(mmchealthdata.buf[59] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Vccq_Voltage_Drop_Detect_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Vccq_Voltage_Drop_Detect_count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Vccq_Voltage_Drop_Detect_count_fops = {
    .open = YMTC_EC230_Vccq_Voltage_Drop_Detect_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Suddent_power_off_count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[60] << 24) & 0xff000000) |
			((mmchealthdata.buf[61] << 16) & 0xff0000) |
			((mmchealthdata.buf[62] << 8) & 0xff00) |
			(mmchealthdata.buf[63] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Suddent_power_off_count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Suddent_power_off_count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Suddent_power_off_count_fops = {
    .open = YMTC_EC230_Suddent_power_off_count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Suddent_power_off_recovery_success_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[64] << 24) & 0xff000000) |
			((mmchealthdata.buf[65] << 16) & 0xff0000) |
			((mmchealthdata.buf[66] << 8) & 0xff00) |
			(mmchealthdata.buf[67] & 0xff);
    temp = be32_to_cpu(temp);

    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Suddent_power_off_recovery_success_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Suddent_power_off_recovery_success_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Suddent_power_off_recovery_success_fops = {
    .open = YMTC_EC230_Suddent_power_off_recovery_success_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Min_erase_count_num_SLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[76] << 24) & 0xff000000) |
			((mmchealthdata.buf[77] << 16) & 0xff0000) |
			((mmchealthdata.buf[78] << 8) & 0xff00) |
			(mmchealthdata.buf[79] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Min_erase_count_num_SLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Min_erase_count_num_SLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Min_erase_count_num_SLC_fops = {
    .open = YMTC_EC230_Min_erase_count_num_SLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Max_erase_count_num_SLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[80] << 24) & 0xff000000) |
			((mmchealthdata.buf[81] << 16) & 0xff0000) |
			((mmchealthdata.buf[82] << 8) & 0xff00) |
			(mmchealthdata.buf[83] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Max_erase_count_num_SLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Max_erase_count_num_SLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Max_erase_count_num_SLC_fops = {
    .open = YMTC_EC230_Max_erase_count_num_SLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Ave_erase_count_num_SLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[84] << 24) & 0xff000000) |
			((mmchealthdata.buf[85] << 16) & 0xff0000) |
			((mmchealthdata.buf[86] << 8) & 0xff00) |
			(mmchealthdata.buf[87] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Ave_erase_count_num_SLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Ave_erase_count_num_SLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Ave_erase_count_num_SLC_fops = {
    .open = YMTC_EC230_Ave_erase_count_num_SLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Min_erase_count_num_TLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[92] << 24) & 0xff000000) |
			((mmchealthdata.buf[93] << 16) & 0xff0000) |
			((mmchealthdata.buf[94] << 8) & 0xff00) |
			(mmchealthdata.buf[95] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Min_erase_count_num_TLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Min_erase_count_num_TLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Min_erase_count_num_TLC_fops = {
    .open = YMTC_EC230_Min_erase_count_num_TLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Max_erase_count_num_TLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[96] << 24) & 0xff000000) |
			((mmchealthdata.buf[97] << 16) & 0xff0000) |
			((mmchealthdata.buf[98] << 8) & 0xff00) |
			(mmchealthdata.buf[99] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Max_erase_count_num_TLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Max_erase_count_num_TLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Max_erase_count_num_TLC_fops = {
    .open = YMTC_EC230_Max_erase_count_num_TLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Ave_erase_count_num_TLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[100] << 24) & 0xff000000) |
			((mmchealthdata.buf[101] << 16) & 0xff0000) |
			((mmchealthdata.buf[102] << 8) & 0xff00) |
			(mmchealthdata.buf[103] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Ave_erase_count_num_TLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Ave_erase_count_num_TLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Ave_erase_count_num_TLC_fops = {
    .open = YMTC_EC230_Ave_erase_count_num_TLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Cumulative_Host_Read_MB_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[104] << 24) & 0xff000000) |
			((mmchealthdata.buf[105] << 16) & 0xff0000) |
			((mmchealthdata.buf[106] << 8) & 0xff00) |
			(mmchealthdata.buf[107] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Cumulative_Host_Read_MB_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Cumulative_Host_Read_MB_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Cumulative_Host_Read_MB_fops = {
    .open = YMTC_EC230_Cumulative_Host_Read_MB_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Cumulative_Host_Write_MB_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[108] << 24) & 0xff000000) |
			((mmchealthdata.buf[109] << 16) & 0xff0000) |
			((mmchealthdata.buf[110] << 8) & 0xff00) |
			(mmchealthdata.buf[111] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Cumulative_Host_Write_MB_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Cumulative_Host_Write_MB_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Cumulative_Host_Write_MB_fops = {
    .open = YMTC_EC230_Cumulative_Host_Write_MB_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Cumulative_Initialization_Count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[112] << 24) & 0xff000000) |
			((mmchealthdata.buf[113] << 16) & 0xff0000) |
			((mmchealthdata.buf[114] << 8) & 0xff00) |
			(mmchealthdata.buf[115] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Cumulative_Initialization_Count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Cumulative_Initialization_Count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Cumulative_Initialization_Count_fops = {
    .open = YMTC_EC230_Cumulative_Initialization_Count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Write_amplification_factor_WAF_Value_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[116] << 24) & 0xff000000) |
			((mmchealthdata.buf[117] << 16) & 0xff0000) |
			((mmchealthdata.buf[118] << 8) & 0xff00) |
			(mmchealthdata.buf[119] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Write_amplification_factor_WAF_Value_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Write_amplification_factor_WAF_Value_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Write_amplification_factor_WAF_Value_fops = {
    .open = YMTC_EC230_Write_amplification_factor_WAF_Value_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_History_min_NAND_temperature_Real_Temperature_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[124] << 24) & 0xff000000) |
			((mmchealthdata.buf[125] << 16) & 0xff0000) |
			((mmchealthdata.buf[126] << 8) & 0xff00) |
			(mmchealthdata.buf[127] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_History_min_NAND_temperature_Real_Temperature_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_History_min_NAND_temperature_Real_Temperature_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_History_min_NAND_temperature_Real_Temperature_fops = {
    .open = YMTC_EC230_History_min_NAND_temperature_Real_Temperature_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_History_max_NAND_temperature_Real_Temperature_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[128] << 24) & 0xff000000) |
			((mmchealthdata.buf[129] << 16) & 0xff0000) |
			((mmchealthdata.buf[130] << 8) & 0xff00) |
			(mmchealthdata.buf[131] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_History_max_NAND_temperature_Real_Temperature_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_History_max_NAND_temperature_Real_Temperature_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_History_max_NAND_temperature_Real_Temperature_fops = {
    .open = YMTC_EC230_History_max_NAND_temperature_Real_Temperature_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Spare_SLC_Block_Count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[148] << 24) & 0xff000000) |
			((mmchealthdata.buf[149] << 16) & 0xff0000) |
			((mmchealthdata.buf[150] << 8) & 0xff00) |
			(mmchealthdata.buf[151] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Spare_SLC_Block_Count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Spare_SLC_Block_Count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Spare_SLC_Block_Count_fops = {
    .open = YMTC_EC230_Spare_SLC_Block_Count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Spare_TLC_Block_Count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[152] << 24) & 0xff000000) |
			((mmchealthdata.buf[153] << 16) & 0xff0000) |
			((mmchealthdata.buf[154] << 8) & 0xff00) |
			(mmchealthdata.buf[155] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Spare_TLC_Block_Count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Spare_TLC_Block_Count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Spare_TLC_Block_Count_fops = {
    .open = YMTC_EC230_Spare_TLC_Block_Count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Reserved_TLC_Block_Count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[160] << 24) & 0xff000000) |
			((mmchealthdata.buf[161] << 16) & 0xff0000) |
			((mmchealthdata.buf[162] << 8) & 0xff00) |
			(mmchealthdata.buf[163] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Reserved_TLC_Block_Count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Reserved_TLC_Block_Count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Reserved_TLC_Block_Count_fops = {
    .open = YMTC_EC230_Reserved_TLC_Block_Count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Reserved_SLC_Block_Count_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[164] << 24) & 0xff000000) |
			((mmchealthdata.buf[165] << 16) & 0xff0000) |
			((mmchealthdata.buf[166] << 8) & 0xff00) |
			(mmchealthdata.buf[167] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Reserved_SLC_Block_Count_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Reserved_SLC_Block_Count_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Reserved_SLC_Block_Count_fops = {
    .open = YMTC_EC230_Reserved_SLC_Block_Count_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Read_Reclaim_Count_of_SLC_show(struct seq_file *m, void *v)
{
    u32 temp = ((mmchealthdata.buf[168] << 24) & 0xff000000) |
			((mmchealthdata.buf[169] << 16) & 0xff0000) |
			((mmchealthdata.buf[170] << 8) & 0xff00) |
			(mmchealthdata.buf[171] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Read_Reclaim_Count_of_SLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Read_Reclaim_Count_of_SLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Read_Reclaim_Count_of_SLC_fops = {
    .open = YMTC_EC230_Read_Reclaim_Count_of_SLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_Read_Reclaim_Count_of_TLC_show(struct seq_file *m, void *v)
{
    u32 temp= ((mmchealthdata.buf[172] << 24) & 0xff000000) |
			((mmchealthdata.buf[173] << 16) & 0xff0000) |
			((mmchealthdata.buf[174] << 8) & 0xff00) |
			(mmchealthdata.buf[175] & 0xff);
    seq_printf(m, "0x%x\n", temp);

    return 0;
}
static int YMTC_EC230_Read_Reclaim_Count_of_TLC_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_Read_Reclaim_Count_of_TLC_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_Read_Reclaim_Count_of_TLC_fops = {
    .open = YMTC_EC230_Read_Reclaim_Count_of_TLC_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static int YMTC_EC230_health_datat_show(struct seq_file *m, void *v)
{
    int i;

    for (i = 0; i < 512; i++)
        seq_printf(m, "%02x", mmchealthdata.buf[i]);

    return 0;
}
static int YMTC_EC230_health_data_open(struct inode *inode,
        struct file *file)
{
    return single_open(file, YMTC_EC230_health_datat_show, inode->i_private);
}
static const struct file_operations YMTC_EC230_health_data_fops = {
    .open = YMTC_EC230_health_data_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
//------------------------------------------------------------------------------------------------//
static const struct file_operations *proc_fops_list6[] = {
    &YMTC_EC230_FBB_Factory_bad_block_count_fops,
    &YMTC_EC230_Run_time_bad_block_count_TLC_fops,
    &YMTC_EC230_Run_time_bad_block_count_SLC_fops,
    &YMTC_EC230_Run_time_bad_block_count_erase_fail_fops,
    &YMTC_EC230_Run_time_bad_block_count_program_fail_fops,
    &YMTC_EC230_Run_time_bad_block_count_read_UECC_fops,
    &YMTC_EC230_UECC_count_fops,
    &YMTC_EC230_Vcc_Voltage_Drop_Detect_count_fops,
    &YMTC_EC230_Vccq_Voltage_Drop_Detect_count_fops,
    &YMTC_EC230_Suddent_power_off_count_fops,
    &YMTC_EC230_Suddent_power_off_recovery_success_fops,
    &YMTC_EC230_Min_erase_count_num_SLC_fops,
    &YMTC_EC230_Max_erase_count_num_SLC_fops,
    &YMTC_EC230_Ave_erase_count_num_SLC_fops,
    &YMTC_EC230_Min_erase_count_num_TLC_fops,
    &YMTC_EC230_Max_erase_count_num_TLC_fops,
    &YMTC_EC230_Ave_erase_count_num_TLC_fops,
    &YMTC_EC230_Cumulative_Host_Read_MB_fops,
    &YMTC_EC230_Cumulative_Host_Write_MB_fops,
    &YMTC_EC230_Cumulative_Initialization_Count_fops,
    &YMTC_EC230_Write_amplification_factor_WAF_Value_fops,
    &YMTC_EC230_History_min_NAND_temperature_Real_Temperature_fops,
    &YMTC_EC230_History_max_NAND_temperature_Real_Temperature_fops,
    &YMTC_EC230_Spare_SLC_Block_Count_fops,
    &YMTC_EC230_Spare_TLC_Block_Count_fops,
    &YMTC_EC230_Reserved_TLC_Block_Count_fops,
    &YMTC_EC230_Reserved_SLC_Block_Count_fops,
    &YMTC_EC230_Read_Reclaim_Count_of_SLC_fops,
    &YMTC_EC230_Read_Reclaim_Count_of_TLC_fops,
    &YMTC_EC230_health_data_fops,
};

static char * const sprd_emmc_node_info6[] = {
    "FBB_Factory_bad_block_count",
    "Run_time_bad_block_count_TLC",
    "Run_time_bad_block_count_SLC",
    "Run_time_bad_block_count_erase_fail",
    "Run_time_bad_block_count_program_fail",
    "Run_time_bad_block_count_read_UECC",
    "UECC_Count",//change for upload UECC_count
    "Vcc_Voltage_Drop_Detect_count",
    "Vccq_Voltage_Drop_Detect_count",
    "Suddent_power_off_count",
    "Suddent_power_off_recovery_success",
    "Min_erase_count_num_SLC",
    "Max_erase_count_num_SLC",
    "Ave_EC_Num_SLC",//change for Ave_erase_count_num_SLC
    "Min_erase_count_num_TLC",
    "Max_erase_count_num_TLC",
    "Ave_EC_Num_TLC",//change for Ave_erase_count_num_TLC
    "Total_byte_read(MB)",//change for Cumulative_Host_Read_MB
    "Total_byte_write(MB)",//change for Cumulative_Host_Write_MB
    "Cumulative_Initialization_Count",
    "Write_amplification_factor_WAF_Value",
    "History_min_NAND_temperature_Real_Temperature",
    "History_max_NAND_temperature_Real_Temperature",
    "Spare_SLC_Block_Count",
    "Spare_TLC_Block_Count",
    "Reserved_TLC_Block_Count",
    "Reserved_SLC_Block_Count",
    "Read_reclaim_SLC_block_count",//change for upload Read_Reclaim_Count_of_SLC
    "Read_reclaim_TLC_block_count",//change for upload Read_Reclaim_Count_of_TLC
    "health_data",
};
int sprd_create_mmc_health_init6(void)
{
    struct proc_dir_entry *mmchealthdir;
    struct proc_dir_entry *prEntry;
    int i, node;

    mmchealthdir = proc_mkdir("mmchealth", NULL);
    if (!mmchealthdir) {
        pr_err("%s: failed to create /proc/mmchealth\n",
            __func__);
        return -1;
    }

    node = ARRAY_SIZE(sprd_emmc_node_info6);
    for (i = 0; i < node; i++) {
        prEntry = proc_create(sprd_emmc_node_info6[i], PROC_MODE,
                      mmchealthdir, proc_fops_list6[i]);
        if (!prEntry) {
            pr_err("%s,failed to create node: /proc/mmchealth/%s\n",
                __func__, sprd_emmc_node_info6[i]);
            return -1;
        }
    }

    return 0;
}

/*  最终提供的接口  */
int sprd_create_mmc_health_init(int flag)
{
  int res = -1;
  static int mmc_health_has_init = 0;

  if (mmc_health_has_init)
      return 0;
  mmc_health_has_init = 1;

  pr_err("sprd_create_mmc_health_init start flag= %d\n", flag);
  /* YMTC_EC110_eMMC 32G */
  if (flag == YMTC_EC110_eMMC)
	res = sprd_create_mmc_health_init1();
  /* HFCS 32G eMMC */
  if (flag == HFCS_32G_eMMC1 || flag == HFCS_32G_eMMC2)
	res = sprd_create_mmc_health_init2();
  /* HFCS 64G eMMC */
  if (flag == HFCS_64G_eMMC2)
	res = sprd_create_mmc_health_init3();
  /* Western-Digital-iNAND-7550-eMMC */
  if (flag == Western_Digital_eMMC)
	res = sprd_create_mmc_health_init4();
  /* YMTC_EC110_eMMC 128G*/
  if (flag == YMTC_EC110_eMMC1)
        res = sprd_create_mmc_health_init1();
  /* YMTC_EC110_eMMC 64G */
  if (flag == YMTC_EC110_eMMC2)
        res = sprd_create_mmc_health_init1();
  /* Micron emmc 64G */
  if (flag == Micron_64G_eMMC)
    res = sprd_create_mmc_health_init5();
  /* Micron emmc 128G */
  if (flag == Micron_128G_eMMC)
    res = sprd_create_mmc_health_init5();
  /* Foresee_eMMC 128G*/
  if (flag == Foresee_64G_eMMC)
    res = foresee_sprd_create_mmc_health_init();
  /* Foresee_eMMC 128G*/
  if (flag == Foresee_128G_eMMC)
    res = foresee_sprd_create_mmc_health_init();
  /* Foresee_eMMC 128G*/
  if (flag == Phison_64G_eMMC)
    res = phison_64G_sprd_create_mmc_health_init();
  /* Foresee_eMMC 128G*/
  if (flag == Phison_128G_eMMC)
    res = phison_128G_sprd_create_mmc_health_init();
  /* YMTC_EC230_eMMC 256G */
  if (flag == YMTC_EC230_eMMC)
    res = sprd_create_mmc_health_init6();

  return res;
}
