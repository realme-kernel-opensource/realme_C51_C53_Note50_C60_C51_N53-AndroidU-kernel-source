#ifndef _DEVICE_INFO_H
#define _DEVICE_INFO_H

#define HQ_DEVINFO_ATTR(name, fmt, args...) \
static int hq_##name##_show(struct seq_file *m, void *v){\
	char name_tmp[32];\
	strcpy(name_tmp, #name);\
	seq_printf(m, fmt, args);\
	return 0;\
}\
static int hq_##name##_open(struct inode *inode, struct file *file){\
	return single_open(file, hq_##name##_show, inode->i_private);\
}\
static const struct file_operations name##_fops = {\
	.open = hq_##name##_open,\
	.read = seq_read,\
}

// dram type
enum {
	DRAM_TYPE0 = 0,
	DRAM_TYPE1,
	DRAM_TYPE2,
	DRAM_TYPE3,
	DRAM_UNKNOWN,
};

enum {
	ACCEL_HQ,
	ALSPS_HQ,
	MSENSOR_HQ,
	GYRO_HQ,
};

struct sensor_devinfo {
	char *ic_name;
	char *vendor_name;
};

struct manufacture_info {
	char *version;
	char *manufacture;
	char *fw_path;
};

int register_device_proc(char *name, char *version, char *manufacture);
int register_devinfo(char *name, struct manufacture_info *info);
void hq_register_sensor_info(int type, char ic_name[]);
#endif /*_DEVICE_INFO_H*/
