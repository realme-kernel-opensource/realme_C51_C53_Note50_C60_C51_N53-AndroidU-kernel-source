/*
 * Copyright (C) 2022, SI-IN
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "sipa_tuning_if.h"

/*
 up:     pc -> kernel -> hal -> dsp
    vdd/cmd -> kernel -> hal -> dsp

 down:   dsp -> hal -> kernel -> pc
*/
#define DEVICE_NAME_UP     "sipa_up"
#define DEVICE_NAME_DOWN   "sipa_down"
#define DATA_MAX_LEN       4096
#define MSG_MAX_SIZE       128

struct dev_comm_data {
	uint32_t opt;//get/set or reply
	uint32_t param_id;//the same to qcom define, to distinguish the param type(set topo or set/read parameter)
	uint32_t payload_size;
    uint32_t reserve;
	uint8_t payload[];
} __packed;

#define DEV_COMM_DATA_LEN(data) \
	(sizeof(struct dev_comm_data) + data->payload_size)

#define PARAM_CHECK(buf, len) \
    if (buf == NULL || len <= 0 || len > DATA_MAX_LEN) {                    \
        pr_err("%s: param invalid, buf:%x, len:%d\n", __func__, buf, len);  \
        return -EFAULT;                                                     \
    }

typedef struct {
    struct mutex lock;
    wait_queue_head_t wq;
    uint8_t data[DATA_MAX_LEN];
    uint32_t len;
    bool flag;
} sipa_sync_t;

typedef struct _algo_ctrl {
    uint32_t cmdid;
    uint32_t ch;
    uint8_t msg[MSG_MAX_SIZE];
} algo_cmd_t;

typedef struct _algo_ctrl_sync {
    algo_cmd_t cmd;
    wait_queue_head_t wq;
    bool flag;
} algo_ctrl_sync;

typedef struct {
    sipa_sync_t up;
    sipa_sync_t down;
    algo_ctrl_sync ctrl;
} sipa_turning_t;

sipa_turning_t *g_sipa_turning = NULL;

#define SIPA_CMD_TUNING_CTRL_WR _IOW(0x10, 0xE0, algo_cmd_t)
#define SIPA_CMD_TUNING_CTRL_RD _IOR(0x10, 0xE1, algo_cmd_t)

ssize_t sipa_turning_up_read(struct file *fl, char __user *buf, size_t len, loff_t *off)
{
    sipa_turning_t *priv = g_sipa_turning;
    int ret = 0;
    PARAM_CHECK(buf, len);

    ret = wait_event_interruptible(priv->up.wq, priv->up.flag);
    if (ret) {
        pr_err("%s: wait_event failed\n", __func__);
        return -ERESTART; 
    }

    if (copy_to_user(buf, priv->up.data, priv->up.len)) {
        pr_err("%s: copy to user failed\n", __func__);
        return -EFAULT;
    }
    priv->up.flag = false;
    pr_info("[ info] %s: read:%d\n", __func__, priv->up.len);
    ret = priv->up.len;

    return ret;
}

ssize_t sipa_turning_up_write(struct file *fl, const char __user *buf, size_t len, loff_t *off)
{
    sipa_turning_t *priv = g_sipa_turning;
    struct dev_comm_data *cmd = NULL;
    PARAM_CHECK(buf, len);

    mutex_lock(&priv->up.lock);
    if (copy_from_user(priv->up.data, buf, len)) {
        pr_err("copy from user failed\n");
        mutex_unlock(&priv->up.lock);
        return -EFAULT;
    }

    cmd = (struct dev_comm_data *)priv->up.data;
    priv->up.len = DEV_COMM_DATA_LEN(cmd);
    priv->up.flag = true;
    pr_info("[ info] %s: datalen:%d payload len:%d\n", __func__, len, priv->up.len);
    wake_up_interruptible(&priv->up.wq);
    mutex_unlock(&priv->up.lock);

    return len; 
}

static long sipa_tuning_up_unlocked_ioctl(struct file *fp,
	unsigned int cmd, unsigned long arg)
{
    sipa_turning_t *priv = g_sipa_turning;
    algo_ctrl_sync *ctrl = &(priv->ctrl);
    int ret = 0;

	pr_info("[ info] %s: enter\n", __func__);

	switch (cmd) {
        case SIPA_CMD_TUNING_CTRL_WR: {
                pr_info("[ info] %s: write cmd\n", __func__);
                if (copy_from_user(&(ctrl->cmd),  (void __user *)arg, sizeof(algo_cmd_t))) {
                    return -EFAULT;
                }
                ctrl->flag = true;
                wake_up_interruptible(&ctrl->wq);
            }
            break;
        case SIPA_CMD_TUNING_CTRL_RD: {
                ret = wait_event_interruptible(ctrl->wq, ctrl->flag);
                if (ret) {
                    pr_err("%s: wait_event failed\n", __func__);
                    return -ERESTART; 
                }
                if (copy_to_user((void __user *)arg, &(ctrl->cmd), sizeof(algo_cmd_t))) {
                    return -EFAULT;
                }
                ctrl->flag = false;
                pr_info("[ info] %s: read cmd \n", __func__);
            }
            break;
        default:
	        pr_info("[ info] %s: unsuport cmd:0x%x\n", __func__, cmd);
            return -EFAULT;
    }
	return 0;
}

struct file_operations sipa_turning_up_fops = {
    .owner = THIS_MODULE,
    .read = sipa_turning_up_read,
    .write = sipa_turning_up_write,
	.unlocked_ioctl = sipa_tuning_up_unlocked_ioctl,
	.compat_ioctl = sipa_tuning_up_unlocked_ioctl,
};

struct miscdevice sipa_up_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME_UP,
    .fops = &sipa_turning_up_fops,
};

ssize_t sipa_turning_down_read(struct file *fl, char __user *buf, size_t len, loff_t *off)
{
    sipa_turning_t *priv = g_sipa_turning;
    int ret = 0;
    PARAM_CHECK(buf, len);

    ret = wait_event_interruptible(priv->down.wq, priv->down.flag);
    if (ret) {
        pr_err("%s: wait_event failed\n", __func__);
        return -ERESTART; 
    }

    if (copy_to_user(buf, priv->down.data, priv->down.len)) {
        pr_err("%s: copy to user failed\n", __func__);
        return -EFAULT;
    }
    priv->down.flag = false;
    pr_info("[ info] %s: read:%d\n", __func__, priv->down.len);
    ret = priv->down.len;

    return ret;
}

ssize_t sipa_turning_down_write(struct file *fl, const char __user *buf, size_t len, loff_t *off)
{
    sipa_turning_t *priv = g_sipa_turning;
    struct dev_comm_data *cmd = NULL;
    PARAM_CHECK(buf, len);

    if (copy_from_user(priv->down.data, buf, len)) {
        pr_err("copy from user failed\n");
        return -EFAULT;
    }

    cmd = (struct dev_comm_data *)priv->down.data;
    priv->down.len = DEV_COMM_DATA_LEN(cmd);
    priv->down.flag = true;
    pr_info("[ info] %s: datalen:%d payload len:%d\n", __func__, len, priv->up.len);
    wake_up_interruptible(&priv->down.wq);

    return len; 
}

static long sipa_tuning_down_unlocked_ioctl(struct file *fp,
	unsigned int cmd, unsigned long arg)
{
	pr_info("[ info] %s: run\n", __func__);
	return 0;
}

struct file_operations sipa_turning_down_fops = {
    .owner = THIS_MODULE,
    .read = sipa_turning_down_read,
    .write = sipa_turning_down_write,
	.unlocked_ioctl = sipa_tuning_down_unlocked_ioctl,
	.compat_ioctl = sipa_tuning_down_unlocked_ioctl,
};

struct miscdevice sipa_down_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME_DOWN,
    .fops = &sipa_turning_down_fops,
};

static int __init sipa_tuning_if_init(void)
{
    int ret = 0;
    sipa_turning_t *priv = NULL;

	pr_info("[ info] %s: run\n", __func__);
    priv = kzalloc(sizeof(sipa_turning_t), GFP_KERNEL);
	if (priv == NULL) {
		pr_err("[  err]%s: kmalloc failed \r\n", __func__);
		return -EFAULT;
	}

    init_waitqueue_head(&priv->up.wq);
    init_waitqueue_head(&priv->down.wq);
    init_waitqueue_head(&priv->ctrl.wq);
	mutex_init(&priv->up.lock);
    mutex_init(&priv->down.lock);

	ret = misc_register(&sipa_up_dev);
	if (ret) {
	    pr_err("[ err] %s: err\n", __func__);
	    goto err1;
	}

    ret = misc_register(&sipa_down_dev);
	if (ret) {
	    pr_err("[ err] %s: err\n", __func__);
	    goto err2;
	}
    g_sipa_turning = priv;

	pr_info("[ info] %s: success\n", __func__);

    return 0;
err2:
	misc_deregister(&sipa_up_dev);
err1:
    if (priv) {
        kfree(priv);
		priv = NULL;
    }
	return ret;
}

static void __exit sipa_tuning_if_exit(void)
{
	pr_info("[ info][%s] %s: run\n", __func__);

    if (g_sipa_turning) {
        mutex_destroy(&(g_sipa_turning->up.lock));
        mutex_destroy(&(g_sipa_turning->down.lock));
        kfree(g_sipa_turning);
		g_sipa_turning = NULL;
    }
	misc_deregister(&sipa_up_dev);
	misc_deregister(&sipa_down_dev);
}

module_init(sipa_tuning_if_init);
module_exit(sipa_tuning_if_exit);
MODULE_LICENSE("GPL");