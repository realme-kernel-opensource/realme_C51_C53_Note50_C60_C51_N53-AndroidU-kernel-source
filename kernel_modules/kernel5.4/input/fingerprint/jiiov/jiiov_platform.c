/**
 * The device control driver for JIIOV's fingerprint sensor.
 *
 * Copyright (C) 2020 JIIOV Corporation. <http://www.jiiov.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 **/
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <net/sock.h>
#include <linux/hardware_info.h>
#include <linux/of_platform.h>
#include <linux/pinctrl/consumer.h>
#include <linux/gpio/consumer.h>
// clang-format off
#include "jiiov_log.h"
#include "jiiov_platform.h"
#include "custom.h"
#include "jiiov_netlink.h"
// clang-format on

#ifdef CONFIG_PM_WAKELOCKS
#include <linux/pm_wakeup.h>
#else
#include "../include/wakelock.h"
#endif

#if defined(ANC_USE_SPI) || defined(MTK_PLATFORM)
#include <linux/spi/spi.h>
#include <linux/spi/spidev.h>
#endif

#define ANC_IOC_MAGIC 'a'

#define ANC_IOC_RESET _IO(ANC_IOC_MAGIC, 0)

#define ANC_IOC_REQUEST_RESOURCE _IO(ANC_IOC_MAGIC, 1)
#define ANC_IOC_RELEASE_RESOURCE _IO(ANC_IOC_MAGIC, 2)

#define ANC_IOC_ENABLE_IRQ _IO(ANC_IOC_MAGIC, 3)
#define ANC_IOC_DISABLE_IRQ _IO(ANC_IOC_MAGIC, 4)
#define ANC_IOC_INIT_IRQ _IO(ANC_IOC_MAGIC, 5)
#define ANC_IOC_DEINIT_IRQ _IO(ANC_IOC_MAGIC, 6)
#define ANC_IOC_SET_IRQ_FLAG_MASK _IO(ANC_IOC_MAGIC, 7)
#define ANC_IOC_CLEAR_IRQ_FLAG_MASK _IO(ANC_IOC_MAGIC, 8)

#define ANC_IOC_ENABLE_SPI_CLK _IO(ANC_IOC_MAGIC, 9)
#define ANC_IOC_DISABLE_SPI_CLK _IO(ANC_IOC_MAGIC, 10)

#define ANC_IOC_ENABLE_POWER _IO(ANC_IOC_MAGIC, 11)
#define ANC_IOC_DISABLE_POWER _IO(ANC_IOC_MAGIC, 12)

#define ANC_IOC_SPI_SPEED _IOW(ANC_IOC_MAGIC, 13, uint32_t)

#define ANC_IOC_CLEAR_FLAG _IO(ANC_IOC_MAGIC, 14)

#define ANC_IOC_WAKE_LOCK _IO(ANC_IOC_MAGIC, 15)
#define ANC_IOC_WAKE_UNLOCK _IO(ANC_IOC_MAGIC, 16)

#ifdef ANC_SUPPORT_NAVIGATION_EVENT
/* Android system-wide key event, for navigation purpose */
#define ANC_IOC_REPORT_KEY_EVENT _IOW(ANC_IOC_MAGIC, 17, ANC_KEY_EVENT)
#endif

#define ANC_IOC_SET_PRODUCT_ID _IOW(ANC_IOC_MAGIC, 18, ANC_SENSOR_PRODUCT_INFO)

#define ANC_COMPATIBLE_SW_FP "jiiov,fingerprint"
#define ANC_DEVICE_NAME "jiiov_fp"

#ifdef ANC_SUPPORT_NAVIGATION_EVENT
#define ANC_INPUT_NAME "jiiov-keys"
#endif



#if defined(ANC_USE_SPI) || defined(MTK_PLATFORM)
#ifdef ANC_USE_SPI
#define SPI_BUFFER_SIZE (50 * 1024)
#define ANC_DEFAULT_SPI_SPEED (18 * 1000 * 1000)
static uint8_t *spi_buffer = NULL;
#endif
typedef struct spi_device anc_device_t;
typedef struct spi_driver anc_driver_t;
#else
typedef struct platform_device anc_device_t;
typedef struct platform_driver anc_driver_t;
#endif
static int finger_screen_status = 0;

finger_screen fingerprint_get_screen_status = NULL;

struct pinctrl *p = NULL;
static anc_device_t *g_anc_spi_device = NULL;
int anc_spi_transfer(const uint8_t *txbuf, uint8_t *rxbuf, int len);

// static const char *const pctl_names[] = {
//     "anc_reset_low",
//     "anc_reset_high",
//     "anc_irq_default",
// };
 static const char * const pctl_names[] = {
    "anc_spi_active",
    "anc_spi_output_low",
};
struct vreg_config {
    char *name;
    unsigned int vmin;
    unsigned int vmax;
    int ua_load;
};

#define ANC_VREG_VDD_NAME "vdd"
#define ANC_VDD_CONFIG_NAME "anc,vdd_config"
static struct vreg_config vreg_conf;

struct anc_data {
    struct device *dev;
    struct class *dev_class;
    dev_t dev_num;
    struct cdev cdev;
    ANC_SENSOR_PRODUCT_INFO product_info;
#ifdef ANC_SUPPORT_NAVIGATION_EVENT
    struct input_dev *input;
    ANC_KEY_EVENT key_event;
#endif

    struct pinctrl *fingerprint_pinctrl;
    struct pinctrl_state *pinctrl_state[ARRAY_SIZE(pctl_names)];
    struct regulator *vreg;
#ifdef CONFIG_PM_WAKELOCKS
    struct wakeup_source *fp_wakelock;
#else
    struct wake_lock fp_wakelock;
#endif
    struct work_struct work_queue;
    int irq_gpio;
    int irq;
    atomic_t irq_enabled;
    bool irq_mask_flag;
    int irq_init;
    int pwr_gpio;
    int rst_gpio;
    struct mutex lock;
    bool resource_requested;

    bool vdd_use_gpio;
    bool vdd_use_pmic;
    char fb_black;
};

struct anc_data *g_anc_data = NULL;

static int vreg_setup(struct anc_data *data, const char *name, bool enable) {
    int ret_val = 0;
    struct device *dev = data->dev;

    ret_val = strncmp(vreg_conf.name, name, strlen(vreg_conf.name));
    if (ret_val != 0) {
        ANC_LOGE("Regulator %s not found", name);
        return -EINVAL;
    }

    if (enable) {
        if (data->vreg == NULL) {
            data->vreg = regulator_get(dev, name);
            if (IS_ERR(data->vreg)) {
                ANC_LOGE("Unable to get %s", name);
                return PTR_ERR(data->vreg);
            }
        }

        if (regulator_count_voltages(data->vreg) > 0) {
            ret_val = regulator_set_voltage(data->vreg, vreg_conf.vmin, vreg_conf.vmax);
            if (ret_val) {
                ANC_LOGE("Unable to set voltage on %s, %d", name, ret_val);
            }
        }

        ret_val = regulator_set_load(data->vreg, vreg_conf.ua_load);
        if (ret_val < 0) {
            ANC_LOGE("Unable to set current on %s, %d", name, ret_val);
        }

        ret_val = regulator_enable(data->vreg);
        if (ret_val) {
            ANC_LOGE("error enabling %s: %d", name, ret_val);
            regulator_put(data->vreg);
            data->vreg = NULL;
        }
    } else {
        if (data->vreg != NULL) {
            ret_val = regulator_is_enabled(data->vreg);
            if (ret_val != 0) {
                regulator_disable(data->vreg);
                ANC_LOGD("disabled %s", name);
            }
            regulator_put(data->vreg);
            data->vreg = NULL;
        }
    }

    return ret_val;
}

/*add screen status */
static ssize_t fp_suspend_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
        return sprintf(buf, "%s\n",
               finger_screen_status? "true" : "false");
}

static ssize_t fp_suspend_store(struct device *dev,
        struct device_attribute *attr, const char *buf, size_t count)
{
    if ((buf[0] == '1') ) {
        finger_screen_status = 1;
        printk("kaoshan buf[0] = %c finger_screen_status = %d \n",buf[0],finger_screen_status);
        if(fingerprint_get_screen_status != NULL)
            fingerprint_get_screen_status(1);
    } else if ((buf[0] == '0')) {
        finger_screen_status = 0;
        printk("kaoshan buf[0] = %c finger_screen_status = %d \n",buf[0],finger_screen_status);
        if(fingerprint_get_screen_status != NULL)
            fingerprint_get_screen_status(0);
    }
    return count;
}



static DEVICE_ATTR_RW(fp_suspend);
static struct attribute *fp_debug_attrs[] = {
        &dev_attr_fp_suspend.attr,
        NULL,
};
static struct attribute_group fp_debug_attr_group = {
        .attrs = fp_debug_attrs,
};


void get_anc_data(struct anc_data *data) {
    data = g_anc_data;
}


static void anc_fp_get_screen_status(int status)
{
    struct anc_data *anc_data = NULL;
    char netlink_msg = (char)ANC_NETLINK_EVENT_INVALID;
    anc_data = g_anc_data;
    if (anc_data == NULL) {
        ANC_LOGE(" anc_data is null return \n");
        return ;
    }
    if(status) {
        anc_data->fb_black = 1;
        netlink_msg = ANC_NETLINK_EVENT_SCR_OFF;
        ANC_LOGE("[anc] LXMNET SCREEN OFF!\n");
        netlink_send_message_to_user(&netlink_msg, sizeof(netlink_msg));
    } else {
        anc_data->fb_black = 0;
        netlink_msg = ANC_NETLINK_EVENT_SCR_ON;
        ANC_LOGE("[anc] LXMNET SCREEN ON!\n");
        netlink_send_message_to_user(&netlink_msg, sizeof(netlink_msg));
    }
}


/**
 * sysfs node to forward netlink event
 */
static ssize_t forward_netlink_event_set(struct device *p_dev, struct device_attribute *p_attr,
                                         const char *p_buffer, size_t count) {
    char netlink_msg = (char)ANC_NETLINK_EVENT_INVALID;

    ANC_LOGD("forward netlink event: %s", p_buffer);
    if (!strncmp(p_buffer, "test", strlen("test"))) {
        netlink_msg = (char)ANC_NETLINK_EVENT_TEST;
    } else if (!strncmp(p_buffer, "irq", strlen("irq"))) {
        netlink_msg = (char)ANC_NETLINK_EVENT_IRQ;
    } else if (!strncmp(p_buffer, "screen_off", strlen("screen_off"))) {
        netlink_msg = (char)ANC_NETLINK_EVENT_SCR_OFF;
    } else if (!strncmp(p_buffer, "screen_on", strlen("screen_on"))) {
        netlink_msg = (char)ANC_NETLINK_EVENT_SCR_ON;
    } else if (!strncmp(p_buffer, "touch_down", strlen("touch_down"))) {
        netlink_msg = (char)ANC_NETLINK_EVENT_TOUCH_DOWN;
    } else if (!strncmp(p_buffer, "touch_up", strlen("touch_up"))) {
        netlink_msg = (char)ANC_NETLINK_EVENT_TOUCH_UP;
    } else if (!strncmp(p_buffer, "ui_ready", strlen("ui_ready"))) {
        netlink_msg = (char)ANC_NETLINK_EVENT_UI_READY;
    } else if (!strncmp(p_buffer, "exit", strlen("exit"))) {
        netlink_msg = (char)ANC_NETLINK_EVENT_EXIT;
    } else {
        ANC_LOGE("don't support the netlink evnet: %s", p_buffer);
        return -EINVAL;
    }

    return netlink_send_message_to_user(&netlink_msg, sizeof(netlink_msg));
}
static DEVICE_ATTR(netlink_event, S_IWUSR, NULL, forward_netlink_event_set);

/**
 * sysfs node to select the set of pins (GPIOS) defined in a pin control node of
 * the device tree
 */
 static int select_pin_ctl(struct anc_data *data, const char *name) {
     size_t i;
     int ret_val = 0;

     ANC_LOGD("name is %s", name);
     for (i = 0; i < ARRAY_SIZE(data->pinctrl_state); i++) {
         const char *n = pctl_names[i];

         if (!strncmp(n, name, strlen(n))) {
             ret_val = pinctrl_select_state(data->fingerprint_pinctrl, data->pinctrl_state[i]);
             if (ret_val) {
                 ANC_LOGE("cannot select %s", name);
             } else {
                 ANC_LOGD("Selected %s", name);
             }
             goto exit;
         }
     }

     ret_val = -EINVAL;
     ANC_LOGE("%s not found", name);

 exit:
     return ret_val;
 }

static ssize_t pinctl_set(struct device *dev, struct device_attribute *attr, const char *buf,
                          size_t count) {
    int ret_val = 0;
    struct anc_data *data = dev_get_drvdata(dev);

    mutex_lock(&data->lock);
  //  ret_val = select_pin_ctl(data, buf);
    mutex_unlock(&data->lock);

    return ret_val ? ret_val : count;
}
static DEVICE_ATTR(pinctl_set, S_IWUSR, NULL, pinctl_set);

static int anc_reset(struct anc_data *data) {
    int ret_val = 0;
    ANC_LOGD("hardware reset");
    mutex_lock(&data->lock);
  //  select_pin_ctl(data, "anc_reset_low");
    gpio_set_value(data->rst_gpio,0);
    // T2 >= 10ms
    mdelay(10);
    //select_pin_ctl(data, "anc_reset_high");
    gpio_set_value(data->rst_gpio,1);
    mdelay(10);
    mutex_unlock(&data->lock);

    return ret_val;
}

static ssize_t hw_reset_set(struct device *dev, struct device_attribute *attr, const char *buf,
                            size_t count) {
    int ret_val = 0;
    struct anc_data *data = dev_get_drvdata(dev);

    if (!strncmp(buf, "reset", strlen("reset"))) {
        ANC_LOGD("hw_reset");
        ret_val = anc_reset(data);
    } else {
        ret_val = -EINVAL;
    }

    return ret_val ? ret_val : count;
}
static DEVICE_ATTR(hw_reset, S_IWUSR, NULL, hw_reset_set);

static void anc_power_onoff(struct anc_data *data, bool power_onoff) {
	int ret = 0;
    ANC_LOGD("power_onoff = %d ", power_onoff);

    if (!data->resource_requested) {
        ANC_LOGW("warning: resource is not requested, return!");
        return;
    }

    if (data->vdd_use_gpio) {
        gpio_set_value(data->pwr_gpio, power_onoff);
    }

    if (data->vdd_use_pmic) {
        vreg_setup(data, ANC_VREG_VDD_NAME, power_onoff);
    }
    if (power_onoff == true) {
        mdelay(6);
        ANC_LOGE("REDAY UP");
        ret = select_pin_ctl(g_anc_data,"anc_spi_active");
        if (ret != 0) {
            ANC_LOGE("select pinctrl failed, %d", ret);
            return;
        }
    }
	else if (power_onoff == false){
        ANC_LOGE("REDAY DOWN");
        ret = select_pin_ctl(g_anc_data,"anc_spi_output_low");
        if (ret != 0) {
            ANC_LOGE("select pinctrl failed, %d", ret);
            return;
        }
        mdelay(4);
        ret = gpio_request(154,"SPI0_CS");
        if (ret != 0) {
            ANC_LOGE("request spi0-cs gpio failed, %d", ret);
            return;
        }
        ret = gpio_direction_output(154,0);
        if (gpio_is_valid(154)) {
            ANC_LOGE("lxm free spi0_cs");
            gpio_free(154);
        }
        if (ret != 0) {
            ANC_LOGE("set spi0-cs gpio failed, %d", ret);
            return;
        }
        ret = gpio_get_value(154);
        ANC_LOGE("%d",ret);
        if(ret == 0)
        {
           ANC_LOGE("spi0_cs set 0");
        }
        ret = gpio_direction_output(data->rst_gpio, 0);
        if (ret) {
            ANC_LOGD("reset gpio direction output failed, ret:%d", ret);
            return ;
        }
        ANC_LOGE("lxmRST SET 0");
	}
}

static void device_power_up(struct anc_data *data) {
    ANC_LOGD("device power up");
    anc_power_onoff(data, true);
}

/**
 * sysfs node to power on/power off the sensor
 */
static ssize_t device_power_set(struct device *dev, struct device_attribute *attr, const char *buf,
                                size_t count) {
    ssize_t ret_val = count;
    struct anc_data *data = dev_get_drvdata(dev);

    mutex_lock(&data->lock);
    if (!strncmp(buf, "on", strlen("on"))) {
        ANC_LOGD("device power on");
        anc_power_onoff(data, true);
    } else if (!strncmp(buf, "off", strlen("off"))) {
        ANC_LOGD("device power off");
        anc_power_onoff(data, false);
    } else {
        ret_val = -EINVAL;
    }
    mutex_unlock(&data->lock);

    return ret_val;
}
static DEVICE_ATTR(device_power, S_IWUSR, NULL, device_power_set);

#ifdef ANC_USE_SPI
static uint32_t anc_read_sensor_id(struct anc_data *data) {
    int ret_val = -1;
    int trytimes = 3;
    uint32_t sensor_chip_id = 0;

    do {
        memset(spi_buffer, 0, 4);
        spi_buffer[0] = 0x30;
        spi_buffer[1] = (char)(~0x30);

        anc_reset(data);

        ret_val = anc_spi_transfer(spi_buffer, spi_buffer, 4);
        if (ret_val != 0) {
            ANC_LOGE("spi_transfer failed");
            continue;
        }

        sensor_chip_id = (uint32_t)((spi_buffer[3] & 0x00FF) | ((spi_buffer[2] << 8) & 0xFF00));
        ANC_LOGD("sensor chip_id = %#x", sensor_chip_id);

        if (sensor_chip_id == 0x6311) {
            ANC_LOGD("Read Sensor Id Success");
            return 0;
        } else {
            ANC_LOGE("Read Sensor Id Fail");
        }
    } while (trytimes--);

    return sensor_chip_id;
}

/**
 * sysfs node to read sensor id
 */
static ssize_t sensor_id_show(struct device *dev, struct device_attribute *attr, char *buf) {
    struct anc_data *data = dev_get_drvdata(dev);
    uint32_t sensor_chip_id = anc_read_sensor_id(data);

    return scnprintf(buf, PAGE_SIZE, "0x%04x", sensor_chip_id);
}
static DEVICE_ATTR(sensor_id, S_IRUSR, sensor_id_show, NULL);

static int set_spi_speed(uint32_t speed) {
    ANC_LOGD("set spi speed : %dhz", speed);
    g_anc_spi_device->max_speed_hz = speed;

    return spi_setup(g_anc_spi_device);
}

int anc_spi_transfer(const uint8_t *txbuf, uint8_t *rxbuf, int len) {
    struct spi_transfer t;
    struct spi_message m;

    memset(&t, 0, sizeof(t));
    spi_message_init(&m);
    t.tx_buf = txbuf;
    t.rx_buf = rxbuf;
    t.bits_per_word = 8;
    t.len = len;
    t.speed_hz = g_anc_spi_device->max_speed_hz;
    spi_message_add_tail(&t, &m);
    return spi_sync(g_anc_spi_device, &m);
}

static ssize_t anc_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
    ssize_t status = 0;
    // struct anc_data *dev_data = filp->private_data;

    ANC_LOGD("count = %zu", count);

    if (count > SPI_BUFFER_SIZE) {
        return (-EMSGSIZE);
    }

    if (copy_from_user(spi_buffer, buf, count)) {
        ANC_LOGE("copy_from_user failed");
        return (-EMSGSIZE);
    }

    status = anc_spi_transfer(spi_buffer, spi_buffer, count);

    if (status == 0) {
        status = copy_to_user(buf, spi_buffer, count);

        if (status != 0) {
            status = -EFAULT;
        } else {
            status = count;
        }
    } else {
        ANC_LOGE("spi_transfer failed");
    }

    return status;
}

static ssize_t anc_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
    ssize_t status = 0;
    // struct anc_data *dev_data = filp->private_data;

    ANC_LOGD("count = %zu", count);

    if (count > SPI_BUFFER_SIZE) {
        return (-EMSGSIZE);
    }

    if (copy_from_user(spi_buffer, buf, count)) {
        ANC_LOGE("copy_from_user failed");
        return (-EMSGSIZE);
    }

    status = anc_spi_transfer(spi_buffer, NULL, count);

    if (status == 0) {
        status = count;
    } else {
        ANC_LOGE("spi_transfer failed");
    }

    return status;
}

static int anc_config_spi(void) {
    g_anc_spi_device->mode = SPI_MODE_0;
    g_anc_spi_device->bits_per_word = 8;
    g_anc_spi_device->max_speed_hz = ANC_DEFAULT_SPI_SPEED;

    return spi_setup(g_anc_spi_device);
}
#endif

static void anc_enable_irq(struct anc_data *data) {
    ANC_LOGD("enable irq");
    if (atomic_read(&data->irq_enabled)) {
        ANC_LOGW("IRQ has been enabled");
    } else {
        enable_irq(data->irq);
        atomic_set(&data->irq_enabled, 1);
    }
}

static void anc_disable_irq(struct anc_data *data) {
    ANC_LOGD("disable irq");
    if (atomic_read(&data->irq_enabled)) {
        disable_irq(data->irq);
        atomic_set(&data->irq_enabled, 0);
    } else {
        ANC_LOGW("IRQ has been disabled");
    }
}

static void anc_wake_lock(struct anc_data *data) {
    ANC_LOGD("wake lock");
#ifdef CONFIG_PM_WAKELOCKS
    __pm_stay_awake(data->fp_wakelock);
#else
    wake_lock(&data->fp_wakelock);
#endif
}

static void anc_wake_unlock(struct anc_data *data) {
    ANC_LOGD("wake unlock");
#ifdef CONFIG_PM_WAKELOCKS
    __pm_relax(data->fp_wakelock);
    __pm_wakeup_event(data->fp_wakelock, msecs_to_jiffies(ANC_WAKELOCK_HOLD_TIME));
#else
    wake_unlock(&data->fp_wakelock);
    wake_lock_timeout(&data->fp_wakelock, msecs_to_jiffies(ANC_WAKELOCK_HOLD_TIME));
#endif
}

/**
 * sysfs node for controlling whether the driver is allowed
 * to wake up the platform on interrupt.
 */
static ssize_t irq_control_set(struct device *dev, struct device_attribute *attr, const char *buf,
                               size_t count) {
    ssize_t ret_val = count;
    struct anc_data *data = dev_get_drvdata(dev);

    mutex_lock(&data->lock);
    if (!strncmp(buf, "enable", strlen("enable"))) {
        anc_enable_irq(data);
    } else if (!strncmp(buf, "disable", strlen("disable"))) {
        anc_disable_irq(data);
    } else {
        ret_val = -EINVAL;
    }
    mutex_unlock(&data->lock);

    return ret_val;
}
static DEVICE_ATTR(irq_set, S_IWUSR, NULL, irq_control_set);

static struct attribute *attributes[] = {&dev_attr_pinctl_set.attr,
                                         &dev_attr_device_power.attr,
                                         &dev_attr_hw_reset.attr,
                                         &dev_attr_irq_set.attr,
                                         &dev_attr_netlink_event.attr,
#ifdef ANC_USE_SPI
                                         &dev_attr_sensor_id.attr,
#endif
                                         NULL};

static const struct attribute_group attribute_group = {
    .attrs = attributes,
};

static void anc_do_irq_work(struct work_struct *ws) {
    char netlink_msg = (char)ANC_NETLINK_EVENT_IRQ;

    netlink_send_message_to_user(&netlink_msg, sizeof(netlink_msg));
}

static irqreturn_t anc_irq_handler(int irq, void *handle) {
    struct anc_data *data = handle;

    ANC_LOGD("irq handler");
    if (data->irq_mask_flag) {
        return IRQ_HANDLED;
    }
#ifdef CONFIG_PM_WAKELOCKS
    __pm_wakeup_event(data->fp_wakelock, msecs_to_jiffies(ANC_WAKELOCK_HOLD_TIME));
#else
    wake_lock_timeout(&data->fp_wakelock, msecs_to_jiffies(ANC_WAKELOCK_HOLD_TIME));
#endif
    schedule_work(&data->work_queue);

    return IRQ_HANDLED;
}

static int anc_request_named_gpio(struct anc_data *data, const char *label, int *gpio) {
    struct device *dev = data->dev;
    struct device_node *np = dev->of_node;
    int ret_val = of_get_named_gpio(np, label, 0);

    if (ret_val < 0) {
        ANC_LOGE("failed to get '%s'", label);
        return ret_val;
    }
    *gpio = ret_val;

    ret_val = devm_gpio_request(dev, *gpio, label);
    if (ret_val) {
        ANC_LOGE("failed to request gpio %d", *gpio);
        return ret_val;
    }
    ANC_LOGD("%s %d", label, *gpio);

    return 0;
}

static int anc_irq_init(struct anc_data *data) {
    int ret_val = 0;
    int irqf = IRQF_TRIGGER_RISING | IRQF_ONESHOT;  // IRQF_TRIGGER_FALLING or IRQF_TRIGGER_RISING

    data->irq = gpio_to_irq(data->irq_gpio);
    if (data->irq_init == 0) {
        ret_val = devm_request_threaded_irq(
            data->dev, data->irq, NULL, anc_irq_handler, irqf, dev_name(data->dev), data);
        if (ret_val) {
            ANC_LOGE("Could not request irq %d", data->irq);
            return ret_val;
        }
        data->irq_init = 1;

        /* Request that the interrupt should be wakeable */
        enable_irq_wake(data->irq);
        atomic_set(&data->irq_enabled, 1);
    }

    return ret_val;
}

static int anc_irq_deinit(struct anc_data *data) {
    if (data->irq_init == 1) {
        disable_irq_wake(data->irq);
        devm_free_irq(data->dev, data->irq, data);
        data->irq_init = 0;
    }

    return 0;
}

#ifdef ANC_SUPPORT_NAVIGATION_EVENT
static int anc_report_key_event(struct anc_data *data) {
    int rc = 0;
    unsigned int key_code = KEY_UNKNOWN;

    ANC_LOGD("key = %d, value = %d", data->key_event.key, data->key_event.value);

    switch (data->key_event.key) {
        case ANC_KEY_HOME:
            key_code = KEY_HOME;
            break;
        case ANC_KEY_MENU:
            key_code = KEY_MENU;
            break;
        case ANC_KEY_BACK:
            key_code = KEY_BACK;
            break;
        case ANC_KEY_UP:
            key_code = KEY_UP;
            break;
        case ANC_KEY_DOWN:
            key_code = KEY_DOWN;
            break;
        case ANC_KEY_LEFT:
            key_code = KEY_LEFT;
            break;
        case ANC_KEY_RIGHT:
            key_code = KEY_RIGHT;
            break;
        case ANC_KEY_POWER:
            key_code = KEY_POWER;
            break;
        case ANC_KEY_WAKEUP:
            key_code = KEY_WAKEUP;
            break;
        case ANC_KEY_CAMERA:
            key_code = KEY_CAMERA;
            break;
        default:
            key_code = (unsigned int)(data->key_event.key);
            break;
    }
	
    input_report_key(data->input, key_code, data->key_event.value);
    input_sync(data->input);

    return rc;
}
#endif
#if 1
static int use_pinctrl_init(struct anc_data *data) {
    int ret_val = 0;
    struct device *dev = data->dev;
    size_t i = 0;

    data->fingerprint_pinctrl = devm_pinctrl_get(dev);
    if (IS_ERR(data->fingerprint_pinctrl)) {
        if (PTR_ERR(data->fingerprint_pinctrl) == -EPROBE_DEFER) {
            ANC_LOGD("pinctrl not ready");
            return -EPROBE_DEFER;
        }
        ANC_LOGE("Target does not use pinctrl");
        data->fingerprint_pinctrl = NULL;
        return -EINVAL;
    }

    for (i = 0; i < ARRAY_SIZE(data->pinctrl_state); i++) {
        struct pinctrl_state *state =
            pinctrl_lookup_state(data->fingerprint_pinctrl, pctl_names[i]);
        if (IS_ERR(state)) {
            ANC_LOGE("cannot find '%s'", pctl_names[i]);
            return -EINVAL;
        }
        ANC_LOGD("found pin control %s", pctl_names[i]);
        data->pinctrl_state[i] = state;
    }

    ret_val = select_pin_ctl(data, "anc_spi_active");
    if (ret_val) {
        ANC_LOGD("set anc_spi_active failed, ret:%d", ret_val);
        return ret_val;
    }

    ret_val = select_pin_ctl(data, "anc_spi_output_low");
    if (ret_val) {
        ANC_LOGD("set anc_spi_output_low failed, ret:%d", ret_val);
        return ret_val;
    }

    return ret_val;
}
#endif
static int use_gpio_init(struct anc_data *data) {
    int ret_val = 0;

    ret_val = anc_request_named_gpio(data, "anc,gpio_rst", &data->rst_gpio);
    ANC_LOGD("request anc,gpio_rst = %d , ret:%d",data->rst_gpio, ret_val);
    if (ret_val) {
        ANC_LOGD("request reset gpio failed, ret:%d", ret_val);
        return ret_val;
    }

    ret_val = gpio_direction_output(data->rst_gpio, 0);
    if (ret_val) {
        ANC_LOGD("reset gpio direction output failed, ret:%d", ret_val);
        return ret_val;
    }
    /*set cs 0*/
    ret_val = gpio_request(154,"SPI0_CS");
    if (ret_val != 0) {
        ANC_LOGE("request spi0-cs gpio failed, %d", ret_val);
        return ret_val;
    }
    ret_val = gpio_direction_output(154,0);
    if (gpio_is_valid(154)) {
        gpio_free(154);
    }
    if (ret_val != 0) {
        ANC_LOGE("set spi0-cs gpio failed, %d", ret_val);
        return ret_val;
    }
    ret_val = gpio_get_value(154);
    ANC_LOGE("%d",ret_val);
    if(ret_val == 0)
    {
        ANC_LOGE("spi0_cs set 0");
    }
    /************/
    ret_val = anc_request_named_gpio(data, "anc,gpio_irq", &data->irq_gpio);
    ANC_LOGD("request anc,anc,gpio_irq = %d , ret:%d",data->irq_gpio, ret_val);
    if (ret_val) {
        ANC_LOGD("request irq gpio failed, ret:%d", ret_val);
        return ret_val;
    }

    ret_val = gpio_direction_input(data->irq_gpio);
    if (ret_val) {
        ANC_LOGD("irq gpio direction input failed, ret:%d", ret_val);
        return ret_val;
    }

    return ret_val;
}

static int anc_gpio_init(struct anc_data *data) {
    int ret_val = 0;
    struct device *dev = data->dev;

    ANC_LOGD("init gpio data->resource_requested = %d",data->resource_requested);

    if (data->resource_requested) {
        ANC_LOGW("warning: resource is already released, return!");
        return 0;
    }

    if (data->vdd_use_gpio) {
        ret_val = anc_request_named_gpio(data, "anc,gpio_pwr", &data->pwr_gpio);
        ANC_LOGE("requestanc,gpio_pwr = %d ret_val = %d  , ret:%d",data->pwr_gpio, ret_val);
        if (ret_val) {
            ANC_LOGE("request power gpio failed, ret:%d", ret_val);
            return ret_val;
        }

        ret_val = gpio_direction_output(data->pwr_gpio, 0);
        if (ret_val) {
            ANC_LOGE("power gpio direction output failed, ret:%d", ret_val);
            return ret_val;
        }
    }

     ret_val = use_pinctrl_init(data);
     if (ret_val) {
         ANC_LOGE("use pinctrl init failed, ret:%d", ret_val);
         return ret_val;
     }

    ret_val = use_gpio_init(data);
    if (ret_val) {
        ANC_LOGE("use gpio init failed, ret:%d", ret_val);
        return ret_val;
    }

    if (of_property_read_bool(dev->of_node, "anc,enable-on-boot")) {
        ANC_LOGD("Enabling hardware");
        device_power_up(data);
    }

    data->resource_requested = true;
    ANC_LOGD("success");

    return 0;
}

static int anc_gpio_deinit(struct anc_data *data) {
    ANC_LOGD("deinit gpio");

    if (!data->resource_requested) {
        ANC_LOGW("warning: resource is already released, return!");
        return 0;
    }

    if (data->vdd_use_gpio) {
        if (gpio_is_valid(data->pwr_gpio)) {
            gpio_free(data->pwr_gpio);
        }
    }

    /* Release pinctl */
    if (data->fingerprint_pinctrl) {
        ANC_LOGD("devm_pinctrl_put");
        devm_pinctrl_put(data->fingerprint_pinctrl);
        data->fingerprint_pinctrl = NULL;
    }

    if (gpio_is_valid(data->rst_gpio)) {
        gpio_free(data->rst_gpio);
    }

    if (gpio_is_valid(data->irq_gpio)) {
        gpio_free(data->irq_gpio);
    }

    data->resource_requested = false;
    ANC_LOGD("success");

    return 0;
}

static int anc_open(struct inode *inode, struct file *filp) {
    struct anc_data *dev_data;
    dev_data = container_of(inode->i_cdev, struct anc_data, cdev);
    filp->private_data = dev_data;
    return 0;
}

static int anc_platform_init(void) {
    int ret_val = 0;

    ret_val = anc_gpio_init(g_anc_data);
    if (ret_val) {
        ANC_LOGE("Failed to init gpio");
        return ret_val;
    }

    return ret_val;
}

static int anc_platform_free(void) {
    int ret_val = 0;

    ret_val = anc_gpio_deinit(g_anc_data);
    if (ret_val) {
        ANC_LOGE("Failed to deinit gpio");
        return ret_val;
    }

    return ret_val;
}

#ifdef MTK_PLATFORM
extern void mt_spi_enable_master_clk(struct spi_device *spidev);
extern void mt_spi_disable_master_clk(struct spi_device *spidev);

void spi_clk_enable(bool enable_flag) {
    static bool is_spi_clk_open = false;

    if (enable_flag) {
        if (!is_spi_clk_open) {
            ANC_LOGD("enable spi clk");
            mt_spi_enable_master_clk(g_anc_spi_device);
            is_spi_clk_open = true;
        } else {
            ANC_LOGD("spi clk already enable");
        }
    } else {
        if (is_spi_clk_open) {
            ANC_LOGD("disable spi clk ");
            mt_spi_disable_master_clk(g_anc_spi_device);
            is_spi_clk_open = false;
        } else {
            ANC_LOGD("spi clk already disable ");
        }
    }
}
#endif

static void set_irq_flag(struct anc_data *data, bool flag) {
    ANC_LOGD("set irq flag mask : %d", flag);
    data->irq_mask_flag = flag;
}

static int init_irq(struct anc_data *data) {
    int ret_val = 0;

    ANC_LOGD("init irq");
    ret_val = anc_irq_init(data);
    INIT_WORK(&data->work_queue, anc_do_irq_work);

    return ret_val;
}

static void deinit_irq(struct anc_data *data) {
    ANC_LOGD("deinit irq");
    anc_irq_deinit(data);
    cancel_work_sync(&data->work_queue);
}

static long anc_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    int ret_val = 0;
    struct anc_data *dev_data = filp->private_data;

    if (_IOC_TYPE(cmd) != ANC_IOC_MAGIC) {
        return -ENOTTY;
    }

    ANC_LOGD("#####  cmd = %d", _IOC_NR(cmd));

    switch (cmd) {
        case ANC_IOC_RESET:
            ret_val = anc_reset(dev_data);
            break;
        case ANC_IOC_ENABLE_POWER:
            anc_power_onoff(dev_data, true);
            break;
        case ANC_IOC_DISABLE_POWER:
            anc_power_onoff(dev_data, false);
            break;
        case ANC_IOC_CLEAR_FLAG:
            clear_last_touch_state();
            break;
        case ANC_IOC_ENABLE_IRQ:
            anc_enable_irq(dev_data);
            break;
        case ANC_IOC_DISABLE_IRQ:
            anc_disable_irq(dev_data);
            break;
        case ANC_IOC_SET_IRQ_FLAG_MASK:
            set_irq_flag(dev_data, true);
            break;
        case ANC_IOC_CLEAR_IRQ_FLAG_MASK:
            set_irq_flag(dev_data, false);
            break;
#ifdef ANC_USE_SPI
        case ANC_IOC_SPI_SPEED:
            ret_val = set_spi_speed(arg);
            break;
#endif
        case ANC_IOC_WAKE_LOCK:
            anc_wake_lock(dev_data);
            break;
        case ANC_IOC_WAKE_UNLOCK:
            anc_wake_unlock(dev_data);
            break;

#ifdef MTK_PLATFORM
        case ANC_IOC_ENABLE_SPI_CLK:
            spi_clk_enable(true);
            break;
        case ANC_IOC_DISABLE_SPI_CLK:
            spi_clk_enable(false);
            break;
#endif
        case ANC_IOC_INIT_IRQ:
            ret_val = init_irq(dev_data);
            break;
        case ANC_IOC_DEINIT_IRQ:
            deinit_irq(dev_data);
            break;
        case ANC_IOC_REQUEST_RESOURCE:
            ret_val = anc_platform_init();
            break;
        case ANC_IOC_RELEASE_RESOURCE:
            ret_val = anc_platform_free();
            break;
#ifdef ANC_SUPPORT_NAVIGATION_EVENT
        case ANC_IOC_REPORT_KEY_EVENT:
            if (copy_from_user(
                    &(dev_data->key_event), (ANC_KEY_EVENT *)arg, sizeof(ANC_KEY_EVENT))) {
                ANC_LOGE("Failed to copy input key event from user to kernel");
                ret_val = -EFAULT;
                break;
            }
            anc_report_key_event(dev_data);
            break;
#endif
        case ANC_IOC_SET_PRODUCT_ID:
	    if (copy_from_user(
                    &(dev_data->product_info), (ANC_SENSOR_PRODUCT_INFO *)arg, sizeof(ANC_SENSOR_PRODUCT_INFO))) {
                ANC_LOGE("Failed to product info from user to kernel");
                ret_val = -EFAULT;
            } else {
                ANC_LOGE("product id : %s", dev_data->product_info.product_id);
		get_hardware_info_data(HWID_FINGERPRINT,dev_data->product_info.product_id);
            }
            break;
	default:
            ret_val = -EINVAL;
            break;
    }
    return ret_val;
}

#ifdef CONFIG_COMPAT
static long anc_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    return anc_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations anc_fops = {
    .owner = THIS_MODULE,
    .open = anc_open,
    .unlocked_ioctl = anc_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = anc_compat_ioctl,
#endif
#ifdef ANC_USE_SPI
    .write = anc_write,
    .read = anc_read,
#endif
};

static int anc_malloc(struct device *dev) {
    /* Allocate device data */
    g_anc_data = devm_kzalloc(dev, sizeof(struct anc_data), GFP_KERNEL);
    if (g_anc_data == NULL) {
        ANC_LOGE("Failed to allocate memory for device data");
        return -ENOMEM;
    }

#ifdef ANC_USE_SPI
    /* Allocate SPI transfer DMA buffer */
    spi_buffer = kmalloc(SPI_BUFFER_SIZE, GFP_KERNEL | GFP_DMA);
    if (!spi_buffer) {
        ANC_LOGE("Failed to allocate memory for spi buffer");
        return -ENOMEM;
    }
#endif

    return 0;
}

static void anc_free(struct device *dev) {
    if (g_anc_data) {
        devm_kfree(dev, g_anc_data);
        g_anc_data = NULL;
    }

#ifdef ANC_USE_SPI
    if (spi_buffer) {
        kfree(spi_buffer);
        spi_buffer = NULL;
    }
#endif
}

static int anc_create_device(void) {
    int ret_val = 0;
    struct device *device_ptr;

    g_anc_data->dev_class = class_create(THIS_MODULE, ANC_DEVICE_NAME);
    if (IS_ERR(g_anc_data->dev_class)) {
        ANC_LOGE("class_create failed");
        return -ENODEV;
    }

    ret_val = alloc_chrdev_region(&g_anc_data->dev_num, 0, 1, ANC_DEVICE_NAME);
    if (ret_val < 0) {
        ANC_LOGE("Failed to alloc char device region, ret_val: %d", ret_val);
        goto device_region_err;
    }
    ANC_LOGD("Major number of device = %d", MAJOR(g_anc_data->dev_num));

    device_ptr = device_create(
        g_anc_data->dev_class, NULL, g_anc_data->dev_num, g_anc_data, ANC_DEVICE_NAME);
    if (IS_ERR(device_ptr)) {
        ANC_LOGE("Failed to create char device");
        ret_val = -ENODEV;
        goto device_create_err;
    }

    cdev_init(&g_anc_data->cdev, &anc_fops);
    g_anc_data->cdev.owner = THIS_MODULE;
    ret_val = cdev_add(&g_anc_data->cdev, g_anc_data->dev_num, 1);
    if (ret_val < 0) {
        ANC_LOGE("Failed to add char device");
        goto cdev_add_err;
    }

    return 0;

cdev_add_err:
    device_destroy(g_anc_data->dev_class, g_anc_data->dev_num);
device_create_err:
    unregister_chrdev_region(g_anc_data->dev_num, 1);
device_region_err:
    class_destroy(g_anc_data->dev_class);
    return ret_val;
}

static int anc_destroy_device(void) {
    cdev_del(&g_anc_data->cdev);
    device_destroy(g_anc_data->dev_class, g_anc_data->dev_num);
    unregister_chrdev_region(g_anc_data->dev_num, 1);
    class_destroy(g_anc_data->dev_class);

    return 0;
}

#ifdef ANC_SUPPORT_NAVIGATION_EVENT
static int anc_input_init(struct device *dev, struct anc_data *data) {
    int rc = 0;

    data->input = input_allocate_device();
    if (!data->input) {
        ANC_LOGE("Failed to allocate input device");
        return -ENOMEM;
    }

    data->input->name = ANC_INPUT_NAME;
    __set_bit(EV_KEY, data->input->evbit);
    __set_bit(KEY_HOME, data->input->keybit);
    __set_bit(KEY_MENU, data->input->keybit);
    __set_bit(KEY_BACK, data->input->keybit);
    __set_bit(KEY_UP, data->input->keybit);
    __set_bit(KEY_DOWN, data->input->keybit);
    __set_bit(KEY_LEFT, data->input->keybit);
    __set_bit(KEY_RIGHT, data->input->keybit);
    __set_bit(KEY_POWER, data->input->keybit);
    __set_bit(KEY_WAKEUP, data->input->keybit);
    __set_bit(KEY_CAMERA, data->input->keybit);

    rc = input_register_device(data->input);
    if (rc) {
        ANC_LOGE("Failed to register input device");
        input_free_device(data->input);
        data->input = NULL;
        return -ENODEV;
    }

    return rc;
}
#endif

static int anc_parse_dts(struct anc_data *data) {
    int ret_val = 0;

    data->vdd_use_gpio = 1; // of_property_read_bool(data->dev->of_node, "anc,vdd_use_gpio");
    data->vdd_use_pmic = of_property_read_bool(data->dev->of_node, "anc,vdd_use_pmic");
    ANC_LOGD("vdd_use_gpio = %d, vdd_use_pmic = %d", data->vdd_use_gpio, data->vdd_use_pmic);

    if (data->vdd_use_pmic) {
        vreg_conf.name = ANC_VREG_VDD_NAME;
        ret_val =
            of_property_read_u32_index(data->dev->of_node, ANC_VDD_CONFIG_NAME, 0, &vreg_conf.vmin);
        if (ret_val != 0) {
            ANC_LOGE("read anc,vdd_config index 0 failed");
            return ret_val;
        }

        ret_val =
            of_property_read_u32_index(data->dev->of_node, ANC_VDD_CONFIG_NAME, 1, &vreg_conf.vmax);
        if (ret_val != 0) {
            ANC_LOGE("read anc,vdd_config index 1 failed");
            return ret_val;
        }

        ret_val = of_property_read_u32_index(
            data->dev->of_node, ANC_VDD_CONFIG_NAME, 2, &vreg_conf.ua_load);
        if (ret_val != 0) {
            ANC_LOGE("read anc,vdd_config index 2 failed");
            return ret_val;
        }
        ANC_LOGD("vreg config: name = %s, vmin = %d, vmax = %d, ua_load = %d",
                 vreg_conf.name,
                 vreg_conf.vmin,
                 vreg_conf.vmax,
                 vreg_conf.ua_load);
    }

    return ret_val;
}

static int anc_probe(anc_device_t *pdev) {
    struct device *dev = &pdev->dev;
    int ret_val = 0;

    ANC_LOGD("entry  lks");

    ret_val = anc_malloc(dev);
    if (ret_val != 0) {
        goto out_free;
    }
    ANC_LOGD(" lks ####    %d ",__LINE__);
    g_anc_data->dev = dev;
    g_anc_data->resource_requested = false;
    g_anc_spi_device = pdev;
    g_anc_data->irq_mask_flag = false;
    g_anc_data->irq_init = 0;
	p = devm_pinctrl_get(&pdev->dev);
ANC_LOGD(" lks ####    %d ",__LINE__);
    ret_val = custom_init();
    if (ret_val != 0) {
        ANC_LOGE("custom init failed");
        goto out_free;
    }
ANC_LOGD(" lks ####    %d ",__LINE__);
    ret_val = anc_parse_dts(g_anc_data);
    if (ret_val != 0) {
        ANC_LOGE("parse dts failed");
        goto out_deinit_custom;
    }
ANC_LOGD(" lks ####    %d ",__LINE__);
    ret_val = anc_create_device();
    if (ret_val != 0) {
        goto out_deinit_custom;
    }
ANC_LOGD(" lks ####    %d ",__LINE__);
    mutex_init(&g_anc_data->lock);

#ifdef CONFIG_PM_WAKELOCKS
    g_anc_data->fp_wakelock = wakeup_source_register(dev, "anc_fp_wakelock");
#else
    wake_lock_init(&g_anc_data->fp_wakelock, WAKE_LOCK_SUSPEND, "anc_fp_wakelock");
#endif

#ifdef ANC_SUPPORT_NAVIGATION_EVENT
    ret_val = anc_input_init(dev, dev_data);
    if (ret_val != 0) {
        ANC_LOGE("Failed to init input dev");
        goto out_destroy_device;
    }
#endif

#if defined(ANC_USE_SPI) || defined(MTK_PLATFORM)
	spi_set_drvdata(pdev, g_anc_data);
#ifdef ANC_USE_SPI
    ret_val = anc_config_spi();
    if (ret_val != 0) {
        ANC_LOGE("config spi failed");
        goto out;
    }
#endif
#else
	platform_set_drvdata(pdev, g_anc_data);
#endif
    ANC_LOGD("Create sysfs path = %s", (&dev->kobj)->name);
    ret_val = sysfs_create_group(&dev->kobj, &attribute_group);
    if (ret_val != 0) {
        ANC_LOGE("Could not create sysfs");
        goto out;
    }
    ret_val = sysfs_create_group(&dev->kobj,
                &fp_debug_attr_group);
    printk("kaoshan #### %s %d ###\n",__func__,__LINE__);
    if (ret_val < 0) {
            //  dev_err(dev, "Fail to create debug files!");
            return -ENOMEM;
    }
    fingerprint_get_screen_status = anc_fp_get_screen_status;

    ANC_LOGD("Success");
    return 0;

out:
#ifdef ANC_SUPPORT_NAVIGATION_EVENT
    input_unregister_device(dev_data->input);
out_destroy_device:
#endif
    anc_destroy_device();
out_deinit_custom:
    custom_deinit();
out_free:
    anc_free(dev);
    ANC_LOGE("Probe Failed, ret_val = %d", ret_val);
    return ret_val;
}

static int anc_remove(anc_device_t *pdev) {
    struct anc_data *data = NULL;
#if defined(ANC_USE_SPI) || defined(MTK_PLATFORM)
    data = spi_get_drvdata(pdev);
#else
    data = platform_get_drvdata(pdev);
#endif

    sysfs_remove_group(&pdev->dev.kobj, &attribute_group);
    sysfs_remove_link(NULL, "fingerprintscreen");
    mutex_destroy(&data->lock);

#ifdef CONFIG_PM_WAKELOCKS
    wakeup_source_unregister(data->fp_wakelock);
#else
    wake_lock_destroy(&data->fp_wakelock);
#endif

    custom_deinit();
    anc_destroy_device();
    anc_free(&pdev->dev);
    return 0;
}

static void anc_shutdown(anc_device_t *pdev) {
    struct anc_data *data = NULL;

    ANC_LOGD("entry");
#if defined(ANC_USE_SPI) || defined(MTK_PLATFORM)
    data = spi_get_drvdata(pdev);
#else
    data = platform_get_drvdata(pdev);
#endif

    anc_power_onoff(data, false);
}

static struct of_device_id anc_of_match[] = {
    {
        .compatible = ANC_COMPATIBLE_SW_FP,
    },
    {},
};
MODULE_DEVICE_TABLE(of, anc_of_match);

static anc_driver_t anc_driver = {
    .driver =
        {
            .name = ANC_DEVICE_NAME,
            .owner = THIS_MODULE,
            .of_match_table = anc_of_match,
#if defined(ANC_USE_SPI) || defined(MTK_PLATFORM)
            .bus = &spi_bus_type,
#endif
            
        },
    .probe = anc_probe,
    .remove = anc_remove,
	.shutdown = anc_shutdown,
};

static int __init ancfp_init(void) {
    int ret_val = 0;

    ANC_LOGE("entry");
    ANC_LOGE("entry  LKS");

#if defined(ANC_USE_SPI) || defined(MTK_PLATFORM)
    ret_val = spi_register_driver(&anc_driver);
#else
    ret_val = platform_driver_register(&anc_driver);
#endif
    if (!ret_val) {
        ANC_LOGE("success");
    } else {
        ANC_LOGE("register spi driver failed, ret_val:%d", ret_val);
        return ret_val;
    }

    anc_netlink_init();
    return ret_val;
}

static void __exit ancfp_exit(void) {
    ANC_LOGE("entry");

    anc_netlink_exit();
#if defined(ANC_USE_SPI) || defined(MTK_PLATFORM)
    spi_unregister_driver(&anc_driver);
#else
    platform_driver_unregister(&anc_driver);
#endif
}

module_init(ancfp_init);
module_exit(ancfp_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("JIIOV");
MODULE_DESCRIPTION("JIIOV fingerprint sensor device driver");
