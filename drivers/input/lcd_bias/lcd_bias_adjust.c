#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/i2c.h>

#define MAX_REG 3 // three reg for lcd bias
//#define MAX_PARAM 2 // reg and val

static int set_reg[MAX_REG] = {0x00,0x01,0x03};
static u8 set_val[MAX_REG] = {0x0f,0x0f,0x03};
//static u8 set_val2[MAX_REG] = {0x0f,0x0f,0x03};

struct voltage_adjust_drvdata {
	struct regmap *map;
	/* other members */
};

struct voltage_adjust_drvdata *lcd_bias_data;

int set_lcm_bias_voltage_parameter(u8 *val ,int size)
{
	int i;

	printk("[drm]befor lcd bias parameter  0x00 = 0x%x 0x01 = 0x%x;0x03 = 0x%x\n",val[0],val[1],val[2]);
	for(i = 0; i < size; i++){
		set_val[i] = val[i];
	}
	printk("[drm]after lcd bias parameter  0x00 = 0x%x 0x01 = 0x%x;0x03 = 0x%x\n",set_val[0],set_val[1],set_val[2]);

	return 0;
}
EXPORT_SYMBOL(set_lcm_bias_voltage_parameter);

int set_lcm_bias_voltage_for_sprd(void)
{
	int ret = -1;
	int i;

	for(i = 0; i < MAX_REG; i++){
		ret = regmap_write(lcd_bias_data->map, set_reg[i], set_val[i]);
		if(!ret) {
			printk("[drm] lcd write bias ok at reg = 0x%x;val = 0x%x \n",set_reg[i],set_val[i]);
		}
	}

	return ret;
}
EXPORT_SYMBOL(set_lcm_bias_voltage_for_sprd);

int lcd_bias_get_register_val(u8 register_addr)
{
	int ret = -1;
	int val[1] = {0};

	ret = regmap_read(lcd_bias_data->map, register_addr, &val[0]);
	if (!ret) {
		printk("[drm] lcd read bias ok at reg = 0x%x, val = 0x%x\n", register_addr, val[0]);
	}

	return val[0];
}
EXPORT_SYMBOL(lcd_bias_get_register_val);

static ssize_t lcd_bias_voltage_get(struct device *dev,
                struct device_attribute *attr, char *buf)
{
	int val[4];
	struct i2c_client *client = to_i2c_client(dev);
	struct voltage_adjust_drvdata *data = i2c_get_clientdata(client);

	regmap_read(data->map, 0x00, &val[0]);
	regmap_read(data->map, 0x01, &val[1]);
	regmap_read(data->map, 0x03, &val[2]);
	regmap_read(data->map, 0x04, &val[3]);
	return sprintf(buf, "0x00 = 0x%x; 0x01 = 0x%x; 0x03 = 0x%x; 0x04 = 0x%x\n", val[0], val[1], val[2], val[3]);
}

static ssize_t lcd_bias_voltage_set(struct device *dev,
                struct device_attribute *attr, const char *buf, size_t size)
{
	int val;
	struct i2c_client *client = to_i2c_client(dev);
	struct voltage_adjust_drvdata *data = i2c_get_clientdata(client);

	sscanf(buf, "%d", &val);

	if (val == 60) {
		regmap_write(data->map, 0x00, 0x14);
		regmap_write(data->map, 0x01, 0x14);
		regmap_write(data->map, 0x03, 0x03);
	} else if(val == 55) {
		regmap_write(data->map, 0x00, 0x0f);
		regmap_write(data->map, 0x01, 0x0f);
		regmap_write(data->map, 0x03, 0x03);
	} else if (val == 58) {
		regmap_write(data->map, 0x00, 0x12);
		regmap_write(data->map, 0x01, 0x12);
		regmap_write(data->map, 0x03, 0x03);
	}

	return size;
}

static DEVICE_ATTR(lcd_bias_voltage, 0644, lcd_bias_voltage_get, lcd_bias_voltage_set);

static const struct regmap_config lcd_bias_i2c_regmap_conf = {
	.reg_bits = 8,
	.val_bits = 8,
	//.max_register = xx,
};

static int lcd_bias_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct voltage_adjust_drvdata *data;
	struct regmap *regmap;
	int ret = 0;

	data = devm_kzalloc(&client->dev, sizeof(struct voltage_adjust_drvdata), GFP_KERNEL);
	regmap = devm_regmap_init_i2c(client, &lcd_bias_i2c_regmap_conf);
	if (IS_ERR(regmap)) {
		dev_err(&client->dev, "Failed to initialize i2c regmap\n");
		return PTR_ERR(regmap);
	}

	data->map = regmap;
	i2c_set_clientdata(client, data);
	device_create_file(&client->dev, &dev_attr_lcd_bias_voltage);

	lcd_bias_data = data;

	return ret;
}

static int lcd_bias_remove(struct i2c_client *client)
{
	device_remove_file(&client->dev, &dev_attr_lcd_bias_voltage);
	return 0;
}

static const struct i2c_device_id lcd_bias_id[] = {
	{}
};

static const struct of_device_id msm_match_table[] = {
	{.compatible = "sprd,lcm_bias"},
	{}
};

static struct i2c_driver lcd_bias_driver = {
	.driver = {
		.name       = "lcd_bias",
		.of_match_table = msm_match_table,
		.pm         = NULL,
	},
	.probe          = lcd_bias_probe,
	.remove         = lcd_bias_remove,
	.id_table       = lcd_bias_id,
};
module_i2c_driver(lcd_bias_driver);
MODULE_AUTHOR("Licheng@huaqin.com");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("lcd_bias driver");