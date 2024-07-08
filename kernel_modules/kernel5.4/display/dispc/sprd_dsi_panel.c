// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Unisoc Inc.
 */

#include <linux/backlight.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <video/of_display_timing.h>
#include <video/mipi_display.h>
#include <video/videomode.h>
#include <linux/reboot.h>

/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 add for lcd esd*/
#include <linux/notifier.h>

#include <drm/drm_atomic_helper.h>

#include "sprd_crtc.h"
#include "sprd_dpu.h"
#include "sprd_drm.h"
#include "sprd_dsi.h"
#include "sprd_dsi_panel.h"
#include "dsi/sprd_dsi_api.h"
#include "sysfs/sysfs_display.h"
#include "sysfs/oplus_display_private_api.h"

#define SPRD_MIPI_DSI_FMT_DSC 0xff
#define SPRD_OLED_DEFAULT_BRIGHTNESS 25

#define host_to_dsi(host) \
	container_of(host, struct sprd_dsi, host)

static void dpu_dump(struct dpu_context *ctx)
{
       u32 *reg = (u32 *)ctx->base;
       int i;

    DRM_INFO("%s()\n", __func__);
       DRM_INFO("      0          4          8          C\n");
       for (i = 0; i < 400; i += 4) {
               DRM_INFO("%04x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
                       i * 4, reg[i], reg[i + 1], reg[i + 2], reg[i + 3]);
       }
}

static void dsi_dump(struct dsi_context *ctx)
{
       u32 *reg = (u32 *)ctx->base;
       int i;

    DRM_INFO("%s()\n", __func__);
       DRM_INFO("      0          4          8          C\n");
       for (i = 0; i < 200; i += 4) {
               DRM_INFO("%04x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
                       i * 4, reg[i], reg[i + 1], reg[i + 2], reg[i + 3]);
       }
}

/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/13, add for lcm bias set, begin */
#define LCM_BIAS_MAXVAL 3
static bool first_turnoff_screen = true;
static u8 bias_lcd[LCM_BIAS_MAXVAL] = {0x0f,0x0f,0x03};
extern int set_lcm_bias_voltage_parameter(u8 *val ,int size);
extern int set_lcm_bias_voltage_for_sprd(void);  //end
extern int lcd_bias_get_register_val(u8 register_addr);

extern int tp_gesture;
extern int touch_black_test;
extern int himax_mcu_vsn_recovery_flag;
extern int vsn_recovery;
extern int himax_chip_common_resume_esd(void);
extern int himax_chip_common_suspend_esd(void);

/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/02/18, add for silence mode */
extern int search_str(char* str, char **result);

static inline struct sprd_panel *to_sprd_panel(struct drm_panel *panel)
{
	return container_of(panel, struct sprd_panel, base);
}

/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/06, add for set backlight after esd recovery */
static int sprd_oled_set_brightness(struct backlight_device *bdev);

static int sprd_panel_send_cmds(struct mipi_dsi_device *dsi,
				const void *data, int size)
{
	struct sprd_panel *panel;
	const struct dsi_cmd_desc *cmds = data;
	u16 len;

	if ((cmds == NULL) || (dsi == NULL))
		return -EINVAL;

	panel = mipi_dsi_get_drvdata(dsi);

	while (size > 0) {
		len = (cmds->wc_h << 8) | cmds->wc_l;

		if (panel->info.use_dcs)
			mipi_dsi_dcs_write_buffer(dsi, cmds->payload, len);
		else
			mipi_dsi_generic_write(dsi, cmds->payload, len);

		if (cmds->wait)
			msleep(cmds->wait);
		cmds = (const struct dsi_cmd_desc *)(cmds->payload + len);
		size -= (len + 4);
	}

	return 0;
}

static int sprd_panel_unprepare(struct drm_panel *p)
{
	struct sprd_panel *panel = to_sprd_panel(p);
	struct gpio_timing *timing;
	int items, i;
	u8 register_addr = 0x03;
	int register_val = 0;

	DRM_INFO("%s:%d tp_gesture=%d touch_black_test=%d\n" ,__func__,__LINE__,tp_gesture,touch_black_test);

	/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/13, add for lcm bias set */
	if (first_turnoff_screen) {
		/* yizhou@MULTIMEDIA.DISPLAY.LCD, 2023/06/01, add for AW bias IC set register val 0x43, begin */
		register_val = lcd_bias_get_register_val(register_addr);
		if (register_val == 0x43) {
			bias_lcd[2] = 0x43;
		}
		/* yizhou@MULTIMEDIA.DISPLAY.LCD, 2023/06/01, add for AW bias IC set register val 0x43, end */
		set_lcm_bias_voltage_parameter(bias_lcd, LCM_BIAS_MAXVAL);
		first_turnoff_screen = false;
	}

	if (tp_gesture != 1 && touch_black_test != 1) {
		if (panel->info.reset_gpio) {
			items = panel->info.rst_off_seq.items;
			timing = panel->info.rst_off_seq.timing;
			for (i = 0; i < items; i++) {
				gpiod_direction_output(panel->info.reset_gpio,
							timing[i].level);
				mdelay(timing[i].delay);
			}
		}

		if (panel->info.avee_gpio) {
			gpiod_direction_output(panel->info.avee_gpio, 0);
			mdelay(5);
		}
	/* xiazhiping@MULTIMEDIA.DISPLAY.LCD, 2023/05/16, add for HX83108A sequence in time, begin */
		if (panel->info.himax_sequence == 1) {
		if (panel->info.avdd_gpio) {
			items = panel->info.rst_off_avdd_seq.items;
			timing = panel->info.rst_off_avdd_seq.timing;
			for (i = 0; i < items; i++) {
				gpiod_direction_output(panel->info.avdd_gpio,
							timing[i].level);
				mdelay(timing[i].delay);
			}
		}
		}else{//end
		if (panel->info.avdd_gpio) {
			gpiod_direction_output(panel->info.avdd_gpio, 0);
			mdelay(5);
		}
		}
		regulator_disable(panel->supply);
	} else {
		DRM_ERROR("%s:%d not turn off lcd power tp_gesture=%d touch_black_test=%d\n" ,__func__,__LINE__,tp_gesture,touch_black_test);
	}
	return 0;
}

static int sprd_panel_prepare(struct drm_panel *p)
{
	struct sprd_panel *panel = to_sprd_panel(p);
	struct gpio_timing *timing;
	int items, i, ret;
	int reset_second_high_items = 2;
	unsigned char reset_short_packet[] = {0x05,0x1E,0x00,0x01,0x4F};

	DRM_INFO("%s(), lcd_name = %s\n", __func__, panel->lcd_name);

	/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/21, add for HX83108A sequence in time, begin */
	if (panel->info.himax_sequence == 1) {
		if (panel->info.reset_gpio) {
			gpiod_direction_output(panel->info.reset_gpio, 0);
			mdelay(3);
		}

		ret = regulator_enable(panel->supply);
		if (ret < 0)
			DRM_ERROR("enable lcd regulator failed\n");

		if (panel->info.avdd_gpio) {
			gpiod_direction_output(panel->info.avdd_gpio, 1);
			mdelay(5);
		}

		if (panel->info.avee_gpio) {
			gpiod_direction_output(panel->info.avee_gpio, 1);
			mdelay(5);
		}

		set_lcm_bias_voltage_for_sprd();

		if (panel->info.reset_gpio) {
			items = panel->info.rst_on_seq.items;
			timing = panel->info.rst_on_seq.timing;

			for (i = 0; i < items; i++) {
				gpiod_direction_output(panel->info.reset_gpio,
							timing[i].level);
				mdelay(timing[i].delay);

				if (i == reset_second_high_items) {
					mutex_lock(&panel->lock);
					sprd_panel_send_cmds(panel->slave, &reset_short_packet[0], sizeof(reset_short_packet)/sizeof(char));
					mutex_unlock(&panel->lock);
				}
			}
		}
	} else { //end
		ret = regulator_enable(panel->supply);
		if (ret < 0)
			DRM_ERROR("enable lcd regulator failed\n");
		/* maohesong@MULTIMEDIA.DISPLAY.LCD, 2024/1/15, add for pre_avdd_rst_on_seq reset_sequence start*/
		if(panel->info.ft8057_sequence_enable)
		{
			gpiod_direction_output(panel->info.reset_gpio, 0);
			mdelay(5);
		}

		if (panel->info.avdd_gpio) {
			gpiod_direction_output(panel->info.avdd_gpio, 1);
			mdelay(5);
		}

		if (panel->info.avee_gpio) {
			gpiod_direction_output(panel->info.avee_gpio, 1);
			mdelay(5);
		}

		/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/13, add for lcm bias set */
		set_lcm_bias_voltage_for_sprd();

		if (panel->info.reset_gpio) {
			items = panel->info.rst_on_seq.items;
			timing = panel->info.rst_on_seq.timing;
			for (i = 0; i < items; i++) {
				gpiod_direction_output(panel->info.reset_gpio,
							timing[i].level);
				mdelay(timing[i].delay);
			}
		}
	}

	return 0;
}

void  sprd_panel_enter_doze(struct drm_panel *p)
{
	struct sprd_panel *panel = to_sprd_panel(p);

	DRM_INFO("%s() enter\n", __func__);

	mutex_lock(&panel->lock);

	if (panel->esd_work_pending) {
		cancel_delayed_work_sync(&panel->esd_work);
		panel->esd_work_pending = false;
	}

	sprd_panel_send_cmds(panel->slave,
	       panel->info.cmds[CMD_CODE_DOZE_IN],
	       panel->info.cmds_len[CMD_CODE_DOZE_IN]);

	mutex_unlock(&panel->lock);
}

void  sprd_panel_exit_doze(struct drm_panel *p)
{
	struct sprd_panel *panel = to_sprd_panel(p);

	DRM_INFO("%s() enter\n", __func__);

	mutex_lock(&panel->lock);

	sprd_panel_send_cmds(panel->slave,
		panel->info.cmds[CMD_CODE_DOZE_OUT],
		panel->info.cmds_len[CMD_CODE_DOZE_OUT]);

	if (panel->info.esd_check_en) {
		schedule_delayed_work(&panel->esd_work,
				      msecs_to_jiffies(1000));
		panel->esd_work_pending = true;
	}

	mutex_unlock(&panel->lock);
}

static int sprd_panel_disable(struct drm_panel *p)
{
	struct sprd_panel *panel = to_sprd_panel(p);

	DRM_INFO("%s()\n", __func__);

	mutex_lock(&panel->lock);
	/*
	 * FIXME:
	 * The cancel work should be executed before DPU stop,
	 * otherwise the esd check will be failed if the DPU
	 * stopped in video mode and the DSI has not change to
	 * CMD mode yet. Since there is no VBLANK timing for
	 * LP cmd transmission.
	 */
	if (panel->esd_work_pending) {
		cancel_delayed_work_sync(&panel->esd_work);
		panel->esd_work_pending = false;
	}

	if (panel->backlight) {
		panel->backlight->props.power = FB_BLANK_POWERDOWN;
		panel->backlight->props.state |= BL_CORE_FBBLANK;
		backlight_update_status(panel->backlight);
	}

	/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/21, add for HX83108A sequence in time */
	if ((panel->info.himax_sequence == 1) && tp_gesture != 1) {
		sprd_panel_send_cmds(panel->slave,
				     panel->info.cmds[CMD_CODE_SLEEP_IN_GESTURE_OFF],
				     panel->info.cmds_len[CMD_CODE_SLEEP_IN_GESTURE_OFF]);
	} else {
		sprd_panel_send_cmds(panel->slave,
				     panel->info.cmds[CMD_CODE_SLEEP_IN],
				     panel->info.cmds_len[CMD_CODE_SLEEP_IN]);
	}

	panel->enabled = false;
	mutex_unlock(&panel->lock);

	return 0;
}

static int sprd_panel_enable(struct drm_panel *p)
{
	struct sprd_panel *panel = to_sprd_panel(p);

	DRM_INFO("%s()\n", __func__);

	mutex_lock(&panel->lock);
	sprd_panel_send_cmds(panel->slave,
			     panel->info.cmds[CMD_CODE_INIT],
			     panel->info.cmds_len[CMD_CODE_INIT]);

	if (panel->backlight) {
		panel->backlight->props.power = FB_BLANK_UNBLANK;
		panel->backlight->props.state &= ~BL_CORE_FBBLANK;
		backlight_update_status(panel->backlight);
	}

	if (panel->info.esd_check_en) {
		schedule_delayed_work(&panel->esd_work,
				      msecs_to_jiffies(1000));
		panel->esd_work_pending = true;
	}

	panel->enabled = true;
	mutex_unlock(&panel->lock);

	return 0;
}

/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 add cabc func  start*/
static struct sprd_panel *p;

int private_panel_cabc(unsigned int level)
{

	DRM_INFO("%s() start! level =%d \n", __func__,level);
	//mutex_lock(&panel_lock);
	if (level == 1) {
		sprd_panel_send_cmds(p->slave,
			     p->info.cmds[CMD_CODE_CABC_UI],
			     p->info.cmds_len[CMD_CODE_CABC_UI]);
    } else if (level == 2) {
		sprd_panel_send_cmds(p->slave,
			     p->info.cmds[CMD_CODE_CABC_STILL],
			     p->info.cmds_len[CMD_CODE_CABC_STILL]);
    } else if (level == 3) {
		sprd_panel_send_cmds(p->slave,
			     p->info.cmds[CMD_CODE_CABC_MOVING],
			     p->info.cmds_len[CMD_CODE_CABC_MOVING]);
    } else {
		sprd_panel_send_cmds(p->slave,
			     p->info.cmds[CMD_CODE_CABC_OFF],
			     p->info.cmds_len[CMD_CODE_CABC_OFF]);
    }
	//p->is_enabled = true;
	//mutex_unlock(&panel_lock);
	DRM_INFO("%s() end!\n", __func__);
	return 0;
}

/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 add cabc func  end*/

static int sprd_panel_get_modes(struct drm_panel *p)
{
	struct drm_display_mode *mode;
	struct sprd_panel *panel = to_sprd_panel(p);
	struct sprd_dsi *dsi = container_of(p->connector, struct sprd_dsi, connector);
	struct device_node *np = panel->slave->dev.of_node;
	u32 surface_width = 0, surface_height = 0;
	u32 sr_width = 0, sr_height = 0;
	int i, mode_count = 0;

	DRM_INFO("%s()\n", __func__);
	mode = drm_mode_duplicate(p->drm, &panel->info.mode);
	if (!mode) {
		DRM_ERROR("failed to alloc mode %s\n", panel->info.mode.name);
		return 0;
	}
	mode->type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED;
	drm_mode_probed_add(p->connector, mode);
	mode_count++;

	for (i = 0; i < panel->info.num_buildin_modes - 1; i++) {
		mode = drm_mode_duplicate(p->drm,
			&(panel->info.buildin_modes[i]));
		if (!mode) {
			DRM_ERROR("failed to alloc mode %s\n",
				panel->info.buildin_modes[i].name);
			return 0;
		}

		mode->type = DRM_MODE_TYPE_DRIVER;
		drm_mode_probed_add(p->connector, mode);
		mode_count++;
	}

	/* parse and create sr mode config */
	of_property_read_u32(panel->info.of_node, "sprd,sr-width", &sr_width);
	of_property_read_u32(panel->info.of_node, "sprd,sr-height", &sr_height);
	if (sr_width && sr_height) {
		for (i = 0; i < panel->info.num_buildin_modes; i++) {
			struct videomode vm = {};
			vm.hactive = sr_width;
			vm.vactive = sr_height;
			vm.pixelclock = sr_width * sr_height * drm_mode_vrefresh(&panel->info.buildin_modes[i]);
			mode = drm_mode_create(p->drm);
			mode->vrefresh = drm_mode_vrefresh(&panel->info.buildin_modes[i]);
			mode->type = DRM_MODE_TYPE_DRIVER;
			mode->width_mm = panel->info.mode.width_mm;
			mode->height_mm = panel->info.mode.height_mm;
			drm_display_mode_from_videomode(&vm, mode);
			drm_mode_probed_add(p->connector, mode);
			mode_count++;
		}
	}

	of_property_read_u32(np, "sprd,surface-width", &surface_width);
	of_property_read_u32(np, "sprd,surface-height", &surface_height);
	if (surface_width && surface_height) {
		struct videomode vm = {};

		vm.hactive = surface_width;
		vm.vactive = surface_height;
		vm.pixelclock = surface_width * surface_height * 60;

		mode = drm_mode_create(p->drm);

		mode->type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_USERDEF;
		mode->vrefresh = 60;
		mode->width_mm = panel->info.mode.width_mm;
		mode->height_mm = panel->info.mode.height_mm;
		drm_display_mode_from_videomode(&vm, mode);
		drm_mode_probed_add(p->connector, mode);
		mode_count++;
		dsi->ctx.surface_mode = true;
	}

	p->connector->display_info.width_mm = panel->info.mode.width_mm;
	p->connector->display_info.height_mm = panel->info.mode.height_mm;

	panel->info.display_mode_count = mode_count;

	return mode_count;
}

static const struct drm_panel_funcs sprd_panel_funcs = {
	.get_modes = sprd_panel_get_modes,
	.enable = sprd_panel_enable,
	.disable = sprd_panel_disable,
	.prepare = sprd_panel_prepare,
	.unprepare = sprd_panel_unprepare,
};

static bool sprd_check_crtc_active_state(struct sprd_panel *panel, int crtc_index)
{
	struct mipi_dsi_host *host = panel->slave->host;
	struct sprd_dsi *dsi = host_to_dsi(host);
	struct drm_connector *connector = &dsi->connector;
	struct sprd_drm *sprd;
	struct drm_crtc *crtc;

	if (!connector->dev ||
	    !connector->dev->registered) {
		DRM_INFO("crtc can not be obtained when drm is not inited\n");
		return false;
	}

	sprd = connector->dev->dev_private;
	mutex_lock(&sprd->state_lock);
	crtc = sprd_find_crtc_from_index(connector->dev, 0);
	if (crtc && crtc->state && crtc->state->active) {
		mutex_unlock(&sprd->state_lock);
		return true;
	}
	mutex_unlock(&sprd->state_lock);

	return false;
}

static int sprd_panel_esd_check(struct sprd_panel *panel)
{
	struct mipi_dsi_host *host = panel->slave->host;
	struct sprd_dsi *dsi = host_to_dsi(host);
	struct panel_info *info = &panel->info;
	struct sprd_dpu *dpu;
	bool crtc_active_state;
	u8 read_val = 0;

	crtc_active_state = sprd_check_crtc_active_state(panel, 0);
	if (!crtc_active_state) {
		DRM_INFO("skip esd during panel suspend\n");
		return 0;
	}

	dsi = container_of(panel->base.connector, struct sprd_dsi, connector);
	if (!dsi->ctx.enabled) {
		DRM_WARN("dsi is not initialized，skip esd check\n");
		return 0;
	}

	mutex_lock(&panel->lock);
	if (!panel->enabled) {
		DRM_INFO("panel is not enabled, skip esd check");
		mutex_unlock(&panel->lock);
		return 0;
	}

	dpu = dsi->dpu;

	/* FIXME: we should enable HS cmd tx here */
	mipi_dsi_set_maximum_return_packet_size(panel->slave, 1);
	mipi_dsi_dcs_read(panel->slave, info->esd_check_reg,
			  &read_val, 1);

	/*
	 * TODO:
	 * Should we support multi-registers check in the future?
	 */
	if (read_val != info->esd_check_val) {
		DRM_ERROR("esd check failed, read value = 0x%02x\n",
			  read_val);
		mutex_unlock(&panel->lock);
		return -EINVAL;
	}

	mutex_unlock(&panel->lock);
	return 0;
}

static int sprd_panel_te_check(struct sprd_panel *panel)
{
	struct mipi_dsi_host *host = panel->slave->host;
	struct sprd_dsi *dsi = host_to_dsi(host);
	struct sprd_dpu *dpu;
	int ret;
	bool crtc_active_state;
	bool irq_occur = false;

	crtc_active_state = sprd_check_crtc_active_state(panel, 0);
	if (!crtc_active_state) {
		DRM_INFO("skip esd during panel suspend\n");
		return 0;
	}

	if (!dsi->ctx.enabled) {
		DRM_WARN("dsi is not initialized，skip esd check\n");
		return 0;
	}

	mutex_lock(&panel->lock);
	if (!panel->enabled) {
		DRM_INFO("panel is not enabled, skip esd check");
		mutex_unlock(&panel->lock);
		return 0;
	}

	dpu = dsi->dpu;

	/* DPU TE irq maybe enabled in kernel */
	if (!dpu->ctx.enabled) {
		mutex_unlock(&panel->lock);
		return 0;
	}

	dpu->ctx.te_check_en = true;

	/* wait for TE interrupt */
	ret = wait_event_interruptible_timeout(dpu->ctx.te_wq,
		dpu->ctx.evt_te, msecs_to_jiffies(500));
	if (!ret) {
		/* double check TE interrupt through dpu_int_raw register */
		if (dpu->core && dpu->core->check_raw_int) {
			down(&dpu->ctx.lock);
			if (dpu->ctx.enabled)
				irq_occur = dpu->core->check_raw_int(&dpu->ctx,
					BIT_DPU_INT_TE);
			up(&dpu->ctx.lock);
			if (!irq_occur) {
				DRM_ERROR("TE esd timeout.\n");
				ret = -ETIMEDOUT;
			} else
				DRM_WARN("TE occur, but isr schedule delay\n");
		} else {
			DRM_ERROR("TE esd timeout.\n");
			ret = -ETIMEDOUT;
		}
	}

	dpu->ctx.te_check_en = false;
	dpu->ctx.evt_te = false;

	mutex_unlock(&panel->lock);

	return ret < 0 ? ret : 0;
}

static int sprd_panel_mix_check(struct sprd_panel *panel)
{
	int ret;

	ret = sprd_panel_esd_check(panel);
	if (ret) {
		DRM_ERROR("mix check use read reg with error\n");
		return ret;
	}

	ret = sprd_panel_te_check(panel);
	if (ret) {
		DRM_ERROR("mix check use te signal with error\n");
		return ret;
	}

	return 0;
}

static void sprd_panel_esd_work_func(struct work_struct *work)
{
	struct sprd_panel *panel = container_of(work, struct sprd_panel,
						esd_work.work);
	struct panel_info *info = &panel->info;
	struct mipi_dsi_host *host = panel->slave->host;
	struct sprd_dsi *dsi = host_to_dsi(host);
	struct drm_connector *connector = &dsi->connector;
	struct sprd_dpu *dpu;
	int ret;

	if ((!dsi->ctx.enabled) || (!panel->enabled)) {
		DRM_ERROR("dsi is suspended, skip esd work\n");
		return;
	}

	if (info->esd_check_mode == ESD_MODE_REG_CHECK)
		ret = sprd_panel_esd_check(panel);
	else if (info->esd_check_mode == ESD_MODE_TE_CHECK)
		ret = sprd_panel_te_check(panel);
	else if (info->esd_check_mode == ESD_MODE_MIX_CHECK)
		ret = sprd_panel_mix_check(panel);
	else {
		DRM_ERROR("unknown esd check mode:%d\n", info->esd_check_mode);
		return;
	}

	if (himax_mcu_vsn_recovery_flag == 1)//Prevent concurrency
		ret = -EINVAL;

	if ((ret && sprd_check_crtc_active_state(panel, 0)) ||
	(himax_mcu_vsn_recovery_flag && sprd_check_crtc_active_state(panel, 0))){
		const struct drm_encoder_helper_funcs *encoder_funcs;
		const struct drm_connector_helper_funcs *conn_funcs;
		struct drm_encoder *encoder;

		conn_funcs = connector->helper_private;
		encoder = conn_funcs->best_encoder(connector);
		encoder_funcs = encoder->helper_private;
		panel->esd_work_pending = false;

		if (!sprd_check_crtc_active_state(panel, 0)) {
			DRM_INFO("skip esd recovery during panel suspend\n");
			return;
		}
		dpu = dsi->dpu;

		if (vsn_recovery == 1)
			himax_chip_common_suspend_esd();

		DRM_INFO("====== esd recovery start ========\n");
		dpu_dump(&dpu->ctx);
		dsi_dump(&dsi->ctx);
		panel->is_esd_rst = true;
		encoder_funcs->disable(encoder);
		encoder_funcs->enable(encoder);
		panel->is_esd_rst = false;
		if (!panel->esd_work_pending && panel->enabled)
			schedule_delayed_work(&panel->esd_work,
					msecs_to_jiffies(info->esd_check_period));

		/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/06, add for set backlight after esd recovery, begin*/
		if (panel->oled_bdev) {
			DRM_INFO("====== recovery oled backlight ========\n");
			if (panel->oled_bdev->props.brightness) {
				sprd_oled_set_brightness(panel->oled_bdev);
			} else {
				panel->oled_bdev->props.brightness = SPRD_OLED_DEFAULT_BRIGHTNESS;
				sprd_oled_set_brightness(panel->oled_bdev);
			}
		}

		if (vsn_recovery == 1)
		{
			himax_chip_common_resume_esd();
			himax_mcu_vsn_recovery_flag = 0;
		}

		DRM_INFO("======= esd recovery end =========\n");
		panel->esd_count++;
		DRM_INFO("esd_count is %lld\n", panel->esd_count); //end
	} else
		schedule_delayed_work(&panel->esd_work,
			msecs_to_jiffies(info->esd_check_period));
}

static int sprd_panel_gpio_request(struct device *dev,
			struct sprd_panel *panel)
{
	panel->info.avdd_gpio = devm_gpiod_get_optional(dev,
					"avdd", GPIOD_ASIS);
	if (IS_ERR_OR_NULL(panel->info.avdd_gpio))
		DRM_WARN("can't get panel avdd gpio: %ld\n",
				 PTR_ERR(panel->info.avdd_gpio));

	panel->info.avee_gpio = devm_gpiod_get_optional(dev,
					"avee", GPIOD_ASIS);
	if (IS_ERR_OR_NULL(panel->info.avee_gpio))
		DRM_WARN("can't get panel avee gpio: %ld\n",
				 PTR_ERR(panel->info.avee_gpio));

	panel->info.reset_gpio = devm_gpiod_get_optional(dev,
					"reset", GPIOD_ASIS);
	if (IS_ERR_OR_NULL(panel->info.reset_gpio))
		DRM_WARN("can't get panel reset gpio: %ld\n",
				 PTR_ERR(panel->info.reset_gpio));

	return 0;
}

static int of_parse_reset_seq(struct device_node *np,
				struct panel_info *info)
{
	struct property *prop;
	int bytes, rc;
	u32 *p;

	prop = of_find_property(np, "sprd,reset-on-sequence", &bytes);
	if (!prop) {
		DRM_ERROR("sprd,reset-on-sequence property not found\n");
		return -EINVAL;
	}

	p = kzalloc(bytes, GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	rc = of_property_read_u32_array(np, "sprd,reset-on-sequence",
					p, bytes / 4);
	if (rc) {
		DRM_ERROR("parse sprd,reset-on-sequence failed\n");
		kfree(p);
		return rc;
	}

	info->rst_on_seq.items = bytes / 8;
	info->rst_on_seq.timing = (struct gpio_timing *)p;

	prop = of_find_property(np, "sprd,reset-off-sequence", &bytes);
	if (!prop) {
		DRM_ERROR("sprd,reset-off-sequence property not found\n");
		return -EINVAL;
	}

	p = kzalloc(bytes, GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	rc = of_property_read_u32_array(np, "sprd,reset-off-sequence",
					p, bytes / 4);
	if (rc) {
		DRM_ERROR("parse sprd,reset-off-sequence failed\n");
		kfree(p);
		return rc;
	}

	info->rst_off_seq.items = bytes / 8;
	info->rst_off_seq.timing = (struct gpio_timing *)p;

	/* xiazhiping@MULTIMEDIA.DISPLAY.LCD, 2023/05/16, add for HX83108A sequence in time, begin */
	prop = of_find_property(np, "sprd,reset-off-avdd-sequence", &bytes);
	if (!prop) {
		DRM_ERROR("sprd,reset-off-avdd-sequence property not found\n");
		return -EINVAL;
	}

	p = kzalloc(bytes, GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	rc = of_property_read_u32_array(np, "sprd,reset-off-avdd-sequence",
					p, bytes / 4);
	if (rc) {
		DRM_ERROR("parse sprd,reset-off-avdd-sequence failed\n");
		kfree(p);
		return rc;
	}

	info->rst_off_avdd_seq.items = bytes / 8;
	info->rst_off_avdd_seq.timing = (struct gpio_timing *)p;
	//end

	return 0;
}

static int of_parse_buildin_modes(struct panel_info *info,
	struct device_node *lcd_node)
{
	int i, rc, num_timings;
	struct device_node *timings_np;


	timings_np = of_get_child_by_name(lcd_node, "display-timings");
	if (!timings_np) {
		DRM_ERROR("%s: can not find display-timings node\n",
			lcd_node->name);
		return -ENODEV;
	}

	num_timings = of_get_child_count(timings_np);
	if (num_timings == 0) {
		/* should never happen, as entry was already found above */
		DRM_ERROR("%s: no timings specified\n", lcd_node->name);
		goto done;
	}

	info->buildin_modes = kzalloc(sizeof(struct drm_display_mode) *
				num_timings, GFP_KERNEL);

	for (i = 0; i < num_timings; i++) {
		rc = of_get_drm_display_mode(lcd_node,
			&info->buildin_modes[i], NULL, i);
		if (rc) {
			DRM_ERROR("get display timing failed\n");
			goto entryfail;
		}

		info->buildin_modes[i].width_mm = info->mode.width_mm;
		info->buildin_modes[i].height_mm = info->mode.height_mm;
		info->buildin_modes[i].vrefresh = drm_mode_vrefresh(&info->buildin_modes[i]);
	}
	info->num_buildin_modes = num_timings;
	DRM_INFO("info->num_buildin_modes = %d\n", num_timings);
	goto done;

entryfail:
	kfree(info->buildin_modes);
done:
	of_node_put(timings_np);

	return 0;
}

static int of_parse_oled_cmds(struct sprd_oled *oled,
		const void *data, int size)
{
	const struct dsi_cmd_desc *cmds = data;
	struct dsi_cmd_desc *p;
	u16 len;
	int i, total;

	if (cmds == NULL)
		return -EINVAL;

	/*
	 * TODO:
	 * Currently, we only support the same length cmds
	 * for oled brightness level. So we take the first
	 * cmd payload length as all.
	 */
	len = (cmds->wc_h << 8) | cmds->wc_l;
	total =  size / (len + 4);

	p = (struct dsi_cmd_desc *)kzalloc(size, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	memcpy(p, cmds, size);
	for (i = 0; i < total; i++) {
		oled->cmds[i] = p;
		p = (struct dsi_cmd_desc *)(p->payload + len);
	}

	oled->cmds_total = total;
	oled->cmd_len = len + 4;

	return 0;
}
/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 solve cabc dump  start*/
unsigned int flag_bl = 0;
/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 solve cabc dump  end*/


static int map_exp[4096] = {0};
static int oplus_max_normal_brightness =3338;
static void init_global_exp_backlight(void)
{
	int lut_index[41] = {0, 4, 99, 144, 187, 227, 264, 300, 334, 366, 397, 427, 456, 484, 511, 537, 563, 587, 611, 635, 658, 680,
						702, 723, 744, 764, 784, 804, 823, 842, 861, 879, 897, 915, 933, 950, 967, 984, 1000, 1016, 1023};
	int lut_value1[41] = {0, 4, 6, 14, 24, 37, 52, 69, 87, 107, 128, 150, 173, 197, 222, 248, 275, 302, 330, 358, 387, 416, 446,
						477, 507, 539, 570, 602, 634, 667, 700, 733, 767, 801, 835, 869, 903, 938, 973, 1008, 1023};
	int index_start = 0, index_end = 0;
	int value1_start = 0, value1_end = 0;
	int i,j;
	int index_len = sizeof(lut_index) / sizeof(int);
	int value_len = sizeof(lut_value1) / sizeof(int);
	if (index_len == value_len) {
		for (i = 0; i < index_len - 1; i++) {
			index_start = lut_index[i] * oplus_max_normal_brightness / 1023;
			index_end = lut_index[i+1] * oplus_max_normal_brightness / 1023;
			value1_start = lut_value1[i] * oplus_max_normal_brightness / 1023;
			value1_end = lut_value1[i+1] * oplus_max_normal_brightness / 1023;
			for (j = index_start; j <= index_end; j++) {
				map_exp[j] = value1_start + (value1_end - value1_start) * (j - index_start) / (index_end - index_start);
			}
		}
	}
}
static int sprd_oled_set_brightness(struct backlight_device *bdev)
{
	int brightness;
        int bl_map;
	struct sprd_oled *oled = bl_get_data(bdev);
	struct sprd_panel *panel = oled->panel;

	unsigned char oled_add_short_packet[] = {0x05,0x0,0x0,0x01,0x0,0x39,0x0,0x0,0x03,0x51,0x0,0x0};

	mutex_lock(&panel->lock);
	if (!panel->enabled) {
		mutex_unlock(&panel->lock);
		DRM_WARN("oled panel has been powered off\n");
		return -ENXIO;
	}

	brightness = bdev->props.brightness;

	//DRM_INFO("%s brightness: %d\n", __func__, brightness);

/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 solve cabc dump  start*/
	flag_bl = brightness;
/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 solve cabc dump  end*/

    bl_map = brightness;
	if ((brightness > 0) && (brightness < oplus_max_normal_brightness)) {
		bl_map = map_exp[brightness];
	}

	if ((bl_map > 0) && (bl_map < 145)) {
		bl_map = 144;
		DRM_INFO("lowlight %s brightness: %d, bl_map: %d\n", __func__, brightness, bl_map);
	}
	DRM_INFO("%s brightness: %d, bl_map: %d\n", __func__, brightness, bl_map);

	oled_add_short_packet[10] = bl_map >> 8;
	oled_add_short_packet[11] = bl_map & 0xFF;

	sprd_panel_send_cmds(panel->slave,
			     panel->info.cmds[CMD_OLED_REG_LOCK],
			     panel->info.cmds_len[CMD_OLED_REG_LOCK]);

	if(!strcmp(panel->lcd_name, "lcd_hx83108a_boe_mipi_hd") || !strcmp(panel->lcd_name, "lcd_hx83108a_lce_mipi_hd" ) || !strcmp(panel->lcd_name, "lcd_hx83108a_lce_new_mipi_hd" )) {
		sprd_panel_send_cmds(panel->slave, &oled_add_short_packet[0], sizeof(oled_add_short_packet)/sizeof(char));
	} else {
		if (oled->cmds_total == 1) {
			if (oled->cmds[0]->wc_l == 3) {	
			    if(panel->info.use_high_bit == 1) {
			        oled->cmds[0]->payload[1] = (bl_map >> 4)& 0xFF;
			        oled->cmds[0]->payload[2] = bl_map & 0x0F;
			    } else {
				    oled->cmds[0]->payload[1] = bl_map >> 8;
				    oled->cmds[0]->payload[2] = bl_map & 0xFF;
			    }
			} else
				oled->cmds[0]->payload[1] = bl_map;

			sprd_panel_send_cmds(panel->slave,
				     oled->cmds[0],
				     oled->cmd_len);
		} else {
			if (brightness >= oled->cmds_total)
				brightness = oled->cmds_total - 1;

			sprd_panel_send_cmds(panel->slave,
				     oled->cmds[bl_map],
				     oled->cmd_len);
		}
	}

	sprd_panel_send_cmds(panel->slave,
			     panel->info.cmds[CMD_OLED_REG_UNLOCK],
			     panel->info.cmds_len[CMD_OLED_REG_UNLOCK]);

	mutex_unlock(&panel->lock);

	return 0;
}

static const struct backlight_ops sprd_oled_backlight_ops = {
	.update_status = sprd_oled_set_brightness,
};

static int sprd_oled_backlight_init(struct sprd_panel *panel)
{
	struct sprd_oled *oled;
	struct device_node *oled_node;
	struct panel_info *info = &panel->info;
	const void *p;
	int bytes, rc;
	u32 temp;

	oled_node = of_get_child_by_name(info->of_node,
				"oled-backlight");
	if (!oled_node)
		return 0;

	oled = devm_kzalloc(&panel->dev,
			sizeof(struct sprd_oled), GFP_KERNEL);
	if (!oled)
		return -ENOMEM;

	oled->bdev = devm_backlight_device_register(&panel->dev,
			"sprd_backlight", &panel->dev, oled,
			&sprd_oled_backlight_ops, NULL);
	if (IS_ERR(oled->bdev)) {
		DRM_ERROR("failed to register oled backlight ops\n");
		return PTR_ERR(oled->bdev);
	}

	p = of_get_property(oled_node, "brightness-levels", &bytes);
	if (p) {
		info->cmds[CMD_OLED_BRIGHTNESS] = p;
		info->cmds_len[CMD_OLED_BRIGHTNESS] = bytes;
	} else
		DRM_ERROR("can't find brightness-levels property\n");

	p = of_get_property(oled_node, "sprd,reg-lock", &bytes);
	if (p) {
		info->cmds[CMD_OLED_REG_LOCK] = p;
		info->cmds_len[CMD_OLED_REG_LOCK] = bytes;
	} else
		DRM_INFO("can't find sprd,reg-lock property\n");

	p = of_get_property(oled_node, "sprd,reg-unlock", &bytes);
	if (p) {
		info->cmds[CMD_OLED_REG_UNLOCK] = p;
		info->cmds_len[CMD_OLED_REG_UNLOCK] = bytes;
	} else
		DRM_INFO("can't find sprd,reg-unlock property\n");

	rc = of_property_read_u32(oled_node, "default-brightness-level", &temp);
	if (!rc)
		oled->bdev->props.brightness = temp;
	else
		oled->bdev->props.brightness = 25;

	rc = of_property_read_u32(oled_node, "sprd,max-level", &temp);
	if (!rc)
		oled->max_level = temp;
	else
		oled->max_level = 255;

	oled->bdev->props.max_brightness = oled->max_level;
	oled->panel = panel;
	of_parse_oled_cmds(oled,
			panel->info.cmds[CMD_OLED_BRIGHTNESS],
			panel->info.cmds_len[CMD_OLED_BRIGHTNESS]);

	/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/06, add for set backlight after esd recovery */
	panel->oled_bdev = oled->bdev;

	DRM_INFO("%s() ok\n", __func__);

	return 0;
}

int sprd_panel_parse_lcddtb(struct device_node *lcd_node,
	struct sprd_panel *panel)
{
	struct panel_info *info = &panel->info;
	int bytes, rc;
	const void *p;
	const char *str;
	u32 val;

	if (!lcd_node) {
		DRM_ERROR("lcd node from dtb is null\n");
		return -ENODEV;
	}
	info->of_node = lcd_node;

	rc = of_property_read_u32(lcd_node, "sprd,dsi-work-mode", &val);
	if (!rc) {
		if (val == SPRD_DSI_MODE_CMD)
			info->mode_flags = 0;
		else if (val == SPRD_DSI_MODE_VIDEO_BURST)
			info->mode_flags = MIPI_DSI_MODE_VIDEO |
					   MIPI_DSI_MODE_VIDEO_BURST;
		else if (val == SPRD_DSI_MODE_VIDEO_SYNC_PULSE)
			info->mode_flags = MIPI_DSI_MODE_VIDEO |
					   MIPI_DSI_MODE_VIDEO_SYNC_PULSE;
		else if (val == SPRD_DSI_MODE_VIDEO_SYNC_EVENT)
			info->mode_flags = MIPI_DSI_MODE_VIDEO;
	} else {
		DRM_ERROR("dsi work mode is not found! use video mode\n");
		info->mode_flags = MIPI_DSI_MODE_VIDEO |
				   MIPI_DSI_MODE_VIDEO_BURST;
	}

	if (of_property_read_bool(lcd_node, "sprd,dsi-non-continuous-clock"))
		info->mode_flags |= MIPI_DSI_CLOCK_NON_CONTINUOUS;

	rc = of_property_read_u32(lcd_node, "sprd,dsi-lane-number", &val);
	if (!rc)
		info->lanes = val;
	else
		info->lanes = 4;

	rc = of_property_read_u32(lcd_node, "sprd,slice-width", &val);
	if (!rc)
		info->slice_width = val;
	else
		DRM_DEBUG("slice-width is not found!\n");

	rc = of_property_read_u32(lcd_node, "sprd,slice-height", &val);
	if (!rc)
		info->slice_height = val;
	else
		DRM_DEBUG("slice-height is not found!\n");

	rc = of_property_read_u32(lcd_node, "sprd,output-bpc", &val);
	if (!rc)
		info->output_bpc = val;
	else
		DRM_DEBUG("output-bpc is not found!\n");

		rc = of_property_read_u32(lcd_node, "sprd,dsc-enable", &val);
	if (!rc)
		info->dsc_en = val;
	else
		DRM_DEBUG("dsc-enable is not found!\n");

	rc = of_property_read_u32(lcd_node, "sprd,dual-dsi-enable", &val);
	if (!rc)
		info->dual_dsi_en = val;
	else
		DRM_DEBUG("dual-dsi-enable is not found!\n");

	rc = of_property_read_string(lcd_node, "sprd,dsi-color-format", &str);
	if (rc)
		info->format = MIPI_DSI_FMT_RGB888;
	else if (!strcmp(str, "rgb888"))
		info->format = MIPI_DSI_FMT_RGB888;
	else if (!strcmp(str, "rgb666"))
		info->format = MIPI_DSI_FMT_RGB666;
	else if (!strcmp(str, "rgb666_packed"))
		info->format = MIPI_DSI_FMT_RGB666_PACKED;
	else if (!strcmp(str, "rgb565"))
		info->format = MIPI_DSI_FMT_RGB565;
	else if (!strcmp(str, "dsc"))
		info->format = SPRD_MIPI_DSI_FMT_DSC;
	else
		DRM_ERROR("dsi-color-format (%s) is not supported\n", str);

	rc = of_property_read_u32(lcd_node, "sprd,phy-bit-clock", &val);
	if (!rc)
		info->hs_rate = val;
	else
		info->hs_rate = 500000;

	rc = of_property_read_u32(lcd_node, "sprd,phy-escape-clock", &val);
	if (!rc)
		info->lp_rate = val > 20000 ? 20000 : val;
	else
		info->lp_rate = 20000;

	rc = of_property_read_u32(lcd_node, "sprd,width-mm", &val);
	if (!rc)
		info->mode.width_mm = val;
	else
		info->mode.width_mm = 68;

	rc = of_property_read_u32(lcd_node, "sprd,height-mm", &val);
	if (!rc)
		info->mode.height_mm = val;
	else
		info->mode.height_mm = 121;

	rc = of_property_read_u32(lcd_node, "sprd,esd-check-enable", &val);
	if (!rc)
		info->esd_check_en = val;

	rc = of_property_read_u32(lcd_node, "sprd,esd-check-mode", &val);
	if (!rc)
		info->esd_check_mode = val;
	else
		info->esd_check_mode = 1;

	rc = of_property_read_u32(lcd_node, "sprd,esd-check-period", &val);
	if (!rc)
		info->esd_check_period = val;
	else
		info->esd_check_period = 1000;

	rc = of_property_read_u32(lcd_node, "sprd,esd-check-register", &val);
	if (!rc)
		info->esd_check_reg = val;
	else
		info->esd_check_reg = 0x0A;

	rc = of_property_read_u32(lcd_node, "sprd,esd-check-value", &val);
	if (!rc)
		info->esd_check_val = val;
	else
		info->esd_check_val = 0x9C;

	 /* maohesong@MULTIMEDIA.DISPLAY.LCD, 2024/01/25,ft8507p screen set 51 register high 8bit*/
	rc = of_property_read_u32(lcd_node,"sprd,use-high-bit-mode",&val);
	if(!rc)
		info->use_high_bit = val;
	else
		info->use_high_bit = 0;

	if (of_property_read_bool(lcd_node, "sprd,use-dcs-write"))
		info->use_dcs = true;
	else
		info->use_dcs = false;

	rc = of_parse_reset_seq(lcd_node, info);
	if (rc)
		DRM_ERROR("parse lcd reset sequence failed\n");

	/* maohesong@MULTIMEDIA.DISPLAY.LCD, 2024/1/26, add for pre_avdd_rst_on_seq reset_sequence start*/
	rc = of_property_read_u32(lcd_node,"sprd,ft8057-sequence",&val);
	if(!rc)
		info->ft8057_sequence_enable = val;
	else
		info->ft8057_sequence_enable = 0;

	/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/13, add for lcm bias set */
	p = of_get_property(lcd_node, "sprd,power-i2c-val", &bytes);
	if (p) {
		of_property_read_u8_array(lcd_node,"sprd,power-i2c-val",bias_lcd,bytes);
		DRM_INFO("[lcm] sprd,power-i2c-val bias_lcd[0]=0x%02x; bias_lcd[1]=0x%02x; bias_lcd[2]=0x%02x; bytes=%d\n", bias_lcd[0], bias_lcd[1], bias_lcd[2], bytes);
	} else
		DRM_ERROR("[lcm] can't find sprd,power-i2c-val property\n");

	p = of_get_property(lcd_node, "sprd,initial-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_INIT] = p;
		info->cmds_len[CMD_CODE_INIT] = bytes;
	} else
		DRM_ERROR("can't find sprd,init-command property\n");

	p = of_get_property(lcd_node, "sprd,sleep-in-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_SLEEP_IN] = p;
		info->cmds_len[CMD_CODE_SLEEP_IN] = bytes;
	} else
		DRM_ERROR("can't find sprd,sleep-in-command property\n");

	/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/04/07, add for HX83108A sequence in time, begin */
	rc = of_property_read_u32(lcd_node, "sprd,himax-sequence", &val);
	if (!rc)
		info->himax_sequence = val;
	else
		info->himax_sequence = 0;

	p = of_get_property(lcd_node, "sprd,sleep-in-command-gesture-off", &bytes);
	if (p) {
		info->cmds[CMD_CODE_SLEEP_IN_GESTURE_OFF] = p;
		info->cmds_len[CMD_CODE_SLEEP_IN_GESTURE_OFF] = bytes;
	} else
		DRM_ERROR("[lcm] can't find sprd,sleep-in-command-gesture-off property\n"); //end

	p = of_get_property(lcd_node, "sprd,sleep-out-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_SLEEP_OUT] = p;
		info->cmds_len[CMD_CODE_SLEEP_OUT] = bytes;
	} else
		DRM_ERROR("can't find sprd,sleep-out-command property\n");

	p = of_get_property(lcd_node, "sprd,doze-in-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_DOZE_IN] = p;
		info->cmds_len[CMD_CODE_DOZE_IN] = bytes;
	} else
		DRM_INFO("can't find sprd,doze-in-command property\n");

	p = of_get_property(lcd_node, "sprd,doze-out-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_DOZE_OUT] = p;
		info->cmds_len[CMD_CODE_DOZE_OUT] = bytes;
	} else
		DRM_INFO("can't find sprd,doze-out-command property\n");

/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 add cabc func  start*/
	p = of_get_property(lcd_node, "sprd,cabc-off-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_CABC_OFF] = p;
		info->cmds_len[CMD_CODE_CABC_OFF] = bytes;
	} else
		DRM_ERROR("can't find sprd,cabc-off-command property\n");

	p = of_get_property(lcd_node, "sprd,cabc-ui-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_CABC_UI] = p;
		info->cmds_len[CMD_CODE_CABC_UI] = bytes;
	} else
		DRM_ERROR("can't find sprd,cabc-ui-command property\n");

	p = of_get_property(lcd_node, "sprd,cabc-still-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_CABC_STILL] = p;
		info->cmds_len[CMD_CODE_CABC_STILL] = bytes;
	} else
		DRM_ERROR("can't find sprd,cabc-still-command property\n");

	p = of_get_property(lcd_node, "sprd,cabc-moving-command", &bytes);
	if (p) {
		info->cmds[CMD_CODE_CABC_MOVING] = p;
		info->cmds_len[CMD_CODE_CABC_MOVING] = bytes;
	} else
		DRM_ERROR("can't find sprd,cabc-moving-command property\n");
/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 add cabc func  end*/

	rc = of_get_drm_display_mode(lcd_node, &info->mode, 0,
				     OF_USE_NATIVE_MODE);
	if (rc) {
		DRM_ERROR("get display timing failed\n");
		return rc;
	}

	info->mode.vrefresh = drm_mode_vrefresh(&info->mode);
	of_parse_buildin_modes(info, lcd_node);

	return 0;
}

static int sprd_panel_parse_dt(struct device_node *np, struct sprd_panel *panel)
{
	struct device_node *lcd_node, *cmdline_node;
	const char *cmd_line, *lcd_name_p;
	char lcd_path[60];
	int rc;

	cmdline_node = of_find_node_by_path("/chosen");
	rc = of_property_read_string(cmdline_node, "bootargs", &cmd_line);
	if (!rc) {
		lcd_name_p = strstr(cmd_line, "lcd_name=");
		if (lcd_name_p) {
			sscanf(lcd_name_p, "lcd_name=%s", panel->lcd_name);
			DRM_INFO("lcd name: %s\n", panel->lcd_name);
		}
	} else {
		DRM_ERROR("can't not parse bootargs property\n");
		return rc;
	}

	sprintf(lcd_path, "/lcds/%s", panel->lcd_name);
	lcd_node = of_find_node_by_path(lcd_path);
	if (!lcd_node) {
		DRM_ERROR("%pOF: could not find %s node\n", np, panel->lcd_name);
		return -ENODEV;
	}
	rc = sprd_panel_parse_lcddtb(lcd_node, panel);
	if (rc)
		return rc;

	return 0;
}

/* yizhou 2023/3/25 add for shutdown enter normal down-current logic start */
static int lcd_vsn_reset_notify_callback(struct notifier_block *np, unsigned long type, void *_unused)
{
    struct sprd_panel *panel = container_of(np,struct sprd_panel, lcd_vsn_reset_nb);

    switch (type) {
    case SYS_DOWN:case SYS_POWER_OFF:
        {
	DRM_INFO("reboot_notify : SYS_POWER_OFF/SYS_DOWN !\n");

        DRM_INFO("lcd_vsn_reset_notify_callback,tp_gesture = %d\n",tp_gesture);
        if (tp_gesture == 1)
        {
            tp_gesture = 0;
            /* xiazhiping  2023/5/19 add for avoid powering off the LCM in advance when shutting down, start */
            if(!panel->enabled)
            {
            sprd_panel_unprepare(&panel->base);
            DRM_INFO("reboot_notify : lcd_vsn_reset_notify_callback,tp_gesture = %d  panel->enabled=false\n",tp_gesture);
            }else{
            DRM_INFO("reboot_notify : tp_gesture = %d panel->enabled=true\n",tp_gesture);
            }//end
        }
        break;
        }

    case SYS_HALT:
        DRM_INFO("reboot_notify : SYS_HALT !\n");
        break;

    default:
        DRM_INFO("reboot_notify : default !\n");
        break;
    }
    return NOTIFY_OK;
}

static struct notifier_block lcd_vsn_reset_notifier = {
    .notifier_call = lcd_vsn_reset_notify_callback,
    .priority = 128,
};
/* yizhou 2023/3/25 add for shutdown enter normal down-current logic end */

static int sprd_panel_device_create(struct device *parent,
				    struct sprd_panel *panel)
{
	panel->dev.class = display_class;
	panel->dev.parent = parent;
	panel->dev.of_node = panel->info.of_node;
	dev_set_name(&panel->dev, "panel0");
	dev_set_drvdata(&panel->dev, panel);

	return device_register(&panel->dev);
}

static int sprd_panel_probe(struct mipi_dsi_device *slave)
{
	struct sprd_panel *panel;
	struct device_node *bl_node;
	int ret;
	char *bootmode = NULL;

	DRM_INFO("sprd_panel_probe start!\n");
	panel = devm_kzalloc(&slave->dev, sizeof(*panel), GFP_KERNEL);
	if (!panel)
		return -ENOMEM;

/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 add cabc func  start*/
	p = panel;
/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/1/30 add cabc func  end*/

	bl_node = of_parse_phandle(slave->dev.of_node,
					"sprd,backlight", 0);
	if (bl_node) {
		panel->backlight = of_find_backlight_by_node(bl_node);
		of_node_put(bl_node);

		if (panel->backlight) {
			panel->backlight->props.state &= ~BL_CORE_FBBLANK;
			panel->backlight->props.power = FB_BLANK_UNBLANK;
			backlight_update_status(panel->backlight);
		} else {
			DRM_WARN("backlight is not ready, panel probe deferred\n");
			return -EPROBE_DEFER;
		}
	} else
		DRM_WARN("backlight node not found\n");

	panel->supply = devm_regulator_get(&slave->dev, "power");
	if (IS_ERR(panel->supply)) {
		if (PTR_ERR(panel->supply) == -EPROBE_DEFER)
			DRM_ERROR("regulator driver not initialized, probe deffer\n");
		else
			DRM_ERROR("can't get regulator: %ld\n", PTR_ERR(panel->supply));

		return PTR_ERR(panel->supply);
	}

	INIT_DELAYED_WORK(&panel->esd_work, sprd_panel_esd_work_func);

	ret = sprd_panel_parse_dt(slave->dev.of_node, panel);
	if (ret) {
		DRM_ERROR("parse panel info failed\n");
		return ret;
	}

	ret = sprd_panel_gpio_request(&slave->dev, panel);
	if (ret) {
		DRM_WARN("gpio is not ready, panel probe deferred\n");
		return -EPROBE_DEFER;
	}

	ret = sprd_panel_device_create(&slave->dev, panel);
	if (ret)
		return ret;

	ret = sprd_oled_backlight_init(panel);
	if (ret)
		return ret;

	panel->base.dev = &panel->dev;
	panel->base.funcs = &sprd_panel_funcs;
	drm_panel_init(&panel->base);

	ret = drm_panel_add(&panel->base);
	if (ret) {
		DRM_ERROR("drm_panel_add() failed\n");
		return ret;
	}

	slave->lanes = panel->info.lanes;
	slave->format = panel->info.format;
	slave->hs_rate = panel->info.hs_rate;
	slave->lp_rate = panel->info.lp_rate;
	slave->mode_flags = panel->info.mode_flags;

	ret = mipi_dsi_attach(slave);
	if (ret) {
		DRM_ERROR("failed to attach dsi panel to host\n");
		drm_panel_remove(&panel->base);
		return ret;
	}
	panel->slave = slave;

	ret = sprd_panel_sysfs_init(&panel->dev);
	if (ret)
		return ret;
	/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/2/9 add cabc func start*/
	ret = oplus_display_private_api_init(&panel->dev);
	if (ret)
		return ret;
	/* xiazhiping@MULTIMEDIA.DISPLAY.LCD  2023/2/9 add cabc func end*/
	mipi_dsi_set_drvdata(slave, panel);

	/*
	 * FIXME:
	 * The esd check work should not be scheduled in probe
	 * function. It should be scheduled in the enable()
	 * callback function. But the dsi encoder will not call
	 * drm_panel_enable() the first time in encoder_enable().
	 */
	if (panel->info.esd_check_en) {
		schedule_delayed_work(&panel->esd_work,
				      msecs_to_jiffies(2000));
		panel->esd_work_pending = true;
	}

	/* panzhibin@MULTIMEDIA.DISPLAY.LCD, 2023/02/18, add for silence mode */
	search_str("androidboot.mode=", &bootmode);
	printk("[lcm] bootmode from uboot: %s\n", bootmode);

	if (bootmode != NULL) {
		if (!strcmp(bootmode, "silent")) {
			panel->enabled = false;
		} else {
			panel->enabled = true;
		}
	}
	init_global_exp_backlight();

	/* yizhou 2023/3/25 add for shutdown enter normal down-current logic start */
	panel->lcd_vsn_reset_nb = lcd_vsn_reset_notifier;
	register_reboot_notifier(&panel->lcd_vsn_reset_nb);
	/* yizhou 2023/3/25 add for shutdown enter normal down-current logic start */

	mutex_init(&panel->lock);
	DRM_INFO("sprd_panel_probe start!!!\n");
	return 0;
}

static int sprd_panel_remove(struct mipi_dsi_device *slave)
{
	struct sprd_panel *panel = mipi_dsi_get_drvdata(slave);
	int ret;

	DRM_INFO("%s() start!\n", __func__);

	sprd_panel_disable(&panel->base);
	sprd_panel_unprepare(&panel->base);

	ret = mipi_dsi_detach(slave);
	if (ret < 0)
		DRM_ERROR("failed to detach from DSI host: %d\n", ret);
	/* yizhou 2023/3/25 add for shutdown enter normal down-current logic start */
	unregister_reboot_notifier(&panel->lcd_vsn_reset_nb);
	/* yizhou 2023/3/25 add for shutdown enter normal down-current logic start */
	drm_panel_detach(&panel->base);
	drm_panel_remove(&panel->base);
	DRM_INFO("%s() end!\n", __func__);
	return 0;
}

static const struct of_device_id panel_of_match[] = {
	{ .compatible = "sprd,generic-mipi-panel", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, panel_of_match);

struct mipi_dsi_driver sprd_panel_driver = {
	.driver = {
		.name = "sprd-mipi-panel-drv",
		.of_match_table = panel_of_match,
	},
	.probe = sprd_panel_probe,
	.remove = sprd_panel_remove,
};

MODULE_AUTHOR("Leon He <leon.he@unisoc.com>");
MODULE_AUTHOR("Kevin Tang <kevin.tang@unisoc.com>");
MODULE_DESCRIPTION("UNISOC MIPI DSI Panel Driver");
MODULE_LICENSE("GPL v2");
