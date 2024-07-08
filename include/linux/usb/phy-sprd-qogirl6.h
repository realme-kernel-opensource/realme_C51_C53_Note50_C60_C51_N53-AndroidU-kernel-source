/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 Spreadtrum Communications Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __SPRD_PHY_QOGIRL6_H__
#define __SPRD_PHY_QOGIRL6_H__


#if IS_ENABLED(CONFIG_SPRD_QOGIRL6_USB2_PHY)
extern int sprd_hsphy_set_dpdm_high_impedance_state(void);
extern int sprd_hsphy_cancel_dpdm_high_impedance_state(void);
#else
static inline int sprd_hsphy_set_dpdm_high_impedance_state(void)
{
	return 0;
}
static inline int sprd_hsphy_cancel_dpdm_high_impedance_state(void)
{
	return 0;
}
#endif /* IS_ENABLED(CONFIG_SPRD_QOGIRL6_USB2_PHY) */

#endif /* __LINUX_USB_SPRD_PHY_H */