
#ifndef __SGM4154x_HEADER__
#define __SGM4154x_HEADER__

/* Register 00h */
#define SGM4154x_REG_00				0x00	/*REG00, OK*/
#define SGM4154x_ENHIZ_MASK		    0x80	/*D[7]*/
#define SGM4154x_ENHIZ_SHIFT		7
#define SGM4154x_HIZ_ENABLE         1
#define SGM4154x_HIZ_DISABLE        0

#define SGM4154x_IINLIM_MASK		0x1F  	/*D[4:0]*/
#define SGM4154x_IINLIM_SHIFT		0
#define SGM4154x_IINLIM_BASE        100
#define SGM4154x_IINLIM_LSB         100

/* Register 0x03 */
#define SGM4154x_REG_03              0x01		/*REG01*/
#define SGM4154x_BAT_VOKOTG_EN_MASK   0x20
#define SGM4154x_BAT_VOKOTG_EN_SHIFT  5

#define SGM4154x_WDT_RESET_MASK      0x40		/*D[6]*/
#define SGM4154x_WDT_RESET_SHIFT     6
#define SGM4154x_WDT_RESET           1

#define SGM4154x_OTG_CONFIG_MASK     0x20		/*D[5]*/
#define SGM4154x_OTG_CONFIG_SHIFT    5
#define SGM4154x_OTG_ENABLE          1
#define SGM4154x_OTG_DISABLE         0

#define SGM4154x_CHG_CONFIG_MASK     0x10		/*D[4]*/
#define SGM4154x_CHG_CONFIG_SHIFT    4
#define SGM4154x_CHG_ENABLE          1
#define SGM4154x_CHG_DISABLE         0


#define SGM4154x_SYS_MINV_MASK       0x0E		/*D[3:1]*/
#define SGM4154x_SYS_MINV_SHIFT      1
#define SGM4154x_SYS_MINV_LIMIT      4

#define SGM4154x_SYS_MINV_BASE       2600
#define SGM4154x_SYS_MINV_LSB        200


/* Register 0x04*/
#define SGM4154x_REG_04              0x02		/*REG02*/
#define SGM4154x_EN_PUMPX_MASK       0x80		/*D[7]*/
#define SGM4154x_EN_PUMPX_SHIFT      7
#define SGM4154x_PUMPX_ENABLE        1
#define SGM4154x_PUMPX_DISABLE       0
#define SGM4154x_ICHG_MASK           0x7F		/*D[5:0]*/
#define SGM4154x_ICHG_SHIFT          0
#define SGM4154x_ICHG_BASE           0
#define SGM4154x_ICHG_LSB            60

/* Register 0x05*/
#define SGM4154x_REG_05              0x03		/*REG03*/
#define SGM4154x_IPRECHG_MASK        0xF0		/*D[7:4]*/
#define SGM4154x_IPRECHG_SHIFT       4
#define SGM4154x_ITERM_MASK          0x0F		/*D[3:0]*/
#define SGM4154x_ITERM_SHIFT         0
#define SGM4154x_IPRECHG_BASE        60
#define SGM4154x_IPRECHG_LSB         60
#define SGM4154x_ITERM_BASE          60
#define SGM4154x_ITERM_LSB           60

/* Register 0x06*/
#define SGM4154x_REG_06              0x04		/*REG04*/
#define SGM4154x_VREG_MASK           0xF8		/*D[7:3]*/
#define SGM4154x_VREG_SHIFT          3
#define SGM4154x_VRECHG_MASK         0x01		/*D[0]*/
#define SGM4154x_VRECHG_SHIFT        0
#define SGM4154x_VRECHG_100MV        0
#define SGM4154x_VRECHG_200MV        1
#define SGM4154x_VREG_BASE           3856
#define SGM4154x_VREG_LSB            32

/* Register 0x07*/
#define SGM4154x_REG_07              0x05
#define SGM4154x_EN_TERM_MASK        0x80
#define SGM4154x_EN_TERM_SHIFT       7
#define SGM4154x_TERM_ENABLE         1
#define SGM4154x_TERM_DISABLE        0

#define SGM4154x_WDT_MASK            0x30
#define SGM4154x_WDT_SHIFT           4
#define SGM4154x_WDT_DISABLE         0
#define SGM4154x_WDT_40S             1
#define SGM4154x_WDT_80S             2
#define SGM4154x_WDT_160S            3
#define SGM4154x_WDT_BASE            0
#define SGM4154x_WDT_LSB             40

#define SGM4154x_EN_TIMER_MASK       0x08
#define SGM4154x_EN_TIMER_SHIFT      3

#define SGM4154x_CHG_TIMER_ENABLE    1
#define SGM4154x_CHG_TIMER_DISABLE   0

#define SGM4154x_CHG_TIMER_MASK      0x04		/*D[2]*/
#define SGM4154x_CHG_TIMER_SHIFT     2
#define SGM4154x_CHG_TIMER_5HOURS    0			/*5hrs*/
#define SGM4154x_CHG_TIMER_8HOURS    1			/*12hrs*/


#define SGM4154x_JEITA_ISET_MASK     0x01
#define SGM4154x_JEITA_ISET_SHIFT    0
#define SGM4154x_JEITA_ISET_50PCT    0
#define SGM4154x_JEITA_ISET_20PCT    1


/* Register 0x09*/
#define SGM4154x_REG_09              0x07
#define SGM4154x_FORCE_ICO_MASK      0x80
#define SGM4154x_FORCE_ICO_SHIFT     7
#define SGM4154x_FORCE_ICO           1
#define SGM4154x_TMR2X_EN_MASK       0x40
#define SGM4154x_TMR2X_EN_SHIFT      6
#define SGM4154x_BATFET_DIS_MASK     0x20
#define SGM4154x_BATFET_DIS_SHIFT    5
#define SGM4154x_BATFET_OFF          1
#define SGM4154x_BATFET_ON			0

/* Register 0x0A*/
#define SGM4154x_REG_0A              0x06
#define SGM4154x_BOOSTV_MASK         0x30
#define SGM4154x_BOOSTV_DEFAULT         0x02



#define SGM4154x_BOOST_LIM_MASK      0x07
#define SGM4154x_BOOST_LIM_SHIFT     0
#define SGM4154x_BOOST_LIM_500MA     0x00
#define SGM4154x_BOOST_LIM_750MA     0x01
#define SGM4154x_BOOST_LIM_1200MA    0x02
#define SGM4154x_BOOST_LIM_1400MA    0x03
#define SGM4154x_BOOST_LIM_1650MA    0x04
#define SGM4154x_BOOST_LIM_1875MA    0x05
#define SGM4154x_BOOST_LIM_2150MA    0x06
#define SGM4154x_BOOST_LIM_2450MA    0x07


/* Register 0x0B*/
#define SGM4154x_REG_0B              0x08
#define SGM4154x_VBUS_STAT_MASK      0xE0
#define SGM4154x_VBUS_STAT_SHIFT     5
#define SGM4154x_VBUS_TYPE_NONE		0
#define SGM4154x_VBUS_TYPE_SDP		1
#define SGM4154x_VBUS_TYPE_CDP		2
#define SGM4154x_VBUS_TYPE_DCP		3
#define SGM4154x_VBUS_TYPE_HVDCP		4
#define SGM4154x_VBUS_TYPE_UNKNOWN	5
#define SGM4154x_VBUS_TYPE_NON_STD	6
#define SGM4154x_VBUS_TYPE_OTG		7

#define SGM4154x_CHRG_STAT_MASK      0x18
#define SGM4154x_CHRG_STAT_SHIFT     3
#define SGM4154x_CHRG_STAT_IDLE      0
#define SGM4154x_CHRG_STAT_PRECHG    1
#define SGM4154x_CHRG_STAT_FASTCHG   2
#define SGM4154x_CHRG_STAT_CHGDONE   3

#define SGM4154x_PG_STAT_MASK        0x04
#define SGM4154x_PG_STAT_SHIFT       2
#define SGM4154x_SDP_STAT_MASK       0x02
#define SGM4154x_SDP_STAT_SHIFT      1
#define SGM4154x_VSYS_STAT_MASK      0x01
#define SGM4154x_VSYS_STAT_SHIFT     0


/* Register 0x0C*/
#define SGM4154x_REG_0C              0x09
#define SGM4154x_FAULT_WDT_MASK      0x80
#define SGM4154x_FAULT_WDT_SHIFT     7
#define SGM4154x_FAULT_BOOST_MASK    0x40
#define SGM4154x_FAULT_BOOST_SHIFT   6
#define SGM4154x_FAULT_CHRG_MASK     0x30
#define SGM4154x_FAULT_CHRG_SHIFT    4
#define SGM4154x_FAULT_CHRG_NORMAL   0
#define SGM4154x_FAULT_CHRG_INPUT    1
#define SGM4154x_FAULT_CHRG_THERMAL  2
#define SGM4154x_FAULT_CHRG_TIMER    3

#define SGM4154x_FAULT_BAT_MASK      0x08
#define SGM4154x_FAULT_BAT_SHIFT     3
#define SGM4154x_FAULT_NTC_MASK      0x07
#define SGM4154x_FAULT_NTC_SHIFT     0
#define SGM4154x_FAULT_NTC_TSCOLD    1
#define SGM4154x_FAULT_NTC_TSHOT     2

#define SGM4154x_FAULT_NTC_WARM      2
#define SGM4154x_FAULT_NTC_COOL      3
#define SGM4154x_FAULT_NTC_COLD      5
#define SGM4154x_FAULT_NTC_HOT       6


/* Register 0x0D*/
#define SGM4154x_REG_0D              0x06
#define SGM4154x_VINDPM_MASK         0x0F
#define SGM4154x_VINDPM_SHIFT        0

#define SGM4154x_VINDPM_BASE         3900
#define SGM4154x_VINDPM_LSB          100


/* Register 0x0E*/
#define SGM4154x_REG_0E              0x0E
#define SGM4154x_THERM_STAT_MASK     0x80
#define SGM4154x_THERM_STAT_SHIFT    7
#define SGM4154x_BATV_MASK           0x7F
#define SGM4154x_BATV_SHIFT          0
#define SGM4154x_BATV_BASE           2304
#define SGM4154x_BATV_LSB            20


/* Register 0x0F*/
#define SGM4154x_REG_0F              0x0F
#define SGM4154x_SYSV_MASK           0x7F
#define SGM4154x_SYSV_SHIFT          0
#define SGM4154x_SYSV_BASE           2304
#define SGM4154x_SYSV_LSB            20


/* Register 0x10*/
#define SGM4154x_REG_10              0x10
#define SGM4154x_TSPCT_MASK          0x7F
#define SGM4154x_TSPCT_SHIFT         0
#define SGM4154x_TSPCT_BASE          21
#define SGM4154x_TSPCT_LSB           465

/* Register 0x11*/
#define SGM4154x_REG_11              0x0A
#define SGM4154x_VBUS_GD_MASK        0x80
#define SGM4154x_VBUS_GD_SHIFT       7
#define SGM4154x_VBUSV_MASK          0x7F
#define SGM4154x_VBUSV_SHIFT         0
#define SGM4154x_VBUSV_BASE          2600
#define SGM4154x_VBUSV_LSB           100


/* Register 0x12*/
#define SGM4154x_REG_12              0x12
#define SGM4154x_ICHGR_MASK          0x7F
#define SGM4154x_ICHGR_SHIFT         0
#define SGM4154x_ICHGR_BASE          0
#define SGM4154x_ICHGR_LSB           50


/* Register 0x13*/
#define SGM4154x_REG_13              0x13
#define SGM4154x_VDPM_STAT_MASK      0x80
#define SGM4154x_VDPM_STAT_SHIFT     7
#define SGM4154x_IDPM_STAT_MASK      0x40
#define SGM4154x_IDPM_STAT_SHIFT     6
#define SGM4154x_IDPM_LIM_MASK       0x3F
#define SGM4154x_IDPM_LIM_SHIFT      0
#define SGM4154x_IDPM_LIM_BASE       100
#define SGM4154x_IDPM_LIM_LSB        50


/* Register 0x14*/
#define SGM4154x_REG_14              0x0B
#define SGM4154x_RESET_MASK          0x80
#define SGM4154x_RESET_SHIFT         7
#define SGM4154x_RESET               1
#define SGM4154x_ICO_OPTIMIZED_MASK  0x40
#define SGM4154x_ICO_OPTIMIZED_SHIFT 6
#define SGM4154x_PN_MASK             0x78
#define SGM4154x_PN_SHIFT            3
#define SGM4154x_TS_PROFILE_MASK     0x04
#define SGM4154x_TS_PROFILE_SHIFT    2
#define SGM4154x_DEV_REV_MASK        0x03
#define SGM4154x_DEV_REV_SHIFT       0

extern int opchg_get_real_charger_type(void);

#endif
