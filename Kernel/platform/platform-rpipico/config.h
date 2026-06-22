#ifndef CONFIG_H
#define CONFIG_H
#include "tusb_config.h"
/*
 * Set this according to your SD card pins
 *  CONFIG_RC2040
 *      SCK GPIO 14
 *      TX  GPIO 15
 *      RX  GPIO 12
 *      CS  GPIO 13
 *  CONFIG_MAKER_PI
 *	    SCK GPIO 10
 *	    TX  GPIO 11
 *	    RX  GPIO 12
 *	    CS  GPIO 15
 *  CONFIG_PICOCALC
 *	    SCK GPIO 18
 *	    TX  GPIO 19
 *	    RX  GPIO 16
 *	    CS  GPIO 17
 *  If Undefined
 *      SCK GPIO 2
 *      TX  GPIO 3
 *      RX  GPIO 4
 *      CS  GPIO 5
 *
 * The board variant is normally supplied by the build (the BOARD make
 * variable, passed through CMake as -DFUZIX_BOARD=...). If nothing was
 * supplied we default to the RC2040 pin mapping below.
 */

#if !defined(CONFIG_RC2040) && !defined(CONFIG_MAKER_PI) && !defined(CONFIG_PICOCALC)
#define CONFIG_RC2040
#endif

/* We have a GPIO interface */
#define CONFIG_DEV_GPIO
/* Enable to make ^Z dump the inode table for debug */
#undef CONFIG_IDUMP
/* Enable to make ^A drop back into the monitor */
#undef CONFIG_MONITOR
/* Enable to support network stack.
 * CONFIG_NET_CYW43 is set by CMakeLists.txt when PICO_BOARD ends with _w
 * (i.e. pico_w or pico2_w).  Do not set CONFIG_NET_NATIVE – that is for
 * the user-space daemon approach used on other platforms.
 */
#if defined(CONFIG_NET_CYW43)
#define CONFIG_NET
#else
#undef CONFIG_NET
#endif
#undef CONFIG_NET_NATIVE
/* Profil syscall support (not yet complete) */
#undef CONFIG_PROFIL
/* Multiple processes in memory at once */
#define CONFIG_MULTI
/* 32bit with flat memory */
#undef CONFIG_FLAT
/* Pure swap */
#define CONFIG_BANKS 1
/* brk() calls pagemap_realloc() to get more memory. */
#define CONFIG_BRK_CALLS_REALLOC
/* Inlined irq handling */
#define CONFIG_INLINE_IRQ
/* Trim disk blocks when no longer used */
#define CONFIG_TRIM
/* Enable single tasking */
#define CONFIG_SWAP_ONLY
#define CONFIG_SPLIT_UDATA
/* Enable SD card code. */
#define CONFIG_SD
#define SD_DRIVE_COUNT 1
/* Enable dynamic swap. */
#define CONFIG_PLATFORM_SWAPCTL
/* Platform manages process brk. */
#define CONFIG_PLATFORM_BRK
/* Platform IOCTL on /dev/sys (maj:min)(4:6) */
#define CONFIG_DEV_PLATFORM

#define CONFIG_32BIT
#define CONFIG_USERMEM_DIRECT

#ifdef CONFIG_PICOCALC
/*
 * PicoCalc has an on-board ILI9488-class LCD and an STM32 keyboard on I2C,
 * so it gets a real VT console driven by the shared Kernel/vt.c code path
 * (see devlcd.c / devkbd.c). Everything below is PicoCalc-only.
 */
#define CONFIG_VT
#define CONFIG_FONT8X8

/* 320x320 panel, 8x8 cells -> 40x40 character console.
 * TODO: confirm the exact panel resolution against the PicoCalc schematic. */
#define VT_WIDTH	40
#define VT_HEIGHT	40
#define VT_RIGHT	(VT_WIDTH - 1)
#define VT_BOTTOM	(VT_HEIGHT - 1)

/* ILI9488 LCD on SPI. TODO: confirm pins/controller against schematic. */
#define LCD_SPI_MOD	spi1
#define LCD_PIN_SCK	10
#define LCD_PIN_TX	11	/* MOSI */
#define LCD_PIN_RX	12	/* MISO */
#define LCD_PIN_CS	13
#define LCD_PIN_DC	14	/* data/command */
#define LCD_PIN_RST	15	/* reset */

/* STM32 keyboard controller on I2C. TODO: confirm bus/pins/address. */
#define KBD_I2C_MOD	i2c1
#define KBD_PIN_SDA	6
#define KBD_PIN_SCL	7
#define KBD_I2C_ADDR	0x1F
#define KBD_I2C_BAUD	100000

/* One extra TTY for the on-board LCD+keyboard console. */
#define NUM_DEV_TTY_LCD	1
#else
/* Serial TTY only, no VT or font. */
#undef CONFIG_VT
#undef CONFIG_FONT8X8
#define NUM_DEV_TTY_LCD	0
#endif

/* Built in NAND flash. Warning, it's unstable. */
#define CONFIG_PICO_FLASH

/* Program layout */

#define UDATA_BLKS  3
#define UDATA_SIZE  (UDATA_BLKS << BLKSHIFT)

#define TOTALMEM 160
#if TOTALMEM == 0
#error TOTALMEM should have been defined via cmake
#endif
#define NETMEM 0

#ifdef CONFIG_NET
#undef NETMEM
#define NETMEM 10
#endif

#define USERMEM ((TOTALMEM-NETMEM)*1024)

#define PROGSIZE (65536 - UDATA_SIZE)
extern uint8_t progbase[USERMEM];
#define udata (*(struct u_data*)progbase)

#define USERSTACK (4*1024) /* 4kB */

#define CONFIG_CUSTOM_VALADDR
#define PROGBASE ((uaddr_t)&progbase[0])
#define PROGLOAD ((uaddr_t)&progbase[UDATA_SIZE])
#define PROGTOP (PROGLOAD + PROGSIZE)
#define SWAPBASE PROGBASE
#define SWAPTOP (PROGBASE + (uaddr_t)alignup(udata.u_break - PROGBASE, 1<<BLKSHIFT)) /* never swap in/out data above break */
#define SWAP_SIZE   ((PROGSIZE >> BLKSHIFT) + UDATA_BLKS)
#define MAX_SWAPS   (2048*2 / SWAP_SIZE) /* for a 2MB swap partition */

#define BOOT_TTY (512 + 1)   /* Set this to default device for stdio, stderr */
                          /* In this case, the default is the first TTY device */

#define TICKSPERSEC 200   /* Ticks per second */
/* 
 * Boot cmd line.
 * [BOOTDEVICE] [tty=<TTYLIST>]
 * 
 * <BOOTDEVICE> - use `hda` for built-in flash or `hdbX` for SD card, where X is partition number
 * <TTYLIST> - list of TTY devices in order. If not specified system will
 *      map USB devices to tty1-4 and UART0 to tty5 if USB is connected. Or UART0 to tty1 etc if not.
 *      Example: `tty=usb1,uart1,usb2`
*/
#define CMDLINE	NULL	  /* Location of root dev name */

#define BOOTDEVICENAMES "hd#"
#define SWAPDEV    (swap_dev) /* dynamic swap */

/* Device parameters */
#define NUM_DEV_TTY_UART 1 /* min 1 max 2*/
#define DEV_UART_0_TX_PIN PICO_DEFAULT_UART_TX_PIN
#define DEV_UART_0_RX_PIN PICO_DEFAULT_UART_RX_PIN
#define DEV_UART_1_TX_PIN 6
#define DEV_UART_1_RX_PIN 7
#define DEV_UART_1_CTS_PIN 8
#define DEV_UART_1_RTS_PIN 9
#define NUM_DEV_TTY_USB 4 /* min 1 max 4. */
#define NUM_DEV_TTY (NUM_DEV_TTY_UART + NUM_DEV_TTY_USB + NUM_DEV_TTY_LCD)
#define DEV_USB_DETECT_TIMEOUT 5000 /* (ms) Total timeout time to detect USB host connection*/
#define DEV_USB_INIT_TIMEOUT 2000 /* (ms) Total timeout to try not swallow messages */

#define TTYDEV   BOOT_TTY /* Device used by kernel for messages, panics */
#define NBUFS    20       /* Number of block buffers */
#define NMOUNTS	 4	  /* Number of mounts at a time */

#define MAX_BLKDEV	4

#define CONFIG_SMALL

#define plt_copyright() /* */
#define swap_map(x) ((uint8_t*)(x))

/* Prevent name clashes wish the Pico SDK */

#define MANGLED 1
#include "mangle.h"

#endif
// vim: sw=4 ts=4 et

