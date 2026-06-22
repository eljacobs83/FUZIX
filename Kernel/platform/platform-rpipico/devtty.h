#ifndef __DEVTTY_DOT_H__
#define __DEVTTY_DOT_H__

#include <stdint.h>
#include <tty.h>

struct ttydriver
{
    void (*putc)(uint8_t devn, uint8_t c);
    ttyready_t (*ready)(uint8_t devn);
    void (*sleeping)(uint8_t devn);
    int (*getc)(uint8_t devn);
    void (*setup)(uint_fast8_t minor, uint_fast8_t devn, uint_fast8_t flags);
};

struct ttymap
{
    uint8_t tty;
    uint8_t drv;
};

#define TTYDRV_UART 0
#define TTYDRV_USB 1
#ifdef CONFIG_PICOCALC
#define TTYDRV_LCD 2

/* PicoCalc LCD console + I2C keyboard (devlcd.c / devkbd.c). */
extern void lcd_init(void);
extern void lcdconsole_putc(uint8_t devn, uint8_t c);
extern ttyready_t lcdconsole_ready(uint8_t devn);
extern void lcdconsole_sleeping(uint8_t devn);
extern int lcdconsole_getc(uint8_t devn);
extern void kbd_init(void);
extern void kbd_poll(void);
#endif

extern int ttymap_count;
extern struct ttymap ttymap[NUM_DEV_TTY+1];
extern void tty_interrupt(void);
extern void devtty_early_init(void);
extern void devtty_init(void);

#endif
