/*
 *	PicoCalc keyboard driver - reads the on-board STM32 keyboard controller
 *	over I2C and feeds keystrokes into the LCD console tty.
 *
 *	SCAFFOLD - NOT built or tested on hardware (no ARM / Pico-SDK toolchain in
 *	the dev environment). The I2C transaction shape follows the ClockworkPi
 *	PicoCalc keyboard firmware (a key-FIFO register returning state:keycode
 *	pairs), but the register number, key codes, modifier handling and bus pins
 *	all need confirming against the schematic/firmware before bring-up. Those
 *	points are marked TODO.
 *
 *	Build: only compiled for BOARD=picocalc (CONFIG_PICOCALC).
 */

#include <kernel.h>
#include <kdata.h>
#include <printf.h>
#include <stdbool.h>
#include <vt.h>
#include <tty.h>
#include "config.h"
#include "devtty.h"
#include "picosdk.h"
#include <hardware/i2c.h>
#include <hardware/gpio.h>

#ifdef CONFIG_PICOCALC

/* Auto-repeat timing for the shared vt.c key handling (first delay, interval),
 * in ticks. TODO: tune. */
struct vt_repeat keyrepeat = { 40, 4 };

/* The tty minor the LCD console is mapped to. Set by devtty when CONFIG_PICOCALC
 * makes the LCD the primary console (tty1). */
#ifndef LCD_CONSOLE_MINOR
#define LCD_CONSOLE_MINOR 1
#endif

/* PicoCalc keyboard FIFO register. The controller returns a 16-bit word:
 * high byte = key state (press/release/hold), low byte = key code.
 * TODO: confirm register index and the state/keycode encoding. */
#define KBD_REG_FIFO	0x09
#define KBD_STATE_PRESS	0x01

/*
 * Translation from the controller's key codes to the bytes we feed the tty.
 * The PicoCalc firmware already returns ASCII for the printable keys, so the
 * scaffold passes those straight through and only needs a table for the
 * special keys (arrows, function keys, etc).
 * TODO: populate special-key translation (cursor keys -> ANSI sequences via
 * vt_inproc, etc).
 */
static int kbd_translate(uint8_t code)
{
	if (code >= 0x20 && code < 0x7F)
		return code;
	switch (code) {
	case 0x0A:			/* enter */
	case 0x0D:
		return '\n';
	case 0x08:			/* backspace */
		return 0x08;
	case 0x09:			/* tab */
		return '\t';
	case 0x1B:			/* escape */
		return 0x1B;
	default:
		return -1;		/* TODO: arrows / function keys */
	}
}

void kbd_init(void)
{
	i2c_init(KBD_I2C_MOD, KBD_I2C_BAUD);
	gpio_set_function(KBD_PIN_SDA, GPIO_FUNC_I2C);
	gpio_set_function(KBD_PIN_SCL, GPIO_FUNC_I2C);
	gpio_pull_up(KBD_PIN_SDA);
	gpio_pull_up(KBD_PIN_SCL);
}

/*
 * Poll the keyboard FIFO and push any pending key presses into the console
 * tty. Called from the timer tick (devices.c). Drains until the FIFO reports
 * empty (key code 0).
 */
void kbd_poll(void)
{
	uint8_t reg = KBD_REG_FIFO;
	uint8_t buf[2];

	for (;;) {
		int state, code, c;

		/* write register pointer, then read 2 bytes back */
		if (i2c_write_blocking(KBD_I2C_MOD, KBD_I2C_ADDR, &reg, 1,
				       true) < 0)
			return;
		if (i2c_read_blocking(KBD_I2C_MOD, KBD_I2C_ADDR, buf, 2,
				      false) < 0)
			return;

		state = buf[0];
		code = buf[1];
		if (code == 0)		/* FIFO empty */
			return;
		if (state != KBD_STATE_PRESS)
			continue;	/* ignore release/hold for now */

		c = kbd_translate(code);
		if (c >= 0)
			tty_inproc(LCD_CONSOLE_MINOR, c);
	}
}

#endif /* CONFIG_PICOCALC */

/* vim: sw=8 ts=8 noet: */
