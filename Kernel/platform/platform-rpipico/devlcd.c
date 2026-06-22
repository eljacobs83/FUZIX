/*
 *	PicoCalc ILI9488-class SPI LCD console driver.
 *
 *	SCAFFOLD - this driver has NOT been built or run on hardware. There is no
 *	ARM / Pico-SDK toolchain in the development environment it was written in.
 *	The structure follows the shared Kernel/vt.c console contract (see
 *	Kernel/include/vt.h); the panel-specific bits (init sequence, exact pixel
 *	format, hardware scroll) are marked TODO and must be confirmed against the
 *	ClockworkPi PicoCalc schematic and the panel controller datasheet before
 *	bring-up.
 *
 *	Build: this tree is PicoCalc-only (CONFIG_PICOCALC always defined); wired
 *	in by CMakeLists.txt.
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
#include <hardware/spi.h>
#include <hardware/gpio.h>

#ifdef CONFIG_PICOCALC

/* 8x8 glyph bitmaps for printable ASCII 0x20..0x7F (see fontdata8x8.c). */
extern const uint8_t fontdata8x8[96 * 8];

/* The shared vt.c asks the platform what visual attributes the display can
 * render. The scaffold reports none for now. */
uint8_t vtattr_cap = 0;

/* 16bpp RGB565 colours. TODO: confirm the panel pixel format (the ILI9488
 * commonly runs 18bpp/3-byte over SPI; adjust lcd_fill/lcd_blit accordingly). */
#define LCD_INK		0xFFFF		/* white */
#define LCD_PAPER	0x0000		/* black */

#define FONT_W		8
#define FONT_H		8
#define LCD_PX_W	(VT_WIDTH * FONT_W)
#define LCD_PX_H	(VT_HEIGHT * FONT_H)

/* ---- low level SPI plumbing ---------------------------------------------- */

static void lcd_cs(bool select)
{
	gpio_put(LCD_PIN_CS, select ? 0 : 1);
}

static void lcd_cmd(uint8_t c)
{
	gpio_put(LCD_PIN_DC, 0);
	lcd_cs(true);
	spi_write_blocking(LCD_SPI_MOD, &c, 1);
	lcd_cs(false);
}

static void lcd_data(const uint8_t *d, unsigned int len)
{
	gpio_put(LCD_PIN_DC, 1);
	lcd_cs(true);
	spi_write_blocking(LCD_SPI_MOD, d, len);
	lcd_cs(false);
}

static void lcd_data1(uint8_t d)
{
	lcd_data(&d, 1);
}

/* Set the controller's active drawing window to a pixel rectangle.
 * TODO: confirm CASET/PASET command bytes for the fitted controller. */
static void lcd_window(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1)
{
	uint8_t buf[4];

	lcd_cmd(0x2A);			/* CASET - column address set */
	buf[0] = x0 >> 8; buf[1] = x0 & 0xFF;
	buf[2] = x1 >> 8; buf[3] = x1 & 0xFF;
	lcd_data(buf, 4);

	lcd_cmd(0x2B);			/* PASET - page address set */
	buf[0] = y0 >> 8; buf[1] = y0 & 0xFF;
	buf[2] = y1 >> 8; buf[3] = y1 & 0xFF;
	lcd_data(buf, 4);

	lcd_cmd(0x2C);			/* RAMWR - start memory write */
}

/* Fill a character cell rectangle with a solid colour. */
static void lcd_fill(uint16_t x0, uint16_t y0, uint16_t w, uint16_t h,
		     uint16_t colour)
{
	uint8_t px[2];
	uint32_t n = (uint32_t)w * h;

	px[0] = colour >> 8;
	px[1] = colour & 0xFF;

	lcd_window(x0, y0, x0 + w - 1, y0 + h - 1);
	gpio_put(LCD_PIN_DC, 1);
	lcd_cs(true);
	while (n--)
		spi_write_blocking(LCD_SPI_MOD, px, 2);
	lcd_cs(false);
}

/* ---- init ---------------------------------------------------------------- */

void lcd_init(void)
{
	gpio_init(LCD_PIN_CS);
	gpio_init(LCD_PIN_DC);
	gpio_init(LCD_PIN_RST);
	gpio_set_dir(LCD_PIN_CS, true);
	gpio_set_dir(LCD_PIN_DC, true);
	gpio_set_dir(LCD_PIN_RST, true);
	lcd_cs(false);

	gpio_set_function(LCD_PIN_SCK, GPIO_FUNC_SPI);
	gpio_set_function(LCD_PIN_TX, GPIO_FUNC_SPI);
	gpio_set_function(LCD_PIN_RX, GPIO_FUNC_SPI);
	spi_init(LCD_SPI_MOD, 24000000);
	spi_set_format(LCD_SPI_MOD, 8, 0, 0, SPI_MSB_FIRST);

	/* hardware reset pulse */
	gpio_put(LCD_PIN_RST, 0);
	gpio_put(LCD_PIN_RST, 1);

	/*
	 * TODO: real ILI9488 power/gamma/pixel-format init sequence. The few
	 * commands below are the minimum to leave sleep and turn the panel on;
	 * a fitted PicoCalc panel needs its full vendor init table here.
	 */
	lcd_cmd(0x11);			/* SLPOUT - sleep out */
	lcd_cmd(0x3A);			/* COLMOD - pixel format */
	lcd_data1(0x55);		/* 16bpp; use 0x66 for 18bpp (3 byte) */
	lcd_cmd(0x29);			/* DISPON - display on */

	lcd_fill(0, 0, LCD_PX_W, LCD_PX_H, LCD_PAPER);
}

/* ---- vt.c platform hooks ------------------------------------------------- */

void plot_char(int8_t y, int8_t x, uint16_t c)
{
	const uint8_t *glyph;
	uint8_t row;
	uint8_t bit;
	uint16_t px = (uint16_t)x * FONT_W;
	uint16_t py = (uint16_t)y * FONT_H;

	if (c < 0x20 || c > 0x7F)
		c = '?';
	glyph = &fontdata8x8[(c - 0x20) * FONT_H];

	lcd_window(px, py, px + FONT_W - 1, py + FONT_H - 1);
	gpio_put(LCD_PIN_DC, 1);
	lcd_cs(true);
	for (row = 0; row < FONT_H; row++) {
		uint8_t bits = glyph[row];
		for (bit = 0; bit < FONT_W; bit++) {
			uint16_t colour = (bits & 0x80) ? LCD_INK : LCD_PAPER;
			uint8_t p[2];
			p[0] = colour >> 8;
			p[1] = colour & 0xFF;
			spi_write_blocking(LCD_SPI_MOD, p, 2);
			bits <<= 1;
		}
	}
	lcd_cs(false);
}

void clear_lines(int8_t y, int8_t ct)
{
	lcd_fill(0, (uint16_t)y * FONT_H, LCD_PX_W, (uint16_t)ct * FONT_H,
		 LCD_PAPER);
}

void clear_across(int8_t y, int8_t x, int16_t l)
{
	lcd_fill((uint16_t)x * FONT_W, (uint16_t)y * FONT_H,
		 (uint16_t)l * FONT_W, FONT_H, LCD_PAPER);
}

void cursor_off(void)
{
	/* Soft cursor handled by vt.c re-plotting the underlying glyph. */
}

void cursor_on(int8_t y, int8_t x)
{
	/* TODO: draw a block/underline cursor. vt.c also drives a soft cursor
	 * by plotting VT_CURSOR_CHAR, so this can stay a no-op initially. */
	used(y);
	used(x);
}

void cursor_disable(void)
{
}

void scroll_up(void)
{
	/*
	 * TODO: use the controller's vertical scroll (VSCRDEF/VSCRSAR) for a
	 * cheap hardware scroll. The scaffold just clears the bottom line; the
	 * shared vt.c will repaint as needed.
	 */
	clear_lines(VT_BOTTOM, 1);
}

void scroll_down(void)
{
	clear_lines(0, 1);
}

void do_beep(void)
{
	/* TODO: PicoCalc has a PWM buzzer; pulse it here. */
}

void vtattr_notify(void)
{
	/* No hardware attributes wired up yet (vtattr_cap == 0). */
}

/* ---- tty driver glue ----------------------------------------------------- */

void lcdconsole_putc(uint8_t minor, uint8_t c)
{
	used(minor);
	vtoutput(&c, 1);
}

ttyready_t lcdconsole_ready(uint8_t minor)
{
	used(minor);
	return TTY_READY_NOW;
}

void lcdconsole_sleeping(uint8_t minor)
{
	used(minor);
}

int lcdconsole_getc(uint8_t minor)
{
	/* Input is delivered by devkbd.c's kbd_poll() straight into
	 * tty_inproc(); nothing to pull from here. */
	used(minor);
	return -1;
}

#endif /* CONFIG_PICOCALC */

/* vim: sw=8 ts=8 noet: */
