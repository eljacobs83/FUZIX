# PicoCalc

The [ClockworkPi PicoCalc](https://www.clockworkpi.com/product-page/picocalc) is
a small handheld computer kit built around a Raspberry Pi Pico–form-factor
module: a 320×320 colour LCD (ILI9488-class controller), an STM32-based keyboard
exposed over I2C, an SD-card slot, and audio. It accepts either a **Pico
(RP2040, Cortex-M0+)** or a **Pico 2 (RP2350, Cortex-M33)** module.

This tree is **PicoCalc-only**: the `rpipico` platform
(`Kernel/platform/platform-rpipico/`) always builds for the ClockworkPi
PicoCalc, so `CONFIG_PICOCALC` is always on. The only build choice is which
Pico-form-factor module is fitted.

## Building

The single build knob is **`SUBTARGET`**, which selects the *chip / module*:
`pico` or `pico_w` (RP2040) and `pico2` or `pico2_w` (RP2350). It drives
`PICO_BOARD`, the amount of RAM (`TOTALMEM`), the `picotool` family, and —
importantly — the userspace CPU. `SUBTARGET` defaults to `pico`.

```sh
# PicoCalc on a Pico (RP2040)
make TARGET=rpipico SUBTARGET=pico    diskimage

# PicoCalc on a Pico W (RP2040 + CYW43 wireless)
make TARGET=rpipico SUBTARGET=pico_w  diskimage

# PicoCalc on a Pico 2 (RP2350)
make TARGET=rpipico SUBTARGET=pico2   diskimage

# PicoCalc on a Pico 2 W (RP2350 + CYW43 wireless)
make TARGET=rpipico SUBTARGET=pico2_w diskimage
```

Outputs land in `Kernel/platform/platform-rpipico/`: `build/fuzix.uf2` (kernel)
and `filesystem.uf2`. Install by holding BOOTSEL, plugging in USB, and copying
the `.uf2` (or `picotool load`). See [`BUILD.md`](../BUILD.md) for the toolchain
prerequisites and full build/deploy walkthrough, and
`Kernel/platform/platform-rpipico/README.md` for install and runtime details.

### RP2040 vs RP2350

| | Pico (RP2040) | Pico 2 (RP2350) |
|---|---|---|
| `SUBTARGET` | `pico` / `pico_w` | `pico2` / `pico2_w` |
| Core | Cortex-M0+ (ARMv6-M) | Cortex-M33 (ARMv8-M) |
| `TOTALMEM` | 160 | 320 |
| `picotool --family` | `rp2040` | `data` |
| Userspace CPU | `armm0` (ARMv6-M) | `armm4` (ARMv7E-M) |

On the Pico 2 the kernel is compiled for the RP2350 by the Pico SDK, and
userspace is built natively from the `cpu-armm4` tree (ARMv7E-M, which the M33
runs) rather than the M0+ `armm0` baseline used on the RP2040. The selection is
automatic from `SUBTARGET`.

## Hardware support

### Working / shared with the base Pico port
- Root filesystem on the onboard NAND flash (`/dev/hda`, Dhara FTL).
- SD card (`/dev/hdb`) on SPI0 — the PicoCalc SD pins (GPIO 16/17/18/19).
- Console over USB CDC and UART0.
- Swap to SD card; GPIO via `/dev/gpio`.

### PicoCalc-specific (driver scaffolding — see roadmap)
- **LCD console** (`devlcd.c`): an ILI9488 SPI driver hooked into the shared
  `Kernel/vt.c` console (40×40 character cells from an 8×8 font in
  `fontdata8x8.c`). Registered as the primary console (`tty1`).
- **Keyboard** (`devkbd.c`): the STM32 keyboard polled over I2C from the timer
  tick, feeding `tty_inproc()`.

> **Status:** the LCD and keyboard drivers are **scaffolding**. They were written
> without an ARM/Pico-SDK toolchain available and have **not** been compiled or
> run on hardware. They follow the FUZIX VT/TTY contracts and are structurally
> complete, but the panel-specific and keyboard-specific details below are marked
> `TODO` in the source and must be confirmed against the PicoCalc schematic and
> the panel/keyboard firmware before they will work.

## Driver roadmap / PicoCalc tech-debt

Bring-up checklist for the scaffolded drivers and the still-missing pieces:

1. **LCD pins & controller** (`config.h` `LCD_PIN_*`, `LCD_SPI_MOD`; `devlcd.c`):
   confirm the SPI bus and DC/RST/CS GPIOs, the exact panel resolution, and the
   real ILI9488 init sequence (power/gamma) and pixel format (16bpp vs 18bpp).
2. **LCD scrolling** (`devlcd.c` `scroll_up`/`scroll_down`): use the controller's
   vertical scroll commands instead of the placeholder clear-and-repaint.
3. **Keyboard bus/codes** (`config.h` `KBD_*`; `devkbd.c`): confirm the I2C bus,
   pins, address, the FIFO register, the state/keycode encoding, and fill in the
   special-key translation (arrows/function keys → ANSI via `vt_inproc`). Also
   reconsider doing the blocking I2C read off the interrupt path.
4. **Audio**: PicoCalc has a PWM buzzer/speaker; `do_beep()` is a stub and there
   is no audio device.
5. **RTC**: no persistent real-time clock driver (uptime only).
6. **`/dev/i2c`**: the filesystem creates the node but there is no I2C userspace
   interface yet.

## Testing

There is no free RP2040/RP2350 emulator in CI, so all `rpipico` jobs are
**build-only** and actual LCD/keyboard behaviour is validated on hardware. CI
does compile the PicoCalc kernel on both chips — the `rpipico` job builds it for
the Pico (RP2040, the default `SUBTARGET`) and the `rpipico-picocalc` job builds
it for the Pico 2 (`SUBTARGET=pico2`, RP2350) — and the `armm4-libs` job builds
the native Cortex-M33 userspace libraries. Both kernel builds include the
LCD/keyboard/font sources, which are always compiled in. See
[Testing](Testing.md) for the FUZIX automated-test harness (and how a target
would plug into it if a suitable emulator becomes available), and
[TechDebt](TechDebt.md) for the kernel-wide work-marker inventory.
