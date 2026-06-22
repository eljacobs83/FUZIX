# Building and Deploying FUZIX for the PicoCalc

This tree builds FUZIX exclusively for the [ClockworkPi
PicoCalc](https://www.clockworkpi.com/product-page/picocalc). It runs on any of
the four Raspberry Pi Pico–form-factor modules the PicoCalc accepts:

| Module | Chip | Core | RAM | Userspace CPU | Wireless |
|---|---|---|---|---|---|
| Pico | RP2040 | Cortex-M0+ | 264 KB | `armm0` (ARMv6-M) | no |
| Pico W | RP2040 | Cortex-M0+ | 264 KB | `armm0` (ARMv6-M) | CYW43 |
| Pico 2 | RP2350 | Cortex-M33 | 520 KB | `armm4` (ARMv7E-M) | no |
| Pico 2 W | RP2350 | Cortex-M33 | 520 KB | `armm4` (ARMv7E-M) | CYW43 |

The module is selected at build time with the `SUBTARGET` variable. The kernel
is built for the chip by the Raspberry Pi Pico SDK; userspace is built natively
for the module's CPU (`armm0` on RP2040, `armm4` on RP2350). Both are selected
automatically from `SUBTARGET`.

For PicoCalc hardware details and the LCD/keyboard driver roadmap see
[`docs/PicoCalc.md`](docs/PicoCalc.md); for runtime/install notes see
[`Kernel/platform/platform-rpipico/README.md`](Kernel/platform/platform-rpipico/README.md).

## 1. Set up the build environment

Tested on Ubuntu 24.04 (the CI host). On other distributions install the
equivalent packages.

### Required packages

```sh
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake git byacc automake \
    gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib

# FUZIX forces the Berkeley yacc (Bison output is too large for these toolchains)
sudo update-alternatives --set yacc /usr/bin/byacc
```

What each piece is for:

- **`gcc-arm-none-eabi` + newlib** — the bare-metal ARM cross compiler used for
  both the kernel and userspace.
- **`cmake`** — drives the Pico SDK kernel build.
- **`git`** — the Pico SDK is fetched from git automatically (see below).
- **GNU `make`, `byacc`, `automake`, `build-essential`** — the FUZIX build
  itself and its host-side tools.

### Pico SDK

You do **not** need to install the Pico SDK by hand. The platform Makefile sets
`PICO_SDK_FETCH_FROM_GIT=yes`, so CMake clones a matching SDK (including RP2350
support) on first build. If you would rather use a local checkout, edit
`Kernel/platform/platform-rpipico/Makefile` to set `PICO_SDK_PATH` instead.

### `picotool` (optional)

`picotool` is only needed if you want to flash over USB from the command line
(instead of the drag-and-drop BOOTSEL method). If it is not on your `PATH`, the
build falls back to the copy the Pico SDK builds under `build/_deps/picotool/`.

## 2. Build

From the repository root, pick the module fitted to your PicoCalc and run:

```sh
make TARGET=rpipico SUBTARGET=pico    diskimage   # Pico       (RP2040)
make TARGET=rpipico SUBTARGET=pico_w  diskimage   # Pico W     (RP2040 + wireless)
make TARGET=rpipico SUBTARGET=pico2   diskimage   # Pico 2     (RP2350)
make TARGET=rpipico SUBTARGET=pico2_w diskimage   # Pico 2 W   (RP2350 + wireless)
```

`SUBTARGET` defaults to `pico`, so `make TARGET=rpipico diskimage` builds for a
plain Pico. Use `-j$(nproc)` to build in parallel.

Useful goals (run with the same `TARGET=`/`SUBTARGET=`):

| Goal | Builds |
|---|---|
| `diskimage` | kernel + userspace + bootable filesystem images (the full deploy artifact set) |
| `kernel` | the kernel only |
| `libs` | the userspace C library only |
| `apps` | the userspace applications only |
| `clean` | removes this platform's build output |

Other knobs:

- **`FUZIX_CCOPTS`** — global optimisation level (default `-O2`).
- **`USERCPU`** — userspace CPU. It is chosen automatically from `SUBTARGET`
  (`armm0`/`armm4`); override only if you know you need to.

### Build outputs

After a successful `diskimage` build:

| File | What it is |
|---|---|
| `Kernel/platform/platform-rpipico/build/fuzix.uf2` | the kernel, ready to flash |
| `Kernel/platform/platform-rpipico/filesystem.uf2` | the root filesystem for the on-board NAND flash |
| `Kernel/platform/platform-rpipico/filesystem.ftl` | the same filesystem as a raw FTL image (for `picotool`) |
| `Images/rpipico/filesys*.img` | filesystem images for an SD card |

## 3. Deploy to hardware

### Flash the kernel

1. Hold the **BOOTSEL** button on the Pico module while plugging it into USB. It
   appears as a mass-storage device.
2. Copy `build/fuzix.uf2` onto it. The board reboots into FUZIX.

Or, with `picotool`:

```sh
cd Kernel/platform/platform-rpipico
picotool load build/fuzix.uf2
```

### Install the root filesystem on the NAND flash

Either copy `filesystem.uf2` the same BOOTSEL way as the kernel, or with a
terminal on UART0:

```sh
cd Kernel/platform/platform-rpipico
picotool load filesystem.ftl -t bin -o 0x10018000
```

### Use an SD card instead (optional)

The PicoCalc's on-board SD slot is on SPI0 and appears as `/dev/hdb`. Only
filesystems up to 32MB are supported. Partition the card with an MBR scheme,
create a ≤32MB partition, and copy an image onto it:

```sh
dd if=Images/rpipico/filesys.img of=/dev/sdXn oflag=direct bs=8192
```

Swapping to the SD card is optional and off by default; see the platform README
for `swapon` setup.

## 4. Verify

- `make help` and `make list-targets` describe the available goals and targets.
- There is no free RP2040/RP2350 emulator, so CI builds the PicoCalc kernel on
  both chips (the `rpipico` job = RP2040, the `rpipico-picocalc` job = RP2350)
  plus the `armm4` userspace libraries (`armm4-libs` job); see
  [`.github/workflows/continuous-integration.yml`](.github/workflows/continuous-integration.yml).
- The LCD console and I2C keyboard drivers are **not yet hardware-verified** —
  they compile but their panel/keymap specifics are marked `TODO`. Final
  validation is on a real PicoCalc; the bring-up checklist is in
  [`docs/PicoCalc.md`](docs/PicoCalc.md).
- See [`docs/Testing.md`](docs/Testing.md) for the FUZIX automated-test harness
  and [`Kernel/PORTING`](Kernel/PORTING) for the deeper platform reference.
