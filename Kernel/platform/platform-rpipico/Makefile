# Set one of these depending.
export PICO_SDK_FETCH_FROM_GIT = yes
#export PICO_SDK_PATH = ${HOME}/.pico-sdk/sdk/1.5.1

# Set 'SUBTARGET' to one of pico-sdk compatible boards (selects the chip).
# valid values: pico, pico_w (RP2040) or pico2, pico2_w (RP2350)
ifndef SUBTARGET
# default subtarget (keep on its own line: a trailing comment would leave a
# stray space in the value and break the ifeq comparisons below)
SUBTARGET=pico
endif

# Set 'BOARD' to the FUZIX board variant (SD card pins + onboard peripherals).
# This is independent of the chip selected by SUBTARGET above.
# valid values: rc2040 (default), makerpi, picocalc
BOARD ?= rc2040

ifeq ($(SUBTARGET),pico)
TOTALMEM=160
endif
ifeq ($(SUBTARGET),pico_w)
TOTALMEM=160
endif
ifeq ($(SUBTARGET),pico2)
TOTALMEM=320
endif
ifeq ($(SUBTARGET),pico2_w)
TOTALMEM=320
endif

# Userspace CPU: the RP2350 (pico2/pico2_w) runs a native Cortex-M33 userspace
# (armm4 / ARMv7E-M); the RP2040 (pico/pico_w) uses Cortex-M0+ (armm0).
# The kernel itself is built by the Pico SDK for the selected chip.
USERCPU=armm0
ifeq ($(SUBTARGET),pico2)
USERCPU=armm4
endif
ifeq ($(SUBTARGET),pico2_w)
USERCPU=armm4
endif

PICOTOOLFLAGS= --family rp2040
ifeq (${SUBTARGET}, pico2)
PICOTOOLFLAGS= --family data
endif
ifeq (${SUBTARGET}, pico2_w)
PICOTOOLFLAGS= --family data
endif

PICOTOOL=picotool

ifeq (, $(shell which picotool))
PICOTOOL=build/_deps/picotool/picotool
endif

include ../../../version.mk

build/fuzix.elf: ../../version.c build/Makefile
	$(MAKE) -C build

../../version.c:
	$(MAKE) -C ../.. TARGET=rpipico version.c

build/Makefile: CMakeLists.txt $(wildcard ../../*.[chS]) $(wildcard ../../*/*.[chS])
	mkdir -p build
	(cd build && cmake -DPICO_BOARD=${SUBTARGET} -DTOTALMEM=${TOTALMEM} -DFUZIX_BOARD=${BOARD} ..)

image:: world
	./update-flash.sh
	../../../Standalone/mkftl -s 1952 -e 0x1000 -g 10 filesystem.img -o filesystem.ftl
	${PICOTOOL} uf2 convert filesystem.ftl -t bin filesystem.uf2 -o 0x10018000 ${PICOTOOLFLAGS}

diskimage:

clean:
	rm -rf build
	rm -f uf2conv
	$(MAKE) -C ../../../Library/libs -f Makefile.$(USERCPU) clean
	$(MAKE) -C ../../../Applications/util -f Makefile.$(USERCPU) clean
	$(MAKE) -C ../../../Applications/V7/cmd -f Makefile.$(USERCPU) clean
	$(MAKE) -C ../../../Applications/V7/cmd/sh -f Makefile.$(USERCPU) clean
	$(MAKE) -C ../../../Applications/games -f Makefile.$(USERCPU) clean
	$(MAKE) -C ../../../Applications/levee -f Makefile.$(USERCPU) clean
	$(MAKE) -C ../../../Applications/cave -f Makefile.$(USERCPU) clean
	$(MAKE) -C ../../../Applications/cursesgames -f Makefile.$(USERCPU) clean
	$(MAKE) -C ../../../Standalone clean
	$(MAKE) -C utils clean

world: build/fuzix.elf
	$(MAKE) -C ../../../Library/libs -f Makefile.$(USERCPU)
	$(MAKE) -C ../../../Applications/util -f Makefile.$(USERCPU)
	$(MAKE) -C ../../../Applications/V7/cmd -f Makefile.$(USERCPU)
	$(MAKE) -C ../../../Applications/V7/cmd/sh -f Makefile.$(USERCPU)
	$(MAKE) -C ../../../Applications/games -f Makefile.$(USERCPU)
	$(MAKE) -C ../../../Applications/levee -f Makefile.$(USERCPU)
	$(MAKE) -C ../../../Applications/cave -f Makefile.$(USERCPU)
	$(MAKE) -C ../../../Applications/cursesgames -f Makefile.$(USERCPU)
	$(MAKE) -C ../../../Standalone
	$(MAKE) -C utils
