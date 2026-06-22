export CPU = armm0

# Userspace CPU. The Pico 2 (RP2350) runs a native Cortex-M33 userspace
# (armm4 / ARMv7E-M); the Pico (RP2040) uses Cortex-M0+ (armm0). This has to be
# decided here in target scope: the top-level Makefile builds libs/apps with
# $(USERCPU) before it ever descends into the platform submake, and it defaults
# USERCPU to $(CPU) unless we set it first. Selection keys off SUBTARGET (the
# chip), so it is independent of BOARD. A command-line USERCPU= still overrides.
ifeq ($(SUBTARGET),pico2)
export USERCPU = armm4
endif
ifeq ($(SUBTARGET),pico2_w)
export USERCPU = armm4
endif

