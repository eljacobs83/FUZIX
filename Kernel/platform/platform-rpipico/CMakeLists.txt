cmake_minimum_required(VERSION 3.12)

# Pull in SDK (must be before project)
include(pico_sdk_import.cmake)

project(fuzix C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)
option(TOTALMEM "specify how much TOTALMEM is present" 0)
option(WIFI_SSID     "WiFi SSID to connect at boot (optional)"     "")
option(WIFI_PASSWORD "WiFi password (optional, empty = open)"       "")

# Detect wireless builds: PICO_BOARD ending with _w (pico_w, pico2_w)
if(PICO_BOARD MATCHES ".*_w$")
    set(FUZIX_CYW43_BUILD TRUE)
    message(STATUS "CYW43 wireless build enabled for board: ${PICO_BOARD}")
else()
    set(FUZIX_CYW43_BUILD FALSE)
endif()

# Copy-to-RAM puts the entire image in SRAM which speeds execution but
# consumes all available memory.  Wireless builds need the lwIP / CYW43
# BSS pools in SRAM, so keep code in XIP flash instead.
if(NOT FUZIX_CYW43_BUILD)
    set(PICO_COPY_TO_RAM 1)
endif()

set(COMMON_DEFINITIONS
    PICO_HEAP_SIZE=0x0
    PICO_NO_BINARY_INFO=1
    PICO_TIME_DEFAULT_ALARM_POOL_DISABLED
    TOTALMEM=${TOTALMEM}
)

if(FUZIX_CYW43_BUILD)
    list(APPEND COMMON_DEFINITIONS
        CONFIG_NET_CYW43=1
        FUZIX_CYW43_BUILD=1
    )
    if(NOT "${WIFI_SSID}" STREQUAL "")
        list(APPEND COMMON_DEFINITIONS "WIFI_SSID=\"${WIFI_SSID}\"")
    endif()
    if(NOT "${WIFI_PASSWORD}" STREQUAL "")
        list(APPEND COMMON_DEFINITIONS "WIFI_PASSWORD=\"${WIFI_PASSWORD}\"")
    endif()
endif()

add_compile_definitions(${COMMON_DEFINITIONS})

pico_sdk_init()

include_directories(
	.
	../..
	../../dev
	../../include
	../../cpu-armm0
)

set(FUZIX_SOURCES
	devices.c
	devflash.c
	devsdspi.c
	devtty.c
	elf.c
	main.c
	misc.c
	rawflash.c
	rawuart.c
	swapper.c
	tricks.S
	core1.c
	devgpio.c
	usbdescriptors.c
	../../dev/blkdev.c
	../../dev/mbr.c
	../../dev/devsd_discard.c
	../../dev/devsd.c
	../../lib/dhara/error.c
	../../lib/dhara/journal.c
	../../lib/dhara/map.c
	../../lib/hexdump.c
	../../blk512.c
	../../devio.c
	../../devsys.c
	../../filesys.c
	../../inode.c
	../../kdata.c
	../../cpu-armm0/lowlevel-armm0.c
	../../mm/malloc.c
	../../mm.c
	../../mm/memalloc_none.c
	../../process.c
	../../start.c
	../../swap.c
	../../syscall_execelf32.c
	../../syscall_exec.c
	../../syscall_fs.c
	../../syscall_fs2.c
	../../syscall_fs3.c
	../../syscall_other.c
	../../syscall_proc.c
	../../timer.c
	../../tty.c
	../../usermem.c
	../../version.c
	../../dev/net/net_native.c
	../../syscall_net.c
	../../network.c
)

if(FUZIX_CYW43_BUILD)
    list(APPEND FUZIX_SOURCES ../../dev/net/net_cyw43.c)
endif()

add_executable(fuzix ${FUZIX_SOURCES})

set(FUZIX_LIBS
	pico_stdlib
	pico_multicore
	hardware_flash
	hardware_spi
	tinyusb_device
)

if(FUZIX_CYW43_BUILD)
    # pico_cyw43_arch_lwip_poll: single-threaded poll-based lwIP integration.
    # cyw43_arch_poll() is called from plt_idle() in net_cyw43.c.
    list(APPEND FUZIX_LIBS pico_cyw43_arch_lwip_poll)
endif()

target_link_libraries(fuzix ${FUZIX_LIBS})

pico_set_float_implementation(fuzix none)
pico_set_double_implementation(fuzix none)
pico_add_extra_outputs(fuzix)

