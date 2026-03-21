#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* Bare-metal polling mode — no RTOS */
#define NO_SYS                  1
#define SYS_LIGHTWEIGHT_PROT    0

/* Use only the raw (callback) API; no BSD sockets */
#define LWIP_SOCKET             0
#define LWIP_NETCONN            0

/* IPv4 only */
#define LWIP_IPV4               1
#define LWIP_IPV6               0

/* Enable TCP and UDP */
#define LWIP_TCP                1
#define LWIP_UDP                1

/*
 * Memory pools — tuned to minimise BSS footprint on the Pico W.
 * FUZIX maps each kernel socket directly to one lwIP raw PCB, and the
 * kernel's NSOCKET limit is small (typically 4–8), so we don't need
 * large pools.
 */
#define MEM_ALIGNMENT           4
#define MEM_SIZE                4096        /* dynamic heap */

#define MEMP_NUM_TCP_PCB        4
#define MEMP_NUM_TCP_PCB_LISTEN 2
#define MEMP_NUM_UDP_PCB        4
#define MEMP_NUM_PBUF           8
#define PBUF_POOL_SIZE          8

#define TCP_MSS                 1460
#define TCP_WND                 (2 * TCP_MSS)
#define TCP_SND_BUF             (2 * TCP_MSS)
#define TCP_SND_QUEUELEN        4

/* Required by pico_cyw43_arch */
#define LWIP_NETIF_HOSTNAME     1

#endif /* LWIPOPTS_H */
