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

/* Memory — keep footprint small on Pico */
#define MEM_ALIGNMENT           4
#define MEM_SIZE                16000
#define TCP_WND                 2920
#define TCP_MSS                 1460

/* Required by pico_cyw43_arch */
#define LWIP_NETIF_HOSTNAME     1

#endif /* LWIPOPTS_H */
