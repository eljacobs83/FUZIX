/*
 * CYW43 WiFi network driver for FUZIX
 * Supports Raspberry Pi Pico W (RP2040) and Pico 2W (RP2350)
 *
 * Uses the Pico SDK CYW43 driver with lwIP in polling mode
 * (pico_cyw43_arch_lwip_poll).  cyw43_arch_poll() is called from
 * plt_idle() so that the network stack is serviced whenever the
 * FUZIX scheduler has no runnable process.
 *
 * Protocol layer implements the FUZIX netproto_* interface, mapping
 * FUZIX sockets directly onto lwIP raw-API TCP/UDP PCBs.
 *
 * WiFi credentials are supplied at build time via -DWIFI_SSID="..." and
 * -DWIFI_PASSWORD="..." CMake options.  They can also be changed at
 * runtime through the SIOCWIFICONNECT ioctl.
 */

#include <kernel.h>

#ifdef CONFIG_NET_CYW43

#include <kdata.h>
#include <netdev.h>
#include <printf.h>

/*
 * Temporarily undo the FUZIX name-mangling applied by config.h so that
 * the Pico SDK / lwIP headers compile without seeing our #define redirects
 * (e.g.  #define panic fpanic).  We re-apply the mangling afterwards so
 * the rest of this file still calls the FUZIX kernel correctly.
 */
#define MANGLED 0
#include "mangle.h"

#define ssize_t __ssize_t
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#undef ssize_t

#define MANGLED 1
#include "mangle.h"

/* ------------------------------------------------------------------ */
/* Compile-time sanity checks                                          */
/* ------------------------------------------------------------------ */
#if NSOCKET > 8
#error "net_cyw43: sock_free_mask is uint8_t; NSOCKET must be <= 8"
#endif

/* ------------------------------------------------------------------ */
/* Per-slot type tags                                                   */
/* ------------------------------------------------------------------ */
#define SLOT_UNUSED  0
#define SLOT_TCP     1
#define SLOT_UDP     2

/* ------------------------------------------------------------------ */
/* Per-socket private state                                             */
/* ------------------------------------------------------------------ */
struct cyw43_sock {
    uint8_t  type;              /* SLOT_UNUSED / SLOT_TCP / SLOT_UDP   */
    uint8_t  flags;
#define CFLG_EOF   0x01         /* Remote side closed the connection   */
#define CFLG_ERR   0x02         /* lwIP reported a fatal error         */
    struct socket *fuzix_sock;  /* Back-pointer to owning FUZIX socket */
    union {
        struct tcp_pcb *tcp;    /* TCP data (or listen) PCB            */
        struct udp_pcb *udp;    /* UDP PCB                             */
    } pcb;
    /*
     * Receive queue: a singly-linked chain of pbufs.  For TCP, data
     * is appended via pbuf_cat(); rx_offset tracks how far into the
     * head pbuf we have already copied.  For UDP, only one datagram
     * is kept at a time (subsequent arrivals drop the previous one).
     */
    struct pbuf *rx_head;
    uint16_t    rx_offset;      /* Bytes consumed in rx_head->payload  */
    /* Source address of the last-received UDP datagram (net order)    */
    uint32_t    rx_src_ip;
    uint16_t    rx_src_port;
};

static struct cyw43_sock cyw43_socks[NSOCKET];

/*
 * Bitmask of free FUZIX socket-table slots (bit i = 1 → slot i free).
 * Initialised to all-ones in netdev_init().
 */
static uint8_t sock_free_mask;

/* Required by netdev.h – declared extern there, defined here          */
uint8_t sock_wake[NSOCKET];

/* ------------------------------------------------------------------ */
/* Interface / WiFi state                                               */
/* ------------------------------------------------------------------ */
static uint8_t  wifi_up;        /* Non-zero once successfully associated */
static uint16_t autoport;       /* Next ephemeral port, host byte order  */

#ifndef WIFI_SSID
#define WIFI_SSID     ""
#endif
#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD ""
#endif
#ifndef WIFI_AUTH
#define WIFI_AUTH     CYW43_AUTH_WPA2_AES_PSK
#endif

/* ------------------------------------------------------------------ */
/* SIOCWIFICONNECT ioctl                                                */
/* ------------------------------------------------------------------ */
#define SIOCWIFICONNECT  0x0480

struct wifi_req {
    char     ssid[33];
    char     password[64];
    uint32_t auth;      /* CYW43_AUTH_* constant; 0 → WPA2-AES-PSK    */
};

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * slot_alloc – claim a free FUZIX-socket-table slot.
 * Returns the slot index (0..NSOCKET-1) or -1 if none available.
 * The cyw43_socks entry is zeroed; the caller must fill it in.
 */
static int slot_alloc(void)
{
    uint8_t i;
    uint8_t mask = 1;

    for (i = 0; i < NSOCKET; i++, mask <<= 1) {
        if (sock_free_mask & mask) {
            sock_free_mask &= ~mask;
            memset(&cyw43_socks[i], 0, sizeof(cyw43_socks[i]));
            return (int)i;
        }
    }
    return -1;
}

static void slot_free_entry(uint8_t slot)
{
    cyw43_socks[slot].type      = SLOT_UNUSED;
    cyw43_socks[slot].fuzix_sock = NULL;
    sock_free_mask |= (uint8_t)(1u << slot);
}

/*
 * net_wake – mark socket n's event and wake any sleeper.
 * Safe to call from within cyw43_arch_poll() callbacks because those
 * run synchronously (no IRQ races in lwip_poll mode).
 */
static void net_wake(uint8_t n)
{
    /* Guard: n must be a valid slot index */
    if (n >= NSOCKET)
        return;
    sock_wake[n] = 1;
    wakeup(sock_wake + n);
    wakeup(sockets + n);
}

/* ------------------------------------------------------------------ */
/* lwIP TCP callbacks                                                   */
/* ------------------------------------------------------------------ */

/*
 * Data received from the remote end.  We append the new pbuf(s) to
 * our per-socket receive queue and wake any waiting reader.
 */
static err_t tcp_recv_cb(void *arg, struct tcp_pcb *tpcb,
                         struct pbuf *p, err_t err)
{
    struct cyw43_sock *cs = (struct cyw43_sock *)arg;
    struct socket     *s;

    used(tpcb);
    used(err);

    /* Guard: callback may fire after slot teardown */
    if (cs == NULL || cs->fuzix_sock == NULL) {
        if (p != NULL)
            pbuf_free(p);
        return ERR_OK;
    }
    s = cs->fuzix_sock;

    if (p == NULL) {
        /* FIN from remote – signal EOF                                */
        cs->flags   |= CFLG_EOF;
        s->s_iflags |= SI_EOF;
        net_wake(s->s_num);
        return ERR_OK;
    }

    /* Append the new pbuf chain to our queue                         */
    if (cs->rx_head == NULL) {
        cs->rx_head = p;
    } else {
        pbuf_cat(cs->rx_head, p);   /* links p at tail of existing chain */
    }

    s->s_iflags |= SI_DATA;
    net_wake(s->s_num);
    return ERR_OK;
}

/*
 * TX window opened – a previously-throttled writer can retry.
 */
static err_t tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    struct cyw43_sock *cs = (struct cyw43_sock *)arg;
    struct socket     *s;

    used(tpcb);
    used(len);

    if (cs == NULL || cs->fuzix_sock == NULL)
        return ERR_OK;
    s = cs->fuzix_sock;

    s->s_iflags &= ~SI_THROTTLE;
    net_wake(s->s_num);
    return ERR_OK;
}

/*
 * TCP connect() completed (or failed).
 */
static err_t tcp_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    struct cyw43_sock *cs = (struct cyw43_sock *)arg;
    struct socket     *s;

    used(tpcb);

    if (cs == NULL || cs->fuzix_sock == NULL)
        return ERR_OK;
    s = cs->fuzix_sock;

    if (err != ERR_OK) {
        cs->flags  |= CFLG_ERR;
        s->s_error  = ECONNREFUSED;
        s->s_state  = SS_CLOSED;
    } else {
        s->s_state  = SS_CONNECTED;
    }
    net_wake(s->s_num);
    return ERR_OK;
}

/*
 * lwIP error callback – the PCB has already been freed by lwIP when
 * this fires.  We must not use the PCB pointer after this point.
 */
static void tcp_err_cb(void *arg, err_t err)
{
    struct cyw43_sock *cs = (struct cyw43_sock *)arg;
    struct socket     *s;

    if (cs == NULL || cs->fuzix_sock == NULL)
        return;
    s = cs->fuzix_sock;

    cs->pcb.tcp  = NULL;        /* PCB is gone; do not touch it        */
    cs->flags   |= CFLG_ERR;

    s->s_error   = (err == ERR_RST || err == ERR_ABRT)
                    ? ECONNRESET : EIO;
    s->s_iflags |= SI_EOF;
    s->s_state   = SS_CLOSED;
    net_wake(s->s_num);
}

/*
 * Incoming connection on a listening socket.
 *
 * We claim a free FUZIX socket slot for the accepted connection and
 * park it with s_parent pointing at the listener.  The accept() syscall
 * will find it via netproto_sockpending() on the next iteration.
 */
static err_t tcp_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    struct socket     *ls  = (struct socket *)arg; /* listening socket  */
    struct cyw43_sock *ncs;
    struct socket     *ns;
    int                slot;

    if (err != ERR_OK || newpcb == NULL)
        return ERR_VAL;

    slot = slot_alloc();
    if (slot < 0) {
        /* No free slot – reject the incoming connection               */
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    /* Initialise the new cyw43_sock entry                             */
    ncs             = &cyw43_socks[slot];
    ncs->type       = SLOT_TCP;
    ncs->flags      = 0;
    ncs->pcb.tcp    = newpcb;
    ncs->rx_head    = NULL;
    ncs->rx_offset  = 0;

    /* Initialise the corresponding FUZIX socket struct                */
    ns = sockets + slot;
    memset(ns, 0, sizeof(*ns));
    ns->s_num       = (uint8_t)slot;
    ns->s_type      = SLOT_TCP;
    ns->s_class     = SOCK_STREAM;
    ns->s_state     = SS_CONNECTED;  /* matches netproto_sockpending()  */
    ns->s_parent    = ls->s_num;
    ns->s_error     = 0;
    ns->proto.slot  = (uint8_t)slot; /* so netproto_close() finds us    */

    /* Inherit the local address from the listener                     */
    memcpy(&ns->src_addr, &ls->src_addr, sizeof(struct ksockaddr));
    ns->src_len = ls->src_len;

    /* Record the remote address                                       */
    ns->dst_addr.sa.sin.sin_family          = AF_INET;
    ns->dst_addr.sa.sin.sin_addr.s_addr     = newpcb->remote_ip.addr;
    ns->dst_addr.sa.sin.sin_port            = lwip_htons(newpcb->remote_port);
    ns->dst_len = sizeof(struct sockaddr_in);

    ncs->fuzix_sock = ns;

    /* Register callbacks on the new PCB                               */
    tcp_arg(newpcb,  ncs);
    tcp_recv(newpcb, tcp_recv_cb);
    tcp_sent(newpcb, tcp_sent_cb);
    tcp_err(newpcb,  tcp_err_cb);

    /* Tell the scheduler that accept() can now return                 */
    net_wake(ls->s_num);
    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* lwIP UDP callback                                                    */
/* ------------------------------------------------------------------ */

/*
 * UDP datagram received.  We keep only the most-recently-received
 * datagram per socket; the previous one is dropped if unread.
 */
static void udp_recv_cb(void *arg, struct udp_pcb *pcb,
                        struct pbuf *p,
                        const ip_addr_t *addr, u16_t port)
{
    struct cyw43_sock *cs = (struct cyw43_sock *)arg;
    struct socket     *s;

    used(pcb);

    /* Guard: callback may fire after slot teardown */
    if (cs == NULL || cs->fuzix_sock == NULL) {
        pbuf_free(p);
        return;
    }
    s = cs->fuzix_sock;

    if (cs->rx_head != NULL) {
        pbuf_free(cs->rx_head);     /* drop previous unread datagram   */
    }

    cs->rx_head     = p;
    cs->rx_offset   = 0;
    cs->rx_src_ip   = addr->addr;           /* network byte order      */
    cs->rx_src_port = lwip_htons(port);     /* to network byte order   */

    s->s_iflags |= SI_DATA;
    net_wake(s->s_num);
}

/* ------------------------------------------------------------------ */
/* netproto_* interface implementation                                  */
/* ------------------------------------------------------------------ */

void netproto_setup(struct socket *s)
{
    used(s);
}

void netproto_free(struct socket *s)
{
    uint8_t slot = s->proto.slot;

    if (slot >= NSOCKET)
        return;
    slot_free_entry(slot);
    s->s_state = SS_UNUSED;
}

/*
 * Create a new socket.  Called when userspace invokes socket(2).
 */
int netproto_socket(void)
{
    struct socket *s;
    int            slot;
    uint8_t        stype;

    if (!wifi_up) {
        udata.u_error = ENETDOWN;
        return 0;
    }

    if (udata.u_net.args[1] != AF_INET) {
        udata.u_error = EAFNOSUPPORT;
        return 0;
    }

    switch (udata.u_net.args[2]) {
    case SOCK_STREAM:   stype = SLOT_TCP;   break;
    case SOCK_DGRAM:    stype = SLOT_UDP;   break;
    default:
        udata.u_error = EPROTONOSUPPORT;
        return 0;
    }

    slot = slot_alloc();
    if (slot < 0) {
        udata.u_error = ENOBUFS;
        return 0;
    }

    s = sockets + slot;
    memset(s, 0, sizeof(*s));
    s->s_num      = (uint8_t)slot;
    s->s_type     = stype;
    s->s_class    = udata.u_net.args[2];
    s->s_state    = SS_UNCONNECTED;
    s->s_parent   = 0xFF;
    s->proto.slot = (uint8_t)slot;

    cyw43_socks[slot].type       = stype;
    cyw43_socks[slot].flags      = 0;
    cyw43_socks[slot].fuzix_sock = s;
    cyw43_socks[slot].pcb.tcp    = NULL;
    cyw43_socks[slot].rx_head    = NULL;
    cyw43_socks[slot].rx_offset  = 0;

    net_setup(s);
    udata.u_net.sock = (uint16_t)slot;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Bind – open the lwIP PCB and assign a local port                    */
/* ------------------------------------------------------------------ */

/*
 * do_bind – internal bind helper.
 * port is in network byte order (as stored in sin_port).
 */
static int do_bind(struct socket *s, uint16_t net_port)
{
    struct cyw43_sock *cs;
    uint16_t           hport = lwip_ntohs(net_port); /* host byte order */
    err_t              rc;

    if (s->proto.slot >= NSOCKET) {
        udata.u_error = EBADF;
        return -1;
    }
    cs = &cyw43_socks[s->proto.slot];

    if (cs->type == SLOT_TCP) {
        struct tcp_pcb *pcb = tcp_new();
        if (pcb == NULL) {
            udata.u_error = ENOBUFS;
            return -1;
        }
        rc = tcp_bind(pcb, IP4_ADDR_ANY, hport);
        if (rc != ERR_OK) {
            tcp_abort(pcb);
            udata.u_error = EADDRINUSE;
            return -1;
        }
        tcp_arg(pcb, cs);
        cs->pcb.tcp = pcb;
    } else {
        struct udp_pcb *pcb = udp_new();
        if (pcb == NULL) {
            udata.u_error = ENOBUFS;
            return -1;
        }
        rc = udp_bind(pcb, IP4_ADDR_ANY, hport);
        if (rc != ERR_OK) {
            udp_remove(pcb);
            udata.u_error = EADDRINUSE;
            return -1;
        }
        udp_recv(pcb, udp_recv_cb, cs);
        cs->pcb.udp = pcb;
    }

    s->s_state = SS_BOUND;
    s->src_len = sizeof(struct sockaddr_in);
    return 0;
}

int netproto_autobind(struct socket *s)
{
    s->src_addr.sa.family               = AF_INET;
    s->src_addr.sa.sin.sin_addr.s_addr  = 0;

    /* Scan for an unused ephemeral port in the range 5000-32767.
     * Bail out after one full cycle to avoid an infinite loop when all
     * ports are exhausted.
     */
    {
        uint16_t start = autoport;
        for (;;) {
            s->src_addr.sa.sin.sin_port = lwip_htons(autoport);
            autoport++;
            if (autoport > 32767)
                autoport = 5000;
            if (netproto_find_local(&s->src_addr) == -1)
                break;          /* port is free                        */
            if (autoport == start) {
                udata.u_error = EADDRNOTAVAIL;
                return -1;
            }
        }
    }

    return do_bind(s, s->src_addr.sa.sin.sin_port);
}

int netproto_bind(struct socket *s)
{
    if (udata.u_net.addrbuf.sa.family != AF_INET) {
        udata.u_error = EPROTONOSUPPORT;
        return 0;
    }
    if (lwip_ntohs(udata.u_net.addrbuf.sa.sin.sin_port) < 1024
            && udata.u_euid != 0) {
        udata.u_error = EACCES;
        return 0;
    }
    memcpy(&s->src_addr, &udata.u_net.addrbuf, sizeof(struct ksockaddr));
    return do_bind(s, s->src_addr.sa.sin.sin_port);
}

/* ------------------------------------------------------------------ */
/* Listen                                                               */
/* ------------------------------------------------------------------ */

int netproto_listen(struct socket *s)
{
    struct cyw43_sock *cs;

    if (s->proto.slot >= NSOCKET) {
        udata.u_error = EBADF;
        return -1;
    }
    cs = &cyw43_socks[s->proto.slot];
    struct tcp_pcb    *lpcb;

    if (cs->type != SLOT_TCP || cs->pcb.tcp == NULL) {
        udata.u_error = EINVAL;
        return 0;
    }

    lpcb = tcp_listen(cs->pcb.tcp);
    if (lpcb == NULL) {
        udata.u_error = EADDRINUSE;
        return 0;
    }
    cs->pcb.tcp = lpcb;

    /*
     * Pass the FUZIX socket pointer as the accept-callback argument so
     * tcp_accept_cb can find the listening socket's slot and parent info.
     */
    tcp_arg(lpcb,    s);
    tcp_accept(lpcb, tcp_accept_cb);

    s->s_state = SS_LISTENING;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Connect                                                              */
/* ------------------------------------------------------------------ */

int netproto_begin_connect(struct socket *s)
{
    struct cyw43_sock *cs;

    if (s->proto.slot >= NSOCKET) {
        udata.u_error = EBADF;
        return 0;
    }
    cs = &cyw43_socks[s->proto.slot];
    ip_addr_t          dst;
    uint16_t           dport;
    err_t              rc;

    dst.addr = udata.u_net.addrbuf.sa.sin.sin_addr.s_addr;
    dport    = lwip_ntohs(udata.u_net.addrbuf.sa.sin.sin_port);

    memcpy(&s->dst_addr, &udata.u_net.addrbuf, sizeof(struct ksockaddr));
    s->dst_len = sizeof(struct sockaddr_in);

    if (cs->type == SLOT_TCP) {
        /*
         * The PCB was created during autobind/bind.  Register the
         * data-path callbacks and initiate the TCP handshake.
         */
        if (cs->pcb.tcp == NULL) {
            udata.u_error = ENOTCONN;
            return 0;
        }
        tcp_recv(cs->pcb.tcp, tcp_recv_cb);
        tcp_sent(cs->pcb.tcp, tcp_sent_cb);
        tcp_err(cs->pcb.tcp,  tcp_err_cb);

        rc = tcp_connect(cs->pcb.tcp, &dst, dport, tcp_connected_cb);
        if (rc != ERR_OK) {
            udata.u_error = ECONNREFUSED;
            return 0;
        }
        s->s_state = SS_CONNECTING;
        return 1;   /* Caller should sleep until tcp_connected_cb fires */
    } else {
        /*
         * UDP "connect" just records the default destination in the PCB.
         * No blocking needed.
         */
        if (cs->pcb.udp != NULL)
            udp_connect(cs->pcb.udp, &dst, dport);
        s->s_state = SS_CONNECTED;
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Accept                                                               */
/* ------------------------------------------------------------------ */

/*
 * Scan the socket table for a socket that is waiting to be accepted on
 * the given listener.  Matches WizNet's approach (state != SS_UNUSED &&
 * s_parent == listener slot).
 */
struct socket *netproto_sockpending(struct socket *ls)
{
    struct socket *s = sockets;
    uint8_t        parent = ls->s_num;
    uint8_t        i;

    for (i = 0; i < NSOCKET; i++, s++) {
        if (s->s_state != SS_UNUSED && s->s_parent == parent) {
            s->s_parent = 0xFF;
            return s;
        }
    }
    return NULL;
}

int netproto_accept(struct socket *s)
{
    used(s);
    return 0;
}

int netproto_accept_complete(struct socket *s)
{
    used(s);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Read                                                                 */
/* ------------------------------------------------------------------ */

int netproto_read(struct socket *s)
{
    struct cyw43_sock *cs;

    if (s->proto.slot >= NSOCKET) {
        udata.u_error = EBADF;
        return 0;
    }
    cs = &cyw43_socks[s->proto.slot];
    uint16_t           avail, n;

    /* Give the network stack a chance to deliver data before sleeping  */
    cyw43_arch_poll();

    if (cs->type == SLOT_TCP) {
        if (cs->rx_head == NULL) {
            if (cs->flags & (CFLG_EOF | CFLG_ERR) ||
                    s->s_iflags & SI_EOF)
                return 0;           /* EOF/error – signal end-of-data  */
            return 1;               /* No data yet – caller should sleep */
        }

        /*
         * Only copy from the current (head) pbuf's contiguous payload;
         * rx_offset tracks how far into payload[] we have consumed.
         * Bug-fix: use ->len (bytes in this pbuf), not ->tot_len (sum
         * of the whole chain) to bound the contiguous copy.
         */
        avail = cs->rx_head->len - cs->rx_offset;
        n     = (avail < udata.u_count) ? avail : udata.u_count;

        if (uput((uint8_t *)cs->rx_head->payload + cs->rx_offset,
                 udata.u_base, n) == -1) {
            udata.u_error = EFAULT;
            return 0;
        }

        udata.u_done  += n;
        udata.u_base  += n;
        cs->rx_offset += n;

        /* Advance the queue when the head pbuf is fully consumed      */
        if (cs->rx_offset >= cs->rx_head->len) {
            struct pbuf *next = cs->rx_head->next;
            /* Dechain before freeing so pbuf_free doesn't walk ahead  */
            cs->rx_head->next = NULL;
            pbuf_free(cs->rx_head);
            cs->rx_head   = next;
            cs->rx_offset = 0;
        }

        /* Inform lwIP how many bytes we consumed (opens recv window)  */
        if (cs->pcb.tcp != NULL)
            tcp_recved(cs->pcb.tcp, n);

        if (cs->rx_head == NULL)
            s->s_iflags &= ~SI_DATA;

        return 0;

    } else {
        /* UDP                                                          */
        uint8_t  buf[64];
        uint16_t off;
        uint16_t copied;

        if (cs->rx_head == NULL) {
            if (cs->flags & CFLG_ERR)
                return 0;
            return 1;               /* No datagram yet – sleep          */
        }

        n = cs->rx_head->tot_len;
        if (n > udata.u_count)
            n = udata.u_count;

        /* Copy via a bounce buffer to stay portable across USERMEM modes */
        off = 0;
        while (off < n) {
            uint16_t chunk = n - off;
            if (chunk > (uint16_t)sizeof(buf))
                chunk = (uint16_t)sizeof(buf);
            copied = pbuf_copy_partial(cs->rx_head, buf, chunk, off);
            if (copied == 0) {
                /* pbuf chain is corrupt; discard and report error     */
                pbuf_free(cs->rx_head);
                cs->rx_head   = NULL;
                cs->rx_offset = 0;
                s->s_iflags  &= ~SI_DATA;
                udata.u_error = EIO;
                return 0;
            }
            if (uput(buf, udata.u_base + off, copied) == -1) {
                udata.u_error = EFAULT;
                return 0;
            }
            off += copied;
        }

        udata.u_done += off;
        udata.u_base += off;

        /* Fill in the source address for recvfrom()                   */
        udata.u_net.addrbuf.sa.sin.sin_family          = AF_INET;
        udata.u_net.addrbuf.sa.sin.sin_addr.s_addr     = cs->rx_src_ip;
        udata.u_net.addrbuf.sa.sin.sin_port            = cs->rx_src_port;
        udata.u_net.addrlen = sizeof(struct sockaddr_in);

        /* Consume the datagram                                        */
        pbuf_free(cs->rx_head);
        cs->rx_head  = NULL;
        cs->rx_offset = 0;
        s->s_iflags &= ~SI_DATA;
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Write                                                                */
/* ------------------------------------------------------------------ */

arg_t netproto_write(struct socket *s, struct ksockaddr *ka)
{
    struct cyw43_sock *cs;

    if (s->proto.slot >= NSOCKET) {
        udata.u_error = EBADF;
        return 0;
    }
    cs = &cyw43_socks[s->proto.slot];
    uint16_t           n;
    err_t              rc;

    if (cs->type == SLOT_TCP) {
        uint16_t room;
        uint16_t done = 0;
        uint8_t  buf[64];   /* Small stack buffer; avoid stack overflow */

        if (cs->pcb.tcp == NULL) {
            udata.u_error = ENOTCONN;
            return 0;
        }

        room = tcp_sndbuf(cs->pcb.tcp);
        if (room == 0) {
            s->s_iflags |= SI_THROTTLE;
            return 1;               /* No TX space – sleep             */
        }

        n = (udata.u_count < room) ? udata.u_count : room;

        /* Copy from user space in small chunks via a bounce buffer     */
        while (done < n) {
            uint16_t chunk = n - done;
            if (chunk > (uint16_t)sizeof(buf))
                chunk = (uint16_t)sizeof(buf);
            if (uget(udata.u_base + done, buf, chunk) == -1) {
                if (done == 0) {
                    udata.u_error = EFAULT;
                    return 0;
                }
                break;
            }
            rc = tcp_write(cs->pcb.tcp, buf, chunk, TCP_WRITE_FLAG_COPY);
            if (rc != ERR_OK) {
                /* lwIP TX buffer full mid-write; commit what we have   */
                if (done == 0) {
                    udata.u_error = EIO;
                    return 0;
                }
                break;
            }
            done += chunk;
        }

        tcp_output(cs->pcb.tcp);    /* Push buffered data immediately  */

        udata.u_done += done;
        udata.u_base += done;
        return 0;

    } else {
        /* UDP                                                          */
        struct pbuf *p;
        uint16_t     done = 0;
        uint8_t      buf[64];

        if (udata.u_count > 1472) {
            udata.u_error = EMSGSIZE;
            return 0;
        }

        if (cs->pcb.udp == NULL) {
            udata.u_error = ENOTCONN;
            return 0;
        }

        p = pbuf_alloc(PBUF_TRANSPORT, udata.u_count, PBUF_RAM);
        if (p == NULL) {
            udata.u_error = ENOBUFS;
            return 0;
        }

        /* Copy payload into the pbuf via a bounce buffer              */
        while (done < udata.u_count) {
            uint16_t chunk = udata.u_count - done;
            uint16_t copied;
            if (chunk > (uint16_t)sizeof(buf))
                chunk = (uint16_t)sizeof(buf);
            if (uget(udata.u_base + done, buf, chunk) == -1) {
                pbuf_free(p);
                udata.u_error = EFAULT;
                return 0;
            }
            /* pbuf_take_at copies buf into the pbuf at offset done    */
            if (pbuf_take_at(p, buf, chunk, done) != ERR_OK) {
                pbuf_free(p);
                udata.u_error = ENOBUFS;
                return 0;
            }
            done += chunk;
        }

        /*
         * For a connected UDP socket use udp_send() (the PCB already
         * has a destination from udp_connect()).  For sendto(), use
         * udp_sendto() with the caller-supplied address.
         */
        if (ka != NULL && ka->sa.family == AF_INET &&
                ka->sa.sin.sin_addr.s_addr != 0 &&
                ka->sa.sin.sin_port != 0) {
            ip_addr_t dst;
            dst.addr = ka->sa.sin.sin_addr.s_addr;
            rc = udp_sendto(cs->pcb.udp, p,
                            &dst, lwip_ntohs(ka->sa.sin.sin_port));
        } else {
            rc = udp_send(cs->pcb.udp, p);
        }
        pbuf_free(p);

        if (rc != ERR_OK) {
            udata.u_error = EIO;
            return 0;
        }

        udata.u_done += udata.u_count;
        udata.u_base += udata.u_count;
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Shutdown / close                                                     */
/* ------------------------------------------------------------------ */

arg_t netproto_shutdown(struct socket *s, uint8_t how)
{
    struct cyw43_sock *cs;

    if (s->proto.slot >= NSOCKET)
        return 0;   /* nothing to do for an invalid slot */
    cs = &cyw43_socks[s->proto.slot];

    if (how & SI_SHUTW) {
        s->s_iflags |= SI_SHUTW;
        if (cs->type == SLOT_TCP && cs->pcb.tcp != NULL)
            tcp_shutdown(cs->pcb.tcp, 0, 1);
    }
    if (how & SI_SHUTR)
        s->s_iflags |= SI_SHUTR;

    return 0;
}

int netproto_close(struct socket *s)
{
    struct cyw43_sock *cs;

    if (s->proto.slot >= NSOCKET)
        return 0;
    cs = &cyw43_socks[s->proto.slot];

    if (cs->type == SLOT_TCP) {
        if (cs->pcb.tcp != NULL) {
            /* Detach our callbacks before closing so we don't get a
             * spurious error callback after the PCB is freed.         */
            tcp_arg(cs->pcb.tcp,  NULL);
            tcp_recv(cs->pcb.tcp, NULL);
            tcp_sent(cs->pcb.tcp, NULL);
            tcp_err(cs->pcb.tcp,  NULL);
            if (tcp_close(cs->pcb.tcp) != ERR_OK)
                tcp_abort(cs->pcb.tcp);
            cs->pcb.tcp = NULL;
        }
    } else if (cs->type == SLOT_UDP) {
        if (cs->pcb.udp != NULL) {
            udp_remove(cs->pcb.udp);
            cs->pcb.udp = NULL;
        }
    }

    /* Discard any pending receive data                                */
    if (cs->rx_head != NULL) {
        pbuf_free(cs->rx_head);
        cs->rx_head = NULL;
    }

    s->s_state = SS_CLOSED;
    netproto_free(s);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Local-address lookup (used by autobind)                             */
/* ------------------------------------------------------------------ */

int netproto_find_local(struct ksockaddr *ka)
{
    struct socket *s = sockets;
    uint8_t        i;

    for (i = 0; i < NSOCKET; i++, s++) {
        if (s->s_state < SS_BOUND || s->src_addr.sa.family != AF_INET)
            continue;
        if (s->src_addr.sa.sin.sin_port != ka->sa.sin.sin_port)
            continue;
        if (s->src_addr.sa.sin.sin_addr.s_addr == 0 ||
            ka->sa.sin.sin_addr.s_addr == 0 ||
            s->src_addr.sa.sin.sin_addr.s_addr ==
                ka->sa.sin.sin_addr.s_addr)
            return (int)i;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* ioctl – interface configuration and WiFi control                    */
/* ------------------------------------------------------------------ */

arg_t netproto_ioctl(struct socket *s, int op, char *ifr_u)
{
    static struct ifreq ifr;
    struct netif       *nif;

    used(s);

    /* WiFi connection/association request                             */
    if (op == SIOCWIFICONNECT) {
        struct wifi_req wr;
        uint32_t        auth;
        int             rc;

        if (uget(ifr_u, &wr, sizeof(wr)) == -1) {
            udata.u_error = EFAULT;
            return -1;
        }
        wr.ssid[sizeof(wr.ssid) - 1]         = '\0';
        wr.password[sizeof(wr.password) - 1] = '\0';

        auth = (wr.auth != 0) ? wr.auth : (uint32_t)CYW43_AUTH_WPA2_AES_PSK;

        rc = cyw43_arch_wifi_connect_timeout_ms(
                wr.ssid,
                wr.password[0] ? wr.password : NULL,
                auth,
                30000);
        if (rc != 0) {
            udata.u_error = ENETUNREACH;
            return -1;
        }
        wifi_up = 1;
        return 0;
    }

    if (uget(ifr_u, &ifr, sizeof(ifr)) == -1) {
        udata.u_error = EFAULT;
        return -1;
    }

    /* We expose a single interface named "wlan0"                      */
    if (op != SIOCGIFNAME && strcmp(ifr.ifr_name, "wlan0") != 0) {
        udata.u_error = ENODEV;
        return -1;
    }

    nif = netif_default;

    switch (op) {
    case SIOCGIFNAME:
        if (ifr.ifr_ifindex != 0) {
            udata.u_error = ENODEV;
            return -1;
        }
        memcpy(ifr.ifr_name, "wlan0", 6);
        goto copyback;

    case SIOCGIFINDEX:
        ifr.ifr_ifindex = 0;
        goto copyback;

    case SIOCGIFFLAGS:
        ifr.ifr_flags = (short)(IFF_BROADCAST | IFF_RUNNING);
        if (wifi_up)
            ifr.ifr_flags |= (short)(IFF_UP | IFF_LINKUP);
        goto copyback;

    case SIOCGIFADDR:
        ifr.ifr_addr.sa.sin.sin_family = AF_INET;
        ifr.ifr_addr.sa.sin.sin_addr.s_addr =
            (nif != NULL) ? nif->ip_addr.addr : 0;
        goto copyback;

    case SIOCGIFNETMASK:
        ifr.ifr_netmask.sa.sin.sin_family = AF_INET;
        ifr.ifr_netmask.sa.sin.sin_addr.s_addr =
            (nif != NULL) ? nif->netmask.addr : 0;
        goto copyback;

    case SIOCGIFGWADDR:
        ifr.ifr_gwaddr.sa.sin.sin_family = AF_INET;
        ifr.ifr_gwaddr.sa.sin.sin_addr.s_addr =
            (nif != NULL) ? nif->gw.addr : 0;
        goto copyback;

    case SIOCGIFBRDADDR:
        ifr.ifr_broadaddr.sa.sin.sin_family = AF_INET;
        if (nif != NULL) {
            ifr.ifr_broadaddr.sa.sin.sin_addr.s_addr =
                (nif->ip_addr.addr & nif->netmask.addr) | ~nif->netmask.addr;
        } else {
            ifr.ifr_broadaddr.sa.sin.sin_addr.s_addr = 0xFFFFFFFFUL;
        }
        goto copyback;

    case SIOCGIFHWADDR: {
        uint8_t mac[6];
        cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_STA, mac);
        memcpy(ifr.ifr_hwaddr.sa.hw.shw_addr, mac, 6);
        ifr.ifr_hwaddr.sa.hw.shw_family = HW_WLAN;
        goto copyback;
    }

    case SIOCGIFMTU:
        ifr.ifr_mtu = (nif != NULL) ? (int)nif->mtu : 1500;
        goto copyback;

    /* Setters – propagate changes into the lwIP netif.
     * Return ENETDOWN if the netif is not yet up (nif == NULL).        */
    case SIOCSIFADDR:
        if (nif == NULL) { udata.u_error = ENETDOWN; return -1; }
        {
            ip4_addr_t ip;
            ip.addr = ifr.ifr_addr.sa.sin.sin_addr.s_addr;
            netif_set_ipaddr(nif, &ip);
        }
        return 0;

    case SIOCSIFNETMASK:
        if (nif == NULL) { udata.u_error = ENETDOWN; return -1; }
        {
            ip4_addr_t nm;
            nm.addr = ifr.ifr_netmask.sa.sin.sin_addr.s_addr;
            netif_set_netmask(nif, &nm);
        }
        return 0;

    case SIOCSIFGWADDR:
        if (nif == NULL) { udata.u_error = ENETDOWN; return -1; }
        {
            ip4_addr_t gw;
            gw.addr = ifr.ifr_gwaddr.sa.sin.sin_addr.s_addr;
            netif_set_gw(nif, &gw);
        }
        return 0;

    case SIOCSIFFLAGS:
        if (nif == NULL) { udata.u_error = ENETDOWN; return -1; }
        if (ifr.ifr_flags & IFF_UP)
            netif_set_up(nif);
        else
            netif_set_down(nif);
        return 0;

    default:
        udata.u_error = EINVAL;
        return -1;
    }

copyback:
    return uput(&ifr, ifr_u, sizeof(ifr));
}

/* ------------------------------------------------------------------ */
/* plt_idle – poll the CYW43 / lwIP stack when the CPU is idle         */
/* ------------------------------------------------------------------ */

/*
 * This definition replaces the wfi-only plt_idle in tricks.S.
 * tricks.S protects its definition with #ifndef FUZIX_CYW43_BUILD
 * so there is no duplicate-symbol error.
 *
 * We call cyw43_arch_poll() first (which may fire callbacks and
 * call wakeup()), then fall through to WFI so we don't busy-spin
 * while genuinely idle.
 */
void plt_idle(void)
{
    cyw43_arch_poll();
    __asm volatile ("wfi");
}

/* ------------------------------------------------------------------ */
/* netdev_init – called once from device_init() at boot                */
/* ------------------------------------------------------------------ */

void netdev_init(void)
{
    /* Mark all slots free */
    sock_free_mask = (uint8_t)((1u << NSOCKET) - 1u);
    autoport       = 5000;
    wifi_up        = 0;

    memset(cyw43_socks, 0, sizeof(cyw43_socks));
    memset(sock_wake,   0, sizeof(sock_wake));

    if (cyw43_arch_init() != 0) {
        kputs("cyw43: init failed\n");
        return;
    }

    /*
     * Light the power LED via the CYW43 GPIO now that the chip is up.
     * This is the earliest safe point; driving it before cyw43_arch_init()
     * returns is undefined behaviour (the SPI link is not ready yet).
     * main() skips the LED init for PICO_CYW43_SUPPORTED boards and
     * defers it here instead.
     */
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

    cyw43_arch_enable_sta_mode();
    kputs("cyw43: WiFi ready\n");

#if defined(WIFI_SSID) && (sizeof(WIFI_SSID) > 1)
    kprintf("cyw43: connecting to '%s'...\n", WIFI_SSID);
    if (cyw43_arch_wifi_connect_timeout_ms(
            WIFI_SSID,
            (sizeof(WIFI_PASSWORD) > 1) ? WIFI_PASSWORD : NULL,
            WIFI_AUTH,
            30000) == 0) {
        wifi_up = 1;
        kputs("cyw43: connected\n");
    } else {
        kputs("cyw43: connect failed (use SIOCWIFICONNECT to retry)\n");
    }
#endif
}

#endif /* CONFIG_NET_CYW43 */
