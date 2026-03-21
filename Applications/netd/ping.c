/*
  A ipv4 ping client

  (C) 2017, Brett M. Gordon, GPL2 under Fuzix
  Enhanced with RTT timing, min/max/avg/sdev statistics, -c count,
  and alarm race fix via setjmp/longjmp.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <setjmp.h>
#include "netdb.h"

#define AF_INET     1
#define SOCK_RAW    1

struct ip {
    uint8_t ver;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t cksum;
    uint32_t src;
    uint32_t dest;
};

struct icmp {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
};

#define PING_DATA "FUZIX ping client"
#define MAXBUF 256

static int fd;
static char buf[MAXBUF];
static struct sockaddr_in addr;
static int id;
static int seq = 0;
static int sent = 0;
static int nrecv = 0;
static int count = 0;       /* 0 = unlimited */

/* RTT stats in milliseconds */
static double rtt_min;
static double rtt_max;
static double rtt_sum;
static double rtt_sum2;     /* sum of squares for stddev */

static jmp_buf alarm_jmp;

static void print_stats(void)
{
    printf("\n--- ping statistics ---\n");
    printf("%d packets transmitted, %d received", sent, nrecv);
    if (sent > 0)
        printf(", %d%% packet loss", (sent - nrecv) * 100 / sent);
    printf("\n");
    if (nrecv > 0) {
        double avg = rtt_sum / nrecv;
        double variance = (rtt_sum2 / nrecv) - (avg * avg);
        double sdev = (variance > 0.0) ? sqrt(variance) : 0.0;
        printf("rtt min/avg/max/sdev = %.3f/%.3f/%.3f/%.3f ms\n",
               rtt_min, avg, rtt_max, sdev);
    }
}

static void alarm_handler(int signum)
{
    longjmp(alarm_jmp, 1);
}

static void int_handler(int signum)
{
    print_stats();
    exit(0);
}

/* print an IP address */
static void ipprint(uint32_t *a)
{
    unsigned char *b = (unsigned char *)a;
    printf("%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* returns inet checksum */
static uint16_t cksum(char *b, int len)
{
    uint16_t sum = 0;
    uint16_t t;
    char *e = b + len;
    b[len] = 0;
    while (b < e) {
        t = ((unsigned char)b[0] << 8) + (unsigned char)b[1];
        sum += t;
        if (sum < t) sum++;
        b += 2;
    }
    return ~sum;
}

/* get time as milliseconds using CLOCK_MONOTONIC */
static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

/* sends a ping to remote */
static void sendping(void)
{
    struct icmp *i = (struct icmp *)buf;
    int dlen = strlen(PING_DATA);
    int l = 8 + dlen;
    memset(buf, 0, l + 1);
    i->type = 8;  /* echo request */
    i->id = htons(id);
    i->seq = htons(seq);
    memcpy(&buf[8], PING_DATA, dlen);
    i->cksum = htons(cksum(buf, l));
    write(fd, buf, l);
    sent++;
    seq++;
}

static void my_open(const char *hostname)
{
    struct hostent *h;

    h = gethostbyname(hostname);
    if (!h) {
        fprintf(stderr, "ping: cannot resolve hostname\n");
        exit(1);
    }
    memcpy(&addr.sin_addr.s_addr, h->h_addr_list[0], 4);

    fd = socket(AF_INET, SOCK_RAW, 1);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    addr.sin_port = 0;
    addr.sin_family = AF_INET;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    int x;
    time_t t;
    struct icmp *icmpbuf;
    struct ip *ipbuf;
    struct ip *ipbuf2;
    const char *hostname;
    double send_time, rtt;

    srand(time(&t));
    id = rand();

    signal(SIGINT, int_handler);

    /* parse optional -c count */
    if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
        count = atoi(argv[2]);
        if (count <= 0) {
            fprintf(stderr, "ping: invalid count\n");
            exit(1);
        }
        if (argc < 4) {
            fprintf(stderr, "usage: ping [-c count] hostname\n");
            exit(1);
        }
        hostname = argv[3];
    } else if (argc >= 2) {
        hostname = argv[1];
    } else {
        fprintf(stderr, "usage: ping [-c count] hostname\n");
        exit(1);
    }

    my_open(hostname);

    while (1) {
        send_time = now_ms();
        sendping();

        signal(SIGALRM, alarm_handler);
        alarm(2);

        if (setjmp(alarm_jmp) != 0) {
            /* alarm fired before a reply arrived */
            printf("Request timeout for icmp_seq=%d\n", seq - 1);
            goto next;
        }

    ragain:
        x = read(fd, buf, MAXBUF);
        if (x > 0) {
            ipbuf = (struct ip *)buf;
            if (ipbuf->ver >> 4 != 4)
                goto ragain;

            icmpbuf = (struct icmp *)(buf + (ipbuf->ver & 15) * 4);

            /* dest unreachable */
            if (icmpbuf->type == 3) {
                ipbuf2 = (struct ip *)(icmpbuf + 1);
                icmpbuf = (struct icmp *)((char *)ipbuf2 + (ipbuf2->ver & 15) * 4);
                if (icmpbuf->id == htons(id)) {
                    printf("ICMP: from ");
                    ipprint(&ipbuf->src);
                    printf(" dest unreachable\n");
                }
                goto ragain;
            }

            /* filter for our id */
            if (icmpbuf->id != htons(id))
                goto ragain;

            alarm(0);   /* cancel pending alarm */

            rtt = now_ms() - send_time;

            /* update RTT stats */
            nrecv++;
            if (nrecv == 1 || rtt < rtt_min) rtt_min = rtt;
            if (nrecv == 1 || rtt > rtt_max) rtt_max = rtt;
            rtt_sum  += rtt;
            rtt_sum2 += rtt * rtt;

            printf("%d bytes from ", x);
            ipprint(&ipbuf->src);
            printf(": icmp_seq=%d ttl=%d time=%.3f ms\n",
                   ntohs(icmpbuf->seq), ipbuf->ttl, rtt);
        }

    next:
        if (count > 0 && sent >= count) {
            print_stats();
            exit(0);
        }
        sleep(1);
    }
}
