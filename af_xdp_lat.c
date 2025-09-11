/*
 * AF_XDP Latency Measurement Tool - Architecture Overview
 * ======================================================
 *
 * This program implements a ping-pong latency measurement system using AF_XDP sockets.
 * It operates in two modes that work together to measure round-trip time (RTT):
 *
 * TEST MODE (Client):
 * ------------------
 * 1. Creates and sends Ethernet frames with embedded timestamps
 * 2. Waits for echo responses from the echo server
 * 3. Calculates RTT by comparing original send time with receive time
 * 4. Provides detailed timing breakdown (echo delay + return delay)
 * 5. Optionally logs events to ftrace for kernel-level analysis
 *
 * ECHO MODE (Server):
 * ------------------
 * 1. Listens for incoming packets on the specified interface
 * 2. Captures precise receive timestamps using CLOCK_TAI
 * 3. Adds echo timestamp to the packet payload
 * 4. Swaps source/destination MAC addresses
 * 5. Sends the packet back immediately to minimize processing delay
 *
 * PACKET STRUCTURE:
 * ----------------
 * [Ethernet Header (14 bytes)]
 * [Timestamp Payload (16 bytes)]
 *   - tx_timestamp_ns: Original send time (set by test mode)
 *   - echo_timestamp_ns: Echo processing time (set by echo mode)
 * [Padding to minimum frame size if needed]
 *
 * TIMING MEASUREMENT:
 * ------------------
 * - RTT = receive_time - tx_timestamp_ns
 * - Echo Delay = echo_timestamp_ns - tx_timestamp_ns
 * - Return Delay = receive_time - echo_timestamp_ns
 *
 * XDP INTEGRATION:
 * ---------------
 * - Uses custom XDP program (af_xdp_kern.o) to redirect target packets to AF_XDP
 * - Bypasses kernel network stack for minimal latency
 * - Supports native, SKB, and auto-detect XDP modes
 * - Updates XSKMAP to route packets to userspace socket
 *
 * USAGE PATTERN:
 * -------------
 * Terminal 1: ./af_xdp_lat -d veth_b -M echo        # Start echo server
 * Terminal 2: ./af_xdp_lat -d veth_a -M test -c 10  # Run 10 ping-pong cycles
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <poll.h>

#include "common.h"
#include "config.h"
#include "utils.h"
#include "ftrace.h"

/* Timestamp payload structure */
struct timestamp_payload {
    uint64_t tx_timestamp_ns;    /* Original send timestamp */
    uint64_t echo_timestamp_ns;  /* Echo timestamp */
};

/* struct to hold XDP ring setup */
struct xsk_rings {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx_ring;
    struct xsk_ring_prod tx_ring;
    struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons comp_ring;
    int rx_offset;
    int tx_offset;
};

/* Program modes */
typedef enum {
    MODE_TEST,
    MODE_ECHO
} program_mode_t;

/* Global configuration */
static volatile int keep_running = 1;
static program_mode_t program_mode = MODE_TEST;
static int packet_count_limit = 0;  /* 0 means no limit */
static int ftrace_enabled = 0;
static int ftrace_fd = -1;
static int receive_timeout_ms = 1000;  /* Default 1 second timeout for packet reception */
static int64_t send_interval_us = 500;  /* Default 500µs interval between packets */
static int echo_poll_mode = 0;  /* 0 = busy wait, 1 = poll mode */

static const struct option long_options[] = {
    {"help",        no_argument,       NULL, 'h'},
    {"dev",         required_argument, NULL, 'd'},
    {"skb-mode",    no_argument,       NULL, 'S'},
    {"native-mode", no_argument,       NULL, 'N'},
    {"auto-mode",   no_argument,       NULL, 'A'},
    {"debug",       no_argument,       NULL, 'D'},
    {"mode",        required_argument, NULL, 'M'},
    {"count",       required_argument, NULL, 'c'},
    {"ftrace",      no_argument,       NULL, 'F'},
    {"timeout",     required_argument, NULL, 't'},
    {"output",      required_argument, NULL, 'o'},
    {"rtt-threshold", required_argument, NULL, 'r'},
    {"no-detach-on-exit", no_argument, NULL, 'n'},
    {"interval",    required_argument, NULL, 'i'},
    {"poll",        no_argument,       NULL, 'p'},
    {0, 0, NULL, 0}
};

static void usage(const char *prog_name)
{
    printf("Usage: %s [options]\n"
           "Options:\n"
           "  -h, --help          Show this help message\n"
           "  -d, --dev <ifname>  Operate on device <ifname>\n"
           "  -M, --mode <mode>   Program mode: test, echo (default: test)\n"
           "  -c, --count <num>   Stop after processing <num> packets (0 = no limit)\n"
           "  -o, --output <path> Output a CSV file with latencies samples\n"
           "  -t, --timeout <ms>  Timeout in milliseconds to wait for packet response (default: 5000)\n"
           "  -r, --rtt-threshold <us> Stop test when RTT exceeds threshold in microseconds (default: no threshold)\n"
           "  -i, --interval <us> Interval in microseconds between packet sends (default: 500)\n"
           "  -p, --poll          Use poll mode for echo (reduces CPU usage, may increase latency)\n"
           "  -S, --skb-mode      Install XDP program in SKB (AKA generic) mode\n"
           "  -N, --native-mode   Install XDP program in native mode (default mode)\n"
           "  -n, --no-detach-on-exit   Do no detach XDP program on exit\n"
           "  -A, --auto-mode     Auto-detect SKB or native mode\n"
           "  -D, --debug         Enable debug output\n"
           "  -F, --ftrace        Enable ftrace output\n",
           prog_name);
}

static void signal_handler(int sig) {
    keep_running = 0;
    printf("\nReceived signal %d, shutting down...\n", sig);
}

/* Display packet information with RTT calculation */
static void display_packet_info(void *pkt_data, __u32 len, const char *direction)
{
    printf("\n=== %s Packet ===\n", direction);
    printf("Length: %u bytes\n", len);

    /* Display Ethernet header */
    if (len >= sizeof(struct ethhdr)) {
        struct ethhdr *eth = (struct ethhdr *)pkt_data;
        printf("Ethernet Header:\n");
        printf("  Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("  Src MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("  EtherType: 0x%04x\n", ntohs(eth->h_proto));

        /* Display timestamp information if available */
        if (len >= sizeof(struct ethhdr) + sizeof(struct timestamp_payload)) {
            struct timestamp_payload *payload = (struct timestamp_payload *)((char *)pkt_data + sizeof(struct ethhdr));
            uint64_t current_time = get_timestamp_ns();

            printf("Timestamp Info:\n");
            printf("  TX timestamp: %lu ns\n", payload->tx_timestamp_ns);
            printf("  Echo timestamp: %lu ns\n", payload->echo_timestamp_ns);
            printf("  Current time: %lu ns\n", current_time);

            if (strcmp(direction, "Received") == 0 && payload->tx_timestamp_ns > 0) {
                uint64_t rtt_ns = current_time - payload->tx_timestamp_ns;
                printf("  RTT: %lu ns (%.3f μs)\n", rtt_ns, rtt_ns / 1000.0);

                if (payload->echo_timestamp_ns > 0) {
                    uint64_t echo_delay = payload->echo_timestamp_ns - payload->tx_timestamp_ns;
                    uint64_t return_delay = current_time - payload->echo_timestamp_ns;
                    printf("  Echo delay: %lu ns (%.3f μs)\n", echo_delay, echo_delay / 1000.0);
                    printf("  Return delay: %lu ns (%.3f μs)\n", return_delay, return_delay / 1000.0);
                }
            }
        }
    }

    /* Display raw packet data (first 64 bytes) */
    if (debug_enabled) {
        printf("Raw packet data (first %d bytes):\n", len > 64 ? 64 : len);
        unsigned char *pkt_bytes = (unsigned char *)pkt_data;
        for (int i = 0; i < len && i < 64; i++) {
            if (i % 16 == 0)
                printf("  %04x: ", i);
            printf("%02x ", pkt_bytes[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        if (len % 16 != 0)
            printf("\n");
    }

    printf("========================\n");
}

/* Write packet send event to ftrace marker */
static void write_ftrace_send(int packet_num, uint64_t timestamp_ns)
{
    char buffer[256];
    int len;

    if (ftrace_fd < 0) return;

    len = snprintf(buffer, sizeof(buffer),
                  "af_xdp_send: packet=%d timestamp=%lu\n",
                  packet_num, timestamp_ns);

    if (write(ftrace_fd, buffer, len) < 0) {
        debug_printf("Failed to write send event to ftrace marker: %s\n", strerror(errno));
    }
}

static void wait_for_tx_completion(struct xsk_ring_cons *comp_ring)
{
    /* Wait for TX completion before next iteration */
    __u32 comp_idx;
    unsigned int comp;
    int timeout_count = 0;

    while ((comp = xsk_ring_cons__peek(comp_ring, 1, &comp_idx)) < 1) {
        usleep(1);
        timeout_count++;
        if (timeout_count > 5000) { /* 5ms timeout for TX completion */
            debug_printf("TX completion timeout\n");
            break;
        }
    }

    if (comp > 0) {
        __u64 comp_addr = *xsk_ring_cons__comp_addr(comp_ring, comp_idx);
        debug_printf("TX completed: addr=0x%llx\n", comp_addr);
        xsk_ring_cons__release(comp_ring, comp);
    }
}

/* Common function to send a packet with last-moment timestamp */
static int send_packet(struct xsk_rings *rings, void *buffer, __u32 len, int wait_completion, uint64_t *tx_timestamp)
{
    static int send_packet_counter = 0;
    unsigned long long addr = rings->tx_offset;
    __u32 tx_idx;
    int err = xsk_ring_prod__reserve(&rings->tx_ring, 1, &tx_idx);
    if (err != 1) {
        debug_printf("Failed to reserve TX ring slot: %d\n", err);
        return -1;
    }

    /* Set timestamp at the last possible moment before sending */
    void *pkt_data = xsk_umem__get_data(buffer, addr);
    uint64_t send_timestamp = 0;
    if (len >= sizeof(struct ethhdr) + sizeof(struct timestamp_payload)) {
        struct timestamp_payload *payload = (struct timestamp_payload *)((char *)pkt_data + sizeof(struct ethhdr));
        if (payload->tx_timestamp_ns == 0) {  /* Only set if not already set */
            payload->tx_timestamp_ns = get_timestamp_ns();
        }
        send_timestamp = payload->tx_timestamp_ns;
    } else {
        send_timestamp = get_timestamp_ns();
    }

    /* output TX timestamp if needed */
    if(tx_timestamp) {
        *tx_timestamp = send_timestamp;
    }

    /* Set up TX descriptor */
    xsk_ring_prod__tx_desc(&rings->tx_ring, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&rings->tx_ring, tx_idx)->len = len;
    xsk_ring_prod__submit(&rings->tx_ring, 1);

    /* Send packet immediately */
    int xsk_fd = xsk_socket__fd(rings->xsk);
    ssize_t send_result = sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (send_result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            debug_printf("sendto would block (queue full)\n");
        } else {
            debug_printf("sendto failed: %s\n", strerror(errno));
        }
        return -1;
    }

    send_packet_counter++;
    debug_printf("Packet sent successfully\n");

    if (ftrace_enabled) {
        write_ftrace_send(send_packet_counter, send_timestamp);
    }

    /* Wait for completion if requested */
    if (wait_completion)
        wait_for_tx_completion(&rings->comp_ring);

    return 0;
}

/* Common function to handle received packets with immediate timestamp */
static int handle_received_packet(struct xsk_ring_cons *rx_ring, void *buffer,
                                 __u32 *rx_idx, __u64 *addr, __u32 *len, void **pkt_data,
                                 uint64_t *rx_timestamp)
{
    unsigned int rcvd = xsk_ring_cons__peek(rx_ring, 1, rx_idx);
    if (rcvd > 0) {
        /* Capture timestamp immediately upon detecting packet */
        *rx_timestamp = get_timestamp_ns();
        // TODO: XDP seem to be able to output HW TS
        //       See: https://docs.kernel.org/networking/xdp-rx-metadata.html
        //       That might be interesting data

        *addr = xsk_ring_cons__rx_desc(rx_ring, *rx_idx)->addr;
        *len = xsk_ring_cons__rx_desc(rx_ring, *rx_idx)->len;
        *pkt_data = xsk_umem__get_data(buffer, *addr);
        return 1;
    }
    return 0;
}

/* Create AF_PACKET interface socket and bind it to the specified interface */
static int create_interface_socket(int ifindex)
{
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        debug_printf("Failed to create AF_PACKET interface socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* Bind socket to specific interface using sockaddr_ll */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        debug_printf("Failed to bind AF_PACKET socket to interface ifindex %d: %s\n", 
                    ifindex, strerror(errno));
        close(sockfd);
        return -1;
    }
    
    debug_printf("AF_PACKET interface socket bound to interface ifindex %d\n", ifindex);
    debug_printf("Interface socket created (fd=%d)\n", sockfd);
    return sockfd;
}

/* Get device MTU using the provided AF_PACKET interface socket */
static int get_device_mtu_and_frame_size_early(int sockfd, const char *ifname, int *mtu, int *frame_size)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFMTU, &ifr) < 0) {
        fprintf(stderr, "Error: Failed to get MTU for interface %s: %s\n", ifname, strerror(errno));
        return -1;
    }

    *mtu = ifr.ifr_mtu;
    
    /* Calculate frame size: MTU + Ethernet header + some padding for alignment */
    int calculated_frame_size = *mtu + sizeof(struct ethhdr) + 64; /* 64 bytes padding */
    
    /* Ensure frame size is at least the default XSK frame size */
    if (calculated_frame_size < XSK_UMEM__DEFAULT_FRAME_SIZE) {
        calculated_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
    }
    
    /* Round up to next power of 2 for better memory alignment */
    int power_of_2 = 1;
    while (power_of_2 < calculated_frame_size) {
        power_of_2 <<= 1;
    }
    
    *frame_size = power_of_2;

    debug_printf("Interface %s: MTU=%d, calculated frame size=%d\n", ifname, *mtu, *frame_size);
    return 0;
}

/* Get interface hardware address using the provided AF_PACKET interface socket */
static int get_interface_hwaddr(int sockfd, const char *ifname, unsigned char *hwaddr)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        debug_printf("Failed to get hardware address for interface %s: %s\n", ifname, strerror(errno));
        return -1;
    }

    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    debug_printf("Interface %s hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname, hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return 0;
}

/* Global variable to store interface hardware address */
static unsigned char interface_hwaddr[ETH_ALEN];

/* Fill ethernet packet for test mode with timestamp and real source MAC */
static void fill_ethernet_packet(void *buffer, __u32 *packet_len)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;

    /* Destination MAC (broadcast) */
    memset(eth->h_dest, 0xff, ETH_ALEN);

    /* Source MAC (use actual interface hardware address) */
    memcpy(eth->h_source, interface_hwaddr, ETH_ALEN);

    eth->h_proto = htons(TARGET_ETHERTYPE);

    /* Add timestamp payload - timestamp will be set just before sending */
    struct timestamp_payload *payload = (struct timestamp_payload *)((char *)buffer + sizeof(struct ethhdr));
    payload->tx_timestamp_ns = 0;  /* Will be filled just before send */
    payload->echo_timestamp_ns = 0;  /* Will be filled by echo */

    *packet_len = sizeof(struct ethhdr) + sizeof(struct timestamp_payload);

    /* Ensure minimum Ethernet frame size */
    if (*packet_len < 64) {
        memset((char *)buffer + *packet_len, 0, 64 - *packet_len);
        *packet_len = 64;
    }
}

/* Common initialization for both test and echo modes */
static int initialize_fill_ring(struct xsk_rings *rings, const char *mode_name)
{
    __u32 fill_idx;
    int fill_ret = xsk_ring_prod__reserve(&rings->fill_ring, 1, &fill_idx);
    if (fill_ret == 1) {
        *xsk_ring_prod__fill_addr(&rings->fill_ring, fill_idx) = rings->rx_offset;
        xsk_ring_prod__submit(&rings->fill_ring, 1);
        debug_printf("Fill ring initialized with RX buffer at offset %d for %s mode\n", 
                    rings->rx_offset, mode_name);
        return 0;
    } else {
        fprintf(stderr, "Error: Failed to initialize fill ring for %s mode: %d\n", 
                mode_name, fill_ret);
        return -1;
    }
}

/* Test mode implementation with receive timeout and retry logic */
static int run_test_mode(struct xsk_rings *rings, void *buffer, FILE *output_f,
                        uint64_t rtt_threshold_us)
{
    int packet_counter = -10; /* <0 number are warm-up */
    int packets_sent = packet_counter;
    int timeouts = 0;
    long next_send_time_us = 0;
    uint64_t rtt_max_ns = 0, echo_delay_max_ns = 0, return_delay_max_ns = 0;

    /* Initialize fill ring */
    if (initialize_fill_ring(rings, "test") < 0) {
        return 1;
    }

    printf("Starting ping-pong test mode with RTT measurement...\n");
    if (packet_count_limit > 0) {
        printf("Will stop after %d successful ping-pong cycles\n", packet_count_limit);
    }
    printf("Receive timeout: %d ms\n", receive_timeout_ms);
    printf("Press Ctrl+C to exit\n");

    /* Wait for response with timeout */
    struct timespec start_time, current_time, tx_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    while (keep_running) {
        /* Send packet */
        uint64_t tx_timestamp;
        uint64_t rtt_ns, echo_delay, return_delay;
        __u32 packet_len;
        void *packet_buffer = xsk_umem__get_data(buffer, rings->tx_offset);
        fill_ethernet_packet(packet_buffer, &packet_len);
        clock_gettime(CLOCK_MONOTONIC, &tx_time);
        if (send_packet(rings, buffer, packet_len, 0, &tx_timestamp) < 0) {
            fprintf(stderr, "Error: Failed to send packet %d\n", packets_sent + 1);
            continue;
        }

        packets_sent++;
        debug_printf("Packet %d sent\n", packets_sent);

        int packet_received = 0;

        while (keep_running && !packet_received) {
            __u32 rx_idx;
            __u64 addr;
            __u32 len;
            void *pkt_data;
            uint64_t rx_timestamp;

            if (handle_received_packet(&rings->rx_ring, buffer, &rx_idx, &addr, &len, &pkt_data, &rx_timestamp)) {
                packet_counter++;
                packet_received = 1;

                debug_printf("Packet %d received%s\n", packet_counter, packet_counter <= 0? " (warm-up)" : "");

                /* Write receive event to ftrace */
                if (ftrace_enabled) {
                    write_ftrace_receive(packet_counter, rx_timestamp, len);
                }

                /* Calculate and display RTT using immediate RX timestamp */
                if (len >= sizeof(struct ethhdr) + sizeof(struct timestamp_payload)) {
                    struct timestamp_payload *payload = (struct timestamp_payload *)((char *)pkt_data + sizeof(struct ethhdr));
                    rtt_ns = (int64_t)rx_timestamp - (int64_t)payload->tx_timestamp_ns;
                    double rtt_us = rtt_ns / 1000.0;

                    printf("Packet % 10d RTT: %8.3f μs", packet_counter, rtt_us);

                    if (payload->echo_timestamp_ns > 0) {
                        echo_delay = payload->echo_timestamp_ns - payload->tx_timestamp_ns;
                        return_delay = rx_timestamp - payload->echo_timestamp_ns;
                        if(echo_delay > echo_delay_max_ns) {
                            echo_delay_max_ns = echo_delay;
                        }
                        if(return_delay > return_delay_max_ns) {
                            return_delay_max_ns = return_delay;
                        }
                        double echo_us = echo_delay / 1000.0;
                        double return_us = return_delay / 1000.0;
                        printf(" (echo: %8.3f μs, return: %8.3f μs)", echo_us, return_us);

                        /* Write to ftrace marker */
                        if (ftrace_enabled) {
                            write_ftrace_rtt(packet_counter, rtt_us, echo_us, return_us);
                        }
                    } else {
                        /* Write to ftrace marker */
                        if (ftrace_enabled) {
                            write_ftrace_rtt(packet_counter, rtt_us, 0, 0);
                        }
                    }
                    if(packet_counter <= 0) {
                        printf(" (warm-up)");
                    } else {
                        if(rtt_ns > rtt_max_ns) {
                            rtt_max_ns = rtt_ns;
                        }
                        printf(" max RTT: %8.3f µs", rtt_max_ns / 1000.0);
                    }
                    printf("\n");
                }

                /* Display packet info only in debug mode */
                if (debug_enabled) {
                    display_packet_info(pkt_data, len, "Received");
                }

                /* Release the received packet */
                xsk_ring_cons__release(&rings->rx_ring, 1);

                /* Refill the fill ring */
                __u32 fill_idx;
                if (xsk_ring_prod__reserve(&rings->fill_ring, 1, &fill_idx) == 1) {
                    *xsk_ring_prod__fill_addr(&rings->fill_ring, fill_idx) = addr;
                    xsk_ring_prod__submit(&rings->fill_ring, 1);
                }

                /* Check if we've reached the packet limit */
                if (packet_count_limit > 0 && packet_counter >= packet_count_limit) {
                    debug_printf("Reached packet limit (%d packets), stopping...\n", packet_count_limit);
                    keep_running = 0;
                    break;
                }

                if(rtt_threshold_us > 0 && rtt_ns > rtt_threshold_us * 1000) {
                    printf("Packet %d RTT (%ld ns) exceeds threshold (%ld μs) - stopping...\n",
                           packet_counter, rtt_ns, rtt_threshold_us * 1000);
                    keep_running = 0;
                    break;
                }

                break;
            }

            /* Check timeout */
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            long elapsed_ms = (current_time.tv_sec - tx_time.tv_sec) * 1000 +
                             (current_time.tv_nsec - tx_time.tv_nsec) / 1000000;

            if (elapsed_ms >= receive_timeout_ms) {
                timeouts++;
                printf("Timeout waiting for response to packet %d (waited %ld ms) - retrying...\n", 
                       packets_sent, elapsed_ms);
                break;  /* Break out of receive loop to retry */
            }
        }

        /* We are now out of the critical section */
        if(output_f  != NULL && packet_counter > 0) {
            if(packet_received) {
                fprintf(output_f, "%ld,%ld,%ld,%ld\n", tx_timestamp, rtt_ns, echo_delay, return_delay); 
            } else {
                fprintf(output_f, "%ld,,,\n", tx_timestamp); 
            }
        }

        wait_for_tx_completion(&rings->comp_ring);

        /* Calculate when the next packet should be sent */
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        
        long elapsed_us = (current_time.tv_sec - start_time.tv_sec) * 1000000 +
                         (current_time.tv_nsec - start_time.tv_nsec) / 1000;
        while(next_send_time_us < elapsed_us)
            next_send_time_us += send_interval_us;
        long sleep_us = next_send_time_us - elapsed_us;
        if (sleep_us > 0) {
            usleep(sleep_us);
        }
    }

    printf("\nTest completed:\n");
    printf("  Packets sent: %d\n", packets_sent);
    printf("  Packets received: %d\n", packet_counter);
    printf("  Timeouts: %d\n", timeouts);
    printf("  RTT max: %.3f μs\n", rtt_max_ns / 1000.0);
    printf("    echo delay max: %.3f μs\n", echo_delay_max_ns / 1000.0);
    printf("    return delay max: %.3f μs\n", return_delay_max_ns / 1000.0);
    if (packets_sent > 0) {
        printf("  Success rate: %.1f%%\n", (packet_counter * 100.0) / packets_sent);
    }

    return 0;
}

/* Echo mode implementation with timestamp addition */
static int run_echo_mode(struct xsk_rings *rings, void *buffer)
{
    int packet_counter = 0;
    int xsk_fd = -1;
    struct pollfd pfd;

    /* Initialize fill ring with single RX frame */
    if (initialize_fill_ring(rings, "echo") < 0) {
        return 1;
    }

    printf("Starting echo loop with timestamp recording...\n");
    if (packet_count_limit > 0) {
        printf("Will stop after processing %d packets\n", packet_count_limit);
    }

    if (echo_poll_mode) {
        printf("Using poll mode (lower CPU usage)\n");
        xsk_fd = xsk_socket__fd(rings->xsk);
        pfd.fd = xsk_fd;
        pfd.events = POLLIN;
    } else {
        printf("Using busy wait mode (lowest latency)\n");
    }

    printf("Press Ctrl+C to exit\n");

    /* Echo loop */
    while (keep_running) {
        __u32 rx_idx;
        __u64 rx_addr;
        __u32 len;
        void *pkt_data;
        uint64_t rx_timestamp;

        /* Check for packets based on mode */
        if (echo_poll_mode) {
            /* Poll mode - wait for socket to become readable */
            int poll_ret = poll(&pfd, 1, 100); /* 100ms timeout */
            if (poll_ret < 0) {
                if (errno == EINTR) {
                    continue; /* Interrupted by signal */
                }
                debug_printf("Poll error: %s\n", strerror(errno));
                break;
            } else if (poll_ret == 0) {
                continue; /* Timeout, check keep_running */
            }
            /* Socket is readable, fall through to packet handling */
        }

        if (handle_received_packet(&rings->rx_ring, buffer, &rx_idx, &rx_addr, &len, &pkt_data, &rx_timestamp)) {
            packet_counter++;

            debug_printf("Packet %d received\n", packet_counter);

            /* Write receive event to ftrace */
            if (ftrace_enabled) {
                write_ftrace_receive(packet_counter, rx_timestamp, len);
            }

            /* Display packet info only in debug mode */
            if (debug_enabled) {
                display_packet_info(pkt_data, len, "Received");
            }

            /* Copy packet to TX frame */
            void *tx_data = xsk_umem__get_data(buffer, rings->tx_offset);
            memcpy(tx_data, pkt_data, len);

            /* Add echo timestamp if this is our timestamp packet */
            uint64_t echo_tx_timestamp = 0;
            if (len >= sizeof(struct ethhdr) + sizeof(struct timestamp_payload)) {
                struct timestamp_payload *payload = (struct timestamp_payload *)((char *)tx_data + sizeof(struct ethhdr));
                /* Set echo timestamp to the RX timestamp for more accurate measurement */
                payload->echo_timestamp_ns = rx_timestamp;
                debug_printf("Added echo timestamp: %lu ns\n", payload->echo_timestamp_ns);
            }

            if (len >= sizeof(struct ethhdr)) {
                struct ethhdr *eth = (struct ethhdr *)tx_data;

                memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
                memcpy(eth->h_source, interface_hwaddr, ETH_ALEN);
            }

            /* Release the RX descriptor first */
            xsk_ring_cons__release(&rings->rx_ring, 1);
            /* Refill the fill ring with the RX frame after sending the reply */
            __u32 fill_idx;
            if (xsk_ring_prod__reserve(&rings->fill_ring, 1, &fill_idx) == 1) {
                *xsk_ring_prod__fill_addr(&rings->fill_ring, fill_idx) = rings->rx_offset;
                xsk_ring_prod__submit(&rings->fill_ring, 1);
            }

            /* Send the packet back using TX frame - timestamp will be updated in send_packet */
            if (send_packet(rings, buffer, len, 1, &echo_tx_timestamp) == 0) {
                /* Write echo event to ftrace */
                if (ftrace_enabled) {
                    write_ftrace_echo(packet_counter, rx_timestamp, echo_tx_timestamp);
                }

                /* Display echoed packet info only in debug mode */
                if (debug_enabled) {
                    display_packet_info(tx_data, len, "Echoed");
                }
                debug_printf("Packet echoed successfully\n");
            } else {
                debug_printf("TX failed, packet dropped\n");
            }


            /* Check if we've reached the packet limit */
            if (packet_count_limit > 0 && packet_counter >= packet_count_limit) {
                debug_printf("Reached packet limit (%d packets), stopping...\n", packet_count_limit);
                break;
            }        }
    }

    printf("Echo loop terminated\n");
    printf("Total packets processed: %d\n", packet_counter);
    return 0;
}

static struct xdp_program* xdp_program_open_attach(char *path, int ifindex, enum xdp_attach_mode mode, int flags)
{
    struct xdp_program *prog;
    int err;

    /* Check if file exists before attempting to open */
    if (access(path, F_OK) != 0) {
        debug_printf("XDP program file does not exist: %s (%s)\n", path, strerror(errno));
        return NULL;
    }

    debug_printf("Opening XDP program from: %s\n", path);
    prog = xdp_program__open_file(path, NULL, NULL);
    if (!prog) {
        debug_printf("Failed to open XDP program file: %s\n", path);
        return NULL;
    }

    debug_printf("Attaching XDP program to interface ifindex %d\n", ifindex);
    err = xdp_program__attach(prog, ifindex, mode, flags);
    if (err) {
        debug_printf("Failed to attach XDP program to interface ifindex %d: %d (%s)\n",
                    ifindex, err, strerror(-err));
        /*
            TODO calling xdp_program__close(prog) here segfaults.
                 Investigate why as it is potentially a leak
        */
        return NULL;
    }

    // TODO: Investigate why this generates these info lines:
    //       "libbpf: elf: skipping unrecognized data section(7) xdp_metadata"


    debug_printf("XDP program successfully attached\n");
    return prog;
}

int main(int argc, char **argv)
{
    struct xdp_program *prog = NULL;
    void *buffer = NULL;
    int interface_sockfd = -1;
    int err;
    char *ifname = NULL;
    char *output_path = NULL;
    FILE *output_f = NULL;
    int ifindex = 0;
    enum xdp_attach_mode mode = XDP_MODE_NATIVE;
    int flags = 0;
    int opt;
    int ret = 0;
    uint64_t rtt_threshold_us = 0;
    int detach_xdp_on_exit = 1;

    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while ((opt = getopt_long(argc, argv, "hd:SNADM:c:Ft:o:r:ni:p", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'd':
            ifname = optarg;
            break;
        case 'M':
            if (strcmp(optarg, "test") == 0) {
                program_mode = MODE_TEST;
            } else if (strcmp(optarg, "echo") == 0) {
                program_mode = MODE_ECHO;
            } else {
                fprintf(stderr, "Error: Invalid mode '%s'. Valid modes: test, echo\n", optarg);
                return 1;
            }
            break;
        case 'c':
            packet_count_limit = atoi(optarg);
            if (packet_count_limit < 0) {
                fprintf(stderr, "Error: Packet count must be non-negative\n");
                return 1;
            }
            break;
        case 't':
            receive_timeout_ms = atoi(optarg);
            if (receive_timeout_ms <= 0) {
                fprintf(stderr, "Error: Timeout must be positive\n");
                return 1;
            }
            break;
        case 'r':
            rtt_threshold_us = atoi(optarg);
            if (rtt_threshold_us <= 0) {
                fprintf(stderr, "Error: RTT threshold must be positive\n");
                return 1;
            }
            break;
        case 'S':
            mode = XDP_MODE_SKB;
            break;
        case 'N':
            mode = XDP_MODE_NATIVE;
            break;
        case 'n':
            detach_xdp_on_exit = 0;
            break;
        case 'A':
            mode = XDP_MODE_UNSPEC;
            break;
        case 'D':
            debug_enabled = 1;
            break;
        case 'F':
            ftrace_enabled = 1;
            break;
        case 'o':
            output_path = optarg;
            break;
        case 'i':
            send_interval_us = atoll(optarg);
            if (send_interval_us <= 0) {
                fprintf(stderr, "Error: Send interval must be positive\n");
                return 1;
            }
            break;
        case 'p':
            echo_poll_mode = 1;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!ifname) {
        fprintf(stderr, "Error: Device name is required\n");
        usage(argv[0]);
        return 1;
    }

    /* Remove memory lock limit */
    if (remove_memlock_rlimit()) {
        fprintf(stderr, "Warning: Failed to remove memlock rlimit\n");
    }

    /* Create interface socket for various interface operations */
    interface_sockfd = create_interface_socket(ifindex);
    if (interface_sockfd < 0) {
        fprintf(stderr, "Error: Failed to create interface socket\n");
        return 1;
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Error: Invalid interface name '%s'\n", ifname);
        ret = 1;
        goto cleanup_iface_socket;
    }

    if (packet_count_limit > 0) {
        printf("  Packet limit: %d\n", packet_count_limit);
    } else {
        printf("  Packet limit: No limit\n");
    }
    printf("  Send interval: %ld µs\n", send_interval_us);
    if (program_mode == MODE_ECHO) {
        printf("  Echo mode: %s\n", echo_poll_mode ? "Poll" : "Busy wait");
    }
    printf("  XDP mode: %s\n",
           mode == XDP_MODE_SKB ? "SKB" :
           mode == XDP_MODE_NATIVE ? "Native" : "Auto-detect");
    printf("  Debug: %s\n", debug_enabled ? "Enabled" : "Disabled");
    printf("  Ftrace: %s\n", ftrace_enabled ? "Enabled" : "Disabled");
    if(rtt_threshold_us > 0)
        printf("  RTT threshold: %lu μs\n", rtt_threshold_us);
    else
        printf("  RTT threshold: disabled\n");

    /* Set process name based on mode and interface */
    char process_name[32];
    if (program_mode == MODE_TEST) {
        snprintf(process_name, sizeof(process_name), "xdp-test-%s", ifname);
    } else {
        snprintf(process_name, sizeof(process_name), "xdp-echo-%s", ifname);
    }
    set_process_name(process_name);

    /* Initialize ftrace marker */
    if (ftrace_enabled && init_ftrace_marker() < 0) {
        fprintf(stderr, "Error: Failed to initialize ftrace marker\n");
        goto cleanup_iface_socket;
    }

    prog = xdp_program_open_attach(BPF_PROGRAM_INSTALL_PATH "/af_xdp_kern.o", ifindex, mode, flags);
    if (!prog) {
        printf("Loading local BPF program\n");
        prog = xdp_program_open_attach("./af_xdp_kern.o", ifindex, mode, flags);
    }
    if (!prog) {
        fprintf(stderr, "Error: Failed to open XDP program\n");
        ret = 1;
        goto cleanup_iface_socket;
    }

    printf("XDP program attached to interface %s (ifindex %d)\n", ifname, ifindex);

    /* Get device MTU and calculate appropriate frame size early */
    int device_mtu;
    int frame_size;
    if (get_device_mtu_and_frame_size_early(interface_sockfd, ifname, &device_mtu, &frame_size) < 0) {
        fprintf(stderr, "Error: Failed to get device MTU, using default frame size\n");
        ret = 1;
        goto detach_prog;
    }

    /* Get interface hardware address for use in packet generation */
    if (get_interface_hwaddr(interface_sockfd, ifname, interface_hwaddr) < 0) {
        fprintf(stderr, "Error: Failed to get hardware address for %s\n", ifname);
        ret = 1;
        goto detach_prog;
    } else {
        printf("Using interface %s hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               ifname, interface_hwaddr[0], interface_hwaddr[1], interface_hwaddr[2],
               interface_hwaddr[3], interface_hwaddr[4], interface_hwaddr[5]);
    }

    printf("Device MTU: %d bytes\n", device_mtu);
    printf("Calculated frame size: %d bytes\n", frame_size);

    /* Calculate dynamic buffer size and offsets */
    /* buffer map is 2 frames, 0 is TX, next one is RX */
    int buffer_size = 2 * frame_size;
    int frame_tx_offset = 0;
    int frame_rx_offset = frame_size;

    printf("Buffer configuration:\n");
    printf("  Total buffer size: %d bytes\n", buffer_size);
    printf("  TX frame offset: %d\n", frame_tx_offset);
    printf("  RX frame offset: %d\n", frame_rx_offset);

    /* Allocate page-aligned memory for UMEM using dynamic buffer size */
    err = posix_memalign(&buffer, getpagesize(), buffer_size);
    if (err) {
        fprintf(stderr, "Error: Failed to allocate memory: %s\n", strerror(err));
        ret = 1;
        goto detach_prog;
    }

    /* Create AF_XDP socket */
    struct xsk_umem *umem = NULL;
    struct xsk_rings rings = {
        .xsk = NULL,
        .tx_offset = frame_tx_offset,
        .rx_offset = frame_rx_offset,
    };

    err = xsk_umem__create(&umem, buffer, buffer_size, &rings.fill_ring, &rings.comp_ring, NULL);
    if (err) {
        fprintf(stderr, "Error: Failed to create UMEM: %d\n", err);
        ret = 1;
        goto free_buffer;
    }

    /* Create AF_XDP socket with custom program support */
    struct xsk_socket_config xsk_config = {
        .rx_size = 8,
        .tx_size = 8,
        .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,  /* Don't load default program */
        .xdp_flags = 0,
        .bind_flags = XDP_USE_NEED_WAKEUP
    };

    err = xsk_socket__create(&rings.xsk, ifname, 0, umem, &rings.rx_ring, &rings.tx_ring, &xsk_config);
    if (err) {
        fprintf(stderr, "Error: Failed to create AF_XDP socket: %d\n", err);
        ret = 1;
        goto cleanup_umem;
    }

    /* Update the XSKMAP with our socket */
    struct bpf_map *xsks_map = NULL;
    struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);
    if (bpf_obj) {
        xsks_map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
        if (!xsks_map) {
            fprintf(stderr, "Error: Could not find xsks_map in BPF object\n");
            ret = 1;
            goto cleanup_socket;
        }

        int map_fd = bpf_map__fd(xsks_map);
        int queue_id = 0;  /* Queue ID 0 */
        int xsk_fd = xsk_socket__fd(rings.xsk);

        err = bpf_map_update_elem(map_fd, &queue_id, &xsk_fd, BPF_ANY);
        if (err) {
            fprintf(stderr, "Error: Failed to update XSKMAP: %d (%s)\n", err, strerror(-err));
            ret = 1;
            goto cleanup_socket;
        }

        printf("XSKMAP updated successfully (queue_id=%d, xsk_fd=%d)\n", queue_id, xsk_fd);
    } else {
        fprintf(stderr, "Error: Could not get BPF object from XDP program\n");
        ret = 1;
        goto cleanup_socket;
    }

    printf("AF_XDP socket created successfully\n");

    /* Wait for network interface carrier using XDP socket */
    if (wait_for_carrier(ifname, &keep_running) < 0) {
        fprintf(stderr, "Warning: Proceeding without confirmed carrier\n");
    }

    if(output_path != NULL){
        output_f = fopen(output_path, "w");
        if(output_f == NULL) {
            fprintf(stderr, "Error: can't create output file '%s': %s\n", output_path, strerror(errno));
            ret = 1;
            goto cleanup_socket;
        }
    }

    /* Run the appropriate mode */
    switch (program_mode) {
    case MODE_TEST:
        ret = run_test_mode(&rings, buffer, output_f, rtt_threshold_us);
        break;
    case MODE_ECHO:
        ret = run_echo_mode(&rings, buffer);
        break;
    }

    /* Cleanup AF_XDP socket */
cleanup_socket:
    xsk_socket__delete(rings.xsk);

cleanup_umem:
    if (umem)
        xsk_umem__delete(umem);

detach_prog:
    if (detach_xdp_on_exit) {
        err = xdp_program__detach(prog, ifindex, mode, 0);
        if (err) {
            fprintf(stderr, "Warning: Failed to detach XDP program: %d\n", err);
        } else {
            xdp_program__close(prog);
            printf("XDP program detached and closed from interface %s\n", ifname);
        }
    } else {
        printf("XDP program left attached to interface %s\n", ifname);
    }

free_buffer:
    if (buffer)
        free(buffer);

    /* Cleanup ftrace marker */
    cleanup_ftrace_marker();

cleanup_iface_socket:
    /* Close interface socket */
    if (interface_sockfd >= 0) {
        close(interface_sockfd);
        debug_printf("Interface socket closed\n");
    }

    return ret;
}
