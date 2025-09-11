#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include "utils.h"


static int ftrace_fd = -1;

/* Cleanup ftrace marker */
void cleanup_ftrace_marker(void)
{
    if (ftrace_fd >= 0) {
        close(ftrace_fd);
        ftrace_fd = -1;
    }
}

/* Initialize ftrace marker */
int init_ftrace_marker(void)
{
    const char *ftrace_marker_path = "/sys/kernel/debug/tracing/trace_marker";

    ftrace_fd = open(ftrace_marker_path, O_WRONLY);
    if (ftrace_fd < 0) {
        fprintf(stderr, "Warning: Failed to open ftrace marker (%s): %s\n",
                ftrace_marker_path, strerror(errno));
        fprintf(stderr, "Make sure debugfs is mounted and you have write permissions\n");
        return -1;
    }

    
    char *str = "xdp_lat starting";
    int ret = write(ftrace_fd, str, strlen(str));
    if (ret < 0) {
        fprintf(stderr, "Can't write to ftrace_marker (%s). Is ftrace running?\n", strerror(errno));
        cleanup_ftrace_marker();
        return -1;
    }
    
    printf("Ftrace marker initialized successfully\n");
    return 0;
}

/* Write RTT to ftrace marker */
void write_ftrace_rtt(int packet_num, double rtt_us, double echo_us, double return_us)
{
    char buffer[256];
    int len;

    if (ftrace_fd < 0) return;

    if (echo_us > 0 && return_us > 0) {
        len = snprintf(buffer, sizeof(buffer),
                      "af_xdp_rtt: packet=%d rtt=%.3f echo=%.3f return=%.3f\n",
                      packet_num, rtt_us, echo_us, return_us);
    } else {
        len = snprintf(buffer, sizeof(buffer),
                      "af_xdp_rtt: packet=%d rtt=%.3f\n",
                      packet_num, rtt_us);
    }

    if (write(ftrace_fd, buffer, len) < 0) {
        debug_printf("Failed to write to ftrace marker: %s\n", strerror(errno));
    }
}

/* Write packet receive event to ftrace marker */
void write_ftrace_receive(int packet_num, uint64_t timestamp_ns, uint32_t len)
{
    char buffer[256];
    int buf_len;

    if (ftrace_fd < 0) return;

    buf_len = snprintf(buffer, sizeof(buffer),
                      "af_xdp_receive: packet=%d timestamp=%lu len=%u\n",
                      packet_num, timestamp_ns, len);

    if (write(ftrace_fd, buffer, buf_len) < 0) {
        debug_printf("Failed to write receive event to ftrace marker: %s\n", strerror(errno));
    }
}

/* Write echo event to ftrace marker */
void write_ftrace_echo(int packet_num, uint64_t rx_timestamp_ns, uint64_t tx_timestamp_ns)
{
    char buffer[256];
    int len;

    if (ftrace_fd < 0) return;

    len = snprintf(buffer, sizeof(buffer),
                  "af_xdp_echo: packet=%d rx_timestamp=%lu tx_timestamp=%lu\n",
                  packet_num, rx_timestamp_ns, tx_timestamp_ns);

    if (write(ftrace_fd, buffer, len) < 0) {
        debug_printf("Failed to write echo event to ftrace marker: %s\n", strerror(errno));
    }
}
