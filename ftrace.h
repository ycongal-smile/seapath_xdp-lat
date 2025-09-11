#ifndef __FTRACE_H__
#define __FTRACE_H__

void cleanup_ftrace_marker(void);
int init_ftrace_marker(void);
void write_ftrace_rtt(int packet_num, double rtt_us, double echo_us, double return_us);
void write_ftrace_receive(int packet_num, uint64_t timestamp_ns, uint32_t len);
void write_ftrace_echo(int packet_num, uint64_t rx_timestamp_ns, uint64_t tx_timestamp_ns);
#endif
