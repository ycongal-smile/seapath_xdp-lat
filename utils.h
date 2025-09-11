#ifndef __UTILS_H__
#define __UTILS_H__
int debug_printf(const char *format, ...);
extern int debug_enabled;
int remove_memlock_rlimit(void);
void set_process_name(const char *process_name);
uint64_t get_timestamp_ns(void);
int get_primary_ifname(const char *ifname_or_altname, char *primary_name, size_t name_len);
int wait_for_carrier(const char *ifname, volatile int *keep_running);
#endif
