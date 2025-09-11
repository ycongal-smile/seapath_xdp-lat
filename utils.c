#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/resource.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h> 

int debug_enabled = 0;
/* Debug printf function */
int debug_printf(const char *format, ...)
{
    va_list args;
    int ret = 0;

    if (debug_enabled) {
        va_start(args, format);
        ret = vprintf(format, args);
        va_end(args);
        fflush(stdout);
    }

    return ret;
}


int remove_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) '%s'\n",
                strerror(errno));
        return -1;
    }

    return 0;
}

/* Set process name */
void set_process_name(const char *process_name)
{
    char truncated_name[16]; /* Linux process names are limited to 15 chars + null terminator */

    /* Copy and ensure null termination */
    strncpy(truncated_name, process_name, sizeof(truncated_name) - 1);
    truncated_name[15] = '\0';

    if (prctl(PR_SET_NAME, truncated_name, 0, 0, 0) != 0) {
        debug_printf("Warning: Failed to set process name to '%s': %s\n",
                    truncated_name, strerror(errno));
    } else {
        debug_printf("Process name set to: %s\n", truncated_name);
    }
}

/* Get current timestamp in nanoseconds */
uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_TAI, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}


/* Get primary interface name from alternative name or ifindex */
int get_primary_ifname(const char *ifname_or_altname, char *primary_name, size_t name_len)
{
    int ifindex;
    char *resolved_name;

    /* First try to get ifindex - this works for both primary and alt names */
    ifindex = if_nametoindex(ifname_or_altname);
    if (ifindex == 0) {
        debug_printf("Failed to get ifindex for '%s': %s\n", ifname_or_altname, strerror(errno));
        return -1;
    }

    /* Convert ifindex back to primary name */
    resolved_name = if_indextoname(ifindex, primary_name);
    if (!resolved_name) {
        debug_printf("Failed to get primary name for ifindex %d: %s\n", ifindex, strerror(errno));
        return -1;
    }

    debug_printf("Resolved '%s' to primary interface name '%s' (ifindex %d)\n", 
                ifname_or_altname, primary_name, ifindex);
    return 0;
}

/* Check if interface supports carrier detection */
static int interface_supports_carrier(const char *ifname)
{
    char primary_ifname[IFNAMSIZ];
    char carrier_path[256];
    struct stat st;

    /* Resolve to primary interface name */
    if (get_primary_ifname(ifname, primary_ifname, sizeof(primary_ifname)) < 0) {
        return 0;
    }

    snprintf(carrier_path, sizeof(carrier_path), "/sys/class/net/%s/carrier", primary_ifname);
    
    /* Check if carrier file exists */
    if (stat(carrier_path, &st) == 0) {
        debug_printf("Interface %s supports carrier detection\n", ifname);
        return 1;
    } else {
        debug_printf("Interface %s does not support carrier detection: %s\n", 
                    ifname, strerror(errno));
        return 0;
    }
}

/* Wait for network interface carrier to be up */
int wait_for_carrier(const char *ifname, volatile int *keep_running)
{
    char primary_ifname[IFNAMSIZ];
    char carrier_path[256];
    char carrier_status;
    FILE *carrier_file;
    int max_attempts = 200;  /* Maximum 20 seconds (200 * 100ms) */
    int attempt = 0;

    /* Check if interface supports carrier detection */
    if (!interface_supports_carrier(ifname)) {
        printf("Interface %s does not support carrier detection, skipping wait\n", ifname);
        return 0;
    }

    /* Resolve to primary interface name */
    if (get_primary_ifname(ifname, primary_ifname, sizeof(primary_ifname)) < 0) {
        fprintf(stderr, "Error: Failed to resolve interface name '%s'\n", ifname);
        return -1;
    }

    /* Use primary name for sysfs path */
    snprintf(carrier_path, sizeof(carrier_path), "/sys/class/net/%s/carrier", primary_ifname);

    printf("Waiting for carrier on interface %s", ifname);
    if (strcmp(ifname, primary_ifname) != 0) {
        printf(" (primary name: %s)", primary_ifname);
    }
    printf("...\n");

    while (attempt < max_attempts && keep_running) {
        carrier_file = fopen(carrier_path, "r");
        if (carrier_file) {
            if (fread(&carrier_status, 1, 1, carrier_file) == 1) {
                fclose(carrier_file);

                if (carrier_status == '1') {
                    printf("Carrier detected on %s after %.1f seconds\n",
                           ifname, (attempt + 1) * 0.1);
                    return 0;
                }
            } else {
                fclose(carrier_file);
            }
        } else {
            /* If we can't open the carrier file on first attempt, log it */
            if (attempt == 0) {
                debug_printf("Cannot open carrier file '%s': %s\n", carrier_path, strerror(errno));
            }
        }

        /* Wait 100ms before next attempt */
        usleep(100000);
        attempt++;

        /* Print progress every second */
        if (attempt % 10 == 0) {
            printf("Still waiting for carrier on %s... (%d seconds)\n",
                   ifname, attempt / 10);
        }
    }

    if (!keep_running) {
        printf("Carrier wait interrupted by signal\n");
        return -1;
    }

    fprintf(stderr, "Warning: No carrier detected on %s after %d seconds\n",
            ifname, max_attempts / 10);
    return -1;
}
