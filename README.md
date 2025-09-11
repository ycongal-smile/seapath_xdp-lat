
# XDP Latency Measurement Tool

A high-performance network latency measurement tool using XDP (eXpress Data
Path) for kernel bypass networking. This tool provides precise round-trip time
(RTT) measurements with microsecond accuracy.

## Building

```bash
# Setup build directory
meson setup builddir

# Compile
meson compile -C builddir

# Optional: Install
meson install -C builddir
```

# Usage
## Basic Usage
```bash
cd builddir/
# Test mode (default) - measures latency to a target
sudo ./af_xdp_lat -d eth0

# Echo mode - responds to incoming packets
sudo ./af_xdp_lat -d eth0 -M echo
```

## Command Line Options
```
Usage: af_xdp_lat [options]
Options:
  -h, --help          Show this help message
  -d, --dev <ifname>  Operate on device <ifname>
  -M, --mode <mode>   Program mode: test, echo (default: test)
  -c, --count <num>   Stop after processing <num> packets (0 = no limit)
  -o, --output <path> Output a CSV file with latencies samples
  -t, --timeout <ms>  Timeout in milliseconds to wait for packet response (default: 5000)
  -r, --rtt-threshold <us> Stop test when RTT exceeds threshold in microseconds (default: no threshold)
  -i, --interval <us> Interval in microseconds between packet sends (default: 500)
  -p, --poll          Use poll mode for echo (reduces CPU usage, may increase latency)
  -S, --skb-mode      Install XDP program in SKB (AKA generic) mode
  -N, --native-mode   Install XDP program in native mode (default mode)
  -n, --no-detach-on-exit   Do no detach XDP program on exit
  -A, --auto-mode     Auto-detect SKB or native mode
  -D, --debug         Enable debug output
  -F, --ftrace        Enable ftrace output
```
