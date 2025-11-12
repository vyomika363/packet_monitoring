#!/usr/bin/env python3
from bcc import BPF
import socket, struct, argparse, os
from datetime import datetime
import ctypes as ct
import re

OUTPUT_FILE = "packet_drops.log"

def kfree_has_reason():
    fmt = "/sys/kernel/debug/tracing/events/skb/kfree_skb/format"
    try:
        with open(fmt, "r") as f:
            txt = f.read()
        return "reason" in txt
    except Exception:
        return False

def load_drop_reason_map():
    mapping = {}
    try:
        hdr_paths = [
            f"/usr/src/linux-headers-{os.uname().release}/include/net/dropreason-core.h",
            f"/usr/src/linux-headers-{os.uname().release}/include/net/dropreason.h",
        ]
        for path in hdr_paths:
            if os.path.exists(path):
                with open(path) as f:
                    for i, name in enumerate(
                        re.findall(r"SKB_DROP_REASON_[A-Z0-9_]+", f.read())
                    ):
                        mapping[i] = name
                if mapping:
                    print(f"[+] Loaded {len(mapping)} drop reasons from {path}")
                    return mapping
    except Exception:
        pass
    print("Could not auto-load drop reasons using minimal fallback map.")
    return {
        0: "NOT_SPECIFIED",
        1: "NO_SOCKET",
        2: "SOCKET_FILTER",
        3: "RcvBuf_FULL",
        4: "TCP_CSUM_ERROR",
    }


DROP_REASON_MAP = load_drop_reason_map()
WITH_REASON = kfree_has_reason()

COMMON_C = r"""
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

#define IFNAMSIZ 16

struct packet_event {
    u64 timestamp;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  protocol;
    u32 len;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u32 drop_reason;
    char reason[32];
};

BPF_PERF_OUTPUT(events);

static __inline void set_reason(char *dst, const char *src, int n) {
    __builtin_memset(dst, 0, 32);
    __builtin_memcpy(dst, src, n);
}
"""

PROG_WITH_REASON = COMMON_C + r"""
TRACEPOINT_PROBE(skb, kfree_skb) {
    struct packet_event data = {};
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    data.timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (skb->dev)
        bpf_probe_read_kernel_str(&data.ifname, sizeof(data.ifname), skb->dev->name);
    else
        set_reason(data.ifname, "unknown", 7);

    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr iph = {};
        if (bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header) == 0) {
            data.saddr = iph.saddr;
            data.daddr = iph.daddr;
            data.protocol = iph.protocol;

            if (data.protocol == IPPROTO_TCP) {
                struct tcphdr tcph = {};
                if (bpf_probe_read_kernel(&tcph, sizeof(tcph), skb->head + skb->transport_header) == 0) {
                    data.sport = tcph.source;
                    data.dport = tcph.dest;
                }
            } else if (data.protocol == IPPROTO_UDP) {
                struct udphdr udph = {};
                if (bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header) == 0) {
                    data.sport = udph.source;
                    data.dport = udph.dest;
                }
            }
        }
    }

    data.len = skb->len;
    data.drop_reason = args->reason;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

//transmit failures
TRACEPOINT_PROBE(net, net_dev_xmit) {
    if (args->rc == 0)
        return 0;
    struct packet_event data = {};
    data.timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    set_reason(data.ifname, "net_dev_xmit", 13);
    set_reason(data.reason, "transmit_failed", 16);
    data.drop_reason = 0;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


class Data(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("protocol", ct.c_ubyte),
        ("len", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("ifname", ct.c_char * 16),
        ("drop_reason", ct.c_uint),
        ("reason", ct.c_char * 32),
    ]


PROTO_MAP = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
    58: "ICMPv6", 89: "OSPF", 132: "SCTP", 136: "UDPLite"
}


def ntoa(ip_u32):
    try:
        return socket.inet_ntoa(struct.pack("<I", ip_u32))
    except Exception:
        return "0.0.0.0"


def print_event(cpu, data, size):
    ev = b["events"].event(data)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    comm = ev.comm.decode("utf-8", "replace").strip("\x00")
    ifname = ev.ifname.decode("utf-8", "replace").strip("\x00")
    reason_str = ev.reason.decode("utf-8", "replace").strip("\x00")
    proto = PROTO_MAP.get(ev.protocol, f"Other({ev.protocol})")

    src_ip, dst_ip = ntoa(ev.saddr), ntoa(ev.daddr)
    sport, dport = socket.ntohs(ev.sport), socket.ntohs(ev.dport)

    if ev.drop_reason != 0:
        reason_h = DROP_REASON_MAP.get(ev.drop_reason, f"code={ev.drop_reason}")
    else:
        reason_h = reason_str or "unknown"

    log_line = (
        f"[{ts}] PID: {ev.pid}, COMM: {comm}\n"
        f"  IF: {ifname}, {src_ip}:{sport} -> {dst_ip}:{dport}\n"
        f"  Protocol: {proto}, Length: {ev.len} bytes, Reason: {reason_h}\n"
    )
    print(log_line, flush=True)

    try:
        with open(OUTPUT_FILE, "w") as f:
            f.write(log_line)
    except Exception:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trace where and why packets drop (eBPF)")
    _ = parser.parse_args()

    program = PROG_WITH_REASON if WITH_REASON else PROG_NO_REASON
    print(f"Loading eBPF program Logging to {OUTPUT_FILE}")
    b = BPF(text=program)
    b["events"].open_perf_buffer(print_event)
    print("Monitoring packets Press Ctrl+C to exit.")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting")
