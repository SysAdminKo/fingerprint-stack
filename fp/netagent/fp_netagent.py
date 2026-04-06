#!/usr/bin/env python3
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address

from bcc import BPF


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

struct ttl_stat_t {
  u64 last_ts_ns;
  u32 last_ttl;
  u32 count;
  u32 min_ttl;
  u32 max_ttl;
};

BPF_HASH(ttl_stats, u32, struct ttl_stat_t, 65536);

// Hook ip_rcv_core because some receive paths (e.g. GRO) bypass ip_rcv().
int kprobe__ip_rcv_core(struct pt_regs *ctx, struct sk_buff *skb) {
  if (skb == NULL) return 0;

  // Read skb->head and skb->network_header to find IPv4 header
  void *head = NULL;
  u16 nh_off = 0;
  bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
  bpf_probe_read_kernel(&nh_off, sizeof(nh_off), &skb->network_header);
  if (head == NULL) return 0;

  struct iphdr iph;
  void *iph_ptr = head + nh_off;
  if (bpf_probe_read_kernel(&iph, sizeof(iph), iph_ptr) < 0) return 0;
  if (iph.version != 4) return 0;

  u32 saddr = iph.saddr;
  u32 ttl = (u32)iph.ttl;

  struct ttl_stat_t *st = ttl_stats.lookup(&saddr);
  if (!st) {
    struct ttl_stat_t init = {};
    init.last_ts_ns = bpf_ktime_get_ns();
    init.last_ttl = ttl;
    init.count = 1;
    init.min_ttl = ttl;
    init.max_ttl = ttl;
    ttl_stats.update(&saddr, &init);
    return 0;
  }

  st->last_ts_ns = bpf_ktime_get_ns();
  st->last_ttl = ttl;
  st->count += 1;
  if (ttl < st->min_ttl) st->min_ttl = ttl;
  if (ttl > st->max_ttl) st->max_ttl = ttl;
  return 0;
}
"""


def u32_to_ip(u32):
    # saddr is in network byte order
    return socket.inet_ntoa(int(u32).to_bytes(4, byteorder="little", signed=False))


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.by_ip = {}  # ip -> dict

    def update_snapshot(self, snap):
        with self.lock:
            self.by_ip = snap

    def get(self, ip):
        with self.lock:
            return self.by_ip.get(ip)

    def all(self):
        with self.lock:
            return dict(self.by_ip)


def run_collector(store: Store, interval_s: float):
    b = BPF(text=BPF_PROGRAM)
    ttl_map = b["ttl_stats"]

    while True:
        snap = {}
        now = time.time()
        for k, v in ttl_map.items():
            ip = u32_to_ip(k.value)
            snap[ip] = {
                "ip": ip,
                "last_ttl": int(v.last_ttl),
                "min_ttl": int(v.min_ttl),
                "max_ttl": int(v.max_ttl),
                "count": int(v.count),
                "last_seen_unix": now,
            }
        store.update_snapshot(snap)
        time.sleep(interval_s)


class Handler(BaseHTTPRequestHandler):
    store: Store = None

    def _send(self, code, obj):
        body = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.write(b"\n")

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True})
        if self.path == "/api/ttl/all":
            return self._send(200, {"ttl": self.store.all()})
        if self.path.startswith("/api/ttl/ip/"):
            ip = self.path[len("/api/ttl/ip/") :].strip()
            try:
                ip_address(ip)
            except Exception:
                return self._send(400, {"error": "invalid ip"})
            v = self.store.get(ip)
            return self._send(200, {"ttl": v, "ip": ip})
        return self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        # keep quiet in journal
        return


def main():
    listen = ("127.0.0.1", 9100)
    store = Store()
    Handler.store = store

    t = threading.Thread(target=run_collector, args=(store, 1.0), daemon=True)
    t.start()

    httpd = HTTPServer(listen, Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()

