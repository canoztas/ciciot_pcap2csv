#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ciciot_pcap2csv.py — Convert PCAP/PCAPNG into CICIoT2023-style CSV features (NO timestamp column).

Key points:
- Outputs exactly 47 columns matching CICIoT2023 paper header (no 'ts'), in the exact order below.
- Uses dpkt if available; otherwise falls back to a pure-Python PCAP (DLT_EN10MB) parser.
- Windows are non-overlapping and per bidirectional 5-tuple ("conversation").
- Direction (+1 outbound / −1 inbound) is defined by lexicographic canonicalization of the endpoint tuple.
- Directional stats follow CICIoT definitions (see paper): Magnitue, Radius, Covariance, Variance (in/out), Weight.

Columns (order):
  flow_duration, Header_Length, Protocol Type, Duration,
  Rate, Srate, Drate, fin_flag_number, syn_flag_number, rst_flag_number,
  psh_flag_number, ack_flag_number, ece_flag_number, cwr_flag_number,
  ack_count, syn_count, fin_count, urg_count, rst_count,
  HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP, IPv, LLC,
  Tot sum, Min, Max, AVG, Std, Tot size, IAT, Number,
  Magnitue, Radius, Covariance, Variance, Weight, label
"""

import argparse, sys, socket, struct
from collections import defaultdict, Counter
from typing import Optional, Tuple, List, Dict
import numpy as np
import pandas as pd

# ---------- Optional dpkt ----------
_have_dpkt = True
try:
    import dpkt  # noqa: F401
except Exception:
    _have_dpkt = False

# ---------- Helpers ----------
def ip_to_str(addr_bytes: bytes) -> str:
    if len(addr_bytes) == 4:
        return socket.inet_ntop(socket.AF_INET, addr_bytes)
    if len(addr_bytes) == 16:
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    return ""

def infer_app_proto(port: Optional[int]) -> Dict[str, int]:
    m = {
        "HTTP": 1 if port in {80, 8080, 8000, 8008, 8888} else 0,
        "HTTPS": 1 if port in {443, 8443} else 0,
        "DNS": 1 if port in {53, 5353} else 0,
        "Telnet": 1 if port == 23 else 0,
        "SMTP": 1 if port in {25, 465, 587} else 0,
        "SSH": 1 if port == 22 else 0,
        "IRC": 1 if port in {6665, 6666, 6667, 6668, 6669, 6697} else 0,
        "DHCP": 1 if port in {67, 68} else 0,
    }
    return m

class WindowBuilder:
    def __init__(self, N: int):
        self.N = N
        self.buffers: Dict[Tuple, List[dict]] = defaultdict(list)

    @staticmethod
    def conv_key(src, sport, dst, dport, proto):
        a = (src, sport if sport is not None else -1)
        b = (dst, dport if dport is not None else -1)
        return (a, b, proto) if a <= b else (b, a, proto)

    def add_packet(self, key, pkt_info):
        buf = self.buffers[key]
        buf.append(pkt_info)
        out = []
        while len(buf) >= self.N:
            out.append(buf[:self.N])
            del buf[:self.N]
        return out

def _safe_mean(x: np.ndarray) -> float:
    return float(np.mean(x)) if x.size else 0.0

def _safe_var(x: np.ndarray) -> float:
    return float(np.var(x)) if x.size else 0.0

def compute_window_features(window: List[dict], include_igmp: bool) -> dict:
    # arrays
    ts = np.array([p["ts"] for p in window], dtype=float)
    sizes = np.array([p["size"] for p in window], dtype=float)
    ttl_vals = np.array([p["ttl"] for p in window if p["ttl"] is not None], dtype=float)
    directions = np.array([p["dir"] for p in window], dtype=int)  # +1 outbound, -1 inbound
    l3_proto_vals = np.array([p["l3_proto"] for p in window], dtype=int)

    # flags (include URG support)
    fin = np.array([p["flags"].get("fin",0) for p in window], dtype=int)
    syn = np.array([p["flags"].get("syn",0) for p in window], dtype=int)
    rst = np.array([p["flags"].get("rst",0) for p in window], dtype=int)
    psh = np.array([p["flags"].get("psh",0) for p in window], dtype=int)
    ack = np.array([p["flags"].get("ack",0) for p in window], dtype=int)
    ece = np.array([p["flags"].get("ece",0) for p in window], dtype=int)
    cwr = np.array([p["flags"].get("cwr",0) for p in window], dtype=int)
    urg = np.array([p["flags"].get("urg",0) for p in window], dtype=int)

    # protocol presence
    proto_flags = Counter()
    has_tcp = any(p["l4"] == "TCP" for p in window)
    has_udp = any(p["l4"] == "UDP" for p in window)
    has_arp = any(p["is_arp"] for p in window)
    has_icmp = any(p["is_icmp"] for p in window)
    has_ip  = any(p["is_ip"] for p in window)
    has_llc = any(p["is_llc"] for p in window)
    # IGMP presence is not part of the final schema; we ignore it in the row.

    for p in window:
        for k, v in p["app"].items():
            proto_flags[k] += 1 if v else 0

    # timing
    flow_duration = float(ts.max() - ts.min()) if ts.size else 0.0
    dur = max(flow_duration, 1e-9)  # avoid div/0 but keep scale like paper
    total_rate = len(window) / dur
    iats = np.diff(ts) if ts.size > 1 else np.array([0.0])
    # CICIoT uses microseconds for IAT mean (see paper Table 4/5)
    iat_metric = float(np.mean(iats) * 1e6)

    # packet sizes (overall)
    tot_sum = float(np.sum(sizes))
    min_len = float(np.min(sizes)) if sizes.size else 0.0
    max_len = float(np.max(sizes)) if sizes.size else 0.0
    avg_len = _safe_mean(sizes)
    std_len = float(np.std(sizes)) if sizes.size else 0.0
    var_len = _safe_var(sizes)

    # l3 majority proto (for "Protocol Type") and TTL mean ("Duration" in CICIoT)
    proto_type = int(np.bincount(l3_proto_vals).argmax()) if l3_proto_vals.size else 0
    ttl_mean = float(np.mean(ttl_vals)) if ttl_vals.size else 0.0

    # header length sum
    header_lengths = np.array([p["hdr_len"] for p in window], dtype=float)
    header_len_sum = float(np.sum(header_lengths))

    # directional split
    sizes_out = sizes[directions == +1]
    sizes_in  = sizes[directions == -1]
    n_out = int(sizes_out.size)
    n_in  = int(sizes_in.size)

    mean_out = _safe_mean(sizes_out)
    mean_in  = _safe_mean(sizes_in)
    var_out  = _safe_var(sizes_out)
    var_in   = _safe_var(sizes_in)

    # Srate/Drate (packets per second), per CICIoT
    srate = (n_out / dur) if n_out else 0.0
    drate = (n_in  / dur) if n_in  else 0.0

    # Magnitue / Radius / Covariance / Variance / Weight (CICIoT definitions)
    magnitue = float(np.sqrt(max(mean_in, 0.0) + max(mean_out, 0.0)))
    radius   = float(np.sqrt(max(var_in, 0.0) + max(var_out, 0.0)))
    # Covariance between incoming/outgoing lengths: align by index to min length
    if n_in > 0 and n_out > 0:
        m = min(n_in, n_out)
        cov = float(np.cov(sizes_in[:m], sizes_out[:m], ddof=0)[0, 1])
    else:
        cov = 0.0
    # Variance ratio (in/out), guard divide-by-zero
    variance_ratio = float(var_in / var_out) if var_out > 0 else 0.0
    weight = float(n_in * n_out)

    row = {
        # ---- exact output schema ----
        "flow_duration": flow_duration,
        "Header_Length": header_len_sum,
        "Protocol Type": proto_type,
        "Duration": ttl_mean,                 # TTL
        "Rate": total_rate,
        "Srate": srate,
        "Drate": drate,

        "fin_flag_number": float(np.mean(fin)),
        "syn_flag_number": float(np.mean(syn)),
        "rst_flag_number": float(np.mean(rst)),
        "psh_flag_number": float(np.mean(psh)),
        "ack_flag_number": float(np.mean(ack)),
        "ece_flag_number": float(np.mean(ece)),
        "cwr_flag_number": float(np.mean(cwr)),

        "ack_count": int(np.sum(ack)),
        "syn_count": int(np.sum(syn)),
        "fin_count": int(np.sum(fin)),
        "urg_count": int(np.sum(urg)),
        "rst_count": int(np.sum(rst)),

        "HTTP": 1 if proto_flags["HTTP"] > 0 else 0,
        "HTTPS": 1 if proto_flags["HTTPS"] > 0 else 0,
        "DNS": 1 if proto_flags["DNS"] > 0 else 0,
        "Telnet": 1 if proto_flags["Telnet"] > 0 else 0,
        "SMTP": 1 if proto_flags["SMTP"] > 0 else 0,
        "SSH": 1 if proto_flags["SSH"] > 0 else 0,
        "IRC": 1 if proto_flags["IRC"] > 0 else 0,
        "TCP": 1 if has_tcp else 0,
        "UDP": 1 if has_udp else 0,
        "DHCP": 1 if proto_flags["DHCP"] > 0 else 0,
        "ARP": 1 if has_arp else 0,
        "ICMP": 1 if has_icmp else 0,
        "IPv": 1 if has_ip else 0,
        "LLC": 1 if has_llc else 0,

        "Tot sum": tot_sum,
        "Min": min_len,
        "Max": max_len,
        "AVG": avg_len,
        "Std": std_len,
        "Tot size": avg_len,  # matches observed CSVs (paper text is ambiguous)
        "IAT": iat_metric,
        "Number": int(len(window)),

        "Magnitue": magnitue,               # note CICIoT spelling
        "Radius": radius,
        "Covariance": cov,
        "Variance": variance_ratio,         # in/out ratio (directional)
        "Weight": weight,
    }
    return row

# ---------- dpkt path ----------
def _run_with_dpkt(pcaps: List[str], out_csv: str, window: int, label: Optional[str]):
    import dpkt
    def is_ipv4(eth): return isinstance(eth.data, dpkt.ip.IP)
    def is_ipv6(eth): return isinstance(eth.data, dpkt.ip6.IP6)
    def is_arp(eth): return isinstance(eth.data, dpkt.arp.ARP)
    def is_llc(eth): return hasattr(dpkt, "llc") and isinstance(eth.data, dpkt.llc.LLC)
    def get_transport(ip):
        if isinstance(ip, dpkt.ip.IP): return ip.data, ip.p
        if isinstance(ip, dpkt.ip6.IP6): return ip.data, ip.nxt
        return None, None
    def get_ports(l4):
        return getattr(l4,"sport",None), getattr(l4,"dport",None)
    def tcp_flags(tcp):
        f = getattr(tcp,"flags",0)
        return {
            "fin": 1 if (f & dpkt.tcp.TH_FIN) else 0,
            "syn": 1 if (f & dpkt.tcp.TH_SYN) else 0,
            "rst": 1 if (f & dpkt.tcp.TH_RST) else 0,
            "psh": 1 if (f & dpkt.tcp.TH_PUSH) else 0,
            "ack": 1 if (f & dpkt.tcp.TH_ACK) else 0,
            "ece": 1 if (f & dpkt.tcp.TH_ECE) else 0,
            "cwr": 1 if (f & dpkt.tcp.TH_CWR) else 0,
            "urg": 1 if (f & dpkt.tcp.TH_URG) else 0,
        }
    def open_pcap_any(path):
        data = open(path,"rb").read(4)
        if data == b"\x0A\x0D\x0D\x0A":
            return dpkt.pcapng.Reader(open(path,"rb")), "pcapng"
        try:
            return dpkt.pcap.Reader(open(path,"rb")), "pcap"
        except Exception:
            return dpkt.pcapng.Reader(open(path,"rb")), "pcapng"

    include_igmp = True
    wb = WindowBuilder(window)
    rows = []
    for p in pcaps:
        reader, kind = open_pcap_any(p)
        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            info = {
                "is_ip": False, "is_icmp": False, "is_arp": False, "is_llc": False,
                "l4": None, "l3_proto": 0, "ttl": None, "hdr_len": 0,
                "src": None, "dst": None, "sport": None, "dport": None
            }

            # Layer decoding
            flags={"fin":0,"syn":0,"rst":0,"psh":0,"ack":0,"ece":0,"cwr":0,"urg":0}

            if is_arp(eth):
                info["is_arp"] = True
            elif is_llc(eth):
                info["is_llc"] = True
            elif is_ipv4(eth):
                ip = eth.data
                info["is_ip"] = True; info["l3_proto"]=int(ip.p); info["ttl"]=int(ip.ttl)
                src = socket.inet_ntoa(ip.src); dst = socket.inet_ntoa(ip.dst)
                l4, _ = get_transport(ip)
                if isinstance(l4, dpkt.tcp.TCP):
                    info["l4"]="TCP"; info["sport"],info["dport"]=get_ports(l4); info["src"],info["dst"]=src,dst
                    info["hdr_len"]= ip.hl*4 + l4.off*4; flags = tcp_flags(l4)
                elif isinstance(l4, dpkt.udp.UDP):
                    info["l4"]="UDP"; info["sport"],info["dport"]=get_ports(l4); info["src"],info["dst"]=src,dst
                    info["hdr_len"]= ip.hl*4 + 8
                elif isinstance(l4, dpkt.icmp.ICMP):
                    info["l4"]="ICMP"; info["src"],info["dst"]=src,dst; info["hdr_len"]= ip.hl*4 + 8
                else:
                    info["src"],info["dst"]=src,dst; info["hdr_len"]=ip.hl*4
            elif is_ipv6(eth):
                ip6 = eth.data
                info["is_ip"] = True; info["l3_proto"]=int(ip6.nxt); info["ttl"]=int(ip6.hlim)
                src = socket.inet_ntop(socket.AF_INET6, ip6.src); dst = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                l4, _ = get_transport(ip6)
                if isinstance(l4, dpkt.tcp.TCP):
                    info["l4"]="TCP"; info["sport"],info["dport"]=get_ports(l4); info["src"],info["dst"]=src,dst
                    info["hdr_len"]= 40 + l4.off*4; flags = tcp_flags(l4)
                elif isinstance(l4, dpkt.udp.UDP):
                    info["l4"]="UDP"; info["sport"],info["dport"]=get_ports(l4); info["src"],info["dst"]=src,dst
                    info["hdr_len"]= 40 + 8
                elif isinstance(l4, dpkt.icmp6.ICMP6):
                    info["l4"]="ICMP"; info["src"],info["dst"]=src,dst; info["hdr_len"]= 40 + 8
                else:
                    info["src"],info["dst"]=src,dst; info["hdr_len"]=40
            else:
                info["is_llc"] = True

            if not info.get("src") or not info.get("dst"):
                continue

            sport = info.get("sport"); dport = info.get("dport")
            key = WindowBuilder.conv_key(info["src"], sport, info["dst"], dport, info["l3_proto"])

            min_side = (min(info["src"], info["dst"]),
                        min(sport if sport is not None else -1, dport if dport is not None else -1))
            direction = +1 if (info["src"], (sport if sport is not None else -1)) == min_side else -1

            app = infer_app_proto(sport); app_dst = infer_app_proto(dport)
            for k in app.keys():
                app[k] = 1 if (app[k] or app_dst[k]) else 0

            pkt_info = {
                "ts": float(ts),
                "size": int(len(buf)),
                "ttl": info["ttl"],
                "dir": direction,
                "l4": info["l4"],
                "l3_proto": info["l3_proto"],
                "flags": flags,
                "app": app,
                "is_arp": info["is_arp"],
                "is_icmp": (info["l4"] == "ICMP"),
                "is_ip": info["is_ip"],
                "is_llc": info["is_llc"],
                "hdr_len": info["hdr_len"],
            }
            for w in wb.add_packet(key, pkt_info):
                rows.append(compute_window_features(w, include_igmp))

    df = pd.DataFrame(rows)
    _write_csv(df, out_csv, label)

# ---------- Pure-Python PCAP parser (DLT_EN10MB) ----------
PCAP_MAGIC_USEC_BE  = 0xa1b2c3d4
PCAP_MAGIC_USEC_LE  = 0xd4c3b2a1
PCAP_MAGIC_NSEC_BE  = 0xa1b23c4d
PCAP_MAGIC_NSEC_LE  = 0x4d3cb2a1

def _read_pcap(path: str):
    f = open(path, 'rb')
    gh = f.read(24)
    if len(gh) < 24:
        raise ValueError("Not a PCAP file")
    magic = int.from_bytes(gh[:4], "big")
    if magic in (PCAP_MAGIC_USEC_LE, PCAP_MAGIC_NSEC_LE):
        end = "<"
        magic = int.from_bytes(gh[:4], "little")
    else:
        end = ">"
    nsec = magic in (PCAP_MAGIC_NSEC_BE, PCAP_MAGIC_NSEC_LE)

    ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack(end+"HHiiii", gh[4:24])
    ph_fmt = end+"IIII"
    while True:
        ph = f.read(16)
        if len(ph) < 16: break
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(ph_fmt, ph)
        pkt = f.read(incl_len)
        if len(pkt) < incl_len: break
        ts = ts_sec + (ts_frac / (1e9 if nsec else 1e6))
        yield ts, pkt

def _parse_ethernet(pkt: bytes) -> Tuple[int, int, int]:
    if len(pkt) < 14:
        return 0, -1, 0
    eth_type = struct.unpack(">H", pkt[12:14])[0]
    off = 14
    if eth_type in (0x8100, 0x88a8) and len(pkt) >= 18:
        eth_type = struct.unpack(">H", pkt[16:18])[0]
        off = 18
    return 14, eth_type, off

def _parse_ipv4(pkt: bytes, off: int):
    if len(pkt) < off+20: return None
    vhl = pkt[off]
    ver = vhl >> 4
    ihl = (vhl & 0x0F) * 4
    if ver != 4 or len(pkt) < off + ihl: return None
    ttl = pkt[off+8]
    proto = pkt[off+9]
    src = pkt[off+12:off+16]
    dst = pkt[off+16:off+20]
    l4_off = off + ihl
    return {"version":4, "ttl":ttl, "proto":proto, "src":src, "dst":dst, "hdr_len":ihl, "l4_off":l4_off}

def _parse_ipv6(pkt: bytes, off: int):
    if len(pkt) < off+40: return None
    ver = pkt[off] >> 4
    if ver != 6: return None
    nxt = pkt[off+6]
    hlim = pkt[off+7]
    src = pkt[off+8:off+24]
    dst = pkt[off+24:off+40]
    l4_off = off + 40
    return {"version":6, "ttl":hlim, "proto":nxt, "src":src, "dst":dst, "hdr_len":40, "l4_off":l4_off}

def _parse_tcp(pkt: bytes, off: int):
    if len(pkt) < off+20: return None
    sport, dport, seq, ack, off_flags = struct.unpack(">HHIIH", pkt[off:off+14])
    data_off = (off_flags >> 12) & 0xF
    if len(pkt) < off + data_off*4: data_off = 5
    flags_byte = off_flags & 0x01FF
    fin = 1 if (flags_byte & 0x001) else 0
    syn = 1 if (flags_byte & 0x002) else 0
    rst = 1 if (flags_byte & 0x004) else 0
    psh = 1 if (flags_byte & 0x008) else 0
    ackf= 1 if (flags_byte & 0x010) else 0
    urg = 1 if (flags_byte & 0x020) else 0
    ece = 1 if (flags_byte & 0x040) else 0
    cwr = 1 if (flags_byte & 0x080) else 0
    return {"sport":sport, "dport":dport, "hdr_len": data_off*4,
            "flags":{"fin":fin,"syn":syn,"rst":rst,"psh":psh,"ack":ackf,"ece":ece,"cwr":cwr,"urg":urg}}

def _parse_udp(pkt: bytes, off: int):
    if len(pkt) < off+8: return None
    sport, dport, ulen, csum = struct.unpack(">HHHH", pkt[off:off+8])
    return {"sport":sport, "dport":dport, "hdr_len":8}

def _run_pure_pcap(pcaps: List[str], out_csv: str, window: int, label: Optional[str]):
    wb = WindowBuilder(window)
    rows = []
    include_igmp = True

    for p in pcaps:
        for ts, buf in _read_pcap(p):
            l2_len, ethertype, off = _parse_ethernet(buf)
            is_ip=False; is_icmp=False; is_arp=False; is_llc=False
            l4_name=None; l3_proto=0; ttl=None; hdr_len=0
            src_ip=None; dst_ip=None; sport=None; dport=None
            flags={"fin":0,"syn":0,"rst":0,"psh":0,"ack":0,"ece":0,"cwr":0,"urg":0}

            if ethertype == 0x0806:  # ARP
                is_arp=True
            elif ethertype == 0x0800:  # IPv4
                iph = _parse_ipv4(buf, off)
                if iph:
                    is_ip=True; l3_proto=iph["proto"]; ttl=iph["ttl"]; hdr_len += iph["hdr_len"]
                    src_ip = ip_to_str(iph["src"]); dst_ip = ip_to_str(iph["dst"])
                    if iph["proto"] == 6:
                        tcph = _parse_tcp(buf, iph["l4_off"])
                        if tcph:
                            l4_name="TCP"; sport=tcph["sport"]; dport=tcph["dport"]; hdr_len += tcph["hdr_len"]; flags = tcph["flags"]
                    elif iph["proto"] == 17:
                        udph = _parse_udp(buf, iph["l4_off"])
                        if udph:
                            l4_name="UDP"; sport=udph["sport"]; dport=udph["dport"]; hdr_len += udph["hdr_len"]
                    elif iph["proto"] == 1:
                        l4_name="ICMP"; hdr_len += 8; is_icmp=True
            elif ethertype == 0x86DD:  # IPv6
                ip6 = _parse_ipv6(buf, off)
                if ip6:
                    is_ip=True; l3_proto=ip6["proto"]; ttl=ip6["ttl"]; hdr_len += ip6["hdr_len"]
                    src_ip = ip_to_str(ip6["src"]); dst_ip = ip_to_str(ip6["dst"])
                    if ip6["proto"] == 6:
                        tcph = _parse_tcp(buf, ip6["l4_off"])
                        if tcph:
                            l4_name="TCP"; sport=tcph["sport"]; dport=tcph["dport"]; hdr_len += tcph["hdr_len"]; flags = tcph["flags"]
                    elif ip6["proto"] == 17:
                        udph = _parse_udp(buf, ip6["l4_off"])
                        if udph:
                            l4_name="UDP"; sport=udph["sport"]; dport=udph["dport"]; hdr_len += udph["hdr_len"]
                    elif ip6["proto"] == 58:
                        l4_name="ICMP"; hdr_len += 8; is_icmp=True
            else:
                is_llc=True

            if not (src_ip and dst_ip):
                continue

            key = WindowBuilder.conv_key(src_ip, sport, dst_ip, dport, l3_proto)
            min_side = (min(src_ip, dst_ip),
                        min(sport if sport is not None else -1, dport if dport is not None else -1))
            direction = +1 if (src_ip, (sport if sport is not None else -1)) == min_side else -1

            app = infer_app_proto(sport); app_dst = infer_app_proto(dport)
            for k in app.keys(): app[k] = 1 if (app[k] or app_dst[k]) else 0

            pkt_info = {
                "ts": float(ts),
                "size": int(len(buf)),
                "ttl": ttl,
                "dir": direction,
                "l4": l4_name,
                "l3_proto": l3_proto,
                "flags": flags,
                "app": app,
                "is_arp": is_arp,
                "is_icmp": is_icmp,
                "is_ip": is_ip,
                "is_llc": is_llc,
                "hdr_len": hdr_len,
            }
            for w in wb.add_packet(key, pkt_info):
                rows.append(compute_window_features(w, include_igmp))

    df = pd.DataFrame(rows)
    _write_csv(df, out_csv, label)

def _write_csv(df: pd.DataFrame, out_csv: str, label: Optional[str]):
    ordered_cols = [
        "flow_duration","Header_Length","Protocol Type","Duration",
        "Rate","Srate","Drate",
        "fin_flag_number","syn_flag_number","rst_flag_number","psh_flag_number",
        "ack_flag_number","ece_flag_number","cwr_flag_number",
        "ack_count","syn_count","fin_count","urg_count","rst_count",
        "HTTP","HTTPS","DNS","Telnet","SMTP","SSH","IRC","TCP","UDP","DHCP","ARP","ICMP","IPv","LLC",
        "Tot sum","Min","Max","AVG","Std","Tot size","IAT","Number",
        "Magnitue","Radius","Covariance","Variance","Weight","label"
    ]

    # Ensure presence and order
    if df.empty:
        df = pd.DataFrame(columns=ordered_cols)
    else:
        for c in ordered_cols:
            if c not in df.columns:
                # sensible defaults
                if c in ("HTTP","HTTPS","DNS","Telnet","SMTP","SSH","IRC","TCP","UDP","DHCP","ARP","ICMP","IPv","LLC"):
                    df[c] = 0
                elif c == "label":
                    df[c] = ""
                else:
                    df[c] = 0.0
        df = df.loc[:, ordered_cols]

    # Apply label if provided (string), else keep as-is/empty
    if label is not None:
        df["label"] = str(label)

    df.to_csv(out_csv, index=False)

def main():
    ap = argparse.ArgumentParser(description="PCAP -> CICIoT2023-style CSV (no timestamp column)")
    ap.add_argument("pcaps", nargs="+", help="Input .pcap/.pcapng files")
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument("--window", type=int, default=10, help="Window size (packets per row)")
    ap.add_argument("--label", type=str, default=None, help="Optional constant label for all rows")
    args = ap.parse_args()

    try:
        if _have_dpkt:
            _run_with_dpkt(args.pcaps, args.out, args.window, args.label)
        else:
            _run_pure_pcap(args.pcaps, args.out, args.window, args.label)
    except Exception:
        # last-resort fallback
        _run_pure_pcap(args.pcaps, args.out, args.window, args.label)

if __name__ == "__main__":
    main()
