
# ciciot_pcap2csv

A small, dependency‑light tool that converts PCAP/PCAPNG files into **CICIoT2023‑style** CSV feature rows — **without** a timestamp column — so your output matches example CSVs like `SqlInjection.pcap.csv`.

- **No `ts` column** (matches the dataset’s example CSVs).
- **Fixed packet windows** per bidirectional conversation (non‑overlapping).
- **dpkt optional**: uses `dpkt` if installed; otherwise falls back to a pure‑Python PCAP parser (Ethernet / IPv4 / IPv6).
- Outputs **exactly 39 columns** in the same order commonly found in CICIoT2023 CSVs (plus an optional `Label` at the end).

## Install

```bash
python -m pip install -r requirements.txt
```

`dpkt` is optional; if it’s missing, the script uses its pure‑Python parser.

## Usage

```bash
# 10‑packet windows, no timestamp column, and a constant label
python ciciot_pcap2csv.py input.pcap --out out.csv --window 10 --label SqlInjection

# multi‑file
python ciciot_pcap2csv.py a.pcap b.pcap --out merged.csv --window 10 --label Benign

# bigger windows (e.g., for DDoS/DoS/Mirai traffic)
python ciciot_pcap2csv.py ddos01.pcap --out ddos.csv --window 100 --label DDoS
```

## Output schema (39 columns)

```
Header_Length, Protocol Type, Time_To_Live, Rate,
fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
ack_flag_number, ece_flag_number, cwr_flag_number,
ack_count, syn_count, fin_count, rst_count,
HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP, IGMP, IPv, LLC,
Tot sum, Min, Max, AVG, Std, Tot size, IAT, Number, Variance
```

- **Header_Length** — sum of [IP + L4] header sizes within the window (best effort).
- **Protocol Type** — majority L3 protocol number (`IP.p` for IPv4, `nxt` for IPv6) within the window.
- **Time_To_Live** — mean TTL / Hop‑Limit across packets in the window.
- **Rate** — packets/second over the window duration (`end_ts - start_ts`).
- **TCP flags** — window average (proportions) for `fin/syn/rst/psh/ack/ece/cwr` + counts.
- **App/L2/L3 presence flags** — `HTTP/HTTPS/DNS/Telnet/SMTP/SSH/IRC/TCP/UDP/DHCP/ARP/ICMP/IGMP/IPv/LLC` (1 if present in the window).
- **Size stats** — `Tot sum` (sum of frame lengths), `Min/Max/AVG/Std` of frame length.
- **Tot size** — retained as average frame length to mirror common CICIoT practice (paper wording varies).
- **IAT** — mean inter‑arrival time in microseconds (`µs`).  
- **Number** — packets in the window (equals `--window` unless last chunk of a conversation).  
- **Variance** — variance of frame lengths in the window.

> Windows are **non‑overlapping** and computed **per 5‑tuple conversation** (normalized by `(ip,port)` order).

## Notes & assumptions

- **IGMP** is raised when IPv4 protocol number `2` is seen in the window.
- Protocol indicators (`HTTP/…/DHCP`) are inferred by common ports (best‑effort).
- If your target CSV uses a slightly different meaning for **Tot size**, you can post‑process that column with a simple formula (sum, mean, or bytes/sec).

## Dev tips

- The pure‑Python reader handles classic PCAP (Ethernet). For PCAPNG, install `dpkt` to auto‑detect/parse.
- If you need **overlapping** windows or **flow‑time windows**, you can extend the `WindowBuilder` easily.

## License

MIT — see [LICENSE](LICENSE).
