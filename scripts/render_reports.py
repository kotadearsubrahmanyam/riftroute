#!/usr/bin/env python3
import json
import os

def render(snap_path, out_path):
    with open(snap_path, 'r', encoding='utf-8') as f:
        s = json.load(f)
    out = []
    out.append('=' * 80)
    out.append('                 RiftRoute Network Path Snapshot Report                         ')
    out.append('=' * 80 + '\n')
    out.append(f"Measurement ID:        {s['measurement_id']}")
    out.append(f"Timestamp (UTC):       {s['timestamp_utc']}")
    out.append(f"Target Destination:    {s['destination']}")
    if s.get('destination_ip'):
        out.append(f"Resolved Target IP:    {s['destination_ip']}")
    out.append(f"Diagnostic Method:     {s['probe_method']}")
    out.append(f"Active Interface:      {s.get('active_interface', 'Unknown')}")
    out.append(f"Source IPv4:           {s.get('source_ipv4', 'Unknown')}")
    out.append(f"Default Gateway:       {s.get('default_gateway', 'Unknown')}")
    dur_sec = s['measurement_duration_ms'] / 1000.0
    out.append(f"Execution Duration:    {dur_sec:.2f} s")
    out.append(f"Route Fingerprint:     {s['fingerprint']}")
    out.append(f"Fingerprint SHA-256:   {s['fingerprint_sha256']}")
    out.append(f"Canonical Path:        {s['canonical_path']}\n")
    out.append('-' * 80)
    out.append('Observed Route Hop Progression')
    out.append('-' * 80)
    out.append('Hop   Address / Status              Min RTT   Median   Mean RTT   Max RTT   Jitter')
    out.append('----  ----------------------------  --------  -------  ---------  --------  ------')
    for h in s['hops']:
        if h['responded']:
            if h.get('hostname'):
                addr_label = f"{h['primary_address']} ({h['hostname']})"
            else:
                addr_label = h.get('primary_address', 'Unknown')
        else:
            addr_label = f"* (Timeout - {h['timeout_count']}/{h['probe_count']} probes)"

        if len(addr_label) > 28:
            addr_label = addr_label[:25] + "..."

        if h.get('rtt_stats'):
            st = h['rtt_stats']
            j_str = f"{st['jitter_ms']:.1f} ms" if st.get('jitter_ms') is not None else "-"
            out.append(f"{h['hop_number']:<4}  {addr_label:<28}  {st['min_ms']:>5.1f} ms  {st['median_ms']:>5.1f} ms  {st['mean_ms']:>6.1f} ms  {st['max_ms']:>5.1f} ms  {j_str:>6}")
        else:
            out.append(f"{h['hop_number']:<4}  {addr_label:<28}        -        -          -         -       -")

    out.append('\n' + '-' * 80)
    out.append('Path Metrics Summary:')
    out.append(f"  Total Hops Observed:    {s['hop_count']}")
    out.append(f"  Responding Hops:        {s['responding_hops']}")
    out.append(f"  Timeout Hops:           {s['timeout_hops']}")
    out.append('=' * 80)
    out.append('SCIENTIFIC INTEGRITY DISCLAIMER:')
    out.append('1. Traceroute probe RTT reflects ICMP Time Exceeded generation latency from router')
    out.append('   control planes, NOT actual game client-server application latency.')
    out.append("2. Router timeouts ('*') indicate ICMP rate-limiting or filtering, NOT packet loss.")
    out.append('3. This measurement observes network topology; it does not alter routing behavior.')
    out.append('=' * 80 + '\n')

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out))

if __name__ == '__main__':
    render('reports/phase1/route_gateway_snapshot.json', 'reports/phase1/route_gateway_snapshot.txt')
    render('reports/phase1/route_cloudflare_snapshot.json', 'reports/phase1/route_cloudflare_snapshot.txt')
    render('reports/phase1/route_google_snapshot.json', 'reports/phase1/route_google_snapshot.txt')
    render('reports/phase1/route_pubg_snapshot.json', 'reports/phase1/route_pubg_snapshot.txt')
    print('All reports successfully rendered.')
