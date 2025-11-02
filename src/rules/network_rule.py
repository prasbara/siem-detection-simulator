import ipaddress
from typing import List

import pandas as pd

ALERT_COLUMNS = ["rule_name", "timestamp", "source", "dest_or_command", "description", "severity", "dataset_source"]


_WHITELIST_PORTS = {80, 443, 22, 3389, 53}
_C2_PORTS = {6667, 8080, 8443, 31337, 4444, 5555, 135}


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast)
    except Exception:
        return False


def _reverse_dns(ip: str) -> str:
    try:
        import dns.resolver

        answers = dns.resolver.resolve(ip, "PTR")
        return ";".join(str(r) for r in answers)
    except Exception:
        return ""


def detect(df: pd.DataFrame, enrich_rdns: bool = True) -> pd.DataFrame:
    """Detect external IP connections on unusual ports from flow dataframe.

    Expects: timestamp, src_ip, dst_ip, dst_port, protocol
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    alerts = []
    import pandas as _pd
    for _, row in df.iterrows():
        dst = row.get("dst_ip")
        if _pd.isna(dst):
            dst = ""
        src = row.get("src_ip")
        if _pd.isna(src):
            src = ""
        port = row.get("dst_port")
        ts = row.get("timestamp")

        try:
            port_int = int(port) if pd.notna(port) else None
        except Exception:
            port_int = None

        if dst and _is_public(dst):
            port_ok = (port_int in _WHITELIST_PORTS) if port_int is not None else False
            if not port_ok:
                desc_parts: List[str] = [f"dst_port={port_int}"]
                severity = "Low"
                if port_int in _C2_PORTS:
                    severity = "High"
                    desc_parts.append("known C2 port")

                rdns = ""
                if enrich_rdns:
                    rdns = _reverse_dns(dst)
                    if rdns:
                        desc_parts.append(f"rDNS={rdns}")

                alerts.append({
                    "rule_name": "External IP on Unusual Port",
                    "timestamp": ts,
                    "source": src,
                    "dest_or_command": f"{dst}:{port_int}",
                    "description": "; ".join(desc_parts),
                    "severity": severity,
                    "dataset_source": "CIC-IDS2017"
                })

    if alerts:
        return pd.DataFrame(alerts)[ALERT_COLUMNS]
    return pd.DataFrame(columns=ALERT_COLUMNS)
