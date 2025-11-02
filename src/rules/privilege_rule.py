from typing import List

import pandas as pd

ALERT_COLUMNS = ["rule_name", "timestamp", "source", "dest_or_command", "description", "severity", "dataset_source"]


def detect(df: pd.DataFrame) -> pd.DataFrame:
    """Detect privilege escalation events in Sysmon-like dataframe.

    Heuristics: eventid matches common admin events, or commandline contains keywords.
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    keywords = ["added to administrators", "net localgroup administrators", "runas", "service install", "create service"]
    admin_eventids = {4672, 4728, 4732, 4727, 1102}  # examples; non-exhaustive

    alerts = []
    for _, row in df.iterrows():
        ts = row.get("timestamp")
        user = row.get("user") or ""
        cmd = str(row.get("commandline", "") or "")
        eventid = row.get("eventid")

        hit = False
        desc_parts: List[str] = []
        try:
            if pd.notna(eventid) and int(eventid) in admin_eventids:
                hit = True
                desc_parts.append(f"eventid={int(eventid)}")
        except Exception:
            pass

        for kw in keywords:
            if kw.lower() in cmd.lower():
                hit = True
                desc_parts.append(f"command contains '{kw}'")

        # simple heuristic: 'net localgroup administrators /add' exact
        if "net localgroup administrators" in cmd.lower():
            hit = True
            desc_parts.append("net localgroup administrators add")

        if hit:
            alerts.append({
                "rule_name": "User Privilege Escalation",
                "timestamp": ts,
                "source": user,
                "dest_or_command": cmd,
                "description": "; ".join(desc_parts) or "privilege escalation indicator",
                "severity": "Medium",
                "dataset_source": "Sysmon"
            })

    if alerts:
        return pd.DataFrame(alerts)[ALERT_COLUMNS]
    return pd.DataFrame(columns=ALERT_COLUMNS)
