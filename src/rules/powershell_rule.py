import re
from typing import List

import pandas as pd


ALERT_COLUMNS = ["rule_name", "timestamp", "source", "dest_or_command", "description", "severity", "dataset_source"]


def detect(df: pd.DataFrame) -> pd.DataFrame:
    """Detect suspicious PowerShell commands in a Sysmon-like dataframe.

    Expects columns: timestamp, user, commandline, eventid, computer
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    kws = [r"invoke-expression", r"downloadstring", r"frombase64string", r"iex", r"-encodedcommand", r"new-object", r"Start-Process"]
    pattern = re.compile(r"(" + r"|".join(kws) + r")", flags=re.IGNORECASE)
    # base64-like long strings heuristic
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

    alerts = []
    for _, row in df.iterrows():
        cmd = str(row.get("commandline", "") or "")
        user = row.get("user") or ""
        ts = row.get("timestamp")
        matched = pattern.search(cmd) is not None
        b64 = b64_pattern.search(cmd) is not None
        long_one_liner = len(cmd) > 200
        if matched or b64 or long_one_liner:
            desc_parts: List[str] = []
            if matched:
                desc_parts.append("matches suspicious keywords")
            if b64:
                desc_parts.append("contains base64 payload-like string")
            if long_one_liner:
                desc_parts.append("very long one-line command")

            alerts.append({
                "rule_name": "Suspicious PowerShell Command",
                "timestamp": ts,
                "source": user,
                "dest_or_command": cmd,
                "description": "; ".join(desc_parts),
                "severity": "High",
                "dataset_source": "Sysmon"
            })

    if alerts:
        return pd.DataFrame(alerts)[ALERT_COLUMNS]
    return pd.DataFrame(columns=ALERT_COLUMNS)
