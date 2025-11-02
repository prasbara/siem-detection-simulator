import os
from typing import Optional

import pandas as pd


def _find_column(cols, candidates):
    cols_low = {c.lower(): c for c in cols}
    for cand in candidates:
        if cand.lower() in cols_low:
            return cols_low[cand.lower()]
    # try partial match
    for col in cols:
        for cand in candidates:
            if cand.lower() in col.lower():
                return col
    return None


def load_sysmon(path: Optional[str] = None) -> pd.DataFrame:
    """Load a Sysmon-like CSV and normalize headers.

    If the file is missing, prints a [WARN] with instructions and returns an empty DataFrame
    with the standardized columns.
    """
    # Prefer project-root data/real/ if present, otherwise fall back to src/data/real/
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
    project_default = os.path.join(repo_root, "data", "real", "sysmon_sample.csv")
    src_default = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "real", "sysmon_sample.csv")
    csv_path = path or (project_default if os.path.exists(project_default) else src_default)

    cols = ["timestamp", "user", "commandline", "eventid", "computer"]
    if not os.path.exists(csv_path):
        print(f"[WARN] Sysmon sample not found at {csv_path}")
        print("[WARN] You can download Sysmon / Windows event CSV samples from https://securitydatasets.com")
        print("[WARN] Or convert EVTX on Windows: Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Export-Csv sysmon_sample.csv -NoTypeInformation")
        return pd.DataFrame(columns=cols)

    df = pd.read_csv(csv_path, low_memory=False)
    original_cols = list(df.columns)

    # normalize
    mapping = {
        "timestamp": ["timestamp", "time", "timegenerated", "timecreated", "datetime"],
        "user": ["user", "account", "useraccount", "username", "subjectuser"],
        "commandline": ["commandline", "cmdline", "processcommandline", "command"],
        "eventid": ["eventid", "event id", "id"],
        "computer": ["computer", "host", "hostname"]
    }

    out = {}
    for std, candidates in mapping.items():
        col = _find_column(original_cols, candidates)
        if col:
            out[std] = df[col]
        else:
            out[std] = pd.NA

    out_df = pd.DataFrame(out)
    # parse timestamp
    try:
        out_df["timestamp"] = pd.to_datetime(out_df["timestamp"], errors="coerce")
    except Exception:
        out_df["timestamp"] = pd.to_datetime(out_df["timestamp"].astype(str), errors="coerce")

    print(f"[INFO] Loaded {len(out_df)} rows from {csv_path}")
    return out_df
