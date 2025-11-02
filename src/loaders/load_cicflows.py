import os
from typing import Optional

import pandas as pd


def _find_column(cols, candidates):
    cols_low = {c.lower(): c for c in cols}
    for cand in candidates:
        if cand.lower() in cols_low:
            return cols_low[cand.lower()]
    for col in cols:
        for cand in candidates:
            if cand.lower() in col.lower():
                return col
    return None


def load_cicflows(path: Optional[str] = None) -> pd.DataFrame:
    """Load a CICFlow-like CSV and normalize headers.

    Expected output columns: timestamp, src_ip, dst_ip, dst_port, protocol
    """
    # Prefer project-root data/real/ if present, otherwise fall back to src/data/real/
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
    project_default = os.path.join(repo_root, "data", "real", "cicflows_sample.csv")
    src_default = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "real", "cicflows_sample.csv")
    csv_path = path or (project_default if os.path.exists(project_default) else src_default)

    cols = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol"]
    if not os.path.exists(csv_path):
        print(f"[WARN] CIC flows sample not found at {csv_path}")
        print("[WARN] Download CIC-IDS2017 flows or CICFlowMeter output. Info: https://www.unb.ca/cic/datasets/ids-2017.html")
        return pd.DataFrame(columns=cols)

    df = pd.read_csv(csv_path, low_memory=False)
    original_cols = list(df.columns)

    mapping = {
        "timestamp": ["timestamp", "time", "starttime", "flow start"],
        "src_ip": ["src_ip", "source ip", "srcip", "sip"],
        "dst_ip": ["dst_ip", "destination ip", "dstip", "dip"],
        "dst_port": ["dst_port", "destination port", "dport", "dstport", "sport"],
        "protocol": ["protocol", "proto"]
    }

    out = {}
    for std, candidates in mapping.items():
        col = _find_column(original_cols, candidates)
        if col:
            out[std] = df[col]
        else:
            out[std] = pd.NA

    out_df = pd.DataFrame(out)
    # parse timestamp and port
    out_df["timestamp"] = pd.to_datetime(out_df["timestamp"], errors="coerce")
    try:
        out_df["dst_port"] = pd.to_numeric(out_df["dst_port"], errors="coerce").astype("Int64")
    except Exception:
        out_df["dst_port"] = pd.NA

    print(f"[INFO] Loaded {len(out_df)} flows from {csv_path}")
    return out_df
