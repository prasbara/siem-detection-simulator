import os
from typing import List

import pandas as pd

from .loaders.load_sysmon import load_sysmon
from .loaders.load_cicflows import load_cicflows
from .rules import powershell_rule, privilege_rule, network_rule


def _dedupe_alerts(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    d = df.copy()
    # ensure timestamp is datetime
    d["timestamp"] = pd.to_datetime(d["timestamp"], errors="coerce")
    # round to minute window
    d["_ts_minute"] = d["timestamp"].dt.floor("T")
    before = len(d)
    d = d.drop_duplicates(subset=["rule_name", "source", "_ts_minute", "dataset_source"])
    after = len(d)
    print(f"[INFO] Deduplicated alerts: {before} -> {after}")
    d = d.drop(columns=["_ts_minute"])
    return d


def run_pipeline(data_dir: str = None, enrich_rdns: bool = True) -> pd.DataFrame:
    # load data
    sysmon = load_sysmon()
    flows = load_cicflows()

    alerts: List[pd.DataFrame] = []

    # run rules on sysmon
    ps_alerts = powershell_rule.detect(sysmon)
    print(f"[INFO] PowerShell rule produced {len(ps_alerts)} alerts")
    alerts.append(ps_alerts)

    priv_alerts = privilege_rule.detect(sysmon)
    print(f"[INFO] Privilege rule produced {len(priv_alerts)} alerts")
    alerts.append(priv_alerts)

    net_alerts = network_rule.detect(flows, enrich_rdns=enrich_rdns)
    print(f"[INFO] Network rule produced {len(net_alerts)} alerts")
    alerts.append(net_alerts)

    merged = pd.concat(alerts, ignore_index=True, sort=False) if alerts else pd.DataFrame()
    merged = _dedupe_alerts(merged)

    out_path = os.path.join(os.path.dirname(__file__), os.pardir)
    out_path = os.path.abspath(out_path)
    csv_path = os.path.join(out_path, "alerts.csv")
    merged.to_csv(csv_path, index=False)
    print(f"[INFO] Saved {len(merged)} alerts to {csv_path}")
    return merged


if __name__ == "__main__":
    run_pipeline()
