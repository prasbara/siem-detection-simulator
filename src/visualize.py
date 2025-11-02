import os

import matplotlib.pyplot as plt
import pandas as pd


def summarize_and_plot(alerts: pd.DataFrame, out_dir: str = None):
    if alerts is None or alerts.empty:
        print("[INFO] No alerts to visualize")
        return None

    out_dir = out_dir or os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    fig_path = os.path.join(out_dir, "alerts_summary.png")

    # counts per rule
    counts = alerts["rule_name"].value_counts()

    # timeline (per hour)
    alerts = alerts.copy()
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
    alerts["hour"] = alerts["timestamp"].dt.floor("H")
    timeline = alerts.groupby(["hour", "rule_name"]).size().unstack(fill_value=0)

    fig, axes = plt.subplots(2, 1, figsize=(10, 8))
    counts.plot(kind="bar", ax=axes[0])
    axes[0].set_title("Alerts by rule")

    if not timeline.empty:
        timeline.plot(ax=axes[1])
        axes[1].set_title("Alerts timeline (per hour)")
        axes[1].set_xlabel("Hour")

    plt.tight_layout()
    fig.savefig(fig_path)
    print(f"[INFO] Saved visual summary to {fig_path}")
    return fig_path
