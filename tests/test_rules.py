import pandas as pd

from src.rules import powershell_rule, privilege_rule, network_rule


def test_powershell_rule_detects_keyword():
    df = pd.DataFrame({
        "timestamp": [pd.Timestamp.now()],
        "user": ["testuser"],
        "commandline": ["powershell -EncodedCommand SGVsbG8=; Invoke-Expression $x"],
        "eventid": ["1"],
        "computer": ["HOST1"]
    })
    alerts = powershell_rule.detect(df)
    assert not alerts.empty
    assert (alerts["severity"] == "High").any()


def test_privilege_rule_detects_net_localgroup():
    df = pd.DataFrame({
        "timestamp": [pd.Timestamp.now()],
        "user": ["bob"],
        "commandline": ["net localgroup administrators bob /add"],
        "eventid": ["4728"],
        "computer": ["HOST1"]
    })
    alerts = privilege_rule.detect(df)
    assert not alerts.empty
    assert (alerts["severity"] == "Medium").any()


def test_network_rule_detects_external_unusual_port():
    df = pd.DataFrame({
        "timestamp": [pd.Timestamp.now()],
        "src_ip": ["10.0.0.5"],
        "dst_ip": ["8.8.8.8"],
        "dst_port": [12345],
        "protocol": ["TCP"]
    })
    alerts = network_rule.detect(df, enrich_rdns=False)
    assert not alerts.empty
    assert (alerts["dataset_source"] == "CIC-IDS2017").any()
