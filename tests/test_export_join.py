"""Join label -> event di ml/export.py harus benar-benar mencocokkan dokumen.

Mapping ES produksi (diverifikasi via _mapping, read-only):
- skema lama (minisoar-events-2026.01.15..07.19): event_id = text + event_id.keyword
- skema ECS  (minisoar-events-2026.06.13..09.28): rule.id  = text + rule.id.keyword
`terms` pada field text tidak pernah cocok dengan ID ber-"|" (teranalisis), jadi
query lama {"terms": {"event_id": ...}} selalu 0 hit dan pipeline diam-diam jatuh
ke data sintetis. Fake ES di bawah meniru semantik itu persis.
"""

import json
import logging

import pytest

from minisoar.ml import export

OLD_ID = "alert_random_url|data|159.223.83.117|1768487640|41540c95dfc0"
ECS_ID = "alert_gambling_slot|kip|66.249.65.41|1790629320|na"
NOMATCH_ID = "alert_url_minor|x|203.0.113.9|1790000000|na"

OLD_EVENT = {
    "event_id": OLD_ID, "detector_type": "alert_random_url", "severity": "low",
    "metrics": {"hit_count": 317}, "perimeter": {"vendor": "imperva"},
    "alert": {"src_ip": "159.223.83.117", "server_name": "data.example"},
}
ECS_EVENT = {
    "rule": {"id": ECS_ID, "name": "alert_gambling_slot"},
    "observer": {"vendor": "akamai"},
    "event": {"severity": 75},
    "source": {"ip": "66.249.65.41"},
    "raw_log": json.dumps({"alert": {"type": "alert_gambling_slot", "count": 12, "severity": "high",
                                     "src_ip": "66.249.65.41", "server_name": "kip.example"}}),
}


def _matched_ids(query, docs):
    """Semantik ES: terms pada *.keyword cocok eksak; terms pada field text tidak pernah cocok."""
    clauses = query["bool"]["should"] if "bool" in query else [query]
    ids = set()
    for c in clauses:
        field, values = next(iter(c["terms"].items()))
        if field in {"event_id.keyword", "rule.id.keyword"}:
            ids |= set(values)
    return [d for d in docs if (d.get("event_id") or d.get("rule", {}).get("id")) in ids]


@pytest.fixture
def fake_es(monkeypatch):
    monkeypatch.setenv("MINISOAR_MOCK", "0")  # guard mock di es_request; .env tidak disentuh
    state = {"labels": [], "events": [], "event_queries": []}

    def fake_request(method, path, body=None):
        if path.startswith("minisoar-labels"):
            return {"hits": {"hits": [{"_source": s} for s in state["labels"]]}}
        if path.startswith("minisoar-events"):
            state["event_queries"].append(body["query"])
            return {"hits": {"hits": [{"_source": s} for s in _matched_ids(body["query"], state["events"])]}}
        return {"hits": {"hits": []}}

    monkeypatch.setattr(export, "es_request", fake_request)
    return state


def test_join_matches_old_and_ecs_events_to_labels(fake_es):
    fake_es["labels"] = [
        {"event_id": OLD_ID, "label": "block"},
        {"event_id": ECS_ID, "label": "ignore"},
        {"event_id": NOMATCH_ID, "label": "block"},
    ]
    fake_es["events"] = [OLD_EVENT, ECS_EVENT]

    rows = export.extract_minisoar_samples("minisoar-labels", "minisoar-events")
    by_id = {r[0]: r for r in rows}

    assert set(by_id) == {OLD_ID, ECS_ID}, f"join tidak mencocokkan event dengan label: {rows}"
    # kolom: event_id, detector_type, severity, reputation_score, hit_count, perimeter_vendor, ..., label
    old = by_id[OLD_ID]
    assert (old[1], old[2], old[4], old[5], old[-1]) == ("alert_random_url", "low", 317, "imperva", 1)
    ecs = by_id[ECS_ID]
    assert (ecs[1], ecs[2], ecs[4], ecs[5], ecs[-1]) == ("alert_gambling_slot", "high", 12, "akamai", 0), ecs
    assert ecs[7] == "66.249.65.41"


def test_same_event_in_both_schemas_is_not_duplicated(fake_es):
    """Jun 13 - Jul 19 kedua skema hidup berdampingan; satu label = satu baris."""
    fake_es["labels"] = [{"event_id": ECS_ID, "label": "block"}]
    fake_es["events"] = [ECS_EVENT, {**OLD_EVENT, "event_id": ECS_ID, "detector_type": "alert_gambling_slot"}]

    rows = export.extract_minisoar_samples("minisoar-labels", "minisoar-events")
    assert [r[0] for r in rows] == [ECS_ID]


def test_zero_joined_samples_warns_loudly(fake_es, caplog):
    fake_es["labels"] = [{"event_id": NOMATCH_ID, "label": "block"}]
    fake_es["events"] = [OLD_EVENT]

    with caplog.at_level(logging.WARNING, logger="minisoar.ml.export"):
        rows = export.extract_minisoar_samples("minisoar-labels", "minisoar-events")

    assert rows == []
    warn = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warn, "0 sampel ter-join tapi tidak ada WARNING: kegagalan diam"
    assert "0" in warn[0].getMessage() and "1" in warn[0].getMessage(), warn[0].getMessage()


def test_synthetic_fallback_warns_loudly(fake_es, caplog, tmp_path, monkeypatch):
    monkeypatch.setenv("ES_SECURESPHERE_ENABLED", "false")
    monkeypatch.setattr(export, "load_env", lambda: None)
    fake_es["labels"] = []

    with caplog.at_level(logging.WARNING, logger="minisoar.ml.export"):
        ok, count, msg = export.export_dataset_from_es(tmp_path / "ds.csv", fallback_synthetic=True)

    assert ok and count > 0 and "synthetic" in msg.lower()
    assert any("SINTETIS" in r.getMessage().upper() or "SYNTHETIC" in r.getMessage().upper()
               for r in caplog.records if r.levelno >= logging.WARNING), \
        "dataset sintetis ditulis tanpa WARNING"
