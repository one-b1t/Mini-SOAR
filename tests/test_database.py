from minisoar.database import make_event_id, parse_ts_epoch

def test_event_ids():
    evt_id = make_event_id("alert_test", "asset_test", "1.2.3.4", 1700000000, 60, ["/path1", "/path2"])
    assert "alert_test" in evt_id
    assert "1.2.3.4" in evt_id

def test_parse_ts_epoch():
    assert parse_ts_epoch({"ts": 1700000000}) == 1700000000
    # 2026-05-26T00:00:00Z epoch
    assert parse_ts_epoch({"@timestamp": "2026-05-26T00:00:00Z"}) == 1779753600
