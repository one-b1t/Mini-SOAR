from minisoar.database import make_event_id, parse_ts_epoch

def test_event_ids():
    evt_id = make_event_id("alert_test", "asset_test", "1.2.3.4", 1700000000, 60, ["/path1", "/path2"])
    assert "alert_test" in evt_id
    assert "1.2.3.4" in evt_id

def test_parse_ts_epoch():
    assert parse_ts_epoch({"ts": 1700000000}) == 1700000000
    # 2026-05-26T00:00:00Z epoch
    assert parse_ts_epoch({"@timestamp": "2026-05-26T00:00:00Z"}) == 1779753600


def test_store_label_mock():
    import os
    import unittest.mock
    from minisoar.database import store_label

    os.environ["ES_HOSTS"] = "http://localhost:9200"
    with unittest.mock.patch("requests.put") as mock_put:
        mock_resp = unittest.mock.Mock()
        mock_resp.status_code = 200
        mock_put.return_value = mock_resp

        class MockUser:
            id = 12345
            username = "test_user"

        store_label(
            event_id="evt_test_123",
            label="block",
            user=MockUser(),
            reason_code="telegram_command",
            ip="1.2.3.4",
            telegram_message_id="999",
            chat_id=888
        )

        assert mock_put.call_count == 1
        call_args, call_kwargs = mock_put.call_args
        url = call_args[0]
        assert "minisoar-labels-" in url

        payload = call_kwargs.get("json")
        assert payload is not None
        assert payload["event_id"] == "evt_test_123"
        assert payload["label"] == "block"
        assert payload["actor"]["username"] == "test_user"
        assert payload["actor"]["id"] == 12345
        assert payload["reason_code"] == "telegram_command"
        assert payload["src"]["ip"] == "1.2.3.4"
        assert payload["telegram"]["message_id"] == "999"
        assert payload["telegram"]["chat_id"] == "888"
