from minisoar.correlation import CorrelationEngine


class MockRedisFull:
    def __init__(self):
        self.data = {}
        self.sets = {}
        self.ttls = {}

    def incrby(self, key, amount):
        val = int(self.data.get(key, 0)) + int(amount)
        self.data[key] = str(val)
        return val

    def get(self, key):
        return self.data.get(key)

    def setex(self, key, ttl, value):
        self.data[key] = str(value)
        self.ttls[key] = ttl
        return True

    def exists(self, key):
        return 1 if key in self.data else 0

    def expire(self, key, ttl):
        self.ttls[key] = ttl
        return True

    def sadd(self, key, *members):
        if key not in self.sets:
            self.sets[key] = set()
        added = 0
        for m in members:
            if m not in self.sets[key]:
                self.sets[key].add(m)
                added += 1
        return added

    def smembers(self, key):
        return self.sets.get(key, set())


def test_correlation_sliding_window_aggregation():
    r = MockRedisFull()
    engine = CorrelationEngine(redis_conn=r, default_window=60)

    res1 = engine.aggregate_event("198.51.100.10", "app.gov.id", "alert_url_probe", top_paths=["/admin"], hits=5)
    assert res1["total_hits"] == 5
    assert res1["is_first"] is True
    assert "/admin" in res1["unique_paths"]

    res2 = engine.aggregate_event("198.51.100.10", "app.gov.id", "alert_url_probe", top_paths=["/login.php"], hits=3)
    assert res2["total_hits"] == 8
    assert res2["is_first"] is False
    assert len(res2["unique_paths"]) == 2


def test_correlation_throttling():
    r = MockRedisFull()
    engine = CorrelationEngine(redis_conn=r, default_window=60)

    # First check: not throttled
    throttled, hits = engine.should_throttle("198.51.100.20", "portal.gov.id", "alert_sqli_attack", throttle_seconds=60)
    assert throttled is False

    # Second check within throttle window: throttled
    throttled_again, _ = engine.should_throttle("198.51.100.20", "portal.gov.id", "alert_sqli_attack", throttle_seconds=60)
    assert throttled_again is True


def test_correlation_campaign_detection():
    r = MockRedisFull()
    engine = CorrelationEngine(redis_conn=r, campaign_threshold=3)

    # IP 1 attacks target
    c1 = engine.detect_campaign("bank.gov.id", "alert_sqli_attack", "10.0.0.1")
    assert c1["is_campaign"] is False
    assert c1["attacker_count"] == 1

    # IP 2 attacks target
    c2 = engine.detect_campaign("bank.gov.id", "alert_sqli_attack", "10.0.0.2")
    assert c2["is_campaign"] is False
    assert c2["attacker_count"] == 2

    # IP 3 attacks target -> Reaches threshold 3 -> Campaign flagged!
    c3 = engine.detect_campaign("bank.gov.id", "alert_sqli_attack", "10.0.0.3")
    assert c3["is_campaign"] is True
    assert c3["attacker_count"] == 3
    assert "10.0.0.1" in c3["attackers"]
