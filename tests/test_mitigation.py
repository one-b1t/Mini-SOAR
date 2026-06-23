import os
import time
from minisoar.mitigation.core import (
    trigger_auto_block,
    trigger_auto_unblock,
    trigger_commit,
    is_ip_blocked,
    register_block_state,
    extend_block_state,
    get_expired_blocks,
    remove_block_state,
)

class MockRedis:
    def __init__(self):
        self.zset = {}

    def zscore(self, key, member):
        return self.zset.get((key, member))

    def zadd(self, key, mapping):
        for member, score in mapping.items():
            self.zset[(key, member)] = float(score)

    def zrangebyscore(self, key, min_val, max_val):
        out = []
        for (k, member), score in self.zset.items():
            if k == key and min_val <= score <= max_val:
                out.append(member)
        return out

    def zrem(self, key, member):
        if (key, member) in self.zset:
            del self.zset[(key, member)]
            return 1
        return 0

def test_trigger_auto_block_mock():
    os.environ["MINISOAR_MOCK"] = "1"
    # test Palo Alto mock block
    ok, msg = trigger_auto_block("1.2.3.4", "paloalto")
    assert ok is True
    assert "SUCCESS" in msg

    # test Palo Alto mock block with commit=False
    ok_deferred, msg_deferred = trigger_auto_block("1.2.3.4", "paloalto", commit=False)
    assert ok_deferred is True
    assert "pending" in msg_deferred

    # test trigger_commit directly
    ok_commit, msg_commit = trigger_commit("paloalto")
    assert ok_commit is True
    assert "SUCCESS" in msg_commit

    # test Imperva mock block
    ok_imp, msg_imp = trigger_auto_block("1.2.3.4", "imperva")
    assert ok_imp is True
    assert "berhasil" in msg_imp

    # test Akamai mock block
    ok_ak, msg_ak = trigger_auto_block("1.2.3.4", "akamai")
    assert ok_ak is True
    assert "IP added" in msg_ak

def test_trigger_auto_unblock_mock():
    os.environ["MINISOAR_MOCK"] = "1"
    
    # test Palo Alto mock unblock
    ok, msg = trigger_auto_unblock("1.2.3.4", "paloalto")
    assert ok is True
    assert "SUCCESS" in msg

    # test Imperva mock unblock
    ok_imp, msg_imp = trigger_auto_unblock("1.2.3.4", "imperva")
    assert ok_imp is True
    assert "berhasil" in msg_imp

    # test Akamai mock unblock
    ok_ak, msg_ak = trigger_auto_unblock("1.2.3.4", "akamai")
    assert ok_ak is True
    assert "IP removed" in msg_ak

def test_redis_block_helpers():
    r = MockRedis()
    
    # Initial state
    assert is_ip_blocked(r, "1.2.3.4", "paloalto") is False
    
    # Register block
    registered = register_block_state(r, "1.2.3.4", "paloalto", duration=60)
    assert registered is True
    assert is_ip_blocked(r, "1.2.3.4", "paloalto") is True
    
    # Registering again should fail if still blocked
    registered_again = register_block_state(r, "1.2.3.4", "paloalto", duration=60)
    assert registered_again is False
    
    # Extend block
    extend_block_state(r, "1.2.3.4", "paloalto", duration=120)
    # Check expiry is roughly now + 120
    score = r.zscore("minisoar:pending_unblocks", "paloalto:1.2.3.4")
    assert score > time.time() + 100
    
    # Remove block
    removed = remove_block_state(r, "1.2.3.4", "paloalto")
    assert removed is True
    assert is_ip_blocked(r, "1.2.3.4", "paloalto") is False
    
    # Test expiration retrieval
    register_block_state(r, "5.6.7.8", "akamai", duration=-10) # already expired
    register_block_state(r, "9.10.11.12", "imperva", duration=100) # active
    
    expired = get_expired_blocks(r)
    assert len(expired) == 1
    assert expired[0] == ("5.6.7.8", "akamai")


def test_es_website_lookups():
    import unittest.mock
    from minisoar.database import es_get_event_website_by_id, es_get_latest_event_website_by_ip

    with unittest.mock.patch("requests.get") as mock_get:
        # Mock search response by ID
        mock_resp_id = unittest.mock.Mock()
        mock_resp_id.status_code = 200
        mock_resp_id.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "server_name": "test-site.com"
                        }
                    }
                ]
            }
        }
        
        # Mock search response by IP
        mock_resp_ip = unittest.mock.Mock()
        mock_resp_ip.status_code = 200
        mock_resp_ip.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "event": {
                                "alert": {
                                    "server_name": "another-site.com"
                                }
                            }
                        }
                    }
                ]
            }
        }
        
        mock_get.side_effect = [mock_resp_id, mock_resp_ip]
        os.environ["ES_HOSTS"] = "http://localhost:9200"
        
        website_id = es_get_event_website_by_id("some-id")
        assert website_id == "test-site.com"
        
        website_ip = es_get_latest_event_website_by_ip("8.8.8.8")
        assert website_ip == "another-site.com"


def test_get_perimeter_info_unmapped():
    from minisoar.utils import get_perimeter_info
    providers, mapped, match_key = get_perimeter_info("unmapped-site.com", "logstash/minisoar-perimeter.yml")
    assert mapped is False
    assert providers == ["none"]
