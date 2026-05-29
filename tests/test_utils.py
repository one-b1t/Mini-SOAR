from minisoar.utils import valid_ip, extract_reputation_score, is_ip_whitelisted

def test_valid_ip():
    assert valid_ip("192.168.1.1") is True
    assert valid_ip("invalid_ip") is False

def test_extract_reputation_score():
    assert extract_reputation_score("🛑 Malicious (95/100, 10 rep)") == 95
    assert extract_reputation_score("✅ Clean (0/100)") == 0
    assert extract_reputation_score("") == 0

def test_whitelist():
    assert is_ip_whitelisted("103.8.77.26") is True
    assert is_ip_whitelisted("8.8.8.8") is False
