from minisoar.config import norm_provider, parse_allowed_users

def test_norm_provider():
    assert norm_provider("palo") == "paloalto"
    assert norm_provider("akamai") == "akamai"
    assert norm_provider("imperva") == "imperva"
    assert norm_provider("external") == "none"
    assert norm_provider("") == "none"

def test_parse_allowed_users():
    assert parse_allowed_users("1234, 5678") == [1234, 5678]
    assert parse_allowed_users("") == []
