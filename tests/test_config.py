import os
from minisoar.config import get_configured_providers, norm_provider, parse_allowed_users

def test_norm_provider():
    assert norm_provider("palo") == "paloalto"
    assert norm_provider("akamai") == "akamai"
    assert norm_provider("imperva") == "imperva"
    assert norm_provider("external") == "none"
    assert norm_provider("") == "none"

def test_parse_allowed_users():
    assert parse_allowed_users("1234, 5678") == [1234, 5678]
    assert parse_allowed_users("") == []

def test_get_configured_providers():
    os.environ["IMPERVA_BASE_URL"] = "https://127.0.0.1"
    os.environ.pop("CLOUDFLARE_API_TOKEN", None)
    os.environ.pop("CLOUDFLARE_ZONE_ID", None)
    
    conf = get_configured_providers()
    assert conf["imperva"] is True
    assert conf["cloudflare"] is False
