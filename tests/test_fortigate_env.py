import pytest
from minisoar.config import get_configured_providers

def test_fortigate_not_configured_by_default(monkeypatch):
    monkeypatch.delenv("FORTIGATE_HOST", raising=False)
    monkeypatch.delenv("FORTIGATE_API_TOKEN", raising=False)
    monkeypatch.delenv("FORTIGATE_API_KEY", raising=False)
    
    providers = get_configured_providers()
    assert providers["fortigate"] is False


def test_fortigate_configured_with_host_and_token(monkeypatch):
    monkeypatch.setenv("FORTIGATE_HOST", "https://192.0.2.1")
    monkeypatch.setenv("FORTIGATE_API_TOKEN", "test-token-value")
    monkeypatch.delenv("FORTIGATE_API_KEY", raising=False)
    
    providers = get_configured_providers()
    assert providers["fortigate"] is True


def test_fortigate_configured_with_token_only(monkeypatch):
    """Buktikan kegagalan: jika operator hanya mengisi FORTIGATE_API_TOKEN tanpa FORTIGATE_HOST,
    kode lama gagal mengenali provider karena hanya mengecek FORTIGATE_API_KEY."""
    monkeypatch.delenv("FORTIGATE_HOST", raising=False)
    monkeypatch.setenv("FORTIGATE_API_TOKEN", "test-token-value")
    monkeypatch.delenv("FORTIGATE_API_KEY", raising=False)
    
    providers = get_configured_providers()
    assert providers["fortigate"] is True, "FORTIGATE_API_TOKEN harus dikenali oleh get_configured_providers()"


def test_fortigate_configured_with_legacy_key_fallback(monkeypatch):
    """Pastikan backward compatibility: jika ada konfigurasi lama yang memakai FORTIGATE_API_KEY,
    get_configured_providers() tetap menganggap aktif."""
    monkeypatch.delenv("FORTIGATE_HOST", raising=False)
    monkeypatch.delenv("FORTIGATE_API_TOKEN", raising=False)
    monkeypatch.setenv("FORTIGATE_API_KEY", "legacy-api-key")
    
    providers = get_configured_providers()
    assert providers["fortigate"] is True
