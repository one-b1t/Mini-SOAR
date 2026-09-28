"""FortiGate DIMATIKAN TOTAL: env var tidak lagi membuat provider terlihat hidup.

Dulu file ini membuktikan deteksi env var FortiGate (HOST, API_TOKEN, API_KEY).
Setelah 01a0e878 provider-nya dipaksa False apa pun isi env, jadi ketiga test
tersebut tidak lagi menguji apa pun yang bisa berubah. Kontrak barunya: env var
FortiGate TIDAK berefek. Ditutup ulang di sini supaya tidak hilang bukti keputusannya.
"""
from minisoar.config import get_configured_providers


def test_fortigate_not_configured_by_default(monkeypatch):
    monkeypatch.delenv("FORTIGATE_HOST", raising=False)
    monkeypatch.delenv("FORTIGATE_API_TOKEN", raising=False)
    monkeypatch.delenv("FORTIGATE_API_KEY", raising=False)

    assert get_configured_providers()["fortigate"] is False


def test_fortigate_env_vars_never_make_it_configured(monkeypatch):
    """Semua kombinasi env FortiGate menghasilkan False: provider dimatikan total."""
    for env in (
        {"FORTIGATE_HOST": "https://192.0.2.1", "FORTIGATE_API_TOKEN": "t"},
        {"FORTIGATE_API_TOKEN": "t"},
        {"FORTIGATE_API_KEY": "legacy"},
        {
            "FORTIGATE_HOST": "https://192.0.2.1",
            "FORTIGATE_API_TOKEN": "t",
            "FORTIGATE_API_KEY": "legacy",
        },
    ):
        for key in ("FORTIGATE_HOST", "FORTIGATE_API_TOKEN", "FORTIGATE_API_KEY"):
            monkeypatch.delenv(key, raising=False)
        for key, val in env.items():
            monkeypatch.setenv(key, val)

        assert get_configured_providers()["fortigate"] is False, (
            f"fortigate tidak boleh aktif untuk env {sorted(env)}"
        )
