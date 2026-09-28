"""Status provider mati harus dibaca dari PERIMETER_NONAKTIF, bukan dari daftar sendiri.

Dua tempat sebelumnya menulis daftar provider mati secara literal:
- minisoar/mitigation/core.py check_perimeter_connectivity
- minisoar/edr/core.py check_all_edr_connectivity
Kalau suatu provider dihidupkan kembali, daftar literal tidak ikut berubah dan
diagnostik tetap berbohong. Plus catatan read-back di harness E2E menyebut
perimeter yang memang tidak pernah disentuh di mode real.
"""
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from minisoar import config as cfg
from minisoar.edr import core as edr_core
from minisoar.mitigation import core as mit_core
from tests.tools import e2e_command_matrix as h


# --- mitigation/core.py ---------------------------------------------------------


def test_perimeter_status_follows_config_when_provider_reactivated(monkeypatch):
    """Cloudflare dihidupkan lagi di config -> baris 'disabled' harus hilang."""
    monkeypatch.setattr(cfg, "PERIMETER_NONAKTIF", frozenset({"fortigate"}))
    providers = {r["provider"]: r for r in mit_core.check_perimeter_connectivity()}
    assert "cloudflare" not in providers
    assert providers["fortigate"].get("disabled") is True


def test_perimeter_status_marks_every_config_disabled_perimeter(monkeypatch):
    monkeypatch.setattr(cfg, "PERIMETER_NONAKTIF", frozenset({"cloudflare", "fortigate"}))
    providers = {r["provider"]: r for r in mit_core.check_perimeter_connectivity()}
    for name in ("cloudflare", "fortigate"):
        assert providers[name].get("disabled") is True, name


# --- edr/core.py ----------------------------------------------------------------


def _fake_edr_module(label):
    mod = types.SimpleNamespace()
    mod.probed = []

    def check_connectivity():
        mod.probed.append(label)
        return {"provider": label, "configured": True, "ok": True, "error": None, "disabled": False}

    mod.check_connectivity = check_connectivity
    return mod


def test_edr_status_skips_probe_for_config_disabled_provider(monkeypatch):
    kav = _fake_edr_module("kaspersky")
    mon = edr_core._EDR_MODULES["trendmicro"]
    monkeypatch.setitem(edr_core._EDR_MODULES, "kaspersky", kav)
    monkeypatch.setattr(edr_core, "trendmicro", mon)
    monkeypatch.setattr(cfg, "PERIMETER_NONAKTIF", frozenset({"kaspersky"}))

    kav.probed.clear()
    rows = {r["provider"]: r for r in edr_core.check_all_edr_connectivity()}

    assert rows["kaspersky"].get("disabled") is True
    assert kav.probed == [], "provider nonaktif tidak boleh diprobe"


def test_edr_status_probes_provider_after_reactivation(monkeypatch):
    """Arah sebaliknya: kaspersky dihidupkan lagi -> harus diprobe, bukan ditandai disabled."""
    kav = _fake_edr_module("kaspersky")
    monkeypatch.setitem(edr_core._EDR_MODULES, "kaspersky", kav)
    monkeypatch.setattr(cfg, "PERIMETER_NONAKTIF", frozenset())

    kav.probed.clear()
    rows = {r["provider"]: r for r in edr_core.check_all_edr_connectivity()}

    assert kav.probed == ["kaspersky"], rows["kaspersky"]
    assert "disabled" not in rows["kaspersky"] or rows["kaspersky"]["disabled"] is False


# --- catatan read-back harness -------------------------------------------------


def test_self_check_note_excludes_perimeters_never_touched_in_real_mode(capsys):
    assert h.self_check() is True
    out = capsys.readouterr().out
    note = [ln for ln in out.splitlines() if "tidak punya read-back" in ln]
    assert note, out
    mentioned = note[0]
    for dead in ("cloudflare", "fortigate", "edr-kaspersky"):
        assert dead not in mentioned, mentioned
    assert "trendmicro" in mentioned, mentioned


def test_note_set_equals_perimeters_without_readback_that_are_reachable():
    unver = {k for k, v in h.PERIMETER.items() if v[0] is None}
    used = {c[4] for c in h.CASES if c[4]}
    # Yang boleh tersisa di catatan: tepat trendmicro, provider yang masih disentuh
    # di mode real tapi tidak punya read-back. Sisanya terfilter oleh dua syarat di atas.
    assert unver & used - set(h.REAL_DISABLED_PERIMETERS) == {"trendmicro"}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
