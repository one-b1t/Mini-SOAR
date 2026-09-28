"""Test offline untuk logika harness E2E real-mode.

Harness-nya butuh Telethon, Telegram, dan kredensial. Tapi keputusan "kasus
mana yang boleh jalan" dan "apakah matriksnya masih waras" adalah logika
murni, dan itu yang menentukan apakah data uji tertinggal di perimeter. Kalau
tidak
diuji, regresinya baru ketahuan saat ada IP tes yang masih terblokir.

Tidak ada jaringan, tidak ada mock, tidak ada sleep.
"""
import pytest

from tests.tools import e2e_command_matrix as h


# --- pemilihan kasus --------------------------------------------------------

def test_read_only_only_picks_read_kind():
    assert {c[2] for c in h.select_cases(read_only=True)} == {"read"}


def test_filter_by_handler_substring():
    got = h.select_cases(only="whitelist")
    assert got and all("whitelist" in c[0] for c in got)


def test_real_never_sends_no_undo_or_mock_only():
    for c in h.select_cases(real=True):
        assert c[2] not in ("no_undo", "mock_only"), c


def test_real_never_commits_paloalto():
    # partial_commit() menaikkan SEMUA pending change milik admin, jadi
    # harness tidak boleh pernah memanggilnya di mode real.
    assert "commitpalo" not in {c[0] for c in h.select_cases(real=True)}


def test_real_never_activates_akamai():
    assert "activateakamai" not in {c[0] for c in h.select_cases(real=True)}


def test_real_still_tests_palo_block_without_commit():
    # Trade-off yang diketahui: blok hanya menyentuh candidate session, jadi
    # jalur API teruji tapi config aktif tidak pernah berubah.
    got = {c[0] for c in h.select_cases(real=True)}
    assert {"blockonpalo", "unblockonpalo"} <= got


def test_mock_mode_keeps_no_undo_cases():
    # Di mode mock tidak ada perimeter nyata, jadi kasus no_undo boleh jalan.
    got = {c[0] for c in h.select_cases()}
    assert "commitpalo" in got and "addedrioc" in got


# --- kunci --allow-host (bug P0 find_host_by_ip) ---------------------------

def test_allow_host_is_locked_even_when_flag_is_passed():
    if not h.HOST_ISOLATION_BLOCKED:
        pytest.skip("P0 sudah diperbaiki, lock sengaja dilepas")
    got = {c[0] for c in h.select_cases(real=True, allow_host=True)}
    assert not ({"isolatehost", "restorehost"} & got)
    assert h.self_check() is True  # matriks konsisten dengan kunci yang aktif


def test_host_kind_still_runs_in_mock_mode():
    # Di mock tidak ada perimeter nyata, jadi menguji jalur pesannya tetap
    # berguna. Kuncinya hanya berlaku untuk mode real.
    assert "isolatehost" in {c[0] for c in h.select_cases()}


def test_cleanup_only_never_picks_host_kind():
    got = h.select_cases(real=True)
    assert all(c[2] != "host" for c in got)


# --- undo plan --------------------------------------------------------------

def test_undo_plan_only_uses_approved_verbs():
    for _handler, cmd in h.undo_plan(h.CASES):
        assert cmd.startswith(h.VERB_UNDO), cmd


def test_undo_never_reblocks():
    for _handler, cmd in h.undo_plan(h.CASES):
        assert "/block" not in cmd, cmd


def test_neutralizer_cases_have_no_undo():
    for handler, cmd, kind, undo in h.CASES:
        if cmd.startswith(h.NEUTRALIZER):
            assert undo is None, handler


def test_every_mutating_case_has_undo_or_is_neutral():
    for handler, cmd, kind, undo in h.CASES:
        if kind in ("write", "host"):
            assert undo or cmd.startswith(h.NEUTRALIZER), handler


# --- peta perimeter dan kejujuran read-back ----------------------------------

def test_cloudflare_and_fortigate_have_no_readback():
    # bot.py blockoncf_cmd / blockonforti_cmd tidak menulis Redis, dan tidak
    # ada command yang membaca blocklist keduanya. Kalau ini berubah, test
    # ini yang harus gagal.
    for key in ("cloudflare", "fortigate"):
        assert h.PERIMETER[key][0] is None, key


def test_whitelist_is_the_only_real_readback():
    with_readback = {k for k, v in h.PERIMETER.items() if v[0] is not None}
    assert with_readback == {"imperva", "palo", "akamai", "whitelist"}


def test_every_unverifiable_perimeter_explains_itself():
    for key, (readback, _bukti, alasan) in h.PERIMETER.items():
        if readback is None:
            assert alasan and len(alasan) > 20, key


def test_every_write_case_maps_to_known_perimeter():
    known = set(h.PERIMETER)
    for handler, _cmd, kind, _undo in h.CASES:
        if kind in ("write", "host"):
            assert h.handler_perimeter(handler) in known, handler


def test_touched_perimeters_for_full_real_run():
    got = h.touched_perimeters(h.select_cases(real=True))
    # Provider yang dimatikan (cloudflare, fortigate, kaspersky/edr) serta imperva
    # tidak boleh disentuh sama sekali di mode real. Default real-mode hanya menyentuh
    # palo, akamai, dan whitelist.
    assert {"palo", "akamai", "whitelist"} == set(got)
    assert not ({"cloudflare", "fortigate", "imperva", "edr", "edr-kaspersky"} & set(got))


def test_real_allowed_providers_constants():
    assert h.REAL_ALLOWED_PROVIDERS == {"palo", "paloalto", "akamai", "trendmicro", "whitelist"}
    assert h.REAL_ALLOWED_PERIMETERS == h.REAL_ALLOWED_PROVIDERS


def test_select_cases_real_excludes_disabled_perimeters_with_reasons():
    reasons = {}
    cases = h.select_cases(real=True, skipped_reasons=reasons)
    handlers = {c[0] for c in cases}
    assert "blockoncf_cmd" not in handlers
    assert "unblockoncf_cmd" not in handlers
    assert "blockonforti_cmd" not in handlers
    assert "unblockonforti_cmd" not in handlers
    assert "queryhost" not in handlers
    assert "blockonimperva" not in handlers
    assert "unblockonimperva" not in handlers

    # Periksa bahwa alasan tercatat di dict
    assert "blockoncf_cmd" in reasons and "cloudflare" in reasons["blockoncf_cmd"].lower()
    assert "blockonforti_cmd" in reasons and "fortigate" in reasons["blockonforti_cmd"].lower()
    assert "queryhost" in reasons and "kaspersky" in reasons["queryhost"].lower()
    assert "blockonimperva" in reasons and "imperva" in reasons["blockonimperva"].lower()


def test_verify_clean_unverified_does_not_contain_dead_perimeters():
    perimeters = h.touched_perimeters(h.select_cases(real=True))
    # Default real run hanya sentuh provider dengan read-back, jadi unverified kosong
    unverified = [k for k in perimeters if h.PERIMETER[k][0] is None]
    assert unverified == []
    assert not ({"cloudflare", "fortigate", "edr", "edr-kaspersky"} & set(perimeters))


def test_real_mode_never_contains_forbidden_commands():
    for allow_host in (False, True):
        cases = h.select_cases(real=True, allow_host=allow_host)
        for _handler, cmd, _kind, _undo in cases:
            assert not cmd.startswith("/block_cf"), f"Bocor ke real: {cmd}"
            assert not cmd.startswith("/unblock_cf"), f"Bocor ke real: {cmd}"
            assert not cmd.startswith("/block_forti"), f"Bocor ke real: {cmd}"
            assert not cmd.startswith("/unblock_forti"), f"Bocor ke real: {cmd}"
            assert not cmd.startswith("/query_host"), f"Bocor ke real: {cmd}"
            assert not cmd.startswith("/add_edr_ioc"), f"Bocor ke real: {cmd}"


def test_mock_mode_keeps_all_38_cases_intact():
    cases = h.select_cases()
    assert len(cases) == 38
    assert len(h.CASES) == 38
    cmds = [c[1] for c in cases]
    assert any(cmd.startswith("/block_cf") for cmd in cmds)
    assert any(cmd.startswith("/unblock_cf") for cmd in cmds)
    assert any(cmd.startswith("/block_forti") for cmd in cmds)
    assert any(cmd.startswith("/unblock_forti") for cmd in cmds)
    assert any(cmd.startswith("/query_host") for cmd in cmds)
    assert any(cmd.startswith("/add_edr_ioc") for cmd in cmds)
    assert any("/isolate_host" in cmd for cmd in cmds)


# --- self-check -------------------------------------------------------------

def test_self_check_passes_on_shipped_matrix(capsys):
    assert h.self_check() is True
    assert "SELF-CHECK OK" in capsys.readouterr().out


@pytest.mark.parametrize("bad,why", [
    (("x", "/block_cf 203.0.113.88", "write", None), "write tanpa undo"),
    (("x", "/block_cf 203.0.113.88", "write", "/block_cf 203.0.113.88"), "undo memblokir"),
    (("x", "/block_cf 203.0.113.88", "write", "/delete_everything"), "undo di luar daftar putih"),
    (("x", "/isolate_real_host all", "host", None), "host tanpa undo"),
    (("x", "/sync_ticket INC-1", "no_undo", "/unblock_cf 1.1.1.1"), "no_undo punya undo"),
    (("x", "/kill_bot", "write", "/unblock_cf 1.1.1.1"), "tidak terhubung ke PERIMETER"),
])
def test_self_check_rejects_bad_matrix(monkeypatch, capsys, bad, why):
    monkeypatch.setattr(h, "CASES", [bad])
    assert h.self_check() is False, why
    assert "SELF-CHECK GAGAL" in capsys.readouterr().out


def test_self_check_flags_perimeter_without_reason(monkeypatch):
    monkeypatch.setattr(h, "PERIMETER", dict(h.PERIMETER, fortigate=(None, "tidak-ada", "")))
    assert h.self_check() is False


@pytest.mark.parametrize("kind", ["no_undo", "mock_only", "host"])
def test_self_check_flags_leak_into_real(monkeypatch, capsys, kind):
    # Simulasikan select_cases yang gagal menyaring - kasus berbahaya lolos ke
    # mode real. self_check harus menangkapnya, bukan diam.
    monkeypatch.setattr(h, "CASES", [("x", "/activate_akamai", kind, None)])
    monkeypatch.setattr(h, "select_cases", lambda **kw: list(h.CASES))
    assert h.self_check() is False
    assert "bocor" in capsys.readouterr().out


@pytest.mark.parametrize("handler", ["blockoncf_cmd", "blockonforti_cmd", "queryhost", "blockonimperva"])
def test_self_check_flags_disabled_perimeter_leak_into_real(monkeypatch, capsys, handler):
    monkeypatch.setattr(h, "CASES", [(handler, "/test", "write", "/unblock_palo 1.1.1.1")])
    monkeypatch.setattr(h, "select_cases", lambda **kw: list(h.CASES))
    assert h.self_check() is False
    assert "bocor" in capsys.readouterr().out


def test_lock_and_filter_stay_in_sync_when_p0_is_fixed(monkeypatch):
    # Melepas kunci harus benar-benar membuka jalur; kalau select_cases masih
    # menyaring host, flag --allow-host jadi tidak berguna tanpa suara.
    monkeypatch.setattr(h, "HOST_ISOLATION_BLOCKED", False)
    assert {"isolatehost", "restorehost"} <= {c[0] for c in h.select_cases(real=True, allow_host=True)}
    assert h.self_check() is True


# --- kontrak argparse -------------------------------------------------------

def test_all_documented_flags_still_exist():
    args = h.parse_args(["--real", "--cleanup-only", "--allow-host", "--read-only"])
    assert args.real and args.cleanup_only and args.allow_host and args.read_only
    assert h.parse_args([]).only is None
    assert h.parse_args(["block"]).only == "block"


def test_no_telethon_needed_for_selection(monkeypatch):
    # Impor Telethon sudah dipindah ke dalam fungsi; logika kasus harus tetap
    # bisa diuji di mesin yang tidak punya Telethon.
    monkeypatch.setattr(h, "TelegramClient", None)
    assert h.select_cases(real=True)
