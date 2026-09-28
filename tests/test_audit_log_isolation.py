"""Audit log SOC (tele-soar-actions.log) tidak boleh ditulis test ke root repo.

resolve_log_path("LOGFILE", ...) jatuh ke Path.cwd() bila LOGFILE kosong, dan
pytest jalan dari root repo. conftest.py (_offline_by_default) mengarahkan
LOGFILE ke tmp_path untuk semua test non-e2e. Test di sini TIDAK menyetel
LOGFILE sendiri: yang diuji justru default yang diberikan conftest.

Audit lokal tetap harus tertulis saat MINISOAR_MOCK=1 (lihat
test_mock_guards.py) - hanya lokasinya yang dipindah.
"""

import hashlib
import json
import os
from pathlib import Path

from minisoar.playbook import ExecutionContext
from minisoar.utils import log_user_action, resolve_log_path

ROOT = Path(__file__).resolve().parent.parent
ROOT_LOG = ROOT / "tele-soar-actions.log"


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def _bot_logfile():
    # Argumen persis seperti handler bot dan daemon.
    return resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")


def _ctx():
    return ExecutionContext(
        event={}, ip="198.51.100.55", website="", providers=[], mapped=False, whitelisted=False,
        bypassed=False, ml_prob=0.0, ml_label=0, reputation_score=0, rep_str="", event_id="e",
    )


def _inside_repo(path):
    try:
        Path(path).resolve().relative_to(ROOT)
        return True
    except ValueError:
        return False


def test_default_audit_log_path_is_outside_repo():
    assert not _inside_repo(_bot_logfile()), f"LOGFILE default test = {_bot_logfile()} (di dalam repo)"
    assert not _inside_repo(_ctx().logfile), f"ExecutionContext.logfile default = {_ctx().logfile}"


def test_playbook_audit_goes_to_tmp_not_repo_root():
    before = _sha(ROOT_LOG)
    ctx = _ctx()

    # Sama dengan minisoar/playbook/actions.py: logfile=ctx.logfile.
    log_user_action("AUTO_BLOCK", {"username": "playbook"}, ip=ctx.ip, target="imperva", logfile=ctx.logfile)

    assert _sha(ROOT_LOG) == before, "audit test masuk ke tele-soar-actions.log di root repo"
    entries = [json.loads(line) for line in Path(ctx.logfile).read_text(encoding="utf-8").splitlines()]
    assert entries[-1]["action"] == "AUTO_BLOCK" and entries[-1]["ip"] == ctx.ip


def test_bot_audit_still_written_locally_under_mock():
    """Mode mock mematikan jaringan, bukan audit lokal - fixture hanya memindah lokasinya."""
    assert os.getenv("MINISOAR_MOCK") == "1"
    before = _sha(ROOT_LOG)
    logfile = _bot_logfile()

    log_user_action("block_imperva", {"id": 1, "username": "soc_admin"}, ip="1.2.3.4", target="Imperva", logfile=logfile)

    assert Path(logfile).exists(), "audit lokal tidak tertulis saat MOCK=1 - regresi"
    assert json.loads(Path(logfile).read_text(encoding="utf-8").splitlines()[-1])["user"] == "soc_admin"
    assert _sha(ROOT_LOG) == before
