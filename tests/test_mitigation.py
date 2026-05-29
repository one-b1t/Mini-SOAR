import os
from minisoar.mitigation.core import trigger_auto_block

def test_trigger_auto_block_mock():
    os.environ["MINISOAR_MOCK"] = "1"
    # test Palo Alto mock block
    ok, msg = trigger_auto_block("1.2.3.4", "paloalto")
    assert ok is True
    assert "SUCCESS" in msg

    # test Imperva mock block
    ok_imp, msg_imp = trigger_auto_block("1.2.3.4", "imperva")
    assert ok_imp is True
    assert "berhasil" in msg_imp
