import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from core import key_extractor


def _run_scan(tmp_path, staged_keys):
    live = tmp_path / "all_keys.json"
    original = {"message/message_1.db": {"enc_key": "a" * 64}}
    live.write_text(json.dumps(original), encoding="utf-8")

    def fake_run(_args, **kwargs):
        Path(kwargs["cwd"], "all_keys.json").write_text(
            json.dumps(staged_keys), encoding="utf-8"
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with (
        mock.patch.object(key_extractor, "DATA_DIR", str(tmp_path)),
        mock.patch.object(key_extractor, "KEYS_FILE", str(live)),
        mock.patch.object(key_extractor, "EXTRACT_LOG", str(tmp_path / "extract.log")),
        mock.patch.object(key_extractor, "compile_scanner", return_value=True),
        mock.patch.object(key_extractor, "get_wechat_pid", return_value=123),
        mock.patch.object(
            key_extractor,
            "load_config",
            return_value={"db_dir": str(tmp_path)},
        ),
        mock.patch.object(key_extractor.subprocess, "run", side_effect=fake_run),
        mock.patch.object(key_extractor, "_rematch_keys_from_log", return_value={}),
    ):
        result = key_extractor.extract_keys()

    return result, json.loads(live.read_text(encoding="utf-8"))


def test_empty_scan_preserves_last_known_good_keys(tmp_path):
    result, live = _run_scan(tmp_path, {})

    assert result is None
    assert live == {"message/message_1.db": {"enc_key": "a" * 64}}


def test_non_empty_scan_atomically_replaces_key_cache(tmp_path):
    new = {"message/message_2.db": {"enc_key": "b" * 64}}
    result, live = _run_scan(tmp_path, new)

    assert result == new
    assert live == new
