from dataclasses import replace
from pathlib import Path

from stoa_security.endpoint_monitoring import (
    ProcessSnapshot,
    build_baseline,
    compare_baselines,
    detect_keylogger_indicators,
    verify_event_chain,
)


def test_integrity_lifecycle_and_tamper_evident_chain(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("one", encoding="utf-8")
    (tmp_path / "renamed.txt").write_text("same", encoding="utf-8")
    before = build_baseline(tmp_path)
    (tmp_path / "keep.txt").write_text("two", encoding="utf-8")
    (tmp_path / "renamed.txt").rename(tmp_path / "moved.txt")
    (tmp_path / "new.txt").write_text("new", encoding="utf-8")
    after = build_baseline(tmp_path)
    events = compare_baselines(before, after, seed="approved-baseline")
    assert {event.kind for event in events} == {"created", "changed", "renamed"}
    assert verify_event_chain(events, seed="approved-baseline")
    assert not verify_event_chain(
        (replace(events[0], path="tampered"), *events[1:]), seed="approved-baseline"
    )


def test_baseline_filters_and_large_file_handling(tmp_path: Path) -> None:
    (tmp_path / "include.cfg").write_text("config", encoding="utf-8")
    (tmp_path / "ignore.cfg").write_text("ignored", encoding="utf-8")
    records = build_baseline(
        tmp_path, include=("*.cfg",), exclude=("ignore*",), maximum_file_bytes=2
    )
    assert set(records) == {"include.cfg"}
    assert records["include.cfg"].sha256 is None


def test_keylogger_adapter_requires_multiple_explainable_indicators() -> None:
    benign = ProcessSnapshot(1, "editor", "/usr/bin/editor", signed=True)
    suspicious = ProcessSnapshot(
        2,
        "helper",
        "/tmp/helper",  # noqa: S108 - intentional suspicious fixture
        "--read /dev/input/event0",
    )
    results = detect_keylogger_indicators((benign, suspicious), platform="linux")
    assert len(results) == 1
    assert results[0].process_id == 2
    assert results[0].confidence == 0.85
    assert "does not establish" in results[0].explanation


def test_windows_adapter_scores_unsigned_hook_process() -> None:
    process = ProcessSnapshot(
        7, "agent.exe", r"C:\\Users\\person\\AppData\\agent.exe", "SetWindowsHookEx", signed=False
    )
    result = detect_keylogger_indicators((process,), platform="windows")[0]
    assert result.severity == "high"
    assert len(result.evidence) == 3
