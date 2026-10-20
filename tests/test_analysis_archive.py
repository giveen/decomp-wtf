"""Archive analysis helpers: the inventory shape REA returns, its regular-file work items, and bounded reads."""

from pathlib import Path

from decompnet.app import analysis

ZIP = Path(__file__).parent / "fixtures" / "artifact-demo.zip"


def inventory():
    return {
        "inspection_id": "ai_test",
        "nodes": [
            {"artifact_id": "root", "format": "zip", "sha256": "a" * 64, "size": 452, "content_state": "materialized"},
            {"artifact_id": "file", "format": "file", "sha256": "b" * 64, "size": 5, "content_state": "embedded"},
        ],
        "occurrences": [
            {"occurrence_id": "root-occ", "artifact_id": "root", "parent_occurrence_id": None,
             "logical_path": ".", "entry_kind": "file", "artifact_kind": "container", "artifact_format": "zip",
             "declared_size": 452, "executable": False, "encrypted": False},
            {"occurrence_id": "file-occ", "artifact_id": "file", "parent_occurrence_id": "root-occ",
             "logical_path": "dir/a.txt", "entry_kind": "file", "artifact_kind": "resource",
             "artifact_format": "file", "declared_size": 5, "executable": False, "encrypted": False},
            {"occurrence_id": "dir-occ", "artifact_id": "root", "parent_occurrence_id": "root-occ",
             "logical_path": "dir", "entry_kind": "directory", "artifact_kind": "container",
             "artifact_format": "zip", "declared_size": None, "executable": True, "encrypted": False},
        ],
    }


def test_inventory_is_found_inside_the_inspect_artifact_envelope():
    inv = inventory()
    assert analysis.artifact_inventory({"substeps": [{"evidence": {"normalized_result": inv}}]}) is inv


def test_only_regular_files_become_work_items_with_inventory_facts():
    entries = analysis.artifact_entries(inventory())
    assert [(e["name"], e["unit"], e["size"], e["sha256"]) for e in entries] == [
        ("dir/a.txt", "dir", 5, "b" * 64),
    ]
    assert entries[0]["kind"] == "artifact-entry"


def test_archive_entries_are_read_without_extracting():
    assert analysis.read_archive_entry(ZIP, "dir/a.txt") == b"hello"
    assert analysis.read_archive_entry(ZIP, "b.bin", 1, 3) == b"orl"
    assert analysis.read_archive_entry(ZIP, "missing") is None
    assert analysis.preview_bytes(b"hello") == "hello"


def test_archive_suffixes_are_recognized():
    assert analysis.is_archive(ZIP)
    assert not analysis.is_archive(Path("game.z64"))


def test_import_analysis_maps_archive_files_to_work_items(tmp_path, monkeypatch):
    from decompnet import rea
    from decompnet.app.engine import RomNetwork

    inv = inventory()

    class FakeClient:
        def call(self, tool, arguments=None, timeout=None, *, any_tool=False):
            if tool == "inspect_artifact":
                return {"substeps": [{"evidence": {"normalized_result": inv}}]}
            if tool in ("binary_overview", "list_segments", "list_procedures"):
                return {}
            raise AssertionError(tool)

    monkeypatch.setattr(rea, "open_analysis", lambda target, provider="": (
        FakeClient(), {"result": {"path": target["path"], "format": "zip", "kind": "archive"}}))
    net = RomNetwork(tmp_path / "decomp.db", tmp_path)
    slug = net.import_analysis(ZIP, confirmed=True, log=lambda *_: None)
    proj = net.project_row(slug)
    assert proj["description"] == "zip · 3 entries · 1 work item"
    rows = net.store.all("SELECT name, size, meta FROM functions WHERE project_id=? ORDER BY name", proj["id"])
    assert [r["name"] for r in rows] == ["dir/a.txt"]
    assert rows[0]["size"] == 5
    assert '"kind": "artifact-entry"' in rows[0]["meta"]
    overview = net.overview(slug)
    assert (overview["entries"], overview["files"], overview["functions"]) == (3, 1, 1)

    agent, _ = net.local_agent("archive-tester")
    net.claim(agent, slug)
    net.complete_analysis(agent, slug, "dir/a.txt", "A five-byte text file containing hello.")
    report = net.analysis_summary(slug)
    assert report["complete"] is True
    assert "A five-byte text file containing hello." in report["markdown"]
    assert Path(report["path"]).name == "SUMMARY.md"
    assert Path(report["path"]).exists()
