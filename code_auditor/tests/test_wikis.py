from __future__ import annotations

from code_auditor.wikis import list_local_wikis


def test_list_local_wikis_finds_git_and_index_roots(tmp_path) -> None:
    git_wiki = tmp_path / "qemu-security"
    (git_wiki / ".git").mkdir(parents=True)
    indexed_wiki = tmp_path / "group" / "virtualbox-security"
    indexed_wiki.mkdir(parents=True)
    (indexed_wiki / "index.md").write_text("# Wiki\n", encoding="utf-8")
    (tmp_path / "notes").mkdir()

    wikis = list_local_wikis(str(tmp_path))

    assert [wiki["name"] for wiki in wikis] == [
        "group/virtualbox-security",
        "qemu-security",
    ]
    assert wikis[0]["path"] == str(indexed_wiki)


def test_list_local_wikis_rejects_unsafe_or_escaping_directories(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    unsafe = root / "unsafe name"
    unsafe.mkdir()
    (unsafe / "index.md").write_text("# Wiki\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "index.md").write_text("# Wiki\n", encoding="utf-8")
    (root / "escape").symlink_to(outside, target_is_directory=True)

    assert list_local_wikis(str(root)) == []


def test_list_local_wikis_missing_root_is_empty(tmp_path) -> None:
    assert list_local_wikis(str(tmp_path / "missing")) == []
