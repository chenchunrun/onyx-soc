from onyx.server.features.release_notes.utils import parse_mdx_to_release_note_entries


def test_parse_mdx_to_release_note_entries_supports_custom_title_and_link() -> None:
    entries = parse_mdx_to_release_note_entries(
        """
<Update label="v0.0.1-local.1" description="2026-04-11" title="本地通知" link="/admin/security-platform">
Body
</Update>
        """.strip()
    )

    assert len(entries) == 1
    assert entries[0].version == "v0.0.1-local.1"
    assert entries[0].date == "2026-04-11"
    assert entries[0].title == "本地通知"
    assert entries[0].link == "/admin/security-platform"
