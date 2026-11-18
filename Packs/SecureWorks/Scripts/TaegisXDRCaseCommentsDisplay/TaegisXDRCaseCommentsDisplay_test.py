import demistomock as demisto
from TaegisXDRCaseCommentsDisplay import (
    _clean_timestamp,
    _is_truthy,
    _meta_for,
    _render,
    _split_author_body,
    main,
)


def test_is_truthy():
    assert _is_truthy(True) is True
    assert _is_truthy("Yes") is True
    assert _is_truthy("no") is False
    assert _is_truthy("") is False


def test_clean_timestamp_strips_micros_and_z():
    assert _clean_timestamp("2026-02-02T19:32:51.772601189Z") == "2026-02-02 19:32:51 UTC"


def test_clean_timestamp_empty():
    assert _clean_timestamp(None) == ""
    assert _clean_timestamp("") == ""


def test_split_author_body_with_header():
    author, body = _split_author_body("alice — 2026-02-02T19:32:51Z\n\nHello there")
    assert author == "alice"
    assert body == "Hello there"


def test_split_author_body_strips_bold_markers():
    author, body = _split_author_body("**alice** — 2026-02-02T19:32:51Z\n\nHello there")
    assert author == "alice"
    assert body == "Hello there"


def test_split_author_body_no_header_returns_none_author():
    author, body = _split_author_body("Just a plain comment\n\nwith two paragraphs")
    assert author is None
    assert body == "Just a plain comment\n\nwith two paragraphs"


def test_split_author_body_none_contents():
    author, body = _split_author_body(None)
    assert author is None
    assert body == ""


def test_meta_for_known_and_unknown_tag():
    assert _meta_for(["CommentFromTaegis"], ["CommentFromTaegis", "xdrcomment"])["direction"] == "from Taegis XDR"
    assert _meta_for(["someothertag"], ["CommentFromTaegis", "xdrcomment"])["default_author"] == "Unknown"


def test_render_no_matching_comments():
    assert _render([], ["xdrcomment"]) == "_No comments yet._"


def test_render_sorts_newest_first_and_labels_direction():
    entries = [
        {
            "Tags": ["CommentFromTaegis"],
            "Metadata": {"created": "2026-02-01T10:00:00Z"},
            "Contents": "**Taegis Analyst** — 2026-02-01T10:00:00Z\n\nOlder comment",
        },
        {
            "Tags": ["xdrcomment"],
            "Metadata": {"created": "2026-02-02T10:00:00Z"},
            "Contents": "alice — 2026-02-02T10:00:00Z\n\nNewer comment",
        },
    ]
    rendered = _render(entries, ["xdrcomment", "CommentFromTaegis"])
    newer_pos = rendered.find("Newer comment")
    older_pos = rendered.find("Older comment")
    assert newer_pos < older_pos
    assert "to Taegis XDR" in rendered
    assert "from Taegis XDR" in rendered


def test_render_degrades_per_malformed_entry(mocker):
    mocker.patch("TaegisXDRCaseCommentsDisplay._clean_timestamp", side_effect=Exception("bad entry"))
    entries = [{"Tags": ["xdrcomment"], "Metadata": {"created": "x"}, "Contents": "text"}]

    rendered = _render(entries, ["xdrcomment"])

    assert "comment failed to render" in rendered
    assert "text" in rendered


def test_main_debug_mode_dumps_json(mocker):
    mocker.patch.object(demisto, "args", return_value={"debug": "true"})
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Tags": ["xdrcomment"], "Contents": "hi"}])
    return_results_mock = mocker.patch("TaegisXDRCaseCommentsDisplay.return_results")

    main()

    result = return_results_mock.call_args[0][0]
    assert "getEntries" in result["Contents"]


def test_main_default_renders_comments(mocker):
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Tags": ["xdrcomment"],
                "Metadata": {"created": "2026-02-02T10:00:00Z"},
                "Contents": "alice — 2026-02-02T10:00:00Z\n\nHello",
            }
        ],
    )
    return_results_mock = mocker.patch("TaegisXDRCaseCommentsDisplay.return_results")

    main()

    result = return_results_mock.call_args[0][0]
    assert "Hello" in result["Contents"]
    assert result["Type"] == 1
