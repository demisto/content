"""Unit tests for the mechanical Markdown processors (GATHER stage B).

Run from the package directory::

    cd content/connectus/connectus_docs && python3 -m pytest markdown_processing_test.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from markdown_processing import (  # noqa: E402
    Section,
    build_section_index,
    get_commands_sections,
    get_section_text,
    strip_command_sections,
    strip_conditionals,
)


# --------------------------------------------------------------------------- #
# get_commands_sections (slug locator — defensive secondary pass)
# --------------------------------------------------------------------------- #
class TestGetCommandsSections:
    def test_no_commands_returns_empty(self):
        assert get_commands_sections("## Overview\nSome prose.\n") == {}

    def test_single_command_runs_to_eof(self):
        text = "Intro line.\n### akamai-get-network-lists\nDoes a thing.\nMore.\n"
        ranges = get_commands_sections(text)
        assert set(ranges) == {"akamai-get-network-lists"}
        start, end = ranges["akamai-get-network-lists"]
        assert start == 1
        assert end == len(text.splitlines())

    def test_multiple_commands_heading_to_heading(self):
        text = "Intro\n### url\nurl body\n### domain\ndomain body\n"
        ranges = get_commands_sections(text)
        assert ranges["url"] == (1, 3)
        assert ranges["domain"] == (3, len(text.splitlines()))

    def test_non_slug_heading_is_not_a_command(self):
        text = "### url reputation\nbody\n"
        assert get_commands_sections(text) == {}

    def test_single_token_slug_allowed(self):
        assert set(get_commands_sections("### ip\nbody\n")) == {"ip"}

    def test_numeric_tokens_allowed(self):
        assert set(get_commands_sections("### get-v2-items\nbody\n")) == {"get-v2-items"}


# --------------------------------------------------------------------------- #
# strip_command_sections (primary: "## Commands" cut; secondary: stray slugs)
# --------------------------------------------------------------------------- #
class TestStripCommandSections:
    def test_removes_whole_commands_section_to_eof(self):
        # Real-world shape: a "## Commands" header followed by per-command blocks.
        text = (
            "## Configure\n"
            "Set up the connection.\n"
            "\n"
            "## Commands\n"
            "You can execute these commands.\n"
            "\n"
            "### akamai-check-group\n"
            "***\n"
            "#### Base Command\n"
            "`akamai-check-group`\n"
            "#### Context Output\n"
            "| Path | Type |\n"
        )
        out = strip_command_sections(text)
        assert "## Commands" not in out
        assert "akamai-check-group" not in out
        assert "Base Command" not in out
        assert "Context Output" not in out
        assert "Set up the connection." in out
        assert "## Configure" in out

    def test_commands_section_stops_at_next_level2_heading(self):
        text = (
            "## Setup\n"
            "setup body\n"
            "## Commands\n"
            "### cmd-one\n"
            "one\n"
            "## Troubleshooting\n"
            "ts body\n"
        )
        out = strip_command_sections(text)
        assert "## Commands" not in out
        assert "cmd-one" not in out
        assert "## Troubleshooting" in out
        assert "ts body" in out
        assert "## Setup" in out

    def test_commands_section_stops_at_next_level1_heading(self):
        text = "## Commands\n### cmd\nbody\n# Top Level After\nkeep\n"
        out = strip_command_sections(text)
        assert "## Commands" not in out
        assert "# Top Level After" in out
        assert "keep" in out

    def test_commands_header_is_case_insensitive(self):
        text = "intro\n## COMMANDS\n### cmd\nbody\n"
        out = strip_command_sections(text)
        assert "COMMANDS" not in out
        assert out.strip() == "intro"

    def test_commands_header_inside_code_fence_is_ignored(self):
        text = (
            "Real prose.\n"
            "```\n"
            "## Commands\n"
            "fake heading inside fence\n"
            "```\n"
            "More prose.\n"
        )
        out = strip_command_sections(text)
        # The fenced "## Commands" is not a real heading -> nothing stripped.
        assert "Real prose." in out
        assert "More prose." in out
        assert "fake heading inside fence" in out

    def test_stray_command_slug_outside_commands_section_removed(self):
        # No "## Commands" header, but a hand-inlined command slug block exists.
        text = "Intro paragraph.\n### cmd-one\none\n### cmd-two\ntwo\n"
        out = strip_command_sections(text)
        assert out.strip() == "Intro paragraph."

    def test_noop_when_no_commands_anywhere(self):
        text = "## Overview\nProse only.\n"
        assert strip_command_sections(text) == text

    def test_empty_input(self):
        assert strip_command_sections("") == ""

    def test_does_not_remove_configuration_prose_before_commands(self):
        text = (
            "## Akamai WAF\n"
            "Manage your network lists.\n"
            "### To configure fetch\n"  # NOT a command slug (has spaces)
            "Set the fetch interval.\n"
            "## Commands\n"
            "### akamai-get-network-lists\n"
            "body\n"
        )
        out = strip_command_sections(text)
        assert "Manage your network lists." in out
        assert "To configure fetch" in out
        assert "Set the fetch interval." in out
        assert "akamai-get-network-lists" not in out


# --------------------------------------------------------------------------- #
# strip_conditionals (§10)
# --------------------------------------------------------------------------- #
class TestStripConditionals:
    def test_no_conditionals_noop(self):
        text = "Plain text with no tags."
        assert strip_conditionals(text) == text

    def test_keeps_and_unwraps_xsiam(self):
        assert strip_conditionals("before <~XSIAM>keep me</~XSIAM> after") == (
            "before keep me after"
        )

    def test_keeps_and_unwraps_platform(self):
        assert strip_conditionals("<~Platform>platform only</~Platform>") == (
            "platform only"
        )

    def test_drops_xsoar(self):
        assert strip_conditionals("before <~XSOAR>drop me</~XSOAR> after") == (
            "before  after"
        )

    def test_drops_unknown_conditional(self):
        assert strip_conditionals("keep <~XPANSE>gone</~XPANSE> end") == "keep  end"

    def test_case_insensitive_tag_name(self):
        assert strip_conditionals("<~xsiam>kept</~xsiam>") == "kept"

    def test_nested_keep_inside_keep(self):
        text = "<~XSIAM>outer <~Platform>inner</~Platform> tail</~XSIAM>"
        assert strip_conditionals(text) == "outer inner tail"

    def test_nested_drop_inside_keep(self):
        text = "<~XSIAM>keep <~XSOAR>drop</~XSOAR> rest</~XSIAM>"
        assert strip_conditionals(text) == "keep  rest"

    def test_nested_keep_inside_drop(self):
        text = "head <~XSOAR>x <~XSIAM>y</~XSIAM> z</~XSOAR> tail"
        assert strip_conditionals(text) == "head  tail"

    def test_collapses_blank_lines_from_dropped_block(self):
        text = "line1\n\n<~XSOAR>\n\ndropped\n\n</~XSOAR>\n\nline2"
        out = strip_conditionals(text)
        assert "dropped" not in out
        assert "line1" in out and "line2" in out
        assert "\n\n\n" not in out

    def test_orphan_open_tag_keep_runs_to_end(self):
        assert strip_conditionals("head <~XSIAM>tail with no close") == (
            "head tail with no close"
        )

    def test_orphan_open_tag_drop_runs_to_end(self):
        assert strip_conditionals("head <~XSOAR>tail with no close") == "head"

    def test_multiline_realistic(self):
        text = (
            "# Setup\n"
            "Common intro.\n"
            "<~XSOAR>XSOAR-only paragraph.</~XSOAR>\n"
            "<~XSIAM>Generate an API key in the console.</~XSIAM>\n"
        )
        out = strip_conditionals(text)
        assert "XSOAR-only" not in out
        assert "Generate an API key in the console." in out
        assert "Common intro." in out


# --------------------------------------------------------------------------- #
# build_section_index / get_section_text (§3.4)
# --------------------------------------------------------------------------- #
class TestBuildSectionIndex:
    def test_flat_sections(self):
        text = "# A\nbody a\n# B\nbody b\n"
        idx = build_section_index(text)
        assert [s.title for s in idx] == ["A", "B"]
        assert idx[0].level == 1
        assert idx[0].heading_line == 0
        assert idx[0].body_start == 1
        assert idx[0].body_end == 2  # up to "# B"
        assert idx[1].body_end == len(text.splitlines())

    def test_nested_subsections_included_in_parent_range(self):
        text = (
            "# Top\n"        # 0
            "intro\n"        # 1
            "## Sub1\n"      # 2
            "s1\n"           # 3
            "## Sub2\n"      # 4
            "s2\n"           # 5
            "# Next\n"       # 6
            "n\n"            # 7
        )
        idx = build_section_index(text)
        top = next(s for s in idx if s.title == "Top")
        assert top.body_end == 6
        sub1 = next(s for s in idx if s.title == "Sub1")
        assert sub1.body_end == 4

    def test_ignores_headings_in_code_fences(self):
        text = "# Real\n```\n# not a heading\n```\n## Also Real\n"
        idx = build_section_index(text)
        assert [s.title for s in idx] == ["Real", "Also Real"]

    def test_tilde_fence_respected(self):
        text = "# Real\n~~~\n### fake\n~~~\n"
        idx = build_section_index(text)
        assert [s.title for s in idx] == ["Real"]

    def test_get_section_text_with_and_without_heading(self):
        text = "# A\nline1\nline2\n# B\nx\n"
        idx = build_section_index(text)
        a = idx[0]
        assert get_section_text(text, a, include_heading=True) == "# A\nline1\nline2"
        assert get_section_text(text, a, include_heading=False) == "line1\nline2"

    def test_section_is_frozen_dataclass(self):
        s = Section(level=1, title="t", heading_line=0, body_start=1, body_end=2)
        try:
            s.level = 2  # type: ignore[misc]
        except Exception as exc:
            assert isinstance(exc, Exception)
        else:  # pragma: no cover
            raise AssertionError("Section should be immutable")


# --------------------------------------------------------------------------- #
# Integration: full GATHER pipeline order (commands -> conditionals)
# --------------------------------------------------------------------------- #
class TestPipelineComposition:
    def test_strip_commands_then_conditionals(self):
        readme = (
            "## Akamai WAF\n"
            "Manage network lists.\n"
            "<~XSOAR>XSOAR notes.</~XSOAR>\n"
            "<~XSIAM>Generate keys in the console.</~XSIAM>\n"
            "\n"
            "## Commands\n"
            "### akamai-get-network-lists\n"
            "Returns the lists.\n"
        )
        trimmed = strip_conditionals(strip_command_sections(readme))
        assert "akamai-get-network-lists" not in trimmed
        assert "## Commands" not in trimmed
        assert "XSOAR notes." not in trimmed
        assert "Generate keys in the console." in trimmed
        assert "Manage network lists." in trimmed
