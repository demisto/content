"""ConnectUs connector documentation backfill toolkit.

This package implements the documentation-skill pipeline that backfills
human-facing documentation onto already-migrated *grouped* ConnectUs connectors
(``unified-connectors-content/connectors/<slug>/``).

Pipeline stages (see ``plans/connector-documentation-skill-design.md``):

    A RESOLVE -> B GATHER -> C AUTHOR (AI) -> D VALIDATE -> E APPLY

This module currently provides the deterministic, dependency-free *mechanical*
text processors used by stage B (GATHER):

    * :func:`markdown_processing.get_commands_sections`
    * :func:`markdown_processing.strip_command_sections`
    * :func:`markdown_processing.strip_conditionals`
    * :func:`markdown_processing.build_section_index`
"""

from __future__ import annotations
