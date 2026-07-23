#!/usr/bin/env python3
"""Migrate a Cortex XSOAR / XSIAM playbook from old Core commands to new PCI commands.

Given a playbook YAML file, this script rewrites, in place:

  1. Command tasks: any ``task.script`` of the form ``<brand>|||<old_command>`` whose
     ``old_command`` is present in the mapping is rewritten to ``Builtin|||<new_command>``
     and ``task.brand`` is set to ``Builtin``.
  2. Argument keys: ``scriptarguments`` keys are renamed per the mapping's
     ``args_changes.moved`` and dropped per ``args_changes.removed`` (with a warning).
  3. Output context paths: every downstream reference to an old output context path is
     rewritten per the union of every command's ``output_changes.moved`` +
     ``output_changes.changed``. References are rewritten in ``scriptarguments`` (simple
     DT ``${...}`` expressions and ``complex`` root/accessor), ``conditions``,
     ``filters``, ``transformers`` args, ``fieldMapping`` outputs, and the playbook-level
     ``inputs`` / ``outputs`` lists.

Anything that cannot be mapped (a command in ``not_migrated``, an unmatched command, a
removed argument still in use, or a removed output still referenced) is reported as a
red line on stderr and the script continues.

Usage:
    python scripts/cmdmap/migrate_playbook.py <playbook.yml> [--mapping <path>] [--dry-run]

Prerequisites:
    pip install ruamel.yaml
"""

import argparse
import json
import os
import re
import sys

try:
    from ruamel.yaml import YAML
    from ruamel.yaml.scalarstring import (
        DoubleQuotedScalarString,
        SingleQuotedScalarString,
        PlainScalarString,
    )
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write(
        "ruamel.yaml is required. Install it with: pip install ruamel.yaml\n"
    )
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MAPPING = os.path.join(HERE, "endpoint_mapping.json")

NEW_BRAND = "Builtin"
SCRIPT_SEP = "|||"

# ANSI colors
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RESET = "\033[0m"


class Reporter:
    """Collects warnings and prints red lines to stderr, then a final summary."""

    def __init__(self):
        self.warnings = 0
        self.tasks_migrated = 0
        self.args_renamed = 0
        self.args_dropped = 0
        self.outputs_rewritten = 0

    def warn(self, message):
        self.warnings += 1
        sys.stderr.write("{}[UNMAPPABLE] {}{}\n".format(RED, message, RESET))

    def note(self, message):
        sys.stderr.write("{}[NOTE] {}{}\n".format(YELLOW, message, RESET))

    def summary(self):
        sys.stderr.write(
            "\n{}Migration summary:{}\n"
            "  tasks migrated:      {}\n"
            "  args renamed:        {}\n"
            "  args dropped:        {}\n"
            "  output refs rewritten: {}\n"
            "  warnings:            {}\n".format(
                GREEN,
                RESET,
                self.tasks_migrated,
                self.args_renamed,
                self.args_dropped,
                self.outputs_rewritten,
                self.warnings,
            )
        )


def load_mapping(path):
    """Load the mapping JSON and build lookup tables.

    Returns a dict with:
      matched:        old_command -> match entry
      not_migrated:   set of old_command strings
      output_renames: old_context_path -> new_context_path (global, across all commands)
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    matched = {}
    for entry in data.get("matched_commands", []):
        old = entry.get("old_command")
        if old:
            # One-to-many collapses (e.g. quick-action variants -> same new command)
            # are resolved deterministically here by exact old_command key.
            matched[old] = entry

    not_migrated = {
        e.get("old_command")
        for e in data.get("not_migrated", [])
        if e.get("old_command")
    }

    output_renames = {}
    for entry in data.get("matched_commands", []):
        oc = entry.get("output_changes", {}) or {}
        for old_path, new_path in (oc.get("moved") or {}).items():
            output_renames[old_path] = new_path
        for old_path, new_path in (oc.get("changed") or {}).items():
            output_renames[old_path] = new_path

    output_removed = set()
    for entry in data.get("matched_commands", []):
        oc = entry.get("output_changes", {}) or {}
        for removed in oc.get("removed") or []:
            output_removed.add(removed)

    return {
        "matched": matched,
        "not_migrated": not_migrated,
        "output_renames": output_renames,
        "output_removed": output_removed,
    }


def parse_script(script_value):
    """Split a 'brand|||command' script string into (brand, command).

    Returns (None, None) when the value is not a command script string.
    """
    if not isinstance(script_value, str) or SCRIPT_SEP not in script_value:
        return None, None
    brand, _, command = script_value.partition(SCRIPT_SEP)
    return brand, command


def preserve_style(original, new_text):
    """Return new_text wrapped to match the quoting style of the original scalar."""
    if isinstance(original, SingleQuotedScalarString):
        return SingleQuotedScalarString(new_text)
    if isinstance(original, DoubleQuotedScalarString):
        return DoubleQuotedScalarString(new_text)
    if isinstance(original, PlainScalarString):
        return PlainScalarString(new_text)
    return new_text


def make_path_regex(old_path):
    """Compile a regex matching old_path as a whole context-path token.

    Matches the path when it is followed by a boundary: end, '.', a bracket index
    like '.[0]' or '[0]', a closing brace '}', whitespace, or common delimiters.
    """
    escaped = re.escape(old_path)
    # Boundary before: start, or a non-path char (not a letter/digit/_/.)
    # Boundary after: not a letter/digit/_ (so 'Foo' does not match inside 'FooBar').
    return re.compile(r"(?<![A-Za-z0-9_.])" + escaped + r"(?![A-Za-z0-9_])")


class OutputRewriter:
    """Rewrites old output context paths to new ones inside string scalars."""

    def __init__(self, output_renames, output_removed, reporter):
        self.reporter = reporter
        self.output_removed = output_removed
        # Sort longest-first so more specific paths are replaced before their prefixes.
        self.rules = sorted(
            (
                (old, new, make_path_regex(old))
                for old, new in output_renames.items()
            ),
            key=lambda r: len(r[0]),
            reverse=True,
        )
        self.removed_rules = sorted(
            ((p, make_path_regex(p)) for p in output_removed),
            key=lambda r: len(r[0]),
            reverse=True,
        )

    def rewrite_text(self, text, location):
        """Rewrite a single string. Returns (new_text, changed_bool)."""
        if not isinstance(text, str) or not text:
            return text, False

        changed = False
        result = text
        for old, new, rx in self.rules:
            new_result, n = rx.subn(new, result)
            if n:
                changed = True
                self.reporter.outputs_rewritten += n
                result = new_result

        # Warn about references to removed outputs that are still present.
        for removed_path, rx in self.removed_rules:
            if rx.search(result):
                self.reporter.warn(
                    "removed output '{}' is still referenced at {} "
                    "(left unchanged for manual review)".format(removed_path, location)
                )
        return result, changed


def walk_and_rewrite_strings(node, rewriter, location):
    """Recursively rewrite output context paths in every string scalar under node."""
    if isinstance(node, dict):
        for key in list(node.keys()):
            value = node[key]
            child_loc = "{}.{}".format(location, key)
            if isinstance(value, (dict, list)):
                walk_and_rewrite_strings(value, rewriter, child_loc)
            elif isinstance(value, str):
                new_text, changed = rewriter.rewrite_text(value, child_loc)
                if changed:
                    node[key] = preserve_style(value, new_text)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            child_loc = "{}[{}]".format(location, idx)
            if isinstance(value, (dict, list)):
                walk_and_rewrite_strings(value, rewriter, child_loc)
            elif isinstance(value, str):
                new_text, changed = rewriter.rewrite_text(value, child_loc)
                if changed:
                    node[idx] = preserve_style(value, new_text)


def normalize_changed(changed):
    """Yield (arg_name, [change_dict, ...]) from args_changes.changed.

    ``changed`` values may be a single dict or a list of dicts.
    """
    for name, val in (changed or {}).items():
        if isinstance(val, list):
            yield name, val
        else:
            yield name, [val]


def migrate_scriptarguments(task_obj, entry, reporter, task_label):
    """Rename/drop scriptarguments keys per the command's args_changes."""
    args = task_obj.get("scriptarguments")
    if not isinstance(args, dict):
        return

    args_changes = entry.get("args_changes", {}) or {}
    moved = args_changes.get("moved") or {}
    removed = set(args_changes.get("removed") or [])

    # Rename moved keys, preserving insertion order and comments where possible.
    for old_key, new_key in moved.items():
        if old_key in args:
            value = args.pop(old_key)
            args[new_key] = value
            reporter.args_renamed += 1
            reporter.note(
                "{}: renamed argument '{}' -> '{}'".format(task_label, old_key, new_key)
            )

    # Drop removed keys with a warning that a used arg is gone.
    for old_key in list(args.keys()):
        if old_key in removed:
            args.pop(old_key)
            reporter.args_dropped += 1
            reporter.warn(
                "{}: argument '{}' was removed in the new command and has been "
                "dropped".format(task_label, old_key)
            )


def migrate_task(task_id, task_wrapper, mapping, reporter):
    """Migrate a single task entry. Returns True if the command was rewritten."""
    if not isinstance(task_wrapper, dict):
        return False
    task_obj = task_wrapper.get("task")
    if not isinstance(task_obj, dict):
        return False
    if not task_obj.get("iscommand"):
        return False

    script_value = task_obj.get("script")
    brand, old_command = parse_script(script_value)
    if old_command is None:
        return False

    task_name = task_obj.get("name") or ""
    task_label = "task '{}' ({})".format(task_id, task_name).strip()

    matched = mapping["matched"]
    if old_command in matched:
        entry = matched[old_command]
        new_command = entry.get("new_command")
        if not new_command:
            reporter.warn(
                "{}: command '{}' has no new_command in mapping".format(
                    task_label, old_command
                )
            )
            return False

        new_script = "{}{}{}".format(NEW_BRAND, SCRIPT_SEP, new_command)
        task_obj["script"] = preserve_style(script_value, new_script)
        if "brand" in task_obj:
            task_obj["brand"] = preserve_style(task_obj["brand"], NEW_BRAND)
        else:
            task_obj["brand"] = NEW_BRAND

        migrate_scriptarguments(task_wrapper, entry, reporter, task_label)
        reporter.tasks_migrated += 1
        reporter.note(
            "{}: migrated command '{}' -> '{}'".format(
                task_label, old_command, new_command
            )
        )
        return True

    if old_command in mapping["not_migrated"]:
        reporter.warn(
            "{}: command '{}' is in not_migrated (no PCI replacement); "
            "left unchanged".format(task_label, old_command)
        )
        return False

    # Not a Core command we know about. Only warn for core-/xdr- style commands to
    # avoid noise from built-in scripts already using new names.
    if old_command.startswith("core-") or old_command.startswith("xdr-"):
        reporter.warn(
            "{}: command '{}' not found in mapping; left unchanged".format(
                task_label, old_command
            )
        )
    return False


def migrate_playbook(playbook, mapping, reporter):
    """Mutate the loaded playbook structure in place."""
    tasks = playbook.get("tasks")
    if isinstance(tasks, dict):
        for task_id, task_wrapper in tasks.items():
            migrate_task(task_id, task_wrapper, mapping, reporter)

    # Rewrite output context-path references across the entire playbook.
    rewriter = OutputRewriter(
        mapping["output_renames"], mapping["output_removed"], reporter
    )
    walk_and_rewrite_strings(playbook, rewriter, "playbook")


def build_yaml():
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096  # avoid line-wrapping long scalars
    yaml.indent(mapping=2, sequence=2, offset=0)
    return yaml


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Migrate a playbook from old Core commands to new PCI commands."
    )
    parser.add_argument("playbook", help="Path to the playbook YAML file (edited in place).")
    parser.add_argument(
        "--mapping",
        default=DEFAULT_MAPPING,
        help="Path to endpoint_mapping.json (default: scripts/cmdmap/out/endpoint_mapping.json).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do everything except writing the file back.",
    )
    args = parser.parse_args(argv)

    if not os.path.isfile(args.playbook):
        sys.stderr.write(
            "{}playbook not found: {}{}\n".format(RED, args.playbook, RESET)
        )
        return 1
    if not os.path.isfile(args.mapping):
        sys.stderr.write(
            "{}mapping not found: {}{}\n".format(RED, args.mapping, RESET)
        )
        return 1

    mapping = load_mapping(args.mapping)
    reporter = Reporter()

    yaml = build_yaml()
    with open(args.playbook, encoding="utf-8") as fh:
        playbook = yaml.load(fh)

    if playbook is None:
        sys.stderr.write(
            "{}empty or invalid playbook: {}{}\n".format(RED, args.playbook, RESET)
        )
        return 1

    migrate_playbook(playbook, mapping, reporter)

    if args.dry_run:
        reporter.note("dry-run: not writing changes to disk")
    else:
        with open(args.playbook, "w", encoding="utf-8") as fh:
            yaml.dump(playbook, fh)

    reporter.summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
