import demistomock as demisto
from CommonServerPython import *

import json
from typing import Any


MITRE_MAPPINGS_FIELD = "devicesecuritymitremappingsraw"
IEC_REFERENCES_FIELD = "devicesecurityiecreferences"


def parse_json_value(value: Any) -> Any:
    """Parse a value that may have been JSON-encoded multiple times."""
    parsed_value = value

    for _ in range(3):
        if not isinstance(parsed_value, str):
            break

        try:
            parsed_value = json.loads(parsed_value)
        except (json.JSONDecodeError, TypeError):
            break

    return parsed_value


def normalize_mappings(value: Any) -> list[dict[str, Any]]:
    """Convert nested or individually stringified mappings to dictionaries."""
    normalized_mappings: list[dict[str, Any]] = []

    def collect(item: Any) -> None:
        parsed_item = parse_json_value(item)

        if isinstance(parsed_item, list):
            for nested_item in parsed_item:
                collect(nested_item)
            return

        if not isinstance(parsed_item, dict):
            return

        nested_mappings = parsed_item.get("mitre_mappings")
        if nested_mappings is not None:
            collect(nested_mappings)
            return

        if "framework" in parsed_item:
            normalized_mappings.append(parsed_item)

    collect(value)
    return normalized_mappings


def normalize_references(value: Any) -> list[str]:
    """Convert IEC references into a flat list of strings."""
    normalized_references: list[str] = []

    def collect(item: Any) -> None:
        parsed_item = parse_json_value(item)

        if isinstance(parsed_item, list):
            for nested_item in parsed_item:
                collect(nested_item)
            return

        if isinstance(parsed_item, dict):
            nested_references = parsed_item.get("iec_62443_references")
            if nested_references is not None:
                collect(nested_references)
            return

        if parsed_item is not None:
            reference = str(parsed_item).strip()
            if reference:
                normalized_references.append(reference)

    collect(value)
    return normalized_references


def get_event_data() -> dict[str, Any]:
    """Read the mapped storage fields from the current incident."""
    incidents = demisto.incidents()
    if not incidents:
        return {
            "mitre_mappings": [],
            "iec_62443_references": [],
        }

    incident = incidents[0]
    incident_fields = incident.get("CustomFields", {})

    if not isinstance(incident_fields, dict):
        incident_fields = {}

    raw_mappings = incident_fields.get(MITRE_MAPPINGS_FIELD, [])
    raw_references = incident_fields.get(IEC_REFERENCES_FIELD, [])

    return {
        "mitre_mappings": normalize_mappings(raw_mappings),
        "iec_62443_references": normalize_references(raw_references),
    }


def escape_markdown(value: Any) -> str:
    """Escape characters that can break a Markdown table."""
    return str(value or "").replace("\\", "\\\\").replace("|", r"\|").replace("\r", " ").replace("\n", " ").strip()


def get_framework_mappings(
    framework: str,
    mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return mappings belonging to the requested MITRE framework."""
    matching_mappings: list[dict[str, Any]] = []

    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue

        mapping_framework = str(mapping.get("framework", "")).strip()
        if mapping_framework.casefold() == framework.casefold():
            matching_mappings.append(mapping)

    return matching_mappings


def create_technique_table(
    title: str,
    framework: str,
    mappings: list[dict[str, Any]],
) -> list[str]:
    """Create a Markdown table for one MITRE framework."""
    matching_mappings = get_framework_mappings(framework, mappings)

    lines = [
        f"#### {title}",
        "| Technique ID | Technique |",
        "| --- | --- |",
    ]

    if not matching_mappings:
        lines.append("| N/A | N/A |")
        return lines

    displayed_rows: set[tuple[str, str]] = set()

    for mapping in matching_mappings:
        technique_id = escape_markdown(mapping.get("techniqueId"))
        technique = escape_markdown(mapping.get("technique"))

        technique_id = technique_id or "N/A"
        technique = technique or "N/A"

        row_key = (technique_id, technique)
        if row_key in displayed_rows:
            continue

        displayed_rows.add(row_key)
        lines.append(f"| {technique_id} | {technique} |")

    return lines


def shorten_iec_reference(reference: str) -> str:
    """Remove the repeated standard prefix for compact display."""
    standard_prefix = "IEC 62443-3-3 "
    cleaned_reference = reference.strip()

    if cleaned_reference.startswith(standard_prefix):
        return cleaned_reference[len(standard_prefix) :]

    return cleaned_reference


def create_iec_section(references: list[str]) -> list[str]:
    """Create a compact IEC 62443 references section."""
    lines = ["#### IEC 62443 Security Standards"]

    if not references:
        lines.append("N/A")
        return lines

    displayed_references: list[str] = []

    for reference in references:
        shortened_reference = shorten_iec_reference(reference)
        escaped_reference = escape_markdown(shortened_reference)

        if escaped_reference and escaped_reference not in displayed_references:
            displayed_references.append(escaped_reference)

    if displayed_references:
        lines.append(" · ".join(displayed_references))
    else:
        lines.append("N/A")

    return lines


def create_readable_output(event_data: dict[str, Any]) -> str:
    """Build the complete Markdown output for the dynamic section."""
    mappings = event_data.get("mitre_mappings", [])
    references = event_data.get("iec_62443_references", [])

    if not isinstance(mappings, list):
        mappings = []

    if not isinstance(references, list):
        references = []

    markdown_lines: list[str] = []

    markdown_lines.extend(
        create_technique_table(
            title="MITRE ATT&CK Enterprise Techniques",
            framework="Enterprise",
            mappings=mappings,
        )
    )

    markdown_lines.append("")

    markdown_lines.extend(
        create_technique_table(
            title="MITRE ATT&CK ICS Techniques",
            framework="ICS",
            mappings=mappings,
        )
    )

    markdown_lines.append("")
    markdown_lines.extend(create_iec_section(references))

    return "\n".join(markdown_lines)


def main() -> None:
    try:
        event_data = get_event_data()
        readable_output = create_readable_output(event_data)

        return_results(
            CommandResults(
                readable_output=readable_output,
            )
        )
    except Exception as error:
        return_error("Failed to render Device Security framework mappings: " f"{error!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
