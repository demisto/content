import ast
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DELIMITER = "|||"


def parse_taxonomy(taxonomy_raw: str | list) -> dict[str, list[str]]:
    """Parse the taxonomy argument into a dict mapping category -> list of concentrations.

    Args:
        taxonomy_raw: Either a JSON string, a Python repr string, or a list of
            single-key dicts (e.g. [{"Agent": ["Communication", ...]}, ...]).

    Returns:
        A dict where keys are issue categories and values are lists of valid
        problem concentrations.
    """
    if isinstance(taxonomy_raw, str):
        # Try JSON first (double-quoted), fall back to Python literal (single-quoted)
        try:
            taxonomy_raw = json.loads(taxonomy_raw)
        except json.JSONDecodeError:
            demisto.debug("taxonomy is not valid JSON, trying ast.literal_eval")
            taxonomy_raw = ast.literal_eval(taxonomy_raw)

    if not isinstance(taxonomy_raw, list):
        raise ValueError("taxonomy must be a list of single-key dictionaries.")

    taxonomy: dict[str, list[str]] = {}
    for entry in taxonomy_raw:
        if not isinstance(entry, dict):
            raise ValueError(f"Each taxonomy entry must be a dict, got {type(entry).__name__}.")
        for category, concentrations in entry.items():
            taxonomy[category] = concentrations
    return taxonomy


def validate_against_taxonomy(
    issue_category: str | None,
    problem_concentration: str | None,
    taxonomy: dict[str, list[str]],
) -> tuple[str | None, str | None, list[str]]:
    """Validate that the category and concentration exist in the taxonomy.

    Args:
        issue_category: The issue category to validate.
        problem_concentration: The problem concentration to validate.
        taxonomy: Parsed taxonomy mapping categories to concentrations.

    Returns:
        A tuple of (validated_category, validated_concentration, warnings).
        If a value is not found in the taxonomy the corresponding field is
        returned as-is and a warning is appended.
    """
    warnings: list[str] = []

    if issue_category and issue_category not in taxonomy:
        warnings.append(
            f'issue_category "{issue_category}" is not a valid category in the taxonomy. '
            f"Valid categories: {list(taxonomy.keys())}"
        )

        return None, None, warnings

    if issue_category and problem_concentration and issue_category in taxonomy:
        valid_concentrations = taxonomy[issue_category]
        if problem_concentration not in valid_concentrations:
            warnings.append(
                f'problem_concentration "{problem_concentration}" is not valid for '
                f'category "{issue_category}". '
                f"Valid concentrations: {valid_concentrations}"
            )
            problem_concentration = None

    return issue_category, problem_concentration, warnings


def parse_and_validate(args: dict) -> CommandResults:
    """Main logic: split the delimited classification result and validate against taxonomy.

    The LLM classification script (``SupportTicketClassification``) returns a single
    delimited string in the format ``<issue_category>|||<problem_concentration>``.
    This function splits that string on the ``|||`` delimiter and validates both
    parts against the provided taxonomy.

    Args:
        args: Script arguments containing *classification_result* and *taxonomy*.

    Returns:
        A ``CommandResults`` object with the parsed and validated values.
    """
    classification_result: str = args.get("classification_result", "")
    taxonomy_raw = args.get("taxonomy", "[]")

    demisto.debug(f"Input - classification_result: {classification_result}")

    if DELIMITER in classification_result:
        parts = classification_result.split(DELIMITER)
        issue_category = parts[0].strip() if len(parts) > 0 else None
        problem_concentration = parts[1].strip() if len(parts) > 1 else None
    else:
        issue_category = classification_result.strip() if classification_result else None
        problem_concentration = None
        demisto.debug(
            f"No delimiter found in classification_result. "
            f"Using entire value as issue_category: {issue_category}"
        )

    demisto.debug(
        f"Parsed - issue_category: {issue_category}, "
        f"problem_concentration: {problem_concentration}"
    )

    taxonomy = parse_taxonomy(taxonomy_raw)
    issue_category, problem_concentration, warnings = validate_against_taxonomy(
        issue_category, problem_concentration, taxonomy
    )

    for warning in warnings:
        demisto.debug(f"Taxonomy validation warning: {warning}")

    outputs = {
        "IssueCategory": issue_category,
        "ProblemConcentration": problem_concentration,
        "IsValid": len(warnings) == 0,
        "Warnings": warnings if warnings else None,
    }

    if warnings:
        readable = (
            f"### Support Ticket Category Parser\n\n"
            f"- **Issue Category**: {issue_category}\n"
            f"- **Problem Concentration**: {problem_concentration}\n"
            f"- **Valid**: No\n\n"
            f"#### Warnings\n" + "\n".join(f"- {w}" for w in warnings)
        )
    else:
        readable = (
            f"### Support Ticket Category Parser\n\n"
            f"- **Issue Category**: {issue_category}\n"
            f"- **Problem Concentration**: {problem_concentration}\n"
            f"- **Valid**: Yes"
        )

    return CommandResults(
        outputs_prefix="Core.SupportTicketCategoryParser",
        outputs=outputs,
        readable_output=readable,
    )


def main():  # pragma: no cover
    try:
        args = demisto.args()
        result = parse_and_validate(args)
        return_results(result)
    except Exception as e:
        return_error(f"Failed to parse support ticket category: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
