from CommonServerPython import *


ML_ONLY_MARKERS = ("ml-only", "snortml", "gid 411", "gid:411", "generatorid=411")
ML_MARKERS = ML_ONLY_MARKERS + ("signature+ml", "signature and ml")
CORROBORATION_MARKERS = ("signature+ml", "signature and ml")
SIGNATURE_MARKERS = ("signature", "rule match", "rule-based", "rule based")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(_text(item) for item in value)
    return str(value).strip().lower()


def _is_true(value: Any) -> bool:
    return _text(value) in {"true", "yes", "1"}


def _has_true_flag(text: str, name: str) -> bool:
    return any(token in text for token in (f"{name}=true", f"{name}:true", f"{name}: true"))


def evaluate_containment_evidence(args: dict[str, Any]) -> dict[str, Any]:
    basis = _text(args.get("detection_basis")).replace("-", "_")
    analytic_type = _text(args.get("analytic_type"))
    generator_id = _text(args.get("generator_id"))
    signature_id = _text(args.get("signature_id"))
    classification = _text(args.get("classification"))
    context = _text(args.get("incident_context"))
    combined = " ".join((analytic_type, classification, context))

    explicit_ml = basis == "ml_only"
    explicit_ml_only = (
        explicit_ml
        or generator_id == "411"
        or _has_true_flag(combined, "is_ml_only")
        or any(marker in combined for marker in ML_ONLY_MARKERS)
    )
    inferred_ml = (
        generator_id == "411"
        or _has_true_flag(combined, "is_ml_only")
        or any(marker in combined for marker in ML_MARKERS)
    )
    ml_evidence = explicit_ml or inferred_ml or analytic_type in {"ml", "learning", "machine_learning"}

    explicit_signature = basis == "signature"
    inferred_signature = bool(signature_id) or any(marker in combined for marker in SIGNATURE_MARKERS)
    signature_evidence = explicit_signature or inferred_signature

    explicit_corroboration = basis == "corroborated" or _is_true(args.get("is_corroborated"))
    corroboration_evidence = (
        explicit_corroboration
        or _has_true_flag(combined, "is_corroborated")
        or any(marker in combined for marker in CORROBORATION_MARKERS)
    )

    reasons: list[str] = []
    if basis and basis not in {"ml_only", "signature", "corroborated", "unknown"}:
        reasons.append("invalid_detection_basis")
        disposition = "unknown"
    elif basis == "unknown":
        reasons.append("explicit_unknown_evidence")
        disposition = "unknown"
    elif explicit_ml_only:
        # Explicit ML-only evidence wins over classifications left on the same event.
        reasons.append("explicit_ml_only_evidence")
        disposition = "ml_only"
    elif explicit_corroboration:
        if ml_evidence and signature_evidence:
            reasons.append("independent_ml_and_signature_evidence")
            disposition = "corroborated"
        else:
            reasons.append("corroboration_missing_independent_signals")
            disposition = "unknown"
    elif explicit_signature:
        reasons.append("explicit_signature_evidence")
        disposition = "signature"
    elif ml_evidence and signature_evidence and corroboration_evidence:
        reasons.append("independent_ml_and_signature_evidence")
        disposition = "corroborated"
    elif signature_evidence and not ml_evidence:
        reasons.append("inferred_signature_evidence")
        disposition = "signature"
    elif ml_evidence:
        reasons.append("inferred_ml_only_evidence")
        disposition = "ml_only"
    else:
        reasons.append("insufficient_evidence")
        disposition = "unknown"

    allow_auto_contain = disposition in {"signature", "corroborated"}
    return {
        "disposition": disposition,
        "allow_auto_contain": allow_auto_contain,
        "require_user_verification": not allow_auto_contain,
        "reason_codes": reasons,
        "evidence_summary": (
            f"disposition={disposition}; auto_contain={'allowed' if allow_auto_contain else 'denied'}; "
            f"reason={','.join(reasons)}"
        ),
    }


def main() -> None:
    try:
        result = evaluate_containment_evidence(demisto.args())
        return_results(CommandResults(
            outputs_prefix="ContainmentEvidence",
            outputs=result,
            raw_response=result,
            readable_output=tableToMarkdown("Containment evidence decision", result, removeNull=True),
        ))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to evaluate containment evidence: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
