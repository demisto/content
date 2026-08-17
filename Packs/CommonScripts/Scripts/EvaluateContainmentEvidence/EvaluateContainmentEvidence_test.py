import pytest

from EvaluateContainmentEvidence import evaluate_containment_evidence


@pytest.mark.parametrize(
    "args, disposition, allowed, reason",
    [
        ({"detection_basis": "ml_only"}, "ml_only", False, "explicit_ml_only_evidence"),
        ({"detection_basis": "signature"}, "signature", True, "explicit_signature_evidence"),
        ({"generator_id": "411", "classification": "attempted-admin"}, "ml_only", False,
         "explicit_ml_only_evidence"),
        ({"incident_context": "SnortML high confidence"}, "ml_only", False, "explicit_ml_only_evidence"),
        ({"signature_id": "100042", "classification": "signature match"}, "signature", True,
         "inferred_signature_evidence"),
        ({}, "unknown", False, "insufficient_evidence"),
        ({"detection_basis": "unknown", "signature_id": "42"}, "unknown", False,
         "explicit_unknown_evidence"),
        ({"detection_basis": "invalid"}, "unknown", False, "invalid_detection_basis"),
        ({"detection_basis": "corroborated", "signature_id": "42"}, "unknown", False,
         "corroboration_missing_independent_signals"),
        ({"detection_basis": "corroborated", "signature_id": "42", "analytic_type": "ML"},
         "corroborated", True, "independent_ml_and_signature_evidence"),
        ({"incident_context": "signature+ml corroboration"}, "corroborated", True,
         "independent_ml_and_signature_evidence"),
        ({"generator_id": "411", "signature_id": "42", "is_corroborated": "True"}, "ml_only", False,
         "explicit_ml_only_evidence"),
        ({"incident_context": "is_ml_only=false", "signature_id": "42"}, "signature", True,
         "inferred_signature_evidence"),
    ],
)
def test_evaluate_containment_evidence(args, disposition, allowed, reason):
    result = evaluate_containment_evidence(args)

    assert result["disposition"] == disposition
    assert result["allow_auto_contain"] is allowed
    assert result["require_user_verification"] is not allowed
    assert result["reason_codes"] == [reason]


def test_output_is_deterministic():
    args = {"generator_id": "411", "classification": "signature", "incident_context": ["A", "B"]}

    assert evaluate_containment_evidence(args) == evaluate_containment_evidence(args)
