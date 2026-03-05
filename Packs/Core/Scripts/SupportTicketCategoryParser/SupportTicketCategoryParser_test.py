import json
import pytest
from SupportTicketCategoryParser import parse_and_validate, parse_taxonomy, validate_against_taxonomy

TAXONOMY_DATA = [
    {"Agent": ["Communication", "Device Control", "Install/Upgrade/Uninstall", "Performance", "non-persistent VDI"]},
    {"Attack Surface Management": ["Asset Inventory", "Attack Surface Issues", "Policies and Configuration"]},
    {"Cases and Issues": [
        "Breach Assessment", "Custom Domain", "Health Domain", "Hunting Domain",
        "IT Domain", "Posture Domain", "Security Domain", "Threat Coverage Analysis",
    ]},
    {"Tenant Administration and Access Control": [
        "Access Management", "Add-ons", "Audit Logs and Health Issues", "Copilot",
        "Cortex Gateway", "Licensing, Onboarding and Access", "Support Case Creation",
        "Tenant Availability", "Tenant Configuration", "Tenant Migration",
    ]},
    {"XDR Agent": [
        "XDR Agent for Cloud - App-embedded", "XDR Agent for Cloud - Container",
        "XDR Agent for Cloud - Host", "XDR Agent for Cloud - Kubernetes",
        "XDR Agent for Cloud - Serverless", "XDR Agent for Enterprise - Android",
        "XDR Agent for Enterprise - Linux", "XDR Agent for Enterprise - Windows",
        "XDR Agent for Enterprise - iOS", "XDR Agent for Enterprise - macOS",
    ]},
]

TAXONOMY_JSON = json.dumps(TAXONOMY_DATA)

# Python repr with single quotes — the format actually received at runtime
TAXONOMY_SINGLE_QUOTES = str(TAXONOMY_DATA)


class TestParseTaxonomy:
    """Tests for the ``parse_taxonomy`` helper."""

    def test_parse_from_list(self):
        result = parse_taxonomy(TAXONOMY_DATA)
        assert "Agent" in result
        assert "Communication" in result["Agent"]

    def test_parse_from_json_string(self):
        result = parse_taxonomy(TAXONOMY_JSON)
        assert "XDR Agent" in result
        assert "XDR Agent for Enterprise - Linux" in result["XDR Agent"]

    def test_parse_from_single_quote_string(self):
        """Taxonomy passed as Python repr (single quotes) should be parsed correctly."""
        result = parse_taxonomy(TAXONOMY_SINGLE_QUOTES)
        assert "Agent" in result
        assert "Communication" in result["Agent"]
        assert "XDR Agent" in result

    def test_parse_invalid_type_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            parse_taxonomy({"not": "a list"})

    def test_parse_invalid_entry_raises(self):
        with pytest.raises(ValueError, match="must be a dict"):
            parse_taxonomy(["not_a_dict"])


class TestValidateAgainstTaxonomy:
    """Tests for the ``validate_against_taxonomy`` helper."""

    def test_valid_category_and_concentration(self):
        taxonomy = parse_taxonomy(TAXONOMY_DATA)
        cat, conc, warnings = validate_against_taxonomy("Agent", "Communication", taxonomy)
        assert cat == "Agent"
        assert conc == "Communication"
        assert warnings == []

    def test_invalid_category_returns_none(self):
        """An invalid category should return None for both fields."""
        taxonomy = parse_taxonomy(TAXONOMY_DATA)
        cat, conc, warnings = validate_against_taxonomy("NonExistent", "Communication", taxonomy)
        assert cat is None
        assert conc is None
        assert len(warnings) == 1
        assert "not a valid category" in warnings[0]

    def test_invalid_concentration_returns_none_concentration(self):
        """An invalid concentration should return None for concentration only."""
        taxonomy = parse_taxonomy(TAXONOMY_DATA)
        cat, conc, warnings = validate_against_taxonomy("Agent", "NonExistent", taxonomy)
        assert cat == "Agent"
        assert conc is None
        assert len(warnings) == 1
        assert "not valid for category" in warnings[0]

    def test_none_values(self):
        taxonomy = parse_taxonomy(TAXONOMY_DATA)
        cat, conc, warnings = validate_against_taxonomy(None, None, taxonomy)
        assert cat is None
        assert conc is None
        assert warnings == []


class TestParseAndValidate:
    """Tests for the main ``parse_and_validate`` function."""

    def test_delimited_string_split(self):
        """A delimited string should be split into category and concentration."""
        args = {
            "classification_result": "XDR Agent|||XDR Agent for Enterprise - Linux",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IssueCategory"] == "XDR Agent"
        assert outputs["ProblemConcentration"] == "XDR Agent for Enterprise - Linux"
        assert outputs["IsValid"] is True
        assert outputs["Warnings"] is None

    def test_delimited_string_with_spaces(self):
        """Whitespace around the delimiter should be stripped."""
        args = {
            "classification_result": "Agent ||| Communication",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IssueCategory"] == "Agent"
        assert outputs["ProblemConcentration"] == "Communication"
        assert outputs["IsValid"] is True

    def test_no_delimiter_uses_whole_string_as_category(self):
        """When no delimiter is present, the whole string becomes the category."""
        args = {
            "classification_result": "Agent",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IssueCategory"] == "Agent"
        assert outputs["ProblemConcentration"] is None

    def test_invalid_category_in_taxonomy(self):
        """An invalid category should produce a warning and return None fields."""
        args = {
            "classification_result": "FakeCategory|||Communication",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IsValid"] is False
        assert outputs["IssueCategory"] is None
        assert outputs["ProblemConcentration"] is None
        assert len(outputs["Warnings"]) == 1
        assert "not a valid category" in outputs["Warnings"][0]

    def test_invalid_concentration_in_taxonomy(self):
        """An invalid concentration should produce a warning and return None concentration."""
        args = {
            "classification_result": "Agent|||FakeConcentration",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IsValid"] is False
        assert outputs["IssueCategory"] == "Agent"
        assert outputs["ProblemConcentration"] is None
        assert len(outputs["Warnings"]) == 1
        assert "not valid for category" in outputs["Warnings"][0]

    def test_empty_classification_result(self):
        """An empty classification result should return None for both fields."""
        args = {
            "classification_result": "",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IssueCategory"] is None
        assert outputs["ProblemConcentration"] is None

    def test_single_quote_taxonomy(self):
        """Taxonomy passed as Python repr (single quotes) should work."""
        args = {
            "classification_result": "Agent|||Communication",
            "taxonomy": TAXONOMY_SINGLE_QUOTES,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IssueCategory"] == "Agent"
        assert outputs["ProblemConcentration"] == "Communication"
        assert outputs["IsValid"] is True

    def test_readable_output_valid(self):
        """Readable output should indicate valid classification."""
        args = {
            "classification_result": "Agent|||Communication",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        assert "Valid**: Yes" in result.readable_output

    def test_readable_output_invalid(self):
        """Readable output should show warnings for invalid classification."""
        args = {
            "classification_result": "FakeCategory|||FakeConcentration",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        assert "Valid**: No" in result.readable_output
        assert "Warnings" in result.readable_output

    def test_tenant_admin_valid(self):
        """Test a valid Tenant Administration category."""
        args = {
            "classification_result": "Tenant Administration and Access Control|||Support Case Creation",
            "taxonomy": TAXONOMY_JSON,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IssueCategory"] == "Tenant Administration and Access Control"
        assert outputs["ProblemConcentration"] == "Support Case Creation"
        assert outputs["IsValid"] is True

    def test_globalprotect_not_in_taxonomy(self):
        """GlobalProtect is not in the taxonomy — should return None and a warning."""
        args = {
            "classification_result": "GlobalProtect|||GlobalProtect - Portal/Gateway Connection Issues",
            "taxonomy": TAXONOMY_SINGLE_QUOTES,
        }
        result = parse_and_validate(args)
        outputs = result.outputs
        assert outputs["IsValid"] is False
        assert outputs["IssueCategory"] is None
        assert outputs["ProblemConcentration"] is None
        assert "not a valid category" in outputs["Warnings"][0]
