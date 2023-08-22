from RemediationPathRuleEvaluation import evaluate_criteria, match_remediation_rule
import demistomock as demisto  # noqa: F401
import pytest

ALERT_CONTEXT = {
    "severity": 1,
    "ip": "1.1.1.1",
    "tag": [
        {"key": "env", "source": "AWS", "value": "dev"},
        {"key": "Name", "source": "AWS", "value": "rdp_server"},
    ],
    "provider": ["Amazon Web Services", "Google"],
    "development_environment": True,
    "cloud_managed": [
        {
            "organization": "n/a",
            "other": "us-east-1a",
            "project": "n/a",
            "provider": "AWS",
            "region": "us-east-1",
        }
    ],
    "service_owner_identified": [
        {
            "email": "n/a",
            "name": "service_XSOAR",
            "source": "AWS",
            "timestamp": "2023-01-26T15:51:17.346Z",
        }
    ],
}


# Evaluate Criteria Tests #
@pytest.mark.parametrize(
    "test_condition, test_alert_context, expected_result",
    [
        ({"field": "severity", "operator": "eq", "value": "LOW"}, ALERT_CONTEXT, True),
        ({"field": "severity", "operator": "eq", "value": "HIGH"}, ALERT_CONTEXT, False),
        ({"field": "severity", "operator": "eq", "value": "MEDIUM"}, {"severity": None}, False),
    ]
)
def test_evaluate_criteria_severity(test_condition, test_alert_context, expected_result):
    assert evaluate_criteria(test_condition, test_alert_context) is expected_result


@pytest.mark.parametrize(
    "test_condition, test_alert_context, expected_result",
    [
        ({"field": "ip", "operator": "eq", "value": "1.1.1.1"}, ALERT_CONTEXT, True),
        ({"field": "ip", "operator": "eq", "value": "2.2.2.2"}, ALERT_CONTEXT, False),
        ({"field": "ip", "operator": "eq", "value": "1.1.1.1"}, {"ip": None}, False),
    ]
)
def test_evaluate_criteria_ip(test_condition, test_alert_context, expected_result):
    assert evaluate_criteria(test_condition, test_alert_context) is expected_result


@pytest.mark.parametrize(
    "test_condition, test_alert_context, expected_result",
    [
        ({"field": "tag", "operator": "eq", "value": "rdp_server"}, ALERT_CONTEXT, True),
        ({"field": "tag", "operator": "eq", "value": "env"}, ALERT_CONTEXT, True),
        ({"field": "tag", "operator": "eq", "value": "wrong"}, ALERT_CONTEXT, False),
    ]
)
def test_evaluate_criteria_tag(test_condition, test_alert_context, expected_result):
    assert evaluate_criteria(test_condition, test_alert_context) is expected_result


@pytest.mark.parametrize(
    "test_condition, test_alert_context, expected_result",
    [
        ({"field": "provider", "operator": "eq", "value": "amazon web services"}, ALERT_CONTEXT, True),
        ({"field": "provider", "operator": "eq", "value": "amazon web services"}, {"provider": "Amazon Web Services"}, True),
        ({"field": "provider", "operator": "eq", "value": "amazon web services"}, {"provider": None}, False),
        ({"field": "provider", "operator": "eq", "value": "aws"}, ALERT_CONTEXT, False),
    ]
)
def test_evaluate_criteria_provider(test_condition, test_alert_context, expected_result):
    assert evaluate_criteria(test_condition, test_alert_context) is expected_result


test_data = [
    ("development_environment", True),
    ("cloud_managed", False),
    ("service_owner_identified", False),
]


@pytest.mark.parametrize("field_name, is_boolean", test_data)
def test_evaluate_criteria_boolean_type_check(field_name, is_boolean):
    # is_boolean is True if the field can actually be a True/False value vs.
    # is_boolean is False if True/False is determined by the presence of the field's value

    # test criteria condition is true
    cond = {"field": field_name, "operator": "eq", "value": "true"}
    assert evaluate_criteria(cond, ALERT_CONTEXT) is True

    if is_boolean:
        alert_context = {field_name: False}
        assert evaluate_criteria(cond, alert_context) is False

    alert_context = {field_name: None}
    assert evaluate_criteria(cond, alert_context) is False

    # test criteria condition is false
    cond = {"field": field_name, "operator": "eq", "value": "false"}
    assert evaluate_criteria(cond, ALERT_CONTEXT) is False

    if is_boolean:
        alert_context = {field_name: False}
        assert evaluate_criteria(cond, alert_context) is True

    alert_context = {field_name: None}
    assert evaluate_criteria(cond, alert_context) is True


# Match Remediation Rule Tests #
def test_match_remediation_rule_basic():
    # multiple rule matches
    rules = [
        {
            "rule_id": "8e4ff951-9e17-492a-8fd8-c2a0f45b0d36",
            "rule_name": "RDP dev rule",
            "description": "add a Rdp rule",
            "attack_surface_rule_id": "RdpServer",
            "criteria": [
                {"field": "development_environment", "value": "true", "operator": "eq"},
                {"field": "ip", "value": "1.1.1.1", "operator": "eq"},
            ],
            "criteria_conjunction": "AND",
            "action": "email",
            "created_by": "noc@acme.com",
            "created_by_pretty": "First Last",
            "created_at": 1674264241000,
        },
        {
            "rule_id": "36b215c3-a336-40e3-bf13-0b976c72ebb6",
            "rule_name": "SSH Severity Rule",
            "description": "A SshServer Rule",
            "attack_surface_rule_id": "SshServer",
            "criteria": [{"field": "severity", "value": "low", "operator": "eq"}],
            "criteria_conjunction": "AND",
            "action": "servicenow",
            "created_by": "noc@acme.com",
            "created_by_pretty": "First Last",
            "created_at": 1674540567000,
        },
    ]
    matched_rule = match_remediation_rule(ALERT_CONTEXT, rules)
    assert len(matched_rule) == 1
    assert matched_rule[0]["rule_id"] == "36b215c3-a336-40e3-bf13-0b976c72ebb6"

    # multiple criteria matches
    rules = [
        {
            "rule_id": "8e4ff951-9e17-492a-8fd8-c2a0f45b0d36",
            "rule_name": "RDP dev rule",
            "description": "add a Rdp rule",
            "attack_surface_rule_id": "RdpServer",
            "criteria": [
                {"field": "development_environment", "value": "true", "operator": "eq"},
                {"field": "ip", "value": "1.1.1.1", "operator": "eq"},
            ],
            "criteria_conjunction": "AND",
            "action": "email",
            "created_by": "noc@acme.com",
            "created_by_pretty": "First Last",
            "created_at": 1674264241000,
        },
        {
            "rule_id": "36b215c3-a336-40e3-bf13-0b976c72ebb6",
            "rule_name": "SSH Severity Rule",
            "description": "A SshServer Rule",
            "attack_surface_rule_id": "SshServer",
            "criteria": [{"field": "severity", "value": "high", "operator": "eq"}],
            "criteria_conjunction": "AND",
            "action": "servicenow",
            "created_by": "noc@acme.com",
            "created_by_pretty": "First Last",
            "created_at": 1674540567000,
        },
    ]
    matched_rule = match_remediation_rule(ALERT_CONTEXT, rules)
    assert len(matched_rule) == 1
    assert matched_rule[0]["rule_id"] == "8e4ff951-9e17-492a-8fd8-c2a0f45b0d36"

    # pass in 1 rule
    rules = {
        "rule_id": "8e4ff951-9e17-492a-8fd8-c2a0f45b0d36",
        "rule_name": "RDP dev rule",
        "description": "add a Rdp rule",
        "attack_surface_rule_id": "RdpServer",
        "criteria": [
            {"field": "development_environment", "value": "true", "operator": "eq"},
            {"field": "ip", "value": "1.1.1.1", "operator": "eq"},
        ],
        "criteria_conjunction": "AND",
        "action": "email",
        "created_by": "noc@acme.com",
        "created_by_pretty": "First Last",
        "created_at": 1674264241000,
    }
    matched_rule = match_remediation_rule(ALERT_CONTEXT, rules)
    assert len(matched_rule) == 1
    assert matched_rule[0]["rule_id"] == "8e4ff951-9e17-492a-8fd8-c2a0f45b0d36"

    # only one criteria matches - no rule match
    rules = [
        {
            "rule_id": "8e4ff951-9e17-492a-8fd8-c2a0f45b0d36",
            "rule_name": "RDP dev rule",
            "description": "add a Rdp rule",
            "attack_surface_rule_id": "RdpServer",
            "criteria": [
                {"field": "development_environment", "value": "true", "operator": "eq"},
                {"field": "ip", "value": "2.2.2.2", "operator": "eq"},
            ],
            "criteria_conjunction": "AND",
            "action": "email",
            "created_by": "noc@acme.com",
            "created_by_pretty": "First Last",
            "created_at": 1674264241000,
        },
        {
            "rule_id": "36b215c3-a336-40e3-bf13-0b976c72ebb6",
            "rule_name": "SSH Severity Rule",
            "description": "A SshServer Rule",
            "attack_surface_rule_id": "SshServer",
            "criteria": [{"field": "severity", "value": "high", "operator": "eq"}],
            "criteria_conjunction": "AND",
            "action": "servicenow",
            "created_by": "noc@acme.com",
            "created_by_pretty": "First Last",
            "created_at": 1674540567000,
        },
    ]
    matched_rule = match_remediation_rule(ALERT_CONTEXT, rules)
    assert len(matched_rule) == 0

    # empty list of rules
    rules = []
    matched_rule = match_remediation_rule(ALERT_CONTEXT, rules)
    assert len(matched_rule) == 0
