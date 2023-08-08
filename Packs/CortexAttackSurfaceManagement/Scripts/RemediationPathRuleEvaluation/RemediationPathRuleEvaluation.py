import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Script for evaluating and finding a remediation path rule that matches for
a given alert
"""

import traceback
from typing import Any, Dict, List

# should match IncidentSeverity in CommonServerPython
SEVERITY_MAP = {
    "unknown": 0,
    "info": 0.5,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def match_remediation_rule(alert_context: Dict[str, Any], rules: List) -> List:
    """
    For the given alert (with the field in alert_context), finds the most recently created
    remediation path rule where the alert meets the rule's criteria

    Args:
        alert_context: dictionary of relevant alert fields to check against
        rules: list of remediation path rules to evaluate

    Returns: the matching rule (list of 1)

    """
    matched_rules = []
    # loop through remediation rules
    if isinstance(rules, dict):
        rules = [rules]
    for rule in rules:
        match = True
        conditions = rule["criteria"]
        if len(conditions) == 0:
            demisto.info(
                "Invalid Remediation Path Rule - no criteria condition to evaluate."
            )
            match = False
        else:
            # check criteria conjunction
            if rule.get("criteria_conjunction") == "AND":
                for cond in conditions:
                    rule_matched = evaluate_criteria(cond, alert_context)
                    if not rule_matched:
                        match = False
            else:
                demisto.info(
                    f"Criteria conjunction {rule.get('criteria_conjunction')} not supported at this time."
                )
                match = False

        if match:
            matched_rules.append(rule)

    # sort matched rules by created_at timestamp in descending order
    # return the most recent one
    matched_rules_sorted = sorted(
        matched_rules, key=lambda x: x["created_at"], reverse=True
    )
    if len(matched_rules_sorted) > 0:
        return [matched_rules_sorted[0]]
    else:
        return []


def evaluate_criteria(cond: Dict, alert_context: Dict) -> bool:
    """
    Evaluate whether a criteria condition is met based on the given alert's context fields

    Args:
        cond: Condition to evaluation (dictionary with keys: field, operator, value)
        alert_context: dictionary of relevant alert fields to check against

    Returns: True if the condition is met or False if not

    """
    field = cond["field"]
    operator = cond["operator"]
    value = cond["value"]

    alert_context_value = alert_context.get(field)

    # force lowercase for field and operator and value
    if isinstance(field, str) and isinstance(operator, str) and isinstance(value, str):
        field = field.lower()
        operator = operator.lower()
        value = value.lower()
    else:
        demisto.info("Invalid condition: field, operator or value must be strings")
        return False

    if operator == "eq":
        # severity
        if field == "severity":
            if SEVERITY_MAP.get(value) == alert_context_value:
                return True
            return False
        # boolean fields
        elif (
            field == "development_environment"
            or field == "cloud_managed"
            or field == "service_owner_identified"
        ):
            if value == "true" and (alert_context_value is True or alert_context_value):
                return True
            elif value == "false" and (
                alert_context_value is False or not alert_context_value
            ):
                return True
            return False
        # text match fields
        elif field == "provider":
            # providers can be a string or a list
            if alert_context_value:
                if isinstance(alert_context_value, str):
                    alert_context_value = [alert_context_value]
                providers_set = set(
                    [provider.lower() for provider in alert_context_value]
                )
                if value in providers_set:
                    return True
            return False
        elif isinstance(alert_context_value, str):
            if field == "ip":
                if value == alert_context_value.lower():
                    return True
                return False
            else:
                demisto.info(f"Criteria field {field} not supported at this time.")
                return False
        # list fields
        elif isinstance(alert_context_value, list):
            if field == "tag":
                # build set of tag values to check against
                tags = set()
                for tag in alert_context_value:
                    tags.add(tag.get("value").lower())
                    tags.add(tag.get("key").lower())

                if value in tags:
                    return True
                return False
            else:
                demisto.info(f"Criteria field {field} not supported at this time.")
                return False
        else:
            return False
    else:
        demisto.info(f"Condition Operator {operator} is not supported at this time.")
        return False


""" MAIN FUNCTION """


def main():
    """
    For a given alert and remediation path rules that are defined for that alert's
    attack surface rule, this takes each remediation path rule and looks at the rule
    criteria too see if the rule matches for the given alert. If multiple rules match,
    it will return the most recently created rule.

    This assumes that the rules passed in are filtered to correlate with the alert's
    attack surface rule.

    Args:
        alert_context: dictionary of relevant alert fields we are checking against
        remediation_path_rules: list of remediation path rules for the alert's
            attack surface rule

    Returns:
        asmremediationpathrule: the remediation path rule if there is a match
        Does not populate this alert field if no match is found.

    """
    try:
        # parse args
        args = demisto.args()
        alert_context = {
            "severity": args.get("severity"),
            "ip": args.get("ip"),
            "tag": args.get("tags"),
            "provider": args.get("providers"),
            "development_environment": args.get("development_environment"),
            "cloud_managed": args.get("cloud_managed"),
            "service_owner_identified": args.get("service_owner_identified"),
        }
        rules = args.get("remediation_path_rules")

        matched_rule = match_remediation_rule(alert_context, rules)

        if len(matched_rule) > 0:
            demisto.executeCommand(
                "setAlert", {"asmremediationpathrule": matched_rule[0]}
            )
            return_results(
                CommandResults(readable_output="Remediation path rule match found")
            )
        else:
            return_results(
                CommandResults(
                    readable_output="No matched remediation path rules found"
                )
            )

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute Remediation Path Rule Evaluation. Error: {str(ex)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
