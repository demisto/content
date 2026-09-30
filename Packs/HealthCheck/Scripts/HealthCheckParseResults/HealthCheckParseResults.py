import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re
from typing import Any

ActionItem = dict[str, str]


def make_action_item(
    category: str,
    description: str,
    resolution: str,
    severity: str,
) -> ActionItem:
    """Return a validated ActionItem dict."""
    return {
        "category": category,
        "description": description,
        "resolution": resolution,
        "severity": severity,
    }


THRESHOLDS: dict[str, dict[str, Any]] = {
    "AgentPolicyAssignment": {
        "default_policy_keywords": ["default"],
        "max_default_policy_pct": 30,
        "max_small_policy_agents": 3,
        "max_dominant_policy_pct": 90,
        "severity": "Medium",
    },
    "AgentScanStatus": {
        "severity": "Medium",
    },
    "AutoAgentUpgradeStatus": {
        "severity": "Medium",
    },
    "EDRDisabledEndpoints": {
        "min_rows": 1,
        "severity": "Medium",
    },
    "CIEIngestedDomains": {
        "severity": "Medium",
    },
    "CIENonReportingDomains": {
        "severity": "High",
    },
    "HealthIssues": {
        "severity": "Medium",
    },
    "PlaybookFailingTasks": {
        "severity": "High",
    },
    "SourcesFeedingAuthPreset": {
        "severity": "Medium",
    },
    "SourcesFeedingNetworkPreset": {
        "severity": "Medium",
    },
    "SourcesFeedingSaaSAudit": {
        "severity": "Low",
    },
    "CorrelationRulesWithoutAutomation": {
        "severity": "Medium",
    },
    "NoisyIssueCategories": {
        "max_single_category_pct": 50,
        "correlation_category_keyword": "CORRELATION",
        "max_correlation_multiplier": 2,
        "severity": "Medium",
    },
    "NonPreventedIssues": {
        "severity": "High",
    },
}


_PREFIX_RE = re.compile(
    r"^Health\s+Check\s*-\s*[^-]+(?:-[^-]+)?\s*-\s*",
    re.IGNORECASE,
)

_XQL_SUFFIX_RE = re.compile(r"\s*xql_\d+$", re.IGNORECASE)

_TIME_WINDOW_RE = re.compile(r"\s*-\s*\d+d$", re.IGNORECASE)


def _clean_key(raw_key: str) -> str:
    """Strip dashboard prefix, XQL-ID suffix, and time-window suffix."""
    key = _PREFIX_RE.sub("", raw_key)
    key = _XQL_SUFFIX_RE.sub("", key)
    key = _TIME_WINDOW_RE.sub("", key)
    return key.strip()


WIDGET_KEY_MAP: list[tuple[str, str]] = [
    ("Agent Policy Assignment", "AgentPolicyAssignment"),
    ("Agent Scan Status", "AgentScanStatus"),
    ("Auto Agent Upgrade Status", "AutoAgentUpgradeStatus"),
    ("EDR Disabled Endpoints", "EDRDisabledEndpoints"),
    ("CIE - Ingested Domains", "CIEIngestedDomains"),
    ("CIE Non Reporting Domains", "CIENonReportingDomains"),
    ("Health Issues", "HealthIssues"),
    ("Playbook Failing Tasks", "PlaybookFailingTasks"),
    ("Sources Feeding Authentication", "SourcesFeedingAuthPreset"),
    ("Sources Feeding Network", "SourcesFeedingNetworkPreset"),
    ("Sources Feeding SaaS", "SourcesFeedingSaaSAudit"),
    ("Correlation Rules Without Automation", "CorrelationRulesWithoutAutomation"),
    ("Noisy Issue Categories", "NoisyIssueCategories"),
    ("Non-Prevented Issues", "NonPreventedIssues"),
]


def classify_key(raw_key: str) -> str | None:
    """Return the canonical widget name for *raw_key*, or None if unknown."""
    cleaned = _clean_key(raw_key)
    for substring, canonical in WIDGET_KEY_MAP:
        if substring.lower() in cleaned.lower():
            return canonical
    return None


def handle_agent_policy_assignment(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate agent policy assignment thresholds
    action_items: list[ActionItem] = []

    if not rows:
        return action_items

    total_agents: int = sum(r.get("policy_count", 0) for r in rows)
    if total_agents == 0:
        return action_items

    severity: str = cfg.get("severity", "Medium")

    default_keywords: list[str] = [kw.lower() for kw in cfg.get("default_policy_keywords", ["default"])]
    max_default_pct: int = cfg.get("max_default_policy_pct", 30)

    default_agents: int = sum(
        r.get("policy_count", 0)
        for r in rows
        if any(kw in r.get("assigned_prevention_policy", "").lower() for kw in default_keywords)
    )
    default_pct: int = int(default_agents / total_agents * 100)

    if default_pct >= max_default_pct:
        action_items.append(
            make_action_item(
                category="Agent & Asset",
                description=(f"{default_pct}% of endpoints are operating on the Default Policy rather than a targeted policy."),
                resolution=(
                    "Default policies often serve as a catch-all safety net and rarely"
                    " reflect proper environment-specific tuning, review your policy"
                ),
                severity=severity,
            )
        )

    max_small: int = cfg.get("max_small_policy_agents", 3)
    small_policies: list[dict] = [r for r in rows if r.get("policy_count", 0) <= max_small]

    if small_policies:
        action_items.append(
            make_action_item(
                category="Agent & Asset",
                description=f"Found {len(small_policies)} policies with \u2264 {max_small} agents assigned.",
                resolution="Consider auditing policies to reduce maintenance overhead",
                severity=severity,
            )
        )

    max_dominant_pct: int = cfg.get("max_dominant_policy_pct", 90)
    dominant_row: dict = max(rows, key=lambda r: r.get("policy_count", 0))
    dominant_agents: int = dominant_row.get("policy_count", 0)
    dominant_policy: str = dominant_row.get("assigned_prevention_policy", "unknown")
    dominant_pct: int = int(dominant_agents / total_agents * 100)

    if dominant_pct >= max_dominant_pct:
        action_items.append(
            make_action_item(
                category="Agent & Asset",
                description=(
                    f"{dominant_pct}%+ of agents are under one single policy"
                    f' ("{dominant_policy}"), a disproportionately massive percentage'
                    " of your fleet."
                ),
                resolution="Lack of operational segmentation, define more policies",
                severity=severity,
            )
        )

    return action_items


def handle_agent_scan_status(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate agent scan status
    action_items: list[ActionItem] = []
    return action_items


def handle_auto_agent_upgrade_status(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate auto agent upgrade status
    action_items: list[ActionItem] = []
    return action_items


def handle_edr_disabled_endpoints(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate EDR disabled endpoints
    action_items: list[ActionItem] = []
    min_rows = cfg.get("min_rows", 1)
    if len(rows) >= min_rows:
        names = ", ".join(r.get("name", "unknown") for r in rows)
        action_items.append(
            make_action_item(
                category="Agent & Asset",
                description=f"EDR is disabled on {len(rows)} endpoints: {names}",
                resolution="Review the prevention policy assigned to these endpoints and enable EDR protection.",
                severity=cfg.get("severity", "Medium"),
            )
        )
    return action_items


def handle_cie_ingested_domains(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate CIE ingested domains
    action_items: list[ActionItem] = []
    return action_items


def handle_cie_non_reporting_domains(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate CIE non-reporting domains
    action_items: list[ActionItem] = []
    return action_items


def handle_health_issues(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate health issues
    action_items: list[ActionItem] = []
    return action_items


def handle_playbook_failing_tasks(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate playbook failing tasks
    action_items: list[ActionItem] = []
    return action_items


def handle_sources_feeding_auth_preset(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate sources feeding authentication preset
    action_items: list[ActionItem] = []
    return action_items


def handle_sources_feeding_network_preset(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate sources feeding network preset
    action_items: list[ActionItem] = []
    return action_items


def handle_sources_feeding_saas_audit(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate sources feeding SaaS audit
    action_items: list[ActionItem] = []
    return action_items


def handle_correlation_rules_without_automation(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate correlation rules without automation
    action_items: list[ActionItem] = []
    return action_items


def handle_noisy_issue_categories(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate noisy issue categories
    action_items: list[ActionItem] = []

    if not rows:
        return action_items

    total_alerts: int = sum(r.get("Alerts", 0) for r in rows)
    if total_alerts == 0:
        return action_items

    severity: str = cfg.get("severity", "Medium")

    max_single_pct: int = cfg.get("max_single_category_pct", 50)

    for row in rows:
        category: str = row.get("xdm.issue.detection.method", "unknown")
        alerts: int = row.get("Alerts", 0)
        pct: int = int(alerts / total_alerts * 100)
        if pct > max_single_pct:
            action_items.append(
                make_action_item(
                    category="Agent & Asset",
                    description=(
                        f"Category {category} is generating a disproportionately high"
                        " percentage of all system issues, indicating high signal-to-noise"
                        " ratio from that specific detection mechanism."
                    ),
                    resolution=("Create targeted suppression rules or baseline exceptions for known benign behaviors"),
                    severity=severity,
                )
            )

    correlation_keyword: str = cfg.get("correlation_category_keyword", "CORRELATION").lower()
    max_multiplier: float = cfg.get("max_correlation_multiplier", 0.5)

    correlation_alerts: int = sum(
        r.get("Alerts", 0) for r in rows if correlation_keyword in r.get("xdm.issue.detection.method", "").lower()
    )
    non_correlation_alerts: int = sum(
        r.get("Alerts", 0) for r in rows if correlation_keyword not in r.get("xdm.issue.detection.method", "").lower()
    )

    if non_correlation_alerts > 0 and correlation_alerts > max_multiplier * non_correlation_alerts:
        action_items.append(
            make_action_item(
                category="Agent & Asset",
                description=(
                    "The Correlation category issue volume significantly exceeds the"
                    " baseline of non-correlation issues"
                    f" ({correlation_alerts} vs {non_correlation_alerts} alerts,"
                    f" {max_multiplier}x threshold)."
                ),
                resolution=(
                    "Adjust the correlation engine thresholds by tightening the correlation"
                    " time windows and increasing the minimum required distinct alert"
                ),
                severity=severity,
            )
        )

    return action_items


def handle_non_prevented_issues(rows: list[dict], cfg: dict) -> list[ActionItem]:
    # Evaluate non-prevented issues
    action_items: list[ActionItem] = []
    return action_items


WIDGET_HANDLERS: dict = {
    "AgentPolicyAssignment": handle_agent_policy_assignment,
    "AgentScanStatus": handle_agent_scan_status,
    "AutoAgentUpgradeStatus": handle_auto_agent_upgrade_status,
    "EDRDisabledEndpoints": handle_edr_disabled_endpoints,
    "CIEIngestedDomains": handle_cie_ingested_domains,
    "CIENonReportingDomains": handle_cie_non_reporting_domains,
    "HealthIssues": handle_health_issues,
    "PlaybookFailingTasks": handle_playbook_failing_tasks,
    "SourcesFeedingAuthPreset": handle_sources_feeding_auth_preset,
    "SourcesFeedingNetworkPreset": handle_sources_feeding_network_preset,
    "SourcesFeedingSaaSAudit": handle_sources_feeding_saas_audit,
    "CorrelationRulesWithoutAutomation": handle_correlation_rules_without_automation,
    "NoisyIssueCategories": handle_noisy_issue_categories,
    "NonPreventedIssues": handle_non_prevented_issues,
}


def load_context_data() -> dict[str, Any]:
    """Load HealthCheck data from the incident context."""
    ctx = demisto.context()
    health_check = ctx.get("HealthCheck", {})
    if not health_check:
        raise ValueError("HealthCheck key not found in incident context")
    if isinstance(health_check, list):
        if not health_check:
            raise ValueError("HealthCheck list in incident context is empty")
        health_check = health_check[0]
    if not isinstance(health_check, dict):
        raise ValueError(f"HealthCheck in incident context has unexpected type {type(health_check).__name__}")
    return health_check


def parse_collect_results(collect_results: dict) -> list[ActionItem]:
    """Parse collect results and return action items."""
    action_items: list[ActionItem] = []
    seen_canonical: set[str] = set()

    for raw_key, rows in collect_results.items():
        canonical = classify_key(raw_key)
        if canonical is None:
            demisto.debug(f"HealthCheckParseResults: unrecognised widget key '{raw_key}' — skipping")
            continue

        if canonical in seen_canonical:
            demisto.debug(f"HealthCheckParseResults: duplicate canonical '{canonical}' from '{raw_key}' — skipping")
            continue
        seen_canonical.add(canonical)

        handler = WIDGET_HANDLERS.get(canonical)
        if handler is None:
            demisto.debug(f"HealthCheckParseResults: no handler registered for '{canonical}' — skipping")
            continue

        cfg = THRESHOLDS.get(canonical, {})

        if not isinstance(rows, list):
            demisto.debug(f"HealthCheckParseResults: rows for '{canonical}' is not a list — skipping")
            continue

        try:
            items = handler(rows, cfg)
            action_items.extend(items)
        except Exception as exc:  # noqa: BLE001
            demisto.error(f"HealthCheckParseResults: handler for '{canonical}' raised {exc}")

    return action_items


def main() -> None:
    raw_data = load_context_data()

    collect_results: dict[str, list[dict]] = raw_data.get("CollectResults") or {}

    if not collect_results:
        return_warning("HealthCheck.CollectResults is empty — nothing to parse")
        return

    action_items = parse_collect_results(collect_results)

    return_results(
        CommandResults(
            outputs_prefix="HealthCheck",
            outputs_key_field="",
            outputs={"ActionableItems": action_items},
            readable_output=tableToMarkdown(
                "HealthCheck Actionable Items",
                action_items,
                headers=["category", "severity", "description", "resolution"],
            )
            if action_items
            else "No actionable items generated.",
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
