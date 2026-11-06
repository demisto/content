import json
import re
import subprocess
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).with_name("TypeSafeJevMarketplaceAssessment.js")
EXPORTED_FUNCTIONS = (
    "compare",
    "dependencyGroups",
    "determine",
    "inventory",
    "installUpdates",
    "maintenanceOnly",
    "normalizeAnalysis",
    "parse",
    "summarizeNotes",
    "validateChoice",
    "version",
)


def run_javascript(test_body: str, command_mock: str = "function () { throw new Error('Unexpected executeCommand call'); }") -> None:
    """Run a focused unit test against the native JavaScript automation."""
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    source = re.sub(r"\nreturn main\(args\);\s*$", "", source)
    exports = ",".join(f"{name}:{name}" for name in EXPORTED_FUNCTIONS)
    harness = f"""
const assert = require('assert');
const source = {json.dumps(source)};
const factory = new Function(
  'executeCommand',
  'setContext',
  'args',
  source + '\\nreturn {{{exports}}};'
);
const api = factory(
  {command_mock},
  function () {{}},
  {{}}
);
{test_body}
"""
    subprocess.run(
        ["node", "-e", harness],
        check=True,
        capture_output=True,
        text=True,
    )


def test_version_comparison_and_invalid_version() -> None:
    """Version ordering handles releases and prereleases and rejects bad input."""
    run_javascript(
        """
assert.strictEqual(api.compare('1.2.3', '1.2.4'), -1);
assert.strictEqual(api.compare('1.2.3', '1.2.3'), 0);
assert.strictEqual(api.compare('1.2.3', '1.2.3-beta.1'), 1);
assert.throws(function () { api.version('latest'); }, /Unsupported version/);
"""
    )


def test_inventory_keeps_only_enabled_mapped_integrations() -> None:
    """Inventory reports enabled mapped instances and surfaces unmapped brands."""
    run_javascript(
        """
const result = api.inventory({
  configurations: [
    {id: 'definition-1', name: 'Example', display: 'Example Integration', packID: 'ExamplePack'}
  ],
  instances: [
    {id: 'instance-1', name: 'Enabled', brand: 'definition-1', enabled: true},
    {id: 'instance-2', name: 'Disabled', brand: 'definition-1', enabled: false},
    {id: 'instance-3', name: 'Unknown', brand: 'missing-definition', enabled: 'true'}
  ]
});
assert.deepStrictEqual(result.components, [{
  kind: 'integration',
  id: 'instance-1',
  name: 'Enabled',
  brand: 'definition-1',
  display: 'Example Integration',
  pack_id: 'ExamplePack',
  enabled: true
}]);
assert.deepStrictEqual(result.unmapped, ['Unknown']);
"""
    )


@pytest.mark.parametrize(
    ("breaking_notes", "expected_status"),
    [
        ("The Example integration is removed.", "affected"),
        ("The Example integration is removed when using legacy mode.", "unresolved"),
    ],
)
def test_breaking_release_requires_applicability_evidence(breaking_notes: str, expected_status: str) -> None:
    """Conditional breaking changes are held when enablement cannot prove impact."""
    run_javascript(
        f"""
const result = api.determine(
  {{id: 'ExamplePack', name: 'Example Pack', installed_version: '1.0.0', target_version: '2.0.0'}},
  {{version: '2.0.0', notes: 'Release notes', breaking: true, breaking_notes: {json.dumps(breaking_notes)}}},
  [{{id: 'instance-1', pack_id: 'ExamplePack', brand: 'Example', display: 'Example Integration', enabled: true}}]
);
assert.strictEqual(result.status, {json.dumps(expected_status)});
"""
    )


def test_choice_validation_rejects_malformed_probability_distributions() -> None:
    """Only complete normalized Choice answers with valid confidence are accepted."""
    run_javascript(
        """
const valid = api.validateChoice({
  type: 'choice',
  choice: 'affected',
  probabilities: {affected: 0.9, unknown: 0.1},
  confidence: 0.85
}, ['affected', 'unknown']);
assert.strictEqual(valid.choice, 'affected');
assert.strictEqual(valid.probability, 0.9);

assert.strictEqual(api.validateChoice({
  type: 'choice',
  choice: 'affected',
  probabilities: {affected: 0.7, unknown: 0.7},
  confidence: 0.85
}, ['affected', 'unknown']), null);

assert.strictEqual(api.validateChoice({
  type: 'choice',
  choice: 'affected',
  probabilities: {affected: 0.4, unknown: 0.6},
  confidence: 0.85
}, ['affected', 'unknown']), null);
"""
    )


def test_normalize_analysis_preserves_release_and_component_binding() -> None:
    """Jev answers cannot escape the review plan or select an unknown component."""
    run_javascript(
        """
const plan = {model_alias: 'jev-1.13.0', items: [{
  id: 'release_0',
  key: 'pack:2.0.0',
  candidates: [{id: 'instance-1'}]
}]};
const response = {
  model: 'jev-1.13.0',
  answers: {
    release_0: {
      type: 'choice', choice: 'affected', confidence: 0.9,
      probabilities: {affected: 0.9, nonbreaking: 0.04, unaffected: 0.03, unknown: 0.03}
    },
    release_0_component: {
      type: 'choice', choice: 'component_0', confidence: 0.9,
      probabilities: {none: 0.03, unobserved: 0.02, component_0: 0.95}
    }
  }
};
const decisions = api.normalizeAnalysis(plan, response);
assert.strictEqual(decisions.length, 1);
assert.strictEqual(decisions[0].key, 'pack:2.0.0');
assert.strictEqual(decisions[0].status, 'affected');
assert.deepStrictEqual(decisions[0].component_ids, ['instance-1']);

response.answers.unexpected_question = response.answers.release_0;
assert.throws(
  function () { api.normalizeAnalysis(plan, response); },
  /outside this review plan/
);
delete response.answers.unexpected_question;
response.model = 'unexpected-model';
assert.throws(
  function () { api.normalizeAnalysis(plan, response); },
  /Unexpected Jev model version/
);
"""
    )


def test_dependency_groups_keep_cycles_atomic() -> None:
    """Mutually dependent packs are submitted as one installation group."""
    run_javascript(
        """
const candidates = [
  {id: 'A', dependencies: {B: {mandatory: true, minVersion: '1.0.0'}}},
  {id: 'B', dependencies: {A: {mandatory: true, minVersion: '1.0.0'}}},
  {id: 'C', dependencies: {}}
];
const groups = api.dependencyGroups(candidates, {});
const normalized = groups.map(function (group) {
  return group.map(function (item) { return item.id; }).sort().join(',');
}).sort();
assert.deepStrictEqual(normalized, ['A,B', 'C']);
"""
    )


def test_maintenance_override_accepts_only_known_nonbreaking_lines() -> None:
    """The deterministic maintenance override does not accept arbitrary notes."""
    run_javascript(
        """
assert.strictEqual(api.maintenanceOnly({
  publisher_breaking: false,
  release_notes: 'Updated the Docker image to: demisto/python3:3.12.0.',
  breaking_notes: ''
}), true);
assert.strictEqual(api.maintenanceOnly({
  publisher_breaking: false,
  release_notes: 'Changed authentication behavior.',
  breaking_notes: ''
}), false);
"""
    )


def test_release_note_summary_escapes_html_injection() -> None:
    """Untrusted release notes cannot create HTML elements in review cases."""
    run_javascript(
        r"""
const summary = api.summarizeNotes('<scr<script>ipt>alert(1)</script>\n**safe**', 500);
assert.strictEqual(summary.includes('<'), false);
assert.strictEqual(summary.includes('>'), false);
assert.strictEqual(summary.includes('&lt;script&gt;'), true);
assert.strictEqual(summary.includes('safe'), true);
"""
    )


@pytest.mark.parametrize(
    ("error", "observed", "bucket"),
    [
        ("polling timed out for task ID [12345]", "3.3.16", "held"),
        ("polling timed out for task ID [12345]", "3.3.17", "installed"),
        ("installation rejected", "3.3.16", "failed"),
    ],
)
def test_install_reconciles_marketplace_polling_timeout(error: str, observed: str, bucket: str) -> None:
    run_javascript(
        f"""
const stamp = new Date().toISOString();
const snapshot = {{collected_at: stamp, core_instance: 'test', packs: [{{
  id: 'Example', installed_version: '3.3.16', target_version: '3.3.17',
  update_available: true, releases: [{{version: '3.3.17'}}]
}}]}};
const report = {{assessed_at: stamp, core_instance: 'test', analysis_provider: 'TypeSafe Jev',
  ai_decision_count: 1, expected_ai_decision_count: 1,
  findings: [{{pack_id: 'Example', release_version: '3.3.17', status: 'not_flagged', release_notes: 'Maintenance'}}]
}};
const result = api.installUpdates(snapshot, report, 'test', false);
assert.strictEqual(result[{json.dumps(bucket)}].length, 1);
assert.strictEqual(result.installed.length + result.held.length + result.failed.length, 1);
if (result.held.length) assert.match(result.held[0].reason, /12345/);
assert.strictEqual(globalThis.installRequests, 1);
""",
        f"""function (command, args) {{
  let response;
  if (args.uri === '/contentpacks/metadata/installed') {{
    response = [{{id: 'Example', currentVersion: globalThis.installRequests ? {json.dumps(observed)} : '3.3.16'}}];
  }} else if (args.uri === '/contentpacks/marketplace/search/dependencies') {{
    response = {{packs: [{{extras: {{pack: {{id: 'Example', currentVersion: '3.3.17', dependencies: {{}}}}}}}}]}};
  }} else if (args.uri === '/contentpacks/marketplace/install') {{
    globalThis.installRequests = (globalThis.installRequests || 0) + 1;
    return [{{Type: 4, Contents: {json.dumps(error)}}}];
  }} else {{
    throw new Error('Unexpected command: ' + command + ' ' + args.uri);
  }}
  return [{{Type: 1, Contents: {{response: response}}}}];
}}""",
    )
