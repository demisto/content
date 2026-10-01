Ad-hoc entry point for Tenzai exposure validation, invoked from the **Start Tenzai Validation** button on the Tenzai issue layout (the **Validate** tab).

On the first click it gathers the exposure context (optionally enriching from the ASM service via `asm-get-external-service`, or parsing the `host:port` from the exposure name), triggers a Tenzai validation assessment with `tenzai-trigger-validation-check`, and sets **Tenzai Assessment Status** to `Running`. It then **drives the whole loop itself**: a self-scheduling `ScheduledCommand` polls `tenzai-fetch-validation-check` until the assessment reaches a terminal status, then writes the verdict — status, exploit validation, assessment details, reproduction, fix guidance, credit usage, and reference URL — back onto the issue. It does not change the issue severity.

Transient fetch failures are retried on the next poll; if the polling window (`MAX_POLLS`) is exhausted without a verdict the status is set to `Error` rather than left on `Running`. A second click while a validation is already `Running` on the issue is a no-op (no duplicate assessment).

When run from the **Tenzai Agentic Issue Validation** playbook, the playbook passes `poll=false`: the script then only triggers and marks the issue `Running`, and the playbook owns the poll + write-back so the loop is not run twice.

## Inputs

| Argument | Description |
| --- | --- |
| service_id | ASM ExternalService id; used to enrich the target when `target` is not provided. |
| target | The exposure target (IP or FQDN). If omitted, derived from the ASM service or parsed from `exposure_name`. |
| exposure_name | Human-readable exposure name (typically the issue name). |
| supporting_data | Free-text context (CVEs, rule, classification). |
| alert_internal_id | The Cortex issue/alert id for result correlation. |
| application_type / port / protocol / service_classification | Optional raw fields forwarded to Tenzai. |
| poll | Whether the script polls to completion and writes the verdict itself. Defaults to `true` (the button); the playbook passes `false`. |

## Outputs

| Path | Description |
| --- | --- |
| Tenzai.ValidationCheck.checkId | The Tenzai validation assessment id. |
| Tenzai.ValidationCheck.status | The assessment status (`Running` while polling; `Complete`/`Error` when terminal). |
| Tenzai.ValidationCheck.validated | Whether the exposure was validated as exploitable (on terminal completion). |
| Tenzai.ValidationCheck.evidence | Markdown assessment details (on terminal completion). |
| Tenzai.ValidationCheck.reproduction | Markdown reproduction steps (on terminal completion). |
| Tenzai.ValidationCheck.guidance | Remediation or mitigation guidance (on terminal completion). |
| Tenzai.ValidationCheck.creditUsage | Approximate Tenzai credit/ACU cost of the assessment (on terminal completion). |
| Tenzai.ValidationCheck.referenceUrl | Deep link to the assessment results in Tenzai (on terminal completion). |
