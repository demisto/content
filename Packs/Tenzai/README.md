# Tenzai

Validate **Cortex ASM-discovered exposures** with [Tenzai](https://www.tenzai.com)'s agentic penetration testing — without leaving Cortex.

When an Attack Surface Management (ASM) issue is raised, this pack can trigger a Tenzai agentic validation assessment against the exposed service, poll for completion, and write the verdict (validated / not reproducible), supporting evidence, and a deep-link back into Cortex — enriching the issue so analysts prioritize **demonstrated** risk over theoretical risk.

## Use Cases

- **Validate ASM exposures:** automatically (via an automation rule) or ad-hoc (via a layout button), confirm whether a High/Critical ASM exposure is actually exploitable.

## What's included

- **Tenzai integration** — connectivity and authentication to the Tenzai API, plus the commands that drive a validation assessment (`tenzai-create-scan`, `tenzai-get-scan`, `tenzai-get-scan-result`).
- **Issue fields, a validation playbook, an automation-rule trigger, an ad-hoc "Start Agentic Validation" script, and a custom issue layout + layout rule** that surface the Tenzai verdict and evidence directly on the Cortex ASM issue.

## Coexistence with the Cortex ASM alert playbook

This pack ships a trigger (**Tenzai - Agentic Issue Validation** → the *Tenzai Agentic Issue Validation* playbook) and a layout rule (**Tenzai Layout Rule** → the *Tenzai Issue Layout*). Both match High/Critical `VULNERABILITY`/`CONFIGURATION` exposures in the `DOMAIN_POSTURE` domain whose finding source is `CORTEX_ATTACK_SURFACE_MANAGEMENT`.

The Cortex Attack Surface Management pack ships its own trigger (**ASM** → the *Cortex ASM - ASM Alert* playbook) and layout rule (*ASM Alert Layout*), which match every alert whose `alert_source` is `XPANSE`. The Xpanse-sourced High/Critical exposures Tenzai targets are a **subset** of those ASM alerts, so **both packs' rules match the same alerts** — the filters overlap by design, not by accident.

Cortex applies **one layout rule and one alert-handling playbook per alert**, and neither pack sets a priority field, so you decide which applies:

- **Layout — use the Tenzai Issue Layout for exposures you validate.** It is a superset of the ASM Alert Layout: the same ASM case details plus a **Validate** tab (Start / Re-validate actions and the Tenzai verdict panel). The ASM Alert Layout stays in effect for every other Xpanse alert. If both layout rules are enabled and compete, disable one for the overlapping subset — enable the Tenzai Layout Rule for the High/Critical exposures and let the ASM rule cover the rest.
- **Playbook — prefer the ad-hoc button; it never competes with the ASM playbook.** The **Start Agentic Validation** layout button (and the `!tenzai-*` commands) runs a validation on demand from the issue, so you keep the *Cortex ASM - ASM Alert* playbook as the alert's automation and launch Tenzai only when an analyst wants it. For this reason, leave the **Tenzai - Agentic Issue Validation** trigger disabled unless you deliberately want automatic validation (see below).
- **For automatic validation**, either enable the Tenzai trigger — accepting that the *Tenzai Agentic Issue Validation* playbook then runs instead of *Cortex ASM - ASM Alert* for the High/Critical exposure subset (disable the ASM trigger for that subset to avoid ambiguity) — or embed Tenzai validation **inside** the ASM playbook by adding the `StartAgenticValidation` script (or the `tenzai-*` commands) as a task, so the ASM playbook keeps ownership of the alert and calls Tenzai as one step.

The Tenzai playbook is self-guarding: it first checks that an enabled Tenzai integration instance exists and ends without changing the issue if none is configured, so enabling the trigger on a tenant without a Tenzai instance is a no-op.

## Dependencies

- **Cortex Attack Surface Management** — this pack reads ASM issue/service data (`asm-get-external-service`, ASM issue fields) to build the validation request.

## Requirements for use

- A **Tenzai license** and a **Tenzai partner API key** (generated in the Tenzai application).
- Cortex modules: **XSIAM**, **ASM**.

## Configuration

Configure the **Tenzai** integration instance with your Tenzai **Server URL** and **API Key**. See the integration's documentation for details.
