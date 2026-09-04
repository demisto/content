# Tenzai

Validate **Cortex ASM-discovered exposures** with [Tenzai](https://www.tenzai.com)'s agentic penetration testing — without leaving Cortex.

When an Attack Surface Management (ASM) issue is raised, this pack can trigger a Tenzai agentic validation assessment against the exposed service, poll for completion, and write the verdict (validated / not reproducible), supporting evidence, and a deep-link back into Cortex — enriching the issue so analysts prioritize **demonstrated** risk over theoretical risk.

## Use cases

- **Validate ASM exposures (Milestone 1):** automatically (via an automation rule) or ad-hoc (via a layout button), confirm whether a High/Critical ASM exposure is actually exploitable.

## What's included

- **Tenzai integration** — connectivity and authentication to the Tenzai API, plus the commands that drive a validation assessment.
- *(subsequent releases)* issue fields, a default validation playbook, an automation-rule trigger, an ad-hoc "Start Agentic Validation" script, and a custom issue layout + layout rule.

## Dependencies

- **Cortex Attack Surface Management** — this pack reads ASM issue/service data (`asm-get-external-service`, ASM issue fields) to build the validation request.

## Requirements for use

- A **Tenzai license** and a **Tenzai partner API key** (generated in the Tenzai application).
- Cortex modules: **xsiam**, **asm**.

## Configuration

Configure the **Tenzai** integration instance with your Tenzai **Server URL** and **API Key**. See the integration's documentation for details.
