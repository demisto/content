### Partner Contributed Integration - Extended Build

This integration extends the Binalyze AIR Cortex XSOAR integration with operational commands for incident response workflows.

#### Purpose
- Start endpoint isolation and release isolation.
- Start forensic acquisition tasks by built-in or custom acquisition profiles.
- Create, validate, update, list, get, delete, and assign triage rules.
- Create, get, list, query, and close Binalyze AIR cases.
- Query assets/endpoints before taking response actions.
- Poll task status and task assignments for playbook automation.
- List acquisition profiles and repositories.
- Download files from Binalyze AIR InterACT library into the War Room.

#### Setup
1. Create an API token in Binalyze AIR.
2. Create a Cortex XSOAR integration instance.
3. Configure the Binalyze AIR Server URL and API Key.
4. Test the connection before using commands in playbooks.

#### Notes
- The original public Cortex XSOAR integration exposes isolation and acquisition commands.
- This extended build adds operational API coverage commonly required by SOAR playbooks.
- Validate endpoint paths against your deployed Binalyze AIR version before production rollout.