# Reco

Reco is the leader in SaaS & AI Security — the only approach that secures AI sprawl across SaaS apps and agents. Our platform provides complete visibility and control across your entire SaaS ecosystem, from core applications to the latest AI agents, enabling security teams to keep pace with the speed of AI adoption while maintaining robust security and reducing risk.

The Reco integration for Cortex XSOAR and Cortex XSIAM brings Reco's SaaS & AI intelligence directly into your SOC workflows — surfacing threats, enriching investigations, and automating remediation across the broader Cortex content ecosystem.

## What does this pack do?

- **Govern AI usage** — discover AI agents, AI-powered SaaS apps, and SaaS-to-SaaS OAuth grants with AI capabilities; prevent unauthorized data sharing; maintain audit-ready AI activity records
- **Secure AI agents** — continuously monitor non-human identities operating in SaaS; enforce least-privilege policies; detect agent misuse and anomalous behavior
- **Audit your SaaS posture** — query posture issues, posture checks, and threat detection policies across every connected app; score against SOC 2, ISO 27001, CIS, NIST, PCI DSS, HITRUST, and more
- **Detect and respond to SaaS threats** — fetch behavioral threat alerts with a minimum-severity filter and AI-powered summaries; respond with existing SIEM & SOAR tooling
- **Investigate identities and accounts** — enrich user context, flag risky employees, and track account activity across SaaS apps
- **Manage app risk** — inventory your app portfolio, update authorization status, and track shadow IT
- **Protect sensitive data** — surface files shared publicly, externally, or with private emails; query sensitivity-labeled assets
- **Automate remediation** — tag leaving employees, add risk labels, post comments to alerts, and trigger playbooks

## The SaaS Security Gap

Five types of sprawl are widening the gap between what you can and cannot protect:

- **App Sprawl** — Apps constantly multiply, update, and form SaaS-to-SaaS connections, making it impossible to keep up
- **AI Sprawl** — The infusion of GenAI into SaaS apps, and the surge of AI agents, undermines AI security readiness
- **Identity Sprawl** — Keeping accounts secure while minimizing access privileges is unfeasible with the relentless proliferation of human and machine identities
- **Configuration Sprawl** — The security posture of apps and users is critical yet utterly impractical to continuously update and maintain
- **Data Sprawl** — More entities — including AI agents — access your data through more pathways, making breaches and insider threats harder to spot

## Key Capabilities

### AI Governance

- Gain full visibility into AI tool adoption — from ChatGPT to copilots to embedded AI features
- Prevent unauthorized data sharing and monitor AI usage for policy compliance
- List AI agents with authorization status, risk level, and vendor
- Surface apps and SaaS-to-SaaS grants using AI capabilities

### AI Agent Security

- Discover and continuously monitor AI agents operating within your SaaS environment
- Understand what data agents access, what actions they perform, and where over-permission creates risk
- Enforce least-privilege policies for non-human identities at scale
- Detect AI agent misuse through behavioral threat detection policies

### Posture Management

- Continuously assess security risk across applications, identities, and data
- List posture issues with severity, check status, and compliance framework mappings (SOC 2, ISO 27001, CIS, NIST CSF, NIST 800-53, PCI DSS, HITRUST)
- List posture check definitions and threat detection policies
- Track configuration drift with one-click remediation guidance

### Threat Detection & Response (ITDR)

- Fetch incidents with a minimum-severity filter (e.g., `MEDIUM` fetches medium severity and higher)
- Get full alert details including policy violation evidence
- Add comments to alerts and update incident timelines
- Change alert status and resolve visibility events
- Get AI-generated alert summaries

### Identity & Account Intelligence

- List all SaaS accounts with risk signals (MFA status, admin flag, risky user label)
- Look up user context by email address across all integrated apps
- List identities with aggregated cross-app view
- Tag risky users and departing employees

### SaaS Application Governance

- Discover all apps (sanctioned, shadow, AI-powered) with vendor risk grades
- List app instances (portfolio) from actively integrated apps
- List SaaS-to-SaaS OAuth grants with permission risk scores
- Update app authorization status

### Data Security

- Find sensitive files by name, ID, or sensitivity level
- Query files shared with third-party domains
- Identify files shared publicly or with external emails
- List NetApp files carrying active business-impact labels

### Platform Visibility

- List SaaS events with actor, application, and outcome context
- List groups and IP addresses
- List business units
- Query platform audit logs

## Commands

**Alerts & Incidents**

- `reco-add-comment-to-alert` — Add a comment to a Reco alert
- `reco-update-incident-timeline` — Add a comment to an incident timeline
- `reco-change-alert-status` — Update alert status (NEW / IN_PROGRESS / CLOSED)
- `reco-resolve-visibility-event` — Resolve a visibility event in a Reco Finding
- `reco-get-alert-ai-summary` — Get an AI-generated summary of an alert

**Identities & Users**

- `reco-get-risky-users` — List all accounts flagged as risky
- `reco-add-risky-user-label` — Tag a user as risky
- `reco-add-leaving-org-user-label` — Tag a user as a departing employee
- `reco-get-user-context-by-email-address` — Get identity context for an email address

**SaaS Applications**

- `reco-get-apps` — List discovered apps with risk and AI signals
- `reco-set-app-authorization-status` — Update an app's authorization status

**Posture & Policies**

- `reco-list-posture-issues` — List posture issues with severity and check status
- `reco-list-posture-checks` — List posture check definitions
- `reco-list-threat-detection-policies` — List threat detection policies
- `reco-list-exclusions` — List alert suppression exclusion rules

**Data & Files**

- `reco-get-sensitive-assets-by-name` — Find sensitive assets by name
- `reco-get-sensitive-assets-by-id` — Find sensitive assets by ID
- `reco-get-assets-by-id` — Find any asset by ID
- `reco-get-assets-user-has-access-to` — List files a user has access to
- `reco-get-sensitive-assets-with-public-link` — List publicly exposed sensitive files
- `reco-get-assets-shared-externally` — List files shared outside the organization
- `reco-get-files-exposed-to-email-address` — List files accessible to a specific email
- `reco-get-files-shared-with-3rd-parties` — List files shared with a third-party domain
- `reco-get-3rd-parties-accessible-to-data-list` — List third-party domains with data access
- `reco-get-private-email-list-with-access` — List private emails with file access

**SaaS Events & Activity**

- `reco-list-events` — List SaaS activity events
- `reco-list-accounts` — List SaaS accounts with risk signals
- `reco-list-groups` — List SaaS groups
- `reco-list-saas-to-saas` — List SaaS-to-SaaS OAuth grants
- `reco-list-ip-addresses` — List observed IP addresses
- `reco-list-audit-logs` — List Reco platform audit logs

**AI Governance**

- `reco-list-ai-agents` — List detected AI agents

**Platform**

- `reco-list-app-instances` — List integrated app instances (portfolio)
- `reco-list-devices` — List managed and unmanaged devices
- `reco-list-business-units` — List business units
- `reco-get-link-to-user-overview-page` — Generate a deep link to the Reco UI
- `reco-add-exclusion-filter` — Add a classifier exclusion filter

_For more information: [www.reco.ai](https://www.reco.ai)_

![Reco Overview](doc_files/Reco_image.png)
