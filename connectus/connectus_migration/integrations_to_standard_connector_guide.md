# Standard Connector Migration Guide

> **Purpose**: This document briefs an LLM tasked with migrating XSOAR integrations into a **Standard (non-grouped) Connector**. Given a set of integration YMLs (not necessarily from the same pack), scope the migration, identify gaps, flag decisions, and produce the connector YAML files.
>
> **Output**: A complete connector (all YAML files).

---

## Table of Contents

- [Section 1: What is a Standard Connector](#section-1-what-is-a-standard-connector)
- [Section 2: Connector Specification Reference](#section-2-connector-specification-reference)
- [Section 3: Migration Rules and Defaults](#section-3-migration-rules-and-defaults)
- [Appendix A: XSOAR Parameter Type → Manifest Type Mapping](#appendix-a-xsoar-parameter-type--manifest-type-mapping)
- [Appendix B: Authentication Frontend Rendering](#appendix-b-authentication-frontend-rendering)
- [Appendix C: Field ID Uniqueness Rule](#appendix-c-field-id-uniqueness-rule)
- [Appendix I: Server-Style Integrations](#appendix-i-server-style-integrations)
- [Appendix J: Backend-Managed Fields (`config_type: backend`)](#appendix-j-backend-managed-fields-config_type-backend)

---

## Section 1: What is a Standard Connector

A **Standard Connector** is a declarative, YAML-based framework that consolidates one or more of a vendor's integrations into **one** connector. Authentication and shared connection configuration are defined once and shared, allowing multiple modules (XSOAR, SaaS) to contribute integrations for the same vendor.

A Standard connector is **non-grouped**: it does **not** set `settings.grouped`, and it declares **no** `view_groups` registries anywhere. When more than one integration lives under a single connector, **capabilities** (not view_groups) organize them — each integration's features map onto capabilities, and the connection page is a single implicit screen shared by all capabilities.

**The migration model:**

1. All of a vendor's in-scope integrations are consolidated into `connectors/<vendor>/` as ONE Standard connector.
2. Authentication is defined once in `connection.yaml`. **Shared connection parameters** (e.g. the server URL / domain) live in `connection.yaml general_configurations`; **auth secrets** live inside `profiles[].configurations[].fields[]`. Each handler subscribes to the relevant auth method.
3. Capabilities (and, optionally, sub-capabilities) declare what features the connector supports. Multiple integrations are distinguished by the **capabilities** they contribute to.
4. Each legacy integration becomes exactly **one handler** (1:1) under `components/handlers/`. A handler subscribes to all capabilities its integration covers (e.g. commands + fetch).
5. The platform manages authentication (OAuth token lifecycle); Python code uses the new CommonServerPython auth APIs instead of managing tokens directly.

**Benefits:** one connector per vendor, unified auth, consistent UI rendered from a shared spec, platform-managed token lifecycle.

**Note:** ConnectUs is supported only on **Platform Marketplace**.

### Architecture

A Standard connector has **no** `view_groups` registries — neither in `connection.yaml` nor in `configurations.yaml`. Multiple integrations are organized by **capabilities**; the connection page is a single shared screen.

```
CODEOWNERS                      # Required: code owners (repo root)
connectors/<vendor>/
├── connector.yaml              # Required: identity and metadata (no settings.grouped)
├── connection.yaml             # Required: shared connection config (general_configurations) + auth profiles
├── capabilities.yaml           # Required: feature definitions (capabilities; sub-capabilities optional)
├── configurations.yaml         # Optional: per-capability config fields (no view_groups)
├── triggers.yaml               # Optional: conditional field/capability behavior
├── summary.yaml                # Optional: documentation / next steps
├── availability.yaml           # Optional: tenant/region visibility
├── <icon>.{png,jpg,jpeg,svg}   # Optional: icon (max 1)
└── components/handlers/
    └── xsoar_<integration>/
        ├── handler.yaml        # Handler definition
        └── serializer.yaml     # Field name/value mapping (optional)
```

---

## Section 2: Connector Specification Reference

> **Source of truth**: [`README.md`](../README.md) and [`schema/*.schema.json`](../schema/). 
### 2.1 connector.yaml

Defines the connector identity. Schema: [`connector.schema.json`](schema/connector.schema.json).

> **Standard connectors do NOT set `settings.grouped`.** The `grouped` key stays **absent** (it defaults to `false`). Setting `grouped: true` opts into the Grouped model (top-level `view_groups` registries, per-row `view_group` tags), which is **not** used here. Keep only `allow_skip_verification` and `skip_cut_off_check` under `settings`.

### 2.2 connection.yaml

Defines shared connection config and authentication profiles. Schema: [`connection.schema.json`](schema/connection.schema.json).

**Profile types (framework):** See the schema for the types

> **Mass-migration note:** the automated XSOAR mass migration most often emits **`plain`**, **`api_key`**, and **`passthrough`** profiles, but the full framework list — including the `oauth2_*` types — is available and should be used when the vendor's auth is a proper OAuth2 flow (as Salesforce is).

> **VaultMapping shape** ([`VaultMapping`](../schema/connection.schema.json)): each entry has a `id` (stable, unique-within-profile — the platform derives the vault-selector control ids and its display label from it) and a `map` object binding the selected credential's `user`/`password`/`sshkey` onto passthrough auth parameter names (**at least one** of the three must be set). Each mapped name must resolve to a field's `metadata.auth.parameter` (or field id) in the profile's effective scope.

#### 2.2.1 Passthrough Profile

`passthrough` stores an arbitrary, per-connector set of credential fields **without** IDP/token exchange and returns them verbatim to the handler on `getCredentials`. It is the escape hatch for mass migration when a connection cannot be cleanly mapped to a typed profile, or needs several credential inputs simultaneously (e.g. Slack v3's three API keys).

**Data Flow (all profile types):**

1. Backend reads the profile `type` (e.g., `oauth2_client_credentials`).
2. Backend finds fields by their `metadata.auth.parameter` value (e.g., `parameter: "client_key"`).
3. Backend maps user-entered values to the correct auth parameters using the parameter tag, **not** the field ID.
4. For `passthrough` profiles, the backend **skips token exchange entirely** and returns the decrypted user inputs verbatim to the handler on `getCredentials`, keyed by `metadata.auth.parameter`.

**Semantics:**

- **Storage**: each field encrypted on save (same pipeline as typed profiles).
- **Token exchange**: none. The platform never contacts an IDP.
- **`getCredentials`**: returns decrypted inputs verbatim, keyed by `metadata.auth.parameter`. The handler uses them (Basic auth, custom header, mTLS, etc.).
- **Field shape**: 100% YAML-defined; any schema field type allowed; parameter names free-form.
- **Test connection**: implemented entirely by the handler.
- **Refresh/rotation**: none — a handler concern or user re-save.

**Use `passthrough`** when the platform's only job is "store these fields, return them to the handler." **Use a typed profile** (including `oauth2_*`) when the platform should manage the credential lifecycle (token exchange, refresh, expiry).

**Wire contract** (`getCredentials` response):

```json
{
  "profile_id": "passthrough.acme_api",
  "profile_type": "passthrough",
  "parameters": {
    "client_id": "<decrypted value>",
    "client_secret": "<decrypted value>",
    "accept_user_certificate": true
  }
}
```

`parameters` keys come from `metadata.auth.parameter`, not `field.id`. Values preserve type. There is **no PR-time contract enforcement** for `passthrough` — handlers must validate presence/types defensively.

**Security:** secrets are decrypted on every call (no revocable short-lived token) — recommend audit logging. Set `options.mask: true` on every sensitive field. Treat `auth.parameter` names as **immutable** once published (renaming silently breaks stored credentials).

**Example:**

```yaml
profiles:
  - id: "passthrough.acme_api"
    type: "passthrough"
    title: "Acme API Credentials"
    description: "Stores Acme credentials; returned as-is to the handler."
    configurations:
      - fields:
          - id: "acme_client_id"
            title: "Client ID"
            field_type: "input"
            metadata: { auth: { parameter: "client_id" } }
            options:
              mask: false
              create_modifiers: { required: true }
              edit_modifiers: { required: true }
          - id: "acme_client_secret"
            title: "Client Secret"
            field_type: "input"
            metadata: { auth: { parameter: "client_secret" } }
            options:
              mask: true
              create_modifiers: { required: true }
              edit_modifiers: { required: true }
```

Handlers reference it like any other profile: `auth_options: [{ id: "passthrough.acme_api", workloads: ["xsoar-pod", "xsoar-automationhub-runner"] }]`.

#### 2.2.2 Profile Metadata & the `interpolation_mapping`

Profiles may carry an optional, **module-namespaced** `metadata` object (`profiles[].metadata`, keyed by handler module — `xsoar`, etc.) holding profile-scoped **non-secret** runtime context. The platform flattens the matching module's namespace into the connector lifecycle event (same channel as `metadata.event.publish`, §2.17 — **not** get-credentials). The `auth` namespace and secrets are **forbidden** here.

> **Schema constraints** ([`ProfileMetadata`](../schema/connection.schema.json)): the object must have **≥1 property** (`minProperties: 1`), the `auth` key is **forbidden**, and each top-level key must be a **known handler-module name** (matching a handler's `metadata.module` under `components/handlers/`, enforced by OPA xref Check 23). Each module value is a free-form object (strings/numbers/booleans/nested objects) — the list-of-single-key-maps form is rejected.

**`interpolation_mapping` — run unmodified integration code in UCP.** When the mass migration does **not** rewrite integration code, a migrated profile carries `metadata.xsoar.interpolation_mapping`. At runtime the XSOAR runtime injects each credential value into `demisto.params()` at the mapped path, so the legacy code runs unchanged.

**Format.** A single string of comma-separated `<ucp_param>:<xsoar_path>` pairs:

```yaml
metadata:
  xsoar:
    interpolation_mapping: "ucpparamname:xsoar.path.with.names,ucpparamname2:otherfield"
```

- **Left of the colon (`<ucp_param>`)** — the field's `metadata.auth.parameter` value (e.g. `username`, `app_password`). **Only auth fields** (fields carrying `metadata.auth`) appear in the mapping — never `engine`/`engineGroup`/`proxy`/`insecure`.
- **Right of the colon (`<xsoar_path>`)** — a **dotted path** into the legacy `demisto.params()` structure where the runtime injects the value. The path is **free-form** — it must match exactly what the integration code reads.

**Path levels.** The feature supports arbitrarily nested paths; **today expect only 1 or 2 levels**:

- **1 level** (flat params) — e.g. a URL or API key: `api_token:flatclientkey`, `base_url:host`.
- **2 levels** (XSOAR `type: 9` credentials) — the `credentials` param holds an identifier and a password (each renamable), plus optional nested extras: `username:credentials.identifier`, `app_password:credentials.password`, `bitbucket_email:credentials.email`.

**Profile-field vs. mapping (both supported).** A field's value can be supplied **either** through `interpolation_mapping` **or** directly by the profile/field itself. Some fields (e.g. a server URL) are sometimes carried in the profile/shared config rather than the mapping. **The runtime handles both scenarios** — if a UCP param is not listed in `interpolation_mapping`, it is resolved from the profile field directly.

```yaml
profiles:
  - id: "passthrough.credentials"
    type: "passthrough"
    title: "Bitbucket Credentials (Passthrough)"
    metadata:
      xsoar:
        # left = field metadata.auth.parameter; right = demisto.params() dotted path
        interpolation_mapping: "username:credentials.identifier,app_password:credentials.password,bitbucket_email:credentials.metadata.email,api_token:flatclientkey,base_url:credentials.connection.host"
    configurations:
      - fields: [...]   # each auth field's metadata.auth.parameter matches a left-side key above
```

> **Migration default**: emit `metadata.xsoar.interpolation_mapping` on every migrated profile whose integration code reads credentials from `demisto.params()`. Omit it only if the integration code was explicitly adapted to fetch credentials via the UCP get-credentials API.

### 2.3 capabilities.yaml

Defines connector capabilities. Schema: [`capabilities.schema.json`](schema/capabilities.schema.json).

**MANDATORY:** exactly one field with `metadata.connector.parameter: "instance_name"` under `general_configurations` (see §3.4 for the verbatim block).

> **Multi-service capability fields (out of scope for standard mass migration).** For **multi-service connectors** only, `Capability` also accepts `global` (bool), `partial` (bool, mutually exclusive with `global`), `service_ids` (string[]; required when `partial: true`, forbidden when `global: true`), `author_image` (only valid when `global: true`), and `global_message`. Standard mass-migration connectors are single-service and **do not** emit these — see §2.19.

#### 2.3.1 Sub-capabilities are OPTIONAL

`sub_capabilities` is **not** a required key on a `Capability` (schema `required` is `id, title, description, default_enabled, required`). A capability may have **zero** sub-capabilities. Add a sub-capability only when it models a genuinely distinct, separately-toggled feature.


### 2.4 configurations.yaml

Per-capability config fields. Schema: [`configurations.schema.json`](schema/configurations.schema.json).

### 2.5 handler.yaml

How a handler uses the connector. Schema: [`handler.schema.json`](schema/handler.schema.json).

> **`test_connection` is not waived by an auth id.** There is **no** `"none"` profile id — `test_connection` (and `test_connection_metro`) are schema-**required on every handler**, and mass migration always emits them. Anonymous capabilities (below) do not waive `test_connection`; they only change the `capabilities[]` entry shape.

### 2.6 serializer.yaml

Field name/value transforms. Schema: [`serializer.schema.json`](schema/serializer.schema.json). Two optional sections (at least one required):

1. **`field_mappings`** — rename fields and/or transform values (processed first). Each entry: `id` (✅, must match a defined field), `field_name` (rename target), `field_value` (transform function). At least one of `field_name`/`field_value` required.
2. **`computed_fields`** — synthetic output fields (processed second). Each rule has `output` (fields to emit) and `any_of` (condition groups: AND within a group, OR across groups). Condition `type` is `capability` (`{capability_id, value: on|off}`) or `field` (`{field_id, op, value}`). Evaluated against **original** field IDs (before `field_mappings`). This is the mechanism used to emit the **BE fetch flags** for every collection capability (§3.9.1).

### 2.7 triggers.yaml

Conditional field/capability behavior — show/hide, enable/disable, require, lock — driven by field values and/or capability state. Schema: [`triggers.schema.json`](schema/triggers.schema.json). **Optional**; omit or ship `triggers: []` when not needed. Triggers live in a flat root array; each has a recursive `conditions` tree and one or more reversible `effects`.

**Condition node variants** (discriminated **structurally** — there is no `type` field): a **field-condition leaf** is identified by `behavior: value` (scalar fields) or `behavior: values` (collection fields), with a sibling `value:` literal to compare against; a **capability-condition leaf** is identified by `behavior: selected`, with a boolean `value:` (`true`/`false`); a **group** is any object carrying an `operator` (`AND`/`OR`) plus a `children[]` array. Groups may mix field and capability leaves and nest to any depth.

**Operators:** field — `eq, neq, gt, gte, lt, lte, contains, starts_with, is_empty, is_not_empty`; capability — `eq, neq` only. `is_empty`/`is_not_empty` **must omit `value`**.

**Effect:** targets a field or capability by `id` with an `action` (boolean flags `hidden`/`required`/`read_only`/`enabled`, ≥1 present). Effects are **reversible** — the action applies when conditions match and its inverse applies when they don't, restoring the target's prior (snapshotted) state. `effect.message` is allowed on any trigger (use it to explain why a capability requires another capability or field).

### 2.8 summary.yaml

Schema: [`summary.schema.json`](schema/summary.schema.json). Fields: `metadata.title` (✅), `metadata.description` (✅), `metadata.link` (❌, docs URL), `metadata.next_steps` (❌, Markdown).

### 2.9 availability.yaml

Controls visibility per region/tenant **in production only** (dev/staging show all). Schema: [`availability.schema.json`](schema/availability.schema.json). Absent → GA. Present → `tenants` map restricts: region key = valid GCP region; value = array of tenant IDs or `null`; empty/`null` = all tenants in that region; region not listed = not visible there.

### 2.10 Connector Icon

Lives in the connector root, referenced by filename via `metadata.author_image`.


### 2.11 Field Options

Schema: [`field-options.schema.json`](schema/definitions/field-options.schema.json). Highlights:

#### Duration field — integration contract

A `duration` field renders one numeric box per unit and serializes to one value.

```yaml
- id: "incidentFetchInterval"
  title: "Incidents Fetch Interval"
  field_type: "duration"
  options:
    units: ["days", "hours", "minutes"]   # mandatory set & order
    output_format: "minutes"               # mandatory for migration
    default_value: { hours: 1, minutes: 30 }
    create_modifiers: { hidden: false, read_only: false }
    edit_modifiers: { hidden: false, read_only: false }
```

**Rules:** `output_format` MUST be `"minutes"`; `units` MUST be `["days","hours","minutes"]`; `required` is forbidden; per-unit caps are `hours ≤ 23`, `minutes ≤ 59`, `days` uncapped (normalized, no carry-over).

**Converting the legacy default** (XSOAR stores the interval as a minutes string, e.g. `"90"`):
- `days = floor(total/1440)`, `hours = floor((total%1440)/60)`, `minutes = total%60`.
- `"90"` → `{hours:1, minutes:30}`; `"240"` → `{hours:4}`; `"1500"` → `{days:1, hours:1}`.
- Emit only non-zero units.

### 2.12 Dynamic Field Values

`select`/`multi_select` fields can fetch their option list at runtime via `metadata.dynamic_values` (platform-internal; stripped before pub/sub) instead of static `options.values`.

| Property | Req | Description |
|---|---|---|
| `provider` | ✅ | v1 enum: `"xsoar"`. Must match a handler's `metadata.module`. |
| `trigger` | ✅ | Non-empty, unique subset of `"on_create"`, `"on_edit"`. |
| `params` | ✅ | Provider-specific. |

**Provider `xsoar`** requires `params: {integrationID, dynamicField}`. The platform POSTs to XSOAR's `/settings/integration/connector/dynamic-fields/search` and normalizes `{id, name}[]` into `{key, label}`. Typical `dynamicField`: `engine`, `engine-group`, `classifier`, `mapper-incoming`, `mapper-outgoing`, `incident-type`.

```yaml
- id: "xsoar_incoming_mapper"
  title: "Incoming Mapper"
  field_type: "select"
  metadata:
    dynamic_values:
      provider: "xsoar"
      trigger: ["on_create", "on_edit"]
      params: { integrationID: "Salesforce", dynamicField: "mapper-incoming" }
  options:
    placeholder: "Select an incoming mapper"
    default_value: "Salesforce-Incoming-Mapper"   # best-effort literal
    searchable: true
    clearable: true
```

### 2.13 Field Metadata & `event.publish`

A field's `metadata` is a free-form bag, classified for pub/sub forwarding:

| Category | Keys | Behavior |
|---|---|---|
| Platform-internal | `auth`, `connector`, `dynamic_values`, `event` | Stripped — never forwarded. |
| Handler-specific | Handler module names (`xsoar`, `cwp`, …) | Forwarded only to the matching handler. |
| Common enrichment | Everything else | Forwarded to all handlers. |

**`metadata.event.publish: true`** opts a connection-profile field's value into the create/edit lifecycle pub/sub event (and the verify API), so the BE receives non-secret operational values up front without a get-credentials round-trip.

- **Scope**: only valid on `connection.yaml profiles[].configurations[].fields[]`. Forbidden elsewhere (including `connection.yaml general_configurations` fields).
- **Mutually exclusive with `metadata.auth`** — secrets always flow through get-credentials.
- **Shape**: exactly `{ publish: <boolean> }`.

> **Migration rule**: when a connection **profile** carries non-secret operational fields (e.g. region-style params that genuinely belong to a single profile), those SHOULD carry `metadata.event.publish: true`, with **two exceptions**: (1) `engine_mode` (the radio control), and (2) any field carrying `metadata.auth`. **However, for Standard connectors the engine 3-field pattern (`engine_mode`/`engine`/`engineGroup`), `proxy`, and `insecure` are connector-wide and live in `general_configurations` (§3.6), where `metadata.event` is FORBIDDEN — so they are NOT `event.publish`ed.** This supersedes any earlier "publish engine/proxy/insecure" wording: `event.publish` applies to those fields only in the legacy per-profile shape; in the Standard `general_configurations` placement they are not event-published (their values reach handlers via the general-config section of the lifecycle event instead). Likewise the shared server URL/domain typically lives in `general_configurations` (§3.6), where `metadata.event` is **not** permitted — the domain is interpolated into the profile directly instead.

When the platform builds the event for handler **H**, the field's other metadata is classified per the table above (handler-specific keys included only if they match H's module).

---

## Section 3: Migration Rules and Defaults

### 3.1 Assumptions

1. **Handler == integration** (1:1). No two handlers point to the same integration.
2. **Duplicate command names**: a connector CANNOT expose the same command name twice. Raise a flag when seeing such a case, needs to think of a solution.
3. **Platform marketplace only**: if `marketplaces` is absent from the integration YML, it's in the pack's `pack_metadata.json`.
4. **Hidden on platform**: a parameter hidden on `platform` (`hidden: [platform]`, `isfetch:platform: false`, etc.) is excluded from the manifest.
5. **Platform-specific fields**: respect marketplace-specific overrides (`defaultvalue:platform`, `id:xsoar`, `quickaction:platform`, etc.).
6. **Author image**: the PNG in `<pack>/integrations/<integration>/` is the connector icon. If multiple exist, take the first; verify it manually. If none, flag.
7. **Capabilities organize integrations.** In a Standard connector. Sub-capabilities are **optional** (§2.5.1) — add one only when it models a genuinely distinct, separately-toggled feature.
10. **Capability/sub-capability licenses MUST be a subset of the integration's `supportedModules`** (see §3.1.1).

#### 3.1.1 License subsetting

A capability's (or sub-capability's) `config.required_license` must contain only licenses present in the integration's `supportedModules` (or the parent pack's `supported_modules` if the integration omits it). **Rationale**: UCP triggers instance creation, but the XSOAR BE only creates the instance if the tenant's licenses match the integration's `supportedModules`. Declaring an unsupported license causes a silent BE failure that is hard to triage. A **strict subset** is allowed (to narrow the tier); a superset is a migration bug — fail/flag it.

### 3.2 Out of Scope when creating a connector

1. Deprecated, community, or partner integrations.
2. Mirroring (not supported on Platform): `outgoingMapperId`, `defaultMapperOut`.

### 3.3 connector.yaml Rules

**Inputs**: gather the parent packs' `pack_metadata.json` (`relevant_packs_jsons`) and the integration YMLs (`relevant_integrations_ymls`). For licenses, read the integration YML's `supportedModules`; if absent, the parent pack's `supported_modules`; if neither, flag.

| Field | Rule |
|---|---|
| `id` | lowercased, spaces → dashes  |
| `enabled` | `true` (unless intentionally disabling). |
| `metadata.title` | Same name as `id`, Title Case  |
| `metadata.description` | Synthesize from `READMEs` and `pack_metadata.json` . Flag for author to review|
| `metadata.version` | Always `1.0.0` for a new connector. |
| `metadata.categories` | Deduplicated union of packs categories (≥1). |
| `metadata.tags` | Deduplicated union of packs tags. |
| `metadata.publisher` | Always `"Palo Alto Networks"`. |
| `metadata.vendor` | From the integration `provider` field. Flag if providers differ. |
| `metadata.author_image` | Filename in connector root; source from `<pack>/integrations/<integration>/` (take non dark mode if many, flag if none). |
| `metadata.is_recommended` | Optional. Set `true` to highlight the connector in the Data Sources Catalog (as the real Salesforce connector does). Defaults `false`. |
| `metadata.ownership.team` | Always `"xsoar"`. |
| `metadata.ownership.maintainers` | Always `["@xsoar-content"]`. |
| `settings.allow_skip_verification` | `true` unless the vendor requires successful verification before enabling. |

> **Do NOT set `settings.grouped`.** A Standard connector leaves `grouped` absent (defaults `false`). `settings` carries only `allow_skip_verification` and `skip_cut_off_check`.

#### 3.3.1 ID and title naming

`id` is taken from the integration YML commonfields.id and `metadata.title` taken from integration YML display field. 
If you are working on multiple integrations, the LLM will ask author for name, either way the name should be approved by the author.  

**Collision handling** — if the `id` or `title` already exists, append a capability-based suffix to **both** `id` and `title`, and **flag**:

| Capabilities declared | `title` suffix | `id` suffix |
|---|---|---|
| `automation-and-remediation` AND ≥1 collection capability | `Automation and Collection` | `automation-and-collection` |
| Only `automation-and-remediation` | `Automation` | `automation` |
| Only collection capabilities | `Collection` | `collection` |

("Collection" is the umbrella for all fetch capabilities — the suffix never enumerates them.) Example: `Okta` (automation + log-collection) → `okta-automation-and-collection`.


### 3.4 capabilities.yaml Rules

**Sub-capabilities are OPTIONAL** (§2.5.1). Capabilities organize the connector; add a sub-capability only when it models a genuinely distinct, separately-toggled feature (as the real Salesforce connector does with `saas-posture-config-remediation` under `saas-posture-config-monitoring`).

#### Capability mapping


The capability mapping should come from the PRD or from the user/author. 
If they did not give it, then prompt them to do so and suggest the following mapping based off the integration YML.

| XSOAR feature (on platform) | Capability |
|---|---|
| Any command other than fetch | `automation-and-remediation` |
| `isfetchevents: true` | `log-collection` |
| `isfetch: true` | `fetch-issues` |
| `isfetchassets: true` | `fetch-assets-and-vulnerabilities` |
| `isFeed: true` | `threat-intelligence-and-enrichment` |
| `isFetchCredentials: true` | `fetch-secrets` |

**Notes:**

1. **`eventcollector` carve-out** (If Integration name/id contains **`eventcollector`**, case-insensitive):
   - **Default**: contribute to **`log-collection`** only. Do **NOT** contribute to `automation-and-remediation` for its commands.
   - **EXCEPTION** — also contribute to `automation-and-remediation` (so the integration maps to **BOTH** `log-collection` **AND** `automation-and-remediation`) if **either**:
     1. the integration has **≥ 3 commands**, **OR**
     2. the integration has **≥ 1 command whose name does NOT contain `get-events`**.
     (If the only commands are `get-events`-style **and** there are **< 3** of them, it stays `log-collection`-only; otherwise it also gets automation.)
   - When the exception applies, the handler's `capabilities[]` lists **both** the `log-collection` and `automation-and-remediation` entries (handler subscribes to both — §3.8).
   - **`defaultIgnore`**: ALWAYS emitted only on/for the `automation-and-remediation` capability (§3.7). A `log-collection`-only eventcollector integration gets **no** `defaultIgnore`; one that also gets automation **does** (governing its commands).
2. An integration may map to multiple capabilities (e.g. fetch + commands) — emit each.
3. Multiple integrations may share a capability. In a Standard connector they are **not** split into per-integration sub-capabilities by default — they contribute to the same capability. Add a sub-capability only when a genuinely distinct sub-feature warrants it. When two integrations both contribute config fields to the same capability, resolve any field-id collisions via Appendix C.
4. **Flag** (but allow) if two integrations declare the same fetch type, or one integration declares multiple fetch/feed/credential capabilities.
5. When `isFetchEvents`/`isFetchAssets` etc. are set, **omit** the corresponding checkbox param if there is a dedicated capability for that feature — choosing the capability implies the feature is on. Still emit the related fields (interval, classifier, mapper, incidentType, etc.). If there is no dedicated capability for the feature, then the corresponding checkbox must still be kept. 
6. **Fetch mutex (per handler/integration)**: a single integration MUST NOT enable more than one of the five fetch capabilities at once (each handler → exactly one XSOAR instance, which cannot have multiple fetches). Multiple fetches across **different** integrations are fine. The UI prevents the conflict (no error) via [`triggers.yaml`](README.md:833) (§3.5).

#### Metadata & general_configurations

| Field | Rule |
|---|---|
| `metadata.title` | `"Capabilities"`. |
| `metadata.description` | `"Name and configure the instance capabilities"`. Flag for writer review. |
| `metadata.help` | Tech team to generate. |
| `general_configurations.description` | `"General configurations for all capabilities"`. |
| `general_configurations.configurations` | Include the mandatory `instance_name` field (below). |

Mandatory `instance_name` field (verbatim):

```yaml
- fields:
    - id: "instance_name"
      title: "Enter a unique name for this instance"
      field_type: "input"
      metadata:
        connector:
          parameter: "instance_name"
      validations:
        - trigger: "change"
          rules:
            - type: "pattern"
              value: "^[a-zA-Z0-9 _-]+$"
              message: "Only alphanumeric characters, spaces, underscores, and hyphens are allowed."
            - type: "async"
              validation_type: "uniqueness"
      options:
        placeholder: "Enter a unique name for this instance"
        create_modifiers: { required: true, read_only: false, hidden: false }
        edit_modifiers: { required: true, read_only: false, hidden: false }
```

#### Capability rules

| Field | Rule |
|---|---|
| `id` | One of: `automation-and-remediation`, `log-collection`, `fetch-issues`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets` |
| `title` | Title Case of the id ("Automation and Remediation", "Log Collection", "Fetch Issues", "Fetch Assets and Vulnerabilities", "Threat Intelligence and Enrichment", "Fetch Secrets", "Data Security", "Identity Posture", "Security Posture"). |
| `description` | Tech team / PM / writer to author. |
| `default_enabled` | Per product decision  |
| `required` |  Per product decision |
| `config.required_license` | From the integration YML (else parent pack). **Must be a subset of `supportedModules`** — flag any superset. |

### 3.5 triggers.yaml

Optional connector-root file defining reactive, reversible UI behavior. See [`README.md`](README.md:833), [`schema/triggers.schema.json`](schema/triggers.schema.json:1), and [`plans/triggers-v2.md`](plans/triggers-v2.md:1) for the full spec. Common migration patterns:

- **Capability → capability gating** (§3.5.2) — lock one capability until another is enabled (e.g. Salesforce's Data Security requires Identity).
- **Capability → field gating** — reveal/require a field only when a capability is on (e.g. show `feedExpirationInterval` only when `threat-intelligence-and-enrichment` is on AND `feedExpirationPolicy == "interval"`).
- **Field → field gating** — show `longRunningPort` only when `longRunning == true` AND no engine/group is selected AND the integration is engine-excluded.
- **Fetch mutex** (§3.4 note 6) — for an integration contributing more than one fetch capability, author one trigger per *other* fetch capability of that integration: condition = that other capability is `on`; effect = `read_only: true` on the current one with message *"Select only one fetch option"*.

```yaml
triggers:
  - conditions:
      id: log-collection
      behavior: selected
      operator: eq
      value: true
    effects:
      - id: fetch-issues
        action: { read_only: true }
        message: "Select only one fetch option"
  - conditions:
      id: fetch-issues
      behavior: selected
      operator: eq
      value: true
    effects:
      - id: log-collection
        action: { read_only: true }
        message: "Select only one fetch option"
```

#### 3.5.1 Collection capability → auto-enable `automation-and-remediation`

Every fetch type requires the integration's automation. So for **each** collection (fetch) capability the connector contributes (`fetch-issues`, `log-collection`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets`), author a trigger that, when that capability is selected, **auto-enables and locks** `automation-and-remediation`.

- **Condition**: the collection capability is `selected`.
- **Effect**: `{ read_only: true, enabled: true }` on `automation-and-remediation` — `enabled: true` turns it on (selected), `read_only: true` locks it so the user can't clear it while the dependency is active.
- **Message** (verbatim): *"A selected capability enables this setting. Clear the active dependency to disable it"*.

The effect is reversible (§2.10): when no collection capability is selected, the lock and auto-enable are lifted and `automation-and-remediation` returns to its prior state.

```yaml
# triggers.yaml — collection capability auto-enables + locks automation-and-remediation
triggers:
  - conditions:
      operator: OR
      children:
        - id: fetch-issues
          behavior: selected
          operator: eq
          value: true
        - id: log-collection
          behavior: selected
          operator: eq
          value: true
    effects:
      - id: automation-and-remediation
        action: { read_only: true, enabled: true }
        message: "A selected capability enables this setting. Clear the active dependency to disable it"
```

#### 3.5.2 Capability → capability gating (Standard pattern)

A capability can depend on another capability. The real Salesforce Standard connector gates **Data Security on Identity**: when Identity is NOT selected, Data Security is locked (`read_only: true`) and unchecked (`enabled: false`) so it stays **visible** but cannot be enabled on its own, with a message explaining why. Identity provides the user/group/role context that Data Security scanning relies on. When Identity is selected, the lock releases; Data Security stays UNCHECKED (the user must choose it — selecting Identity does not auto-enable Data Security).

```yaml
# triggers.yaml — Data Security depends on Identity
triggers:
  - conditions:
      id: identity
      behavior: selected
      operator: eq
      value: false
    effects:
      - id: data-security
        action:
          read_only: true
          enabled: false
        message: "Data Security requires the Identity capability to be enabled. Select Identity first to enable Data Security."
```

### 3.6 connection.yaml Rules

| Field | Rule |
|---|---|
| `metadata.title` | Usually `"Connection"` (the real Salesforce connector uses this). Otherwise take the `auth_details.auth_types.name` and convert to Title Case. |
| `metadata.description` | `"Enter the credentials to securely authorize the connection"`. Flag for writer review. |
| `metadata.help` | Long Markdown: extract connection methods from the integration description.md + READMEs (auth only — no commands/IO), combined with vendor knowledge. Flag for writer review. |


#### XSOAR type-9 credential leaf semantics

A `type: 9` credential renders as two leaves — an identifier (`<id>.identifier`) and a password (`<id>.password`). The following YML fields control leaf suppression and labeling:

- **`hiddenusername: true`** — the identifier leaf is suppressed. Do NOT include `<id>.identifier` as a key in `xsoar_param_map`. The `<id>.password` leaf, if not also hidden, MAY still appear.
- **`hiddenpassword: true`** — the password leaf is suppressed. Do NOT include `<id>.password` as a key in `xsoar_param_map`. The `<id>.identifier` leaf, if not also hidden, MAY still appear. (`hiddenpassword` is a real YML field per demisto-sdk's strict-objects schema.)
- **`displaypassword: "<custom label>"`** — overrides the **display name** of the password component of the `type: 9` credential. It does NOT change the underlying leaf id (`<id>.password`); it only changes the UI label. Common use: renaming "Password" to "API Key" / "Token" / "Secret Key" in the form.

#### Shared connection params live in `general_configurations`; secrets live in the profile

**Standard connectors USE `connection.yaml general_configurations`.** Shared, **non-secret** connection parameters — the server URL/domain and (when applicable) other params shown for all profiles — are declared **once** in `general_configurations.configurations[].fields[]`. **Auth secrets** (`client_key`, `client_secret`, `username`, `password`, `api_key`, type-9 credential leaves, etc.) live inside `profiles[].configurations[].fields[]`, keyed by `metadata.auth.parameter`.

> **`options.mask` is mandatory on EVERY `connection.yaml` field** (§2.2) — both `general_configurations` fields and `profiles[].configurations[]` fields. Set `mask: true` for secrets, `mask: false` for non-secret fields (`domain`, `engine`, `proxy`, `insecure`, etc.). Omitting `mask` on a connection field fails schema validation ([`ConnectionFieldGroup`](../schema/connection.schema.json)).

This mirrors the real Salesforce connector exactly:

- **`domain`** (the server URL) is a **`general_configurations`** field. It carries a `behavior: { type: "apply", label: "Apply" }` (so the user clicks **Apply** to lock the domain), `validations`, and `options` (mask, placeholder, help_text, create/edit modifiers). It does **not** carry `metadata.event` — that key is forbidden on `general_configurations` fields.
- Each **profile** interpolates the shared `domain` where it needs it, e.g. `discovery_url: "https://{{domain}}/.well-known/openid-configuration"`.
- Each **profile** carries only its own **secrets** under `profiles[].configurations[].fields[]` (e.g. `client_key`, `client_secret`), each tagged with `metadata.auth.parameter`.

```yaml
# connection.yaml — shared domain in general_configurations; secrets in the profile
general_configurations:
  description: "General configurations"
  configurations:
    - fields:
        - id: "domain"
          title: "Domain URL"
          field_type: "input"
          behavior:
            type: "apply"
            label: "Apply"
          validations:
            - trigger: "change"
              rules:
                - type: "pattern"
                  value: "^\\S+(\\s+\\S+)*$"
                  message: "Domain URL must not contain leading or trailing whitespace"
          options:
            mask: false
            placeholder: "https://<my_domain>"
            help_text: "Copy the URL from your browser's address bar while logged in."
            create_modifiers: { required: true, hidden: false }
            edit_modifiers: { required: true, hidden: false, read_only: true }

profiles:
  - id: "oauth2_client_credentials.example"
    type: "oauth2_client_credentials"
    title: "OAuth 2.0 Client Credentials Flow"
    discovery_url: "https://{{domain}}/.well-known/openid-configuration"
    configurations:
      - fields:
          - id: "client_key"
            title: "Consumer Key (Client ID)"
            field_type: "input"
            metadata: { auth: { parameter: "client_key" } }
            options:
              mask: false
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: false }
          - id: "client_secret"
            title: "Consumer Secret"
            field_type: "input"
            metadata: { auth: { parameter: "client_secret" } }
            options:
              mask: true
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: false }
```

> **`metadata.event.publish`** applies only to **profile** fields (§2.17). Shared `general_configurations` fields cannot carry `metadata.event`; the shared domain is made available to handlers via profile interpolation instead.

#### Connection params with NO credentials (url/proxy only, no secrets)

Some integrations need a connection screen to collect **non-secret** connection params — a server URL/domain, `proxy`, `insecure`, and/or the engine fields — but have **no actual credential**. Model it as follows:

1. **Put shared non-secret params in `general_configurations`** where they are shared across profiles (e.g. the server URL/domain).
2. **Profile type: `passthrough`.** With no secret to manage, neither `plain` nor `api_key` fits. Use `passthrough` (§2.6.1) — here it stores only non-secret connection params and the platform performs no token exchange.
3. **No `metadata.auth` fields.** Every field is a non-secret connection param. None carry `metadata.auth.parameter`. Consequently the `getCredentials` `parameters` object (§2.6.1) is **empty**.
4. **`metadata.event.publish: true` on any remaining per-profile non-secret fields** (except `engine_mode`, per §2.13). Note the engine 3-field pattern, `proxy`, and `insecure` are connector-wide and live in `general_configurations` (§3.6), where `metadata.event` is forbidden — they are NOT event-published. Shared `general_configurations` fields are made available via interpolation / the general-config section of the lifecycle event instead.
5. **`interpolation_mapping` is empty / omitted.** Per §2.6.2 the mapping covers **only** auth fields. With no auth fields, there is nothing to map.
6. **`test_connection` is still required** (§2.8 — only `auth_options[].id: "none"` waives it, which mass migration does not emit). For a `passthrough` profile the handler implements the test connection itself (§2.6.1).

> **FLAG IT.** This "connection params but no credentials" shape is **not** a first-class, separately-documented pattern — it is assembled from the `general_configurations` + `passthrough` + `event.publish` building blocks above. It is also distinct from the §6 open item *"skip the connection screen for integrations that have no auth/connection"* (that covers integrations with **no** connection at all; here a connection screen is still needed). Surface it in **Gap Analysis / Decisions Needed** (§5.2) so the reviewer confirms the chosen modeling.

#### Profiles

1. For each profile, follow §2.2 and the auth-parameter tagging in §2.6. The LLM should look at the profiles and the integrations, and see where we can re-use the same profile for multiple integrations/handlers. This will reduce the number of profiles users will need to configure. 
This should be best effort, and a deep analysis of the code and integration YAML if its possible. You should bring up to user/author if the LLM has suggestions to make the connector better with regards to this. 
2. **Use the profile type that matches the vendor's auth.** `oauth2_client_credentials` / `oauth2_authorization_code` / other `oauth2_*` for OAuth flows (as the real Salesforce connector does); `plain` for user/password; `api_key` for a single API-key secret; `passthrough` (§2.6.1) when credentials can't be cleanly mapped to a typed profile or need several inputs at once (e.g. Slack v3).
3. **`engine`/`engineGroup`/`proxy`/`insecure` are connector-wide — declare them ONCE in `general_configurations`, NOT per-profile.** In a Standard connector these non-secret operational fields are connector-wide, not per-profile, so they are declared **once** at the connector level in `connection.yaml general_configurations.configurations[]` (each field group gated to the relevant capability via `required_for_capabilities`), instead of being repeated inside each profile. See **"Connector-wide connection fields via `general_configurations` + `required_for_capabilities`"** below for the canonical shape. `proxy` & `insecure` are only emitted if the integration YML defines them. 
4. **One profile per handler — OR, never AND.** A handler binds to a single profile at runtime. Multiple auth methods → separate profiles advertised as alternatives in `auth_options[]` (user picks one). If an integration needs several inputs simultaneously, model it as one `passthrough` profile. A single profile MAY be shared by multiple handlers when they use the same auth.
5. **`metadata.xsoar.interpolation_mapping`** on every migrated profile whose integration code reads credentials from `demisto.params()` (§2.6.2). Map each auth field's `metadata.auth.parameter` to its `demisto.params()` dotted path (`"<ucp_param>:<xsoar_path>,..."`). This should be last case scenario. the Ideal should be that the integration uses UCP correctly and not read credentials from demisto.params and use interpolation. 

#### Connector-wide connection fields via `general_configurations` + `required_for_capabilities`

**Standard-connector rule (supersedes any conflicting general-mode instruction).** The engine 3-field pattern (`engine_mode`, `engine`, `engineGroup`), `insecure`, and `proxy` are **non-secret, connector-wide** connection fields. In a Standard connector they are declared **once** at the connector level in [`connection.yaml`](../schema/connection.schema.json) `general_configurations.configurations[]` — **NOT** repeated inside each profile. Auth **secrets** continue to live in `profiles[].configurations[].fields[]`, keyed by `metadata.auth.parameter`.

**What moves to `general_configurations`.**

- The **engine 3-field pattern** (`engine_mode` radio + `engine` select + `engineGroup` select) — as **one** field group.
- **`insecure`** (checkbox) — as its **own** field group.
- **`proxy`** (checkbox) — as its **own** field group.

These are per-connector, not per-profile: a handler still binds to exactly one profile for its **secrets**, but the engine/proxy/insecure choices are shared connection settings surfaced once for the whole connector.

**`required_for_capabilities` gating.** Each `general_configurations.configurations[]` field group carries a `required_for_capabilities: ["<capability-id>", ...]` list so the FE knows which capabilities to render these fields for when showing general configurations. `required_for_capabilities` is a valid key on a `general_configurations` FieldGroup — it is defined on the `FieldGroup` `$def` in [`field.schema.json`](../schema/definitions/field.schema.json) ("Only valid on FieldGroup rows inside `general_configurations` sections… When present, the platform shows this field group only when at least one of the listed capabilities/sub-capabilities is enabled") and referenced by `general_configurations` in [`connection.schema.json`](../schema/connection.schema.json). Each field group is its **own** entry in `configurations[]` — the engine group, `insecure`, and `proxy` are **three separate field groups**, each with its own `required_for_capabilities`.

**No `metadata.event` on these fields.** `general_configurations` FieldGroups **cannot** carry `metadata.event` — the schema explicitly forbids it ("metadata.event is only valid on fields inside `profiles[].configurations[].fields[]` — not on `connection.yaml general_configurations` fields", [`connection.schema.json`](../schema/connection.schema.json) `GeneralConfigurations`). So when engine/proxy/insecure live in `general_configurations` (the Standard rule), they are **NOT** `event.publish`ed. This changes the earlier "publish engine/proxy/insecure" guidance (§2.13): that rule applied only while these fields lived inside a profile. In `general_configurations` they are not event-published; their values reach handlers via the connector lifecycle event for the general-config section instead.

**`proxy` ships locked by default.** `proxy` carries `read_only: true` in **both** `create_modifiers` and `edit_modifiers` — i.e. it is locked (default-off) until an engine or engine group is selected, at which point it is unlocked via a reversible [`triggers.yaml`](../schema/triggers.schema.json) effect (see "Proxy field — conditional read-only" below in this §3.6 section). Keep the existing proxy trigger guidance consistent: the trigger UNLOCKS `proxy` when an engine/engine group is chosen; the locked state is the default that applies when `engine_mode == "no_engine"`.

**`options.mask` is still mandatory** on every field (`general_configurations` included) — `mask: false` for these non-secret fields. `engine`/`engineGroup` remain `select` + `dynamic_values` with `metadata.xsoar.config_type: "backend"`, `empty_values_message`, `searchable`/`clearable`; `engine_mode` is a horizontal `radio`.

**Canonical example** (mirrors the real [`connectors/googleworkspace/connection.yaml`](../../../unified-connectors-content/connectors/googleworkspace/connection.yaml) `general_configurations.configurations[]`, whose engine `dynamic_values.params.integrationID` is `"GoogleDrive"`) — three separate field groups, each gated to `automation-and-remediation`:

```yaml
    - required_for_capabilities:
        - "automation-and-remediation"
      fields:
        - id: "engine_mode"
          title: "Engine"
          field_type: "radio"
          options:
            mask: false
            orientation: horizontal
            default_value: no_engine
            values:
              - key: no_engine
                label: "No engine"
              - key: engine
                label: "Engine"
              - key: engineGroup
                label: "Engine Group"
            create_modifiers:
              required: true
              hidden: false
            edit_modifiers:
              required: true
              hidden: false
        - id: "engine"
          title: "Engine"
          field_type: "select"
          metadata:
            xsoar:
              config_type: "backend"
            dynamic_values:
              provider: "xsoar"
              trigger: ["on_create", "on_edit"]
              params:
                integrationID: "GoogleDrive"
                dynamicField: "engine"
          options:
            mask: false
            empty_values_message: "No engines available"
            searchable: true
            clearable: true
            create_modifiers:
              required: false
              hidden: false
            edit_modifiers:
              required: false
              hidden: false
        - id: "engineGroup"
          title: "Engine Group"
          field_type: "select"
          metadata:
            xsoar:
              config_type: "backend"
            dynamic_values:
              provider: "xsoar"
              trigger: ["on_create", "on_edit"]
              params:
                integrationID: "GoogleDrive"
                dynamicField: "engine-group"
          options:
            mask: false
            empty_values_message: "No engine groups available"
            searchable: true
            clearable: true
            create_modifiers:
              required: false
              hidden: false
            edit_modifiers:
              required: false
              hidden: false
    - required_for_capabilities:
        - "automation-and-remediation"
      fields:
        - id: "insecure"
          title: "Trust any certificate (not secure)"
          field_type: "checkbox"
          options:
             mask: false
             default_value: false
             create_modifiers:
               required: false
               hidden: false
             edit_modifiers:
               required: false
               hidden: false
    - required_for_capabilities:
        - "automation-and-remediation"
      fields:
        - id: "proxy"
          title: "Use system proxy settings"
          field_type: "checkbox"
          options:
             mask: false
             default_value: false
             create_modifiers:
               required: false
               hidden: false
               read_only: true
             edit_modifiers:
               required: false
               hidden: false
               read_only: true
```

##### Engine handling — 3-field pattern

Replaces legacy `engine`/`engineGroup`. **For Standard connectors the three engine fields live ONCE in [`connection.yaml`](../schema/connection.schema.json) `general_configurations.configurations[]`** as a single field group gated via `required_for_capabilities` (the canonical block is the "Canonical example" above) — **NOT** repeated inside each profile. **Shape, IDs, options, and visibility are locked.** Because they live in `general_configurations`, these fields do **NOT** carry `metadata.event` (the schema forbids `metadata.event` on general-config fields — see §2.13 / §3.6).

| ID | Type | Default | `event.publish` | `config_type` |
|---|---|---|---|---|
| `engine_mode` | `radio` (horizontal) | `no_engine` | ❌ (general-config field — `metadata.event` forbidden) | — |
| `engine` | `select` + `dynamic_values` (`dynamicField: engine`) | — | ❌ (general-config field — `metadata.event` forbidden) | `backend` |
| `engineGroup` | `select` + `dynamic_values` (`dynamicField: engine-group`) | — | ❌ (general-config field — `metadata.event` forbidden) | `backend` |

`engine_mode` options: `no_engine` ("No engine"), `engine` ("Engine"), `engineGroup` ("Engine Group").

**Mandatory** empty-state messages: `engine` → `empty_values_message: "No engines available"`; `engineGroup` → `"No engine groups available"`.

**Visibility** via `triggers.yaml`: hide `engine` when `engine_mode != "engine"`; hide `engineGroup` when `engine_mode != "engineGroup"`.

```yaml
# connection.yaml — inside general_configurations.configurations[] as ONE field group.
# NOTE: general-config fields, so options.mask is MANDATORY on each (§2.2) AND
# metadata.event is FORBIDDEN here (general-config constraint — §2.13/§3.6).
- required_for_capabilities: ["automation-and-remediation"]
  fields:
    - id: engine_mode
      field_type: radio          # horizontal radio group — NOT a select dropdown
      title: Engine
      options:
        mask: false              # mandatory on every connection.yaml field
        orientation: horizontal  # render the radio options in a single horizontal row
        default_value: no_engine
        values:
          - { key: no_engine, label: "No engine" }
          - { key: engine, label: "Engine" }
          - { key: engineGroup, label: "Engine Group" }
        # "required" is NOT a FieldOptions key — express it via create_modifiers/edit_modifiers
        create_modifiers: { required: true, hidden: false }
        edit_modifiers: { required: true, hidden: false }
    - id: engine
      field_type: select
      title: Engine
      metadata:
        # NO event.publish here — metadata.event is forbidden on general_configurations fields
        xsoar: { config_type: backend }
        dynamic_values:
          provider: xsoar
          trigger: [on_create, on_edit]
          params: { integrationID: "<integration-id>", dynamicField: engine }
      options:
        mask: false              # mandatory on every connection.yaml field
        empty_values_message: "No engines available"
        searchable: true
        clearable: true
    - id: engineGroup
      field_type: select
      title: Engine Group
      metadata:
        # NO event.publish here — metadata.event is forbidden on general_configurations fields
        xsoar: { config_type: backend }
        dynamic_values:
          provider: xsoar
          trigger: [on_create, on_edit]
          params: { integrationID: "<integration-id>", dynamicField: engine-group }
      options:
        mask: false              # mandatory on every connection.yaml field
        empty_values_message: "No engine groups available"
        searchable: true
        clearable: true
```

```yaml
# triggers.yaml — visibility
triggers:
  - conditions: { id: engine_mode, behavior: value, operator: neq, value: engine }
    effects: [{ id: engine, action: { hidden: true } }]
  - conditions: { id: engine_mode, behavior: value, operator: neq, value: engineGroup }
    effects: [{ id: engineGroup, action: { hidden: true } }]
```

##### Proxy field — conditional read-only

The `proxy` field (a `checkbox`) lives **in `general_configurations.configurations[]` as its own field group** (gated via `required_for_capabilities`), NOT inside a profile. Its title is **"Use system proxy settings"**. Proxy routing is only meaningful when traffic flows through an engine or engine group, so:

- **`proxy` ships `read_only: true` in BOTH `create_modifiers` and `edit_modifiers`** — locked (default-off) while `engine_mode == "no_engine"` (i.e. no engine and no engine group is chosen).
- **Once the user selects an engine OR an engine group** (`engine_mode == "engine"` OR `engine_mode == "engineGroup"`), `proxy` is unlocked so the user can check it.
- A tooltip explains the lock: **"Use system proxy settings is enabled only when an engine or engine group are chosen."**
- proxy is only emitted if the integration YML has this field defined

The lock is enforced via a reversible [`triggers.yaml`](../schema/triggers.schema.json) effect: the default `read_only: true` (shipped in both modifiers) is automatically reversed to `read_only: false` when an engine/engine group is selected.

| ID | Type | Title | Default | `read_only` (default) | `event.publish` | `config_type` |
|---|---|---|---|---|---|---|
| `proxy` | `checkbox` | "Use system proxy settings" | `false` | `true` (both modifiers; unlocked by trigger) | ❌ (general-config field — `metadata.event` forbidden) | — (not backend-managed; see Appendix J) |

```yaml
# connection.yaml — inside general_configurations.configurations[] as its own field group.
# NO metadata.event (forbidden on general-config fields). proxy ships read_only: true
# in BOTH modifiers (locked by default; unlocked via triggers.yaml once an engine/engine group is chosen).
- required_for_capabilities: ["automation-and-remediation"]
  fields:
    - id: proxy
      field_type: checkbox
      title: "Use system proxy settings"
      options:
        mask: false
        default_value: false
        create_modifiers: { required: false, hidden: false, read_only: true }
        edit_modifiers: { required: false, hidden: false, read_only: true }
```

```yaml
# triggers.yaml — lock proxy until an engine or engine group is chosen
# The effect is reversible (§2.10): this trigger UNLOCKS proxy (read_only: false)
# when an engine OR engine group is selected. The described default-locked state
# (read_only while engine_mode == "no_engine") is the REVERSED/default state that
# applies automatically when neither engine nor engineGroup is chosen — no separate
# lock trigger is needed.
- conditions:
    operator: OR
    children:
      - id: engine
        behavior: value
        operator: is_not_empty
      - id: engineGroup
        behavior: value
        operator: is_not_empty
  effects:
    - id: proxy
      action:
        read_only: false
```

> The trigger is reversible (§2.10): when `engine_mode` changes away from `no_engine` (to `engine` or `engineGroup`), the `read_only` lock is lifted and the user can toggle `proxy`.

##### Insecure field — always editable

The `insecure` field (a `checkbox`) also lives **in `general_configurations.configurations[]` as its own field group** (gated via `required_for_capabilities`), NOT inside a profile. Its title is **"Trust any certificate (not secure)"**, it defaults to **off** (`false`), and — unlike `proxy` — it is **always editable** (`read_only: false` at all times, no engine gating, no trigger).
- `insecure` is only emitted if the integration YML has this field defined

| ID | Type | Title | Default | `read_only` | `event.publish` | `config_type` |
|---|---|---|---|---|---|---|
| `insecure` | `checkbox` | "Trust any certificate (not secure)" | `false` | always `false` | ❌ (general-config field — `metadata.event` forbidden) | — (not backend-managed; see Appendix J) |

```yaml
# connection.yaml — inside general_configurations.configurations[] as its own field group.
# NO metadata.event (forbidden on general-config fields).
- required_for_capabilities: ["automation-and-remediation"]
  fields:
    - id: insecure
      field_type: checkbox
      title: "Trust any certificate (not secure)"
      options:
        mask: false
        default_value: false
        create_modifiers: { required: false, read_only: false, hidden: false }
        edit_modifiers: { required: false, read_only: false, hidden: false }
```

**Carve-outs:** for **engine/proxy-excluded** integrations (long-running servers/listeners and platform-native handlers), emit none of the engine fields and no `proxy`. For **single-engine** integrations (which maintain stateful connections that must not be load-balanced), emit `engine_mode` (2 options: `no_engine` + `engine`) and `engine` only; omit `engineGroup` (the proxy read-only rule still applies, gated on `engine_mode == "no_engine"`).

### 3.7 configurations.yaml Rules

| Field | Rule |
|---|---|
| `metadata.title` | `"Configuration"`. |
| `metadata.description` | `"Adjust and refine your configuration settings"`. Flag for writer review. |

#### Principles

1. **All params in manifest** — every field that is not connection related.
2. Fields should be one per row, unless the LLM suggests otherwise as they are small UI components and we can group them in the same row. 
3. **Preserve field behavior** — type, default, options, title, id, tooltip, required must match the YML exactly (unless stated otherwise).
4. **`defaultIgnore`** lives under the **`automation-and-remediation` capability's** `configurations[]` (a `checkbox`, `config_type: backend`) — **with no `view_group`**. It controls "Do not use in CLI by default" for **commands**, which collection-only capabilities (`fetch-issues`, `log-collection`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets`) do not have. Omit `defaultIgnore` when there is no automation capability.
   - Collisions when >1 integration contributes (for either field's id) are resolved via Appendix C.
5. **`longRunning`** is supported.

#### NULL vs empty-string

In ConnectUs, fields that are left unfilled or hidden are sent to the BE as **NULL** (unless the field declares a `default_value`). This differs from legacy XSOAR, where unfilled fields were sometimes sent as empty strings (`""`).

- Fields that are **backend-managed** (`config_type: backend`, e.g. `engine` — see Appendix J) are managed by the XSOAR BE, which sets an appropriate default value.
- For **non-backend** fields, the integration code must be prepared to handle **NULL** values (not empty strings) for any parameter left unset and that has no `default_value`.

#### configurations

1. Each capability (or sub-capability, when used) has its own configurations, mirroring the underlying integration. Each `configurations[]` entry's `id` is a **capability id** (or a sub-capability id when a sub-capability is used) — **no `view_group`**.
2. Config IDs must be globally unique across the connector (Appendix C).
3. **Config params live under the capability they belong to.** For the real Salesforce connector, the automation config lives under `automation-and-remediation`, and the posture config (`sync_interval`, `application_tag`) lives under `saas-posture-config-monitoring`.
4. A capability with **no** config params simply has no `configurations[]` entry (there is no view_group binding to maintain). Only emit an entry when the capability contributes fields.
5. There are scenarios where multiple integrations have the same field (sometimes with not exactly the same ID/name) which can be used with the same value from the user. The LLM will look at the params that seem the same, and if they can get the same value from user, the LLM will suggest to the author to only define the param once and then will be used in both integrations. This reduces params in UI which makes easier for user to onboard, and also reduces the number of params in the manifest. Bring it up to user/author for approval. 

#### Type mapping

See [Appendix A](#appendix-a-xsoar-parameter-type--manifest-type-mapping).

#### Field rules

1. **`id`** = parameter `name` from the YML. Globally unique (Appendix C) — keep the original name; rename only on a real collision.
2. **Title** = `display` from the YML; replace "Incidents" → "Issues" (Platform terminology).
3. **Type** — per Appendix A.
4. **Default** = `defaultvalue` (use platform-specific override if present).
5. **Required** = `required`.
6. **Description** = `additionalinfo` → `options.description`/`help_text`.
7. **Select options** — YML `options` → `{key, label}` pairs.
8. **Exclude** hidden-on-platform params, and auth-related params (type-9 credentials, domain/URL auth fields — the shared domain lives in `connection.yaml general_configurations`, §3.6). For engine/proxy-excluded integrations (long-running servers/listeners and platform-native handlers), also omit `proxy`/`engine`/`engineGroup` entirely; for all others, the engine 3-field pattern, `proxy`, and `insecure` live in `connection.yaml general_configurations` (§3.6, connector-wide with `required_for_capabilities`), not here and not per-profile.
9. **Searchable/clearable** — every `select` and `multi_select` field MUST set `options.searchable: true` and `options.clearable: true`. Unless author says otherwise.

#### Instance-level properties (now explicit in the manifest)

| Property | Where | `field_type` | `config_type` | Notes |
|---|---|---|---|---|
| `integrationLogLevel` | `configurations.yaml`, in `general_configurations.configurations[]`, wrapped in a field group gated by `required_for_capabilities: ["<capability-id>"]` (typically `["automation-and-remediation"]`) — no `view_group`, no `metadata.event` | `select` | `"backend"` | Off/Debug/Verbose. `options.searchable: true`, `options.clearable: true`. Canonical block below. |
| `defaultIgnore` | `configurations.yaml`, under the `automation-and-remediation` capability | `checkbox` | `"backend"` | "Do not use in CLI by default". **Only when an `automation-and-remediation` capability exists** — it governs commands, which collection-only capabilities don't have. Omit otherwise. |
| `mappingId` (label "Classifier") | `configurations.yaml`, **fetch-issues only** | `select` + `dynamic_values` | `"backend"` | When `isFetch`. Provider `xsoar`, `dynamicField: "classifier"`. `default_value` ← `defaultClassifier` (best-effort literal, §2.16). `options.searchable: true`, `options.clearable: true`. Same scoping as `incidentType` — never under `log-collection`/`fetch-assets-and-vulnerabilities`/`threat-intelligence-and-enrichment`/`fetch-secrets` or general configurations. |
| `incomingMapperId` (label "Mapper (incoming)") | `configurations.yaml`, **fetch-issues only** | `select` + `dynamic_values` | `"backend"` | When `isFetch`. Provider `xsoar`, `dynamicField: "mapper-incoming"`. `default_value` ← `defaultMapperIn` (best-effort literal, §2.16). `options.searchable: true`, `options.clearable: true`. Same scoping as `incidentType` — never under `log-collection`/`fetch-assets-and-vulnerabilities`/`threat-intelligence-and-enrichment`/`fetch-secrets` or general configurations. |
| `defaultClassifier` | → `default_value` of `mappingId` | — | — | Not a UI field. Best-effort literal pre-selection (§2.16). |
| `defaultMapperIn` | → `default_value` of `incomingMapperId` | — | — | Not a UI field. Best-effort literal pre-selection (§2.16). |
| `outgoingMapperId` / `defaultMapperOut` | **OUT OF SCOPE** | — | — | Mirroring not supported. |

##### Canonical `integrationLogLevel` block (`configurations.yaml`)

`integrationLogLevel` is a **connector-wide** backend-managed field. In a Standard connector it lives **once** in `configurations.yaml general_configurations.configurations[]`, wrapped in a field group gated by `required_for_capabilities`. Because `general_configurations` fields cannot carry `metadata.event` (schema-enforced) and Standard connectors are **not** grouped (so `required_for_capabilities` is permitted and `view_group` is forbidden), the field carries neither `metadata.event` nor `view_group`. It is a `select` (Off/Debug/Verbose) with `searchable: true`/`clearable: true` and `metadata.xsoar.config_type: backend`.

The block below mirrors the real [`connectors/googleworkspace/configurations.yaml`](../../../unified-connectors-content/connectors/googleworkspace/configurations.yaml) `general_configurations` shape verbatim:

```yaml
general_configurations:
  description: General configurations for all capabilities
  configurations:
  - required_for_capabilities:
    - automation-and-remediation
    fields:
    - field_type: select
      id: integrationLogLevel
      title: Integration Log Level
      metadata:
        xsoar:
          config_type: backend
      options:
        create_modifiers:
          hidden: false
          required: false
        default_value: 'Off'
        description: Set the log level
        edit_modifiers:
          hidden: false
          required: false
        placeholder: Select log level
        searchable: true
        clearable: true
        values:
        - key: 'Off'
          label: 'Off'
        - key: Debug
          label: Debug
        - key: Verbose
          label: Verbose
```

> **`defaultIgnore` is different** — it stays under the `automation-and-remediation` capability's `configurations[]` (capability-level), NOT in `general_configurations`. Only `integrationLogLevel` moves to the connector-wide `general_configurations` + `required_for_capabilities` placement.

#### BE-auto-added params (now explicit)

When a `script` flag is true, the BE used to auto-add params. Define them explicitly. **Omit** the implied checkbox (`isFetch`, `feed`, `isFetchEvents`, `isFetchAssets`, `isFetchCredentials`) — enabling the capability implies it.

**`script.IsFetch: true`** → `fetch-issues`:
- `incidentFetchInterval` — `duration` default to 1 minute or whats given in integration YML.
- `incidentType` — `select` + `dynamic_values` (`dynamicField: "incident-type"`). **User-visible** (do NOT mark backend). Title "Issue Type", tooltip "select if classifier doesn't exist".
  - Placed under the **`fetch-issues`** capability's `configurations[]` — never in `general_configurations` or on an unrelated capability.
  - **Always emit** for `fetch-issues`, regardless of whether the YML has a type-13 param.
  - Never emit under non-issue fetch capabilities.
  - When `script.isfetchsamples: true`, force it always-visible.
- `mappingId` — label "Classifier", `select` + `dynamic_values` (provider `xsoar`, `dynamicField: "classifier"`), `config_type: backend`. `default_value` ← integration YML `defaultClassifier` (best-effort literal, §2.16). `options.searchable: true`, `options.clearable: true`. Placed only under `fetch-issues`.
- `incomingMapperId` — label "Mapper (incoming)", `select` + `dynamic_values` (provider `xsoar`, `dynamicField: "mapper-incoming"`), `config_type: backend`. `default_value` ← integration YML `defaultMapperIn` (best-effort literal, §2.16). `options.searchable: true`, `options.clearable: true`. Placed only under `fetch-issues`.

```yaml
# inside the fetch-issues capability's configurations[]
- id: "incidentType"
  title: "Issue Type"
  field_type: "select"
  metadata:
    dynamic_values:
      provider: "xsoar"
      trigger: ["on_create", "on_edit"]
      params: { integrationID: "<integration-id>", dynamicField: "incident-type" }
  options:
    help_text: "select if classifier doesn't exist"
    placeholder: "Select an issue type"
    create_modifiers: { required: false, hidden: false }
    edit_modifiers: { required: false, hidden: false }
```

**`script.Feed: true`** → `threat-intelligence-and-enrichment`:
- `feedReputation` — `select` (`Unknown`/`Benign`/`Suspicious`/`Malicious`).
- `feedReliability` — `select`; take `values`/`default_value`/`required` from the YML (default `"F - Reliability cannot be judged"`; keep `required: true` unless the YML says otherwise).
- `feedExpirationPolicy` — `select` (`Indicator Type`/`Time Interval`/`Never Expire`/`When removed from the feed`).
- `feedExpirationInterval` — `duration`, shown only when `feedExpirationPolicy == "interval"` (trigger, §3.5).
- `feedFetchInterval` — `duration` (default 240 min → `{hours: 4}` unless the YML differs).
- `feedBypassExclusionList` — `checkbox`.
- `feedIncremental` — `checkbox`. **Only emit if the YML declares it.** Place it **only** under the `threat-intelligence-and-enrichment` capability — never under any other capability or in general configurations.

**`script.IsFetchEvents: true`** → `log-collection`: `eventFetchInterval` — `duration` (default 1 min → `{minutes: 1}`).

**`script.IsFetchAssets: true`** → `fetch-assets-and-vulnerabilities`: `assetsFetchInterval` — `duration` (default `{minutes: 1}`).

**`script.LongRunning: true`** → the relevant fetch capability:
- `longRunning` — `checkbox`, backend-managed.
- `longRunningPort` — `input`, backend-managed; visible only when `longRunning == true` AND no engine/group selected (trigger, §3.5).

**`script.IsFetchCredentials: true`** → `fetch-secrets` (omit the `isFetchCredentials` checkbox).

#### Ignored during migration

- `section` (Connect/Collect/Optimize/Mirroring/Result) — manifest organizes by capability, the LLM can know if the field should be part of connection or configuration based on this. 
- `advanced: true` —  set the FieldGroup `advanced: true`
- `script.mappable`, `script.runOnce`, `script.mcp` — dev-mode/internal only.

### 3.8 handler.yaml Rules

Each integration gets one `handler.yaml` under `components/handlers/<handler-folder>/`. **Folder name == handler id** = the integration `commonfields.id` lowercased with spaces → dashes (e.g. `EWS v2` → `ews-v2`).

| Field | Rule |
|---|---|
| `id` | `xsoar-<integration-id>` (normalized). |
| `enabled` | `true`. |
| `metadata.version` | `"1.0.0"`. |
| `metadata.description` | `"XSOAR handler for <integration name> integration"`. |
| `metadata.module` | `"xsoar"`. |
| `metadata.ownership.team` | `"xsoar"`. |
| `metadata.ownership.maintainers` | `["@xsoar-content"]`. |
| `triggering.type` | `"PUB_SUB"`. |
| `triggering.labels.xsoar-integration-id` | Integration id from the YML. |
| `triggering.labels.xsoar-pack-id` | Pack id from `pack_metadata.json`. |
| `triggering.args` | `{}`. |
| `test_connection.type` | `"service"` (XSOAR-delegated). |
| `test_connection.service` | `"xsoar"`. |
| `test_connection.endpoint` | `"/settings/integration/connector/verification"`. |
| `test_connection_metro` | **REQUIRED on every handler** (§2.8). Emit the same `TestConnection` block for the metro (multi-tenant) deployment. Migration default: mirror `test_connection` — `{ type: "service", service: "xsoar", endpoint: "/settings/integration/connector/verification" }`.


#### capabilities section

1. Each handler maps to exactly **one** integration.
2. An integration with fetch + commands subscribes to both `automation-and-remediation` and the relevant fetch capability.
3. **`capabilities[].id` may reference a capability id directly** (or a sub-capability id when a sub-capability is used). Standard connectors are non-grouped — there are no view_groups — so a handler subscribes to whichever capability (or sub-capability) its integration contributes to. Use a sub-capability id only when the connector actually declares that sub-capability (§2.5.1).
4. **`auth_options[].id`** references a `connection.yaml` profile id only.
5. **`auth_options[]` are OR** (alternatives) — never AND. Multiple methods → separate entries referencing alternative profiles (user picks one). Several simultaneous inputs → one `passthrough` profile.
6. **Workloads** always `["xsoar-pod", "xsoar-automationhub-runner"]`.

```yaml
# Standard connectors: subscribe to a capability id directly (or a sub-capability id when declared).
capabilities:
  - id: "automation-and-remediation"
    auth_options:
      - { id: "oauth2_client_credentials.my_profile", workloads: ["xsoar-pod", "xsoar-automationhub-runner"] }
```

#### Actions per capability

Emit `actions[]` on the relevant capability entry, derived mechanically from the YML fetch flags:

| YML flag (Platform) | Capability | `actions[].type` |
|---|---|---|
| `isfetch: true` | `fetch-issues` | `reset_incidents_last_run` |
| `isfetchevents: true` | `log-collection` | `reset_events_last_run` |
| `isfetchassets: true` | `fetch-assets-and-vulnerabilities` | `reset_assets_last_run` |
| `feed: true` | `threat-intelligence-and-enrichment` | `reset_feed_last_run` |
| `isFetchCredentials: true` | `fetch-secrets` | *(none)* |
| resetContext: true | `automation-and-remediation` | `reset_integration_context`  |

**Rules:** one action per fetch capability; Suggest `display`/`description` when you have confidence, if not then omit and use (platform defaults); if a flag is hidden on Platform, omit its action too.

Here are the default actions display, description. If they are good for the case, lets omit. If requires change do something similar to this language. 

```yaml
 {
    "RESET_INTEGRATION_CONTEXT": {
        "DISPLAY": "Reset Integration Context",
        "DESCRIPTION": "This will clear the integration's stored context."
    },
    "RESET_ASSETS_LAST_RUN": {
        "DISPLAY": "Reset Assets Last Run",
        "DESCRIPTION": "This will reset the last run timestamp for assets and may cause data to be re-fetched."
    },
    "RESET_INCIDENTS_LAST_RUN": {
        "DISPLAY": "Reset Incidents Last Run",
        "DESCRIPTION": "This will reset the last run timestamp for incidents and may cause data to be re-fetched."
    },
    "RESET_FEED_LAST_RUN": {
        "DISPLAY": "Reset Feed Last Run",
        "DESCRIPTION": "This will reset the last run timestamp for the feed and may cause data to be re-fetched."
    },
    "RESET_EVENTS_LAST_RUN": {
        "DISPLAY": "Reset Events Last Run",
        "DESCRIPTION": "This will reset the last run timestamp for events and may cause data to be re-fetched."
    }
}
```

```yaml
capabilities:
  - id: "automation-and-remediation"
    auth_options:
      - { id: "oauth2_client_credentials.my_profile", workloads: ["xsoar-pod", "xsoar-automationhub-runner"] }
  - id: "fetch-issues"
    auth_options:
      - { id: "oauth2_client_credentials.my_profile", workloads: ["xsoar-pod", "xsoar-automationhub-runner"] }
    actions: [{ type: "reset_incidents_last_run" }]
  - id: "log-collection"
    auth_options:
      - { id: "oauth2_client_credentials.my_profile", workloads: ["xsoar-pod", "xsoar-automationhub-runner"] }
    actions: [{ type: "reset_events_last_run" }]
```

### 3.9 serializer.yaml

Use a serializer when a connector field id differs from the integration's expected param name (collision prefixes; connection-profile field remapping). **Not always required.** Create it at `components/handlers/<handler-folder>/serializer.yaml`.

**Field id naming**: keep the original param name when unique; on a real collision, apply [Appendix C](#appendix-c-field-id-uniqueness-rule) — alphabetically-first integration keeps the name (no serializer entry); others are prefixed and remapped.

- **`field_mappings`** — see §2.9.
- **`computed_fields`** — synthetic outputs from connector state; evaluated against original field IDs (§2.9). Used to emit the **BE fetch flags** for collection capabilities (§3.9.1).

#### 3.9.1 Fetch flags — mandatory `computed_fields` per collection capability

The XSOAR BE runtime is **capability-agnostic**: it does not understand UCP capabilities. When a collection capability is chosen, the BE still needs the legacy per-fetch flag to drive its runtime logic (e.g. creating the recurring job that executes the relevant fetch command every interval).

In legacy XSOAR a checkbox in the instance form let the user opt in to fetching (e.g. "Fetches incidents"). In UCP we have dedicated fetch capabilities, so the checkbox is removed (§3.4 note 5) — **choosing the fetch capability IS the opt-in**. We still must send the corresponding flag to the BE.

**Rule:** for **every collection capability the handler subscribes to**, the handler's [`serializer.yaml`](README.md:1381) MUST emit a `computed_fields` block that sends the matching flag (value `true`) **only when that capability is enabled** (`value: "on"`). This is required on **every** handler that subscribes to one or more of the five fetch capabilities — even when no other serializer entry is needed.

**Flag mapping** (capability → flag emitted):

| Collection capability | Flag emitted |
|---|---|
| `fetch-issues` | `isFetch` |
| `log-collection` | `isFetchEvents` |
| `fetch-assets-and-vulnerabilities` | `isFetchAssets` |
| `fetch-secrets` | `isFetchCredentials` |
| `threat-intelligence-and-enrichment` | `feed` |

> **Note:** `automation-and-remediation` is **not** a collection capability and emits **no** fetch flag.

**Example** — a handler subscribing to `fetch-issues` and `log-collection`:

```yaml
# components/handlers/<handler-folder>/serializer.yaml
computed_fields:
  - output:
      - id: "isFetch"
        value: true
    any_of:
      - conditions:
          - type: "capability"
            options: { capability_id: "fetch-issues", value: "on" }
  - output:
      - id: "isFetchEvents"
        value: true
    any_of:
      - conditions:
          - type: "capability"
            options: { capability_id: "log-collection", value: "on" }
```

One `computed_fields` rule per collection capability the handler subscribes to. The `capability_id` matches the handler's `capabilities[].id` (§3.8 rule 3). Emit the flag with `value: true`; the BE treats the flag's absence as "not fetching".

### 3.10 Inventory Checklist

Per integration, document: ID + display name; provider (flag if differing); categories (flag if differing); all params (name, type, default, required); special features (`longRunning`, `isFetch`, `isfetchevents`, `ismappable`, …); `supportedModules` (inherited vs overridden); marketplace-specific behavior; XSOAR-intervened commands (`fetch-incidents`, `fetch-events`, `long-running-execution`); duplicate field IDs needing serializer mappings.

### 3.11 CODEOWNERS

Required at repo root. GitLab evaluates bottom-to-top — connector overrides go **after** the catch-all.

```
# Default: entire repo owned by the team
* @mhafuta @lpaz @adbiton @rlevy @smotna @nzur @lfrost

# Connector-specific overrides (last match wins)
/connectors/salesforce/** @jmizrahi @asharma @pyadav @dbelenky
/connectors/googleworkspace/** @ssingh @kverma
```

**Rules:** keep the default block; add `/connectors/<name>/** ...` after the catch-all; and for every new connector add `@sbenyakir @ybenshalom @juschwartz` as codeowners, and also others the author/user asks for


## Appendix A: XSOAR Parameter Type → Manifest Type Mapping

XSOAR types in use (if you come across another type when migrating, fail and raise a flag).
Also see [`plans/integration-parameter-and-types-overrides.md`](plans/integration-parameter-and-types-overrides.md) for special-param details.

| XSOAR Type | Description | UCP `field_type` | `options.mask` | Notes |
|---|---|---|---|---|
| 0 | Short String / Text | `input` | `false` | Standard text input. |
| 1 | Number / Integer | `input` | `false` | Text input (no separate number type in UCP). Example: `max_fetch`. |
| 4 | Encrypted / Password | `input` | `true` | Masked input for secrets. Example: ApiKey. |
| 8 | Boolean / Checkbox | `checkbox` | N/A | Single boolean toggle. |
| 9 | Credentials / Authentication | `input` (per leaf) | `true` (password leaf) | **IN SCOPE.** Mapped into the **connection profile** (`connection.yaml profiles[].configurations[].fields[]`), same as type 4 . A `type: 9` credential renders as two leaves: an identifier (`<id>.identifier`) and a password (`<id>.password`); each becomes a profile auth field carrying `metadata.auth.parameter`, wired back to `demisto.params()` via the profile's `interpolation_mapping` (when used) . Honor `hiddenusername`/`hiddenpassword`/`displaypassword` leaf semantics  |
| 12 | Long Text / TextArea | `text_area` | `false` | Multi-line text. |
| 13 | Incident Type | `select` + `metadata.dynamic_values` | `false` | Option list fetched at runtime via the XSOAR provider (`dynamicField: "incident-type"`). **User-visible field** |
| 14 | Encrypted Text Area | `text_area` | `true` | Masked input. Example: SSHKey. |
| 15 | Single Select / Dropdown | `select` | `false` | Options from YML `options` array as `{key, label}` pairs. |
| 16 | Multi Select | `multi_select` | `false` | Native UCP field type. Items in `values` use `{key, label}`; `default_value` is an array of keys. See README [Multi-Select Example](README.md:1681). |
| 17 | Feed Expiration Policy | `select` | `false` | Hardcoded display labels: `Indicator Type` / `Time Interval` / `Never Expire` / `When removed from the feed`. Only added when `script.Feed: true`. |
| 18 | Indicator / Feed Reputation | `select` | `false` | New mapped values: `Unknown` / `Benign` / `Suspicious` / `Malicious` (not the legacy None/Good/Suspicious/Bad). Only added when `script.Feed: true`. |
| 19 | Feed Fetch Interval | `duration` | `false` | Multi-unit duration field — `units: ["days","hours","minutes"]`, `output_format: "minutes"`. Convert the YML minutes-string default to a per-unit `default_value` (§2.15). Use [`triggers.yaml`](README.md:833) for conditional visibility (§3.5). |

**Important Notes:**

- Whenever you see the string "Incidents" in the YML, change it to "Issues" — this is the correct terminology for the Platform marketplace where ConnectUs is supported (e.g., "Fetch Incidents" → "Fetch Issues").
- If you come across a type not listed above when migrating, fail and raise a flag.

## Appendix B: Authentication Frontend Rendering

When the platform transforms `handler.yaml` auth configurations for the frontend:

- **Single auth option** → rendered as a single form.
- **Multiple auth options** (alternative profiles in `auth_options[]`) → rendered as a selection (radio/dropdown), user picks ONE.
- **Combined auth** (`methods` array) → rendered as grouped form sections, user configures ALL.

## Appendix C: Field ID Uniqueness Rule

All field IDs must be globally unique across the entire connector directory — across [`connection.yaml`](README.md:162) (including `general_configurations` and profile fields), [`capabilities.yaml`](README.md:509), and [`configurations.yaml`](README.md:719) (including `checkbox_group` item IDs). This is enforced by OPA validation (xref Check covering field_entries).

**Default: keep the original id.** Each field's `id` is the original integration param `name`. Do **not** proactively prefix/suffix — keep the original name whenever it is already unique across the connector. A field that keeps its original id needs **no** serializer entry. This minimizes serializer work.

In a Standard connector, multiple integrations can contribute config fields under the same capability. When two integrations contribute a field with the same id (e.g. both need `domain`, `integrationLogLevel`, or `defaultIgnore`), the collision-resolution algorithm below still applies — it is needed whenever more than one integration contributes.

### Deterministic collision rule (always applied the same way)

A **collision** is when two or more fields anywhere in the connector would otherwise share the same `id`. Resolve every collision with this exact, order-independent algorithm:

1. **Identify** the full set of integrations that contribute a field with the colliding id.
2. LLM would suggest which params we can re-use across multiple integrations to reduce redundancy. 
3. **Sort** those integrations by their **normalized integration id** (the `commonfields.id` lowercased, spaces → dashes — the same normalization as the handler-folder name, §3.8) in ascending lexicographic order.
4. **The first integration in that sorted order KEEPS the original id** (no prefix, no serializer entry).
5. **Every OTHER colliding integration prefixes its field** with `<normalized-integration-id>_<original-id>` and adds a [`serializer.yaml`](README.md:1381) `field_mappings` entry mapping the prefixed id back to the original param name (`field_name: "<original-id>"`).

So for `proxy` appearing in `Salesforce`, `Salesforce IAM` can be defined once, and the field will be used across both integrations.

Determinism guarantees:
- The winner that keeps the original id is always the alphabetically-first normalized integration id — independent of processing order.
- The prefix is always `<normalized-integration-id>_`, never an ad-hoc abbreviation.
- Fields that do **not** collide are **never** renamed.

> This rule is the single source of truth for id collisions everywhere in the guide (config fields, `integrationLogLevel`, `defaultIgnore`, engine fields, `domain`, etc.). Wherever a prefixed id appears in this guide, it follows exactly this rule.

## Appendix I: Server-Style Integrations

Server-style integrations are long-running listeners that accept inbound traffic (HTTP, syslog, SNS, mail polling, etc.) rather than initiating outbound API calls on a schedule. They are generally **out of scope for the standard migration path**, but several are still expected to be migrated under a **server-style profile** with explicit credential-pinning semantics described below.

### Server-style handler rule — credential pinning via `triggering.labels`

Some integrations are server-style but still need to be migrated.
These integrations are ones that open a server and listen to incoming traffic, but they also need to make outbound API calls to a third-party service.

An integration may be a server-style integration if it:

1. Does the YML declare `script.longRunning: true`?
2. Does the integration accept inbound traffic (HTTP listener, syslog listener, SNS push, mail polling, webhook receiver, websocket server, etc.) rather than only initiating outbound API calls on a schedule?
3. Does the integration carry a `type: 9` (credentials) parameter that needs to be pinned to a connection profile via `xsoar-long-running-credentials-profile-id`?

When a server-style integration carries a `type: 9` (credentials) parameter named **`credentials`** in its integration YML, the migrated handler MUST declare which connection profile supplies those credentials by adding a label under `triggering.labels`:

```yaml
# components/handlers/<name>/handler.yaml (fragment)
triggering:
  labels:
    xsoar-long-running-credentials-profile-id: <profile_id>
```

- **`<profile_id>`** is the `id` of the profile under [`connection.yaml`](../README.md) `profiles[]` that contains the migrated `credentials` (type-9) field.
- **If the integration's YML has no `type: 9` parameter named `credentials`, that is a bug in the source integration** — flag it as a blocker; do NOT silently emit a label pointing to an arbitrary profile. 
- Get the user approval that this integration is indeed server style where the server does the auth, and that this is the right profile.
the maintainer MUST analyze it against the server-style criteria below and update this appendix accordingly:


## Appendix J: Backend-Managed Fields (`config_type: backend`)

The following fields — and **only** these fields — MUST carry `metadata.xsoar: { config_type: "backend" }`. They are managed by the XSOAR backend rather than passed through as plain instance parameters. This list is **exclusive**: any field not on it MUST NOT be marked `config_type: backend`.

| Field ID | Where it lives | Notes |
|---|---|---|
| `engine` | `connection.yaml general_configurations` (§3.6 engine 3-field pattern, connector-wide with `required_for_capabilities`) | `select` + `dynamic_values` (`dynamicField: engine`). |
| `engineGroup` | `connection.yaml general_configurations` (§3.6 engine 3-field pattern, connector-wide with `required_for_capabilities`) | `select` + `dynamic_values` (`dynamicField: engine-group`). Field id `engineGroup` in the manifest. |
| `mappingId` | `configurations.yaml`, under the `fetch-issues` capability | Classifier — `select` + `dynamic_values` (`dynamicField: classifier`). |
| `incomingMapperId` | `configurations.yaml`, under the `fetch-issues` capability | Mapper (incoming) — `select` + `dynamic_values` (`dynamicField: mapper-incoming`). |
| `outgoingMapperId` | `configurations.yaml` (mirroring — see §3.2) | Mapper (outgoing). **Mirroring is out of scope on Platform**; listed here only because it is backend-managed when present. |
| `defaultIgnore` | `configurations.yaml`, under the `automation-and-remediation` capability | "Do not use in CLI by default". Only for connectors with an `automation-and-remediation` capability (§3.7). |
| `integrationLogLevel` | `configurations.yaml`, in `general_configurations.configurations[]`, in a field group gated by `required_for_capabilities` (typically `["automation-and-remediation"]`) — no `view_group`, no `metadata.event` (§3.7). | Off / Debug / Verbose. `select` with `searchable: true`/`clearable: true`. |

**Explicitly NOT backend-managed** (do **not** set `config_type: backend`): `proxy`, `insecure`, `engine_mode` (the radio control), the shared `domain` field, all auth/secret fields, and every other configuration parameter migrated from the integration YML.