# Unified Connector Migration Guide

> **Purpose**: This document briefs an LLM tasked with migrating XSOAR integrations into a Unified Connector. Given a set of integration YMLs (not necessarily from the same pack), scope the migration, identify gaps, flag decisions, and produce the connector YAML files.
>
> **Output**: A complete connector (all YAML files).

---

## Table of Contents

- [Section 1: What is a Unified Connector](#section-1-what-is-a-unified-connector)
- [Section 2: Connector Specification Reference](#section-2-connector-specification-reference)
- [Section 3: Migration Rules and Defaults](#section-3-migration-rules-and-defaults)
- [Section 4: Worked Reference — Salesforce Connector (Grouped)](#section-4-worked-reference--salesforce-connector-grouped)
- [Section 5: Your Task](#section-5-your-task)
- [Appendix A: XSOAR Parameter Type → Manifest Type Mapping](#appendix-a-xsoar-parameter-type--manifest-type-mapping)
- [Appendix B: Authentication Frontend Rendering](#appendix-b-authentication-frontend-rendering)
- [Appendix C: Field ID Uniqueness Rule](#appendix-c-field-id-uniqueness-rule)
- [Appendix D: Excluded Integrations (Out of Scope)](#appendix-d-excluded-integrations-out-of-scope)
- [Appendix E: Integrations Requiring Manual Migration](#appendix-e-integrations-requiring-manual-migration)
- [Appendix F: Joint Migration With the SaaS Team](#appendix-f-joint-migration-with-the-saas-team)
- [Appendix G: Engine / EngineGroup / Proxy Exclusion List](#appendix-g-engine--enginegroup--proxy-exclusion-list)
- [Appendix H: Single-Engine Integrations](#appendix-h-single-engine-integrations)
- [Appendix I: Server-Style Integrations](#appendix-i-server-style-integrations)
- [Appendix J: Backend-Managed Fields (config_type: backend)](#appendix-j-backend-managed-fields-config_type-backend)

---

## Section 1: What is a Unified Connector

A **Unified Connector** is a declarative, YAML-based framework that consolidates all of a vendor's integrations into one connector. Authentication and configuration are defined once and shared, allowing multiple modules (XSOAR, SaaS) to contribute integrations for the same vendor.

**The migration model:**

1. All of a vendor's integrations are consolidated into `connectors/<vendor>/`.
2. Authentication is defined once in `connection.yaml`; each handler subscribes to the relevant auth method.
3. Capabilities / sub-capabilities declare what features the connector supports.
4. Each legacy integration becomes exactly **one handler** (1:1) under `components/handlers/`. A handler subscribes to all capabilities its integration covers (e.g. commands + fetch).
5. The platform manages authentication (OAuth token lifecycle); Python code uses the new CommonServerPython auth APIs instead of managing tokens directly.

**Benefits:** one connector per vendor, unified auth, consistent UI rendered from a shared spec, platform-managed token lifecycle.

**Note:** ConnectUs is supported only on **Platform Marketplace**.

### Architecture

```
CODEOWNERS                      # Required: code owners (repo root)
connectors/<vendor>/
├── connector.yaml              # Required: identity and metadata
├── connection.yaml             # Required: authentication profiles
├── capabilities.yaml           # Required: feature definitions
├── configurations.yaml         # Optional: per-capability config fields
├── triggers.yaml               # Optional: conditional field behavior
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

> **Source of truth**: [`README.md`](../README.md) and [`schema/*.schema.json`](../schema/). This section mirrors them — when in doubt, the schemas win. Re-check freshness before relying on it.

### 2.1 connector.yaml

Defines the connector identity. Schema: [`connector.schema.json`](schema/connector.schema.json).

| Field | Type | Req | Description |
|---|---|---|---|
| `enabled` | boolean | ❌ | Defaults `true`. Set `false` only for example connectors. |
| `id` | string | ✅ | Unique identifier (min 3 chars). |
| `metadata.title` | string | ✅ | Display name. |
| `metadata.description` | string | ✅ | Brief description (min 10 chars). |
| `metadata.version` | semver | ✅ | E.g. `1.0.0`. |
| `metadata.categories` | string[] | ✅ | At least one. |
| `metadata.tags` | string[] | ❌ | Searchable tags. |
| `metadata.domain` | string | ❌ | E.g. `"security"`. |
| `metadata.vendor` | string | ✅ | Vendor being integrated. |
| `metadata.publisher` | string | ✅ | Publisher of the definition. |
| `metadata.author_image` | string | ❌ | Icon filename in connector root. Pattern `^[a-zA-Z0-9_.-]+\.(png\|jpg\|jpeg\|svg)$`. See §2.13. |
| `metadata.documentation` | URI | ❌ | External docs URL. |
| `metadata.ownership.team` | string | ✅ | Owning team. |
| `metadata.ownership.maintainers` | string[] | ✅ | Maintainer handles. |
| `settings.allow_skip_verification` | boolean | ❌ | Allow skipping the connection test. |
| `settings.required_features` | string[] | ❌ | Tenant features required for visibility. |
| `settings.grouped` | boolean | ❌ | `true` for Grouped connectors (multiple handlers per vendor). |

### 2.2 connection.yaml

Defines authentication profiles. Schema: [`connection.schema.json`](schema/connection.schema.json).

| Field | Type | Req | Description |
|---|---|---|---|
| `metadata.title` | string | ✅ | Section title. |
| `metadata.description` | string | ✅ | Help text. |
| `metadata.help` | string | ❌ | Markdown/HTML help. |
| `general_configurations` | GeneralConfig | ❌ | Shared fields. **Not used in migration** (§3.6). |
| `view_groups` | ViewGroup[] | Grouped | One tile per integration (Grouped connectors). |
| `profiles` | Profile[] | ✅ | Authentication profiles. |

**Profile types:** `oauth2_client_credentials`, `oauth2_authorization_code`, `oauth2_jwt_bearer`, `plain` (user/password), `api_key`, `passthrough` (store-and-forward, no IDP — see §2.6.1).

**Profile schema:**

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string | ✅ | Format `type.purpose`, e.g. `oauth2_client_credentials.salesforce`. |
| `type` | string | ✅ | One of the profile types above. |
| `title` | string | ✅ | Display name. |
| `description` | string | ✅ | Profile description. |
| `view_group` | string | Grouped | The connection-page tile this profile binds to (§3.6). |
| `configurations` | FieldGroup[] | Conditional | Required for `passthrough` and any profile carrying auth-input fields. Omitted for `oauth2_authorization_code` (secrets come from `{SAAS_REGISTRY.*}`). Fields must include `metadata.auth.parameter` (§2.6). |

### 2.3 OAuth2-Specific Fields

| Field | Applicable | Description |
|---|---|---|
| `discovery_url` | All OAuth2 | OIDC discovery URL. Mutually exclusive with explicit endpoints. |
| `token_endpoint` | All OAuth2 | Token endpoint. Mutually exclusive with `discovery_url`. |
| `authorization_endpoint` | `oauth2_authorization_code` | Authorization URL. |
| `client_id` / `client_secret` | `oauth2_authorization_code` | Use `{SAAS_REGISTRY.*}` for secrets. |
| `refresh_token_scope` | `oauth2_authorization_code` | **Required.** IDP-specific (e.g. `"refresh_token"` for Salesforce, `"offline_access"` for OIDC). |
| `options.use_base64_header` | All OAuth2 | Base64-encode the auth header. |
| `options.allow_scopes` | All OAuth2 | Merge handler-level scopes into the platform request. |

### 2.4 Variable Interpolation

| Pattern | Meaning | Example |
|---|---|---|
| `{{field_id}}` | User-provided field value | `{{salesforce_domain}}` |
| `{SAAS_REGISTRY.*}` | Secrets from registry | `{SAAS_REGISTRY.SALESFORCE_CORE_CLIENT_ID}` |
| `{UNIFIED_CONNECTORS_*}` | Connector-specific config | `{UNIFIED_CONNECTORS_SLACK_CALLBACK}` |

### 2.5 capabilities.yaml

Defines connector capabilities. Schema: [`capabilities.schema.json`](schema/capabilities.schema.json).

| Field | Type | Req | Description |
|---|---|---|---|
| `metadata.title` | string | ✅ | Section title. |
| `metadata.description` | string | ✅ | Help text. |
| `metadata.help` | string | ❌ | Markdown/HTML help. |
| `general_configurations` | GeneralConfig | ❌ | Fields for all capabilities. **Must contain the mandatory `instance_name` field.** |
| `capabilities` | Capability[] | ✅ | Capability list. |

**MANDATORY:** exactly one field with `metadata.connector.parameter: "instance_name"` under `general_configurations` (see §3.4 for the verbatim block).

**Capability schema:** `id`, `title`, `description`, `default_enabled` (bool), `required` (bool), `labels` (string[], e.g. `Recommended`), `config.required_license` (string[]), `config.required_features` (string[], AND logic), `sub_capabilities` (same shape minus `description`/`labels`).

**Valid license values:** `data_security, agentix, asm, cloud, cloud_appsec, cloud_posture, cloud_runtime_security, cold_rtn, compute_unit, edr, endpoint_dlp, epp, exposure_management, forensics, host_insights, identity_threat, rtn, tim, xdr, xsiam, xsoar`.

### 2.6 Auth Parameter Tagging

Fields inside auth profile configurations **must** carry `metadata.auth.parameter`. Field IDs are globally unique and carry no semantic meaning — the backend maps user input to auth parameters via this tag.

| Profile Type | Required `auth.parameter` values |
|---|---|
| `oauth2_client_credentials` | `client_key`, `client_secret` |
| `plain` | `username`, `password` |
| `api_key` | `api_key` |
| `oauth2_authorization_code` | *(none — from `{SAAS_REGISTRY.*}`)* |
| `oauth2_jwt_bearer` | `subject_email`, `credentials_file` |
| `passthrough` | *(free-form per connector — no enum, no PR-time contract)* |

#### 2.6.1 Passthrough Profile

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

**Use `passthrough`** when the platform's only job is "store these fields, return them to the handler." **Use a typed profile** when the platform should manage the credential lifecycle (token exchange, refresh, expiry).

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

Handlers reference it like any other profile: `auth_options: [{ id: "passthrough.acme_api", workloads: ["xsoar-pod"] }]`.

#### 2.6.2 Profile Metadata & the `interpolated` flag

Profiles may carry an optional, **module-namespaced** `metadata` object (`profiles[].metadata`, keyed by handler module — `xsoar`, etc.) holding profile-scoped **non-secret** runtime context. The platform flattens the matching module's namespace into the connector lifecycle event (same channel as `metadata.event.publish`, §2.17 — **not** get-credentials). The `auth` namespace and secrets are **forbidden** here.

**`interpolated: true` — run unmodified integration code in UCP.** For migrations that do **not** rewrite the integration code, set `metadata.xsoar.interpolated: true` on each profile. At runtime the XSOAR runtime calls `getucpcredentials` and injects the secrets into `demisto.params()` exactly as a legacy instance, so the code runs unchanged.

```yaml
profiles:
  - id: "oauth2_client_credentials.salesforce"
    type: "oauth2_client_credentials"
    title: "OAuth 2.0 Client Credentials Flow"
    metadata:
      xsoar:
        interpolated: true   # → runtime injects secrets into demisto.params()
    configurations:
      - fields: [...]
```

> **Migration default**: emit `metadata.xsoar.interpolated: true` on every profile **unless** the integration code was explicitly adapted to fetch credentials via the UCP get-credentials API.

### 2.7 configurations.yaml

Per-capability config fields. Schema: [`configurations.schema.json`](schema/configurations.schema.json).

| Field | Type | Req | Description |
|---|---|---|---|
| `metadata.title` | string | ✅ | Section title. |
| `metadata.description` | string | ✅ | Help text. |
| `general_configurations` | GeneralConfig | ❌ | Fields for all capabilities. |
| `view_groups` | ViewGroup[] | Grouped | Own registry, independent of `connection.yaml` (§3.7). |
| `configurations` | CapabilityConfig[] | ✅ | Per-capability; each `id` matches a capability ID. |

### 2.8 handler.yaml

How a handler uses the connector. Schema: [`handler.schema.json`](schema/handler.schema.json).

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string | ✅ | Unique handler id. |
| `metadata.version` | semver | ✅ | Handler version. |
| `metadata.description` | string | ✅ | Description. |
| `metadata.module` | string | ❌ | e.g. `"xsoar"`. Determines which handler-specific metadata keys are forwarded. |
| `metadata.tags` | string[] | ❌ | Tags. |
| `metadata.labels` | object | ❌ | Free-form key/value forwarded at runtime. |
| `metadata.ownership` | Ownership | ✅ | Team and maintainers. |
| `enabled` | boolean | ✅ | Active flag. |
| `triggering.type` | string | ✅ | `PUB_SUB` or `ZERO_SCALE`. |
| `triggering.labels` | object | ❌ | e.g. `xsoar-integration-id`, `xsoar-pack-id`, `xsoar-long-running-credentials-profile-id`. |
| `capabilities` | HandlerCapability[] | ✅ | Capability-auth mappings; each MAY declare `actions[]` (see below). |
| `test_connection` | TestConnection | Conditional | Required unless every `auth_options[].id` is `"none"`. |
| `test_connection.type` | string | ✅ | `endpoint` or `service`. |
| `test_connection.host` | string | Conditional | Required for `endpoint`. Supports `{tenant_id}`. |
| `test_connection.service` | string | Conditional | Required for `service` (e.g. `"xsoar"`). |
| `test_connection.endpoint` | string | ✅ | Verification path. |
| `test_connection.headers` | object | ❌ | HTTP headers (with `type: endpoint`). |

**Action schema** (`capabilities[].actions[]`): instance-level UI operations (e.g. "Reset Issues Last Run"). Migrated XSOAR handlers always place actions on the **sub-capability** level (§3.8).

| Field | Req | Description |
|---|---|---|
| `type` | ✅ | One of `reset_integration_context`, `reset_assets_last_run`, `reset_incidents_last_run`, `reset_feed_last_run`, `reset_events_last_run`. |
| `display` | ❌ | UI name (platform default if omitted). |
| `description` | ❌ | Description (platform default if omitted). |

### 2.9 serializer.yaml

Field name/value transforms. Schema: [`serializer.schema.json`](schema/serializer.schema.json). Two optional sections (at least one required):

1. **`field_mappings`** — rename fields and/or transform values (processed first). Each entry: `id` (✅, must match a defined field), `field_name` (rename target), `field_value` (transform function). At least one of `field_name`/`field_value` required.
2. **`computed_fields`** — synthetic output fields (processed second). Each rule has `output` (fields to emit) and `any_of` (condition groups: AND within a group, OR across groups). Condition `type` is `capability` (`{capability_id, value: on|off}`) or `field` (`{field_id, op, value}`). Evaluated against **original** field IDs (before `field_mappings`).

### 2.10 triggers.yaml

Conditional field behavior — show/hide, enable/disable, require, lock — driven by field values and/or capability state. Schema: [`triggers.schema.json`](schema/triggers.schema.json). **Optional**; omit or ship `triggers: []` when not needed. Triggers live in a flat root array; each has a recursive `conditions` tree and one or more reversible `effects`.

**Condition node variants** (by `type`): `condition` (field leaf), `condition_group` (AND/OR over field children), `capability_condition` (capability leaf), `capability_condition_group` (AND/OR over capability children). A root `condition_group` may mix families; nested groups stay per-family.

**Operators:** field — `eq, neq, gt, gte, lt, lte, contains, starts_with, is_empty, is_not_empty`; capability — `eq, neq` only. `is_empty`/`is_not_empty` **must omit `value`**.

**Effect:** targets a field by `id` with an `action` (boolean flags `hidden`/`required`/`read_only`/`enabled`, ≥1 present). Effects are **reversible** — the action applies when conditions match and its inverse applies when they don't, restoring the target's prior (snapshotted) state. `effect.message` is allowed on any trigger (use it to explain why a capability requires a field).

### 2.11 summary.yaml

Schema: [`summary.schema.json`](schema/summary.schema.json). Fields: `metadata.title` (✅), `metadata.description` (✅), `metadata.link` (❌, docs URL), `metadata.next_steps` (❌, Markdown).

### 2.12 availability.yaml

Controls visibility per region/tenant **in production only** (dev/staging show all). Schema: [`availability.schema.json`](schema/availability.schema.json). Absent → GA. Present → `tenants` map restricts: region key = valid GCP region; value = array of tenant IDs or `null`; empty/`null` = all tenants in that region; region not listed = not visible there.

### 2.13 Connector Icon

Lives in the connector root, referenced by filename via `metadata.author_image`.

| Constraint | Value |
|---|---|
| Formats | `png`, `jpg`, `jpeg`, `svg` |
| Max size | 512 KB |
| Min raster dims | 32 × 32 px (SVG skipped) |
| Max per connector | 1 |

Icons are excluded from `connectors.tar.gz` and uploaded by CI to GCS at `images/<connector-id>/<filename>`.

### 2.14 Field Types

| Type | Description |
|---|---|
| `input` | Text input. |
| `text_area` | Multi-line text. |
| `select` | Single-choice dropdown (scalar value). |
| `multi_select` | Multi-choice dropdown (array of keys). |
| `checkbox` | Single boolean toggle. |
| `checkbox_group` | Multiple checkboxes (uses `fields[]` for items). |
| `toggle` / `switch` | On/off switches. |
| `label` | Read-only text. |
| `file_upload` | File upload — `options.mask` **must be `true`**. |
| `duration` | Multi-unit duration picker — serialized via `options.output_format`. See §2.15. |

### 2.15 Field Options

Schema: [`field-options.schema.json`](schema/definitions/field-options.schema.json). Highlights:

| Property | Req | Description |
|---|---|---|
| `mask` | ✅ | Mask in UI. **`true`** for `file_upload`. |
| `description` | ❌ | Secondary text. |
| `help_text` | ❌ | Info-icon tooltip (Markdown). |
| `placeholder` | ❌ | Ghost text. |
| `default_value` | ❌ | Initial value. For `select` matches one `values[].key`; for `multi_select` an array of keys; for `checkbox_group` an array of `{key, value}`; for `duration` a per-unit object (e.g. `{hours: 3, minutes: 25}`). With `metadata.dynamic_values`, it is a best-effort literal pre-selection (ignored if not in the fetched list). |
| `values` | ❌ | `{key, label}` options for `select`/`multi_select`. **Absent** when `dynamic_values` is declared. |
| `empty_values_message` | ❌ | Shown when a `select`/`multi_select` has no options at runtime. Only valid on those types. |
| `searchable` | ❌ | Whether the dropdown supports type-to-filter. **Migration MUST set `true` on every `select`/`multi_select`.** Only valid on those types. |
| `clearable` | ❌ | Whether the user can clear the selection back to empty. **Migration MUST set `true` on every `select`/`multi_select`.** Only valid on those types. |
| `units` | duration | Ordered unique time-unit boxes. **Migration MUST emit exactly `["days","hours","minutes"]`.** |
| `output_format` | duration | `"iso8601"` (default) or `"minutes"`. **Migration MUST set `"minutes"`.** |
| `layout` | ❌ | `cols` (≤ 6) and `row_span`. |
| `create_modifiers` / `edit_modifiers` | ❌ | `{required, hidden, read_only}`. **`duration` forbids `required`.** |

#### Duration field — migration contract

A `duration` field renders one numeric box per unit and serializes to one value.

```yaml
- id: "alertFetchInterval"
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

> **Validator** MUST verify every `duration` field has `output_format: "minutes"`, the correct converted `default_value` (round-trips to the original minutes), and `units == ["days","hours","minutes"]`.

### 2.16 Dynamic Field Values

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

### 2.17 Field Metadata & `event.publish`

A field's `metadata` is a free-form bag, classified for pub/sub forwarding:

| Category | Keys | Behavior |
|---|---|---|
| Platform-internal | `auth`, `connector`, `dynamic_values`, `event` | Stripped — never forwarded. |
| Handler-specific | Handler module names (`xsoar`, `cwp`, …) | Forwarded only to the matching handler. |
| Common enrichment | Everything else | Forwarded to all handlers. |

**`metadata.event.publish: true`** opts a connection-profile field's value into the create/edit lifecycle pub/sub event (and the verify API), so the BE receives non-secret operational values up front without a get-credentials round-trip.

- **Scope**: only valid on `connection.yaml profiles[].configurations[].fields[]`. Forbidden elsewhere.
- **Mutually exclusive with `metadata.auth`** — secrets always flow through get-credentials.
- **Shape**: exactly `{ publish: <boolean> }`.

> **Migration rule**: **every** connection-profile field MUST carry `metadata.event.publish: true`, with **two exceptions**: (1) `engine_mode` (the radio control), and (2) any field carrying `metadata.auth`. So `engine`, `engine_group`, `proxy`, `insecure`, server URL, region, etc. are published; secrets are not.

When the platform builds the event for handler **H**, the field's other metadata is classified per the table above (handler-specific keys included only if they match H's module).

### 2.18 Validation Rules

Per field: `trigger` (✅, `change`/`blur`), `rules[].type` (✅, `pattern`/`minLength`/`maxLength`/`async`), `rules[].value` (regex or int), `rules[].message`, `rules[].validation_type` (for `async`, e.g. `"uniqueness"`).

---

## Section 3: Migration Rules and Defaults

### 3.1 Assumptions

1. **Handler == integration** (1:1). No two handlers point to the same integration.
2. **Duplicate command names**: a connector CANNOT expose the same command name twice. Resolve by creating `<command>_<integration_name>` with a copied implementation — requires manual work and XSOAR management approval.
3. **Platform marketplace only**: if `marketplaces` is absent from the integration YML, it's in the pack's `pack_metadata.json`.
4. **Hidden on platform**: a parameter hidden on `platform` (`hidden: [platform]`, `isfetch:platform: false`, etc.) is excluded from the manifest.
5. **Platform-specific fields**: respect marketplace-specific overrides (`defaultvalue:platform`, `id:xsoar`, `quickaction:platform`, etc.).
6. **Author image**: the PNG in `<pack>/integrations/<integration>/` is the connector icon. If multiple exist, take the first; verify it manually. If none, flag.
7. **cooc integrations** (`AWS`, `GCP`, `Azure`) are **not migrated** (see Appendix D).
8. **UI triggers**: none added this quarter, but **author** [`triggers.yaml`](README.md:833) where it cleanly solves a known UI problem (§3.5).
9. **Always have a sub-capability**, even with one integration under a capability. A lone sub-capability is marked `required: true`.
10. **Sub-capability licenses MUST be a subset of the integration's `supportedModules`** (see §3.1.1).

#### 3.1.1 License subsetting

A sub-capability's `config.required_license` must contain only licenses present in the integration's `supportedModules` (or the parent pack's `supported_modules` if the integration omits it). **Rationale**: UCP triggers instance creation, but the XSOAR BE only creates the instance if the tenant's licenses match the integration's `supportedModules`. Declaring an unsupported license causes a silent BE failure that is hard to triage. A **strict subset** is allowed (to narrow the tier); a superset is a migration bug — fail/flag it.

### 3.2 Out of Scope

1. Integrations not in the given list.
2. Deprecated, community, or partner integrations.
3. Mirroring (not supported on Platform): `outgoingMapperId`, `defaultMapperOut`.

> **Open items** are tracked in [this spreadsheet](https://docs.google.com/spreadsheets/d/1C1nZ70rJlBWB0vdH_rc_xe5RFk22CiA9Z2yBtSLgJg4/edit?gid=0#gid=0) (authoritative status + Jira links). Remaining unresolved opens:
>
> - 🔴 **Credentials vaults** — support in progress.
> - 🔴 **`advanced: true`** — legacy per-parameter collapsible "Advanced" sections have no manifest equivalent. Emit such fields as regular fields and note them in Gap Analysis.
> - 🟡 **Per-integration action `display`/`description` overrides** — migration omits both (platform defaults); track integrations needing custom wording (e.g. EWS "Reset Mailbox Last Sync").
> - 🟡 **`metadata.documentation`** and **`help` generation** — tooling TBD by the tech team.
> - 🟡 **Skip the connection screen** for integrations that have no auth/connection — there will be an option to skip the connection screen (no block).
> - 🟡 **`allow_skip_verification` / skip-verify** — option to skip the connection test exists (`settings.allow_skip_verification`, §2.1); confirm UX.
> - 🔴 **Capability auto-select gap** — there is no way to flip a capability's `selected` state from a trigger effect (`EffectAction` exposes only `hidden`/`required`/`read_only`/`enabled`, where `enabled` = UI interactivity, NOT on/off selection). So "auto-enable capability B when A is chosen" / single-sub-capability auto-select cannot be expressed today. Track separately.
> - 🔴 **`duration` field production-block** — connectors with interval (`duration`) fields are blocked from production until the duration field type fully ships in UCP.
> - 🔴 **"No issue type" empty-option** for `incidentType`/`alertType` dynamic dropdowns — legacy FE prepends a selectable empty option whose stored value is `""`. How to express in the manifest is undecided (likely a per-provider `dynamic_values.empty_label` convention). Note: `options.empty_values_message` (§2.15) does NOT solve this — it only supplies placeholder text when there are no options at all, it does not prepend a selectable empty option. Owners: Shahar/Guy.
> - 🔴 **`mail-listener` synthetic fetch toggle** — legacy FE `SYSTEM_ALWAYS_FETCH_BRANDS` forces `mail-listener` to always render a disabled, always-checked fetch toggle. Believed server-managed; confirm with engineering management before authoring a manifest.
> - 🟢 **`SYSTEM_OPTIONAL_FETCH_BRANDS`** (elasticsearch, google, kafka, esm, syslog, crowdstrike-streaming-api) — legacy XSOAR runtime fallback for integrations missing a proper `integrationScript`. Not a migration concern (manifest declares capabilities explicitly); documented for transparency. TODO verify with Guy it's XSOAR-only.

### 3.3 connector.yaml Rules

**Inputs**: gather the parent packs' `pack_metadata.json` (`relevant_packs_jsons`) and the integration YMLs (`relevant_integrations_ymls`). For licenses, read the integration YML's `supportedModules`; if absent, the parent pack's `supported_modules`; if neither, flag.

| Field | Rule |
|---|---|
| `id` | From the **master CSV Connector ID**, lowercased, spaces → dashes (§3.3.1). |
| `enabled` | `true` (unless intentionally disabling). |
| `metadata.title` | Same name as `id`, Title Case (§3.3.1). |
| `metadata.description` | Synthesize from `READMEs`. Flag for technical-writer review. |
| `metadata.version` | Always `1.0.0`. |
| `metadata.categories` | Deduplicated union of packs categories (≥1). |
| `metadata.tags` | Deduplicated union of packs tags. |
| `metadata.publisher` | Always `"Palo Alto Networks"`. |
| `metadata.vendor` | From the integration `provider` field. Flag if providers differ. |
| `metadata.author_image` | Filename in connector root; source from `<pack>/integrations/<integration>/` (take non dark mode if many, flag if none). |
| `metadata.ownership.team` | Always `"xsoar"`. |
| `metadata.ownership.maintainers` | Always `["@xsoar-content"]`. |
| `settings.allow_skip_verification` | `true` unless the vendor requires successful verification before enabling. |

#### 3.3.1 ID and title naming

`id` and `metadata.title` encode the **same** name from the **master CSV Connector ID** (authoritative; flag if absent), differing only in format: `id` is lowercase with dashes; `title` is Title Case (e.g. `Palo Alto Networks` → id `palo-alto-networks`, title `Palo Alto Networks`). The **connector folder name == `id`**.

**Collision handling** — if the `id` or `title` already exists, append a capability-based suffix to **both** `id` and `title`, and **flag**:

| Capabilities declared | `title` suffix | `id` suffix |
|---|---|---|
| `automation-and-remediation` AND ≥1 collection capability | `Automation and Collection` | `automation-and-collection` |
| Only `automation-and-remediation` | `Automation` | `automation` |
| Only collection capabilities | `Collection` | `collection` |

("Collection" is the umbrella for all fetch capabilities — the suffix never enumerates them.) Example: `Okta` (automation + log-collection) → `okta-automation-and-collection`.

**Flag** if: the master CSV has no Connector ID; the `id` collides; zero capabilities are declared; or the name can't be slugified cleanly.

### 3.4 capabilities.yaml Rules

**Every capability has ≥1 sub-capability** (§3.1.9). A lone sub-capability is `required: true`.

#### Capability mapping

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
   - **Default**: create a sub-capability **only** under **`log-collection`** (`log-collection_<integration>`). Do **NOT** create an `automation-and-remediation` sub-capability for its commands.
   - **EXCEPTION** — also create an `automation-and-remediation` sub-capability (so the integration gets sub-capabilities under **BOTH** `log-collection` **AND** `automation-and-remediation`) if **either**:
     1. the integration has **≥ 3 commands**, **OR**
     2. the integration has **≥ 1 command whose name does NOT contain `get-events`**.
     (If the only commands are `get-events`-style **and** there are **< 3** of them, it stays `log-collection`-only; otherwise it also gets an automation sub-capability.)
   - When the exception applies, the handler's `capabilities[]` lists **both** the `log-collection_<integration>` and `automation-and-remediation_<integration>` entries (handler subscribes to both — §3.8).
   - **`defaultIgnore`**: ALWAYS emitted only on/for the `automation-and-remediation` sub-capability (§3.7). A `log-collection`-only eventcollector integration gets **no** `defaultIgnore`; one that also gets an automation sub-capability **does** (governing its commands).
2. An integration may map to multiple capabilities (e.g. fetch + commands) — emit each, with one sub-capability per integration (`<capability_id>_<integration_id>`).
3. Multiple integrations may share a capability; each is its own sub-capability (`title` = integration name; `id` = `<capability_id>_<integration_id>`).
4. **Flag** (but allow) if two integrations declare the same fetch type, or one integration declares multiple fetch/feed/credential capabilities.
5. When `isFetchEvents`/`isFetchAssets` etc. are set, **omit** the corresponding checkbox param — choosing the capability implies the feature is on. Still emit the related fields (interval, classifier, mapper, alertType, etc.).
6. `fetch-issues`, `log-collection`, `fetch-assets-and-vulnerabilities` are shown only to `agentix`/`xsiam` licenses (via `config.required_license`).
7. **Fetch mutex (per handler/integration)**: a single integration MUST NOT enable more than one of the five fetch capabilities at once (each handler → exactly one XSOAR instance, which cannot have multiple fetches). Multiple fetches across **different** integrations are fine. The UI prevents the conflict (no error) by marking the other fetch sub-capabilities of that same integration `read_only: true` with the message *"Select only one fetch option for this capability"* — enforced via [`triggers.yaml`](README.md:833) (§3.5).

#### Metadata & general_configurations

| Field | Rule |
|---|---|
| `metadata.title` | `"Capabilities"`. |
| `metadata.description` | `"Name and configure the instance capabilities"`. Flag for writer review. |
| `metadata.help` | Tech team to generate. |
| `general_configurations.description` | `"General configurations for all capabilities"`. |
| `general_configurations.configurations` | Include the mandatory `instance_name` field (below). |

> **Note:** `integrationLogLevel` and `defaultIgnore` are **not** in `capabilities.yaml` — they live in `configurations.yaml general_configurations` (§3.7). `defaultIgnore` is emitted **only** for integrations that contribute an `automation-and-remediation` sub-capability (it governs commands; collection-only capabilities have none).

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
| `id` | One of: `automation-and-remediation`, `log-collection`, `fetch-issues`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets`. |
| `title` | Title Case of the id ("Automation and Remediation", "Log Collection", "Fetch Issues", "Fetch Assets and Vulnerabilities", "Threat Intelligence and Enrichment", "Fetch Secrets"). |
| `description` | Tech team / PM / writer to author. |
| `required` | `false`. |
| `config.required_license` | Aggregate of sub-capability licenses (or the integration/pack if none). |

#### Sub-capability rules

| Field | Rule |
|---|---|
| `id` | `<capability_id>_<integration_id>` (integration id lowercased, spaces → dashes). E.g. `automation-and-remediation_hello-world-iam`. |
| `title` | Integration name in Title Case. |
| `description` | From the integration YML. Flag for writer review. |
| `default_enabled` | `false`. |
| `required` | `false`. |
| `config.required_license` | From the integration YML (else parent pack). **Must be a subset of `supportedModules`** (§3.1.1) — flag any superset. |

### 3.5 triggers.yaml

Optional connector-root file defining reactive, reversible UI behavior. See [`README.md`](README.md:833), [`schema/triggers.schema.json`](schema/triggers.schema.json:1), and [`plans/triggers-v2.md`](plans/triggers-v2.md:1) for the full spec. Common migration patterns:

- **Capability → field gating** — reveal/require a field only when a capability is on (e.g. show `feedExpirationInterval` only when `threat-intelligence-and-enrichment` is on AND `feedExpirationPolicy == "interval"`).
- **Field → field gating** — show `longRunningPort` only when `longRunning == true` AND no engine/group is selected AND the integration is engine-excluded.
- **Fetch mutex** (§3.4 note 6) — for every fetch sub-capability of an integration, author one trigger per *other* fetch sub-capability **of the same integration**: condition = that other sub-capability is `on`; effect = `read_only: true` on the current one with message *"Select only one fetch option"*. Only pair sub-capabilities of the **same** integration. For `n` fetch sub-capabilities, emit `n × (n-1)` triggers.

```yaml
triggers:
  - conditions:
      type: capability_condition
      id: log-collection_<i>
      behavior: state
      value: on
    effects:
      - id: fetch-issues_<i>
        action: { read_only: true }
        message: "Select only one fetch option"
  - conditions:
      type: capability_condition
      id: fetch-issues_<i>
      behavior: state
      value: on
    effects:
      - id: log-collection_<i>
        action: { read_only: true }
        message: "Select only one fetch option"
```

### 3.6 connection.yaml Rules

| Field | Rule |
|---|---|
| `metadata.title` | `"Connection"`. |
| `metadata.description` | `"Enter the credentials to securely authorize the connection"`. Flag for writer review. |
| `metadata.help` | Long Markdown: extract connection methods from the integration YMLs + READMEs (auth only — no commands/IO), combined with vendor knowledge. Flag for writer review. |

> Migration of XSOAR type-9 credentials and related auth fields (`displaypassword`, `hiddenusername`, `hiddenpassword`, multi-token) is in scope but the profile language is still being refined. See [`plans/integration-parameter-and-types-overrides.md`](plans/integration-parameter-and-types-overrides.md:1).

#### XSOAR type-9 credential leaf semantics

A `type: 9` credential renders as two leaves — an identifier (`<id>.identifier`) and a password (`<id>.password`). The following YML fields control leaf suppression and labeling:

- **`hiddenusername: true`** — the identifier leaf is suppressed. Do NOT include `<id>.identifier` as a key in `xsoar_param_map`. The `<id>.password` leaf, if not also hidden, MAY still appear.
- **`hiddenpassword: true`** — the password leaf is suppressed. Do NOT include `<id>.password` as a key in `xsoar_param_map`. The `<id>.identifier` leaf, if not also hidden, MAY still appear. (`hiddenpassword` is a real YML field per demisto-sdk's strict-objects schema.)
- **`displaypassword: "<custom label>"`** — overrides the **display name** of the password component of the `type: 9` credential. It does NOT change the underlying leaf id (`<id>.password`); it only changes the UI label. Common use: renaming "Password" to "API Key" / "Token" / "Secret Key" in the form.

#### All connection params live inside the profile

**Do NOT use `connection.yaml general_configurations`.** Every connection parameter — auth secrets, server URL/domain, `proxy`, `engine`/`engine_group`, `insecure` — is declared in `profiles[].configurations[].fields[]`, **once per profile**.

**`metadata.event.publish: true` is MANDATORY on every profile field** except (1) `engine_mode` and (2) any `metadata.auth` secret (§2.17).

#### view_groups (Grouped connectors)

When `settings.grouped: true`, `connection.yaml` declares a top-level `view_groups` registry — **one tile per integration**:

1. One `view_groups[]` entry per integration (the connection-page tile).
2. **Profile → tile binding lives on the profile** (`profiles[].view_group`), not the handler. A profile belongs to exactly one tile.
3. One tile may collect several profiles (multiple auth methods for one integration → same `view_group`, rendered as an auth-method choice; Appendix B).
4. `configurations.yaml` has its own independent `view_groups` registry (§3.7). Handler `auth_options[].view_group` is unused.

> Standard connectors (one handler) don't need `view_groups` — there's a single implicit tile.

#### Profiles

1. For each profile, follow §2.2 and the auth-parameter tagging in §2.6.
2. **Typed profile** (`oauth2_*` / `plain` / `api_key` / `oauth2_jwt_bearer`) when the platform manages the credential lifecycle; **`passthrough`** (§2.6.1) when it can't be cleanly mapped or needs several inputs at once (e.g. Slack v3).
3. **`engine`/`engine_group`/`proxy`/`insecure`** appear once inside each profile that needs them. Because a handler binds to exactly one profile, the user supplies a single value per instance.
4. **`profiles[].view_group`** (Grouped): every profile references one `connection.yaml view_groups[].id`.
   - **A profile cannot be shared across integrations** — each `view_group` belongs to one integration, so declare a **separate profile per integration** even when auth is identical (e.g. `oauth2_client_credentials.salesforce` and `.salesforce-iam`).
5. **One profile per handler — OR, never AND.** A handler binds to a single profile at runtime. Multiple auth methods → separate profiles sharing one `view_group`, advertised as alternatives in `auth_options[]` (user picks one). If an integration needs several inputs simultaneously, model it as one `passthrough` profile.
6. **`metadata.xsoar.interpolated: true`** on every profile (§2.6.2) unless the integration code was rewritten for UCP credential retrieval.

### 3.7 configurations.yaml Rules

> **Source of truth for FE/BE override behavior**: [`plans/integration-parameter-and-types-overrides.md`](plans/integration-parameter-and-types-overrides.md:1).

| Field | Rule |
|---|---|
| `metadata.title` | `"Configuration"`. |
| `metadata.description` | `"Adjust and refine your configuration"`. Flag for writer review. |

#### Principles

1. **All params in manifest** — including backend-managed ones (`engine`, `engine_group`, etc.).
2. **One field per row** (each field its own `fields` block).
3. **Preserve field behavior** — type, default, options, title, id, tooltip, required must match the YML exactly (unless stated otherwise).
4. **`integrationLogLevel`** goes in `general_configurations`, **once per integration's `view_group`** (every capability of an integration needs it; this emits it once). **`defaultIgnore`** is **only relevant when the integration contributes an `automation-and-remediation` sub-capability** — it controls "Do not use in CLI by default" for the integration's **commands**, which collection-only capabilities (`fetch-issues`, `log-collection`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets`) do not have. Omit `defaultIgnore` for integrations with no automation capability; otherwise emit it once per integration's `view_group` alongside `integrationLogLevel`. For Standard connectors, place these in `general_configurations` without a `view_group`. Collisions when >1 integration are resolved via Appendix C.
5. **`longRunning`** is supported

#### NULL vs empty-string

In ConnectUs, fields that are left unfilled are sent to the BE as **NULL** (unless the field declares a `default_value`). This differs from legacy XSOAR, where unfilled fields were sometimes sent as empty strings (`""`).

- Fields that are **backend-managed** (`config_type: backend`, e.g. `engine` — see Appendix J) are managed by the XSOAR BE, which sets an appropriate default value.
- For **non-backend** fields, the integration code must be prepared to handle **NULL** values (not empty strings) for any parameter the user left unset and that has no `default_value`.

#### view_groups (Grouped connectors)

`configurations.yaml` declares its own `view_groups` registry, independent of `connection.yaml` (ids may overlap — each registry scopes only its own file). One tile per integration; may add config-only tiles (e.g. `advanced`). Each `general_configurations.configurations[]` and `configurations[]` entry carries a `view_group`; inner `fields[]` rows must NOT.

#### configurations

1. Each capability/sub-capability has its own configurations, mirroring the underlying integration.
2. Config IDs must be globally unique across the connector (Appendix C).

#### Type mapping

See [Appendix A](#appendix-a-xsoar-type--manifest-type-mapping).

#### Field rules

1. **`id`** = parameter `name` from the YML. Globally unique (Appendix C) — keep the original name; rename only on a real collision.
2. **Title** = `display` from the YML; replace "Incidents" → "Issues" (Platform terminology).
3. **Type** — per Appendix A.
4. **Default** = `defaultvalue` (use platform-specific override if present).
5. **Required** = `required`.
6. **Description** = `additionalinfo` → `options.description`/`help_text`.
7. **Select options** — YML `options` → `{key, label}` pairs.
8. **Exclude** hidden-on-platform params, and auth-related params (type-9 credentials, domain/URL auth fields). For Appendix G integrations, also omit `proxy`/`engine`/`engine_group` entirely; for all others, `proxy`/`insecure` live in the connection profile (§3.6), not here.
9. **Searchable/clearable** — every `select` and `multi_select` field MUST set `options.searchable: true` and `options.clearable: true`.

#### Instance-level properties (now explicit in the manifest)

| Property | Where | `field_type` | `config_type` | Notes |
|---|---|---|---|---|
| `integrationLogLevel` | `configurations.yaml` `general_configurations`, per `view_group` | `select` | `"backend"` | Off/Debug/Verbose. |
| `defaultIgnore` | `configurations.yaml` `general_configurations`, per `view_group` | `checkbox` | `"backend"` | "Do not use in CLI by default". **Only for integrations with an `automation-and-remediation` sub-capability** — it governs commands, which collection-only capabilities don't have. Omit otherwise. |
| `engine` / `engine_group` | connection profile (§3.6) | `select` + `dynamic_values` | `"backend"` | Engine 3-field pattern (below). Omit for Appendix G. |
| `mappingId` (label "Classifier") | `configurations.yaml`, **fetch-issues sub-capability only** | `select` + `dynamic_values` | `"backend"` | When `isFetch`. Provider `xsoar`, `dynamicField: "classifier"`. `default_value` ← `defaultClassifier` (best-effort literal, §2.16). `options.searchable: true`, `options.clearable: true`. Same scoping as `alertType` — never under `log-collection`/`fetch-assets-and-vulnerabilities`/`threat-intelligence-and-enrichment`/`fetch-secrets` or general configurations. |
| `incomingMapperId` (label "Mapper (incoming)") | `configurations.yaml`, **fetch-issues sub-capability only** | `select` + `dynamic_values` | `"backend"` | When `isFetch`. Provider `xsoar`, `dynamicField: "mapper-incoming"`. `default_value` ← `defaultMapperIn` (best-effort literal, §2.16). `options.searchable: true`, `options.clearable: true`. Same scoping as `alertType` — never under `log-collection`/`fetch-assets-and-vulnerabilities`/`threat-intelligence-and-enrichment`/`fetch-secrets` or general configurations. |
| `defaultClassifier` | → `default_value` of `mappingId` | — | — | Not a UI field. Best-effort literal pre-selection (§2.16). |
| `defaultMapperIn` | → `default_value` of `incomingMapperId` | — | — | Not a UI field. Best-effort literal pre-selection (§2.16). |
| `outgoingMapperId` / `defaultMapperOut` | **OUT OF SCOPE** | — | — | Mirroring not supported. |

#### Engine handling — 3-field pattern

Replaces legacy `engine`/`engineGroup`. The three fields live **inside the connection profile** (`connection.yaml profiles[].configurations[].fields[]`), declared once per profile alongside `proxy`/`insecure`. **Shape, IDs, options, and visibility are locked.**

| ID | Type | Default | `event.publish` | `config_type` |
|---|---|---|---|---|
| `engine_mode` | `select` (radio) | `no_engine` | ❌ (the only non-published, non-secret field) | — |
| `engine` | `select` + `dynamic_values` (`dynamicField: engine`) | — | ✅ | `backend` |
| `engine_group` | `select` + `dynamic_values` (`dynamicField: engine-group`) | — | ✅ | `backend` |

`engine_mode` options: `no_engine` ("No engine"), `engine` ("Engine"), `engine_group` ("Engine Group").

**Mandatory** empty-state messages: `engine` → `empty_values_message: "No engines available"`; `engine_group` → `"No engine groups available"`.

**Visibility** via `triggers.yaml`: hide `engine` when `engine_mode != "engine"`; hide `engine_group` when `engine_mode != "engine_group"`.

```yaml
# connection.yaml — inside a profile's configurations[].fields[]
- id: engine_mode
  field_type: select
  title: Engine
  options:
    required: true
    default_value: no_engine
    values:
      - { key: no_engine, label: "No engine" }
      - { key: engine, label: "Engine" }
      - { key: engine_group, label: "Engine Group" }
- id: engine
  field_type: select
  title: Engine
  metadata:
    event: { publish: true }
    xsoar: { config_type: backend }
    dynamic_values:
      provider: xsoar
      trigger: [on_create, on_edit]
      params: { integrationID: "<integration-id>", dynamicField: engine }
  options:
    empty_values_message: "No engines available"
- id: engine_group
  field_type: select
  title: Engine Group
  metadata:
    event: { publish: true }
    xsoar: { config_type: backend }
    dynamic_values:
      provider: xsoar
      trigger: [on_create, on_edit]
      params: { integrationID: "<integration-id>", dynamicField: engine-group }
  options:
    empty_values_message: "No engine groups available"
```

```yaml
# triggers.yaml — visibility
triggers:
  - conditions: { type: condition, id: engine_mode, operator: neq, behavior: { value: engine } }
    effects: [{ id: engine, action: { hidden: true } }]
  - conditions: { type: condition, id: engine_mode, operator: neq, behavior: { value: engine_group } }
    effects: [{ id: engine_group, action: { hidden: true } }]
```

#### Proxy field — conditional read-only

The `proxy` field (a `checkbox`) lives in the same connection profile alongside the engine fields. Its title is **"Use system proxy settings"**. Proxy routing is only meaningful when traffic flows through an engine or engine group, so:

- **`proxy` is `read_only` (locked, unchecked) while `engine_mode == "no_engine"`** (i.e. no engine and no engine group is chosen).
- **Once the user selects an engine OR an engine group** (`engine_mode == "engine"` OR `engine_mode == "engine_group"`), `proxy` becomes editable so the user can check it.
- A tooltip explains the lock: **"Use system proxy settings is enabled only when an engine or engine group are chosen."**

The lock is enforced via a reversible [`triggers.yaml`](README.md:833) effect: `read_only: true` while `engine_mode == "no_engine"`, automatically reversed when an engine/engine group is selected.

| ID | Type | Title | Default | `event.publish` | `config_type` |
|---|---|---|---|---|---|
| `proxy` | `checkbox` | "Use system proxy settings" | `false` | ✅ | — (not backend-managed; see Appendix J) |

```yaml
# connection.yaml — inside the same profile's configurations[].fields[]
- id: proxy
  field_type: checkbox
  title: "Use system proxy settings"
  metadata:
    event: { publish: true }
  options:
    mask: false
    default_value: false
    help_text: "Use system proxy settings is enabled only when an engine or engine group are chosen."
```

```yaml
# triggers.yaml — lock proxy until an engine or engine group is chosen
triggers:
  - conditions: { type: condition, id: engine_mode, operator: eq, behavior: { value: no_engine } }
    effects:
      - id: proxy
        action: { read_only: true }
        message: "Use system proxy settings is enabled only when an engine or engine group are chosen."
```

> The trigger is reversible (§2.10): when `engine_mode` changes away from `no_engine` (to `engine` or `engine_group`), the `read_only` lock is lifted and the user can toggle `proxy`.

#### Insecure field — always editable

The `insecure` field (a `checkbox`) also lives in the same connection profile. Its title is **"Trust any certificate (not secure)"**, it defaults to **off** (`false`), and — unlike `proxy` — it is **always editable** (`read_only: false` at all times, no engine gating, no trigger).

| ID | Type | Title | Default | `read_only` | `event.publish` | `config_type` |
|---|---|---|---|---|---|---|
| `insecure` | `checkbox` | "Trust any certificate (not secure)" | `false` | always `false` | ✅ | — (not backend-managed; see Appendix J) |

```yaml
# connection.yaml — inside the same profile's configurations[].fields[]
- id: insecure
  field_type: checkbox
  title: "Trust any certificate (not secure)"
  metadata:
    event: { publish: true }
  options:
    mask: false
    default_value: false
    create_modifiers: { required: false, read_only: false, hidden: false }
    edit_modifiers: { required: false, read_only: false, hidden: false }
```

**Carve-outs:** [Appendix G](#appendix-g-engine--proxy-exclusion-list) — emit none of the engine fields and no `proxy`. [Appendix H](#appendix-h-single-engine-integrations) — emit `engine_mode` (2 options: `no_engine` + `engine`) and `engine` only; omit `engine_group` (the proxy read-only rule still applies, gated on `engine_mode == "no_engine"`). If the FE lacks a horizontal-radio `select`, fall back to plain `select` (IDs/keys/triggers unchanged).

#### BE-auto-added params (now explicit)

When a `script` flag is true, the BE used to auto-add params. Define them explicitly. **Omit** the implied checkbox (`isFetch`, `feed`, `isFetchEvents`, `isFetchAssets`, `isFetchCredentials`) — enabling the capability implies it.

**`script.IsFetch: true`** → `fetch-issues` sub-capability:
- `alertFetchInterval` — `duration` default to 1 minute or whats given in integration YML.
- `incidentType`/`alertType` (Platform uses `alertType`) — `select` + `dynamic_values` (`dynamicField: "incident-type"`). **User-visible** (do NOT mark backend). Title "Issue Type", tooltip "select if classifier doesn't exist".
  - Placed under **each** `fetch-issues` sub-capability's `configurations[]` (pinned to that integration's `view_group`) — never in `general_configurations` or on the parent capability.
  - **Always emit** for every `fetch-issues` sub-capability, regardless of whether the YML has a type-13 param.
  - Never emit under non-issue fetch sub-capabilities.
  - When `script.isfetchsamples: true`, force it always-visible.
- `mappingId` — label "Classifier", `select` + `dynamic_values` (provider `xsoar`, `dynamicField: "classifier"`), `config_type: backend`. `default_value` ← integration YML `defaultClassifier` (best-effort literal, §2.16). `options.searchable: true`, `options.clearable: true`. Placed only under each `fetch-issues_<integration>` sub-capability (like `alertType`) — never under other fetch capabilities or general configurations.
- `incomingMapperId` — label "Mapper (incoming)", `select` + `dynamic_values` (provider `xsoar`, `dynamicField: "mapper-incoming"`), `config_type: backend`. `default_value` ← integration YML `defaultMapperIn` (best-effort literal, §2.16). `options.searchable: true`, `options.clearable: true`. Placed only under each `fetch-issues_<integration>` sub-capability (like `alertType`) — never under other fetch capabilities or general configurations.

```yaml
# inside the fetch-issues_<integration> sub-capability
- id: "alertType"
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
- `feedIncremental` — `checkbox`. **Only emit if the YML declares it.** Place it **only** under the integration's `threat-intelligence-and-enrichment_<integration>` (feed) sub-capability — never under any other capability or in general configurations.

**`script.IsFetchEvents: true`** → `log-collection`: `eventFetchInterval` — `duration` (default 1 min → `{minutes: 1}`).

**`script.IsFetchAssets: true`** → `fetch-assets-and-vulnerabilities`: `assetsFetchInterval` — `duration` (default `{minutes: 1}`).

**`script.LongRunning: true`** → the relevant fetch capability:
- `longRunning` — `checkbox`, backend-managed.
- `longRunningPort` — `input`, backend-managed; visible only when `longRunning == true` AND no engine/group selected (trigger, §3.5).

**`script.IsFetchCredentials: true`** → `fetch-secrets` (omit the `isFetchCredentials` checkbox).

#### Ignored during migration

- `section` (Connect/Collect/Optimize/Mirroring/Result) — manifest organizes by capability.
- `advanced: true` — emit as a regular field; note in Gap Analysis (§3.2 open).
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

> The schema also supports `test_connection.type: "endpoint"` with `host` (+ `{tenant_id}`) and `headers` for direct HTTP verification.

#### capabilities section

1. Each handler maps to exactly **one** integration.
2. An integration with fetch + commands subscribes to both `automation-and-remediation` and the relevant fetch capability.
3. **`auth_options[].id`** references a `connection.yaml` profile id only. The tile comes from the **profile's** `view_group` (§3.6) — do NOT put `view_group` on the handler.
4. **`auth_options[]` are OR** (alternatives) — never AND. Multiple methods → separate entries referencing profiles that share a `view_group`. Several simultaneous inputs → one `passthrough` profile.
5. **Workloads** always `["xsoar-pod"]`.

```yaml
# single capability
capabilities:
  - id: "<capability-id>"
    workloads: ["xsoar-pod"]
# sub-capability
capabilities:
  - id: "<parent-capability-id>/<sub-capability-id>"
    workloads: ["xsoar-pod"]
```

#### Actions per sub-capability

Emit `actions[]` on the relevant **sub-capability** entry, derived mechanically from the YML fetch flags:

| YML flag (Platform) | Sub-capability | `actions[].type` |
|---|---|---|
| `isfetch: true` | `fetch-issues_<i>` | `reset_incidents_last_run` |
| `isfetchevents: true` | `log-collection_<i>` | `reset_events_last_run` |
| `isfetchassets: true` | `fetch-assets-and-vulnerabilities_<i>` | `reset_assets_last_run` |
| `feed: true` | `threat-intelligence-and-enrichment_<i>` | `reset_feed_last_run` |
| `isFetchCredentials: true` | `fetch-secrets_<i>` | *(none)* |
| **Microsoft Teams only** | `automation-and-remediation_microsoft-teams` | `reset_integration_context` (manual) |

**Rules:** one action per fetch sub-capability; never on the parent capability; `reset_integration_context` is Microsoft-Teams-only (manual); omit `display`/`description` (platform defaults); if a flag is hidden on Platform, omit its action too.

```yaml
capabilities:
  - id: "automation-and-remediation_my-integration"
    auth_options:
      - { id: "oauth2_client_credentials.my_profile", workloads: ["xsoar-pod"] }
  - id: "fetch-issues_my-integration"
    auth_options:
      - { id: "oauth2_client_credentials.my_profile", workloads: ["xsoar-pod"] }
    actions: [{ type: "reset_incidents_last_run" }]
  - id: "log-collection_my-integration"
    auth_options:
      - { id: "oauth2_client_credentials.my_profile", workloads: ["xsoar-pod"] }
    actions: [{ type: "reset_events_last_run" }]
```

### 3.9 serializer.yaml

Use a serializer when a connector field id differs from the integration's expected param name (collision prefixes; connection-profile field remapping). **Not always required.** Create it at `components/handlers/<handler-folder>/serializer.yaml`.

**Field id naming**: keep the original param name when unique; on a real collision, apply [Appendix C](#appendix-c-field-id-uniqueness-rule) — alphabetically-first integration keeps the name (no serializer entry); others are prefixed and remapped.

- **`field_mappings`** — see §2.9.
- **`computed_fields`** — synthetic outputs from connector state; evaluated against original field IDs (§2.9).

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

**Rules:** keep the default block; add `/connectors/<name>/** ...` after the catch-all; and for every new connector add `@jmizrahi @juschwartz @yhayun` as codeowners.

---

## Section 4: Worked Reference — Salesforce Connector (Grouped)

A complete **Grouped** connector template consolidating two integrations — **Salesforce** and **Salesforce IAM** — each its own handler + sub-capability + connection tile. Files under [`connectors/salesforce/`](connectors/salesforce/).

```text
connectors/salesforce/
├── connector.yaml
├── connection.yaml
├── capabilities.yaml
├── configurations.yaml
└── components/handlers/
    ├── salesforce/        { handler.yaml, serializer.yaml }
    └── salesforce-iam/    { handler.yaml, serializer.yaml }
```

It exercises the Grouped rules (§3.6–§3.8): `settings.grouped: true`; one connection tile per integration; **all connection params inside profiles** (no `general_configurations` connection block); profile→tile binding via `profiles[].view_group`; per-integration profiles (Salesforce offers two auth methods sharing one tile; IAM uses one); per-integration sub-capabilities; per-handler serializers remapping `domain` to each integration's param.

**Collision note (Appendix C):** `salesforce` < `salesforce-iam`, so Salesforce keeps original ids (`domain`, `integrationLogLevel`, `defaultIgnore`); Salesforce IAM prefixes (`salesforce-iam_domain`, etc.) with serializer remappings. The second Salesforce profile suffixes its second `domain` field (`salesforce_domain`) only for intra-connector uniqueness.

### 4.1 connector.yaml

```yaml
# yaml-language-server: $schema=../../schema/connector.schema.json
id: "salesforce"
metadata:
  title: "Salesforce"
  description: "Salesforce CRM services for identity management, automation, remediation and SaaS Posture Security"
  version: 1.0.0
  categories: ["Case Management"]
  tags: ["Security"]
  vendor: "Salesforce"
  publisher: "Palo Alto Networks"
  author_image: "salesforce-ic.svg"
  documentation: "https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-3.x-Documentation/Ingest-and-run-Salesforce-automation-and-remediation"
  ownership:
    team: "xsoar"
    maintainers: ["@xsoar-content"]
settings:
  allow_skip_verification: false
  grouped: true
```

### 4.2 connection.yaml

```yaml
# yaml-language-server: $schema=../../schema/connection.schema.json
metadata:
  title: "Connection"
  description: "Enter the credentials to securely authorize the connection"

view_groups:
  - { id: "salesforce", label: "Salesforce", help_text: "Salesforce integration credentials. Offers Client Credentials or Authorization Code." }
  - { id: "salesforce-iam", label: "Salesforce IAM", help_text: "Salesforce IAM integration credentials." }

profiles:
  # ── Salesforce — auth method 1 (Client Credentials), tile: salesforce ──
  - id: "oauth2_client_credentials.salesforce"
    type: "oauth2_client_credentials"
    title: "OAuth 2.0 Client Credentials Flow"
    description: "Server-to-server authentication using client credentials"
    view_group: "salesforce"
    configurations:
      - fields:
          - id: "domain"            # alphabetically first → keeps original id
            title: "Domain URL"
            field_type: "input"
            metadata: { event: { publish: true } }
            options:
              mask: false
              placeholder: "https://<my_domain>"
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: false, read_only: true }
          - id: "client_key"
            title: "Consumer Key (Client ID)"
            field_type: "input"
            metadata: { auth: { parameter: "client_key" } }   # secret → not published
            options:
              mask: false
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: true }
          - id: "sf_client_secret"
            title: "Consumer Secret"
            field_type: "input"
            metadata: { auth: { parameter: "client_secret" } }
            options:
              mask: true
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: true }

  # ── Salesforce — auth method 2 (Authorization Code), SAME tile ──
  - id: "oauth2_authorization_code.salesforce"
    type: "oauth2_authorization_code"
    title: "OAuth 2.0 Authorization Web Server Flow"
    description: "Acts on behalf of a user. Requires interactive login."
    view_group: "salesforce"
    client_id: "{SAAS_REGISTRY.SALESFORCE_CORE_CLIENT_ID}"
    client_secret: "{SAAS_REGISTRY.SALESFORCE_CORE_CLIENT_SECRET}"
    refresh_token_scope: "refresh_token"
    configurations:
      - fields:
          - id: "salesforce_domain"   # suffixed for intra-connector uniqueness
            title: "Domain URL"
            field_type: "input"
            metadata: { event: { publish: true } }
            options:
              mask: false
              placeholder: "https://<my_domain>"
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: false, read_only: true }

  # ── Salesforce IAM — own tile ──
  - id: "oauth2_client_credentials.salesforce-iam"
    type: "oauth2_client_credentials"
    title: "OAuth 2.0 Client Credentials Flow"
    description: "Server-to-server authentication for the Salesforce IAM integration"
    view_group: "salesforce-iam"
    discovery_url: "https://{{salesforce-iam_domain}}/.well-known/openid-configuration"
    configurations:
      - fields:
          - id: "salesforce-iam_domain"   # loses collision → prefixed
            title: "Domain URL"
            field_type: "input"
            metadata: { event: { publish: true } }
            options:
              mask: false
              placeholder: "https://<my_domain>"
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: false, read_only: true }
          - id: "salesforce-iam_client_key"
            title: "Consumer Key (Client ID)"
            field_type: "input"
            metadata: { auth: { parameter: "client_key" } }
            options:
              mask: false
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: true }
          - id: "salesforce-iam_client_secret"
            title: "Consumer Secret"
            field_type: "input"
            metadata: { auth: { parameter: "client_secret" } }
            options:
              mask: true
              create_modifiers: { required: true, hidden: false }
              edit_modifiers: { required: true, hidden: true }
```

### 4.3 capabilities.yaml

```yaml
# yaml-language-server: $schema=../../schema/capabilities.schema.json
metadata:
  title: "Capabilities"
  description: "Name and configure the instance capabilities"

general_configurations:
  description: "General configurations for all capabilities"
  configurations:
    - fields:
        - id: "instance_name"
          title: "Instance name"
          field_type: "input"
          metadata: { connector: { parameter: "instance_name" } }
          validations:
            - trigger: "change"
              rules:
                - type: "pattern"
                  value: "^[a-zA-Z0-9 _-]+$"
                  message: "Only alphanumeric characters, spaces, underscores, and hyphens are allowed."
                - type: "async"
                  validation_type: "uniqueness"
          options:
            placeholder: "Please Enter Name for an Instance"
            create_modifiers: { required: true, read_only: false, hidden: false }
            edit_modifiers: { required: true, read_only: false, hidden: false }
# integrationLogLevel / defaultIgnore live in configurations.yaml (§3.7), not here.

capabilities:
  - id: "automation-and-remediation"
    title: "Automation and Remediation"
    description: "Automate identity lifecycle management including user provisioning, updates, and access control"
    default_enabled: true
    required: false
    labels: ["Recommended"]
    config:
      required_license: ["agentix", "xsiam", "edr", "cloud", "cloud_runtime_security"]
    sub_capabilities:
      - { id: "automation-and-remediation_salesforce", title: "Salesforce", description: "Automation and remediation for the Salesforce integration.", default_enabled: false }
      - { id: "automation-and-remediation_salesforce-iam", title: "Salesforce IAM", description: "Identity lifecycle management for the Salesforce IAM integration.", default_enabled: false }
```

### 4.4 configurations.yaml (key sections)

```yaml
# yaml-language-server: $schema=../../schema/configurations.schema.json
metadata:
  title: "Configuration"
  description: "Adjust and refine your configuration"

view_groups:
  - { id: "salesforce", label: "Salesforce" }
  - { id: "salesforce-iam", label: "Salesforce IAM" }

# integrationLogLevel + defaultIgnore — once per view_group (§3.7 rule 4).
# salesforce wins the collision → keeps original ids (no serializer); salesforce-iam prefixes.
general_configurations:
  description: "Per-integration general settings shared across the integration's capabilities."
  configurations:
    - view_group: "salesforce"
      fields:
        - id: "integrationLogLevel"
          title: "Integration Log Level"
          field_type: "select"
          metadata: { xsoar: { config_type: "backend" } }
          options:
            description: "Set the log level for the Salesforce integration"
            placeholder: "Select log level"
            default_value: "Off"
            values: [{ key: "Off", label: "Off" }, { key: "Debug", label: "Debug" }, { key: "Verbose", label: "Verbose" }]
            create_modifiers: { required: false, hidden: false }
            edit_modifiers: { required: false, hidden: false }
        - id: "defaultIgnore"
          title: "Do not use in CLI by default"
          field_type: "checkbox"
          metadata: { xsoar: { config_type: "backend" } }
          options:
            default_value: false
            create_modifiers: { required: false, hidden: false }
            edit_modifiers: { required: false, hidden: false }
    - view_group: "salesforce-iam"
      fields:
        - id: "salesforce-iam_integrationLogLevel"
          title: "Integration Log Level"
          field_type: "select"
          metadata: { xsoar: { config_type: "backend" } }
          options:
            description: "Set the log level for the Salesforce IAM integration"
            placeholder: "Select log level"
            default_value: "Off"
            values: [{ key: "Off", label: "Off" }, { key: "Debug", label: "Debug" }, { key: "Verbose", label: "Verbose" }]
            create_modifiers: { required: false, hidden: false }
            edit_modifiers: { required: false, hidden: false }
        - id: "salesforce-iam_defaultIgnore"
          title: "Do not use in CLI by default"
          field_type: "checkbox"
          metadata: { xsoar: { config_type: "backend" } }
          options:
            default_value: false
            create_modifiers: { required: false, hidden: false }
            edit_modifiers: { required: false, hidden: false }

configurations:
  - id: "automation-and-remediation_salesforce"
    view_group: "salesforce"
    configurations:
      - fields:
          - id: "user_operations"
            title: "User Operations"
            field_type: "checkbox_group"
            options:
              description: "Select allowed user lifecycle operations"
              default_value:
                - { key: "create_user_enabled", value: true }
                - { key: "update_user_enabled", value: true }
                - { key: "enable_user_enabled", value: true }
                - { key: "disable_user_enabled", value: true }
              create_modifiers: { required: false, read_only: false, hidden: false }
              edit_modifiers: { required: false, read_only: false, hidden: false }
            fields:
              - { id: "create_user_enabled", title: "Allow creating users" }
              - { id: "update_user_enabled", title: "Allow updating users" }
              - { id: "enable_user_enabled", title: "Allow enabling users" }
              - { id: "disable_user_enabled", title: "Allow disabling users" }

  - id: "automation-and-remediation_salesforce-iam"
    view_group: "salesforce-iam"
    configurations:
      - fields:
          - id: "create_if_not_exists"   # unique to IAM → keep original id
            title: "Automatically create user if not found"
            field_type: "switch"
            options:
              description: "Automatically create user if not found in update and enable commands"
              default_value: true
              create_modifiers: { required: false, read_only: false, hidden: false }
              edit_modifiers: { required: false, read_only: false, hidden: false }
```

### 4.5 handlers/salesforce/handler.yaml

Two auth options (OR), both referencing `salesforce`-tile profiles. No `view_group` on the handler.

```yaml
# yaml-language-server: $schema=../../../../../schema/handler.schema.json
id: "xsoar-salesforce"
metadata:
  version: "1.0.0"
  description: "XSOAR handler for Salesforce integration"
  module: "xsoar"
  tags: ["crm", "automation"]
  ownership:
    team: "xsoar"
    maintainers: ["@xsoar-content"]
enabled: true
triggering:
  type: "PUB_SUB"
  labels: { xsoar-integration-id: "Salesforce", xsoar-pack-id: "Salesforce" }
  args: {}
capabilities:
  - id: "automation-and-remediation_salesforce"
    auth_options:
      - { id: "oauth2_client_credentials.salesforce", scopes: ["api", "chatter_api", "refresh_token", "offline_access"], workloads: ["xsoar-pod"] }
      - { id: "oauth2_authorization_code.salesforce", scopes: ["api", "chatter_api"], workloads: ["xsoar-pod"] }
test_connection:
  type: "service"
  service: "xsoar"
  endpoint: "/settings/integration/connector/verification"
```

### 4.6 handlers/salesforce-iam/handler.yaml

```yaml
# yaml-language-server: $schema=../../../../../schema/handler.schema.json
id: "xsoar-salesforce-iam"
metadata:
  version: "1.0.0"
  description: "XSOAR handler for Salesforce IAM integration"
  module: "xsoar"
  tags: ["iam", "identity"]
  ownership:
    team: "xsoar"
    maintainers: ["@xsoar-content"]
enabled: true
triggering:
  type: "PUB_SUB"
  labels: { xsoar-integration-id: "Salesforce IAM", xsoar-pack-id: "Salesforce" }
  args: {}
capabilities:
  - id: "automation-and-remediation_salesforce-iam"
    auth_options:
      - { id: "oauth2_client_credentials.salesforce-iam", scopes: ["api", "chatter_api", "refresh_token", "offline_access"], workloads: ["xsoar-pod"] }
test_connection:
  type: "service"
  service: "xsoar"
  endpoint: "/settings/integration/connector/verification"
```

### 4.7 handlers/salesforce/serializer.yaml

Both Salesforce domain fields map to `InstanceURL` (only one active at runtime). `integrationLogLevel`/`defaultIgnore` won the collision → no entries.

```yaml
field_mappings:
  - { id: "domain", field_name: "InstanceURL" }
  - { id: "salesforce_domain", field_name: "InstanceURL" }
```

### 4.8 handlers/salesforce-iam/serializer.yaml

IAM lost every collision → all shared fields prefixed and remapped.

```yaml
field_mappings:
  - { id: "salesforce-iam_domain", field_name: "url" }
  - { id: "salesforce-iam_integrationLogLevel", field_name: "integrationLogLevel" }
  - { id: "salesforce-iam_defaultIgnore", field_name: "defaultIgnore" }
```

---

## Section 5: Your Task

### 5.1 Inputs

This document; the connector (provider) name; the XSOAR Pack content (integration YML paths); the manifest repo [`README.md`](README.md:1); and the [`schema/`](schema/) directory.

### 5.2 Outputs

1. **Integration Inventory** — a per-integration table covering every §3.10 item.
2. **Scoping Decisions** — command name collisions; params needing special support or marketplace-specific handling; duplicate field IDs needing serializer mappings.
3. **Connector YAML files** — `connector.yaml`, `connection.yaml`, `capabilities.yaml`, `configurations.yaml`, `triggers.yaml` (when a §3.5 pattern applies), `summary.yaml`, all `handler.yaml`, all `serializer.yaml`. Follow Section 3.
4. **Gap Analysis** — numbered gaps with severity (🔴 CRITICAL, 🟡 MEDIUM, 🟢 LOW/RESOLVED).
5. **Decisions Needed** — numbered decisions for PMs/Engineering, with options and recommendations.
6. **Appendix** — directory structure.

---

## Appendix A: XSOAR Parameter Type → Manifest Type Mapping

XSOAR types in use (if you come across another type when migrating, fail and raise a flag).
Also see [`plans/integration-parameter-and-types-overrides.md`](plans/integration-parameter-and-types-overrides.md) for special-param details.

| XSOAR Type | Description | UCP `field_type` | `options.mask` | Notes |
|---|---|---|---|---|
| 0 | Short String / Text | `input` | `false` | Standard text input. |
| 1 | Number / Integer | `input` | `false` | Text input (no separate number type in UCP). Example: `max_fetch`. |
| 4 | Encrypted / Password | `input` | `true` | Masked input for secrets. Example: ApiKey. |
| 8 | Boolean / Checkbox | `checkbox` | N/A | Single boolean toggle. |
| 9 | Credentials / Authentication | **OUT OF SCOPE** | — | Handled by connection profiles. Type 9 params are removed by the auth migration script. |
| 12 | Long Text / TextArea | `text_area` | `false` | Multi-line text. |
| 13 | Incident Type | `select` + `metadata.dynamic_values` | `false` | Option list fetched at runtime via the XSOAR provider (`dynamicField: "incident-type"`). **User-visible field** |
| 14 | Encrypted Text Area | `text_area` | `true` | Masked textarea. Example: SSHKey. |
| 15 | Single Select / Dropdown | `select` | `false` | Options from YML `options` array as `{key, label}` pairs. |
| 16 | Multi Select | `multi_select` | `false` | Native UCP field type. Items in `values` use `{key, label}`; `default_value` is an array of keys. See README [Multi-Select Example](README.md:1681). |
| 17 | Feed Expiration Policy | `select` | `false` | Hardcoded display labels: `Indicator Type` / `Time Interval` / `Never Expire` / `When removed from the feed`. Only added when `script.Feed: true`. |
| 18 | Indicator / Feed Reputation | `select` | `false` | New mapped values: `Unknown` / `Benign` / `Suspicious` / `Malicious` (not the legacy None/Good/Suspicious/Bad). Only added when `script.Feed: true`. |
| 19 | Feed Fetch Interval | `duration` | `false` | Multi-unit duration field — `units: ["days","hours","minutes"]`, `output_format: "minutes"`. Convert the YML minutes-string default to a per-unit `default_value` (§2.15). Use [`triggers.yaml`](README.md:833) for conditional visibility (§3.5). |
| 22 | Copy to Clipboard | `label` | `false` | Read-only; appears only in Generic Webhook — likely ignorable. |

**Important Notes:**

- Whenever you see the string "Incidents" in the YML, change it to "Issues" — this is the correct terminology for the Platform marketplace where ConnectUs is supported (e.g., "Fetch Incidents" → "Fetch Issues").
- If you come across a type not listed above when migrating, fail and raise a flag.

## Appendix B: Authentication Frontend Rendering

When the platform transforms `handler.yaml` auth configurations for the frontend:

- **Single auth option** → rendered as a single form.
- **Multiple auth options** (profiles sharing a `view_group`) → rendered as a selection (radio/dropdown), user picks ONE.
- **Combined auth** (`methods` array) → rendered as grouped form sections, user configures ALL.

## Appendix C: Field ID Uniqueness Rule

All field IDs must be globally unique across the entire connector directory — across [`connection.yaml`](README.md:162), [`capabilities.yaml`](README.md:509), and [`configurations.yaml`](README.md:719) (including `checkbox_group` item IDs). This is enforced by OPA validation (xref Check covering field_entries).

**Default: keep the original id.** Each field's `id` is the original integration param `name`. Do **not** proactively prefix/suffix — keep the original name whenever it is already unique across the connector. A field that keeps its original id needs **no** serializer entry. This minimizes serializer work.

### Deterministic collision rule (always applied the same way)

A **collision** is when two or more fields anywhere in the connector would otherwise share the same `id`. Resolve every collision with this exact, order-independent algorithm:

1. **Identify** the full set of integrations that contribute a field with the colliding id.
2. **Sort** those integrations by their **normalized integration id** (the `commonfields.id` lowercased, spaces → dashes — the same normalization as the handler-folder name, §3.8) in ascending lexicographic order.
3. **The first integration in that sorted order KEEPS the original id** (no prefix, no serializer entry).
4. **Every OTHER colliding integration prefixes its field** with `<normalized-integration-id>_<original-id>` and adds a [`serializer.yaml`](README.md:1381) `field_mappings` entry mapping the prefixed id back to the original param name (`field_name: "<original-id>"`).

So for `proxy` appearing in `Salesforce`, `Salesforce IAM`, and `EC` → normalized `ec`, `salesforce`, `salesforce-iam` → **`ec` keeps `proxy`**; the other two become `salesforce_proxy` and `salesforce-iam_proxy` (each with a serializer mapping back to `proxy`). Only **N − 1** of the colliding fields are renamed.

Determinism guarantees:
- The winner that keeps the original id is always the alphabetically-first normalized integration id — independent of processing order.
- The prefix is always `<normalized-integration-id>_`, never an ad-hoc abbreviation.
- Fields that do **not** collide are **never** renamed.

> This rule is the single source of truth for id collisions everywhere in the guide (config fields, `integrationLogLevel`, `defaultIgnore`, `alertType`, engine fields, `domain`, etc.). Wherever a prefixed id appears in this guide, it follows exactly this rule.

## Appendix D: Excluded Integrations (Out of Scope)

The following integrations are excluded from the migration. If the LLM encounters one of these in the input pack list, it must skip the integration and surface a note in the Gap Analysis.

| Category / Integration | Reason |
|---|---|
| `Generic Webhook` | Generic webhook integration — not a vendor-specific connector. |
| Any integration with `defaultEnabled: true` in its YML | Default-instance (auto-enabled) integrations are out of scope. |
| `Image OCR` | `defaultEnabled: true` — default-instance integration; out of scope. |
| `Rasterize` | `defaultEnabled: true` — default-instance integration; out of scope. |
| `WildFire-Reports` | `defaultEnabled: true` — default-instance integration; out of scope. |
| Contributed integrations (partner + community) | Not maintained by the core content team; out of scope for the unified-connector migration. |
| Deprecated integrations | Will not be migrated. Users will be pointed to the replacement connector (see §3.2.2 open item about deprecated-pack redirect text). |
| `Cortex Core - IOC` (`CoreIOCs`), `Cortex Core - IR` (`CortexCoreIR`), `XQL Query Engine` (`CortexCoreXQLQueryEngine`), `Cortex Core - Platform` (`CortexPlatformCore`), `Core REST API` | Internal Cortex core integrations — always excluded.  |
| `Salesforce` | Migrated manually in April — all Salesforce integrations excluded. |
| `AWS`, `GCP`, `Azure` | Already onboarded to the **cooc** experience — excluded from ConnectUs migration.  |

## Appendix E: Integrations Requiring Manual Migration

The following integrations require manual migration because their authentication, configuration, or runtime behavior is too complex for the automated migration rules. Skip these in the automated pass and flag them in the Decisions Needed section. This list will grow.

| Integration | Reason |
|---|---|
| **SAP BTP** | Complex inter-dependent conditional auth-option triggers — the integration's connection screen needs to show/hide auth fields based on multiple inter-dependent selections that today cannot be expressed cleanly in [`connection.yaml`](README.md:162) + [`triggers.yaml`](README.md:833). Migrate manually and consult the connection-screen designs before authoring. |
| **Microsoft Teams** | Requires a manual `reset_integration_context` action on the `automation-and-remediation_microsoft-teams` sub-capability. The action is NOT derivable from any XSOAR YML flag — it is Microsoft-Teams-only and must be added manually by the migration author per the §3.8 "Actions per sub-capability" rules. Microsoft Teams also triggers Appendix G (no engine/proxy fields) and Appendix I (server-style — `xsoar-long-running-credentials-profile-id` label on the handler); ensure all three carve-outs are applied. |

This list will grow as additional complex cases are identified during the migration program.

## Appendix F: Joint Migration With the SaaS Team

The following vendor connectors are owned jointly with the SaaS team. SaaS already maintains (or is actively building) handlers for these connectors. Any XSOAR handler being migrated into one of these must be added to the **existing** connector directory — not into a fresh `connectors/<vendor>/` tree — and the merge must be coordinated with the SaaS team owners (see [`CODEOWNERS`](CODEOWNERS:1)).

| Integration | Notes |
|---|---|
| **G-Suite (Google Workspace)** | Joint with SaaS — existing [`connectors/googleworkspace/`](connectors/googleworkspace/) has SaaS handlers; coordinate XSOAR handler additions. |
| **Salesforce** | Joint with SaaS — existing [`connectors/salesforce/`](connectors/salesforce/). |
| **M365 (Microsoft 365)** | Joint with SaaS — existing [`connectors/microsoft365/`](connectors/microsoft365/). |
| **MS Teams** | Joint with SaaS — if shipped as a separate connector ([`connectors/microsoft-teams/`](connectors/microsoft-teams/)); otherwise rolled into M365. |
| **Claude** | Joint with SaaS — agentic capability lives alongside any XSOAR handler. |
| **Jira** (stretch) | Joint with SaaS — stretch goal for the quarter. |

## Appendix G: Engine / EngineGroup / Proxy Exclusion List

Integrations listed below must have **no `engine_mode`, `engine`, `engine_group`, or `proxy` fields emitted at all** in their connector manifest — none of the three engine fields from the §3.7 "Engine handling — 3-field pattern" sub-section, and no `proxy` field either. They run as long-running servers/listeners or are platform-native handlers. Match is case-insensitive against the integration `commonfields.id`.

> **Note**: `AWS`, `Azure`, and `GCP` are **not** listed here because they are **fully excluded from migration** (cooc — see [Appendix D](#appendix-d-excluded-integrations-out-of-scope)).

| Integration ID | Why excluded |
|---|---|
| `EDL` | Long-running External Dynamic List server — serves indicators over HTTP; no outbound calls through an engine/proxy. |
| `ExportIndicators` | Long-running indicator export server — same model as EDL. |
| `PingCastle` | Standalone scanner integration; no outbound proxy / engine dependency. |
| `Publish List` | Long-running list-publishing server. |
| `Simple API Proxy` | The integration **is** the proxy — emitting a proxy field would be circular. |
| `Syslog v2` | Long-running syslog listener. |
| `TAXII Server` | Long-running TAXII 1.x server. |
| `TAXII2 Server` | Long-running TAXII 2.x server. |
| `Web File Repository` | Long-running HTTP file repository server. |
| `Workday_IAM_Event_Generator` | Long-running event generator. |
| `XSOAR-Web-Server` | Generic long-running HTTP server integration. |
| `Microsoft Teams` | Platform-native handler — networking handled outside the standard engine/proxy model. |
| `AWS-SNS-Listener` | Long-running AWS SNS push listener. |

If the author encounters one of these integrations during automated migration, it must skip the `engine_mode`, `engine`, `engine_group`, and `proxy` field rules entirely for that integration (no `engine_mode`, `engine`, `engine_group`, or `proxy` fields emitted at all) and note the exclusion in the Gap Analysis output.

## Appendix H: Single-Engine Integrations

The legacy FE constant `SINGLE_ENGINE_INTEGRATIONS` disables the *engine group* option for the integrations below, allowing only a single engine to be selected. These integrations maintain stateful connections that would break if load-balanced across multiple engines. **For these integrations, the migration must emit only two fields from the §3.7 "Engine handling — 3-field pattern": (1) `engine_mode` with the radio reduced to 2 options (`no_engine` + `engine`, dropping the `engine_group` option entirely), and (2) the `engine` dropdown (`select` + `metadata.dynamic_values` provider `xsoar` / `dynamicField: "engine"`). The `engine_group` field must NOT be emitted.**

Matching rule: case-insensitive exact match against the integration `commonfields.id`.

| Integration ID | Why single-engine only |
|---|---|
| `saml` | Maintains stateful SAML SSO session — must not be load-balanced. |
| `slack` | Maintains websocket connection to Slack — must not be load-balanced. |
| `sharedagent` | Stateful shared-agent session. |
| `syslog` | Long-running syslog listener — single port binding. |
| `mattermost` | Maintains websocket connection to Mattermost — must not be load-balanced. |
| `duo` | Stateful Duo authentication session. |

The `engine_group` carve-out in §3.7 "Engine handling — 3-field pattern" supersedes the default *"emit all three engine fields (`engine_mode`, `engine`, `engine_group`)"* behavior for any integration in this list — emit only `engine_mode` (2-option radio: `no_engine` + `engine`) and the `engine` dropdown. If an integration also appears in [Appendix G](#appendix-g-engine--enginegroup--proxy-exclusion-list), Appendix G wins (no `engine_mode`, `engine`, `engine_group`, or `proxy` fields at all).

## Appendix I: Server-Style Integrations

Server-style integrations are long-running listeners that accept inbound traffic (HTTP, syslog, SNS, mail polling, etc.) rather than initiating outbound API calls on a schedule. They are **out of scope for the standard migration path** — see [Appendix D](#appendix-d-excluded-integrations-out-of-scope) — but several are still expected to be migrated under a **server-style profile** with explicit credential-pinning semantics described below.

### Server-style handler rule — credential pinning via `triggering.labels`

When a server-style integration carries a `type: 9` (credentials) parameter named **`credentials`** in its integration YML, the migrated handler MUST declare which connection profile supplies those credentials by adding a label under `triggering.labels`:

```yaml
# components/handlers/<name>/handler.yaml (fragment)
triggering:
  labels:
    xsoar-long-running-credentials-profile-id: <profile_id>
```

- **`<profile_id>`** is the `id` of the profile under [`connection.yaml`](../README.md) `profiles[]` that contains the migrated `credentials` (type-9) field.
- **If the integration's YML has no `type: 9` parameter named `credentials`, that is a bug in the source integration** — flag it as a migration blocker; do NOT silently emit a label pointing to an arbitrary profile.

### Integration list

The canonical list of server-style integrations in scope for the server-style profile is:

| Integration ID | Notes |
|---|---|
| `EDL` | Long-running External Dynamic List server — serves indicators over HTTP. |
| `TAXII Server` | Long-running TAXII 1.x server. |
| `TAXII2 Server` | Long-running TAXII 2.x server. |
| `Microsoft Teams` | Long-running inbound listener for Teams events. |
| `AWS-SNS-Listener` | Long-running AWS SNS push listener. |
| `Zoom` | Long-running inbound listener for Zoom events. |

Matching rule: case-insensitive exact match against the integration `commonfields.id`. Any integration outside this list whose YML declares `longRunning: true` AND accepts inbound traffic should be flagged as a candidate for addition to this appendix rather than silently migrated under the server-style profile.

### Forward-looking note — re-evaluate this list whenever new integrations enter scope

This appendix reflects only the integrations **currently in scope** for migration. The list is **not exhaustive of every server-style integration in the Content repo** — it is a working subset. Whenever a new integration is brought into scope (either added to the migration pipeline, or moved out of [Appendix D — Excluded Integrations](#appendix-d-excluded-integrations-out-of-scope) / [Appendix E — Manual Migration](#appendix-e-integrations-requiring-manual-migration)), the maintainer MUST analyze it against the server-style criteria below and update this appendix accordingly:

1. Does the YML declare `script.longRunning: true`?
2. Does the integration accept inbound traffic (HTTP listener, syslog listener, SNS push, mail polling, webhook receiver, websocket server, etc.) rather than only initiating outbound API calls on a schedule?
3. Does the integration carry a `type: 9` (credentials) parameter that needs to be pinned to a connection profile via `xsoar-long-running-credentials-profile-id`?

If the answer to (1) and (2) is yes, the integration belongs in this appendix and likely also in [Appendix G](#appendix-g-engine--enginegroup--proxy-exclusion-list) (no engine/proxy fields).

**Concrete example — `GenericWebhook`**: today it is excluded via [Appendix D](#appendix-d-excluded-integrations-out-of-scope) ("Generic webhook integration — not a vendor-specific connector"). When/if `GenericWebhook` (or any similar webhook-receiver integration) is brought into scope in the future, it MUST be analyzed against the criteria above — it is a long-running inbound HTTP listener and will require addition to this appendix (and to Appendix G), along with the credential-pinning rules described above. Do not migrate such an integration under the standard outbound-API path.

## Appendix J: Backend-Managed Fields (`config_type: backend`)

The following fields — and **only** these fields — MUST carry `metadata.xsoar: { config_type: "backend" }`. They are managed by the XSOAR backend rather than passed through as plain instance parameters. This list is **exclusive**: any field not on it MUST NOT be marked `config_type: backend`.

| Field ID | Where it lives | Notes |
|---|---|---|
| `engine` | connection profile (§3.7 engine 3-field pattern) | `select` + `dynamic_values` (`dynamicField: engine`). |
| `engineGroup` | connection profile (§3.7 engine 3-field pattern) | `select` + `dynamic_values` (`dynamicField: engine-group`). Field id `engine_group` in the manifest. |
| `mappingId` | `configurations.yaml`, under the `fetch-issues` sub-capability | Classifier — `select` + `dynamic_values` (`dynamicField: classifier`). |
| `incomingMapperId` | `configurations.yaml`, under the `fetch-issues` sub-capability | Mapper (incoming) — `select` + `dynamic_values` (`dynamicField: mapper-incoming`). |
| `outgoingMapperId` | `configurations.yaml` (mirroring — see §3.2) | Mapper (outgoing). **Mirroring is out of scope on Platform**; listed here only because it is backend-managed when present. |
| `defaultIgnore` | `configurations.yaml` `general_configurations`, per `view_group` | "Do not use in CLI by default". Only for integrations with an `automation-and-remediation` sub-capability (§3.7). |
| `integrationLogLevel` | `configurations.yaml` `general_configurations`, per `view_group` | Off / Debug / Verbose. |

**Explicitly NOT backend-managed** (do **not** set `config_type: backend`): `proxy`, `insecure`, `engine_mode` (the radio control), all auth/secret fields, and every other configuration parameter migrated from the integration YML.