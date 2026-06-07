# Unified Connector Migration Guide

> **Purpose**: This document is a self-contained briefing for an LLM. You will receive this document alongside XSOAR Pack content (integration YMLs). Your task is to **scope the migration of the given integrations to a unified connector**, identify gaps, flag decisions needed, and produce a migration plan with the connector YAML files.
> Not all integrations will necessarily be part of the same content pack.
>
> **What you should produce**:
> 1. A connector (all YAML files)

---

## Table of Contents

- [Section 1: What is a Unified Connector](#section-1-what-is-a-unified-connector)
- [Section 2: Connector Specification Reference](#section-2-connector-specification-reference)
- [Section 3: Migration Rules and Defaults](#section-3-migration-rules-and-defaults)
- [Section 4: Worked Reference — Salesforce Connector](#section-4-worked-reference--salesforce-connector)
- [Section 5: Your Task](#section-5-your-task)
- [Appendix A: XSOAR Parameter Type to Manifest Type mapping](#appendix-a-xsoar-parameter-type-to-manifest-type-mapping)
- [Appendix B: Authentication Architecture — Frontend Transformation](#appendix-b-authentication-architecture--frontend-transformation)
- [Appendix C: Field ID Uniqueness Rule](#appendix-c-field-id-uniqueness-rule)
- [Appendix D: Excluded Integrations (Out of Scope)](#appendix-d-excluded-integrations-out-of-scope)
- [Appendix E: Integrations Requiring Manual Intervention](#appendix-e-integrations-requiring-manual-migration)
- [Appendix F: Joint Migration With the SaaS Team](#appendix-f-joint-migration-with-the-saas-team)
- [Appendix G: Engine / EngineGroup / Proxy Exclusion List](#appendix-g-engine--enginegroup--proxy-exclusion-list)
- [Appendix H: Single-Engine Integrations](#appendix-h-single-engine-integrations)
- [Appendix I: Server-Style Integrations](#appendix-i-server-style-integrations)

---

## Section 1: What is a Unified Connector

### 1.1 Overview

A **Unified Connector** is a declarative YAML-based framework for defining integrations with external services. It replaces the legacy model where each XSOAR integration was a standalone YML + runtime code package with its own auth config and parameters. It allows multiple modules (XSOAR, SaaS) to create integrations for the same vendor using the same auth and configuration.

**Legacy model (what packs have today)**:
1. Each integration is a standalone.
2. Each has its own YML defining auth parameters, configuration, and commands.
3. Each has its own code handling authentication and command execution logic (a few integrations are written in JavaScript or PowerShell).
4. Users configure each integration instance separately, even though they may use the same auth credentials.

**New model (what packs need to become)**:
1. All integrations from a vendor are consolidated into a single `connectors/<vendor>/` directory.
2. Authentication is defined once in [`connection.yaml`](README.md:162) and each handler can subscribe to that auth method if relevant to them.
3. Capabilities and sub-capabilities define what features the connector supports.
4. Each legacy integration becomes exactly one "handler" under `components/handlers/`. There is a 1:1 relationship between handlers and integrations. If an integration spans multiple capabilities (e.g., it has both commands and fetch), the single handler subscribes to all relevant capabilities.
5. The platform handles authentication — Python code uses the new CommonServerPython auth APIs which call ConnectUs backend instead of managing tokens directly. Detailed information on how the auth code changes in content will be in a separate document.

### 1.2 Key Benefits

1. **One connector per vendor** — all integrations roll up into one connector (also allowing SaaS and other modules to implement integrations within this connector).
2. **Unified auth** — authentication defined once, shared across all handlers.
3. **Consistent UI** — frontend renders forms from the same specification.
4. **Platform-managed auth** — the platform handles OAuth token lifecycle, not the Python code.

### 1.3 Notes

- ConnectUs is only supported on Platform Marketplace.

### 1.4 Architecture

```
CODEOWNERS                      # Required: Define code owners
connectors/<vendor>/
├── connector.yaml              # Required: Identity and metadata
├── connection.yaml             # Required: Authentication profiles
├── capabilities.yaml           # Required: Feature definitions
├── configurations.yaml         # Optional: Per-capability config fields
├── triggers.yaml               # Optional: Conditional field behavior (show/hide/require/lock)
├── summary.yaml                # Optional: Documentation and next steps
├── availability.yaml           # Optional: Tenant/region visibility control
├── <icon>.{png,jpg,jpeg,svg}   # Optional: Connector icon (max 1 per connector)
└── components/
    └── handlers/
        ├── xsoar_<integration_name1>/
        │   ├── handler.yaml    # XSOAR handler
        │   └── serializer.yaml # Field name/value mapping
        ├── xsoar_<integration_name2>/
        │   ├── handler.yaml
        │   └── serializer.yaml
        └── ...
```

---

## Section 2: Connector Specification Reference

> **🕒 Last synced with [README.md](../README.md) and [schema/](../schema/) on 2026-06-05.**
> Re-check freshness against `README.md` and `schema/*.schema.json` before relying on this section.

This section is a compact mirror of the live spec in [`README.md`](README.md:1) and the JSON schemas under [`schema/`](schema/). When in doubt, the schemas are the source of truth.

### 2.1 connector.yaml

The root configuration file that defines the connector's identity and metadata. Defined by [`schema/connector.schema.json`](schema/connector.schema.json).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | ❌ | Whether the connector is enabled. Defaults to `true`. Set to `false` only for example connectors. |
| `id` | string | ✅ | Unique connector identifier (min 3 chars). |
| `metadata.title` | string | ✅ | Display name. |
| `metadata.description` | string | ✅ | Brief description (min 10 chars). |
| `metadata.version` | semver | ✅ | Semantic version (e.g., `1.0.0`). |
| `metadata.categories` | string[] | ✅ | Classification categories — **array**, at least one required. |
| `metadata.tags` | string[] | ❌ | Searchable tags. |
| `metadata.domain` | string | ❌ | Domain classification (e.g., `"productivity"`, `"security"`). |
| `metadata.vendor` | string | ✅ | Vendor of the service being integrated. |
| `metadata.publisher` | string | ✅ | Publisher of this connector definition. |
| `metadata.author_image` | string | ❌ | Filename of the connector icon image in the **connector root directory** (e.g. `"salesforce-ic.svg"`). Pattern `^[a-zA-Z0-9_.-]+\.(png\|jpg\|jpeg\|svg)$` or empty string. See §2.13 below for image constraints. |
| `metadata.documentation` | string (URI) | ❌ | URL to the connector's external documentation page. |
| `metadata.ownership.team` | string | ✅ | Owning team. |
| `metadata.ownership.maintainers` | string[] | ✅ | Maintainer handles. |
| `settings.allow_skip_verification` | boolean | ❌ | Allow skipping the connection test. |
| `settings.required_features` | string[] | ❌ | Tenant features that must be active for this connector to be visible. |

### 2.2 connection.yaml

Defines authentication profiles. Schema: [`schema/connection.schema.json`](schema/connection.schema.json).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `metadata.title` | string | ✅ | Section title. |
| `metadata.description` | string | ✅ | Help text for users. |
| `metadata.help` | string | ❌ | Additional Markdown/HTML help content. |
| `general_configurations` | GeneralConfig | ❌ | Fields shared across all auth profiles (e.g. a `domain` URL field). |
| `profiles` | Profile[] | ✅ | List of authentication profiles. |

#### Profile Types

| Type | Description | Use Case |
|------|-------------|----------|
| `oauth2_client_credentials` | OAuth 2.0 Client Credentials Flow | Server-to-server authentication. |
| `oauth2_authorization_code` | OAuth 2.0 Authorization Code Flow | User-authorized access. |
| `oauth2_jwt_bearer` | OAuth 2.0 JWT Bearer Flow | Server-to-server using a JWT assertion. |
| `plain` | Username & Password | Basic authentication. |
| `api_key` | API Key | Token-based authentication. |
| `passthrough` | Store-and-forward credentials (no IDP) | Stores an arbitrary, content-defined set of credential fields encrypted and returns them verbatim to the handler on `getCredentials` — no token exchange. Used during mass migration when a connection cannot be cleanly mapped to a typed profile. See §2.6.1. |

#### Profile Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique profile identifier (format: `type.purpose`, e.g. `oauth2_client_credentials.salesforce`). |
| `type` | string | ✅ | Authentication type (see table above). |
| `title` | string | ✅ | Display name. |
| `description` | string | ✅ | Profile description. |
| `configurations` | FieldGroup[] | Conditional | Required for `passthrough` and for any profile carrying auth-input fields (e.g. `oauth2_client_credentials`, `plain`, `api_key`, `oauth2_jwt_bearer`). For `oauth2_authorization_code` profiles all credentials come from `{SAAS_REGISTRY.*}` and `configurations` is typically omitted. Fields inside must include `metadata.auth.parameter` (see §2.6). |

### 2.3 OAuth2-Specific Fields

| Field | Type | Applicable Types | Description |
|-------|------|------------------|-------------|
| `discovery_url` | string | All OAuth2 types | OpenID Connect discovery URL. Mutually exclusive with explicit endpoints. |
| `token_endpoint` | string | All OAuth2 types | OAuth token endpoint URL. Mutually exclusive with `discovery_url`. |
| `authorization_endpoint` | string | `oauth2_authorization_code` only | OAuth authorization URL. Mutually exclusive with `discovery_url`. |
| `client_id` | string | `oauth2_authorization_code` | Client ID (use `{SAAS_REGISTRY.*}` for secrets). |
| `client_secret` | string | `oauth2_authorization_code` | Client secret (use `{SAAS_REGISTRY.*}` for secrets). |
| `refresh_token_scope` | string | `oauth2_authorization_code` only | **Required.** IDP-specific scope for refresh tokens (e.g., `"refresh_token"` for Salesforce, `"offline_access"` for OIDC IDPs). |
| `options.use_base64_header` | boolean | All OAuth2 types | Use Base64 encoding for auth header. |
| `options.allow_scopes` | boolean | All OAuth2 types | Allow handler-level scopes to be merged with the platform request. |

### 2.4 Variable Interpolation

| Pattern | Description | Example |
|---------|-------------|---------|
| `{{field_id}}` | User-provided field value | `{{salesforce_domain}}` |
| `{SAAS_REGISTRY.*}` | Secrets from registry | `{SAAS_REGISTRY.SALESFORCE_CORE_CLIENT_ID}` |
| `{UNIFIED_CONNECTORS_*}` | Connector-specific config | `{UNIFIED_CONNECTORS_SLACK_CALLBACK}` |

### 2.5 capabilities.yaml

Defines the features/capabilities the connector supports. Schema: [`schema/capabilities.schema.json`](schema/capabilities.schema.json).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `metadata.title` | string | ✅ | Section title. |
| `metadata.description` | string | ✅ | Help text. |
| `metadata.help` | string | ❌ | Additional Markdown/HTML help content. |
| `general_configurations` | GeneralConfig | ❌ | Fields shown for all capabilities. **Must contain the mandatory `instance_name` field** (see below). |
| `capabilities` | Capability[] | ✅ | List of capabilities. |

**MANDATORY**: Every connector must have exactly one field with `metadata.connector.parameter: "instance_name"` in [`capabilities.yaml`](README.md:509) under `general_configurations`.

**MANDATORY**: Every connector must have an `integrationLogLevel` field in `general_configurations` with `metadata.xsoar.config_type: "backend"`. See §3.7.

#### Capability Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique capability identifier. |
| `title` | string | ✅ | Display name. |
| `description` | string | ✅ | Capability description. |
| `default_enabled` | boolean | ✅ | Enabled by default. |
| `required` | boolean | ✅ | Capability cannot be disabled. |
| `labels` | string[] | ❌ | UI labels (e.g., `Recommended`). |
| `config.required_license` | string[] | ❌ | Required license tiers, sourced from `pack_metadata.json` `supportedModules`. |
| `config.required_features` | string[] | ❌ | Tenant features that must be active for this capability to be visible (AND logic across the list). |
| `sub_capabilities` | SubCapability[] | ❌ | Nested capabilities (same shape minus `description`/`labels`). |

#### Valid License Values

```
data_security, agentix, asm, cloud, cloud_appsec, cloud_posture,
cloud_runtime_security, cold_rtn, compute_unit, edr, endpoint_dlp, epp,
exposure_management, forensics, host_insights, identity_threat, rtn, tim,
xdr, xsiam, xsoar
```

### 2.6 Auth Parameter Tagging

Fields within authentication profile configurations **must** include `metadata.auth.parameter` to identify which authentication parameter the field supplies. Field IDs are globally unique, so the backend cannot rely on them for semantic meaning — the `auth.parameter` tag provides the mapping.

| Profile Type | Required `auth.parameter` Values |
|---|---|
| `oauth2_client_credentials` | `client_key`, `client_secret` |
| `plain` | `username`, `password` |
| `api_key` | `api_key` |
| `oauth2_authorization_code` | *(none — credentials come from `{SAAS_REGISTRY.*}`)* |
| `oauth2_jwt_bearer` | `subject_email`, `credentials_file` |
| `passthrough` | *(free-form — defined per connector in YAML; no enum, no PR-time contract. See §2.6.1.)* |

#### 2.6.1 Passthrough Profile

The `passthrough` profile type lets a connector store and forward an arbitrary, per-connector set of credential fields **without** any IDP/token exchange. Because this is a **mass migration**, we cannot always map a legacy integration's connection to a specific typed profile (`oauth2_*` / `plain` / `api_key` / `oauth2_jwt_bearer`). `passthrough` is the escape hatch: configure whatever fields the connection needs in the profile, and the platform returns them all back, verbatim, on `getCredentials`.

##### Data Flow (all profile types)

1. Backend reads the profile `type` (e.g., `oauth2_client_credentials`).
2. Backend finds fields by their `metadata.auth.parameter` value (e.g., `parameter: "client_key"`).
3. Backend maps user-entered values to the correct auth parameters using the parameter tag, **not** the field ID.
4. For `passthrough` profiles, the backend **skips token exchange entirely** and returns the decrypted user inputs verbatim to the handler on `getCredentials`, keyed by `metadata.auth.parameter`.

##### Semantics

| Behavior | Description |
|---|---|
| Storage | Each field value is encrypted on save (same encryption pipeline as other profile types). |
| Token exchange | **None.** The platform never contacts an IDP for `passthrough` profiles. |
| `getCredentials` | Returns the decrypted user inputs to the handler **as-is**, keyed by `metadata.auth.parameter`. The handler is responsible for using them (Basic auth header, custom header, mTLS material, etc.). |
| Field shape | 100% YAML-defined. Any field type allowed by the schema (`input`, `select`, `checkbox`, `checkbox_group`, etc.) is supported. Field names (`auth.parameter` values) are free-form — no enum. |
| Test connection | Must be implemented entirely by the handler (no platform-side validation of the credentials at save time). |
| Refresh / rotation | None — the platform performs no auth flow for this type. Any rotation is a handler concern or a user-driven re-save. |

##### When to use `passthrough` vs a typed profile

| Choose… | When… |
|---|---|
| **Typed flow** (`oauth2_*`, `plain`, `api_key`, `oauth2_jwt_bearer`) | The platform should manage the credential lifecycle (token exchange, refresh, expiry tracking). Use whenever the connector cleanly fits one of these standard shapes. |
| **`passthrough`** | The platform's only job is "store these fields encrypted, give them back to the handler when asked." Ideal for mass-migration waves where each connector has a different credential shape but the handler can use the raw inputs directly. No platform code change required per connector. |

##### Wire contract — `getCredentials` response

For a `passthrough` profile, the platform returns a payload of the form:

```json
{
  "profile_id": "passthrough.acme_api",
  "profile_type": "passthrough",
  "parameters": {
    "client_id": "<decrypted user value>",
    "client_secret": "<decrypted user value>",
    "accept_user_certificate": true
  }
}
```

Keys in `parameters` come from `metadata.auth.parameter`, **not** from `field.id`. Values preserve the original field type (string, boolean, number, array for multi-select, etc.). Handlers consuming a `passthrough` profile should validate field presence and types defensively at runtime — there is **no PR-time contract enforcement** for `passthrough` (unlike `plain` / `api_key` / `oauth2_*`, which require named parameters via OPA validation).

##### Security notes

- Raw secrets are decrypted on every `getCredentials` call. A compromised handler leaks the actual secret (there is no platform-issued short-lived token to revoke). Audit logging on `getCredentials` is recommended for all `passthrough` profiles.
- Set `options.mask: true` on every sensitive field so the UI does not echo the value.
- Treat `auth.parameter` names as **immutable** once a connector is published — renaming a parameter silently breaks stored credentials (no migration framework today).

##### Example

```yaml
profiles:
  - id: "passthrough.acme_api"
    type: "passthrough"
    title: "Acme API Credentials"
    description: "Stores Acme client credentials and TLS preferences. Values are returned as-is to the handler."
    configurations:
      - fields:
          - id: "acme_client_id"
            title: "Client ID"
            field_type: "input"
            metadata:
              auth:
                parameter: "client_id"
            options:
              mask: false
              create_modifiers:
                required: true
              edit_modifiers:
                required: true
          - id: "acme_client_secret"
            title: "Client Secret"
            field_type: "input"
            metadata:
              auth:
                parameter: "client_secret"
            options:
              mask: true
              create_modifiers:
                required: true
              edit_modifiers:
                required: true
          - id: "acme_accept_user_cert"
            title: "Accept User Certificate"
            field_type: "checkbox"
            metadata:
              auth:
                parameter: "accept_user_certificate"
            options:
              mask: false
              default_value: false
              create_modifiers:
                required: false
              edit_modifiers:
                required: false
```

Handlers reference a passthrough profile in `auth_options` exactly as they reference any other profile, with no special syntax:

```yaml
# components/handlers/<module>/handler.yaml
capabilities:
  - id: "automation"
    auth_options:
      - id: "passthrough.acme_api"
        workloads:
          - "acme-api"
```

### 2.7 configurations.yaml

Defines configuration fields for each capability. Schema: [`schema/configurations.schema.json`](schema/configurations.schema.json).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `metadata.title` | string | ✅ | Section title. |
| `metadata.description` | string | ✅ | Help text. |
| `general_configurations` | GeneralConfig | ❌ | Fields shown for all capabilities. |
| `configurations` | CapabilityConfig[] | ✅ | Per-capability configurations (each `id` must match a capability ID from [`capabilities.yaml`](README.md:509)). |

### 2.8 handler.yaml

Defines how a specific handler uses the connector. Schema: [`schema/handler.schema.json`](schema/handler.schema.json).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique handler identifier. |
| `metadata.version` | semver | ✅ | Handler version. |
| `metadata.description` | string | ✅ | Handler description. |
| `metadata.module` | string | ❌ | Module name (e.g., `"xsoar"`, `"discovery"`). Determines which handler-specific metadata keys are forwarded to this handler. |
| `metadata.tags` | string[] | ❌ | Handler tags. |
| `metadata.labels` | object | ❌ | Handler-specific metadata labels. Free-form key/value pairs forwarded to the handler at runtime. |
| `metadata.ownership` | Ownership | ✅ | Team and maintainers. |
| `enabled` | boolean | ✅ | Whether the handler is active. |
| `triggering.type` | string | ✅ | `PUB_SUB` or `ZERO_SCALE`. |
| `triggering.labels` | object | ❌ | Handler-specific labels (e.g., `xsoar-integration-id`, `xsoar-pack-id`, `xsoar-long-running-credentials-profile-id`). |
| `capabilities` | HandlerCapability[] | ✅ | Capability-auth mappings. Each capability entry MAY declare an `actions[]` array for instance-level operations exposed in the UI (see "Action Schema" below). |
| `test_connection` | TestConnection | Conditional | Connection-test configuration. **Required** unless every `auth_options[].id` in the file is `"none"` (fully-anonymous handler) — in that case `test_connection` may be omitted because there are no credentials to test. |
| `test_connection.type` | string | ✅ | `endpoint` or `service`. |
| `test_connection.host` | string | Conditional | Required when `type: endpoint`. Supports `{tenant_id}` interpolation. |
| `test_connection.service` | string | Conditional | Required when `type: service` (e.g., `"xsoar"`). |
| `test_connection.endpoint` | string | ✅ | API endpoint path for the verification call. |
| `test_connection.headers` | object | ❌ | HTTP headers (used with `type: endpoint`). |

#### Action Schema

Actions are declared directly on each `capabilities[]` entry via `capabilities[].actions[]`. They surface as instance-level operations the user can trigger from the UI (e.g., "Reset Issues Last Run"). Migrated XSOAR handlers always place actions on the **sub-capability** level (see §3.8 for the mapping from XSOAR fetch flags to action types).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | ✅ | Action type identifier. Must be one of: `reset_integration_context`, `reset_assets_last_run`, `reset_incidents_last_run`, `reset_feed_last_run`, `reset_events_last_run`. |
| `display` | string | ❌ | Pretty display name shown in the UI. When omitted, the platform supplies a default. |
| `description` | string | ❌ | Human-readable description of what the action does. When omitted, the platform supplies a default. |

### 2.9 serializer.yaml

Defines field name/value transformations for handler-specific requirements. Schema: [`schema/serializer.schema.json`](schema/serializer.schema.json). Two sections (both optional, at least one required):

1. **`field_mappings`** — rename fields and/or transform values (processed first).
2. **`computed_fields`** — generate synthetic output fields based on conditions (processed second).

#### Field Mappings

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Field ID to serialize (must match a field defined somewhere in the connector). |
| `field_name` | string | ❌ | Target field name for the handler (rename). At least one of `field_name` / `field_value` is required per entry. |
| `field_value` | string | ❌ | Transform function to apply to the field value. |

#### Computed Fields

Each rule has `output` (fields to emit) and `any_of` (list of condition groups). Within a group all `conditions` must match (AND); across groups any match is sufficient (OR).

| Condition `type` | `options` fields | Notes |
|---|---|---|
| `capability` | `capability_id` (string), `value` (`on` / `off`) | Validated against [`capabilities.yaml`](README.md:509). |
| `field` | `field_id` (string), `op` (`eq`/`neq`/`gt`/`gte`/`lt`/`lte`), `value` | Validated against all defined fields. |

`computed_fields` evaluate against the **original** field IDs (before `field_mappings` is applied).

### 2.10 triggers.yaml

Defines conditional field behavior — show/hide, enable/disable, require, or lock fields based on the live values of other fields and/or the on/off state of capabilities. Schema: [`schema/triggers.schema.json`](schema/triggers.schema.json). **Optional** — omit or ship `triggers: []` when no conditional behavior is needed.

Triggers live in a flat array at the root of the file (single source of truth). Each trigger has a recursive `conditions` tree and one or more reversible `effects`.

#### Condition Node Variants (discriminated by `type`)

| `type` | Kind | Description |
|--------|------|-------------|
| `condition` | leaf | Field-driven comparison. |
| `condition_group` | branch | AND/OR over `condition` / nested `condition_group` children (field family). |
| `capability_condition` | leaf | Capability/sub-capability state comparison. |
| `capability_condition_group` | branch | AND/OR over `capability_condition` / nested groups (capability family). |
| `condition_group` (root only) | mixed branch | When used at the trigger root, may mix field and capability children. Nested groups stay strict per-family. |

#### Operators

- Field conditions: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `contains`, `starts_with`, `is_empty`, `is_not_empty`.
- Capability conditions: `eq`, `neq` only (state is boolean).
- `is_empty` / `is_not_empty` **must omit `value`**.

#### Effect

Each effect targets a field by `id` and applies an `action` — an object of boolean flags (`hidden`, `required`, `read_only`, `enabled`), at least one of which must be present. Effects are **reversible**: the action applies when conditions match, and its logical inverse applies when they don't.

`effect.message` is allowed **only** when the condition tree contains at least one `capability_condition` — use it to tell the user *why* a capability requires this field. See the README section [`triggers.yaml`](README.md:833) for full examples.

### 2.11 summary.yaml

Schema: [`schema/summary.schema.json`](schema/summary.schema.json).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `metadata.title` | string | ✅ | Section title. |
| `metadata.description` | string | ✅ | Brief description. |
| `metadata.link` | string | ❌ | Documentation link URL (plain URL string). |
| `metadata.next_steps` | string | ❌ | Post-setup guidance (Markdown). |

### 2.12 availability.yaml

Optional file controlling connector visibility per region and tenant **in production only** — in dev/staging, all connectors are visible regardless. Schema: [`schema/availability.schema.json`](schema/availability.schema.json). When absent, the connector is GA. When present, the `tenants` map restricts visibility:

- Region key must be a valid GCP region name (enum-enforced).
- Value is an array of tenant ID strings or `null`.
- Empty array or `null` = visible to all tenants in that region.
- Region not listed = not visible in that region.

### 2.13 Connector Icon

The optional icon image lives in the **connector root directory** (e.g. [`connectors/salesforce/salesforce-ic.svg`](connectors/salesforce/salesforce-ic.svg)) and is referenced by filename only via `metadata.author_image`.

| Constraint | Value |
|-----------|-------|
| Allowed formats | `png`, `jpg`, `jpeg`, `svg` |
| Max file size | 512 KB |
| Min raster dimensions | 64 × 64 px (PNG/JPG/JPEG; SVG is skipped — vector) |
| Max icons per connector | 1 |

Icons are excluded from the `connectors.tar.gz` archive and uploaded separately to GCS at `images/<connector-id>/<filename>` by CI.

### 2.14 Field Types Reference

Per README [Field Types Reference](README.md:1521):

| Type | Description | Example Use Case |
|------|-------------|------------------|
| `input` | Text input field | Username, domain name |
| `text_area` | Multi-line text input | Long descriptions |
| `select` | Single-choice dropdown — submits a scalar value | Sync interval, priority |
| `multi_select` | Multi-choice dropdown — submits an **array of keys** | Sync intervals, regions, data scopes |
| `checkbox` | Single boolean toggle | Enable/disable feature |
| `checkbox_group` | Multiple checkboxes (uses `fields[]` for items) | Permission selection |
| `toggle` | On/off switch | Feature flags |
| `switch` | Toggle switch | Boolean settings |
| `label` | Read-only text | Section headers |
| `file_upload` | File upload — `options.mask` **must be `true`** | Credentials JSON, certificates |

### 2.15 Field Options

Schema: [`schema/definitions/field-options.schema.json`](schema/definitions/field-options.schema.json). Highlights:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `mask` | boolean | ✅ | Whether the value is masked in the UI. **Must be `true`** for `file_upload`. |
| `description` | string | ❌ | Secondary text below the field. |
| `help_text` | markdown | ❌ | Tooltip on info-icon hover (Markdown). |
| `placeholder` | string | ❌ | Ghost text in the input. |
| `default_value` | any | ❌ | Initial value. For `select` it must match one of `values[].key`; for `multi_select` it must be an array of keys, each matching one `values[].key`. For `checkbox_group` it is an array of `{key, value}` pairs. **When the field declares `metadata.dynamic_values`** (see §2.16), `default_value` is a literal pre-selection hint — applied only if the runtime-fetched list contains the literal key, otherwise silently ignored. |
| `values` | array | ❌ | Options for select-style fields. **Per the live `field-options.schema.json` both `select` and `multi_select` use the `{key, label}` shape** (`SelectValuesItem` / `MultiSelectValuesItem`, each requiring `key` + `label`). **Must be absent** when `metadata.dynamic_values` is declared. |
| `empty_values_message` | string | ❌ | Message displayed when a `select` or `multi_select` field has **no options to show** at runtime (e.g., `dynamic_values` returns an empty list, or static `values` is empty). **Only valid on `select` and `multi_select`** field types (enforced by JSON Schema). Note: this is the "no options at all" placeholder text — it is **not** the same as prepending a selectable empty/"No issue type" option (see §3.2.2 item 12, which remains open). |
| `hint` | string | ❌ | Hint text beneath the input. |
| `layout` | object | ❌ | `cols` (≤ 6 for `input`/`text_area`/`select`/`multi_select`) and `row_span`. |
| `create_modifiers` | object | ❌ | `{required, hidden, read_only}` applied on instance creation. |
| `edit_modifiers` | object | ❌ | `{required, hidden, read_only}` applied on instance edit. |

### 2.16 Dynamic Field Values

`select` and `multi_select` fields can declare that their option list is fetched at runtime by the UCP platform from a named provider, instead of static `options.values`. The descriptor lives on `metadata.dynamic_values` and is platform-internal (stripped before pub/sub message construction).

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `provider` | string (enum) | ✅ | Provider name. v1 enum: `"xsoar"`. Must match the `metadata.module` of at least one handler in the same connector. |
| `trigger` | string[] (enum) | ✅ | Lifecycle events that cause the platform to fetch. v1 enum: `"on_create"`, `"on_edit"`. Non-empty, unique. |
| `params` | object | ✅ | Provider-specific parameters (shape enforced per provider). |

**Provider `xsoar`** requires `params: {integrationID, dynamicField}`. The platform POSTs `{integrationID, dynamicField}` to XSOAR's `/settings/integration/connector/dynamic-fields/search` and normalizes the upstream `{id, name}[]` response into the `{key, label}`/`{key, value}` shape expected by the target field. Typical `dynamicField` values: `"engine"`, `"engine-group"`, `"classifier"`, `"mapper-incoming"`, `"mapper-outgoing"`, `"incident-type"`.

**Minimal example** (XSOAR incoming mapper):

```yaml
- id: "xsoar_incoming_mapper"
  title: "Incoming Mapper"
  field_type: "select"
  metadata:
    dynamic_values:
      provider: "xsoar"
      trigger: ["on_create", "on_edit"]
      params:
        integrationID: "Salesforce"
        dynamicField: "mapper-incoming"
  options:
    placeholder: "Select an incoming mapper"
    searchable: true
    clearable: true
    # Best-effort literal pre-selection — silently ignored if the key is not in the fetched list.
    default_value: "Salesforce-Incoming-Mapper"
```

See README [Dynamic Field Values](README.md:1724) for the full spec.

### 2.17 Field Metadata

The `metadata` object on a field is a free-form enrichment bag. Keys are classified into three categories that determine pub/sub forwarding:

| Category | Keys | Behavior |
|----------|------|----------|
| **Platform-internal** | `auth`, `connector`, `dynamic_values`, `event` | Stripped before pub/sub — never forwarded to handlers. |
| **Handler-specific** | Keys matching handler directory names (e.g., `xsoar`, `cwp`, `discovery`) | Forwarded only to the matching handler. |
| **Common enrichment** | All other keys | Forwarded to all handlers. |

#### `metadata.event.publish` — Publishing Field Values in Lifecycle Events (connection-profile fields only)

Connection profiles often carry **non-secret operational parameters** alongside credentials — for example, an engine selector, a "Trust Any Certificate" toggle, a proxy hostname, or a region. By default, connection-profile field values are **not** sent over the pub/sub message — they are only available to the handler via the **get-credentials** API. But there are scenarios where the XSOAR BE needs these values **before creating the instance** (e.g., `engine`, `proxy`, `insecure`/trust-any-cert), which means an extra get-credentials round-trip isn't viable.

The optional `metadata.event.publish: true` flag opts a connection-profile field into the **create/edit lifecycle pub/sub event payload**, so handlers (and the BE) receive the value directly, without an extra round-trip to get-credentials.

> **Migration rule**: `engine` / `engine_group`, `proxy`, and `insecure` (Trust Any Certificate) fields that live inside a **connection profile** MUST carry `metadata.event.publish: true`, because the XSOAR BE needs these values at instance-creation time. See §3.6.

##### Shape

```yaml
metadata:
  event:
    publish: true
```

`metadata.event` is a platform-internal metadata key (joining `auth`, `connector`, and `dynamic_values`). The `event` key itself is **stripped** before per-handler pub/sub message construction — but the field's **user-entered value** is included in the lifecycle event payload.

##### Scope and Rules

| Rule | Detail / Enforcement |
|------|----------------------|
| Scope | Only valid on fields inside `connection.yaml profiles[].configurations[].fields[]`. Forbidden in `connection.yaml general_configurations`, all of `configurations.yaml`, and all of `capabilities.yaml` (JSON Schema). |
| Mutual exclusion | `metadata.event` and `metadata.auth` are **mutually exclusive** on the same field — auth parameters are secrets and must always flow through get-credentials, never through the lifecycle event payload (JSON Schema `if/then/not`). |
| Shape | Exactly `{ publish: <boolean> }` (`additionalProperties: false`) — modelled as an object so it can grow future options without a breaking change. |

##### Metadata Forwarded with the Published Value

When the platform constructs the lifecycle event for handler **H**, for each connection-profile field whose `metadata.event.publish == true`, it applies the standard [three-category classification](#217-field-metadata) to the field's other metadata keys:

- **Platform-internal keys** (`auth`, `connector`, `dynamic_values`, `event`) — stripped.
- **Handler-specific keys** (`xsoar`, `cwp`, `discovery`, …) — included **only** if the key matches H's module name. This lets a connection-profile field carry per-handler backend labels (`metadata.xsoar.config_type`, `metadata.xsoar.credentials_type`, etc.) that travel alongside the value to the right handler.
- **Common enrichment keys** (everything else) — included for every handler.

##### Example

```yaml
profiles:
  - id: "oauth2_client_credentials.salesforce"
    type: "oauth2_client_credentials"
    title: "OAuth 2.0 Client Credentials Flow"
    configurations:
      - fields:
          - id: "client_key"
            title: "Consumer Key (Client ID)"
            field_type: "input"
            metadata:
              auth:
                parameter: "client_key"          # secret → get-credentials, NOT in event
            options:
              mask: false
              create_modifiers: { required: true }
              edit_modifiers:   { required: true }

          - id: "trust_any_cert"
            title: "Trust Any Certificate"
            field_type: "switch"
            metadata:
              event:
                publish: true                    # ★ value flows into the lifecycle event
              xsoar:                              # handler-specific label → xsoar only
                config_type: "backend"
                credentials_type: "taxii_server"
            options:
              mask: false
              default_value: false
              create_modifiers: { required: false }
              edit_modifiers:   { required: false }
```

**Resulting lifecycle event published to the `xsoar` handler:**

```json
{
  "lifecycle": "on_create",
  "profile_id": "oauth2_client_credentials.salesforce",
  "fields": {
    "trust_any_cert": {
      "value": false,
      "metadata": {
        "xsoar": {
          "config_type": "backend",
          "credentials_type": "taxii_server"
        }
      }
    }
  }
}
```

- `client_key` is **absent** — it's a secret (carries `metadata.auth.parameter`) and must be fetched via get-credentials.
- `trust_any_cert` is **present** because `metadata.event.publish: true` opted it in.
- The `event` and `auth` keys are stripped (platform-internal).
- `metadata.xsoar` accompanies the value because it's a handler-specific key matching the target module.

> **Note**: A field with `metadata.event.publish: true` is rejected by the validator if it also carries `metadata.auth.parameter`. Auth parameters are secrets — they always flow through get-credentials, never through the lifecycle event payload.

### 2.18 Validation Rules

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `trigger` | string | ✅ | `change` or `blur`. |
| `rules[].type` | string | ✅ | `pattern`, `minLength`, `maxLength`, `async`. |
| `rules[].value` | string/int | Conditional | Regex or integer. |
| `rules[].message` | string | ❌ | Error message. |
| `rules[].validation_type` | string | Conditional | For `async` rules (e.g., `"uniqueness"`). |

---

## Section 3: Migration Rules and Defaults

These are the rules you must follow when scoping any connector migration.

### 3.1 Assumptions

1. For simplicity, handler == integration. In a single connector there will NOT be two or more handlers pointing to the same integration.
2. **Duplicate command names**: A connector CANNOT contain two integrations that expose the same command name. If this does happen, resolve by creating a new command with name `<previous_command_name>_<integration_name>` and copy the same command implementation. Something like this needs manual work and approval from xsoar management
3. **Platform marketplace only**: ConnectUs is only supported on Platform Marketplace. If `marketplaces` is not in the integration YML, then it is defined in the `pack_metadata.json` field `marketplaces`.
4. **Fields hidden on platform**: If a configuration parameter is hidden on `platform` in the integration YML (e.g., `hidden: [platform]` or `isfetch:platform: false`), it is not relevant for ConnectUs and should be excluded from the connector manifest.
5. **Fields specific to platform**: If a configuration parameter is specifically relevant on `platform` (e.g., `quickaction:platform: true`), it is relevant for platform. Many fields in the YML can be marketplace-specific (e.g., `hidden: [platform]`, `isfetch:platform: false`, `id:xsoar: Salesforce XSOAR`, etc.).
6. The PNG image for the integration resides in `<pack_name>/integrations/<integration_name>/<something>.png`.
7. The PNG within the integration folder is the author image for the connector.
8. If there is more than one PNG across all integration folders, take the first one you see.
9. You are required to go over the chosen image manually to ensure its correct.  
10. Integrations that were migrated to the **cooc onboarding experience** need special handling. See the sheet at https://docs.google.com/spreadsheets/d/12OT8m-skeXdTZ9iQUiO1ScsMeVPFgAfdMKzbdGJ68ss/edit?gid=0#gid=0. For those integrations, migrate them to connectors but the licenses supported on the connector will equal `{ALL licenses MINUS supportedModules defined in the integration pack}`. See Slack thread https://panw-global.slack.com/archives/C0B31FUQN03/p1778758179721169?thread_ts=1778757354.234039&cid=C0B31FUQN03. These connectors should be reviewed by Rotem Amit.
12. No UI triggers will be added to integrations in the next quarter — see Slack thread https://panw-global.slack.com/archives/D09195K2HLP/p1779778921954079. (Migration authors should still **author** [`triggers.yaml`](README.md:833) where it cleanly solves a known UI problem — see §3.5.)
13. We will always have a sub-capability, even if there is only one integration under a capability. When only one sub-capability exists, document the open UX question (see §3.2.2). If there is only one sub-capability under a capability, then it should be marked as `required:true`
14. **Sub-capability licenses MUST be a subset of the integration's `supportedModules`.** The `config.required_license` declared on a sub-capability must contain only license values that appear in the underlying integration's `supportedModules` (or, if absent on the integration, the parent pack's `pack_metadata.json` `supported_modules`). **Rationale**: when UCP triggers instance creation, the XSOAR BE will only actually create the instance if the tenant's licenses match the integration's `supportedModules`. If we declare a license on the sub-capability that the integration does NOT support, a tenant holding only that extra license will see the sub-capability in the UCP catalog, attempt to enable it, and then hit a silent BE failure that is very hard to triage (the UCP layer thinks the license is fine; the XSOAR layer rejects it). Treat any license that is on the sub-capability but not on the integration as a migration bug and fail/flag the generation. The reverse direction is allowed — a sub-capability may declare a **strict subset** of the integration's licenses (to intentionally restrict it to a narrower tier).

### 3.2 Out of Scope and Opens

#### 3.2.1 Out of Scope

1. Integrations that are not in the given list of integrations.
2. Deprecated, community, or partner integrations are out of scope.
3. `outgoingMapperId` — mirroring is not supported on Platform.
4. `defaultMapperOut` — mirroring is not supported on Platform.
5. mirroring is out of scope, as not supported on platform

#### 3.2.2 Opens

> **📋 Master list of open items** is tracked in [this spreadsheet](https://docs.google.com/spreadsheets/d/1C1nZ70rJlBWB0vdH_rc_xe5RFk22CiA9Z2yBtSLgJg4/edit?gid=0#gid=0), which holds the authoritative status and Jira links for every open item below. Update the sheet first; the items here are a snapshot for context.

Items still requiring a design or platform decision. Resolved items have been moved to the **Recently resolved** sub-section at the bottom.

1. 🟡 **IN PROGRESS** — Integrations that don't have auth/connection. There will be an option to skip the connection screen. --> no block
2. 🟡 **IN PROGRESS** — `duration-picker` field type is still in development in UCP — needed for fetch intervals (`feedFetchInterval`, `incidentFetchInterval`, `eventFetchInterval`, etc.). --> no block
3. 🔴 **IN PROGRESS** — A new UI rendering mechanism called **"view groups"** for the connection and configuration page is still in progress. --> block
4. 🟡 **IN PROGRESS** — Platform documentation site per connector for `metadata.documentation` in [`connector.yaml`](README.md:103). Tech team to tell us how to generate these. --> no block
5. 🟡 **IN PROGRESS** — Tech team to create a tool that generates the `help` sections for each connector onboarding step and for the connector catalog.
6. 🟡 **IN PROGRESS** — Credentials vaults will be supported. Still in progress.
7. 🟢 **RESOLVED** — "Reset last run" / "Reset context" actions on an instance. Now supported via `handler.yaml capabilities[].actions[]` — see §2.8 Action Schema and §3.8 "Actions per sub-capability" rules. Action types: `reset_integration_context`, `reset_assets_last_run`, `reset_incidents_last_run`, `reset_feed_last_run`, `reset_events_last_run`.
8. 🟡 **PARTIALLY RESOLVED — Capability/sub-capability as target in triggers.** Triggers v2 (see §3.5 and [`schema/triggers.schema.json`](schema/triggers.schema.json)) can both **read** capability state (via a `behavior: selected` condition leaf) and **target** a capability/sub-capability id in an `effect.id`. This means the **gating direction is now fully supported**: you can disable/hide/lock/require capability B (or any field) based on capability A's state. Example — disable `sub_capability_1` whenever the `automation` capability is off:

    ```yaml
    triggers:
      - conditions:
          id: automation
          behavior: selected
          operator: eq
          value: false
        effects:
          - id: sub_capability_1
            action:
              enabled: false
            message: "sub_capability_1 requires Automation to be enabled."
    ```

    **Remaining gap**: there is still no way to **flip a capability's selected state** ("auto-enable capability B when A is chosen"). `EffectAction` only exposes the boolean *modifiers* `hidden` / `required` / `read_only` / `enabled` (where `enabled` controls UI interactivity — interactive vs. greyed-out — **not** the on/off selection state). There is no `selected` / `default_enabled` write flag on the effect side, so true auto-selection cannot be expressed today. Track separately.
9. 🟢 **RESOLVED** — Server-style integrations (EDL, Taxii, etc.) that act as a server need special handling. Both open questions are now answered by [Appendix I — Server-Style Integrations](#appendix-i-server-style-integrations): (a) **which integrations** — the canonical in-scope list (EDL, TAXII Server, TAXII2 Server, Microsoft Teams, AWS-SNS-Listener, Zoom) plus the forward-looking criteria for adding more; and (b) **what flag to pass to BE** — credential pinning via the `xsoar-long-running-credentials-profile-id` label under `triggering.labels`, mapping the integration's `type: 9` `credentials` param to a [`connection.yaml`](README.md:162) profile. --> no block
10. 🔴 **OPEN** — There will be a list of integrations that need manual migration as they are complex. LLM to create an appendix; **SAP BTP** should be added to the appendix as it has complex triggers around auth options.

##### Opens raised from FE/BE override analysis

The following opens were identified while consolidating the legacy XSOAR FE/BE override behaviors catalogued in [`plans/integration-parameter-and-types-overrides.md`](plans/integration-parameter-and-types-overrides.md:1) into the manifest model.

11. 🔴 **OPEN** — Allow `effect.message` on any trigger, not only capability triggers. The [`schema/triggers.schema.json`](schema/triggers.schema.json:1) today restricts `effect.message` to triggers whose `conditions` tree contains at least one `capability_condition` (see [`plans/triggers-v2.md`](plans/triggers-v2.md:1)). We need to express user-facing messages for purely field-driven triggers — example: when `proxy` is disabled because no `engine` / `engine_group` is selected, the UI must show *"Use system proxy settings is enabled only when an engine is selected"*. Request a schema relax from Adi to drop the capability-only restriction on `effect.message`.
12. 🔴 **OPEN** — "No issue type" empty-option pattern for `incidentType` / `alertType` dynamic dropdowns. Today the FE prepends a *"No issue type"* option whose stored value is `""`. We need to decide how to express this in the manifest — likely as a per-provider convention on `metadata.dynamic_values` (e.g., the platform always prepends an empty option whose label comes from the field's `placeholder` or a new `dynamic_values.empty_label` field). Open with Shahar and Guy. **Note**: the new `options.empty_values_message` field option (see §2.15) is *adjacent but does not resolve this* — it only supplies placeholder text shown when a `select`/`multi_select` has **no options at all**; it does **not** prepend a *selectable* empty option whose stored value is `""`. This open still needs a real decision.
13. 🟡 **PARTIALLY RESOLVED** — Engine 3-field pattern — location inside [`connection.yaml`](README.md:162) TBD. Shape, field IDs (`engine_mode` / `engine` / `engine_group`), radio options, `dynamic_values` config, and visibility triggers are **locked** — see §3.7 "Engine handling — 3-field pattern". Open question: which [`connection.yaml`](README.md:162) sub-section the three fields live in (`general_configurations` vs per-profile) pending profile-design finalization.
14. 🟡 **IN PROGRESS** — `duration-picker` field type still pending. Affects every `type: 19` (interval) parameter (`incidentFetchInterval`, `alertFetchInterval`, `eventFetchInterval`, `assetsFetchInterval`, `feedFetchInterval`, `feedExpirationInterval`). For now: emit these as `field_type: "duration-picker"` per the migration rules — connectors with these fields will be blocked from production until the field type ships. Cross-references existing item 2.
15. 🔴 **OPEN** — No field-level `advanced: true` collapsible-section concept in the manifest. Legacy XSOAR has `advanced: true` per parameter and a per-section "Show Advanced Settings" toggle. The manifest organizes fields by capability instead, with no notion of collapsible advanced sections within a capability. Decide whether to add `options.advanced: true` to the field schema or to drop the concept entirely.
16. 🔴 **OPEN** — `mail-listener` always-checked synthetic fetch toggle. The legacy FE `SYSTEM_ALWAYS_FETCH_BRANDS` list contains `mail-listener` — it forces the Fetch Settings section to always render with a disabled, always-checked fetch toggle. Believed to be an internal server-managed integration, but to be confirmed with engineering management before deciding if a manifest needs to be authored for it.
17. 🟢 **RESOLVED** — `resetContext` / "Reset Last Run" actions. Resolved together with item 7 — see `handler.yaml capabilities[].actions[]` in §2.8 + §3.8.
18. 🟡 **XSOAR `type: 9` credentials — hidden-leaf and display-name semantics.**

    - **`hiddenusername: true`** — the identifier leaf is suppressed.
      Do **NOT** include `<id>.identifier` as a key in
      `xsoar_param_map`. The `<id>.password` leaf, if not also hidden,
      MAY still appear.
    - **`hiddenpassword: true`** — the password leaf is suppressed.
      Do **NOT** include `<id>.password` as a key in
      `xsoar_param_map`. The `<id>.identifier` leaf, if not also
      hidden, MAY still appear. (`hiddenpassword` is a real YML field
      per demisto-sdk's strict-objects schema.)
    - **`displaypassword: "<custom label>"`** — overrides the **display
      name** of the password component of the `type: 9` credential.
      It does NOT change the underlying leaf id (`<id>.password`); it
      only changes the UI label. Common use: renaming "Password" to
      "API Key" / "Token" / "Secret Key" in the form.

    --> no blocks
19. 🟢 **NOTE** — `SYSTEM_OPTIONAL_FETCH_BRANDS` (elasticsearch, google, kafka, esm, syslog, crowdstrike-streaming-api) is a legacy XSOAR runtime fallback for integrations missing a proper `integrationScript`. **Not a migration concern** — the manifest always declares capabilities explicitly. Documented here for transparency only; no action. TODO verify with Guy that its actually only for XSOAR.
20. 🔴 **Cooc (cross-org / common-org code) integrations — scoping TBD.** Meeting scheduled with Judah to define how cooc integrations are migrated (which connector they belong to, whether they share a `connector.yaml` or get their own, how shared handlers/serializers are organized). Until that meeting concludes, defer any integration whose source file lives under a `cooc/` or `Packs/CommonScripts/`-style shared path. --> blocks
21. 🟡 **OPEN — Per-integration overrides for handler action `display` / `description`.** Per Decision (2026-06-05), the migration LLM omits `display` and `description` on every `capabilities[].actions[]` entry — the platform supplies canonical defaults. Some integrations may eventually want vendor-specific wording (e.g., "Reset Mailbox Last Sync" instead of the default "Reset Issues Last Run" for the EWS family). Track which integrations need overrides and add a per-integration override list when product / tech-writers weigh in. --> no blocks

### 3.3 connector.yaml Rules

#### Collect the following to compute defaults

1. From the list of integrations given, look at all the parent packs' `pack_metadata.json`.
2. Call the relevant integrations `relevant_integrations_ymls` and the relevant pack metadata files `relevant_packs_jsons`.
3. To determine the relevant licenses for an integration, look at the integration YML's `supportedModules` field; if not present, look at the parent pack's `pack_metadata.json` `supported_modules` field. If neither is found, raise a flag for manual intervention.

#### Rules for connector.yaml

| Field | Rule |
|---|---|
| `id` | Derived from the vendor name plus a capability suffix (see §3.3.1 "Connector ID and title — naming convention" below). Lowercase, words separated by dashes (e.g. `okta-automation-and-collection`). |
| `enabled` | always true, unless want to disable the connector |
| `metadata.title` | Derived from the vendor name plus a capability suffix (see §3.3.1 "Connector ID and title — naming convention" below). Title Case, words separated by spaces (e.g. `Okta Automation and Collection`). |
| `metadata.description` | Collect all descriptions from `relevant_packs_jsons` and suggest a generic connector description based on that. Flag this for review by a technical content writer. |
| `metadata.version` | Always `1.0.0` for new connectors. |
| `metadata.categories` | **Array.** Union of all `categories` from `relevant_packs_jsons`, deduplicated. At least one entry required. |
| `metadata.tags` | Union of all tags from `pack_metadata.json`, deduplicated. |
| `metadata.publisher` | Always `"Palo Alto Networks"`.  |
| `metadata.vendor` | Taken from the 'provider' field of the integration. Raise a flaf if the providers for this connector are not all the same.|
| `metadata.documentation` | TBD, still an open |
| `metadata.author_image` | Filename only, referencing an image **in the connector root directory** (e.g., `"salesforce-ic.svg"`). Discover the source PNG/SVG in `<pack>/integrations/<integration>/`. If multiple are found, pick the first. If none found, raise a flag. |
| `metadata.ownership.team` | Always `"xsoar"`. |
| `metadata.ownership.maintainers` | Always `["@xsoar-content"]`. |
| `settings.allow_skip_verification` | Always `true` unless the vendor explicitly requires a successful verification before enabling. |

#### 3.3.1 Connector ID and title — naming convention

The connector `id` (in [`connector.yaml`](#21-connectoryaml)) and `metadata.title` MUST encode the same information — the vendor name plus a suffix that reflects which top-level capability families the connector exposes. They differ only in formatting:

- **`id`** — lowercase, words separated by dashes, no spaces (e.g. `okta-automation-and-collection`). Must satisfy the schema's min-3-char rule and OPA validation.
- **`metadata.title`** — Title Case, words separated by spaces (e.g. `Okta Automation and Collection`).

##### Suffix derivation

Inspect the set of capabilities the connector ends up declaring in [`capabilities.yaml`](#25-capabilitiesyaml) and compute the suffix as follows:

| Capability set declared on the connector | Suffix (title form) | Suffix (id form) |
|---|---|---|
| Only `automation-and-remediation` | `Automation` | `automation` |
| Only one or more **collection** capabilities — any of `log-collection`, `fetch-issues`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets` | `Collection` | `collection` |
| Both `automation-and-remediation` AND at least one **collection** capability | `Automation and Collection` | `automation-and-collection` |

"Collection" is a deliberately broad umbrella that covers **every** fetch capability (`log-collection`, `fetch-issues`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets`) — even if the connector exposes several of them, the suffix is still the single word `Collection`. The suffix does NOT enumerate which collection capabilities are present.

##### Vendor prefix

The vendor prefix is the vendor name (the same value used for [`metadata.vendor`](#21-connectoryaml)) rendered as:

- **`id`**: lowercased, spaces replaced with dashes, any other non-`[a-z0-9-]` character stripped or replaced with a dash (e.g. `Palo Alto Networks` → `palo-alto-networks`).
- **`metadata.title`**: Title Case, spaces preserved (e.g. `palo alto networks` → `Palo Alto Networks`).

##### Worked examples

| Vendor | Capabilities declared | `id` | `metadata.title` |
|---|---|---|---|
| Okta | `automation-and-remediation` + `log-collection` | `okta-automation-and-collection` | `Okta Automation and Collection` |
| Okta | `automation-and-remediation` only | `okta-automation` | `Okta Automation` |
| Okta | `log-collection` only | `okta-collection` | `Okta Collection` |
| Salesforce | `automation-and-remediation` only | `salesforce-automation` | `Salesforce Automation` |
| Palo Alto Networks | `automation-and-remediation` + `fetch-issues` + `threat-intelligence-and-enrichment` | `palo-alto-networks-automation-and-collection` | `Palo Alto Networks Automation and Collection` |

##### Flags

- If the connector declares **zero** capabilities, raise a flag — every connector must expose at least one capability family.
- If the vendor name cannot be cleanly rendered as a slug (e.g. contains characters outside `[A-Za-z0-9 ]`), raise a flag for manual review of the chosen `id`.

### 3.4 capabilities.yaml Rules

**Every capability must have at least one sub-capability** per the migration model (see assumption §3.1 item 13). When only one sub-capability exists under a parent capability, document the open UX question: how does the UI behave when the user enables the parent — should the single sub-capability auto-select? See §3.2.2 item 7.

#### Capability Mappings

| XSOAR Feature | Target Capability |
|---|---|
| All integrations with a command (supported on platform) other than a "fetch" command | Sub-capability with the integration name under capability `automation-and-remediation`. Unless the name/id of the integration contains "eventcollector" @yyy for technical implementation|
| If an integration YML has `isfetchevents: true` for platform | `log-collection` |
| If an integration YML has `isfetch: true` for platform | `fetch-issues` |
| If an integration YML has `isfetchassets: true` for platform | `fetch-assets-and-vulnerabilities` |
| If an integration YML has `isFeed: true` for platform | `threat-intelligence-and-enrichment` |
| If an integration YML has `isFetchCredentials: true` for platform | `fetch-secrets` |

#### Notes

1. An integration can meet the requirement for more than one capability (for example, multiple fetch types, or a fetch type with other commands) in that case create the needed capabilities, each with a sub-capability whose ID is `<capability_id>_<integration_id>` so sub-capability IDs are unique in the connector.
2. There can be more than one integration under each capability. Each integration becomes its own sub-capability whose `title` is the integration name exactly and whose `id` is `<capability_id>_<integration_id>`.
3. If there is more than one integration with the SAME fetch type, raise a flag (i.e. two or more integrations have `isfetch:true` on platform). This is allowed but should be brought to attention.
4. If a single integration contains both `isFeed` and/or `isfetch` (or any other fetch capability: `log-collection`, `fetch-issues`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`) and/or `isFetchCredentials`, raise a flag. This is allowed but should be brought to attention.
5. When `isFetchEvents` or `isFetchAssets` exist → omit the corresponding checkbox parameter (e.g., `isFetchEvents`, `isFetchAssets`). Choosing the capability/sub-capability implies the feature is enabled. Only add the other fields (e.g., `eventFetchInterval`, `assetsFetchInterval`, `longRunning`, classifier, mapper, alertType, etc.).
6. The capabilities `fetch-issues`, `log-collection`, and `fetch-assets-and-vulnerabilities` should only be shown to customers with licenses `agentix` or `xsiam`. This is enforced via `config.required_license`.
7. **Fetch mutex (generalized)** — a connector instance cannot enable more than one fetch capability at a time. The mutex covers **all five** fetch capabilities: `log-collection`, `fetch-issues`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets`. This generalizes (and replaces) the legacy XSOAR check `if (isFetchIncidents && isFeed) || (isFetchIncidents && isFetchEvents) || (isFetchEvents && isFeed) { return error(...) }` which only covered three of the five flags. **Behavior**: instead of failing instance creation with an error, the UI proactively prevents the conflict by marking the non-chosen fetch sub-capabilities as `read_only: true` while one is active, and replacing their description with the message *"Select only one fetch option for this sub-capability"*. Enforced via [`triggers.yaml`](README.md:833) — see §3.5 for the concrete trigger pattern.

#### Rules for capabilities.yaml — metadata

| Field | Rule |
|---|---|
| `metadata.title` | Always `"Capabilities"`. |
| `metadata.description` | Always `"Name and configure the instance capabilities"`. Flag for technical content writer review. |
| `metadata.help` | 🟡 **IN PROGRESS** Tech team to write LLM skill to generate this based on the packs and integrations documentation. |

#### Rules — general_configurations

| Field | Rule |
|---|---|
| `general_configurations.description` | Always `"General configurations for all capabilities"`. |
| `general_configurations.configurations` | Always include the mandatory `instance_name` field (below).  |

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
        create_modifiers:
          required: true
          read_only: false
          hidden: false
        edit_modifiers:
          required: true
          read_only: false
          hidden: false
```

#### Rules — capabilities

1. A list of YAML objects, each defining a capability.
2. For each capability, use the following rules:

| Field | Rule |
|---|---|
| `capabilities.id` | One of: `automation-and-remediation`, `log-collection`, `fetch-issues`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, `fetch-secrets`. |
| `capabilities.title` | `automation-and-remediation` → `"Automation and Remediation"`; `log-collection` → `"Log Collection"`; `fetch-issues` → `"Fetch Issues"`; `fetch-assets-and-vulnerabilities` → `"Fetch Assets and Vulnerabilities"`;`threat-intelligence-and-enrichment` → `"Threat Intelligence and Enrichment"`; `fetch-secrets` → `"Fetch Secrets"`. |
| `capabilities.description` | 🟡 **IN PROGRESS** Tech team / PM / tech-writer to write them up. |
| `capabilities.required` | Always `false`. |
| `capabilities.config.required_license` | Aggregate all licenses from sub-capabilities under this capability. If there are no sub-capabilities, take from the integration YML or its parent pack's `pack_metadata.json`. |

3. For each sub-capability, use the following rules:

| Field | Rule |
|---|---|
| `sub_capabilities.id` | `<capability_id>_<integration_id> Where the integration name lowercased, spaces replaced with dashes 
(e.g., `Hello World IAM`as part of the `automation-and-remediation` capability → `automation-and-remediation_hello-world-iam`). |
| `sub_capabilities.title` | The integration name in Title Case (e.g., `Salesforce IAM`). |
| `sub_capabilities.description` | The description of the integration from the integration YML. TBD weather we should have AI do a description based on the sub-capability and not just the integration description. Flag for technical writer review. |
| `sub_capabilities.default_enabled` | Always `false`. TODO, check if we make this true, if the parent capability is also going to be default enabled true. If there is only 1 sub-capability under the capability and that parent capability is chosen, then we also want that sub-capability chosen automatically, so to check if this is the current behavior which can give us that. |
| `sub_capabilities.required` | Always `false`. |
| `sub_capabilities.config.required_license` | Take licenses from the integration YML; if absent, from the parent pack's `pack_metadata.json`. **MUST be a subset of the integration's `supportedModules`** — see §3.1 assumption 14. Declaring a license here that the underlying integration does not support causes a silent XSOAR BE failure at instance-creation time. Flag any superset as a migration bug. |

### 3.5 Triggers YAML

[`triggers.yaml`](README.md:833) is an **optional** file at the connector root that defines reactive, reversible UI field behavior — show/hide, require, read-only, and enable/disable — driven by field values and/or capability state. It is the single source of truth for conditional form behavior in the connector.

Common migration scenarios where triggers are needed:

- **Capability → field gating** — show or require a field only when a given capability is enabled (e.g., reveal `feedExpirationInterval` only when `threat-intelligence-and-enrichment` is on **AND** `feedExpirationPolicy == "interval"`).
- **Field → field gating** — show `longRunningPort` only when `longRunning == true` **AND** no `engine` / `engineGroup` is selected **AND** the integration is in the engine-excluded list.
- **Fetch-mutex (generalized — all 5 fetch capabilities)** — only ONE fetch capability may be enabled at a time. The mutex pool covers `log-collection`, `fetch-issues`, `fetch-assets-and-vulnerabilities`, `threat-intelligence-and-enrichment`, and `fetch-secrets`. For every fetch sub-capability the connector declares, author one trigger per *other* fetch sub-capability in the connector (per-integration when sub-capabilities are integration-scoped — see §3.4 sub-capability id convention). Trigger shape:
    - `conditions`: a `capability_condition` checking that one of the *other* fetch sub-capabilities is `on`.
    - `effects`: target the current sub-capability by id (`effect.id: <sub_capability_id>`), `action: { read_only: true }`, and `message: "Select only one fetch option for this sub-capability"`.
  When the locking condition turns off, the trigger reverses (the effect is reversible per §2.10), so the sub-capability becomes selectable again.

  **Worked YAML fragment** (assumes per-integration sub-capabilities `fetch-issues_<i>` and `log-collection_<i>` exist for integration `<i>`):

  ```yaml
  triggers:
    # While log-collection is on, lock fetch-issues for the same integration.
    - conditions:
        type: capability_condition
        id: log-collection_<i>
        behavior: state
        value: on
      effects:
        - id: fetch-issues_<i>
          action:
            read_only: true
          message: "Select only one fetch option for this sub-capability"

    # Symmetric — while fetch-issues is on, lock log-collection.
    - conditions:
        type: capability_condition
        id: fetch-issues_<i>
        behavior: state
        value: on
      effects:
        - id: log-collection_<i>
          action:
            read_only: true
          message: "Select only one fetch option for this sub-capability"
  ```

  Repeat for every pair `(A, B)` where both A and B are fetch sub-capabilities of the same integration. For `n` fetch sub-capabilities under one integration the migration emits `n × (n - 1)` triggers (each direction must be a separate trigger because `effect.id` is a single value).

**For the full spec**, see the [`README.md`](README.md:1) "triggers.yaml" section, the schema at [`schema/triggers.schema.json`](schema/triggers.schema.json:1), and the in-repo design doc at [`plans/triggers-v2.md`](plans/triggers-v2.md:1) for condition variants, operators, effect shape, validation rules, and worked YAML examples.

### 3.6 Connection YAML

#### Rules for connection.yaml — metadata

| Field | Rule |
|---|---|
| `metadata.title` | Always `"Connection"`. |
| `metadata.description` | Always `"Enter the credentials to securely authorize the connection"`. Flag for technical content writer review. |
| `metadata.help` | A long Markdown text. Collect the connection profiles from the integration YMLs and the `README.md` for each relevant integration; using an LLM, extract only the parts that explain the connection methods and how to configure each of them (nothing about commands, input/output). Combine with your knowledge of the vendor to explain how to connect with each supported authentication method. Flag for technical content writer review. |

**IN PROGRESS** — The migration of XSOAR Type 9 (credentials) parameters and related auth fields (`displaypassword`, `hiddenusername`, `hiddenpassword`, multi-token patterns) into [`connection.yaml`](README.md:162) profiles is part of this guide's scope, but the **manifest language for profiles is not yet finalized**. The rules below are a working draft — expect refinement as the profile design lands. Tracked in §3.2.2 (Opens).

See [`plans/integration-parameter-and-types-overrides.md`](plans/integration-parameter-and-types-overrides.md:1) for the full FE/BE behavior we are reproducing in the manifest (Type 9 widget, `displaypassword`, `hiddenusername`, `hiddenpassword`).

#### Rules — general_configurations

> **Scoping note**: The `domain` (a.k.a. instance URL) field in `general_configurations` applies **only to Standard connectors** (one vendor → one handler). This migration guide targets **Grouped connectors** (one vendor → many handlers, e.g., `salesforce` with `xsoar_sf` + `xsoar_sf_iam` + `discovery` + `identity`). For Grouped connectors, the `domain` field is OUT OF SCOPE for this migration — each handler manages its own URL/domain logic. Document the existing rules below as reference only; do not emit a `general_configurations.domain` block in Grouped connector manifests.

General configuration section is in progress and currently an open


#### Profiles

1. A list of objects, each defining a connection profile.
2. If an integration's connection cannot be cleanly mapped to a typed profile (`oauth2_*` / `plain` / `api_key` / `oauth2_jwt_bearer`) — including integrations that require more than one auth input simultaneously (e.g., Slack v3 needs three API keys at once) — use the **`passthrough`** profile type. It stores whatever fields you declare and returns them verbatim to the handler on `getCredentials` with no IDP/token exchange. See §2.6.1 for the full spec.
3. For each profile, use the [Profile Schema](#22-connectionyaml) in §2.2 and the auth-parameter tagging rules in §2.6.
4. Fields that are related to connection but **not** to the auth (i.e. `proxy`, `engine` / `engine_group`, `insecure` / Trust Any Certificate) reside **within the profile**.
   - **MANDATORY `metadata.event.publish: true`**: these operational fields MUST carry `metadata.event.publish: true` (see §2.17). Connection-profile field values are normally only available via get-credentials, but the XSOAR BE needs `engine` / `proxy` / `insecure` **before** creating the instance — `event.publish` ships their values in the create/edit lifecycle pub/sub event so the BE gets them up front.
   - These fields carry **no** `metadata.auth.parameter` (they are not secrets), which is why `event.publish` is allowed on them — the two keys are mutually exclusive (§2.17).

   **Worked fragment** (engine + proxy + insecure inside a profile):

   ```yaml
   # connection.yaml (profile fragment)
   configurations:
     - fields:
         - id: "proxy"
           title: "Use system proxy settings"
           field_type: "checkbox"
           metadata:
             event:
               publish: true
             xsoar:
               config_type: "backend"
           options:
             mask: false
             default_value: false
         - id: "insecure"
           title: "Trust Any Certificate (Not Secure)"
           field_type: "checkbox"
           metadata:
             event:
               publish: true
             xsoar:
               config_type: "backend"
           options:
             mask: false
             default_value: false
   ```

   > The exact connection.yaml sub-section the engine 3-field pattern lives in is still TBD — see §3.2.2 item 13 and §3.7 "Engine handling — 3-field pattern" — but wherever the engine/proxy/insecure fields land inside a profile, the `metadata.event.publish: true` requirement above applies.

### 3.7 Configurations YAML

> **Source of truth for FE/BE override behavior**: every custom behavior the legacy XSOAR FE/BE applies to integration parameters (label overrides, conditional visibility, value mapping, auto-added params, etc.) is catalogued in [`plans/integration-parameter-and-types-overrides.md`](plans/integration-parameter-and-types-overrides.md:1). The rules in this section translate those behaviors into the manifest. When in doubt, consult that document first.

#### General principles

1. **ALL params in manifest**: every configuration parameter must be defined in the connector manifest — including backend-managed ones like `proxy`, `insecure`, `incidentType`, `longRunning`, `mapper_in`. Use `metadata.xsoar.config_type: "backend"` for backend-managed fields.
2. **One field per row**: each field gets its own `fields` block in `configurations.yaml` for UI clarity — each field is a separate row.
3. **Field behavior preservation**: field type, default value, options, title, id, tooltip, required — must match the original integration YML exactly (unless stated otherwise).
4. **`integrationLogLevel`**: always include in [`capabilities.yaml`](README.md:509) `general_configurations`. This is a backend-managed field needed for all connectors. Example:
   ```yaml
   - id: "integrationLogLevel"
     title: "Integration Log Level"
     field_type: "select"
     metadata:
       xsoar:
         config_type: "backend"
     options:
       description: "Set the log level for the integration"
       placeholder: "Select log level"
       default_value: "Off"
       values:
         - key: "Off"
           value: "Off"
         - key: "Debug"
           value: "Debug"
         - key: "Verbose"
           value: "Verbose"
       create_modifiers:
         required: false
         hidden: false
       edit_modifiers:
         required: false
         hidden: false
   ```
5. **`longRunning` handling**: long-running integrations are supported. Define `longRunning` as a backend-managed field (`metadata.xsoar.config_type: "backend"`). The backend will create a long-running container when the user enables it.

#### Metadata

| Field | Rule |
|---|---|
| `metadata.title` | Always `"Configuration"`. |
| `metadata.description` | Always `"Adjust and refine your configuration"`. Flag for technical content writer review. |

#### configurations

1. A list of objects, each defining a capability's configuration.
2. Each capability/sub-capability should have its own configurations.
3. The configurations for a capability/sub-capability should mirror the configurations of the underlying integrations.
4. Configuration IDs must be unique across the entire connector (see Appendix C).

#### XSOAR Type → UCP Manifest Type Mapping

| XSOAR Type | UCP `field_type` | `options.mask` | Notes |
|---|---|---|---|
| 0 (Short String) | `input` | `false` | Standard text input. |
| 1 (Number/Integer) | `input` | `false` | Text input (no separate number type in UCP). |
| 4 (Encrypted/Password) | `input` | `true` | Masked input for secrets. |
| 8 (Boolean/Checkbox) | `checkbox` | N/A | Single boolean toggle. |
| 9 (Credentials) | **OUT OF SCOPE** | — | Handled by connection profiles. |
| 12 (Long Text/TextArea) | `text_area` | `false` | Multi-line text. |
| 13 (Incident Type) | `select` + `metadata.dynamic_values` | `false` | Option list fetched at runtime from the XSOAR provider. **User-visible field** — do NOT mark it `metadata.xsoar.config_type: "backend"`. Use `params: {integrationID: "<id>", dynamicField: "incident-type"}`. |
| 14 (Encrypted TextArea) | `text_area` | `true` | Masked textarea. |
| 15 (Single Select) | `select` | `false` | Options from YML `options` array as `{key, label}` pairs. |
| 16 (Multi Select) | `multi_select` | `false` | Use the native `multi_select` field type. Items in `values` use `{key, label}` shape; `default_value` is an array of keys. See README [Multi-Select Example](README.md:1681). |
| 17 (Feed Expiration Policy) | `select` | `false` | Single-select with fixed options. Only added when `script.Feed: true`. |
| 18 (Feed Reputation) | `select` | `false` | New mapped values: `Unknown` / `Benign` / `Suspicious` / `Malicious` (not the legacy None/Good/Suspicious/Bad). Only added when `script.Feed: true`. |
| 19 (Feed Fetch Interval) | `duration-picker` (planned) | `false` | Duration picker is still in development in UCP (§3.2.2 item 2). Stored in minutes. Use [`triggers.yaml`](README.md:833) to control conditional visibility (see §3.5). |
| 22 (Copy to Clipboard) | `label` | `false` | Read-only text with copy functionality. Appears only in Generic Webhook — likely ignorable. |

#### Complete Configuration Field Rules

1. **Configuration `id`** must equal the parameter `name` from the integration YML.
2. **Configuration IDs must be globally unique** across the entire connector (across [`connection.yaml`](README.md:162), [`capabilities.yaml`](README.md:509), and [`configurations.yaml`](README.md:719)). Enforced by OPA validation.
3. **If two configurations have the same id** (from different integrations), give one of them a prefix of the integration id (e.g., `salesforce_iam_proxy`). Then in the handler [`serializer.yaml`](README.md:1381), map the prefixed ID back to the original name the integration expects.
4. **Field title**: use the `display` field from the integration YML parameter. If it contains "Incidents", replace with "Issues" (Platform marketplace terminology).
5. **Field type**: map using the table above.
6. **Default value**: use `defaultvalue` from the YML. For marketplace-specific defaults (e.g., `defaultvalue:platform: "something"`), use the platform-specific value.
7. **Required**: use `required` from the YML.
8. **Description/tooltip**: use `additionalinfo` from the YML as `options.description` or `options.help_text`.
9. **Options for select fields**: convert YML `options` array to `{key, label}` pairs in `options.values` (both `select` and `multi_select` use the `{key, label}` shape per the live schema).
10. **Hidden fields on platform**: if a parameter has `hidden: [platform]` or equivalent, exclude it from the manifest entirely.
11. **Marketplace-specific values**: if a parameter has marketplace-specific overrides (e.g., `defaultvalue:platform: "value"`), use the platform-specific value.
12. **Auth-related params are OUT OF SCOPE**: skip params like `proxy` (omit entirely for integrations listed in [Appendix G](#appendix-g-engine--enginegroup--proxy-exclusion-list)), `insecure`, type 9 credentials, and domain/URL fields used for auth connection.

#### Instance-Level Properties That Must Be in the Manifest

These were previously managed by FE/BE custom code and must now be explicitly defined:

| Property | Where in Manifest | `field_type` | `metadata.xsoar.config_type` | Notes |
|---|---|---|---|---|
| `integrationLogLevel` | [`capabilities.yaml`](README.md:509) → `general_configurations` | `select` | `"backend"` | Always present. Options: Off/Debug/Verbose. |
| `defaultIgnore` | [`configurations.yaml`](README.md:719) → under `automation-and-remediation` capability | `checkbox` | `"backend"` | "Do not use in CLI by default". |
| `engine` | [`configurations.yaml`](README.md:719) | `select` + `metadata.dynamic_values` | `"backend"` | Backend-managed. Always emitted, unless the integration is in [Appendix G — Engine / EngineGroup / Proxy Exclusion List](#appendix-g-engine--enginegroup--proxy-exclusion-list). Use `metadata.dynamic_values: {provider: "xsoar", trigger: ["on_create","on_edit"], params: {integrationID: "<id>", dynamicField: "engine"}}`. MUST set `options.empty_values_message: "No engines available"` (see the 3-field pattern below). |
| `engineGroup` | [`configurations.yaml`](README.md:719) | `select` + `metadata.dynamic_values` | `"backend"` | Backend-managed. Always emitted, unless the integration is in [Appendix G — Engine / EngineGroup / Proxy Exclusion List](#appendix-g-engine--enginegroup--proxy-exclusion-list). Same shape as `engine`, with `dynamicField: "engine-group"`. MUST set `options.empty_values_message: "No engine groups available"` (see the 3-field pattern below). |
| `mappingId` | [`configurations.yaml`](README.md:719) → under relevant capability | `select` + `metadata.dynamic_values` | `"backend"` | "Classifier" — added when `isFetch: true`. Use `dynamicField: "classifier"`. |
| `incomingMapperId` | [`configurations.yaml`](README.md:719) → under relevant capability | `select` + `metadata.dynamic_values` | `"backend"` | Display: "Mapper (incoming)" — added when `isFetch: true`. Use `dynamicField: "mapper-incoming"`. |
| `outgoingMapperId` | **OUT OF SCOPE** | — | — | Mirroring not supported on Platform. |
| `defaultClassifier` | [`configurations.yaml`](README.md:719) → under relevant capability | (becomes the `default_value` of `mappingId`) | N/A | Not a UI field — populated as `options.default_value` on the `mappingId` field. The literal is applied only if it appears in the runtime-fetched list (see §2.16). |
| `defaultMapperIn` | [`configurations.yaml`](README.md:719) → under relevant capability | (becomes the `default_value` of `incomingMapperId`) | N/A | Same pattern as `defaultClassifier`. |
| `defaultMapperOut` | **OUT OF SCOPE** | — | — | Mirroring not supported on Platform. |

##### Engine handling — 3-field pattern

Every migrated integration that previously declared XSOAR `engine` and/or `engineGroup` parameters emits a **three-field pattern** that replaces both. Exact location inside [`connection.yaml`](README.md:162) is still **TBD** (see Open Item 13 in §3.2.2) — pending finalization of profile design — but the **field shape, IDs, options, and visibility logic are locked**.

**Fields (declared somewhere in [`connection.yaml`](README.md:162)):**

| ID | Type | Purpose | Default | Required | `empty_values_message` |
|----|------|---------|---------|----------|------------------------|
| `engine_mode` | `select` (horizontal radio when supported) | Selector for engine routing | `no_engine` | true | — (static options) |
| `engine` | `select` + `dynamic_values` (provider `xsoar`, `dynamicField: engine`) | Specific engine | — | false | `"No engines available"` |
| `engine_group` | `select` + `dynamic_values` (provider `xsoar`, `dynamicField: engine-group`) | Engine group | — | false | `"No engine groups available"` |

`engine_mode` options (keys + labels):
- `no_engine` — "No engine"
- `engine` — "Engine"
- `engine_group` — "Engine Group"

**Empty-state messages (MANDATORY):** because `engine` and `engine_group` are dynamic dropdowns whose option lists are fetched at runtime, they MUST set [`options.empty_values_message`](#215-field-options) so the user gets clear feedback when the tenant has none configured:
- `engine` → `options.empty_values_message: "No engines available"`
- `engine_group` → `options.empty_values_message: "No engine groups available"`

**Visibility via [`triggers.yaml`](README.md:833):**
- Hide `engine` when `engine_mode != "engine"`.
- Hide `engine_group` when `engine_mode != "engine_group"`.

**YAML skeleton (illustrative — final location TBD):**

```yaml
# connection.yaml (fragment)
- id: engine_mode
  field_type: select
  title: Engine
  options:
    required: true
    default_value: no_engine
    values:
      - key: no_engine
        value: "No engine"
      - key: engine
        value: "Engine"
      - key: engine_group
        value: "Engine Group"

- id: engine
  field_type: select
  title: Engine
  metadata:
    dynamic_values:
      provider: xsoar
      trigger: [on_create, on_edit]
      params:
        dynamicField: engine
  options:
    empty_values_message: "No engines available"

- id: engine_group
  field_type: select
  title: Engine Group
  metadata:
    dynamic_values:
      provider: xsoar
      trigger: [on_create, on_edit]
      params:
        dynamicField: engine-group
  options:
    empty_values_message: "No engine groups available"
```

```yaml
# triggers.yaml (fragment) — conditional visibility
triggers:
  - conditions:
      type: condition
      id: engine_mode
      operator: neq
      behavior:
        value: engine
    effects:
      - id: engine
        action: { hidden: true }
  - conditions:
      type: condition
      id: engine_mode
      operator: neq
      behavior:
        value: engine_group
    effects:
      - id: engine_group
        action: { hidden: true }
```

**Carve-outs:**
- **[Appendix G](#appendix-g-engine--enginegroup--proxy-exclusion-list)** integrations: do **not** emit any of the three engine fields (and do not emit `proxy`).
- **[Appendix H](#appendix-h-single-engine-integrations)** integrations: emit only `engine_mode` (radio reduced to `no_engine` + `engine`) and the `engine` dropdown — omit `engine_group` entirely.

> If the FE doesn't yet support a horizontal-radio variant of `select`, fall back to plain `select` rendering — the field IDs, option keys, and triggers remain identical.

#### Excluding `engine`, `engineGroup`, and `proxy` for specific integrations

For the integrations listed in [Appendix G](#appendix-g-engine--enginegroup--proxy-exclusion-list), the `engine`, `engineGroup`, and `proxy` fields must be **completely omitted** from the connector manifest — do not emit field entries for them at all. These integrations either run as long-running servers / listeners (EDL, TAXII servers, XSOAR-Web-Server, AWS-SNS-Listener, Web File Repository, etc.) or are platform-native cloud integrations (AWS, Azure, GCP, Microsoft Teams) whose networking is handled outside the standard engine/proxy model.

**Matching rule**: case-insensitive exact match against the integration `commonfields.id`. AWS / Azure / GCP are the literal integration IDs — do **not** treat them as prefixes (e.g., "AWS-IAM" or "Azure-AD" are not auto-included).

This rule supersedes the default behavior described above for `engine`, `engineGroup`, and `proxy` for these specific integrations.

#### BE-Auto-Added Params That Must Be Explicitly in Manifest

When certain script flags are `true`, the BE previously auto-added params. These must now be explicitly defined in the manifest:

**When `script.IsFetch: true`** → add to **`fetch-issues`** capability (or sub-capability matching this integration):

- ~~`isFetch` checkbox~~ — **OMIT**: choosing the capability implies fetch is enabled.
-  `alertFetchInterval` — duration-picker field
- `incidentType` / `alertType` (Platform/XSIAM uses `alertType`) — `select` + `metadata.dynamic_values` with `dynamicField: "incident-type"`. **User-visible field** —  mark `metadata.xsoar.config_type: "backend"`. Emission rules:
  - **Only emit** if the integration YML actually declares a parameter with `type: 13`. If no `type: 13` param exists in the YML, do not emit the field.
  - **Emit only under the `fetch-issues` capability** — never under `log-collection`, `fetch-assets-and-vulnerabilities`, or `threat-intelligence-and-enrichment` (the legacy BE explicitly strips `incidentType` when `script.Feed: true` or `script.IsFetchEvents: true`).
  - **Visibility**: the field is visible when the `fetch-issues` capability is enabled OR when `script.isfetchsamples: true` (in which case it is ALWAYS visible). The manifest expresses capability-driven visibility implicitly via the capability the field lives under; the `isfetchsamples` always-visible case translates to: *always emit the field, regardless of capability state, when `script.isfetchsamples: true`* (use a [`triggers.yaml`](README.md:833) effect to force visibility on, or place the field outside the per-capability `configurations` block as appropriate).
- `mappingId` — `select` + `metadata.dynamic_values` (`dynamicField: "classifier"`).
- `incomingMapperId` — `select` + `metadata.dynamic_values` (`dynamicField: "mapper-incoming"`).

**When `script.Feed: true`** → add to `threat-intelligence-and-enrichment` capability:

- ~~`feed` checkbox~~ — **OMIT**.
- `feedReputation` — `select` with options: `Unknown` / `Benign` / `Suspicious` / `Malicious`.
- `feedReliability` — `select` field. **Take `values`, `default_value`, and `required` from the integration YML.** If the YML does not declare a `defaultvalue`, use `"F - Reliability cannot be judged"` as the default. The BE auto-adds this as required by default; keep `required: true` unless the YML explicitly says otherwise.
- `feedExpirationPolicy` — `select` with options: `Indicator Type` / `Time Interval` / `Never Expire` / `When removed from the feed`.
- `feedExpirationInterval` — `duration-picker`, shown only when `feedExpirationPolicy === "interval"`. **Use a [`triggers.yaml`](README.md:833) entry** — see §3.5 (capability → field gating pattern).
- `feedFetchInterval` — `duration-picker` (default 240 minutes = 4 hours).
- `feedBypassExclusionList` — `checkbox`.

**When `script.IsFetchEvents: true`** → add to **`log-collection`** capability (or sub-capability matching this integration):

- ~~`isFetchEvents` checkbox~~ — **OMIT**.
- `eventFetchInterval` — `duration-picker` (default 1 minute).

**When `script.IsFetchAssets: true`** → add to **`fetch-assets-and-vulnerabilities`** capability (or sub-capability matching this integration):

- ~~`isFetchAssets` checkbox~~ — **OMIT**.
- `assetsFetchInterval` — `duration-picker` (default 1 minute).

**When `script.LongRunning: true`** → add to the relevant fetch capability this integration maps to (`log-collection` / `fetch-issues` / `fetch-assets-and-vulnerabilities` / `fetch-secrets`):

- `longRunning` — `checkbox` with `metadata.xsoar.config_type: "backend"`.
- `longRunningPort` — `input` with `metadata.xsoar.config_type: "backend"`. **Conditional visibility** is enforced via [`triggers.yaml`](README.md:833) — see §3.5 (field → field gating pattern): visible only when `longRunning == true` AND `engine` is empty AND `engineGroup` is empty.

**When `script.IsFetchCredentials: true`** → add to **`fetch-secrets`** capability:

- ~~`isFetchCredentials` checkbox~~ — **OMIT**.

#### `section` field — ignored

The legacy `section` field on XSOAR parameters (`Connect` / `Collect` / `Optimize` / `Mirroring` / `Result`) is **ignored** during migration. The manifest organizes fields by capability instead. Do not attempt to preserve `section` placement.

#### `advanced: true` per-parameter flag — known gap

The legacy `advanced: true` flag (collapsible "Advanced" sub-section within a tab) has no equivalent in the manifest. During migration, **emit the field as a regular field** (no advanced grouping) and add an entry to the migration Gap Analysis output noting which fields had `advanced: true` in their source YML. Tracked in §3.2.2 Opens.

#### Script flags ignored during migration

The following XSOAR `script` flags are dev-mode/internal and have no effect on the connector manifest — skip them entirely during migration:

- `script.mappable` — schema mapping (dev-mode UI only).
- `script.runOnce` — separate-container execution (dev-mode UI only).
- `script.mcp` — Model Context Protocol marker (FE-only; not in the BE struct).

### 3.8 Handler YAML

1. Each integration gets its own `handler.yaml`.
2. All handlers live under `connectors/<vendor>/components/handlers/<integration-id>/`.
3. The file name is always `handler.yaml`.

#### Rules for handler.yaml

| Field | Rule |
|---|---|
| `id` | Always `"xsoar-<integration-id>"`. |
| `enabled` | Always `true`. |
| `metadata.version` | Always `"1.0.0"`. |
| `metadata.description` | Always `"XSOAR handler for <integration name> integration"`. |
| `metadata.module` | Always `"xsoar"`. |
| `metadata.ownership.team` | Always `"xsoar"`. |
| `metadata.ownership.maintainers` | Always `["@xsoar-content"]`. |
| `triggering.type` | Always `"PUB_SUB"`. |
| `triggering.labels.xsoar-integration-id` | The integration id from the integration YML. |
| `triggering.labels.xsoar-pack-id` | The pack id from the `pack_metadata.json` for this integration. |
| `triggering.args` | Always `{}`. |
| `test_connection.type` | Always `"service"` for XSOAR-delegated verification. |
| `test_connection.service` | Always `"xsoar"`. |
| `test_connection.endpoint` | Always `"/settings/integration/connector/verification"`. |

> **Note**: the schema also supports `test_connection.type: "endpoint"` with `host` (supports `{tenant_id}` interpolation) and optional `headers`. Use it when the verification should call an HTTP endpoint directly rather than delegating to the XSOAR service. See README [TestConnection Schema](README.md:1247).

#### Rules for the handler `capabilities` section

1. Each handler maps to exactly **ONE** integration, and there will not be another handler with the same integration.
2. If an integration has both fetch AND commands, the handler subscribes to both capabilities (`automation-and-remediation` and the relevant fetch capability — `log-collection` / `fetch-issues` / `fetch-assets-and-vulnerabilities` / `threat-intelligence-and-enrichment` / `fetch-secrets`).
3. If there are multiple fetch types across different integrations (e.g., one has `isFetch`, another has `isFetchEvents`):
   - Create sub-capabilities under the matching fetch capability (`fetch-issues` for `isFetch`, `log-collection` for `isFetchEvents`, etc.) for each unique fetch type.
   - Each sub-capability maps to exactly one integration.
   - Each integration still has exactly one handler that subscribes to its relevant sub-capability (and any other capabilities it supports).
4. Auth options reference the connection profile id from [`connection.yaml`](README.md:162). For the Salesforce reference, this is `oauth2_client_credentials.salesforce` and `oauth2_authorization_code.salesforce`.
5. Workloads should always be `["xsoar-pod"]`.

#### Handler capabilities format

```yaml
capabilities:
  - id: "<capability-id>"  # e.g., "automation-and-remediation" or "log-collection"
    workloads:
      - "xsoar-pod"
```

If the handler is for a sub-capability:

```yaml
capabilities:
  - id: "<parent-capability-id>/<sub-capability-id>"
    workloads:
      - "xsoar-pod"
```

If the handler subscribes to multiple capabilities (integration has both commands and fetch):

```yaml
capabilities:
  - id: "automation-and-remediation"
    workloads:
      - "xsoar-pod"
  - id: "log-collection"
    workloads:
      - "xsoar-pod"
```

Example:

```yaml
id: "xsoar-salesforce"

metadata:
  version: "1.0.0"
  description: "XSOAR handler for Salesforce integration"
  module: "xsoar"
  ownership:
    team: "xsoar"
    maintainers:
      - "@xsoar-content"

enabled: true

triggering:
  type: "PUB_SUB"
  labels:
    xsoar-integration-id: "Salesforce"
    xsoar-pack-id: "Salesforce"
  args: {}

capabilities:
  - id: "automation-and-remediation"
    auth_options:
      - id: "oauth2_client_credentials.salesforce"
        scopes:
          - "api"
          - "chatter_api"
          - "refresh_token"
          - "offline_access"
        workloads:
          - "xsoar-pod"
      - id: "oauth2_authorization_code.salesforce"
        scopes:
          - "api"
          - "chatter_api"
        workloads:
          - "xsoar-pod"

test_connection:
  type: "service"
  service: "xsoar"
  endpoint: "/settings/integration/connector/verification"
```

#### Actions per sub-capability

Each handler emits an `actions[]` array on the relevant sub-capability `capabilities[]` entry based on the XSOAR integration YML's fetch flags. The mapping is mechanical:

| XSOAR YML flag | Sub-capability the action is placed on | `actions[].type` |
|---|---|---|
| `isfetch: true` (Platform) | `fetch-issues_<integration>` | `reset_incidents_last_run` |
| `isfetchevents: true` (Platform) | `log-collection_<integration>` | `reset_events_last_run` |
| `isfetchassets: true` (Platform) | `fetch-assets-and-vulnerabilities_<integration>` | `reset_assets_last_run` |
| `feed: true` (a.k.a. `isFeed`) (Platform) | `threat-intelligence-and-enrichment_<integration>` | `reset_feed_last_run` |
| `isFetchCredentials: true` (Platform) | `fetch-secrets_<integration>` | *(none — no `reset_*_last_run` defined for credentials)* |
| **Microsoft Teams ONLY** — manually added | `automation-and-remediation_microsoft-teams` | `reset_integration_context` |

**Migration rules**:

1. **One action per fetch sub-capability.** An integration that declares multiple fetch flags (e.g., `isfetch + isfetchevents + isfetchassets`) emits one handler with multiple `capabilities[]` entries, each carrying its own `actions[]`. The integration's automation sub-capability entry receives NO actions (unless it's Microsoft Teams — see below).
2. **Sub-capability placement only.** Actions are never placed on the parent capability id (`automation-and-remediation`, `fetch-issues`, etc.) — always on the per-integration sub-capability id (`<capability>_<integration-slug>`).
3. **`reset_integration_context` is Microsoft-Teams-only.** This action is NOT derived from any XSOAR flag. Manually add it to the Microsoft Teams handler's `automation-and-remediation_microsoft-teams` capability entry. Do NOT emit it for any other integration.
4. **`display` and `description` are OMITTED by default.** Both are optional in the schema; the platform supplies canonical defaults. Per Decision (2026-06-05), the migration LLM does not pass `display`/`description` — flagged as an [open](#322-opens) for future per-integration overrides if/when product decides specific integrations need custom wording.
5. **Permission-style flags**: `isFeed` may be hidden on Platform (`hidden:platform: true`) — same exclusion rule as for the parent capability applies. If the flag is hidden on Platform, do NOT emit the action either.

**Worked example** — an integration that has commands + `isfetch + isfetchevents` on Platform:

```yaml
capabilities:
  # Automation sub-cap — no actions
  - id: "automation-and-remediation_my-integration"
    auth_options:
      - id: "oauth2_client_credentials.my_profile"
        view_group: "my-integration"
        workloads:
          - "xsoar-pod"

  # Fetch-issues sub-cap — reset_incidents_last_run action
  - id: "fetch-issues_my-integration"
    auth_options:
      - id: "oauth2_client_credentials.my_profile"
        view_group: "my-integration"
        workloads:
          - "xsoar-pod"
    actions:
      - type: "reset_incidents_last_run"

  # Log-collection sub-cap — reset_events_last_run action
  - id: "log-collection_my-integration"
    auth_options:
      - id: "oauth2_client_credentials.my_profile"
        view_group: "my-integration"
        workloads:
          - "xsoar-pod"
    actions:
      - type: "reset_events_last_run"
```

**Worked example — Microsoft Teams** (manual `reset_integration_context`):

```yaml
capabilities:
  - id: "automation-and-remediation_microsoft-teams"
    auth_options:
      - id: "oauth2_client_credentials.shared_oauth"
        view_group: "microsoft-teams"
        workloads:
          - "xsoar-pod"
    actions:
      - type: "reset_integration_context"
```

### 3.9 Serializer YAML

**When to use a serializer**:

- When a connector field ID differs from the integration parameter name (due to duplicate-resolution prefixes across integrations).
- When connection-profile fields need to be mapped to integration-expected parameter names.
- A serializer YAML is **not required**.

**Where to create the serializer**: same directory as the handler YAML — `components/handlers/<integration-id>/serializer.yaml`.

**Field ID naming rule**: use the original integration param name when it is unique across all integrations in the connector. Only prefix with an integration-specific prefix when there is a genuine duplicate (e.g., `proxy` appears in three integrations → `slackv3_proxy`, `iam_proxy`, `ec_proxy`).

#### `field_mappings`

See §2.9. Each entry must have `id` and at least one of `field_name` / `field_value`.

#### `computed_fields`

Use `computed_fields` for synthetic output fields derived from connector state (e.g., boolean flags based on capability enablement). Each rule has:

- `output` — list of `{id, value}` to emit.
- `any_of` — list of condition groups; OR between groups, AND within a group.
- Within `conditions`, each entry has `type: capability` (`{capability_id, value: on|off}`) or `type: field` (`{field_id, op, value}`).

Computed fields evaluate against the original field IDs (before `field_mappings` is applied).

### 3.10 Inventory Checklist

For each integration, the inventory must document:

- Integration ID (`commonfields.id`) and display name.
- Provider (from YML `provider` field) — flag if different across integrations.
- Categories — flag if different across integrations.
- All configuration parameters (name, type, default, required).
- Special features (`longRunning`, `isFetch`, `isfetchevents`, `ismappable`, etc.).
- `supportedModules` — specify if inherited from `pack_metadata.json` or overridden by the integration.
- Marketplace-specific field behavior (e.g., `hidden: [platform]`, `defaultvalue:xpanse: 'false'`).
- XSOAR-intervened commands (e.g., `fetch-incidents`, `fetch-events`, `long-running-execution`).
- Duplicate field IDs across integrations — flag which need serializer mappings.

### 3.11 CODEOWNERS File

Required file at the repository root that defines who owns the connector code. Looks as follows:

```
# Unified Connectors - Code Owners
#
# This file defines code ownership for merge request approvals.
# See: https://docs.gitlab.com/ee/user/project/codeowners/
#
# GitLab evaluates CODEOWNERS rules from bottom to top — the LAST matching
# pattern wins. This means connector-specific overrides MUST appear AFTER
# the catch-all rules so they take precedence.
#
# To add yourself as the owner of a specific connector, add a line at the
# bottom of this file following this pattern:
#
#   /connectors/<connector-name>/**  @username1 @username2
#
# This will make only the listed users required approvers for changes
# in that connector's directory, instead of the default team.

# ──────────────────────────────────────────────────────────────────────
# Default: entire repository owned by the team
# ──────────────────────────────────────────────────────────────────────
* @mhafuta @lpaz @adbiton @rlevy @smotna @nzur @lfrost

# ──────────────────────────────────────────────────────────────────────
# Connector-specific overrides (last match wins)
# Add your connector below to take ownership of approvals.
# ──────────────────────────────────────────────────────────────────────

# Salesforce
/connectors/salesforce/** @jmizrahi @asharma @pyadav @dbelenky

# GoogleWorkspace
/connectors/googleworkspace/** @ssingh @kverma
```

Rules:

1. The default ownership block at the top of the file is owned by the team and must not be removed.
2. Each new connector adds a connector-specific override **after** the catch-all so it takes precedence.
3. The pattern `/connectors/<connector-name>/**` matches every file under that connector's directory.
4. For every new connector created, you **must** add the following users as codeowners: `@jmizrahi @juschwartz @yhayun`.

---

## Section 4: Worked Reference — Salesforce Connector

This is a complete, working connector that you should use as a template. The Salesforce connector consolidates two XSOAR integrations (Salesforce + Salesforce IAM). Files live under [`connectors/salesforce/`](connectors/salesforce/).

### 4.1 connector.yaml

```yaml
# yaml-language-server: $schema=../../schema/connector.schema.json
id: "salesforce"

metadata:
  title: "Salesforce"
  description: "Salesforce CRM services for identity management, automation, remediation and SaaS Posture Security"
  version: 1.0.0
  categories:
    - "Case Management"
  tags:
    - "Security"
  vendor: "Salesforce"
  publisher: "Palo Alto Networks"
  author_image: "salesforce-ic.svg"
  documentation: "https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-3.x-Documentation/Ingest-and-run-Salesforce-automation-and-remediation"
  ownership:
    team: "xsoar"
    maintainers:
      - "@xsoar-content"

settings:
  allow_skip_verification: false
```

### 4.2 connection.yaml

> **⚠️ Reconciliation note (`general_configurations.domain`)**: The Salesforce reference below emits a `domain` field under `general_configurations`. This predates the Grouped-connector scoping rule in §3.6 ("Rules — general_configurations"), which states that for **Grouped connectors** (one vendor → many handlers — and Salesforce *is* a Grouped connector, per Appendix F) the `general_configurations.domain` block is **OUT OF SCOPE** because each handler manages its own URL/domain logic. **§3.6 is authoritative**: do **not** copy this `domain` block when migrating a Grouped connector. It is retained here only to keep the historical Salesforce example intact and to illustrate the field shape for the Standard-connector case. (The reference also relies on a per-handler [`serializer.yaml`](README.md:1381) to remap `domain` to each integration's expected param — see §4.7/§4.8.)

```yaml
# yaml-language-server: $schema=../../schema/connection.schema.json
metadata:
  title: "Connection"
  description: "Enter the credentials to securely authorize the connection"

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
            help_text: |
              **Find your domain:**
              Copy the URL from your browser's address bar while logged into Salesforce.
            create_modifiers:
              required: true
              hidden: false
            edit_modifiers:
              required: true
              hidden: false
              read_only: true

profiles:
  - id: "oauth2_client_credentials.salesforce"
    type: "oauth2_client_credentials"
    title: "OAuth 2.0 Client Credentials Flow"
    description: "Server-to-server authentication using client credentials"
    discovery_url: "https://{{domain}}/.well-known/openid-configuration"
    configurations:
      - fields:
          - id: "client_key"
            metadata:
              auth:
                parameter: "client_key"
            title: "Consumer Key (Client ID)"
            field_type: "input"
            options:
              mask: false
              create_modifiers:
                required: true
                hidden: false
              edit_modifiers:
                required: true
                hidden: true
          - id: "client_secret"
            metadata:
              auth:
                parameter: "client_secret"
            title: "Consumer Secret"
            field_type: "input"
            options:
              mask: true
              create_modifiers:
                required: true
                hidden: false
              edit_modifiers:
                required: true
                hidden: true

  - id: "oauth2_authorization_code.salesforce"
    type: "oauth2_authorization_code"
    title: "OAuth 2.0 Authorization Web Server Flow"
    description: "Acts on behalf of a user. Requires interactive login."
    client_id: "{SAAS_REGISTRY.SALESFORCE_CORE_CLIENT_ID}"
    client_secret: "{SAAS_REGISTRY.SALESFORCE_CORE_CLIENT_SECRET}"
    discovery_url: "https://{{domain}}/.well-known/openid-configuration"
    refresh_token_scope: "refresh_token"
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
            placeholder: "Please Enter Name for an Instance"
            create_modifiers:
              required: true
              read_only: false
              hidden: false
            edit_modifiers:
              required: true
              read_only: false
              hidden: false

        - id: "integrationLogLevel"
          title: "Integration Log Level"
          field_type: "select"
          metadata:
            xsoar:
              config_type: "backend"
          options:
            description: "Set the log level for the integration"
            placeholder: "Select log level"
            default_value: "Off"
            values:
              - key: "Off"
                value: "Off"
              - key: "Debug"
                value: "Debug"
              - key: "Verbose"
                value: "Verbose"
            create_modifiers:
              required: false
              hidden: false
            edit_modifiers:
              required: false
              hidden: false

capabilities:
  - id: "automation-and-remediation"
    title: "Automation and Remediation"
    description: "Automate identity lifecycle management including user provisioning, updates, and access control"
    default_enabled: true
    required: false
    labels:
      - "Recommended"
    config:
      required_license: ["agentix", "xsiam", "edr", "cloud", "cloud_runtime_security"]
```

### 4.4 configurations.yaml (key sections)

```yaml
# yaml-language-server: $schema=../../schema/configurations.schema.json
metadata:
  title: "Configuration"
  description: "Adjust and refine your configuration"

configurations:
  - id: "automation-and-remediation"
    configurations:
      - fields:
          - id: "user_operations"
            title: "User Operations"
            field_type: "checkbox_group"
            options:
              description: "Select allowed user lifecycle operations"
              default_value:
                - key: "create_user_enabled"
                  value: true
                - key: "update_user_enabled"
                  value: true
                - key: "enable_user_enabled"
                  value: true
                - key: "disable_user_enabled"
                  value: true
              create_modifiers:
                required: false
                read_only: false
                hidden: false
              edit_modifiers:
                required: false
                read_only: false
                hidden: false
            fields:
              - id: "create_user_enabled"
                title: "Allow creating users"
              - id: "update_user_enabled"
                title: "Allow updating users"
              - id: "enable_user_enabled"
                title: "Allow enabling users"
              - id: "disable_user_enabled"
                title: "Allow disabling users"
      - fields:
          - id: "create_if_not_exists"
            title: "Automatically create user if not found"
            field_type: "switch"
            options:
              description: "Automatically create user if not found in update and enable commands"
              default_value: true
              create_modifiers:
                required: false
                read_only: false
                hidden: false
              edit_modifiers:
                required: false
                read_only: false
                hidden: false
```

### 4.5 Handler: components/handlers/xsoar_sf/handler.yaml

```yaml
# yaml-language-server: $schema=../../../../../schema/handler.schema.json
id: "xsoar-salesforce"

metadata:
  version: "1.0.0"
  description: "XSOAR handler for Salesforce integration"
  module: "xsoar"
  tags:
    - "crm"
    - "automation"
  ownership:
    team: "xsoar"
    maintainers:
      - "@xsoar-content"

enabled: true

triggering:
  type: "PUB_SUB"
  labels:
    xsoar-integration-id: "Salesforce"
    xsoar-pack-id: "Salesforce"
  args: {}

capabilities:
  - id: "automation-and-remediation"
    auth_options:
      - id: "oauth2_client_credentials.salesforce"
        scopes:
          - "api"
          - "chatter_api"
          - "refresh_token"
          - "offline_access"
        workloads:
          - "xsoar-pod"
      - id: "oauth2_authorization_code.salesforce"
        scopes:
          - "api"
          - "chatter_api"
        workloads:
          - "xsoar-pod"

test_connection:
  type: "service"
  service: "xsoar"
  endpoint: "/settings/integration/connector/verification"
```

### 4.6 Handler: components/handlers/xsoar_sf_iam/handler.yaml

```yaml
id: "xsoar-salesforce-iam"

metadata:
  version: "1.0.0"
  description: "XSOAR handler for Salesforce IAM integration"
  module: "xsoar"
  tags:
    - "iam"
    - "identity"
  ownership:
    team: "xsoar"
    maintainers:
      - "@xsoar-content"

enabled: true

triggering:
  type: "PUB_SUB"
  labels:
    xsoar-integration-id: "Salesforce IAM"
    xsoar-pack-id: "Salesforce"
  args: {}

capabilities:
  - id: "automation-and-remediation"
    auth_options:
      - id: "oauth2_client_credentials.salesforce"
        scopes:
          - "api"
          - "chatter_api"
          - "refresh_token"
          - "offline_access"
        workloads:
          - "xsoar-pod"
      - id: "oauth2_authorization_code.salesforce"
        scopes:
          - "api"
          - "chatter_api"
        workloads:
          - "xsoar-pod"

test_connection:
  type: "service"
  service: "xsoar"
  endpoint: "/settings/integration/connector/verification"
```

### 4.7 Serializer: components/handlers/xsoar_sf/serializer.yaml

```yaml
field_mappings:
  - id: "domain"
    field_name: "InstanceURL"   # salesforce.js expects this name
```

### 4.8 Serializer: components/handlers/xsoar_sf_iam/serializer.yaml

```yaml
field_mappings:
  - id: "domain"
    field_name: "url"            # salesforce_iam.py expects this name
```

---

## Section 5: Your Task

### 5.1 What You Will Receive

1. **This document** — the connector specification, migration rules, and Salesforce reference.
2. The connector name (provider name).
3. **XSOAR Pack content** — path to the integration YMLs for all integrations to migrate.
4. The [`README.md`](README.md:1) of the manifest repo for the latest spec.
5. The [`schema/`](schema/) directory for authoritative JSON Schemas.

### 5.2 What You Must Produce

#### A. Integration Inventory

A per-integration table covering every item in §3.10 (ID, display name, provider, categories, every configuration parameter, special features, `supportedModules`, marketplace-specific behavior, XSOAR-intervened commands, and duplicate field IDs).

#### B. Scoping Decisions

1. Which commands have **name collisions**.
2. Which configuration parameters need special support or are marketplace-specific.
3. Which field IDs are duplicated and need serializer mappings.

#### C. Proposed Connector YAML Files

Produce draft YAML for all connector files:

- `connector.yaml`
- `connection.yaml`
- `capabilities.yaml`
- `configurations.yaml`
- `triggers.yaml` (when any §3.5 pattern applies — fetch mutex, capability-driven visibility, multi-field conditional visibility)
- `summary.yaml`
- `availability.yaml` (optional — only when the connector is gated to specific regions/tenants)
- All `handler.yaml` files
- All `serializer.yaml` files

Follow the rules in Section 3 for constructing each file.

#### D. Gap Analysis

List all gaps in the migration, with severity ratings (🔴 CRITICAL, 🟡 MEDIUM, 🟢 LOW/RESOLVED).

#### E. Decisions Needed

List all decisions that PMs/Engineering must make before migration can proceed, with options and recommendations where possible. Present these clearly so PMs can make informed decisions.

### 5.3 Output Format

Structure your output as a migration plan document with these sections:

1. **Integration Inventory** — tables with all parameters and flags.
2. **Scoping Decisions** — inclusion/exclusion, collisions, auth mapping, duplicates.
3. **Proposed Connector YAML Files** — complete YAML with rules-applied annotations.
4. **Gap Analysis** — numbered gaps with severity (🔴 CRITICAL, 🟡 MEDIUM, 🟢 LOW/RESOLVED).
5. **Decisions Needed** — numbered decisions with options and recommendations.
6. **Appendix** — directory structure.

---

## Appendix A: XSOAR Parameter Type to Manifest Type mapping

XSOAR types in use (if you come across another type when migrating, raise as a flag).
Also refer to the file [`plans/integration-parameter-and-types-overrides.md`](plans/integration-parameter-and-types-overrides.md) for special params details.

| XSOAR Type | Description | UCP `field_type` | `options.mask` | Notes |
|---|---|---|---|---|
| 0 | Short String / Text | `input` | `false` | Standard text input. |
| 1 | Number / Integer | `input` | `false` | Text input (no separate number type in UCP). Example: `max_fetch`. |
| 4 | Encrypted / Password | `input` | `true` | Masked input for secrets. Example: ApiKey. |
| 8 | Boolean / Checkbox | `checkbox` | N/A | Single boolean toggle. |
| 9 | Credentials / Authentication | **OUT OF SCOPE** | — | Handled by connection profiles. Type 9 params are removed by the auth migration script. |
| 12 | Long Text / TextArea | `text_area` | `false` | Multi-line text. |
| 13 | Incident Type | `select` + `metadata.dynamic_values` | `false` | Option list fetched at runtime via the XSOAR provider (`dynamicField: "incident-type"`). **User-visible field** — do NOT mark `metadata.xsoar.config_type: "backend"`. |
| 14 | Encrypted Text Area | `text_area` | `true` | Masked textarea. Example: SSHKey. |
| 15 | Single Select / Dropdown | `select` | `false` | Options from YML `options` array as `{key, label}` pairs. |
| 16 | Multi Select | `multi_select` | `false` | Native UCP field type. Items in `values` use `{key, label}`; `default_value` is an array of keys. See README [Multi-Select Example](README.md:1681). |
| 17 | Feed Expiration Policy | `select` | `false` | Hardcoded display labels: `Indicator Type` / `Time Interval` / `Never Expire` / `When removed from the feed`. Only added when `script.Feed: true`. |
| 18 | Indicator / Feed Reputation | `select` | `false` | New mapped values: `Unknown` / `Benign` / `Suspicious` / `Malicious` (not the legacy None/Good/Suspicious/Bad). Only added when `script.Feed: true`. |
| 19 | Feed Fetch Interval | `duration-picker` (planned) | `false` | Still in development in UCP (§3.2.2 item 2). Stored in minutes. Use [`triggers.yaml`](README.md:833) for conditional visibility (§3.5). |

**Important Notes:**

- Whenever you see the string "Incidents" in the YML, change it to "Issues" — this is the correct terminology for Platform marketplace where ConnectUs is supported (e.g., "Fetch Incidents" → "Fetch Issues").
- If you come across a type not listed above when migrating, fail and raise a flag.

## Appendix B: Authentication Architecture — Frontend Transformation

When the platform transforms `handler.yaml` auth configurations for the frontend:

- **Single auth option** → rendered as a single form.
- **Multiple auth options** → rendered as a selection (dropdown/radio) — user picks ONE.
- **Combined auth** (`methods` array) → rendered as grouped form sections — user configures ALL.

## Appendix C: Field ID Uniqueness Rule

All field IDs must be globally unique across the entire connector directory — across [`connection.yaml`](README.md:162), [`capabilities.yaml`](README.md:509), and [`configurations.yaml`](README.md:719) (including `checkbox_group` item IDs). This is enforced by OPA validation (xref Check covering field_entries).

## Appendix D: Excluded Integrations (Out of Scope)

The following integrations are excluded from the migration. If the LLM encounters one of these in the input pack list, it must skip the integration and surface a note in the Gap Analysis.

| Category / Integration | Reason |
|---|---|
| `Generic Webhook` | Generic webhook integration — not a vendor-specific connector. |
| Any integration with `defaultEnabled: true` in its YML | Auto-enabled integrations are out of scope. |
| Contributed integrations (partner + community) | Not maintained by the core content team; out of scope for the unified-connector migration. |
| Deprecated integrations | Will not be migrated. Users will be pointed to the replacement connector (see §3.2.2 open item about deprecated-pack redirect text). |
| `Cortex Core - IOC` | Internal Cortex integration — the legacy FE's `HIDE_CREDENTIALS_BOX_CONFIGURAIONS_IDS` list hides the credentials box for this integration. Not a vendor integration; do not migrate. |
| `Cortex Core - IR` | Same as `Cortex Core - IOC`. Internal Cortex integration; do not migrate. |
| Server-style integrations (e.g., mail-listener) | Long-running inbound listeners; require credential-pinning via `triggering.labels`. See [Appendix I](#appendix-i-server-style-integrations). |

## Appendix E: Integrations Requiring Manual Intervention

The following integrations require manual migration because their authentication, configuration, or runtime behavior is too complex for the automated migration rules. The LLM must skip these in the automated pass and flag them in the Decisions Needed section.

| Integration | Reason |
|---|---|
| **SAP BTP** | Complex conditional auth-option triggers — the integration's connection screen needs to show/hide auth fields based on multiple inter-dependent selections that today cannot be expressed cleanly in [`connection.yaml`](README.md:162) + [`triggers.yaml`](README.md:833). Migrate manually and consult the connection-screen designs before authoring. |
| **Microsoft Teams** | Requires a `reset_integration_context` action on the `automation-and-remediation_microsoft-teams` sub-capability. The action is NOT derivable from any XSOAR YML flag — it is Microsoft-Teams-only and must be added manually by the migration author per the §3.8 "Actions per sub-capability" rules. Microsoft Teams also triggers Appendix G (no engine/proxy fields) and Appendix I (server-style — `xsoar-long-running-credentials-profile-id` label on the handler); ensure all three carve-outs are applied. |

This list will grow as additional complex cases are identified during the migration program.

## Appendix F: Joint Migration With the SaaS Team

The following vendor connectors are owned jointly with the SaaS team. SaaS already maintains (or is actively building) handlers for these connectors. Any XSOAR handler being migrated into one of these must be added to the existing connector directory — not into a fresh `connectors/<vendor>/` tree — and the merge must be coordinated with the SaaS team owners (see [`CODEOWNERS`](CODEOWNERS:1)).

| Integration | Notes |
|---|---|
| **G-Suite (Google Workspace)** | Joint with SaaS — existing [`connectors/googleworkspace/`](connectors/googleworkspace/) has SaaS handlers; coordinate XSOAR handler additions. |
| **Salesforce** | Joint with SaaS — existing [`connectors/salesforce/`](connectors/salesforce/). |
| **M365 (Microsoft 365)** | Joint with SaaS — existing [`connectors/microsoft365/`](connectors/microsoft365/). |
| **MS Teams** | Joint with SaaS — if shipped as a separate connector ([`connectors/microsoft-teams/`](connectors/microsoft-teams/)); otherwise rolled into M365. |
| **Claude** | Joint with SaaS — agentic capability lives alongside any XSOAR handler. |
| **Jira** (stretch) | Joint with SaaS — stretch goal for the quarter. |

## Appendix G: Engine / EngineGroup / Proxy Exclusion List

Integrations listed below must have **no `engine_mode`, `engine`, `engine_group`, or `proxy` fields emitted at all** in their connector manifest — none of the three engine fields from the §3.7 "Engine handling — 3-field pattern" sub-section, and no `proxy` field either. Match is case-insensitive against the integration `commonfields.id`; AWS / Azure / GCP are literal integration IDs — not prefixes.

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
| `AWS` | Platform-native cloud integration — exact integration ID, not a prefix. |
| `Azure` | Platform-native cloud integration — exact integration ID, not a prefix. |
| `GCP` | Platform-native cloud integration — exact integration ID, not a prefix. |

If the LLM encounters one of these integrations during automated migration, it must skip the `engine_mode`, `engine`, `engine_group`, and `proxy` field rules entirely for that integration (no `engine_mode`, `engine`, `engine_group`, or `proxy` fields emitted at all) and note the exclusion in the Gap Analysis output.

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
