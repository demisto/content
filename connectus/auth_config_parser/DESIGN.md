# `auth_config_parser` — Package Design

Standalone Python package that owns the parsing, validation, and
utility surface for the `Auth Details` JSON column in
[`connectus/connectus-migration-pipeline.csv`](../connectus-migration-pipeline.csv).

> **Status (2026-05 rewrite).** This document describes the **current**
> code shape after the 2026-05 schema simplification. The pre-2026-05
> design carried a `config` expression field (`REQUIRED(...)` /
> `OPTIONAL(...)` / `CHOICE(...)` / `+`-joining / `NoneRequired`
> grammar) — that field was removed because the only inter-profile
> relation is exclusive-OR, which is fully encodable by
> `len(auth_types)` alone. See [Appendix A — Historical design notes](#appendix-a--historical-design-notes)
> for the brief history. The canonical, user-facing schema reference
> is [`column-schemas.md`](../column-schemas.md:1) §"Auth Details";
> this file documents the package's internal layout and contracts.

---

## 1. Motivation

The Auth Details parsing/validation logic previously embedded in
`workflow_state.py` is now consumed by three call sites:

1. **`workflow_state/` package** — the `set-auth` CLI setter and the
   `auth-params` helper. See
   [`workflow_state/validators.py:14-37`](../workflow_state/validators.py:14)
   for the thin wrapper around `validate_auth_details`.
2. **`check_command_params.py`** — via `auth_param_ids` (re-exported
   from `workflow_state`) for the overlap-rejection ignore set.
3. **`check_auth_parity.py`** — needs structured access to parsed
   `AuthDetails` objects, not raw dicts. Imports `AuthDetails`,
   `AuthEntry`, `AuthType`, `parse_auth_details`,
   `validate_auth_details` directly. See
   [`check_auth_parity.py:41-47`](../check_auth_parity.py:41).

Living in a standalone package provides:

- **Typed data model** — frozen dataclasses with type hints replace
  ad-hoc dicts, enabling IDE autocompletion and `mypy` checking.
- **Separation of concerns** — parsing (raise on bad input) vs.
  validation (return error lists) vs. utilities (param extraction)
  are split into independent modules.
- **Testability** — pure functions with no CSV/filesystem
  dependencies. Tests sit in `tests/` alongside the modules they
  cover.
- **Reusability** — every tool imports from one canonical package.

---

## 2. Package layout

```
connectus/auth_config_parser/
├── __init__.py          # Public API re-exports
├── types.py             # AuthType enum, AuthEntry, AuthDetails
├── exceptions.py        # AuthConfigParseError
├── parser.py            # parse_auth_details()
├── validator.py         # validate_auth_details()
├── utils.py             # project_xsoar_param_to_yml_id, auth_param_ids[_with_sources]
├── demo.py              # Hand-run sanity script exercising 4 real integrations
├── DESIGN.md            # This file
└── tests/
    ├── __init__.py
    ├── test_parser.py
    ├── test_validator.py
    └── test_utils.py
```

---

## 3. Module specifications

### 3.1 `types.py` — Data model

All public types live here. Pure Python, no external dependencies.

#### `AuthType` (enum, `str` subclass)

The 4 valid auth-type enum values. Inherits from `str` so that
`AuthType("APIKey") == "APIKey"` and direct JSON serialization round-
trip naturally.

| Value | UCP profile | Canonical roles (xsoar_param_map values) |
|---|---|---|
| `APIKey` | `api_key` (single-secret only) | `"key"` |
| `Plain` | `plain` | `"username"`, `"password"` |
| `Passthrough` | none — catch-all for **all OAuth2 flows** (client-credentials, JWT-bearer, browser-flow Authorization Code, Device Code, ROPC), Managed Identity, mTLS-only, multi-secret packages, custom signing | any non-empty string |
| `NoneRequired` | none — used when the integration has no auth at all (no entry in `auth_types[]`) | n/a |

#### `AuthEntry` (frozen dataclass)

One row in `auth_types[]`: one self-contained, mutually-exclusive UCP
connection type.

| Field | Type | Notes |
|---|---|---|
| `type` | `AuthType` | Required. |
| `name` | `str` | Required, non-empty, unique within the row. Free-form logical id (e.g. `"api_key"`, `"credentials"`, `"hunting_credentials"`). |
| `xsoar_param_map` | `dict[str, str]` | Required and **non-empty** for every entry, including entries with `interpolated=True`. Maps XSOAR field path → role. |
| `interpolated` | `bool` | Optional, default `False`. When `True`, the value is templated at runtime rather than supplied directly. |

The structural invariant — `xsoar_param_map` is required and non-empty
on every entry — is enforced by both parser and validator. The role
values are constrained per type (see `_CANONICAL_ROLES_BY_TYPE` at
[`parser.py:46-49`](parser.py:46)); the parser enforces only the
structural string-non-empty invariant, the validator enforces the
role-enum (see [§3.3](#33-validatorpy)).

#### `AuthDetails` (frozen dataclass)

The fully parsed Auth Details JSON object.

| Field | Type | Notes |
|---|---|---|
| `auth_types` | `list[AuthEntry]` | Sorted by `(type, name)` ascending. Length encodes the inter-profile relation (see table below). |
| `other_connection` | `list[str]` | Required. Sorted, unique, non-empty YML param ids that are connection-adjacent but not auth secrets (URL, proxy, insecure, port, host, region, …). May be `[]`. |

Derived `@property` accessors:

| Property | Returns | Meaning |
|---|---|---|
| `auth_type_names` | `set[str]` | Set of all `.name` values across entries. |
| `requires_choice` | `bool` | `True` when `len(auth_types) >= 2`. |
| `is_none_required` | `bool` | `True` when `len(auth_types) == 0`. |

**Inter-profile relation** (implicit; no `config` expression):

| `len(auth_types)` | Meaning |
|---|---|
| `0` | The integration requires NO authentication. (Historical `NoneRequired`.) |
| `1` | A single profile, always used. |
| `>= 2` | **Exclusive-OR.** The user picks exactly one profile. There is no AND between profiles, no OPTIONAL, no clause-joining. |

AND-ed secrets within a single auth flow live inside **one** profile's
`xsoar_param_map`, never split across profiles.

### 3.2 `parser.py` — Pure parsing

#### `parse_auth_details(data: str | dict) -> AuthDetails`

Converts a JSON string OR pre-parsed dict into an `AuthDetails`
instance. Structural parsing only — does NOT cross-reference
`auth_types[].name` uniqueness or sort-order (those belong to the
validator). On any error, raises `AuthConfigParseError` with the
collected `errors` list attached.

#### Internal helpers

- `_VALID_AUTH_TYPE_VALUES` ([`parser.py:27`](parser.py:27)) —
  `{t.value for t in AuthType}`; used for fast O(1) membership check.
- `_CANONICAL_ROLES_BY_TYPE` ([`parser.py:45-48`](parser.py:45)) —
  per-type allowed role-value set. Only present for the types that
  have a fixed canonical role list (`APIKey`, `Plain`); for
  `Passthrough`, any non-empty string is
  accepted. Aliased to `_ROLE_ENUM_BY_TYPE` for the validator.
- `_parse_auth_entry(index, raw_dict)` ([`parser.py:106`](parser.py:106))
  — per-entry helper. Returns `(entry_or_none, errors)` and is reused
  by `parse_auth_details`.

### 3.3 `validator.py`

#### `validate_auth_details(data: str | dict) -> list[str]`

Returns the list of error strings (empty = valid). Never raises.
Performs ALL validation the package does on Auth Details, including:

- JSON parsing (string input).
- Required top-level keys: `auth_types` (a list) and
  `other_connection` (a list).
- Per-entry shape: `type` enum, `name` string-non-empty +
  unique-within-row, `xsoar_param_map` non-empty
  `dict[str, str]` with non-empty keys and non-empty role values,
  optional `interpolated` bool.
- `xsoar_param_map` role-value enum per `auth_types[].type`:
  - `APIKey` → values must be from `{"key"}`.
  - `Plain` → values must be from `{"username", "password"}`.
  - `Passthrough` → any non-empty string (deliberately undefined
    for now; to be narrowed in a future PR). All OAuth2 flows are
    classified as `Passthrough`.
  - `NoneRequired` → never appears in `auth_types[]`; rule moot.
- `auth_types[]` sort order by `(type, name)` ascending. Reports the
  first out-of-order adjacent pair.
- `other_connection` (when present): list of non-empty unique
  strings, sorted ascending.

Wraps via [`workflow_state.validators.validate_auth_detail()`](../workflow_state/validators.py:25),
which is a thin one-liner around `validate_auth_details` exported for
back-compat.

### 3.4 `utils.py`

| Function | Signature | Purpose |
|---|---|---|
| `project_xsoar_param_to_yml_id(xsoar_param)` | `str → str` | Collapses a dotted path (`"credentials.identifier"`) to its base YML param id (`"credentials"`). Bare ids pass through unchanged. |
| `auth_param_ids(details)` | `AuthDetails → set[str]` | Deduplicated set of YML `configuration[].name` values composed from every `xsoar_param_map` key (projected via the function above) UNION every `other_connection` entry. |
| `auth_param_ids_with_sources(details)` | `AuthDetails → dict[str, list[str]]` | Same as `auth_param_ids`, but each id maps to a list of human-readable source descriptors (`"auth_types[].name='creds' (xsoar_param_map=…)"` or `"other_connection"`). Used by the per-command overlap rejection messages. |

### 3.5 `exceptions.py`

The package ships exactly one custom exception:

- **`AuthConfigParseError`** — raised by `parse_auth_details` on
  structurally invalid input. Carries `message` and `errors: list[str]`
  attributes so callers can inspect every failure individually.

(The earlier `AuthConfigValidationError` class was unused — the
validator always returns a list rather than raising — and was dropped
from `__all__` in the 2026-05 rewrite.)

### 3.6 `__init__.py` — Public API

```python
from auth_config_parser import (
    # Exceptions
    AuthConfigParseError,
    # Types
    AuthDetails,
    AuthEntry,
    AuthType,
    # Parsing
    parse_auth_details,
    # Validation
    validate_auth_details,
    # Utilities
    auth_param_ids,
    auth_param_ids_with_sources,
    project_xsoar_param_to_yml_id,
)
```

### 3.7 `demo.py`

A runnable sanity script that exercises four real integrations
(AbnormalSecurity, Akamai_WAF, Okta_v2, SAP_BTP) end-to-end through
`validate_auth_details` and `parse_auth_details`. Useful as a manual
post-edit smoke check — `python3 connectus/auth_config_parser/demo.py`
prints both validation and parse output for each sample.

---

## 4. Data flow

```
                  ┌───────────────────────┐
   JSON str OR    │                       │
   pre-parsed     │  parse_auth_details   │ ── raises ──▶ AuthConfigParseError
   dict     ─────▶│   (parser.py)         │
                  │                       │ ── ok ─────▶ AuthDetails (typed)
                  └───────────────────────┘                  │
                                                             ▼
                  ┌───────────────────────┐         ┌──────────────────┐
   JSON str OR    │ validate_auth_details │         │  auth_param_ids  │
   pre-parsed     │   (validator.py)      │         │  utils.py        │
   dict     ─────▶│                       │         └────────┬─────────┘
                  └────────┬──────────────┘                  │
                           ▼                                 ▼
                   list[str] errors                  set[str] of YML param ids
                  (empty = valid)             (used as overlap-exclusion set
                                              by check_command_params.py
                                              and set-params-to-commands)
```

---

## 5. Error model

The parser raises; the validator returns. Two different error
contracts because the two call sites need different things:

- The CLI (`set-auth`) wants to render every problem at once so the
  user can fix them in one round-trip. Hence `validate_auth_details`
  returns a `list[str]`.
- Internal consumers (e.g. `check_auth_parity.py`) want a structured
  object the moment they have a known-valid payload. Hence
  `parse_auth_details` raises on the first failure batch, with all
  errors attached.

`set-auth` validates first; if `validate_auth_details` returns `[]`,
it then calls `parse_auth_details` and is guaranteed it will succeed.

### 5.1 Notable error strings (stable contract)

The CLI grep-tests and the migration skill depend on these
substrings being present:

- `"Missing required key: auth_types"`
- `"Missing required key: other_connection"`
- `"'auth_types' must be a list"`
- `"missing 'type'"` / `"missing 'name'"` / `"missing 'xsoar_param_map'"`
- `"invalid type '<X>'"`
- `"duplicate 'name' '<X>'"`
- `"'interpolated' must be a bool"`
- `"auth_types must be sorted by (type, name)"`
- `"'other_connection' must be a list"`
- `"'other_connection' contains duplicate entries"`
- `"'other_connection' must be sorted ascending"`
- For per-type role-enum violations: `"must be one of ['key']"` (APIKey) and `"must be one of ['password', 'username']"` (Plain)

---

## 6. Testing

All tests live under `tests/` and use plain pytest. No fixtures, no
mocks (the package is dependency-free by design). Run:

```bash
pytest connectus/auth_config_parser/
```

### 6.1 `test_parser.py`

Coverage areas:

- Type/structure: missing keys, wrong types, empty/non-string
  values, dict vs. list mix-ups.
- `auth_types[]` entry parsing: every per-entry shape rule,
  `Passthrough` variants (including all OAuth2 flows),
  `interpolated` defaulting, role values for `APIKey` and
  `Plain`.
- `other_connection` required list-of-strings handling.
- Round-trip examples from real integration rows.

### 6.2 `test_validator.py`

Coverage areas:

- The same shape rules as the parser, but verifying error-LIST
  contents rather than exception text.
- Per-type role-enum enforcement (APIKey/Plain strict; others free-
  form).
- Name uniqueness + sort-order check.
- `other_connection` duplicate / sort / non-string detection.

### 6.3 `test_utils.py`

Coverage areas:

- `project_xsoar_param_to_yml_id`: bare ids, dotted ids, empty
  string, non-string input (graceful empty-string return).
- `auth_param_ids`: dedup across entries and `other_connection`, no
  entries → empty set, empty `other_connection` → only the auth ids.
- `auth_param_ids_with_sources`: descriptor format, dedup across
  dotted forms collapsing to one bare id, `other_connection`
  contributing its own descriptor.

---


