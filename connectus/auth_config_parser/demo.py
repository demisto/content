"""Demo for the ``auth_config_parser`` package.

Run from the repo root::

    python connectus/auth_config_parser/demo.py

For each of four real, diverse XSOAR/XSIAM integration YAMLs found
under ``Packs/``, this script:

1. Loads the YAML and prints its ``configuration[]`` param table.
2. Hand-crafts a corresponding Auth Details JSON object (a *connector*
   description for the new Cortex Platform UCP model) that classifies
   each YAML param as an auth secret, an interpolated value, or a
   "connection-adjacent" non-secret (``other_connection``).
3. Feeds the JSON through the parser's full public API:
   - ``parse_auth_details()``  -> typed :class:`AuthDetails`
   - ``parse_config()``        -> typed :class:`ConfigExpression`
   - ``validate_auth_details()`` -> validation error list
   - ``auth_param_ids()``      -> set of bare YML param ids
   - ``auth_param_ids_with_sources()`` -> source-attributed mapping
4. Pretty-prints every result, plus any warnings/validation output.

The four integrations were chosen to exercise distinct auth shapes:

* **AbnormalSecurityEventCollector** -- single API token (APIKey).
* **Akamai_WAF** -- EdgeGrid multi-secret + interpolated legacy params
  (Plain with ``interpolated=true`` on the human-facing fields).
* **Okta_v2** -- CHOICE between APIKey or OAuth2-JWT (private key).
* **SAPBTP** -- CHOICE between Plain client-credentials or Plain
  certificate-based auth.

The script is self-contained: it imports only :mod:`yaml` (already a
dependency of demisto-sdk and the parser tests) and the package itself.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Make ``import auth_config_parser`` work no matter where the script
# is launched from. We prepend the package's *parent* directory.
_PKG_DIR = Path(__file__).resolve().parent
_PKG_PARENT = _PKG_DIR.parent
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

import yaml  # noqa: E402  -- after sys.path tweak

from auth_config_parser import (  # noqa: E402
    AuthConfigParseError,
    AuthDetails,
    auth_param_ids,
    auth_param_ids_with_sources,
    parse_auth_details,
    parse_config,
    validate_auth_details,
)

# Resolve the repo root (two levels above this file: connectus/ -> repo).
REPO_ROOT = _PKG_PARENT.parent


# ---------------------------------------------------------------------------
# Sample fixtures: real YAML path + hand-crafted Auth Details JSON.
# ---------------------------------------------------------------------------

SAMPLES: list[dict] = [
    {
        "label": "1. AbnormalSecurity Event Collector  (single APIKey)",
        "yaml_path": (
            "Packs/AbnormalSecurity/Integrations/"
            "AbnormalSecurityEventCollector/"
            "AbnormalSecurityEventCollector.yml"
        ),
        "notes": (
            "Single mandatory API token (`token`, type=9 EncryptedString). "
            "All other params are connection-adjacent (URL/proxy/verify/"
            "after) rather than authentication secrets."
        ),
        "auth_details": {
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "api_token",
                    "xsoar_params": ["token"],
                },
            ],
            "config": "REQUIRED(api_token)",
            "other_connection": ["after", "proxy", "verify"],
        },
    },
    {
        "label": "2. Akamai WAF  (Plain multi-secret with interpolation)",
        "yaml_path": "Packs/Akamai_WAF/Integrations/Akamai_WAF/Akamai_WAF.yml",
        "notes": (
            "EdgeGrid auth requires THREE secrets: clientToken + "
            "accessToken + clientSecret. The YAML keeps both the legacy "
            "plaintext fields (`clientToken`/...) and the encrypted "
            "`credentials_*` variants. The legacy fields are marked "
            "interpolated=true to reflect that the platform templates "
            "their values at runtime from the encrypted siblings."
        ),
        "auth_details": {
            "auth_types": [
                {
                    "type": "Plain",
                    "name": "edgegrid_legacy",
                    "xsoar_params": [
                        "accessToken",
                        "clientSecret",
                        "clientToken",
                    ],
                    "interpolated": True,
                },
                {
                    "type": "Plain",
                    "name": "edgegrid_v2",
                    "xsoar_params": [
                        "credentials_access_token",
                        "credentials_client_secret",
                        "credentials_client_token",
                    ],
                },
            ],
            "config": "CHOICE(edgegrid_legacy, edgegrid_v2)",
            "other_connection": ["host", "insecure", "proxy"],
        },
    },
    {
        "label": "3. Okta v2  (CHOICE: APIKey OR OAuth2-JWT)",
        "yaml_path": "Packs/Okta/Integrations/Okta_v2/Okta_v2.yml",
        "notes": (
            "Two mutually-exclusive auth modes:\n"
            "  * `apitoken` (APIKey) -- single secret.\n"
            "  * OAuth2 JWT mode requiring client_id + private_key + "
            "key_id + jwt_algorithm.\n"
            "`use_oauth`, `url`, `insecure`, `proxy` are connection-"
            "adjacent, not auth secrets."
        ),
        "auth_details": {
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "api_token",
                    "xsoar_params": ["apitoken"],
                },
                {
                    "type": "OAuth2JWT",
                    "name": "oauth_jwt",
                    "xsoar_params": [
                        "client_id",
                        "jwt_algorithm",
                        "key_id",
                        "private_key",
                    ],
                },
            ],
            "config": "CHOICE(api_token, oauth_jwt)",
            "other_connection": ["insecure", "proxy", "url", "use_oauth"],
        },
    },
    {
        "label": "4. SAP BTP  (CHOICE: client-creds OR certificate)",
        "yaml_path": "Packs/SAP_BTP/Integrations/SAPBTP/SAPBTP.yml",
        "notes": (
            "OAuth2 token endpoint with two credential flavours:\n"
            "  * client_id + client_secret (Plain).\n"
            "  * client_id + certificate + private_key (Plain).\n"
            "Both share `client_id`, deliberately demonstrating that "
            "the parser/utils dedupe overlapping xsoar_params correctly. "
            "Entries are listed in (type, name) ascending order as the "
            "validator requires; an earlier draft of this fixture put "
            "`client_credentials` first and validate_auth_details() "
            "flagged it with a clear 'must be sorted by (type, name)' "
            "error -- a nice demonstration of the validator's value."
        ),
        "auth_details": {
            "auth_types": [
                {
                    "type": "Plain",
                    "name": "client_certificate",
                    "xsoar_params": [
                        "certificate",
                        "client_id",
                        "private_key",
                    ],
                },
                {
                    "type": "Plain",
                    "name": "client_credentials",
                    "xsoar_params": ["client_id", "client_secret"],
                },
            ],
            "config": "CHOICE(client_certificate, client_credentials)",
            "other_connection": [
                "auth_type",
                "insecure",
                "max_fetch",
                "proxy",
                "token_url",
                "url",
            ],
        },
    },
]


# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------

SEP_HEAVY = "=" * 78
SEP_LIGHT = "-" * 78


def _print_header(title: str) -> None:
    print()
    print(SEP_HEAVY)
    print(title)
    print(SEP_HEAVY)


def _print_subheader(title: str) -> None:
    print()
    print(SEP_LIGHT)
    print(title)
    print(SEP_LIGHT)


def _load_yaml_summary(path: Path) -> dict:
    """Return ``{name, display, configuration[]}`` from a YAML on disk."""
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return {
        "name": data.get("name") or data.get("commonfields", {}).get("id", "?"),
        "display": data.get("display", ""),
        "configuration": data.get("configuration", []) or [],
    }


def _print_yaml_params(summary: dict) -> None:
    print(f"  display : {summary['display']!r}")
    print(f"  name    : {summary['name']!r}")
    print(f"  configuration[] ({len(summary['configuration'])} params):")
    for p in summary["configuration"]:
        name = p.get("name", "?")
        display = p.get("display", "")
        ptype = p.get("type", "?")
        required = p.get("required", False)
        print(
            f"    - name={name!r:35s} type={ptype!s:>3} "
            f"required={required!s:>5}  display={display!r}"
        )


def _print_auth_details(details: AuthDetails) -> None:
    print(f"  auth_types ({len(details.auth_types)} entries):")
    for e in details.auth_types:
        flag = "  interpolated" if e.interpolated else ""
        print(
            f"    * type={e.type.value:<17} name={e.name!r:<22} "
            f"xsoar_params={e.xsoar_params}{flag}"
        )

    print("  config:")
    if details.config.none_required:
        print("    NoneRequired")
    else:
        for c in details.config.clauses:
            print(f"    {c.operator.value}({', '.join(c.names)})")
        print(f"    referenced_names = {details.config.referenced_names}")

    print(f"  other_connection: {details.other_connection}")
    print(f"  auth_type_names (derived): {sorted(details.auth_type_names)}")


# ---------------------------------------------------------------------------
# Per-sample runner
# ---------------------------------------------------------------------------

def run_sample(sample: dict) -> bool:
    """Run the full parser pipeline against one sample. Returns success."""
    _print_header(sample["label"])

    yaml_path = REPO_ROOT / sample["yaml_path"]
    print(f"YAML path : {sample['yaml_path']}")
    print(f"Exists    : {yaml_path.exists()}")
    if not yaml_path.exists():
        print("  !! YAML file not found -- skipping.")
        return False

    summary = _load_yaml_summary(yaml_path)

    _print_subheader("Real YAML (from disk)")
    _print_yaml_params(summary)

    print()
    print(f"Notes: {sample['notes']}")

    _print_subheader("Input Auth Details JSON (hand-crafted from YAML)")
    raw_json = json.dumps(sample["auth_details"], indent=2, sort_keys=False)
    print(raw_json)

    # --- parse_config() on the bare expression string -------------------
    _print_subheader("parse_config(<config string>)")
    try:
        expr_obj = parse_config(sample["auth_details"]["config"])
        print(f"  none_required = {expr_obj.none_required}")
        for c in expr_obj.clauses:
            print(f"  clause: {c.operator.value}({', '.join(c.names)})")
    except AuthConfigParseError as e:
        print(f"  AuthConfigParseError: {e.message}")
        for err in e.errors:
            print(f"    - {err}")
        return False

    # --- parse_auth_details() on the full dict --------------------------
    _print_subheader("parse_auth_details(<dict>)  -> typed AuthDetails")
    try:
        details = parse_auth_details(sample["auth_details"])
    except AuthConfigParseError as e:
        print(f"  AuthConfigParseError: {e.message}")
        for err in e.errors:
            print(f"    - {err}")
        return False
    _print_auth_details(details)

    # --- validate_auth_details() ---------------------------------------
    _print_subheader("validate_auth_details(<dict>)  -> list[errors]")
    errors = validate_auth_details(sample["auth_details"])
    if errors:
        print(f"  {len(errors)} validation issue(s):")
        for err in errors:
            print(f"    - {err}")
    else:
        print("  [] (no validation errors)")

    # --- utils ---------------------------------------------------------
    _print_subheader("auth_param_ids(details)  -> set of YML param ids")
    print(f"  {sorted(auth_param_ids(details))}")

    _print_subheader(
        "auth_param_ids_with_sources(details)  -> source attribution"
    )
    sources = auth_param_ids_with_sources(details)
    for yml_id in sorted(sources):
        print(f"  {yml_id!r}:")
        for src in sources[yml_id]:
            print(f"      <- {src}")

    # --- cross-check: declared auth params vs. YAML param ids -----------
    _print_subheader("Cross-check  vs.  YAML configuration[].name")
    yml_param_ids = {p.get("name") for p in summary["configuration"]}
    declared = auth_param_ids(details)
    missing_in_yaml = sorted(declared - yml_param_ids)
    extra_in_yaml = sorted(yml_param_ids - declared)
    print(f"  YAML param ids ({len(yml_param_ids)}): {sorted(yml_param_ids)}")
    print(
        f"  Declared in AuthDetails ({len(declared)}): {sorted(declared)}"
    )
    if missing_in_yaml:
        print(
            f"  ! Declared but absent from YAML: {missing_in_yaml}  "
            "(would be a parity error)"
        )
    else:
        print("  OK: every declared param exists in the YAML.")
    if extra_in_yaml:
        print(
            f"  ! YAML params not covered by AuthDetails: {extra_in_yaml}  "
            "(expected if these are non-connection params, e.g. fetch tuning)"
        )

    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    print("auth_config_parser demo")
    print(f"Repo root: {REPO_ROOT}")
    print(f"Samples  : {len(SAMPLES)}")

    successes = 0
    for sample in SAMPLES:
        if run_sample(sample):
            successes += 1

    _print_header(f"Done -- {successes}/{len(SAMPLES)} samples processed cleanly")
    return 0 if successes == len(SAMPLES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
