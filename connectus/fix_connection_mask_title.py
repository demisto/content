#!/usr/bin/env python3
"""
Remediate mask/title defects in already-generated ConnectUs connection.yaml files.

Given an assignee, iterate over every integration that has PASSED the
``generated manifest`` step and patch its connector's ``connection.yaml`` in
place so that each auth field's ``title`` and ``options.mask`` follow the
canonical rules:

  TITLE
    - type-9 (Credentials) identifier leaf -> param ``display``
    - type-9 (Credentials) password leaf   -> param ``displaypassword`` or "Password"
    - any other (flat) param               -> param ``display``

  MASK (mask: true ONLY for)
    - XSOAR type 4  (Encrypted text)
    - XSOAR type 9  PASSWORD leaf
    - XSOAR type 14 (Certificate / Key)
    everything else (type 0 short text, the type-9 identifier leaf, region/
    host/ARN/session-name routing params, etc.) -> mask: false

The originating XSOAR param for each connection field is resolved from the
profile's ``metadata.xsoar.interpolation_mapping`` (``role:xsoar.path,...``)
keyed by the field's ``metadata.auth.parameter`` (the role). Fields without an
auth role (proxy / insecure / engine / plain connection metadata) are left
untouched.

Patches connection.yaml only; does NOT re-run the manifest generator. Use
``--dry-run`` to preview changes without writing.

Usage:
  python3 content/connectus/fix_connection_mask_title.py --assignee "YuvHayun"
  python3 content/connectus/fix_connection_mask_title.py --assignee "YuvHayun" --dry-run
  python3 content/connectus/fix_connection_mask_title.py --integration-id "AWS - ACM"
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))           # .../content/connectus
CONTENT_ROOT = os.path.dirname(HERE)                        # .../content
REPO_PARENT = os.path.dirname(CONTENT_ROOT)                 # .../demisto (idex cwd)

sys.path.insert(0, HERE)
from workflow_state import integrations_for_assignee  # noqa: E402

_WS = ["python3", "content/connectus/workflow_state.py"]


def get_context(integration_id: str) -> dict:
    """Fetch the integration context JSON via the workflow_state CLI."""
    p = subprocess.run(_WS + ["context", integration_id],
                       capture_output=True, text=True, cwd=REPO_PARENT)
    return json.loads(p.stdout)

# Step name that gates remediation: only integrations whose 'generated manifest'
# checkpoint is done are touched.
GENERATED_MANIFEST_STEP = "generated manifest"

# Resolve the ConnectUs connectors root (same logic the gates use): sibling of
# the content repo, overridable via CONNECTUS_REPO_DIR.
def connectors_root() -> str:
    repo = os.environ.get("CONNECTUS_REPO_DIR") or os.path.join(REPO_PARENT, "unified-connectors-content")
    return os.path.join(repo, "connectors")


def load_yml_params(integration_yml_path: str) -> dict[str, dict]:
    """name -> param dict from the integration YML ``configuration`` list."""
    full = integration_yml_path
    if not os.path.isabs(full):
        full = os.path.join(CONTENT_ROOT, integration_yml_path)
    with open(full) as fh:
        y = yaml.safe_load(fh) or {}
    return {c.get("name"): c for c in (y.get("configuration") or []) if c.get("name")}


def parse_interpolation_mapping(mapping: str) -> dict[str, str]:
    """``role:xsoar.path,role2:path2`` -> {role: xsoar_path}."""
    out: dict[str, str] = {}
    for chunk in (mapping or "").split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        role, _, path = chunk.partition(":")
        out[role.strip()] = path.strip()
    return out


def desired_title_and_mask(xsoar_path: str, yml_params: dict[str, dict]) -> tuple[str | None, bool]:
    """Compute (title, mask) for a connection field given its xsoar param path.

    Returns (None, mask) when the source param can't be resolved (title left
    unchanged in that case, mask still corrected best-effort defaulting to
    unmasked).
    """
    origin = xsoar_path.partition(".")[0]
    leaf = xsoar_path.partition(".")[2]  # 'identifier' | 'password' | ''
    p = yml_params.get(origin)
    if p is None:
        return (None, False)
    ptype = int(p.get("type", 0) or 0)
    if leaf == "password" or (ptype == 9 and leaf == ""):
        # type-9 password leaf (dotted .password, or bare-id hiddenusername leaf)
        title = p.get("displaypassword") or "Password"
        mask = True
    elif leaf == "identifier":
        # type-9 username leaf
        title = p.get("display") or origin
        mask = False
    else:
        # flat param (single field)
        title = p.get("display") or origin
        mask = ptype in (4, 14)
    return (str(title) if title else None, mask)


def _handler_integration_id(hy: dict) -> str | None:
    """Extract the xsoar integration id from a handler.yaml. It lives under
    ``triggering.labels.xsoar-integration-id`` (with a legacy fallback to
    ``metadata.xsoar-integration-id``)."""
    trig = (hy.get("triggering") or {}).get("labels") or {}
    if trig.get("xsoar-integration-id"):
        return trig["xsoar-integration-id"]
    return (hy.get("metadata") or {}).get("xsoar-integration-id")


def scope_for_integration(connector_dir: str, integration_id: str) -> tuple[set[str], set[str]]:
    """Resolve which connection profiles belong to ``integration_id`` via the
    AUTHORITATIVE chain rooted in handler.yaml:

        handler.yaml ``triggering.labels.xsoar-integration-id`` == integration
            -> handler ``id`` ``xsoar-<view_group_id>``  (view_group join key)
            -> handler ``capabilities[].auth_options[].id`` (profile-id join key)

    Returns ``(view_group_ids, profile_ids)`` for the matching handler(s). A
    profile in connection.yaml is owned by this integration if its
    ``view_group`` is in ``view_group_ids`` OR its ``id`` is in ``profile_ids``.
    Robust for shared multi-handler connectors (the single ``aws`` folder with
    29 handlers) — no slug-guessing.
    """
    handlers_root = os.path.join(connector_dir, "components", "handlers")
    vgids: set[str] = set()
    pids: set[str] = set()
    if not os.path.isdir(handlers_root):
        return (vgids, pids)
    for hd in sorted(os.listdir(handlers_root)):
        hpath = os.path.join(handlers_root, hd, "handler.yaml")
        if not os.path.isfile(hpath):
            continue
        with open(hpath) as fh:
            hy = yaml.safe_load(fh) or {}
        if _handler_integration_id(hy) != integration_id:
            continue
        hid = str(hy.get("id", ""))            # e.g. xsoar-aws-acm
        if hid.startswith("xsoar-"):
            vgids.add(hid[len("xsoar-"):])
        for cap in hy.get("capabilities", []) or []:
            for ao in cap.get("auth_options", []) or []:
                if ao.get("id"):
                    pids.add(ao["id"])
    return (vgids, pids)


def patch_connection_file(conn_path: str, yml_params: dict[str, dict],
                          view_group_ids: set[str], profile_ids: set[str],
                          dry_run: bool) -> list[tuple[str, str, str]]:
    """Patch one connection.yaml. Returns list of (field_id, change_kind, detail).

    Only patches profiles owned by THIS integration — i.e. whose ``view_group``
    is in ``view_group_ids`` OR whose ``id`` is in ``profile_ids`` (both resolved
    from the handler ``xsoar-integration-id`` linkage) — so a shared
    multi-handler connector only has the current integration's fields touched.
    """
    with open(conn_path) as fh:
        doc = yaml.safe_load(fh) or {}
    profiles = doc.get("profiles") if isinstance(doc, dict) else doc
    if not profiles:
        return []

    changes: list[tuple[str, str, str]] = []
    for prof in profiles:
        owned = (str(prof.get("view_group", "")) in view_group_ids
                 or str(prof.get("id", "")) in profile_ids)
        if not owned:
            continue  # another integration's profile in a shared connector — skip
        xmap = parse_interpolation_mapping(
            (prof.get("metadata", {}) or {}).get("xsoar", {}).get("interpolation_mapping", "")
        )
        if not xmap:
            continue
        for cg in prof.get("configurations", []) or []:
            for f in cg.get("fields", []) or []:
                auth = (f.get("metadata") or {}).get("auth") or {}
                role = auth.get("parameter")
                if not role or role not in xmap:
                    continue  # non-auth field (proxy/insecure/engine/metadata) — leave alone
                title, mask = desired_title_and_mask(xmap[role], yml_params)
                fid = f.get("id", "?")
                # mask
                opts = f.setdefault("options", {})
                if opts.get("mask") != mask:
                    changes.append((fid, "mask", f"{opts.get('mask')} -> {mask}"))
                    opts["mask"] = mask
                # title
                if title is not None and f.get("title") != title:
                    changes.append((fid, "title", f"{f.get('title')!r} -> {title!r}"))
                    f["title"] = title

    if changes and not dry_run:
        with open(conn_path, "w") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False, default_flow_style=False, allow_unicode=True)
    return changes


GENERATED_MANIFEST_STEP_INDEX = 8  # 'generated manifest' is step #8


def integration_qualifies(iid: str) -> tuple[bool, dict]:
    """True if the integration PASSED 'generated manifest' (step #8) and has a
    connector folder path recorded. ``current_step_index > 8`` means the
    manifest checkpoint is done and we've advanced beyond it.
    """
    ctx = get_context(iid)
    cfp = ctx.get("connector_folder_path") or ""
    passed = int(ctx.get("current_step_index", 0)) > GENERATED_MANIFEST_STEP_INDEX
    return (passed and bool(cfp), ctx)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--assignee")
    g.add_argument("--integration-id")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.integration_id:
        ids = [args.integration_id]
    else:
        rows = integrations_for_assignee(args.assignee)
        ids = [r["integration_id"] for r in rows]

    cr = connectors_root()
    total_changes = 0
    touched = 0
    skipped = 0
    for iid in ids:
        ok, ctx = integration_qualifies(iid)
        if not ok:
            skipped += 1
            continue
        cfp = ctx.get("connector_folder_path")  # e.g. connectors/aws
        connector_dir = os.path.join(os.path.dirname(cr), cfp)
        conn_path = os.path.join(connector_dir, "connection.yaml")
        if not os.path.isfile(conn_path):
            print(f"[skip] {iid}: connection.yaml not found at {conn_path}")
            skipped += 1
            continue
        # Authoritative scoping: resolve this integration's view_group id(s) +
        # profile id(s) from the handler.yaml ``xsoar-integration-id`` linkage,
        # then patch only the profiles bound to those.
        vgids, pids = scope_for_integration(connector_dir, iid)
        if not vgids and not pids:
            print(f"[skip] {iid}: no handler matched xsoar-integration-id in {cfp}")
            skipped += 1
            continue
        yml_params = load_yml_params(ctx["file_paths"]["yml"])
        changes = patch_connection_file(conn_path, yml_params, vgids, pids, args.dry_run)
        if changes:
            touched += 1
            total_changes += len(changes)
            tag = "DRY" if args.dry_run else "FIX"
            print(f"[{tag}] {iid}  ({cfp})")
            for fid, kind, detail in changes:
                print(f"       {kind:<5} {fid}: {detail}")
        else:
            print(f"[ok ] {iid}: nothing to change")

    print(f"\n=== {'DRY-RUN ' if args.dry_run else ''}done: {touched} connector(s) changed, "
          f"{total_changes} field edit(s), {skipped} skipped ===")


if __name__ == "__main__":
    main()
