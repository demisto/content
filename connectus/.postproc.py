#!/usr/bin/env python3
"""Post-process generated connection.yaml files to apply 5 manifest rules:

R1 self_deployed -> read-only checkbox, default_value true (read_only in modifiers)
R2 tenant_id -> promote to general_configurations IFF every profile has it; drop from profiles
R3 strip "(...)" parentheticals from field titles
R4 proxy + insecure/trust -> always general_configurations (once), remove from all profiles
R5 engine* (engine, engine_mode, engine_group) -> always general_configurations, remove from profiles

Usage: ./.venv/bin/python connectus/.postproc.py <connection.yaml path> [more paths...]
Writes in place. Preserves key order via ruamel if available, else yaml round-trip.
"""

import re
import sys

try:
    from ruamel.yaml import YAML

    _ruamel = True
    _yaml = YAML()
    _yaml.preserve_quotes = True
    _yaml.indent(mapping=2, sequence=2, offset=0)
    _yaml.width = 4096
except Exception:
    import yaml as _py

    _ruamel = False

CONNECTORS = "/Users/nodavidi/dev/unified-connectors-content/connectors/"

# Field-id classification on the BARE (unprefixed) id.
ENGINE_IDS = {"engine", "engine_mode", "engine_group"}


def load(path):
    if _ruamel:
        with open(path) as f:
            return _yaml.load(f)
    with open(path) as f:
        return _py.safe_load(f)


def dump(path, data):
    if _ruamel:
        with open(path, "w") as f:
            _yaml.dump(data, f)
    else:
        with open(path, "w") as f:
            _py.safe_dump(data, f, sort_keys=False, width=4096)


def _is_tenant(field):
    """A field is the tenant_id field if its auth.parameter role is tenant_id."""
    return field.get("metadata", {}).get("auth", {}).get("parameter") == "tenant_id"


def _is_managed_identity(profile):
    """True if the profile is a managed-identity flow (id or title contains
    'managed_identity'/'managed identity', or it only carries a managed-identity
    client-id auth field)."""
    pid = (profile.get("id") or "").lower()
    title = (profile.get("title") or "").lower()
    if "managed_identity" in pid or "managed identity" in title or "managed_identities" in pid:
        return True
    # structural fallback: a profile whose only auth.parameter is managed_identities*
    params = []
    for g in profile.get("configurations", []):
        for f in g.get("fields", []):
            ap = f.get("metadata", {}).get("auth", {}).get("parameter")
            if ap:
                params.append(ap)
    return bool(params) and all("managed_identit" in p for p in params)


def strip_title(t):
    if not isinstance(t, str):
        return t
    # remove any parenthetical qualifier, collapse whitespace
    out = re.sub(r"\s*\([^)]*\)", "", t).strip()
    return out or t


def canonical_movable_id(fid):
    """Map any (possibly handler-prefixed) field id to its canonical bare id for
    proxy/insecure/engine, so cross-handler duplicates collapse to one field.
    Returns None if the field is not a movable connection field."""
    low = fid.lower()
    for eng in ("engine_group", "engine_mode", "engine"):  # longest first
        if low.endswith(eng):
            return eng
    if low.endswith("proxy") or low == "proxy":
        return "proxy"
    if any(low.endswith(s) for s in ("insecure", "unsecure")) or "trust" in low:
        return "insecure" if "insecure" in low or "trust" in low else "unsecure"
    return None


def bare_id(fid, profile_id):
    """Strip the per-profile prefix (profile_id with . -> _, plus trailing _)."""
    pref = profile_id.replace(".", "_") + "_"
    if fid.startswith(pref):
        return fid[len(pref) :]
    return fid


def classify(bare):
    low = bare.lower()
    if bare in ENGINE_IDS:
        return "engine"
    if "proxy" in low:
        return "proxy"
    if any(k in low for k in ("insecure", "unsecure", "trust", "verify", "secure")):
        # but NOT secure things like 'secure_connection'? keep broad per rule: insecure/trust
        if "insecure" in low or "unsecure" in low or "trust" in low:
            return "insecure"
    return None


ENGINE_FIELD_IDS = {"engine", "engine_mode", "engine_group"}


def make_general_field(bare, sample_field):
    """Build a general_configurations field from a sample profile field, keeping
    its title/options but using the BARE id.

    Alignments to the reference pattern:
    - engine / engine_mode / engine_group: keep their radio/select shape but add
      metadata.xsoar.config_type: backend.
    - insecure/trust field: title -> "Trust any certificate (not secure)".
    - proxy / insecure: NOT read_only (drop read_only from modifiers).
    general_configurations operational fields otherwise carry NO metadata
    (event.publish is FORBIDDEN here per .clinerules R26)."""
    f = {"id": bare}
    cls = classify(bare)

    # title
    if bare in ENGINE_FIELD_IDS:
        title = sample_field.get("title", "Engine")
    elif cls == "insecure":
        title = "Trust any certificate (not secure)"
    elif cls == "proxy":
        title = sample_field.get("title", "Use system proxy settings")
    else:
        title = strip_title(sample_field.get("title", bare))
    f["title"] = title

    f["field_type"] = sample_field.get("field_type", "input")

    # engine fields get config_type: backend
    if bare in ENGINE_FIELD_IDS:
        f["metadata"] = {"xsoar": {"config_type": "backend"}}

    opts = dict(sample_field.get("options", {}))
    opts.pop("mask", None)
    opts.setdefault("mask", False)
    # proxy / insecure must NOT be read_only
    if cls in ("proxy", "insecure"):
        for mod in ("create_modifiers", "edit_modifiers"):
            if isinstance(opts.get(mod), dict):
                opts[mod].pop("read_only", None)
    f["options"] = opts
    return f


def process(path):
    data = load(path)
    profiles = data.get("profiles", [])
    if not profiles:
        print(f"  {path}: no profiles, skip")
        return

    # 0) Ensure the FIRST profile's id carries its auth-name suffix (the
    # generator gives the first profile the bare integration slug while the
    # rest get '<slug>_<authname>'). Rename it to '<id>_<title>' for
    # consistency, updating handler.yaml auth_options[].id too. The first
    # profile's FIELDS use bare ids (no profile-id prefix), so no field/
    # serializer/trigger refs need changing — only the 2 id references.
    renamed_profiles = _suffix_first_profile_id(path, data, profiles)

    # 1) Gather, per profile, the bare->field for movable fields + tenant_id presence.
    # Promote tenant_id to general_configurations ONLY when there is NO
    # managed_identity profile AND every profile uses tenant_id. If any
    # managed_identity flow exists (or any profile lacks tenant_id), keep
    # tenant_id per-profile (user decision).
    movable_samples = {}  # bare_id -> sample field dict (proxy/insecure/engine)
    has_managed_identity = False
    tenant_flags = []  # has_tenant per profile
    for p in profiles:
        pid = p["id"]
        has_tenant = False
        if _is_managed_identity(p):
            has_managed_identity = True
        for grp in p.get("configurations", []):
            for f in grp.get("fields", []):
                canon = canonical_movable_id(f["id"])
                if canon and canon not in movable_samples:
                    movable_samples[canon] = f
                if _is_tenant(f):
                    has_tenant = True
        tenant_flags.append(has_tenant)

    promote_tenant = (not has_managed_identity) and len(tenant_flags) > 0 and all(tenant_flags)

    # tenant sample (for general field) if promoting
    tenant_sample = None
    if promote_tenant:
        for p in profiles:
            for grp in p.get("configurations", []):
                for f in grp.get("fields", []):
                    if _is_tenant(f):
                        tenant_sample = f
                        break
            if tenant_sample:
                break

    # 2) Remove movable (+tenant if promoting) from every profile; fix self_deployed + titles.
    removed_ids_by_profile = {}
    for p in profiles:
        pid = p["id"]
        for grp in p.get("configurations", []):
            new_fields = []
            for f in grp.get("fields", []):
                b = bare_id(f["id"], pid)
                canon = canonical_movable_id(f["id"])
                if canon or (promote_tenant and _is_tenant(f)):
                    removed_ids_by_profile.setdefault(pid, set()).add(f["id"])
                    continue
                # R1 self_deployed shape
                if b == "self_deployed":
                    f["title"] = "Self Deployed"
                    f["field_type"] = "checkbox"
                    opts = f.setdefault("options", {})
                    opts["mask"] = False
                    opts["default_value"] = True
                    for mod in ("create_modifiers", "edit_modifiers"):
                        m = opts.setdefault(mod, {})
                        m["required"] = False
                        m["hidden"] = False
                        m["read_only"] = True
                # R3 strip titles
                if "title" in f:
                    f["title"] = strip_title(f["title"])
                new_fields.append(f)
            grp["fields"] = new_fields
        # drop now-empty field groups left behind after removal
        p["configurations"] = [g for g in p.get("configurations", []) if g.get("fields")]

    # 2b) DEMOTION: if we are NOT promoting tenant_id (e.g. a managed_identity
    # profile exists) but a prior run left tenant_id in general_configurations,
    # remove it from general_configurations — it belongs per-profile.
    if not promote_tenant:
        existing_gc = data.get("general_configurations")
        if existing_gc:
            for grp in existing_gc.get("configurations", []):
                grp["fields"] = [f for f in grp.get("fields", []) if not _is_tenant(f)]
            existing_gc["configurations"] = [g for g in existing_gc.get("configurations", []) if g.get("fields")]

    # 3) Build general_configurations block (order: tenant_id, proxy, insecure, engine*)
    gen_fields = []
    if promote_tenant and tenant_sample is not None:
        gf = {
            "id": "tenant_id",
            "title": strip_title(tenant_sample.get("title", "Tenant ID")),
            "field_type": tenant_sample.get("field_type", "input"),
            "metadata": {"auth": {"parameter": "tenant_id"}},
            "options": dict(tenant_sample.get("options", {})),
        }
        gen_fields.append(gf)
    order = (
        (["proxy"] if "proxy" in movable_samples else [])
        + ([b for b in movable_samples if classify(b) == "insecure"])
        + [b for b in ("engine", "engine_mode", "engine_group") if b in movable_samples]
    )
    for b in order:
        gen_fields.append(make_general_field(b, movable_samples[b]))

    # bare field_names that were moved out of profiles (for serializer cleanup)
    moved_field_names = set(movable_samples.keys())
    if promote_tenant:
        moved_field_names.add("tenant_id")

    # grouped? need view_group on the general_configurations FieldGroup row
    grouped, vg_id = _grouped_info(path)

    if gen_fields:
        gc = data.get("general_configurations")
        if not gc:
            gc = {"description": "Common configuration shared by all connection profiles", "configurations": [{"fields": []}]}
            data["general_configurations"] = gc
        if not gc.get("configurations"):
            gc["configurations"] = [{"fields": []}]
        existing = {f.get("id") for grp in gc["configurations"] for f in grp.get("fields", [])}
        for gf in gen_fields:
            if gf["id"] not in existing:
                gc["configurations"][0]["fields"].append(gf)
        # grouped connectors: every general_configurations FieldGroup row needs view_group
        if grouped and vg_id:
            for grp in gc["configurations"]:
                grp["view_group"] = vg_id

    # Reorder top-level keys so general_configurations comes BEFORE profiles
    # (matches reference connectors: metadata -> view_groups -> general_configurations -> profiles).
    _reorder_top_level(data)

    dump(path, data)

    # The set of prefixed/bare field IDs that were REMOVED from profiles.
    removed_field_ids = set()
    for ids in removed_ids_by_profile.values():
        removed_field_ids |= ids

    removed_ser = _clean_serializers(path, removed_field_ids)
    removed_trig = _clean_triggers(path, removed_field_ids)

    # Fix generator view_group slug inconsistency (parens kept in usage but
    # stripped in the registry) across connection.yaml + configurations.yaml.
    vg_fixed = _normalize_view_groups(path)

    print(
        f"  {path}: promoted_tenant={promote_tenant} moved={sorted(movable_samples)} "
        f"grouped={grouped} serializer_removed={removed_ser} triggers_removed={removed_trig} "
        f"profile_renames={renamed_profiles} view_group_fixed={vg_fixed}"
    )


def _slug_authname(name):
    return re.sub(r"[^a-z0-9]+", "_", (name or "").strip().lower()).strip("_")


def _suffix_first_profile_id(connection_path, data, profiles):
    """If the first profile's id lacks its auth-name suffix, append it (derived
    from the profile title). Update handler.yaml auth_options ids accordingly.
    Returns dict {old_id: new_id} of any renames performed."""
    import glob
    import os

    renames = {}
    for p in profiles:
        pid = p.get("id", "")
        title = p.get("title", "")
        suffix = _slug_authname(title)
        if not suffix:
            continue
        # already suffixed?
        if pid.endswith("_" + suffix):
            continue
        new_id = pid + "_" + suffix
        # avoid colliding with an existing profile id
        if any(other is not p and other.get("id") == new_id for other in profiles):
            continue
        p["id"] = new_id
        renames[pid] = new_id

    if not renames:
        return renames

    # Update handler.yaml auth_options[].id references
    cdir = os.path.dirname(connection_path)
    for hy in glob.glob(os.path.join(cdir, "components", "handlers", "*", "handler.yaml")):
        h = load(hy)
        changed = False
        for cap in h.get("capabilities", []) or []:
            for ao in cap.get("auth_options", []) or []:
                if ao.get("id") in renames:
                    ao["id"] = renames[ao["id"]]
                    changed = True
        if changed:
            dump(hy, h)
    return renames


def _reorder_top_level(data):
    """Reorder top-level keys to: metadata, view_groups, general_configurations,
    profiles, then any others. Operates in place on the ruamel/dict mapping."""
    desired = ["metadata", "view_groups", "general_configurations", "profiles"]
    present = [k for k in desired if k in data]
    rest = [k for k in data.keys() if k not in desired]
    order = present + rest
    if list(data.keys()) == order:
        return
    if _ruamel:
        from ruamel.yaml.comments import CommentedMap

        new = CommentedMap()
        for k in order:
            new[k] = data[k]
        data.clear()
        for k in order:
            data[k] = new[k]
    else:
        items = {k: data[k] for k in order}
        data.clear()
        data.update(items)


def _grouped_info(connection_path):
    """Return (grouped: bool, view_group_id: str|None) for this connector."""
    import os

    cdir = os.path.dirname(connection_path)
    cy_path = os.path.join(cdir, "connector.yaml")
    grouped = False
    try:
        cy = load(cy_path)
        grouped = bool((cy.get("settings") or {}).get("grouped"))
    except Exception:
        pass
    vg = None
    try:
        conn = load(connection_path)
        vgs = conn.get("view_groups") or []
        if vgs:
            vg = vgs[0].get("id")
    except Exception:
        pass
    return grouped, vg


def _clean_serializers(connection_path, removed_field_ids):
    """Remove field_mappings entries whose id is a removed connection field id,
    across every handler's serializer.yaml in this connector."""
    import glob
    import os

    cdir = os.path.dirname(connection_path)
    removed = 0
    for ser in glob.glob(os.path.join(cdir, "components", "handlers", "*", "serializer.yaml")):
        s = load(ser)
        fm = s.get("field_mappings") if isinstance(s, dict) else None
        if not fm:
            continue
        new = [m for m in fm if m.get("id") not in removed_field_ids]
        if len(new) != len(fm):
            removed += len(fm) - len(new)
            s["field_mappings"] = new
            dump(ser, s)
    return removed


def _refs_removed(node, removed_field_ids):
    """True if any 'id' anywhere in this trigger node is a removed field id."""
    if isinstance(node, dict):
        if node.get("id") in removed_field_ids:
            return True
        return any(_refs_removed(v, removed_field_ids) for v in node.values())
    if isinstance(node, list):
        return any(_refs_removed(v, removed_field_ids) for v in node)
    return False


def _normalize_view_groups(connection_path):
    """Fix the generator's view_group slug inconsistency: a used view_group value
    that isn't in the file's registry but whose parens-stripped form IS registered
    gets rewritten to the registered id. Applies to connection.yaml +
    configurations.yaml. Returns count of rewritten references."""
    import os

    cdir = os.path.dirname(connection_path)
    fixed = 0
    for fn in ("connection.yaml", "configurations.yaml"):
        fp = os.path.join(cdir, fn)
        if not os.path.exists(fp):
            continue
        d = load(fp)
        if not isinstance(d, dict):
            continue
        registry = {vg.get("id") for vg in (d.get("view_groups") or [])}
        if not registry:
            continue

        def resolve(vg):
            # 1) parens-stripped
            cand = re.sub(r"[()]", "", vg)
            if cand in registry:
                return cand
            # 2) full re-slug: any run of non-alphanumeric -> single dash, trim dashes
            cand = re.sub(r"[^a-z0-9]+", "-", vg.lower()).strip("-")
            if cand in registry:
                return cand
            # 3) match a registry id whose own re-slug equals this one's re-slug
            target = re.sub(r"[^a-z0-9]+", "-", vg.lower()).strip("-")
            for rid in registry:
                if re.sub(r"[^a-z0-9]+", "-", rid.lower()).strip("-") == target:
                    return rid
            return None

        def fix(node):
            nonlocal fixed
            if isinstance(node, dict):
                vg = node.get("view_group")
                if isinstance(vg, str) and vg not in registry:
                    r = resolve(vg)
                    if r:
                        node["view_group"] = r
                        fixed += 1
                for v in node.values():
                    fix(v)
            elif isinstance(node, list):
                for v in node:
                    fix(v)

        before = fixed
        fix(d)
        if fixed != before:
            dump(fp, d)
    return fixed


def _clean_triggers(connection_path, removed_field_ids):
    """Drop triggers[] entries that reference any removed connection field id
    (condition id or effect id), in this connector's triggers.yaml."""
    import os

    tp = os.path.join(os.path.dirname(connection_path), "triggers.yaml")
    if not os.path.exists(tp):
        return 0
    t = load(tp)
    trs = t.get("triggers") if isinstance(t, dict) else None
    if not trs:
        return 0
    new = [tr for tr in trs if not _refs_removed(tr, removed_field_ids)]
    removed = len(trs) - len(new)
    if removed:
        t["triggers"] = new
        dump(tp, t)
    return removed


def main():
    for p in sys.argv[1:]:
        process(p)


if __name__ == "__main__":
    main()
