"""YAML config loader for the workflow_state package.

Reads ``connectus/workflow_state_config.yml``, validates the schema
described in ``workflow_state_DESIGN.md`` §5.2, and returns a fully
typed :class:`~workflow_state.types.WorkflowConfig` value.

All errors are collected before the loader raises; callers see a single
:class:`~workflow_state.exceptions.ConfigLoadError` whose ``.errors``
attribute lists every individual problem.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import yaml

from workflow_state.exceptions import ConfigLoadError
from workflow_state.types import (
    IdentityColumn,
    MarkerSet,
    Step,
    StepInteraction,
    WorkflowConfig,
)
from workflow_state.validators import (
    is_known_cross_check,
    known_cross_check_names,
    known_validator_names,
)


SUPPORTED_SCHEMA_VERSIONS = (1,)
_VALID_STEP_KINDS = {"data", "checkpoint", "flag"}
_VALID_INTERACTION_KINDS = {"flag_auto_na_target"}

_TOP_LEVEL_REQUIRED = {"schema_version", "identity_columns", "markers", "steps"}
_TOP_LEVEL_OPTIONAL = {"step_interactions"}
_TOP_LEVEL_ALLOWED = _TOP_LEVEL_REQUIRED | _TOP_LEVEL_OPTIONAL

# Default path: connectus/workflow_state_config.yml, sitting next to the
# `connectus/` package directory.
_DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "workflow_state_config.yml",
)


# Module-level singleton cache.
_CACHED_CONFIG: Optional[WorkflowConfig] = None
_CACHED_PATH: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def default_config_path() -> str:
    """Return the on-disk path to the bundled workflow config YAML."""
    return _DEFAULT_CONFIG_PATH


def load_config(path: Optional[str] = None) -> WorkflowConfig:
    """Load and validate the YAML config; return a :class:`WorkflowConfig`.

    Args:
        path: Optional explicit path. Defaults to the file shipped next
            to the package (``connectus/workflow_state_config.yml``).

    Raises:
        ConfigLoadError: When the file is missing, unparseable, or the
            schema validation fails. ``ConfigLoadError.errors`` lists
            every individual problem.
    """
    global _CACHED_CONFIG, _CACHED_PATH

    resolved = os.path.abspath(path) if path else _DEFAULT_CONFIG_PATH

    if _CACHED_CONFIG is not None and _CACHED_PATH == resolved:
        return _CACHED_CONFIG

    raw = _read_yaml(resolved)
    config = _build_and_validate(raw, resolved)

    _CACHED_CONFIG = config
    _CACHED_PATH = resolved
    return config


def get_config() -> WorkflowConfig:
    """Return the cached :class:`WorkflowConfig`. First call triggers load."""
    if _CACHED_CONFIG is None:
        return load_config()
    return _CACHED_CONFIG


def _reset_config_for_testing() -> None:
    """Clear the singleton cache. Tests use this between fixture YAMLs."""
    global _CACHED_CONFIG, _CACHED_PATH
    _CACHED_CONFIG = None
    _CACHED_PATH = None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _read_yaml(path: str) -> dict:
    """Open the YAML file and return the parsed top-level mapping.

    Wraps both file-not-found and YAML parse errors in
    :class:`ConfigLoadError` with the full path embedded.
    """
    if not os.path.exists(path):
        raise ConfigLoadError(
            f"workflow config file not found: {path}",
            errors=[f"workflow config file not found: {path}"],
        )
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        msg = f"YAML parse error in {path}: {e}"
        raise ConfigLoadError(msg, errors=[msg])

    if data is None:
        msg = f"workflow config file is empty: {path}"
        raise ConfigLoadError(msg, errors=[msg])

    if not isinstance(data, dict):
        msg = f"workflow config root must be a mapping; got {type(data).__name__} in {path}"
        raise ConfigLoadError(msg, errors=[msg])

    return data


def _raise_if_errors(errors: list[str], path: str) -> None:
    if not errors:
        return
    summary = (
        f"{path} has {len(errors)} problem(s):\n"
        + "\n".join(f"  - {e}" for e in errors)
    )
    raise ConfigLoadError(summary, errors=list(errors))


def _build_and_validate(raw: dict, path: str) -> WorkflowConfig:
    """Validate the raw mapping and assemble a :class:`WorkflowConfig`."""
    errors: list[str] = []

    # ---- Top-level shape ------------------------------------------------
    raw_keys = set(raw.keys())
    missing_top = _TOP_LEVEL_REQUIRED - raw_keys
    extra_top = raw_keys - _TOP_LEVEL_ALLOWED
    for k in sorted(missing_top):
        errors.append(f"missing required top-level key: {k!r}")
    for k in sorted(extra_top):
        errors.append(f"unknown top-level key: {k!r}")

    # If the top-level shape is broken, bail early so we don't crash
    # below trying to access missing keys.
    if missing_top:
        _raise_if_errors(errors, path)

    # ---- schema_version -------------------------------------------------
    schema_version = raw.get("schema_version")
    if not isinstance(schema_version, int):
        errors.append(
            f"schema_version must be an int; got {type(schema_version).__name__}"
        )
    elif schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(
            f"unsupported schema_version: {schema_version} "
            f"(supported: {list(SUPPORTED_SCHEMA_VERSIONS)})"
        )

    # ---- identity_columns ----------------------------------------------
    identity_columns, ic_errors = _build_identity_columns(raw.get("identity_columns"))
    errors.extend(ic_errors)

    # ---- markers --------------------------------------------------------
    markers, marker_errors = _build_markers(raw.get("markers"))
    errors.extend(marker_errors)

    # ---- steps ----------------------------------------------------------
    steps, step_errors = _build_steps(raw.get("steps"))
    errors.extend(step_errors)

    # Cross-validation: identity column names must not collide with step names.
    if identity_columns is not None and steps is not None:
        ic_names = {c.name for c in identity_columns}
        for s in steps:
            if s.name in ic_names:
                errors.append(
                    f"steps[{s.index}] ({s.name!r}): step name collides "
                    f"with an identity_columns entry"
                )

    # ---- step_interactions ---------------------------------------------
    interactions, inter_errors = _build_interactions(
        raw.get("step_interactions"),
        steps,
        markers,
    )
    errors.extend(inter_errors)

    _raise_if_errors(errors, path)

    return WorkflowConfig(
        schema_version=schema_version,
        identity_columns=tuple(identity_columns),
        markers=markers,
        steps=tuple(steps),
        step_interactions=tuple(interactions),
    )


def _build_identity_columns(
    raw: Any,
) -> tuple[Optional[list[IdentityColumn]], list[str]]:
    errors: list[str] = []
    if not isinstance(raw, list) or not raw:
        errors.append("identity_columns must be a non-empty list")
        return None, errors

    out: list[IdentityColumn] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            errors.append(
                f"identity_columns[{i}] must be a mapping; got "
                f"{type(item).__name__}"
            )
            continue
        name = item.get("name")
        description = item.get("description", "")
        if not isinstance(name, str) or not name.strip():
            errors.append(
                f"identity_columns[{i}].name must be a non-empty string"
            )
            continue
        if name in seen:
            errors.append(
                f"identity_columns[{i}].name {name!r} is duplicated"
            )
        seen.add(name)
        if description is None:
            description = ""
        if not isinstance(description, str):
            errors.append(
                f"identity_columns[{i}].description must be a string"
            )
            description = ""
        out.append(IdentityColumn(name=name, description=description))

    if not out and not errors:
        errors.append("identity_columns must contain at least one valid entry")
    return (out if out else None), errors


def _build_markers(raw: Any) -> tuple[Optional[MarkerSet], list[str]]:
    errors: list[str] = []
    if not isinstance(raw, dict):
        errors.append("markers must be a mapping")
        return None, errors

    required_keys = {"check", "fail", "na", "checkpoint_done_values", "flag_values"}
    missing = required_keys - set(raw.keys())
    for k in sorted(missing):
        errors.append(f"markers.{k}: missing required key")
    if missing:
        return None, errors

    check = raw["check"]
    fail = raw["fail"]
    na = raw["na"]
    done_values = raw["checkpoint_done_values"]
    flag_values = raw["flag_values"]

    for field_name, value in (("check", check), ("fail", fail), ("na", na)):
        if not isinstance(value, str) or not value:
            errors.append(f"markers.{field_name} must be a non-empty string")

    if not isinstance(done_values, list) or not done_values:
        errors.append("markers.checkpoint_done_values must be a non-empty list of strings")
        return None, errors
    for i, v in enumerate(done_values):
        if not isinstance(v, str) or not v:
            errors.append(
                f"markers.checkpoint_done_values[{i}] must be a non-empty string"
            )

    if not isinstance(flag_values, list) or not flag_values:
        errors.append("markers.flag_values must be a non-empty list of strings")
        return None, errors
    if len(set(flag_values)) != len(flag_values):
        errors.append("markers.flag_values must contain unique values")
    for i, v in enumerate(flag_values):
        if not isinstance(v, str) or not v:
            errors.append(f"markers.flag_values[{i}] must be a non-empty string")

    if isinstance(check, str) and check not in done_values:
        errors.append(
            f"markers.checkpoint_done_values: missing required value "
            f"{check!r} (markers.check)"
        )
    if isinstance(na, str) and na not in done_values:
        errors.append(
            f"markers.checkpoint_done_values: missing required value "
            f"{na!r} (markers.na)"
        )

    if errors:
        return None, errors

    return (
        MarkerSet(
            check=check,
            fail=fail,
            na=na,
            checkpoint_done_values=tuple(done_values),
            flag_values=tuple(flag_values),
        ),
        errors,
    )


def _build_steps(raw: Any) -> tuple[Optional[list[Step]], list[str]]:
    errors: list[str] = []
    if not isinstance(raw, list) or not raw:
        errors.append("steps must be a non-empty list")
        return None, errors

    out: list[Step] = []
    seen_names: set[str] = set()
    seen_setters: set[str] = set()
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            errors.append(f"steps[{idx}] must be a mapping; got {type(item).__name__}")
            continue
        step, step_errors = _build_one_step(idx, item)
        errors.extend(step_errors)
        if step is None:
            continue
        if step.name in seen_names:
            errors.append(f"steps[{idx}] ({step.name!r}): duplicate step name")
        seen_names.add(step.name)
        if step.setter is not None:
            if step.setter in seen_setters:
                errors.append(
                    f"steps[{idx}] ({step.name!r}): duplicate setter "
                    f"{step.setter!r} (already used by an earlier step)"
                )
            seen_setters.add(step.setter)
        out.append(step)

    if not out and not errors:
        errors.append("steps must contain at least one valid entry")
    return (out if out else None), errors


def _coerce_validator_name(item: Any, field_label: str, errors: list[str]) -> Optional[str]:
    """Accept either ``{"validator": "name"}`` (preferred per Q3) or a bare string."""
    if item is None:
        return None
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        if "validator" in item and isinstance(item["validator"], str):
            return item["validator"]
        errors.append(
            f"{field_label}: dict form must contain a 'validator' key with "
            f"a string value (e.g. {{'validator': 'auth_details'}})"
        )
        return None
    errors.append(
        f"{field_label}: must be a string or {{'validator': '<name>'}} mapping"
    )
    return None


def _build_one_step(index: int, item: dict) -> tuple[Optional[Step], list[str]]:
    errors: list[str] = []
    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append(f"steps[{index}].name must be a non-empty string")
        return None, errors

    label = f"steps[{index}] ({name!r})"

    kind = item.get("kind")
    if kind not in _VALID_STEP_KINDS:
        errors.append(
            f"{label}.kind must be one of {sorted(_VALID_STEP_KINDS)}; got {kind!r}"
        )
        return None, errors

    optional = item.get("optional")
    if not isinstance(optional, bool):
        errors.append(f"{label}.optional must be a bool; got {type(optional).__name__}")
        optional = False

    description = item.get("description")
    if not isinstance(description, str) or not description.strip():
        errors.append(f"{label}.description must be a non-empty string")
        description = ""

    setter = item.get("setter", None)
    if kind in ("data", "flag"):
        if not isinstance(setter, str) or not setter.strip():
            errors.append(
                f"{label}.setter must be a non-empty string for kind={kind!r}; "
                f"got {setter!r}"
            )
            setter = None
    elif kind == "checkpoint":
        if setter is not None:
            errors.append(
                f"{label}.setter must be null/absent for kind=checkpoint; "
                f"got {setter!r}"
            )
            setter = None

    cascade_on_set = item.get("cascade_on_set", True)
    if not isinstance(cascade_on_set, bool):
        errors.append(
            f"{label}.cascade_on_set must be a bool; got {type(cascade_on_set).__name__}"
        )
        cascade_on_set = True

    json_schema_name = _coerce_validator_name(
        item.get("json_schema"), f"{label}.json_schema", errors
    )
    if json_schema_name is not None and json_schema_name not in known_validator_names():
        errors.append(
            f"{label}.json_schema: unknown validator name {json_schema_name!r}; "
            f"valid: {known_validator_names()}"
        )
        json_schema_name = None

    cross_check_name = _coerce_validator_name(
        item.get("cross_check"), f"{label}.cross_check", errors
    )
    if cross_check_name is not None and not is_known_cross_check(cross_check_name):
        errors.append(
            f"{label}.cross_check: unknown cross_check name {cross_check_name!r}; "
            f"valid: {known_cross_check_names()}"
        )
        cross_check_name = None

    if errors and (kind not in _VALID_STEP_KINDS or not name):
        return None, errors

    return (
        Step(
            index=index,
            name=name,
            kind=kind,
            optional=optional,
            setter=setter,
            description=description,
            cascade_on_set=cascade_on_set,
            json_schema=json_schema_name,
            cross_check=cross_check_name,
        ),
        errors,
    )


def _build_interactions(
    raw: Any,
    steps: Optional[list[Step]],
    markers: Optional[MarkerSet],
) -> tuple[list[StepInteraction], list[str]]:
    errors: list[str] = []
    out: list[StepInteraction] = []
    if raw is None:
        return out, errors
    if not isinstance(raw, list):
        errors.append("step_interactions must be a list (or omitted)")
        return out, errors

    by_name = {s.name: s for s in (steps or [])}
    flag_values = set(markers.flag_values) if markers else set()
    done_values = set(markers.checkpoint_done_values) if markers else set()
    seen_when_steps: set[str] = set()

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            errors.append(
                f"step_interactions[{i}] must be a mapping; got {type(item).__name__}"
            )
            continue
        kind = item.get("kind")
        if kind not in _VALID_INTERACTION_KINDS:
            errors.append(
                f"step_interactions[{i}].kind must be one of "
                f"{sorted(_VALID_INTERACTION_KINDS)}; got {kind!r}"
            )
            continue

        when_step = item.get("when_step")
        target_step = item.get("target_step")
        when_value_in = item.get("when_value_in")
        write_value = item.get("write_value")

        # when_step
        if not isinstance(when_step, str) or not when_step.strip():
            errors.append(
                f"step_interactions[{i}].when_step must be a non-empty string"
            )
            continue
        when_obj = by_name.get(when_step)
        if when_obj is None:
            errors.append(
                f"step_interactions[{i}].when_step references unknown step "
                f"{when_step!r}"
            )
        elif when_obj.kind != "flag":
            errors.append(
                f"step_interactions[{i}].when_step ({when_step!r}) must be "
                f"kind=flag; got kind={when_obj.kind!r}"
            )

        # target_step
        if not isinstance(target_step, str) or not target_step.strip():
            errors.append(
                f"step_interactions[{i}].target_step must be a non-empty string"
            )
            continue
        target_obj = by_name.get(target_step)
        if target_obj is None:
            errors.append(
                f"step_interactions[{i}].target_step references unknown step "
                f"{target_step!r}"
            )
        elif target_obj.kind != "checkpoint":
            errors.append(
                f"step_interactions[{i}].target_step ({target_step!r}) must "
                f"be kind=checkpoint; got kind={target_obj.kind!r}"
            )

        # when_value_in
        if not isinstance(when_value_in, list) or not when_value_in:
            errors.append(
                f"step_interactions[{i}].when_value_in must be a non-empty list"
            )
            when_value_in_clean: tuple[str, ...] = ()
        else:
            when_value_in_clean = tuple(when_value_in)
            for v in when_value_in:
                if v not in flag_values:
                    errors.append(
                        f"step_interactions[{i}].when_value_in: value {v!r} "
                        f"is not in markers.flag_values"
                    )

        # write_value
        if not isinstance(write_value, str) or not write_value:
            errors.append(
                f"step_interactions[{i}].write_value must be a non-empty string"
            )
        elif write_value not in done_values:
            errors.append(
                f"step_interactions[{i}].write_value: {write_value!r} is not "
                f"in markers.checkpoint_done_values"
            )

        if kind == "flag_auto_na_target" and isinstance(when_step, str):
            if when_step in seen_when_steps:
                errors.append(
                    f"step_interactions[{i}]: duplicate flag_auto_na_target "
                    f"for when_step {when_step!r} (only one is allowed per source)"
                )
            seen_when_steps.add(when_step)

        out.append(
            StepInteraction(
                kind=kind,
                when_step=when_step,
                when_value_in=when_value_in_clean,
                target_step=target_step,
                write_value=write_value if isinstance(write_value, str) else "",
            )
        )

    return out, errors
