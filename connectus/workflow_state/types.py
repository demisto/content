"""Typed dataclasses for the workflow_state package.

Pure data — no I/O, no validation logic. The :func:`config_loader.load_config`
function constructs ``WorkflowConfig`` instances from the YAML file and the
engine consumes those objects.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Step:
    """A single step in the unified workflow sequence.

    Backward-compatible: the original positional signature
    ``Step(index, name, kind, optional, setter, description)`` still
    works because the trailing fields all have defaults.

    Two carve-out flags govern the cascade-reset rule:

    - ``cascade_on_set`` (set-write side): when False, a successful
      ``set-X`` write to THIS step does NOT cascade-reset later steps.
      Example: ``assignee`` (changing the owner shouldn't nuke their
      progress).
    - ``preserve_on_reset`` (reset side): when True, this step's value
      is PRESERVED across ``reset-to``/``fail`` operations whose blast
      radius would otherwise include it. The ``set-auth`` cascade
      (which calls ``reset_after`` directly) ignores this flag — auth
      changes invalidate downstream artifacts and must continue to
      wipe everything. Plain ``reset`` (the "wipe the whole row" verb)
      also ignores this flag.

      The single carve-out: if the user names a preserved step
      EXPLICITLY as the target of ``reset-to``/``fail``, the user's
      intent wins for that one step (the named target is cleared), but
      LATER preserved steps in the same operation are still preserved.
    """

    index: int                              # 1..N
    name: str                               # CSV column AND user-facing identifier
    kind: str                               # "data" | "checkpoint" | "flag"
    optional: bool                          # True only for steps that may be `skip`-ped
    setter: Optional[str]                   # CLI subcommand for setting; None for pure markpass
    description: str                        # short human-readable summary
    cascade_on_set: bool = True             # if False, setting this step does NOT cascade-reset
    json_schema: Optional[str] = None       # named JSON validator key (or None)
    cross_check: Optional[str] = None       # named cross-step validator key (or None)
    preserve_on_reset: bool = False         # if True, reset-to/fail preserve this column's value
    # Per-step enum override for ``kind: flag`` steps. When None, the
    # global ``markers.flag_values`` apply. When set, this list IS the
    # complete enum for this step (the global default does not extend
    # it). Optional even for flag steps — the historical YES/NO/N/A
    # flag did not declare its own values.
    flag_values: Optional[tuple[str, ...]] = None
    # Optional read-side default for ``kind: flag`` steps. When the cell
    # is empty on read, ``is_done`` / ``show-step`` / ``status`` see
    # this value instead of "". The CSV cell is NOT auto-written; only
    # an explicit setter call persists a value to disk.
    default: Optional[str] = None


@dataclass(frozen=True)
class IdentityColumn:
    """One identity / metadata CSV column entry (never managed by the workflow)."""

    name: str
    description: str = ""


@dataclass(frozen=True)
class MarkerSet:
    """Sentinel and marker values used by the engine."""

    check: str
    fail: str
    na: str
    checkpoint_done_values: tuple[str, ...]
    flag_values: tuple[str, ...]


@dataclass(frozen=True)
class StepInteraction:
    """One cross-step interaction rule (today only ``flag_auto_na_target``)."""

    kind: str
    when_step: str
    when_value_in: tuple[str, ...]
    target_step: str
    write_value: str


@dataclass(frozen=True)
class WorkflowConfig:
    """The fully-loaded, validated workflow configuration.

    All derived collections (``step_by_name``, ``workflow_columns``, …)
    are computed lazily via @property so the dataclass remains a pure
    record of what was in the YAML.
    """

    schema_version: int
    identity_columns: tuple[IdentityColumn, ...]
    markers: MarkerSet
    steps: tuple[Step, ...]
    step_interactions: tuple[StepInteraction, ...] = field(default_factory=tuple)

    # ---- Derived helpers ------------------------------------------------

    @property
    def step_by_name(self) -> dict[str, Step]:
        return {s.name: s for s in self.steps}

    @property
    def step_by_index(self) -> dict[int, Step]:
        return {s.index: s for s in self.steps}

    @property
    def identity_column_names(self) -> list[str]:
        return [c.name for c in self.identity_columns]

    @property
    def workflow_columns(self) -> list[str]:
        return [s.name for s in self.steps]

    @property
    def workflow_data_columns(self) -> list[str]:
        return [s.name for s in self.steps if s.kind == "data"]

    @property
    def checkpoint_columns(self) -> list[str]:
        return [s.name for s in self.steps if s.kind == "checkpoint"]

    @property
    def json_valued_columns(self) -> set[str]:
        # A "JSON-valued column" is any data step that has a named
        # json_schema validator. This deliberately matches the legacy
        # `JSON_VALUED_COLUMNS` (data steps minus the `assignee` step,
        # which has no json_schema in YAML).
        return {
            s.name for s in self.steps
            if s.kind == "data" and s.json_schema is not None
        }

    @property
    def all_columns(self) -> list[str]:
        return self.identity_column_names + self.workflow_columns

    @property
    def expected_column_count(self) -> int:
        return len(self.all_columns)

    @property
    def non_checkpoint_steps(self) -> dict[str, str]:
        """Mapping of step name → setter command for steps that have a setter."""
        return {s.name: s.setter for s in self.steps if s.setter is not None}

    @property
    def auth_parity_flag_column(self) -> Optional[str]:
        """The ``when_step`` of the (single) ``flag_auto_na_target`` interaction.

        Returns None if no such interaction is configured. The legacy
        constant ``AUTH_PARITY_FLAG_COLUMN`` is derived from this.
        """
        for inter in self.step_interactions:
            if inter.kind == "flag_auto_na_target":
                return inter.when_step
        return None

    def find_flag_auto_na_target(self, when_step: str) -> Optional[StepInteraction]:
        """Return the ``flag_auto_na_target`` interaction whose ``when_step``
        matches the argument, or ``None``.
        """
        for inter in self.step_interactions:
            if inter.kind == "flag_auto_na_target" and inter.when_step == when_step:
                return inter
        return None

    # ---- Column-number addressability ----------------------------------

    def resolve_column_ref(
        self,
        ref: str,
        *,
        allow_identity: bool = True,
        verb: str = "this operation",
    ) -> str:
        """Resolve a column reference (name OR 1-based number) to a column name.

        ``ref`` may be:
          - a column name (must match an identity column or a step name); or
          - an all-digits string parsed as a 1-based index into
            ``all_columns`` (identity columns first, then steps).

        When ``allow_identity`` is False, an identity-column index is
        rejected with a verb-aware error. Names that match identity
        columns are likewise rejected when ``allow_identity`` is False.

        Raises ``ValueError`` with a single human-readable message on any
        validation failure (out-of-range, unknown name, identity reject).
        The CLI layer wraps this in its own user-facing print/exit.
        """
        all_cols = self.all_columns
        n = len(all_cols)
        identity_names = set(self.identity_column_names)

        stripped = ref.strip()
        if stripped.isdigit() and stripped:
            num = int(stripped)
            if num < 1 or num > n:
                raise ValueError(
                    f"column number must be between 1 and {n}; got {num}"
                )
            resolved = all_cols[num - 1]
            if not allow_identity and resolved in identity_names:
                raise ValueError(
                    f"column #{num} ({resolved!r}) is an identity column; "
                    f"cannot apply {verb}"
                )
            return resolved

        # Name-based lookup.
        if stripped in self.step_by_name:
            return stripped
        if stripped in identity_names:
            if not allow_identity:
                raise ValueError(
                    f"column {stripped!r} is an identity column; "
                    f"cannot apply {verb}"
                )
            return stripped
        raise ValueError(
            f"unknown column {ref!r}. "
            f"Provide a column name or a 1-based number 1..{n}."
        )
