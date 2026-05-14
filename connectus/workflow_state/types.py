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
    works because the two new fields (``cascade_on_set`` and
    ``json_schema``) have defaults.
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
