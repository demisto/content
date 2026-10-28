"""XSUP-79350 platform repro - DO NOT MERGE.

Reproduces: after the server kills a long-running container for a missed heartbeat
("Monitor long running: didn't get heartbeat for [1.5] minutes. Killing long running"),
the respawned container gets the regular 5-minute script timeout instead of the long-running
timeout, and is killed every 5 minutes ("Script done with timeout (300000000000) reached, killing").

How: the first run freezes its own process after N seconds by holding the GIL with catastrophic
regex backtracking, so no thread (including the heartbeat thread) can run. The freeze happens only
once (flag in the integration context). Every later run just logs its uptime, so a run that dies at
~300s shows the bug.
"""

import re
import time
import uuid
from datetime import UTC, datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

LOG_PREFIX = "XSUP79350-LR-REPRO"
MAX_STORED_RUNS = 50
# Exponential backtracking: re holds the GIL for the whole match, which here never finishes in practice.
CATASTROPHIC_PATTERN = re.compile(r"(a+)+$")
CATASTROPHIC_INPUT = "a" * 45 + "b"


def log(message: str) -> None:
    demisto.info(f"{LOG_PREFIX} {message}")


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def register_run() -> tuple[dict, dict]:
    """Record a new run in the integration context and return (context, run)."""
    context = get_integration_context() or {}
    run = {"run_id": uuid.uuid4().hex[:8], "started": utc_now(), "max_uptime_seconds": 0}
    context["runs"] = (context.get("runs", []) + [run])[-MAX_STORED_RUNS:]
    set_integration_context(context)
    return context, run


def save_uptime(context: dict, uptime: int) -> None:
    context["runs"][-1]["max_uptime_seconds"] = uptime
    context["runs"][-1]["last_alive"] = utc_now()
    set_integration_context(context)


def freeze_process(context: dict) -> None:
    """Mark the freeze as done, then block every thread in the process until the server kills it."""
    context["freeze_done"] = utc_now()
    set_integration_context(context)
    log("FREEZING process now (GIL held). Expect a missed-heartbeat kill in about 1.5 minutes.")
    time.sleep(2)  # let the log line go out before the GIL is taken
    CATASTROPHIC_PATTERN.match(CATASTROPHIC_INPUT)


def long_running_loop(freeze_enabled: bool, freeze_after: int, log_interval: int) -> None:
    context, run = register_run()
    should_freeze = freeze_enabled and not context.get("freeze_done")
    log(f"run {run['run_id']} started (run #{len(context['runs'])}). will_freeze={should_freeze} freeze_after={freeze_after}s")
    start = time.monotonic()
    while True:
        uptime = int(time.monotonic() - start)
        save_uptime(context, uptime)
        log(f"run {run['run_id']} alive uptime={uptime}s")
        if should_freeze and uptime >= freeze_after:
            freeze_process(context)
        time.sleep(log_interval)


def status_command() -> CommandResults:
    context = get_integration_context() or {}
    runs = context.get("runs", [])
    readable = tableToMarkdown(
        f"LR repro runs (freeze_done: {context.get('freeze_done') or 'not yet'})",
        runs,
        headers=["run_id", "started", "last_alive", "max_uptime_seconds"],
    )
    return CommandResults(readable_output=readable, raw_response=context)


def reset_command() -> CommandResults:
    set_integration_context({})
    return CommandResults(readable_output="Context cleared. The next run will freeze again (re-save the instance).")


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    try:
        if command == "test-module":
            return_results("ok")
        elif command == "long-running-execution":
            long_running_loop(
                freeze_enabled=argToBoolean(params.get("freeze_enabled", True)),
                freeze_after=arg_to_number(params.get("freeze_after_seconds")) or 180,
                log_interval=arg_to_number(params.get("log_interval_seconds")) or 30,
            )
        elif command == "lr-repro-status":
            return_results(status_command())
        elif command == "lr-repro-reset":
            return_results(reset_command())
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
