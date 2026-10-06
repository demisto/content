# Held back from release

These correlation rules are **not shipped** with the pack. They are kept here
so the work is not lost and so the reasoning is on the record.

## Why

OpenShell's default sandbox policy denies all egress, including routine
destinations such as `api.github.com`. On a live 0.1.2 sandbox, a handful of
ordinary `curl` invocations produced 7 TCP-stage denials across 6 distinct
destinations in under a minute.

`NVIDIAOpenShell_RepeatedEgressDenials.yml` fires at 10 denials across 3
destinations in 30 minutes. An AI agent doing normal work — package installs,
API calls, dependency fetches — clears that threshold within minutes of
starting, on every sandbox, continuously.

The rule treats denial volume as a signal in a system where denial is the
default state. That is not a threshold that can be tuned from the outside; it
needs a baseline from a real deployment with a real policy applied.

`NVIDIAOpenShell_SandboxSecurityFinding.yml` has a different problem. It
targets OCSF Detection Finding (2004) at `severity_id >= 4`. No 2004 event was
ever observed during development. The field names are verified against the
`openshell-ocsf` crate, but whether high-severity findings occur in practice,
and at what rate, is unknown.

## What would make them shippable

1. Baseline data from a deployment with a non-default policy, to establish what
   an abnormal denial rate actually looks like
2. Confirmation that class 2004 events occur, and at what severity distribution
3. Thresholds derived from that data rather than chosen a priori

## Using them anyway

If you have that baseline, both rules are valid XQL and install through the
Correlation Rules UI. Adjust `denial_count` and `distinct_destinations` in the
egress rule to match your environment before enabling it.
