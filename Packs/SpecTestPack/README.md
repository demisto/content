# Spec Test Pack

This pack contains test integrations and scripts for validating the new `spec` field on Integration and Script content items.

## Background

The platform is introducing dedicated workers to run integrations and scripts. Each worker has a default memory limit of 1 GB. The `spec` field allows content authors to configure a larger memory allocation for integrations/scripts that require extra memory (e.g., rasterize).

## Integrations

### Spec Test Large Memory

Test integration **with** the `spec` field set to `L` (large memory allocation) under the `script:` object. Simulates an integration that requires extra memory for heavy data processing.

### Spec Test Default

Test integration **without** the `spec` field. Uses the platform's default worker memory allocation. Serves as a baseline to verify that the absence of the field is handled correctly.

## Scripts

### SpecTestScriptLargeMemory

Test script **with** the `spec` field set to `L` (large memory allocation). Validates the `spec` field behavior on Script content items.

### SpecTestScriptDefault

Test script **without** the `spec` field. Uses the platform's default worker memory allocation. Baseline for Script content items.

## `spec` Field Details

| Property | Value |
|----------|-------|
| **Location (Integration)** | Under the `script:` object (alongside `dockerimage`, `type`, `subtype`) |
| **Location (Script)** | Top-level field (alongside `dockerimage`, `type`, `subtype`) |
| **Values** | `S` (small), `M` (medium), `L` (large) |
| **System-only** | Not user-configurable; set by content authors |
| **Optional** | Defaults to absent (platform uses standard 1 GB worker allocation) |
