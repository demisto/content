# Spec Test Pack

This pack contains test integrations for validating the new `spec` field on Integration content items.

## Background

The platform is introducing dedicated workers to run integrations and scripts. Each worker has a default memory limit of 1 GB. The `spec` field allows content authors to configure a larger memory allocation for integrations that require extra memory (e.g., rasterize).

## Integrations

### Spec Test Large Memory

Test integration **with** the `spec` field set to `L` (large memory allocation). Simulates an integration that requires extra memory for heavy data processing.

### Spec Test Default

Test integration **without** the `spec` field. Uses the platform's default worker memory allocation. Serves as a baseline to verify that the absence of the field is handled correctly.

## `spec` Field Values

| Value | Description |
|-------|-------------|
| `S`   | Small memory allocation |
| `M`   | Medium memory allocation |
| `L`   | Large memory allocation |
