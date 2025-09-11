# Aggregated Command API Module

The **Aggregated Command API Module** is a framework for building  aggregated command scripts in Cortex XSOAR and XSIAM.
It introduces a set of classes and utilities to help you build scripts that run multiple commands in a batch, merge results.

The **ReputationAggregatedCommand** is a framework that inherits from the **AggregatedCommandAPIModule** and provides a simple interface for building complex indicator enrichment scripts in Cortex XSOAR and XSIAM.
It automates the workflow of querying multiple integrations, merging results with existing Threat Intelligence Management (TIM) data, and producing a single, unified output.

Note: Usage of these scripts are subject to breaking changes in the future, due to relying on commands outputs structure.
***

## Key Features

- **Automated Batch Execution**: Efficiently runs multiple commands in a single, parallel batch request.
- **Data Merging**: Combines results from integrations with cached data from TIM, automatically prioritizing fresh information.
- **Declarative Context Mapping**: Use simple data classes to define how raw data from different commands should be transformed into a clean, final context structure.
- **Extensible by Design**: Easily add custom commands (e.g., internal sandbox analysis) to run alongside the standard reputation commands.
- **Brand choice**: Filters commands based on enabled integration instances and user-provided brand names.
- **Verbose Output**: Includes a verbose mode for detailed logging, making debugging and validation straightforward.

***

## Core Concepts

To use the module, you need to understand these fundamental building blocks:

### Indicator

A data class that defines the "schema" for the indicator you are enriching. It tells the framework how to process the data.

- **`type` (str)**: The indicator type, which corresponds to the XSOAR command name (e.g., `'url'`, `'ip'`, `'file'`).
- **`value_field` (str)**: The key name in the final context that will hold the indicator's value (e.g., `'Data'`, `'Address'`).
- **`context_path_prefix` (str)**: The standard context path prefix for this indicator type (e.g., `'URL('`, `'IP('`).
- **`mapping` (dict)**: A dictionary that defines the rules for mapping raw command output to the final context.
  - *Key*: Source path in the raw output using double dot notation (e.g., `'VirusTotal..POSITIVES'`).
  - *Value*: Destination path in the final context using double dot notation (e.g., `'VT..POSITIVES'`).

### Command

A generic class to represent any command you want to execute. You use this to add custom, non-reputation commands to the workflow.

- **`name` (str)**: The name of the command to run (e.g., `'wildfire-get-verdict'`).
- **`args` (dict)**: The arguments for the command.
- **`brand` (str)**: The specific integration brand to use.
- **`command_type` (CommandType)**: The execution policy (`INTERNAL` or `EXTERNAL` or `REGULAR`).
- **`mapping` (dict)**: A dictionary that defines the rules for mapping raw command output to the final context.

### ReputationCommand

A class that extends the Command class and is used to represent a reputation command.

- **`indicator` (Indicator)**: The indicator object.
- **`data` (str)**: The data to enrich only one per command.

### BatchExecutor

A class that executes a list of commands in a batch.

- **`commands` (list[Command])**: A list of commands to execute.
- **`brands_to_run` (list[str])**: A list of brands to run on.

***

## Example: look at URLEnrichment script
