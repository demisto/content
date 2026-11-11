# AI Prompts for Cortex Platform Content Development

This directory contains canonical prompt instructions designed to guide AI coding assistants when developing content for the Cortex Platform (XSOAR/XSIAM) repository.

## How to Use

AI coding assistants can consume the instructions in this directory to align their outputs with repository-specific standards, authentication structures, naming conventions, and testing protocols.

To use these instructions simply provide the target prompt file (e.g., `@/.ai/skills/mcp-integration-development/SKILL.md`) to your AI assistant's active context.

## Structure

AI assets are grouped by type into subdirectories, additional categories may be added over time.

- `skills/` — task-focused instruction sets, each in its own subfolder containing a `SKILL.md` (the full instructions to load into context) and a `README.md` containing a short summary.

### Skills

| Skill | Description |
|-------|-------------|
| [MCP Integration Developer](skills/mcp-integration-development/README.md) | Generates and enhances production-ready MCP (Model Context Protocol) integration packs, following existing reference-pack patterns and the shared `MCPApiModule`. |
