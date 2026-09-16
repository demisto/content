# MCP Integration Developer Skill

This skill guides the creation and enhancement of **MCP (Model Context Protocol) integration packs** for the Cortex Platform content repository.

Given a user-provided specification, it generates complete, production-ready MCP packs that connect to an external MCP server and expose its tools as agentic system actions. All packs follow the patterns of existing reference packs (e.g. `GenericMCP`, `GitHubMCP`, `AtlassianCloudMCP`) and rely on the shared `MCPApiModule` instead of reimplementing MCP protocol logic.

The skill drives a phased workflow with mandatory reviews:

1. **Requirements & research** – gather vendor, server URL, auth method, and config.
2. **Planning & approval** – present a plan and get user sign-off.
3. **Python implementation** + independent review.
4. **YAML configuration** + independent review.
5. **Unit tests** – async unit tests.
6. **Documentation & metadata** – README, `pack_metadata.json`, release notes.
7. **Final refinement** – `pre-commit` and `validate` until clean.

See [`SKILL.md`](SKILL.md) for the full instructions, checklists, and conventions.
