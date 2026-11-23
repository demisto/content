Use the Command Zero MCP integration to securely connect to the Command Zero Model Context Protocol (MCP) server and access Command Zero investigation tools in real time.

## What does this pack do?

This pack is intended for Cortex Agentic AI.

Connects to the Command Zero MCP server to automatically discover tools and expose them as agentic system actions that users can enable for agents.

## Tools

Tool availability depends on the role of the Command Zero API key. **Read** tools work with the Observer role; **Write** tools need the Investigator role or higher.
The list below reflects the tools available at the time this pack was created and may change.

### get_caller_identity

- **Type**: Read
- **Purpose**: Returns the organization and role of the current session.

### list_integrations

- **Type**: Read
- **Purpose**: Lists the integrations Command Zero can contact, with service type, description, and paused state.

### list_investigations

- **Type**: Read
- **Purpose**: Lists investigations, with filtering by status, severity, sensitivity, category, tags, assignees, title, and creation or update time.

### get_investigation

- **Type**: Read
- **Purpose**: Returns an investigation's title, description, status, severity, sensitivity, category, tags, assignees, and time window.

### get_investigation_report

- **Type**: Read
- **Purpose**: Returns the latest AI-generated report for an investigation, including verdicts, confidence, impact, and proposed remediations.

### search_questions

- **Type**: Read
- **Purpose**: Selects the most relevant questions for a described scenario using semantic search.

### list_questions

- **Type**: Read
- **Purpose**: Lists available questions with full metadata, including intent, context, and keywords.

### list_questions_summary

- **Type**: Read
- **Purpose**: Lists available questions with minimal metadata, for faster browsing of a large catalog.

### get_question

- **Type**: Read
- **Purpose**: Returns detailed information for a single question.

### list_categories

- **Type**: Read
- **Purpose**: Lists the question categories available to the organization.

### get_invocation

- **Type**: Read
- **Purpose**: Returns the results of a previously run question.

### list_recent_invocations

- **Type**: Read
- **Purpose**: Lists recently run questions for an investigation.

### create_investigation

- **Type**: Write
- **Purpose**: Creates a visible, titled investigation.

### create_scratch_investigation

- **Type**: Write
- **Purpose**: Creates a hidden, temporary investigation for quick exploration.

### update_investigation

- **Type**: Write
- **Purpose**: Updates investigation properties. Only the fields provided are changed, and status transitions are validated.

### ask_question

- **Type**: Write
- **Purpose**: Runs a question in an investigation and waits for the answers. An optional subject is added to the investigation as a lead.

### investigate_user

- **Type**: Write
- **Purpose**: Investigates a single user end to end across connected identity sources and returns an aggregate result.
