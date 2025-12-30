## ShadowX SOCAI

Support: **info@shadowx.ai** — https://shadowx.ai

ShadowX SOCAI filters sensitive data in security logs and analyzes them with enterprise GenAI engines (e.g., ChatGPT, Gemini, Claude). It returns an AI response, analyst recommendation, risk/result classification, and a prediction score.

### Authentication

**API Key (service token) only.**

1. In ShadowX SOCAI, create a service API token with permission to create and read Security Tasks.
2. In the integration instance, set:
   - **Server URL**
   - **API Key (service token)**

### Behavior

- Submit logs to `/Api/SecurityTasks/Create`.
- Retrieve task status from `/Api/SecurityTasks/Details?taskID={task_id}`.
- Optional polling: pass `wait_seconds` (and `interval_seconds`) to `shadowx-submit-task` to return the final parsed result.

### Commands

- `!shadowx-submit-task log="<text>" [ip_addr=] [user_name=] [policy_id=] [wait_seconds=] [interval_seconds=]`
- `!shadowx-get-task task_id="<GUID>"`

### Tested Against

ShadowX SOCAI backend **v1.1.0**.

