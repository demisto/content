# ShadowX SOCAI

ShadowX SOCAI  , filter sensitive data in security logs and analyze with the GEN AI solutions like  Chatgpt,Gemini,Claude  and produces enriched guidance (response, recommendation, risk/result, prediction score).

## Authentication Modes

### API Key (recommended)
- Set **API Key** in the instance.
- By default we POST JSON to `/api/FreeTextSearch/ShadowxProxy` with `Authorization: Bearer <API_KEY>`.
- If the response contains `TaskId`, we poll `/api/FreeTextSearch/CheckTask/{task_id}` until complete.
- You may change endpoints via **API Submission Path** and **API Check Path Format**.

### Cookie (HTML) login
- Leave **API Key** empty and set **User Email** and **User Password**.
- The integration re-logins on every command:
  1. `POST /User/Login` (JSON) → `AuthToken` cookie
  2. `GET /SecurityTasks/Create` (HTML) → extracts `__RequestVerificationToken` (+ anti-forgery cookie)
  3. `POST /SecurityTasks/Create` (JSON) with header `RequestVerificationToken` and the same token in the body

> If your environment enforces SSO/IdP on `/SecurityTasks/Create`, use **API Key** mode.

## Configuration

Required:
- **Server URL** (e.g., `https://app.shadowx.ai:8443`)

Pick one auth mode:
- **API Key** *(recommended)* — leave email/password blank  
**OR**
- **User Email**, **User Password** (cookie mode)

Optional:
- **AI Driver ID (GUID)**, **Assigned User ID (GUID)**, **Default Policy ID (GUID)**, **Default Task Name**
- **API Submission Path**, **API Check Path Format**
- **Proxy**, **Trust any certificate (insecure)**

## Commands

### `!shadowx-submit-task`
Submit a log for analysis.

**Args**
- `log` (required)
- `ip_addr` (optional)
- `user_name` (optional)
- `policy_id` (optional; overrides instance default)
- `wait_seconds` (optional; API mode polls if `TaskId` returned)

**Examples**
```
!shadowx-submit-task log="Failed login from 192.168.1.10"
!shadowx-submit-task log="37690709650" ip_addr="192.168.1.100" user_name="test" policy_id="..." wait_seconds=30
```

## Troubleshooting

- **415 Unsupported Media Type** on login (cookie mode): your server expects JSON for `/User/Login` (integration already sends JSON).  
- **Redirect loops / 302** on `/SecurityTasks/Create`: ensure you are not mixing IP vs domain; cookies are domain-scoped. Prefer API Key mode if SSO is enforced.  
- **Image pull error**: set `dockerimage` to a tag present on your server (e.g., `demisto/python3:3.11.10.116949`).  