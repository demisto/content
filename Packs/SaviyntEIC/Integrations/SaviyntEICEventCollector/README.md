# SaviyntEIC Event Collector

Collects audit logs from Saviynt Enterprise Identity Cloud (EIC) using Analytics Runtime Control V2.

## Configuration

- Server URL (https://SUBDOMAIN.saviyntcloud.com)
- Credentials (username/password)
- Analytics Name (e.g., SIEMAuditLogs)
- Max events per fetch (default 10000)
- First fetch time (e.g., 3 days)
- Insecure / Proxy

## Commands

- get-events
- fetch-events

## Notes

- Authentication uses `/ECM/api/login` to obtain a bearer token and `/ECM/oauth/access_token` to refresh it.
- Events field mapping includes: Action Taken, IP Address, Event Time, Message, Object Type, Accessed By.
- `_time` is set from the `Event Time` field.
