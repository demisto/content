# Sprinklr Event Collector

This integration collects Sprinklr Reporting API records in Cortex XSIAM and provides investigation and guarded response commands. It authenticates with OAuth 2.0 client credentials and sends collected records with vendor and product values set to `Sprinklr`.

## Configure Sprinklr Event Collector

| Parameter | Description | Required |
|---|---|---|
| Sprinklr API root URL | Sprinklr API host, for example `https://api3.sprinklr.com`. | Yes |
| Sprinklr environment | Environment segment used in API paths, for example `prod3`. | Yes |
| Client ID / API Key | OAuth client ID and the value sent in the `Key` header. | Yes |
| Client Secret / API Secret | OAuth client secret. | Yes |
| Reporting API path | Reporting API path template. | Yes |
| Reporting API payload (JSON) | Base Sprinklr Reporting API v2 request. Runtime timestamps and pagination override the corresponding fields. | Yes |
| Fetch events | Enables scheduled event collection. | No |
| First fetch time interval | Initial collection lookback. | No |
| Maximum number of events per fetch | Maximum page size, capped at 1000. | No |
| Events Fetch Interval | Scheduled collection interval. | No |
| SCIM delete path template | SCIM user endpoint containing the `{userId}` placeholder. | Yes |
| HTTP timeout in seconds | Request timeout. | No |
| Trust any certificate (not secure) | Disables TLS certificate verification. | No |
| Use system proxy settings | Uses the Cortex system proxy. | No |

## Commands

### Collection and reporting

- `sprinklr-get-events`: Retrieves Reporting API records for a time range and can optionally send them to XSIAM.
- `sprinklr-report-query`: Executes the configured or supplied Reporting API request.

### Investigation

- `sprinklr-search-events`: Filters Reporting API records by time, author, account, post, message, channel, status, or deletion state.
- `sprinklr-get-user-activity`: Retrieves recent activity for an author ID.
- `sprinklr-get-account-activity`: Retrieves recent activity for an account ID.
- `sprinklr-get-post`: Retrieves activity for a post ID.
- `sprinklr-get-deleted-events`: Retrieves events marked as deleted.
- `sprinklr-security-summary`: Summarizes activity by status, channel, author, account, and deletion state.
- `sprinklr-get-user`: Retrieves a Governance user by email.
- `sprinklr-get-social-logins`: Retrieves social login profiles linked to an email address.
- `sprinklr-get-account-details`: Retrieves account details by account ID.
- `sprinklr-get-message`: Retrieves activity for a message ID.
- `sprinklr-get-channel-activity`: Retrieves activity for a channel.
- `sprinklr-get-status-events`: Retrieves activity for a status value.
- `sprinklr-get-failed-events`: Retrieves events with status `FAILED`.
- `sprinklr-get-sent-events`: Retrieves events with status `SENT`.
- `sprinklr-get-author-account-activity`: Retrieves events matching an author and account.
- `sprinklr-get-account-channel-activity`: Retrieves events matching an account and channel.
- `sprinklr-get-author-channel-activity`: Retrieves events matching an author and channel.

### Response and recovery

The following state-changing commands require `confirm=yes`:

- `sprinklr-deactivate-user`
- `sprinklr-activate-user`
- `sprinklr-remove-user-from-team`
- `sprinklr-delete-user-by-email`
- `sprinklr-deprovision-user`
- `sprinklr-create-user`
- `sprinklr-remove-ad-account-from-team`
- `sprinklr-attach-ad-account-to-team`
- `sprinklr-remove-page-account-from-team`
- `sprinklr-attach-page-account-to-team`

## Event collection

Scheduled collection stores a completed time checkpoint. While Sprinklr returns `data.hasMore=true`, the integration keeps the same time window and advances the page. The checkpoint advances only after all pages for the window are collected.

The included parsing rule routes events to `sprinklr_sprinklr_raw`. The included modeling rule maps relevant raw fields to XDM.
