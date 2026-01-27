### 1.1.37

#### Integrations
- **CiscoSMA** integration: added enhanced quarantine search and management capabilities.

#### New Features
- **Added `quarantine_type` and `quarantines` support** to quarantine search to allow searching both **spam** and **PVO** quarantines.
- **New commands**
  - `cisco-sma-spam-quarantine-attachment-download` — download an attachment from a quarantined message.
  - `cisco-sma-spam-quarantine-message-send-copy` — send a copy of a quarantined message to specified recipients.
- **Extended existing commands** to support PVO workflows when applicable:
  - `cisco-sma-spam-quarantine-message-release` — now supports releasing messages from PVO quarantines when `quarantine_name` is provided.
  - `cisco-sma-spam-quarantine-message-delete` — now supports deleting messages from PVO quarantines when `quarantine_name` is provided.

#### Improvements
- **Search filtering enhancements**
  - Spam search: added `filter_by`, `filter_operator`, `filter_value`, `recipient_filter_operator`, `recipient_filter_value`, `order_by`, and `order_dir`.
  - PVO search: added `quarantines` plus `envelope_sender_filter_by`, `envelope_sender_filter_value`, `envelope_recipient_filter_by`, `envelope_recipient_filter_value`, `subject_filter_by`, and `subject_filter_value`.
  - Clarified scope: search commands accept **quarantine type** and apply the appropriate filter set depending on `quarantine_type` (`spam` vs `pvo`).
- **Parameter validation**
  - Added validation for dependent filter arguments (e.g., `filter_operator`/`filter_value` require `filter_by`; recipient filters require matching operator/value).
- **Pagination and limits**
  - Enforced `MAX_PAGE_SIZE` and safe handling of `limit`/`offset` to prevent API rejections and large pulls.
- **Client improvements**
  - JWT token handling and refresh logic hardened to reduce authentication errors.
  - Timeout, proxy, and insecure flags passed consistently to the client.

#### Documentation
- **README.md** updated:
  - Documented new configuration parameters: `filter_by`, `filter_operator`, `filter_value`, `recipient_filter_operator`, `recipient_filter_value`.
  - Documented `quarantine_type` and `quarantines` usage.
  - Added command docs for new commands and updated docs for `message-search`, `message-get`, `message-release`, and `message-delete` to reflect PVO behavior and parameter requirements.
  - Added explicit filtering behavior notes and dependency rules.
- **ReleaseNotes** added for version 1.1.31.
- **pack_metadata.json** version bumped to `1.1.31`.
- **CHANGELOG.md** updated with this release entry.

#### Bug Fixes
- Fixed potential silent failures when invalid filter combinations were provided by raising clear errors.
- Fixed inconsistent passing of `timeout`, `proxy`, and `insecure` parameters to the HTTP client.
- Fixed pagination edge cases that could cause duplicate or missing results.

#### Tests
- Updated unit tests and mocks to cover:
  - New search filters for spam and PVO.
  - New commands: attachment download and send copy.
  - PVO release and delete flows.
- Added validation scenarios for filter dependency errors.

#### Notes for Upgraders
- **Version alignment required**: ensure `pack_metadata.json`, `CHANGELOG.md`, and the integration `pack version` comment are all updated to `1.1.31`.
- If you rely on automated fetch-incidents, note that fetch remains spam-focused by default; use the new search command with `quarantine_type=pvo` for PVO-specific queries.
