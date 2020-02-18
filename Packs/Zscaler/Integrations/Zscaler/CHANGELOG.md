## [Unreleased]
- Fixed an issue where the ***url*** command in *Zscaler* was not creating an Indicator in Demisto.
- Fixed the ***url*** and ***ip*** commands in *Zscaler* output descriptions.
- Fixed an issue where the ***zscaler-category-add-url*** command failed when passing multiple URLs separated with spaces.
- Fixed an issue where the ***zscaler-undo-blacklist-url*** command always failed with the error "Given URL is not blacklisted".
- Fixed an issue where the ***zscaler-undo-blacklist-ip*** command always failed with the error "Given IP is not blacklisted".
- Fixed an issue where the ***zscaler-undo-whitelist-url*** command always failed with the error "Given host address is not whitelisted.".
- Fixed an issue where the ***zscaler-undo-whitelist-ip*** command always failed with the error "Given IP address is not whitelisted.".
- Updated command executions to always activate changes after API calls and close session. This fixes issues related to the session not being authenticated or timing out.

## [19.10.2] - 2019-10-29
Fixed an issue where the ***zscaler-undo-blacklist-url*** command failed on key error.
