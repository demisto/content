## [Unreleased]
- Internal code improvements.
- Added new commands:
    - **code42-departingemployee-get-all**
    - **code42-highriskemployee-add**
    - **code42-highriskemployee-remove**
    - **code42-highriskemployee-get-all**
    - **code42-highriskemployee-add-risk-tags**
    - **code42-highriskemployee-remove-risk-tags**
    - **code42-user-deactivate**
    - **code42-user-reactivate**
    - **code42-user-block**
    - **code42-user-unblock**
    - **code42-user-create**
    - **code42-legalhold-add-user**
    - **code42-legalhold-remove-user**
    - **code42-file-download**
    - **code42-departingemployee-get**
    - **code42-highriskemployee-get**
- Improve error messages for all Commands to include exception detail.
- Fixed bug in Fetch where errors occurred when `FileCategory` was set to include only one category.
- Fixed bug in Fetch to handle new Code42 exposure type **Outside trusted domains**.
- Improved Fetch to handle unsupported exposure types better.
- Added option to specify `All` in `exposure` argument in `search-securitydata` command to fetch all results with exfiltration.

## [20.3.3] - 2020-03-18
#### New Integration
Use the Code42 integration to identify potential data exfiltration from insider threats while speeding investigation and response by providing fast access to file events and metadata across physical and cloud environments.