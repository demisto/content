## [Unreleased]
  - Added 3 new commands:
    - ***panorama-query-logs***
    - ***panorama-check-logs-status***
    - ***panorama-get-logs***
  - Added the **Panorama Query Logs** playbook.
  - Improved handling of errors in cases of trying to refresh an EDL object on a Panorama instance.
  - Handle error trying to refresh an EDL object on a Panorama instance error gracefully

## [19.8.0] - 2019-08-06
  - Improved error handling for URL filtering licensing.
  - Improved error handling when trying to edit an uncommitted Custom URL category.
  - Added the ***panorama-list-rules*** command.
  - Added *edl* as an option for the *object_type* argument in the ***panorama-custom-block-rule*** command.
