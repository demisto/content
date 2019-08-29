## [Unreleased]
  - Added 3 new commands:
    - ***panorama-query-logs***
    - ***panorama-check-logs-status***
    - ***panorama-get-logs***
  - Added the **Panorama Query Logs** playbook.
  - Added *log-forwarding* as an option for the *element_to_change* argument in the ***panorama-edit-rule*** command.
  

## [19.8.2] - 2019-08-22
  - Improved error handling in cases of trying to refresh an EDL object on a Panorama instance.

## [19.8.0] - 2019-08-06
  - Improved error handling for URL filtering licensing.
  - Improved error handling when trying to edit an uncommitted Custom URL category.
  - Added the ***panorama-list-rules*** command.
  - Added *edl* as an option for the *object_type* argument in the ***panorama-custom-block-rule*** command.