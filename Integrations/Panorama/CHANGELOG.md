## [Unreleased]


## [19.10.2] - 2019-10-29
Added the ***panorama-security-policy-match*** command.

## [19.9.1] - 2019-09-18
- Added the *tag* argument to several commands.
    - List commands - filter by a tag.
    - Create and edit commands
    - Added the context output Tags to all list, create, edit, and get commands.
  - Added support in the ***panorama-query-logs*** command to supply a list of arguments, which are separated using the "OR" operator.
  - Improved error messaging when trying to configure a *device-group* that does not exist.
  
## [19.9.0] - 2019-09-04
  - Added 3 commands.
    - ***panorama-query-logs***
    - ***panorama-check-logs-status***
    - ***panorama-get-logs***
  - Added the **Panorama Query Logs** playbook.
  - Added *log-forwarding* as an option for the *element_to_change* argument in the ***panorama-edit-rule*** command.
  - Added support for Shared objects and Rules in Panorama instances.
  - Added the device-group argument to all relevant commands.
  

## [19.8.2] - 2019-08-22
  - Improved error handling in cases of trying to refresh an EDL object on a Panorama instance.

## [19.8.0] - 2019-08-06
  - Improved error handling for URL filtering licensing.
  - Improved error handling when trying to edit an uncommitted Custom URL category.
  - Added the ***panorama-list-rules*** command.
  - Added *edl* as an option for the *object_type* argument in the ***panorama-custom-block-rule*** command.

