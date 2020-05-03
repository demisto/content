## [Unreleased]


## [20.4.1] - 2020-04-29
- Remove http/https form items added .

## [20.4.0] - 2020-04-14
- 

## [19.12.1] - 2019-12-25
-

## [19.12.0] - 2019-12-10
  - Updated the detailed description.
  - Fixed an issue where the ***pan-os-edl-update*** command failed when the file path included space characters at *scp_execute()*.
  - Fixed an issue where the *ssh_execute()* function failed when the file name included space characters.
  - Added the following commands.
    - ***pan-os-edl-update-internal-list***
    - ***pan-os-edl-update-external-file*** commands.

## [19.8.0] - 2019-08-06
  - Added the ***pan-os-edl-get-external-file-metadata*** command.
  - When a non-existent list is specified in the ***pan-os-edl-update-from-external-file*** command, the list is automatically created, and the file data is saved to the list.
