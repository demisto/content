## [Unreleased]
  - Fixed an issue where the ***pan-os-edl-update*** command failed when the file path included space characters at *scp_execute()*.
  - Fixed an issue where the *ssh_execute()* functioned failed when the file name included space characters.
  - Added the ***pan-os-edl-update-internal-list***, ***pan-os-edl-update-external-file*** commands.

## [19.8.0] - 2019-08-06
  - Added the ***pan-os-edl-get-external-file-metadata*** command.
  - When a non-existent list is specified in the ***pan-os-edl-update-from-external-file*** command, the list is automatically created, and the file data is saved to the list.
