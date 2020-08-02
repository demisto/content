## [Unreleased]
- DEPRECATED. Use "PAN-OS EDL Setup v3" playbook instead. 

## [20.5.0] - 2020-05-12
Added test playbook

## [20.3.3] - 2020-03-18
Fixed missing letter in device mode(l).

## [20.2.3] - 2020-02-18
#### New Playbook
Configures an external dynamic list in PAN-OS.
In the event that the file exists on the web server, it will sync it to demisto. Then it will create an EDL object and a matching rule.