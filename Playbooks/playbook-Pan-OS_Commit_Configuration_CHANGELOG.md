## [Unreleased]
Added a better error message when commit or push fails

## [20.3.3] - 2020-03-18
Fixed a bug where the commit failed but the playbook succeeded. Now it will fail on unsuccessful commit or push.

## [19.12.0] - 2019-12-10
removed PA-VM as the firewall identificator and changed the condition to else

## [19.9.1] - 2019-09-18
Name changes and layout improvement

## [19.8.2] - 2019-08-22
Automatically determines which product is being used (Firewall or Panorama), and commits accordingly. This playbook replaces the deprecated **panorama-commit-configuration** playbook.
