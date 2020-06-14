## [Unreleased]


## [20.5.2] - 2020-05-26
-

## [20.5.0] - 2020-05-12
Deprecated. We recommend using the demisto-sdk to generate documentation. For full details see the [dev hub docs](https://xsoar.pan.dev/docs/integrations/integration-docs).



## [20.4.0] - 2020-04-14
-


## [19.11.0] - 2019-11-12
- Fixed an issue where commands in the top part were in the format **name:name** instead of **description:name**.
- Added links for the list of commands to each command.

## [19.10.0] - 2019-10-03
Added support for commands that have only headlines and no text in the human readable output.

## [19.9.1] - 2019-09-18
 - Added the *permissions* argument with the following options:
    - **per-command** - the permissions entry will be displayed in every command section.
    - ***global*** - the permissions entry will be displayed once, in its own section.
    - ***none*** - if there are no permissions required for this integration, there will be no permissions section.
 - Added a comment with an HTML example showing how to manually add an image to each command HTML section.
 - Fixed an issue in the arguments descriptions.
 

## [19.9.0] - 2019-09-04
#### New Script
Automates integration documentation.
See [https://github.com/demisto/content/tree/master/docs/integration_documentation](https://github.com/demisto/content/tree/master/docs/integration_documentation)
