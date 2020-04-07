Uses this script to get file and URL reputation for osxcollector result.

This script will use `VirusTotal` for URL checks, and IBM XForce for MD5 file hash checks.
 * maxchecks : for.
 * system  : system name to run agent on.
 * section : the type check that OSXCollector should run.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | osx |


## Dependencies
---
This script uses the following commands and scripts.
* url
* file

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| section | Asks OSXCollector for a specific section. |
| timeout | The timeout to be passed to the OSXCollector script. |
| maxchecks | The maximum amount of files/URLs to verify. |
| system | THe OSX system to be used. |

## Outputs
---
There are no outputs for this script.
