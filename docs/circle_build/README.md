# Overview
This article will explain the CircleCI build process.
In addition, we'll explain common errors and how to troubleshoot them.

# Build Sections
1. [Spin up Environment](#spin-up-environment)
2. [Checkout code](#checkout-code)
3. [Setup a remote Docker engine](#setup-a-remote-docker-engine)
4. [Prepare Environment](#prepare-environment)
5. [Installing additional ssh keys](#installing-additional-ssh-keys)
6. [Create ID Set](#create-id-set)
7. [Infrastructure testing](#infrastructure-testing)
8. [Validate Files and Yaml](#validate-files-and-yaml)
9. [Configure Test Filter](#configure-test-filter)
10. [Spell Checks](#spell-checks)
11. [Build Content Descriptor](#build-content-descriptor)
12. [Common Server Documentation](#common-server-documentation)
13. [Create Content Artifacts](#create-content-artifacts)
14. [Uploading artifacts](#uploading-artifacts)
15. [Run Unit Testing and Lint](#run-unit-testing-and-lint)
16. [Download Artifacts](#download-artifacts)
17. [Download Configuration](#download-configuration)
18. [Create Instance](#create-instance)
19. [Setup Instance](#setup-instance)
20. [Run Tests - Latest GA](#run-tests---latest-ga)
21. [Run Tests - One Before GA](#run-tests---one-before-ga)
22. [Run Tests - Two Before GA](#run-tests---two-before-ga)
23. [Run Tests - Server Master](#run-tests---server-master)
24. [Slack Notifier](#slack-notifier)
25. [Validate Docker Images](#validate-docker-images)
26. [Instance Test](#instance-test)
27. [Destroy Instances](#destroy-instances)
28. [Uploading artifacts](#uploading-artifacts-final)

## Spin up Environment
This is a CircleCI step which setup a machine to run the build on.
  
## Checkout code
Download the content source code (clones and checkout to the specific revision).

## Setup a remote Docker engine
Setup a docker engine in preparation for running python unit-tests in later steps.

## Prepare Environment
Setup workspace: 
- Set global variables.
- Create workspace and artifact folders
- Print build parameters: 
  - `NIGHTLY`: this parameter is set during the build triggered each night.
  - `NON_AMI_RUN`: Indicates whether the build should use predefined AMI (amazon machine image) or not.
  - `SERVER_BRANCH_NAME`: only relevant in case `NON_AMI_RUN` is set. indicates the demisto server build the current build should work against.  

## Installing additional ssh keys
Add ssh keys to circle machine.

## Create ID Set
This is the first step in the static validation process of the content code.

By running [Tests/scripts/update_id_set.py](https://github.com/demisto/content/blob/master/Tests/scripts/update_id_set.py), we are able to detect conflict of entities (for example, IDs that are being used more than once).

Also, the script calculate dependencies between integration commands, scripts, playbooks and test-playbooks.
This is used in the test [selection step](#Configure-Test-Filter).

<!-- TODO: add troubleshooting errors -->

## Infrastructure testing
This step runs all unit-test files in the following folders:
- [Tests/scripts/hook_validations/tests](https://github.com/demisto/content/blob/master/Tests/scripts/hook_validations/tests)
- [Tests/scripts/infrastructure_tests](https://github.com/demisto/content/blob/master/Tests/scripts/infrastructure_tests)

<!-- TODO: add troubleshooting errors -->

## Validate Files and Yaml
This step is responsible for the majority of the static validations of the content code.
- It checks for backward compatibility issues:
  - docker changes
  - id/name changes
  - additional required parameters/arguments
  - context key changes
- Enforce content standards:
  - valid descriptions
  - content entity schemas
  - argument/parameter conflicts
  - context output standards
 
<!-- TODO: add troubleshooting errors -->

## Configure Test Filter
This step decides and filters which test-playbooks should run.
Special behavior:
- nightly: will run all test-playbooks (with the exception of "skip" tests).
- changes to CommonServer/CommonServerPython: will run all test-playbooks (with the exception of "skip" and "nightly" tests).

<!-- TODO: add troubleshooting errors -->

## Spell Checks
**This will not run on master branch**

By running [Tests/scripts/circleci_spell_checker.py](https://github.com/demisto/content/blob/master/Tests/scripts/circleci_spell_checker.py), we scan yml and md files for typos and spelling mistakes.
One can whitelist a word (for example acronyms are usually detected as misspelled words) by adding it to the [known words](https://github.com/demisto/content/blob/master/Tests/known_words.txt) file.

At the moment, this step does not break the build.

## Build Content Descriptor
<!-- TODO: add troubleshooting errors -->

## Common Server Documentation
<!-- TODO: add troubleshooting errors -->

## Create Content Artifacts
<!-- TODO: add troubleshooting errors -->

## Uploading artifacts
This will upload all files stored under the artifact folder as a circle build artifacts.
![](artifacts_1.png)

## Run Unit Testing and Lint

## Download Artifacts
**Not relevant for contributors**

This step is relevant only for custom builds that uses a specific demisto server build.
It will download the demisto installer from the given build number.

## Download Configuration
**Not relevant for contributors**

<!-- TODO: add troubleshooting errors -->

## Create Instance
**Not relevant for contributors**
<!-- TODO: add troubleshooting errors -->

## Setup Instance
**Not relevant for contributors**
<!-- TODO: add troubleshooting errors -->

## Run Tests - Latest GA
**Not relevant for contributors**
<!-- TODO: add troubleshooting errors -->

## Run Tests - One Before GA
**Not relevant for contributors**

Same as [Latest GA](#run-tests---latest-ga) except uses one version before the latest GA.

## Run Tests - Two Before GA
**Not relevant for contributors**

Same as [Latest GA](#run-tests---latest-ga) except uses two version before the latest GA.

## Run Tests - Server Master
**Not relevant for contributors**

Same as [Latest GA](#run-tests---latest-ga) except uses current master branch of demisto server.

## Slack Notifier
**Not relevant for contributors**

This step runs only in nightly builds of master branch.
It will notify the slack channel `#dmst-content-team` about the list of failed tests.


## Validate Docker Images
**This will not run on master branch (or release branches)**
<!-- this should be handled by running validate_files.py -->

## Instance Test
**Not relevant for contributors**

This step runs only in nightly builds of master branch.

Configure each integration instance, trigger a `test-module` (test button in instance configuration screen) and notify `dmst-content-lab` slack channel on failures.

## Destroy Instances
**Not relevant for contributors**

This step will download demisto server log and shutdown each server iff relevant "Run Tests" step passed.

## Uploading artifacts final
Once more, will upload artifact folder (which now also contains serverlogs) as circle build artifacts.